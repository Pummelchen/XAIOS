/* Runtime AArch64 mappings: the walk's reader, the kernel mapping entry
 * points, range and user-buffer validation, cache maintenance and the VMM
 * self-test.
 *
 * The boot map and the page-table helpers those entry points are built on --
 * the descriptors, the allocate-or-find walk, the per-CPU mirror and the
 * SCTLR_EL1 enable sequence -- are in mmu_boot.c, and the per-process user
 * address spaces are in mmu_user.c. Both sides share the descriptor encoding
 * and the helper declarations in mmu_internal.h, so this file names no
 * attribute bits of its own beyond the descriptor decode and the one bit the
 * self-test inspects. Nothing here changed order, attributes or barriers; it
 * moved whole.
 */
#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/pmm.h>
#include <xaios/spinlock.h>
#include <xaios/vmm.h>

#include "mmu_internal.h"

static uint32_t user_address(uint64_t virtual_address) {
  return virtual_address >= XAIOS_USER_BASE &&
         virtual_address < XAIOS_USER_LIMIT;
}

static void invalidate_tlb_page(uint64_t virtual_address) {
  (void)virtual_address;
  __asm__ volatile(
      "dsb ishst\n"
      "tlbi vmalle1is\n"
      "dsb ish\n"
      "isb\n"
      :
      :
      : "memory");
}

/* Ask the hardware, not our own call path.
 *
 * A flag set by aarch64_enable_mmu answers the wrong question: firmware
 * may have enabled translation before the kernel ever ran, which QEMU and
 * Apple's hypervisor both do, and secondaries come online before vmm_init. A
 * flag would have read "off" there while four CPUs were running, and the
 * spinlock would have quietly used plain loads and stores where it needed
 * exclusives -- locks that do not lock. SCTLR_EL1.M is the truth on every
 * platform and costs one system register read. */
uint32_t xaios_translation_enabled(void) {
  uint64_t sctlr = 0U;
  __asm__ volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
  return (sctlr & UINT64_C(1)) != 0U ? 1U : 0U;
}

static xaios_status_t descriptor_to_flags(uint64_t virtual_address,
                                         uint64_t descriptor, uint32_t *flags) {
  if ((descriptor & PTE_VALID) == 0) {
    return XAIOS_ERR_INVALID;
  }

  uint32_t out = XAIOS_VMM_PRESENT;
  uint64_t attr_index = (descriptor >> 2) & 0x7U;
  if (attr_index == 1) {
    out |= XAIOS_VMM_DEVICE;
  }
  if (a64mmu_in_mmio_window(virtual_address)) {
    out |= XAIOS_VMM_DEVICE;
  }
  if ((descriptor & PTE_AP_RO) == 0) {
    out |= XAIOS_VMM_WRITABLE;
  }
  if ((descriptor & PTE_UXN) == 0 || (descriptor & PTE_PXN) == 0) {
    out |= XAIOS_VMM_EXECUTABLE;
  }
  if ((descriptor & PTE_AP_EL0) != 0) {
    out |= XAIOS_VMM_USER;
  }

  *flags = out;
  return XAIOS_OK;
}

static uint64_t dcache_line_bytes(void) {
  uint64_t ctr = 0U;
  __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
  return UINT64_C(4) << ((ctr >> 16U) & UINT64_C(0xf));
}

void vmm_clean_to_memory(const void *buffer, uint64_t bytes) {
  if (buffer == 0 || bytes == 0U) return;
  uint64_t line = dcache_line_bytes();
  uintptr_t start = (uintptr_t)buffer & ~(uintptr_t)(line - 1U);
  uintptr_t end = (uintptr_t)buffer + (uintptr_t)bytes;
  for (uintptr_t address = start; address < end; address += line) {
    __asm__ volatile("dc cvac, %0" : : "r"(address) : "memory");
  }
  __asm__ volatile("dsb sy" : : : "memory");
}

void vmm_invalidate_from_memory(const void *buffer, uint64_t bytes) {
  if (buffer == 0 || bytes == 0U) return;
  uint64_t line = dcache_line_bytes();
  uintptr_t start = (uintptr_t)buffer & ~(uintptr_t)(line - 1U);
  uintptr_t end = (uintptr_t)buffer + (uintptr_t)bytes;
  __asm__ volatile("dsb sy" : : : "memory");
  for (uintptr_t address = start; address < end; address += line) {
    __asm__ volatile("dc ivac, %0" : : "r"(address) : "memory");
  }
  __asm__ volatile("dsb sy" : : : "memory");
}

xaios_status_t vmm_translate(uint64_t virtual_address, uint64_t *physical_address,
                            uint32_t *flags) {
  uint64_t l0_index = (virtual_address >> 39) & 0x1ffU;
  uint64_t l1_index = (virtual_address >> 30) & 0x1ffU;
  uint64_t l2_index = (virtual_address >> 21) & 0x1ffU;
  uint64_t l3_index = (virtual_address >> 12) & 0x1ffU;
  uint64_t page_offset = virtual_address & UINT64_C(0xfff);
  uint64_t l2_offset = virtual_address & (L2_BLOCK_SIZE - 1);
  uint64_t l1_offset = virtual_address & (L1_BLOCK_SIZE - 1);

  const uint64_t *root =
      (const uint64_t *)(uintptr_t)a64mmu_current_root_address();
  uint64_t l0_desc = root[l0_index];
  if ((l0_desc & (PTE_VALID | PTE_TABLE)) != (PTE_VALID | PTE_TABLE)) {
    return XAIOS_ERR_INVALID;
  }
  const uint64_t *l1 = (const uint64_t *)(uintptr_t)(l0_desc & PTE_ADDR_MASK);

  uint64_t l1_desc = l1[l1_index];
  if ((l1_desc & PTE_VALID) == 0U) {
    return XAIOS_ERR_INVALID;
  }
  if ((l1_desc & PTE_TABLE) == 0U) {
    *physical_address = (l1_desc & PTE_BLOCK_L1_ADDR_MASK) + l1_offset;
    return descriptor_to_flags(virtual_address, l1_desc, flags);
  }
  const uint64_t *l2 = (const uint64_t *)(uintptr_t)(l1_desc & PTE_ADDR_MASK);

  uint64_t l2_desc = l2[l2_index];
  if ((l2_desc & PTE_VALID) == 0) {
    return XAIOS_ERR_INVALID;
  }
  if ((l2_desc & PTE_TABLE) == 0) {
    *physical_address = (l2_desc & PTE_BLOCK_L2_ADDR_MASK) + l2_offset;
    return descriptor_to_flags(virtual_address, l2_desc, flags);
  }

  const uint64_t *l3 = (const uint64_t *)(uintptr_t)(l2_desc & PTE_ADDR_MASK);
  uint64_t l3_desc = l3[l3_index];
  if ((l3_desc & PTE_VALID) == 0) {
    return XAIOS_ERR_INVALID;
  }

  *physical_address = (l3_desc & PTE_ADDR_MASK) + page_offset;
  return descriptor_to_flags(virtual_address, l3_desc, flags);
}

xaios_status_t vmm_validate_range_flags(uint64_t virtual_address, uint64_t size,
                                        uint32_t required_flags,
                                        uint32_t forbidden_flags) {
  if (size == 0U || size - 1U > UINT64_MAX - virtual_address) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t page = a64mmu_align_down(virtual_address, PAGE_SIZE);
  uint64_t last = a64mmu_align_down(virtual_address + size - 1U, PAGE_SIZE);
  for (;;) {
    uint64_t physical = 0U;
    uint32_t flags = 0U;
    if (vmm_translate(page, &physical, &flags) != XAIOS_OK ||
        (flags & required_flags) != required_flags ||
        (flags & forbidden_flags) != 0U) {
      return XAIOS_ERR_INVALID;
    }
    (void)physical;
    if (page == last) break;
    if (page > UINT64_MAX - PAGE_SIZE) return XAIOS_ERR_INVALID;
    page += PAGE_SIZE;
  }
  return XAIOS_OK;
}

xaios_status_t vmm_map_page(uint64_t virtual_address, uint64_t physical_address,
                           uint32_t flags) {
  if ((virtual_address & (PAGE_SIZE - 1)) != 0 ||
      (physical_address & (PAGE_SIZE - 1)) != 0 ||
      (flags & XAIOS_VMM_PRESENT) == 0) {
    return XAIOS_ERR_INVALID;
  }

  uint64_t *l3 = a64mmu_ensure_l3_table(virtual_address);
  if (l3 == 0) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t l3_index = (virtual_address >> 12) & 0x1ffU;
  l3[l3_index] = a64mmu_page_descriptor(physical_address,
                                        a64mmu_attrs_from_flags(flags));
  if (user_address(virtual_address) == 0U) {
    a64mmu_sync_kernel_hierarchy(virtual_address);
  }
  invalidate_tlb_page(virtual_address);
  return XAIOS_OK;
}

xaios_status_t vmm_unmap_page(uint64_t virtual_address) {
  if ((virtual_address & (PAGE_SIZE - 1)) != 0) {
    return XAIOS_ERR_INVALID;
  }

  uint64_t *l3 = a64mmu_ensure_l3_table(virtual_address);
  if (l3 == 0) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t l3_index = (virtual_address >> 12) & 0x1ffU;
  l3[l3_index] = 0;
  if (user_address(virtual_address) == 0U) {
    a64mmu_sync_kernel_hierarchy(virtual_address);
  }
  invalidate_tlb_page(virtual_address);
  return XAIOS_OK;
}

xaios_status_t vmm_map_large_page(uint64_t virtual_address,
                                 uint64_t physical_address, uint32_t flags) {
  if ((virtual_address & (L2_BLOCK_SIZE - 1U)) != 0U ||
      (physical_address & (L2_BLOCK_SIZE - 1U)) != 0U ||
      (flags & XAIOS_VMM_PRESENT) == 0U ||
      (flags & XAIOS_VMM_USER) != 0U || user_address(virtual_address) != 0U) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t *l2 = a64mmu_ensure_l2_table(virtual_address);
  if (l2 == 0) return XAIOS_ERR_NO_MEMORY;
  uint64_t l2_index = (virtual_address >> 21U) & 0x1ffU;
  if ((l2[l2_index] & PTE_VALID) != 0U) return XAIOS_ERR_BUSY;
  l2[l2_index] = a64mmu_block_descriptor(physical_address,
                                         a64mmu_attrs_from_flags(flags));
  a64mmu_sync_kernel_hierarchy(virtual_address);
  invalidate_tlb_page(virtual_address);
  return XAIOS_OK;
}

xaios_status_t vmm_unmap_large_page(uint64_t virtual_address) {
  if ((virtual_address & (L2_BLOCK_SIZE - 1U)) != 0U ||
      user_address(virtual_address) != 0U) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t *l2 = a64mmu_find_l2_table(virtual_address);
  if (l2 == 0) return XAIOS_ERR_INVALID;
  uint64_t l2_index = (virtual_address >> 21U) & 0x1ffU;
  uint64_t descriptor = l2[l2_index];
  if ((descriptor & PTE_VALID) == 0U || (descriptor & PTE_TABLE) != 0U) {
    return XAIOS_ERR_INVALID;
  }
  l2[l2_index] = 0U;
  a64mmu_sync_kernel_hierarchy(virtual_address);
  invalidate_tlb_page(virtual_address);
  return XAIOS_OK;
}

xaios_status_t vmm_map_gigantic_page(uint64_t virtual_address,
                                    uint64_t physical_address,
                                    uint32_t flags) {
  (void)virtual_address;
  (void)physical_address;
  (void)flags;
  return XAIOS_ERR_UNSUPPORTED;
}

xaios_status_t vmm_unmap_gigantic_page(uint64_t virtual_address) {
  (void)virtual_address;
  return XAIOS_ERR_UNSUPPORTED;
}

xaios_status_t vmm_validate_user_buffer(uint64_t virtual_address, uint64_t size,
                                       uint32_t required_flags) {
  if (size == 0 || virtual_address < XAIOS_USER_BASE ||
      virtual_address + size < virtual_address ||
      virtual_address + size > XAIOS_USER_LIMIT) {
    return XAIOS_ERR_INVALID;
  }

  uint64_t start = a64mmu_align_down(virtual_address, PAGE_SIZE);
  uint64_t end = a64mmu_align_up(virtual_address + size, PAGE_SIZE);
  for (uint64_t page = start; page < end; page += PAGE_SIZE) {
    uint64_t physical = 0;
    uint32_t flags = 0;
    if (vmm_translate(page, &physical, &flags) != XAIOS_OK) {
      return XAIOS_ERR_INVALID;
    }
    (void)physical;
    if ((flags & XAIOS_VMM_USER) == 0 ||
        (flags & required_flags) != required_flags) {
      return XAIOS_ERR_INVALID;
    }
  }
  return XAIOS_OK;
}

void vmm_self_test(void) {
  const uint64_t large_va = UINT64_C(0x7000000000);
  const uint64_t large_pa = UINT64_C(0x40000000);
  uint64_t translated = 0U;
  uint32_t flags = 0U;
  kassert(vmm_map_large_page(large_va, large_pa,
                             XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE) ==
          XAIOS_OK);
  kassert(vmm_map_large_page(large_va, large_pa, XAIOS_VMM_PRESENT) ==
          XAIOS_ERR_BUSY);
  kassert(vmm_validate_range_flags(
              large_va, XAIOS_VMM_LARGE_PAGE_SIZE,
              XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE,
              XAIOS_VMM_USER | XAIOS_VMM_EXECUTABLE) == XAIOS_OK);
  kassert(vmm_translate(large_va + XAIOS_VMM_LARGE_PAGE_SIZE - 1U,
                        &translated, &flags) == XAIOS_OK);
  kassert(translated == large_pa + XAIOS_VMM_LARGE_PAGE_SIZE - 1U);
  kassert(vmm_unmap_large_page(large_va) == XAIOS_OK);
  kassert(vmm_translate(large_va, &translated, &flags) == XAIOS_ERR_INVALID);
  klog("VMM: ARM64 2 MiB large-page map/unmap self-test passed\n");

  /* Above the first level-0 slot. QEMU's virt machine puts its 64-bit PCI
     window at exactly this address, and firmware placed a disk's registers
     there on a machine with one disk -- which the kernel then could not map,
     leaving it with no durable storage. The mapping is what makes such a
     machine usable, so check that it still works rather than trusting that
     nobody reintroduces the single-slot assumption. */
  const uint64_t high_va = UINT64_C(0x8000004000);
  void *high_page = pmm_alloc_page();
  kassert(high_page != 0);
  kassert(vmm_map_page(high_va, (uint64_t)(uintptr_t)high_page,
                       XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE |
                           XAIOS_VMM_DEVICE) == XAIOS_OK);
  kassert(vmm_translate(high_va, &translated, &flags) == XAIOS_OK);
  kassert(translated == (uint64_t)(uintptr_t)high_page);
  kassert((flags & XAIOS_VMM_DEVICE) != 0U);
  /* A second page in the same slot must reuse the level-1 table the first one
     created, not allocate over it. */
  kassert(vmm_map_page(high_va + PAGE_SIZE, (uint64_t)(uintptr_t)high_page,
                       XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE |
                           XAIOS_VMM_DEVICE) == XAIOS_OK);
  kassert(vmm_translate(high_va, &translated, &flags) == XAIOS_OK);
  kassert(translated == (uint64_t)(uintptr_t)high_page);
  kassert(vmm_unmap_page(high_va + PAGE_SIZE) == XAIOS_OK);
  kassert(vmm_unmap_page(high_va) == XAIOS_OK);
  invalidate_tlb_page(high_va);
  kassert(vmm_translate(high_va, &translated, &flags) == XAIOS_ERR_INVALID);
  pmm_free_page(high_page);
  klog("VMM: mapping above the first level-0 slot passed va=0x%lx\n", high_va);

  uint64_t process_tables[USER_ASPACE_L3_TABLES];
  uint32_t process_table_count = 0U;
  vmm_create_user_aspace(process_tables, USER_ASPACE_L3_TABLES,
                         &process_table_count);
  kassert(process_table_count == USER_ASPACE_L3_TABLES);
  void *boundary_page = pmm_alloc_page();
  kassert(boundary_page != 0);
  uint64_t boundary_va = XAIOS_USER_BASE + L2_BLOCK_SIZE;
  kassert(vmm_map_user_page(boundary_va,
                            (uint64_t)(uintptr_t)boundary_page,
                            XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE |
                                XAIOS_VMM_USER,
                            process_tables, process_table_count) == XAIOS_OK);
  vmm_switch_user_aspace(process_tables, process_table_count);
  kassert(vmm_translate(boundary_va, &translated, &flags) == XAIOS_OK);
  kassert(translated == (uint64_t)(uintptr_t)boundary_page);
  kassert((flags & (XAIOS_VMM_USER | XAIOS_VMM_WRITABLE)) ==
          (XAIOS_VMM_USER | XAIOS_VMM_WRITABLE));
  kassert(vmm_validate_range_flags(
              boundary_va, 16U,
              XAIOS_VMM_PRESENT | XAIOS_VMM_USER | XAIOS_VMM_WRITABLE,
              XAIOS_VMM_EXECUTABLE) == XAIOS_OK);
  kassert(vmm_validate_user_buffer(boundary_va, 16U,
                                   XAIOS_VMM_WRITABLE) == XAIOS_OK);
  uint64_t *second_code_table =
      (uint64_t *)(uintptr_t)process_tables[1];
  kassert((second_code_table[0] & PTE_VALID) != 0U);
  kassert(vmm_unmap_user_page(boundary_va, process_tables,
                              process_table_count) == XAIOS_OK);
  kassert(second_code_table[0] == 0U);
  invalidate_tlb_page(boundary_va);
  kassert(vmm_translate(boundary_va, &translated, &flags) ==
          XAIOS_ERR_INVALID);
  vmm_switch_user_aspace(0, 0U);
  pmm_free_page(boundary_page);
  vmm_destroy_user_aspace(process_tables, process_table_count);
  klog("VMM map/unmap self-test passed mode=per-cpu-user-aspace\n");
}
