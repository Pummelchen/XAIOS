/* Runtime x86_64 mappings: the walk's reader, the kernel mapping entry
 * points, range and user-buffer validation and the VMM self-test.
 *
 * The boot map and the page-table helpers those entry points are built on --
 * the PTE encoding, the allocate-or-find walk, the per-CPU mirror and the
 * EFER.NXE/CR0.WP enable sequence -- are in mmu_boot.c, and the per-process
 * user address spaces are in mmu_user.c. Every side shares the descriptor
 * encoding and the helper declarations in mmu_internal.h, so this file names
 * no PTE bits of its own beyond the decode and the one bit the self-test
 * inspects. Nothing here changed order, table layout or invalidation; it
 * moved whole.
 */
#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/pmm.h>
#include <xaios/vmm.h>
/* x86_64 enters long mode with paging already on -- there is no untranslated
   window here -- so exclusives are always legal. The predicate exists because
   the shared spinlock asks; see kernel/include/xaios/spinlock.h. */
uint32_t xaios_translation_enabled(void) { return 1U; }

#include "mmu_internal.h"
#include "platform.h"

static uint32_t user_address(uint64_t virtual_address) {
  return virtual_address >= XAIOS_USER_BASE &&
         virtual_address < XAIOS_USER_LIMIT;
}

static void invalidate_page(uint64_t virtual_address) {
  x86_64_platform_invalidate_page_all(virtual_address);
}

static uint32_t pte_to_flags(uint64_t pte) {
  uint32_t flags = XAIOS_VMM_PRESENT;
  if ((pte & PTE_WRITABLE) != 0U) flags |= XAIOS_VMM_WRITABLE;
  if ((pte & PTE_USER) != 0U) flags |= XAIOS_VMM_USER;
  if ((pte & PTE_DEVICE) != 0U) flags |= XAIOS_VMM_DEVICE;
  if ((pte & PTE_NX) == 0U) flags |= XAIOS_VMM_EXECUTABLE;
  if ((pte & PTE_GLOBAL) == 0U) flags |= XAIOS_VMM_NG;
  return flags;
}

static uint32_t effective_flags(uint64_t pml4e, uint64_t pdpte,
                                uint64_t pde, uint64_t pte) {
  uint32_t flags = pte_to_flags(pte);
  if ((pml4e & PTE_USER) == 0U || (pdpte & PTE_USER) == 0U ||
      (pde & PTE_USER) == 0U) {
    flags &= (uint32_t)~(uint32_t)XAIOS_VMM_USER;
  }
  if ((pml4e & PTE_WRITABLE) == 0U || (pdpte & PTE_WRITABLE) == 0U ||
      (pde & PTE_WRITABLE) == 0U) {
    flags &= (uint32_t)~(uint32_t)XAIOS_VMM_WRITABLE;
  }
  if (((pml4e | pdpte | pde | pte) & PTE_NX) != 0U) {
    flags &= (uint32_t)~(uint32_t)XAIOS_VMM_EXECUTABLE;
  }
  return flags;
}

xaios_status_t vmm_translate(uint64_t virtual_address,
                            uint64_t *physical_address, uint32_t *flags) {
  if (physical_address == 0 || flags == 0) return XAIOS_ERR_INVALID;
  const uint64_t *root =
      (const uint64_t *)(uintptr_t)x86mmu_current_root_address();
  uint64_t pml4e = root[(virtual_address >> 39U) & 0x1ffU];
  if ((pml4e & PTE_PRESENT) == 0U) return XAIOS_ERR_INVALID;
  const uint64_t *pdpt =
      (const uint64_t *)(uintptr_t)(pml4e & PTE_ADDRESS_MASK);
  uint64_t pdpte = pdpt[(virtual_address >> 30U) & 0x1ffU];
  if ((pdpte & PTE_PRESENT) == 0U) return XAIOS_ERR_INVALID;
  if ((pdpte & PTE_LARGE) != 0U) {
    *physical_address = (pdpte & PTE_HUGE_ADDRESS_MASK) +
                        (virtual_address & (HUGE_PAGE_SIZE - 1U));
    *flags = effective_flags(pml4e, pdpte, pdpte, pdpte);
    return XAIOS_OK;
  }
  const uint64_t *pd =
      (const uint64_t *)(uintptr_t)(pdpte & PTE_ADDRESS_MASK);
  uint64_t pde = pd[(virtual_address >> 21U) & 0x1ffU];
  if ((pde & PTE_PRESENT) == 0U) return XAIOS_ERR_INVALID;
  if ((pde & PTE_LARGE) != 0U) {
    *physical_address = (pde & PTE_LARGE_ADDRESS_MASK) +
                        (virtual_address & (LARGE_PAGE_SIZE - 1U));
    *flags = effective_flags(pml4e, pdpte, pde, pde);
    return XAIOS_OK;
  }
  const uint64_t *pt =
      (const uint64_t *)(uintptr_t)(pde & PTE_ADDRESS_MASK);
  uint64_t pte = pt[(virtual_address >> 12U) & 0x1ffU];
  if ((pte & PTE_PRESENT) == 0U) return XAIOS_ERR_INVALID;
  *physical_address =
      (pte & PTE_ADDRESS_MASK) + (virtual_address & (PAGE_SIZE - 1U));
  *flags = effective_flags(pml4e, pdpte, pde, pte);
  return XAIOS_OK;
}

xaios_status_t vmm_validate_range_flags(uint64_t virtual_address,
                                        uint64_t size,
                                        uint32_t required_flags,
                                        uint32_t forbidden_flags) {
  if (size == 0U || size - 1U > UINT64_MAX - virtual_address) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t page = x86mmu_align_down(virtual_address, PAGE_SIZE);
  uint64_t last = x86mmu_align_down(virtual_address + size - 1U, PAGE_SIZE);
  for (;;) {
    uint64_t physical;
    uint32_t actual;
    if (vmm_translate(page, &physical, &actual) != XAIOS_OK ||
        (actual & required_flags) != required_flags ||
        (actual & forbidden_flags) != 0U) {
      return XAIOS_ERR_INVALID;
    }
    if (page == last) return XAIOS_OK;
    page += PAGE_SIZE;
  }
}

xaios_status_t vmm_map_page(uint64_t virtual_address,
                           uint64_t physical_address, uint32_t flags) {
  if ((virtual_address & (PAGE_SIZE - 1U)) != 0U ||
      (physical_address & (PAGE_SIZE - 1U)) != 0U ||
      (flags & XAIOS_VMM_PRESENT) == 0U) {
    return XAIOS_ERR_INVALID;
  }
  uint32_t is_user = user_address(virtual_address);
  uint64_t root = is_user != 0U ? x86mmu_current_root_address()
                                : x86mmu_shared_root_address();
  uint64_t *pt = x86mmu_ensure_pt((uint64_t *)(uintptr_t)root,
                                  virtual_address, flags);
  pt[(virtual_address >> 12U) & 0x1ffU] =
      physical_address | x86mmu_flags_to_pte(flags);
  if (is_user == 0U) x86mmu_sync_kernel_hierarchy(virtual_address);
  invalidate_page(virtual_address);
  return XAIOS_OK;
}

xaios_status_t vmm_unmap_page(uint64_t virtual_address) {
  if ((virtual_address & (PAGE_SIZE - 1U)) != 0U) return XAIOS_ERR_INVALID;
  uint32_t is_user = user_address(virtual_address);
  uint64_t root = is_user != 0U ? x86mmu_current_root_address()
                                : x86mmu_shared_root_address();
  uint64_t *pt = x86mmu_ensure_pt((uint64_t *)(uintptr_t)root,
                                  virtual_address, 0U);
  pt[(virtual_address >> 12U) & 0x1ffU] = 0U;
  if (is_user == 0U) x86mmu_sync_kernel_hierarchy(virtual_address);
  invalidate_page(virtual_address);
  return XAIOS_OK;
}

xaios_status_t vmm_map_large_page(uint64_t virtual_address,
                                 uint64_t physical_address, uint32_t flags) {
  if ((virtual_address & (LARGE_PAGE_SIZE - 1U)) != 0U ||
      (physical_address & (LARGE_PAGE_SIZE - 1U)) != 0U ||
      (flags & XAIOS_VMM_PRESENT) == 0U ||
      (flags & XAIOS_VMM_USER) != 0U || user_address(virtual_address) != 0U) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t *pd = x86mmu_ensure_pd(
      (uint64_t *)(uintptr_t)x86mmu_shared_root_address(), virtual_address);
  if (pd == 0) return XAIOS_ERR_NO_MEMORY;
  uint32_t pd_index = (uint32_t)((virtual_address >> 21U) & 0x1ffU);
  if ((pd[pd_index] & PTE_PRESENT) != 0U) return XAIOS_ERR_BUSY;
  pd[pd_index] = physical_address | x86mmu_flags_to_pte(flags) | PTE_LARGE;
  x86mmu_sync_kernel_hierarchy(virtual_address);
  invalidate_page(virtual_address);
  return XAIOS_OK;
}

xaios_status_t vmm_map_gigantic_page(uint64_t virtual_address,
                                    uint64_t physical_address,
                                    uint32_t flags) {
  if ((virtual_address & (HUGE_PAGE_SIZE - 1U)) != 0U ||
      (physical_address & (HUGE_PAGE_SIZE - 1U)) != 0U ||
      (flags & XAIOS_VMM_PRESENT) == 0U ||
      (flags & XAIOS_VMM_USER) != 0U || user_address(virtual_address) != 0U) {
    return XAIOS_ERR_INVALID;
  }
  uint32_t pml4_index = (uint32_t)((virtual_address >> 39U) & 0x1ffU);
  uint32_t pdpt_index = (uint32_t)((virtual_address >> 30U) & 0x1ffU);
  uint64_t *root = (uint64_t *)(uintptr_t)x86mmu_shared_root_address();
  uint64_t *pdpt;
  if ((root[pml4_index] & PTE_PRESENT) == 0U) {
    pdpt = x86mmu_allocate_table();
    if (pdpt == 0) return XAIOS_ERR_NO_MEMORY;
    root[pml4_index] = x86mmu_table_entry(pdpt, 0U);
  } else {
    pdpt = (uint64_t *)(uintptr_t)(root[pml4_index] & PTE_ADDRESS_MASK);
  }
  if ((pdpt[pdpt_index] & PTE_PRESENT) != 0U) return XAIOS_ERR_BUSY;
  pdpt[pdpt_index] = physical_address | x86mmu_flags_to_pte(flags) | PTE_LARGE;
  x86mmu_sync_kernel_hierarchy(virtual_address);
  invalidate_page(virtual_address);
  return XAIOS_OK;
}

xaios_status_t vmm_unmap_gigantic_page(uint64_t virtual_address) {
  if ((virtual_address & (HUGE_PAGE_SIZE - 1U)) != 0U ||
      user_address(virtual_address) != 0U) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t *root = (uint64_t *)(uintptr_t)x86mmu_shared_root_address();
  uint64_t pml4e = root[(virtual_address >> 39U) & 0x1ffU];
  if ((pml4e & PTE_PRESENT) == 0U) return XAIOS_ERR_INVALID;
  uint64_t *pdpt = (uint64_t *)(uintptr_t)(pml4e & PTE_ADDRESS_MASK);
  uint32_t index = (uint32_t)((virtual_address >> 30U) & 0x1ffU);
  if ((pdpt[index] & (PTE_PRESENT | PTE_LARGE)) !=
      (PTE_PRESENT | PTE_LARGE)) {
    return XAIOS_ERR_INVALID;
  }
  pdpt[index] = 0U;
  x86mmu_sync_kernel_hierarchy(virtual_address);
  invalidate_page(virtual_address);
  return XAIOS_OK;
}

xaios_status_t vmm_unmap_large_page(uint64_t virtual_address) {
  if ((virtual_address & (LARGE_PAGE_SIZE - 1U)) != 0U ||
      user_address(virtual_address) != 0U) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t *pd = x86mmu_find_pd(
      (uint64_t *)(uintptr_t)x86mmu_shared_root_address(), virtual_address);
  if (pd == 0) return XAIOS_ERR_INVALID;
  uint32_t pd_index = (uint32_t)((virtual_address >> 21U) & 0x1ffU);
  if ((pd[pd_index] & (PTE_PRESENT | PTE_LARGE)) !=
      (PTE_PRESENT | PTE_LARGE)) {
    return XAIOS_ERR_INVALID;
  }
  pd[pd_index] = 0U;
  x86mmu_sync_kernel_hierarchy(virtual_address);
  invalidate_page(virtual_address);
  return XAIOS_OK;
}

xaios_status_t vmm_validate_user_buffer(uint64_t virtual_address,
                                       uint64_t size,
                                       uint32_t required_flags) {
  if (size == 0U || virtual_address < XAIOS_USER_BASE ||
      virtual_address + size < virtual_address ||
      virtual_address + size > XAIOS_USER_LIMIT) {
    return XAIOS_ERR_INVALID;
  }
  return vmm_validate_range_flags(virtual_address, size,
                                  required_flags | XAIOS_VMM_USER, 0U);
}

void vmm_self_test(void) {
  void *page = pmm_alloc_page();
  kassert(page != 0);
  uint64_t address = XAIOS_USER_BASE + LARGE_PAGE_SIZE;
  kassert(vmm_map_page(address, (uint64_t)(uintptr_t)page,
                       XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE |
                           XAIOS_VMM_USER) == XAIOS_OK);
  uint64_t physical;
  uint32_t flags;
  kassert(vmm_translate(address, &physical, &flags) == XAIOS_OK);
  klog("VMM: x86 self-test translated phys=0x%lx flags=0x%x\n",
       physical, flags);
  kassert(physical == (uint64_t)(uintptr_t)page);
  kassert((flags & (XAIOS_VMM_USER | XAIOS_VMM_WRITABLE)) ==
          (XAIOS_VMM_USER | XAIOS_VMM_WRITABLE));
  kassert(vmm_unmap_page(address) == XAIOS_OK);
  pmm_free_page(page);

  const uint64_t large_va = UINT64_C(0x7000000000);
  const uint64_t large_pa = UINT64_C(0x200000);
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
                        &physical, &flags) == XAIOS_OK);
  kassert(physical == large_pa + XAIOS_VMM_LARGE_PAGE_SIZE - 1U);
  kassert(vmm_unmap_large_page(large_va) == XAIOS_OK);
  kassert(vmm_translate(large_va, &physical, &flags) == XAIOS_ERR_INVALID);
  klog("VMM: x86 2 MiB large-page map/unmap self-test passed\n");

  const uint64_t gigantic_va = UINT64_C(0x8000000000);
  const uint64_t gigantic_pa = UINT64_C(0x40000000);
  kassert(vmm_map_gigantic_page(
              gigantic_va, gigantic_pa,
              XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE) == XAIOS_OK);
  kassert(vmm_translate(gigantic_va + XAIOS_VMM_GIGANTIC_PAGE_SIZE - 1U,
                        &physical, &flags) == XAIOS_OK);
  kassert(physical == gigantic_pa + XAIOS_VMM_GIGANTIC_PAGE_SIZE - 1U);
  kassert(vmm_unmap_gigantic_page(gigantic_va) == XAIOS_OK);
  kassert(vmm_translate(gigantic_va, &physical, &flags) ==
          XAIOS_ERR_INVALID);
  kassert(x86_64_platform_tlb_shootdown_count() >= 2U);
  klog("VMM: x86 1 GiB page and SMP address-specific invalidation self-test passed shootdowns=%lu\n",
       x86_64_platform_tlb_shootdown_count());

  uint64_t process_tables[USER_ASPACE_L3_TABLES];
  uint32_t process_table_count = 0U;
  vmm_create_user_aspace(process_tables, USER_ASPACE_L3_TABLES,
                         &process_table_count);
  kassert(process_table_count == USER_ASPACE_L3_TABLES);
  void *boundary_page = pmm_alloc_page();
  kassert(boundary_page != 0);
  uint64_t boundary_address = XAIOS_USER_BASE + LARGE_PAGE_SIZE;
  kassert(vmm_map_user_page(boundary_address,
                            (uint64_t)(uintptr_t)boundary_page,
                            XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE |
                                XAIOS_VMM_USER,
                            process_tables, process_table_count) == XAIOS_OK);
  uint64_t *second_code_table =
      (uint64_t *)(uintptr_t)process_tables[1];
  kassert((second_code_table[0] & PTE_PRESENT) != 0U);
  kassert(vmm_unmap_user_page(boundary_address, process_tables,
                              process_table_count) == XAIOS_OK);
  kassert(second_code_table[0] == 0U);
  pmm_free_page(boundary_page);
  vmm_destroy_user_aspace(process_tables, process_table_count);
  klog("VMM: x86 map/unmap self-test passed\n");
}
