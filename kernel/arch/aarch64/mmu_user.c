/* Per-process user address spaces.
 *
 * The user half of what was mmu.c, moved here whole: creating the leaf tables
 * a process's code, data and stack windows live in, mapping and unmapping one
 * user page through them, pointing this CPU's directory at a process's tables
 * on a context switch, and returning the tables when the process exits. The
 * callers are the shared, architecture-independent process code, through the
 * vmm.h interface, so nothing crossing this boundary is new.
 *
 * It is a module rather than part of mmu.c because everything here is about
 * the 2 MiB windows userspace occupies, while the rest of mmu.c is the
 * kernel's own map. The leaf tables are allocated and the entry arithmetic is
 * built by mmu_boot.c and reached through mmu_internal.h, so this file names
 * no PTE bits of its own, and every fence it makes stays exactly where it
 * was: switching this CPU's directory is a full local invalidation, as it
 * always was.
 */
#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/pmm.h>
#include <xaios/vmm.h>

#include "mmu_internal.h"
#include "platform.h"

#define USER_CODE_L2_INDEX \
  ((uint32_t)((XAIOS_USER_BASE >> 21U) & UINT64_C(0x1ff)))
#define USER_STACK_L2_INDEX \
  ((uint32_t)(((XAIOS_USER_STACK_TOP - PAGE_SIZE) >> 21U) & UINT64_C(0x1ff)))

static uint64_t *current_user_directory(void) {
  return aarch64_platform_user_page_directory(
      aarch64_platform_current_ordinal());
}

/* --- Per-process address space APIs --- */

static xaios_status_t user_l3_slot(uint64_t virtual_address,
                                   uint32_t *out_slot) {
  uint32_t l2_index =
      (uint32_t)((virtual_address >> 21U) & UINT64_C(0x1ff));
  if (l2_index >= USER_CODE_L2_INDEX &&
      l2_index < USER_CODE_L2_INDEX + USER_CODE_WINDOWS) {
    *out_slot = l2_index - USER_CODE_L2_INDEX;
    return XAIOS_OK;
  }
  if (l2_index == USER_STACK_L2_INDEX) {
    *out_slot = USER_CODE_WINDOWS;
    return XAIOS_OK;
  }
  return XAIOS_ERR_INVALID;
}

void vmm_create_user_aspace(uint64_t l3_tables[], uint32_t max_tables,
                            uint32_t *out_count) {
  kassert(l3_tables != 0 && out_count != 0 &&
          max_tables >= USER_ASPACE_L3_TABLES);
  for (uint32_t i = 0; i < max_tables; ++i) {
    l3_tables[i] = 0;
  }
  /* Eight 2 MiB code/data spans and one independent stack span. */
  for (uint32_t i = 0; i < USER_ASPACE_L3_TABLES; ++i) {
    void *page = pmm_alloc_page();
    kassert(page != 0);
    uint64_t *table = (uint64_t *)page;
    for (uint64_t j = 0; j < 512; ++j) {
      table[j] = 0;
    }
    l3_tables[i] = (uint64_t)(uintptr_t)page;
  }
  *out_count = USER_ASPACE_L3_TABLES;
  klog("vmm: created user aspace l3_count=%u\n", *out_count);
}

xaios_status_t vmm_map_user_page(uint64_t virtual_address,
                                uint64_t physical_address, uint32_t flags,
                                uint64_t l3_tables[], uint32_t l3_count) {
  if ((virtual_address & (PAGE_SIZE - 1)) != 0 ||
      (physical_address & (PAGE_SIZE - 1)) != 0 ||
      (flags & XAIOS_VMM_PRESENT) == 0) {
    return XAIOS_ERR_INVALID;
  }
  if (virtual_address < XAIOS_USER_BASE || virtual_address >= XAIOS_USER_LIMIT) {
    return XAIOS_ERR_INVALID;
  }

  uint64_t l3_index = (virtual_address >> 12) & 0x1ffU;
  uint32_t l3_slot = 0U;
  if (user_l3_slot(virtual_address, &l3_slot) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  if (l3_slot >= l3_count || l3_tables[l3_slot] == 0) {
    return XAIOS_ERR_INVALID;
  }

  uint64_t *l3 = (uint64_t *)(uintptr_t)l3_tables[l3_slot];
  l3[l3_index] = a64mmu_page_descriptor(physical_address,
                                        a64mmu_attrs_from_flags(flags));
  return XAIOS_OK;
}

xaios_status_t vmm_unmap_user_page(uint64_t virtual_address,
                                  uint64_t l3_tables[], uint32_t l3_count) {
  if ((virtual_address & (PAGE_SIZE - 1)) != 0) {
    return XAIOS_ERR_INVALID;
  }

  uint64_t l3_index = (virtual_address >> 12) & 0x1ffU;
  uint32_t l3_slot = 0U;
  if (user_l3_slot(virtual_address, &l3_slot) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  if (l3_slot < l3_count && l3_tables[l3_slot] != 0) {
    uint64_t *l3 = (uint64_t *)(uintptr_t)l3_tables[l3_slot];
    l3[l3_index] = 0;
  }

  return XAIOS_OK;
}

void vmm_switch_user_aspace(uint64_t l3_tables[], uint32_t l3_count) {
  uint64_t *l2 = current_user_directory();
  kassert(l2 != 0);

  /* Clear every owned slot before installing the next process. */
  for (uint32_t index = 0U; index < USER_CODE_WINDOWS; ++index) {
    l2[USER_CODE_L2_INDEX + index] = 0U;
  }
  l2[USER_STACK_L2_INDEX] = 0;
  if (l3_tables != 0 && l3_count >= USER_ASPACE_L3_TABLES) {
    for (uint32_t index = 0U; index < USER_CODE_WINDOWS; ++index) {
      if (l3_tables[index] != 0U) {
        l2[USER_CODE_L2_INDEX + index] =
            a64mmu_table_descriptor((uint64_t *)(uintptr_t)l3_tables[index]);
      }
    }
    if (l3_tables[USER_CODE_WINDOWS] != 0U) {
      l2[USER_STACK_L2_INDEX] =
          a64mmu_table_descriptor(
              (uint64_t *)(uintptr_t)l3_tables[USER_CODE_WINDOWS]);
    }
  }

  /* Full TLB invalidation */
  __asm__ volatile(
      "dsb ishst\n"
      "tlbi vmalle1is\n"
      "dsb ish\n"
      "isb\n"
      :
      :
      : "memory");
}

void vmm_destroy_user_aspace(uint64_t l3_tables[], uint32_t l3_count) {
  /* Invalidate TLB before freeing pages to prevent stale entries
   * from pointing to reallocated physical memory */
  __asm__ volatile("dsb ishst\n\t"
                   "tlbi vmalle1is\n\t"
                   "dsb ish\n\t"
                   "isb");
  for (uint32_t i = 0; i < l3_count; ++i) {
    if (l3_tables[i] != 0) {
      pmm_free_page((void *)(uintptr_t)l3_tables[i]);
      l3_tables[i] = 0;
    }
  }
}
