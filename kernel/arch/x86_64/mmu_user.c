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
 * the 2 MiB windows userspace occupies, while mmu_boot.c owns the kernel's own
 * map and the walk underneath it and mmu.c is the runtime mapping interface.
 * The leaf tables are allocated and the entry encoding is built by mmu_boot.c
 * and reached through mmu_internal.h, so this file names no PTE bits of its
 * own, and every fence it makes stays exactly where it was: switching this
 * CPU's directory is a full local invalidation, as it always was.
 */
#include <xaios/assert.h>
#include <xaios/pmm.h>
#include <xaios/vmm.h>

#include "mmu_internal.h"
#include "platform.h"

#define USER_CODE_PD_INDEX \
  ((uint32_t)((XAIOS_USER_BASE >> 21U) & UINT64_C(0x1ff)))
#define USER_STACK_PD_INDEX \
  ((uint32_t)(((XAIOS_USER_STACK_TOP - PAGE_SIZE) >> 21U) & \
              UINT64_C(0x1ff)))

static uint64_t *current_user_directory(void) {
  return x86_64_platform_user_page_directory(
      x86_64_platform_current_ordinal());
}

/* --- Per-process address space APIs --- */

static xaios_status_t user_l3_slot(uint64_t virtual_address,
                                   uint32_t *out_slot) {
  uint32_t pd_index =
      (uint32_t)((virtual_address >> 21U) & UINT64_C(0x1ff));
  if (pd_index >= USER_CODE_PD_INDEX &&
      pd_index < USER_CODE_PD_INDEX + USER_CODE_WINDOWS) {
    *out_slot = pd_index - USER_CODE_PD_INDEX;
    return XAIOS_OK;
  }
  if (pd_index == USER_STACK_PD_INDEX) {
    *out_slot = USER_CODE_WINDOWS;
    return XAIOS_OK;
  }
  return XAIOS_ERR_INVALID;
}

void vmm_create_user_aspace(uint64_t l3_tables[], uint32_t max_tables,
                            uint32_t *out_count) {
  kassert(l3_tables != 0 && out_count != 0 &&
          max_tables >= USER_ASPACE_L3_TABLES);
  for (uint32_t index = 0U; index < max_tables; ++index) l3_tables[index] = 0U;
  for (uint32_t index = 0U; index < USER_ASPACE_L3_TABLES; ++index) {
    uint64_t *pt = x86mmu_allocate_table();
    kassert(pt != 0);
    l3_tables[index] = (uint64_t)(uintptr_t)pt;
  }
  *out_count = USER_ASPACE_L3_TABLES;
}

xaios_status_t vmm_map_user_page(uint64_t virtual_address,
                                uint64_t physical_address, uint32_t flags,
                                uint64_t l3_tables[], uint32_t l3_count) {
  if ((virtual_address & (PAGE_SIZE - 1U)) != 0U ||
      (physical_address & (PAGE_SIZE - 1U)) != 0U ||
      virtual_address < XAIOS_USER_BASE || virtual_address >= XAIOS_USER_LIMIT ||
      (flags & XAIOS_VMM_PRESENT) == 0U || l3_tables == 0) {
    return XAIOS_ERR_INVALID;
  }
  uint32_t slot = 0U;
  if (user_l3_slot(virtual_address, &slot) != XAIOS_OK ||
      slot >= l3_count || l3_tables[slot] == 0U) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t *pt = (uint64_t *)(uintptr_t)l3_tables[slot];
  pt[(virtual_address >> 12U) & 0x1ffU] =
      physical_address | x86mmu_flags_to_pte(flags | XAIOS_VMM_USER);
  return XAIOS_OK;
}

xaios_status_t vmm_unmap_user_page(uint64_t virtual_address,
                                  uint64_t l3_tables[], uint32_t l3_count) {
  if ((virtual_address & (PAGE_SIZE - 1U)) != 0U || l3_tables == 0) {
    return XAIOS_ERR_INVALID;
  }
  uint32_t slot = 0U;
  if (user_l3_slot(virtual_address, &slot) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  if (slot < l3_count && l3_tables[slot] != 0U) {
    uint64_t *pt = (uint64_t *)(uintptr_t)l3_tables[slot];
    pt[(virtual_address >> 12U) & 0x1ffU] = 0U;
  }
  return XAIOS_OK;
}

void vmm_switch_user_aspace(uint64_t l3_tables[], uint32_t l3_count) {
  uint64_t *user_directory = current_user_directory();
  kassert(user_directory != 0);
  for (uint32_t index = 0U; index < USER_CODE_WINDOWS; ++index) {
    user_directory[USER_CODE_PD_INDEX + index] = 0U;
  }
  user_directory[USER_STACK_PD_INDEX] = 0U;
  if (l3_tables != 0 && l3_count >= USER_ASPACE_L3_TABLES) {
    for (uint32_t index = 0U; index < USER_CODE_WINDOWS; ++index) {
      if (l3_tables[index] != 0U) {
        user_directory[USER_CODE_PD_INDEX + index] =
            x86mmu_table_entry((uint64_t *)(uintptr_t)l3_tables[index],
                               PTE_USER);
      }
    }
    if (l3_tables[USER_CODE_WINDOWS] != 0U) {
      user_directory[USER_STACK_PD_INDEX] =
          x86mmu_table_entry((uint64_t *)(uintptr_t)l3_tables[USER_CODE_WINDOWS],
                             PTE_USER);
    }
  }
  x86mmu_flush_tlb();
}

void vmm_destroy_user_aspace(uint64_t l3_tables[], uint32_t l3_count) {
  vmm_switch_user_aspace(0, 0U);
  for (uint32_t index = 0U; index < l3_count; ++index) {
    if (l3_tables[index] != 0U) {
      pmm_free_page((void *)(uintptr_t)l3_tables[index]);
      l3_tables[index] = 0U;
    }
  }
}
