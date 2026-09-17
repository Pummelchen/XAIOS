/* Per-process user address spaces for RISC-V.
 *
 * This was the tail of mmu.c, moved here whole. The shape is unchanged: one
 * leaf table per 2 MiB window a process may use, a per-hart user directory
 * that switching points at them, and the shared map/translate/unmap entry
 * points the kernel calls.
 *
 * What it reaches back into mmu_map.c for is named, never a pointer into that
 * file's state: riscv64_mmu_allocate_table() for a leaf table, and
 * riscv64_mmu_user_directory_address() for this hart's directory -- a number,
 * which is what keeps the hart table in the one translation unit vmm_init
 * fills it in. The fences keep the exact sequences they had.
 */
#include <xaios/pmm.h>
#include <xaios/smp.h>
#include <xaios/status.h>
#include <xaios/vmm.h>

#include "mmu_map.h"

static xaios_status_t user_l3_slot(uint64_t virtual_address,
                                   uint32_t *out_slot) {
  uint32_t l2_index = index_at(virtual_address, 1U);
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

/* One leaf table per 2 MiB window a process may use: the code and data
   windows from XAIOS_USER_BASE, and the one holding the stack. */
void vmm_create_user_aspace(uint64_t l3_tables[], uint32_t max_tables,
                            uint32_t *out_count) {
  uint32_t count = 0U;
  if (l3_tables == 0 || out_count == 0) return;
  for (uint32_t i = 0U; i < max_tables; ++i) l3_tables[i] = 0U;
  if (max_tables >= USER_ASPACE_L3_TABLES) {
    for (uint32_t i = 0U; i < USER_ASPACE_L3_TABLES; ++i) {
      uint64_t *table = riscv64_mmu_allocate_table();
      if (table == 0) {
        vmm_destroy_user_aspace(l3_tables, i);
        for (uint32_t j = 0U; j < i; ++j) l3_tables[j] = 0U;
        *out_count = 0U;
        return;
      }
      l3_tables[i] = (uint64_t)(uintptr_t)table;
    }
    count = USER_ASPACE_L3_TABLES;
  }
  *out_count = count;
}

xaios_status_t vmm_map_user_page(uint64_t virtual_address,
                                 uint64_t physical_address, uint32_t flags,
                                 uint64_t l3_tables[], uint32_t l3_count) {
  uint32_t slot = 0U;
  if ((virtual_address & (PAGE_SIZE - 1U)) != 0U ||
      (physical_address & (PAGE_SIZE - 1U)) != 0U ||
      (flags & XAIOS_VMM_PRESENT) == 0U) {
    return XAIOS_ERR_INVALID;
  }
  if (virtual_address < XAIOS_USER_BASE || virtual_address >= XAIOS_USER_LIMIT) {
    return XAIOS_ERR_INVALID;
  }
  if (l3_tables == 0 || user_l3_slot(virtual_address, &slot) != XAIOS_OK ||
      slot >= l3_count || l3_tables[slot] == 0U) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t *l3 = (uint64_t *)(uintptr_t)l3_tables[slot];
  l3[index_at(virtual_address, 0U)] =
      pte_for(physical_address, flags_to_pte(flags | XAIOS_VMM_USER));
  riscv64_mmu_flush_one(virtual_address);
  return XAIOS_OK;
}

xaios_status_t vmm_unmap_user_page(uint64_t virtual_address,
                                   uint64_t l3_tables[], uint32_t l3_count) {
  uint32_t slot = 0U;
  if ((virtual_address & (PAGE_SIZE - 1U)) != 0U) return XAIOS_ERR_INVALID;
  if (user_l3_slot(virtual_address, &slot) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  if (l3_tables != 0 && slot < l3_count && l3_tables[slot] != 0U) {
    uint64_t *l3 = (uint64_t *)(uintptr_t)l3_tables[slot];
    l3[index_at(virtual_address, 0U)] = 0U;
  }
  riscv64_mmu_flush_one(virtual_address);
  return XAIOS_OK;
}

/* Point this hart's user directory at a process's leaf tables, or at nothing.
   Pointer entries carry no permission bits: on RISC-V a non-leaf entry with U
   set is reserved, which is the one place this differs from x86-64. */
/* Local, and deliberately so -- this is the one fence in the file that is not
   made global. The directory being rewritten is this hart's own: every hart
   has its own copy, reached through its own root, and pointing this one at a
   different process changes nothing another hart can translate. Broadcasting
   it would cost an ecall on every context switch to fence harts whose tables
   were not touched. The leaf tables underneath *are* shared, which is why
   vmm_map_user_page and vmm_unmap_user_page do fence globally. */
void vmm_switch_user_aspace(uint64_t l3_tables[], uint32_t l3_count) {
  uint32_t cpu = smp_cpu_id();
  uint64_t directory_address = riscv64_mmu_user_directory_address(cpu);
  if (directory_address == 0U) {
    riscv64_mmu_flush_all();
    return;
  }
  uint64_t *directory = (uint64_t *)(uintptr_t)directory_address;
  for (uint32_t index = 0U; index < USER_CODE_WINDOWS; ++index) {
    directory[USER_CODE_L2_INDEX + index] = 0U;
  }
  directory[USER_STACK_L2_INDEX] = 0U;
  if (l3_tables != 0 && l3_count >= USER_ASPACE_L3_TABLES) {
    for (uint32_t index = 0U; index < USER_CODE_WINDOWS; ++index) {
      if (l3_tables[index] != 0U) {
        directory[USER_CODE_L2_INDEX + index] = pte_for(l3_tables[index], 0U);
      }
    }
    if (l3_tables[USER_CODE_WINDOWS] != 0U) {
      directory[USER_STACK_L2_INDEX] =
          pte_for(l3_tables[USER_CODE_WINDOWS], 0U);
    }
  }
  riscv64_mmu_flush_all();
}

void vmm_destroy_user_aspace(uint64_t l3_tables[], uint32_t l3_count) {
  /* Flushed before the pages go back, so no stale translation can point at
     memory the allocator has handed to someone else -- and on every hart,
     not just this one. These pages held a process's leaf tables, and any hart
     that ran that process reached them through its own directory; a fence of
     one TLB here leaves the others translating into freed memory, which is
     precisely the corruption this whole mechanism exists to stop. */
  riscv64_mmu_flush_all_everywhere();
  for (uint32_t i = 0U; i < l3_count; ++i) {
    if (l3_tables[i] != 0U) {
      pmm_free_page((void *)(uintptr_t)l3_tables[i]);
      l3_tables[i] = 0U;
    }
  }
}
