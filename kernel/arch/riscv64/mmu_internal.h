/* Private interface shared by mmu.c, its two modules and the shootdown test.
 *
 * mmu_shootdown.h already carries what mmu.c and mmu_shootdown.c share:
 * PAGE_SIZE, VMM_MAX_HARTS, klog and vmm_panic, and the shootdown names the
 * test calls. This header is included from every side and adds only what the
 * split introduced -- the four fences the page-table code calls, which now
 * live in mmu_tlb.c, and the named structural probes mmu_selftest.c asks of
 * the shared kernel root.
 *
 * It exists rather than growing mmu_shootdown.h because that header is the
 * interface to the test in mmu_shootdown.c and nothing else; the declarations
 * here are the page-table side of the boundary.
 */
#ifndef XAIOS_ARCH_RISCV64_MMU_INTERNAL_H
#define XAIOS_ARCH_RISCV64_MMU_INTERNAL_H

#include "mmu_shootdown.h"

/* Address-space fences, defined in mmu_tlb.c and called by the walk, map and
   unmap paths in mmu.c. Named rather than static because they now cross a
   translation unit; each keeps the exact fence sequence it had. */
void riscv64_mmu_flush_all(void);
void riscv64_mmu_flush_all_everywhere(void);
void riscv64_mmu_flush_one(uint64_t virtual_address);
void riscv64_mmu_flush_leaf(uint64_t virtual_address, uint32_t level);

/* What the MMU self-test in mmu_selftest.c asks of the shared kernel root,
   answered into the caller's own locals. The test used to walk these tables
   itself; a named probe is what crosses now, never a pointer into mmu.c's
   file-scope state. `riscv64_mmu_root_level` is declared in mmu_shootdown.h. */
uint32_t riscv64_mmu_on_shared_root(void);
uint32_t riscv64_mmu_leaf_present(uint64_t virtual_address, uint32_t level);
uint32_t riscv64_mmu_leaf_in_root(uint64_t virtual_address, uint32_t level);

#endif /* XAIOS_ARCH_RISCV64_MMU_INTERNAL_H */
