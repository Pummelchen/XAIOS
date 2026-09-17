/* Private interface of the x86_64 page tables, shared by mmu.c, mmu_boot.c
 * and mmu_user.c.
 *
 * mmu_boot.c owns the boot map and the walk underneath every mapping: the
 * 4-level tables build_tables lays down, the per-CPU roots that copy them,
 * the allocate-or-find helpers every mapping goes through, the per-CPU mirror
 * kernel mappings are published to, and the EFER.NXE/CR0.WP enable sequence
 * vmm_init ends with. mmu.c keeps the runtime entry points -- translate, map,
 * unmap, range and user-buffer validation and the self-test -- and mmu_user.c
 * keeps the per-process user address spaces, including the directory pointer
 * vmm_switch_user_aspace installs.
 *
 * Every name below is defined exactly once, in mmu_boot.c, and included from
 * every side. The constants are the single copy of the descriptor encoding,
 * so an entry the boot map builds and one the runtime entry points build
 * cannot disagree about a bit. The two root accessors hand out addresses
 * rather than pointers, because the shared root is mmu_boot.c's own
 * file-scope table; the caller casts. The distinction is load-bearing:
 * kernel mappings are always made in the shared root and then mirrored to
 * every CPU by x86mmu_sync_kernel_hierarchy, while a user mapping goes into
 * this CPU's root directly, exactly as before. */
#ifndef XAIOS_ARCH_X86_64_MMU_INTERNAL_H
#define XAIOS_ARCH_X86_64_MMU_INTERNAL_H

#include <xaios/status.h>
#include <xaios/types.h>

#define PAGE_SIZE UINT64_C(4096)
#define LARGE_PAGE_SIZE UINT64_C(0x200000)
#define HUGE_PAGE_SIZE UINT64_C(0x40000000)
#define USER_CODE_WINDOWS 8U
#define USER_ASPACE_L3_TABLES (USER_CODE_WINDOWS + 1U)

#define PTE_PRESENT UINT64_C(1)
#define PTE_WRITABLE (UINT64_C(1) << 1)
#define PTE_USER (UINT64_C(1) << 2)
#define PTE_LARGE (UINT64_C(1) << 7)
#define PTE_GLOBAL (UINT64_C(1) << 8)
#define PTE_DEVICE (UINT64_C(1) << 9)
#define PTE_NX (UINT64_C(1) << 63)
#define PTE_ADDRESS_MASK UINT64_C(0x000ffffffffff000)
#define PTE_LARGE_ADDRESS_MASK UINT64_C(0x000fffffffe00000)
#define PTE_HUGE_ADDRESS_MASK UINT64_C(0x000fffffc0000000)

/* Round an address down to an alignment. */
uint64_t x86mmu_align_down(uint64_t value, uint64_t alignment);

/* A table pointer as the entry the hardware walks, with the attribute bits
   the caller chose. */
uint64_t x86mmu_table_entry(const uint64_t *table, uint64_t flags);

/* The architecture-independent flag word of vmm.h as this architecture's
   PTE bits. */
uint64_t x86mmu_flags_to_pte(uint32_t flags);

/* A zeroed page-table page, or 0 when the PMM is out of memory. */
uint64_t *x86mmu_allocate_table(void);

/* The walk to the table that holds one address, creating intermediate tables
   where the caller is mapping and finding only where it is unmapping. Each
   returns a pointer into a page table and 0 when it declines. */
uint64_t *x86mmu_ensure_pt(uint64_t *root, uint64_t virtual_address,
                           uint32_t flags);
uint64_t *x86mmu_ensure_pd(uint64_t *root, uint64_t virtual_address);
uint64_t *x86mmu_find_pd(uint64_t *root, uint64_t virtual_address);

/* The base of the root this CPU is walking, as an address: its own per-CPU
   root once one exists and the shared early root before that, which is what
   current_root has always selected. x86mmu_shared_root_address is the shared
   early root alone, which is where kernel mappings are made before they are
   mirrored. Addresses rather than pointers because the shared root is
   mmu_boot.c's own file-scope table. */
uint64_t x86mmu_current_root_address(void);
uint64_t x86mmu_shared_root_address(void);

/* A full local invalidation: reload CR3 with the root this CPU is walking,
   in the same place and the same order mmu.c's callers always did it. */
void x86mmu_flush_tlb(void);

/* The per-CPU mirroring every kernel mapping needs, in the same place and the
   same order mmu.c's entry points always did it. */
void x86mmu_sync_kernel_hierarchy(uint64_t virtual_address);

#endif /* XAIOS_ARCH_X86_64_MMU_INTERNAL_H */
