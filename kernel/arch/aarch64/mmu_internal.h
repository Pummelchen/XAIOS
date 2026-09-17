/* Private interface of the AArch64 page tables, shared by mmu.c, mmu_boot.c
 * and mmu_user.c.
 *
 * mmu_boot.c owns the boot map and the walk underneath every mapping: the
 * identity and kernel page tables build_tables lays down, the per-CPU roots
 * that copy them, the allocate-or-find helpers every mapping goes through,
 * and the SCTLR_EL1 enable sequence vmm_init ends with. mmu.c keeps the
 * runtime entry points -- translate, map, unmap, range and user-buffer
 * validation, the cache maintenance and the self-test -- and mmu_user.c
 * keeps the per-process user address spaces.
 *
 * Every name below is defined exactly once, in mmu_boot.c, and included from
 * both sides. The constants are the single copy of the descriptor encoding,
 * so a descriptor the boot map builds and one the runtime entry points build
 * cannot disagree about a bit. The root accessor hands out a physical address
 * rather than a pointer, because the shared root is mmu_boot.c's own
 * file-scope table.
 */
#ifndef XAIOS_ARCH_AARCH64_MMU_INTERNAL_H
#define XAIOS_ARCH_AARCH64_MMU_INTERNAL_H

#include <xaios/status.h>
#include <xaios/types.h>

#define PAGE_SIZE UINT64_C(4096)
#define L2_BLOCK_SIZE UINT64_C(0x200000)
#define L1_BLOCK_SIZE UINT64_C(0x40000000)
#define USER_CODE_WINDOWS 8U
#define USER_ASPACE_L3_TABLES (USER_CODE_WINDOWS + 1U)

#define PTE_VALID UINT64_C(1)
#define PTE_TABLE UINT64_C(1 << 1)
#define PTE_ATTR_NORMAL UINT64_C(0 << 2)
#define PTE_ATTR_DEVICE UINT64_C(1 << 2)
#define PTE_AP_RO UINT64_C(1 << 7)
#define PTE_AP_EL0 UINT64_C(1 << 6)
#define PTE_SH_INNER UINT64_C(3 << 8)
#define PTE_AF UINT64_C(1 << 10)
#define PTE_NG UINT64_C(1 << 11)
#define PTE_PXN (UINT64_C(1) << 53)
#define PTE_UXN (UINT64_C(1) << 54)
#define PTE_ADDR_MASK UINT64_C(0x0000fffffffff000)
#define PTE_BLOCK_L2_ADDR_MASK UINT64_C(0x0000ffffffe00000)
#define PTE_BLOCK_L1_ADDR_MASK UINT64_C(0x0000ffffc0000000)

#define MAIR_NORMAL_WB UINT64_C(0xff)
#define MAIR_DEVICE_NGNRE UINT64_C(0x04)

/* Round an address down or up to an alignment. */
uint64_t a64mmu_align_down(uint64_t value, uint64_t align);
uint64_t a64mmu_align_up(uint64_t value, uint64_t align);

/* A table pointer, a 4 KiB page and a 2 MiB block, as the descriptors the
   hardware walks, with the attribute bits the caller chose. */
uint64_t a64mmu_table_descriptor(const uint64_t *table);
uint64_t a64mmu_page_descriptor(uint64_t physical_address, uint64_t attrs);
uint64_t a64mmu_block_descriptor(uint64_t physical_address, uint64_t attrs);

/* The architecture-independent flag word of vmm.h as this architecture's
   attribute bits. */
uint64_t a64mmu_attrs_from_flags(uint32_t flags);

/* The walk to the table that holds one address, creating intermediate tables
   where the caller is mapping and finding only where it is unmapping. Each
   returns a pointer into a page table and 0 when it declines. */
uint64_t *a64mmu_ensure_l3_table(uint64_t virtual_address);
uint64_t *a64mmu_ensure_l2_table(uint64_t virtual_address);
uint64_t *a64mmu_find_l2_table(uint64_t virtual_address);

/* The base of the root this CPU is walking, as a physical address: its own
   per-CPU root once one exists and the shared early root before that, which
   is what current_root has always selected. A number rather than a pointer
   because the shared root is mmu_boot.c's own file-scope table. */
uint64_t a64mmu_current_root_address(void);

/* Whether an address falls in the UART window the boot map identity-mapped,
   which the descriptor decoder reports as device memory. */
int a64mmu_in_mmio_window(uint64_t virtual_address);

/* The per-CPU mirroring every kernel mapping needs, in the same place and the
   same order mmu.c's entry points always did it. */
void a64mmu_sync_kernel_hierarchy(uint64_t virtual_address);

#endif /* XAIOS_ARCH_AARCH64_MMU_INTERNAL_H */
