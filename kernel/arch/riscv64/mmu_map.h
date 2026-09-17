/* Private interface of the RISC-V page tables, shared by mmu.c, mmu_map.c and
 * mmu_user.c.
 *
 * mmu_map.c owns the tables and the walk underneath every mapping: the static
 * early pool, the shared kernel root, the level a walk starts from, the
 * create-or-find walk, the per-hart roots and their mirror, and vmm_init,
 * which sets every one of those. mmu.c keeps the runtime entry points --
 * translate, map, unmap, range and user-buffer validation, the structural
 * probes the self-tests ask for and the cache maintenance -- and mmu_user.c
 * keeps the per-process user address spaces.
 *
 * Every name here is defined exactly once. The roots cross as addresses and
 * never as variables: the shared root is mmu_map.c's own file-scope table and
 * mmu.c reaches it through riscv64_mmu_kernel_root_address(), which returns
 * the number vmm_init put there. There is deliberately no setter, because
 * vmm_init is the only writer and it lives beside the table -- so the split
 * cannot leave a walk reading a root nobody set.
 *
 * The entry encoding is the single copy both sides build with; a leaf the boot
 * map lays down and one the runtime entry points make cannot disagree about a
 * bit.
 */
#ifndef XAIOS_ARCH_RISCV64_MMU_MAP_H
#define XAIOS_ARCH_RISCV64_MMU_MAP_H

#include <xaios/elf_loader.h>
#include <xaios/status.h>
#include <xaios/types.h>
#include <xaios/vmm.h>

#include "mmu_internal.h"

#define PTE_V (UINT64_C(1) << 0)
#define PTE_R (UINT64_C(1) << 1)
#define PTE_W (UINT64_C(1) << 2)
#define PTE_X (UINT64_C(1) << 3)
#define PTE_U (UINT64_C(1) << 4)
#define PTE_G (UINT64_C(1) << 5)
#define PTE_A (UINT64_C(1) << 6)
#define PTE_D (UINT64_C(1) << 7)
/* Bits 8 and 9 are reserved for software, which is what makes the device
   attribute expressible after all. RISC-V has no hardware memory-type field
   -- device versus normal follows the physical address -- so the earlier
   version simply could not report XAIOS_VMM_DEVICE back, and the shared
   vmm self-test is right to insist that a mapping made as device reads back
   as device. Recording it in RSW keeps the kernel's own bookkeeping honest
   without claiming the hardware enforces anything it does not. */
#define PTE_RSW_DEVICE (UINT64_C(1) << 8)
#define PTE_LEAF (PTE_R | PTE_W | PTE_X)
#define PTE_PPN_SHIFT 10U

#define SATP_MODE_SV48 (UINT64_C(9) << 60)
#define SATP_MODE_SV39 (UINT64_C(8) << 60)
#define ENTRIES 512U
#define LEVELS 4U

/* Translate the shared flag vocabulary into this architecture's bits.
 *
 * Accessed and Dirty are set unconditionally. The specification permits an
 * implementation to fault when software leaves them clear rather than
 * updating them in hardware, and a kernel that relies on the friendlier
 * behaviour works until it meets a CPU that does not have it. Setting them up
 * front costs nothing and removes the question. */
static inline uint64_t flags_to_pte(uint32_t flags) {
  uint64_t bits = PTE_A | PTE_D;
  if ((flags & XAIOS_VMM_WRITABLE) != 0U) bits |= PTE_R | PTE_W;
  else bits |= PTE_R;
  if ((flags & XAIOS_VMM_EXECUTABLE) != 0U) bits |= PTE_X;
  if ((flags & XAIOS_VMM_USER) != 0U) bits |= PTE_U;
  if ((flags & XAIOS_VMM_DEVICE) != 0U) bits |= PTE_RSW_DEVICE;
  /* Global for kernel mappings only. A global entry survives an address-space
     switch, which is what makes it wrong for a user page: the next process
     would inherit it. */
  if ((flags & (XAIOS_VMM_USER | XAIOS_VMM_NG)) == 0U) bits |= PTE_G;
  return bits;
}

/* XAIOS_VMM_DEVICE has no representation here, and that is the architecture
   rather than an omission.
   AArch64 carries the memory type in the entry through MAIR, and x86-64 has
   the cache-disable bits. RISC-V has neither: whether an access is device or
   normal memory follows the physical address, decided by the platform's
   memory map, not by the page table. So a mapping cannot report DEVICE back,
   and a caller asking for it is asking for something the entry cannot say
   either way -- which is why the already-satisfied check above compares
   everything except that bit. */
static inline uint32_t pte_to_flags(uint64_t entry) {
  uint32_t flags = XAIOS_VMM_PRESENT;
  if ((entry & PTE_W) != 0U) flags |= XAIOS_VMM_WRITABLE;
  if ((entry & PTE_X) != 0U) flags |= XAIOS_VMM_EXECUTABLE;
  if ((entry & PTE_U) != 0U) flags |= XAIOS_VMM_USER;
  if ((entry & PTE_RSW_DEVICE) != 0U) flags |= XAIOS_VMM_DEVICE;
  if ((entry & PTE_G) == 0U) flags |= XAIOS_VMM_NG;
  return flags;
}

static inline uint64_t pte_for(uint64_t physical, uint64_t flags) {
  return ((physical >> 12) << PTE_PPN_SHIFT) | flags | PTE_V;
}

static inline uint64_t pte_physical(uint64_t entry) {
  return (entry >> PTE_PPN_SHIFT) << 12;
}

static inline uint32_t index_at(uint64_t virtual_address, uint32_t level) {
  return (uint32_t)((virtual_address >> (12U + 9U * level)) & 0x1ffU);
}

/* Per-process user address spaces, and the per-hart tables that carry them.
 *
 * There were none. Every user page went into the one shared root, the
 * per-process table list the shared interface hands around was allocated and
 * ignored, and switching address spaces was a TLB flush. Two processes are
 * linked at the same addresses -- every one of them is -- so loading a
 * second while a first was alive overwrote the first's mappings, and
 * reclaiming the second removed them. sshd ran an on-demand application at
 * the same address it lives at itself and faulted on the first byte it wrote
 * back to its own stack. The boot-test configuration never showed it: its
 * processes run one after another in one address space that is never torn
 * down between them.
 *
 * The shape is the one x86-64 uses, because the problem is the same one: the
 * kernel and userspace share the first top-level slot, so a hart cannot have
 * its own user mapping without its own copy of the tables above it. Each
 * hart gets a root of its own, a copy of the table under slot zero, and a
 * user directory -- the 2 MiB-granular table for the gibibyte userspace
 * lives in -- that switching points at a process's leaf tables. Kernel
 * mappings stay in the shared tables; a new entry at either of the two
 * copied levels is mirrored into every hart's copies, and everything below
 * those levels is reached through shared pointers and needs no mirroring.
 * Sv48 puts userspace, at 511 GiB, under slot zero alongside the kernel;
 * that is the same arithmetic x86-64 does with its PDPT. */
#define USER_CODE_WINDOWS XAIOS_ELF_CODE_WINDOWS
#define USER_ASPACE_L3_TABLES (USER_CODE_WINDOWS + 1U)
/* Derived from the constants that define the layout, so the three cannot
   disagree: the gibibyte slot userspace lives in, the first 2 MiB window of
   code and data, and the 2 MiB window holding the stack. */
#define USER_L1_INDEX index_at(XAIOS_USER_BASE, 2U)
#define USER_CODE_L2_INDEX index_at(XAIOS_USER_BASE, 1U)
#define USER_STACK_L2_INDEX index_at(XAIOS_USER_STACK_TOP - PAGE_SIZE, 1U)

/* The root the current hart translates through: its own per-hart root once
   one exists, and the shared kernel root before that -- which is also what
   satp says, so satp is read. A physical address, not a pointer into
   mmu_map.c's file-scope table. */
uint64_t riscv64_mmu_current_root_address(void);

/* The shared kernel root vmm_init built. The boot map, the leaf probes and
   the kernel mapping entry points all work on this one. */
uint64_t riscv64_mmu_kernel_root_address(void);

/* Walk to the entry that would describe `virtual_address` at `target_level`,
   creating intermediate tables when asked. The root is a pointer the caller
   took from one of the accessors above; the table variable itself stays in
   mmu_map.c. */
uint64_t *riscv64_mmu_walk(uint64_t *root, uint64_t virtual_address,
                           uint32_t target_level, int create);

/* A page for a table, from the early pool before the allocator runs and from
   the allocator after. Crosses to mmu_user.c, which builds the per-process
   leaf tables. */
uint64_t *riscv64_mmu_allocate_table(void);

/* The value a secondary hart writes into satp: its own root once the per-hart
   tables exist, the shared root before. `riscv64_hart_satp` in mmu.c is the
   named entry point and forwards here. */
uint64_t riscv64_mmu_hart_satp_value(uint32_t cpu_id);

/* This hart's user directory, or zero when it has none. A number rather than
   a pointer into mmu_map.c's hart table. */
uint64_t riscv64_mmu_user_directory_address(uint32_t cpu_id);

/* Mirror a kernel mapping that landed at one of the two copied levels into
   every hart's copy. Called after every change to the shared root. */
void riscv64_mmu_sync_kernel_hierarchy(uint64_t virtual_address);

/* The two identity-map builders vmm_init lays the boot map down with. They
   live in mmu.c beside the map entry points they call. */
void riscv64_mmu_identity_map_pages(uint64_t start, uint64_t end,
                                    uint32_t flags);
void riscv64_mmu_identity_map_range(uint64_t start, uint64_t end,
                                    uint32_t flags);

#endif /* XAIOS_ARCH_RISCV64_MMU_MAP_H */
