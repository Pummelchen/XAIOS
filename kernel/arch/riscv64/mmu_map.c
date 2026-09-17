/* Sv48 and Sv39 paging for RISC-V: the tables and the walk over them.
 *
 * Sv48 where the hart has it, Sv39 where it does not, chosen at run time and
 * not visible above this file.
 *
 * This used to be Sv48 only, and panicked on a hart that refused it. The
 * reason was `XAIOS_USER_BASE`: at 511 GiB it was not a representable Sv39
 * address, so falling back would have booted a kernel that failed later and
 * further away. Six of the thirteen CPU models QEMU implements offer Sv39 and
 * nothing more -- rva22s64 and rva23s64 among them, the profiles real silicon
 * is certified against -- so a constant was excluding most of the family.
 *
 * The window moved to 255 GiB, which both modes can address, and the two
 * modes then differ by exactly one level. `index_at` is the same arithmetic
 * either way, so Sv48's level-2 table under root slot 0 *is* Sv39's root
 * table: same entries, same meaning, same user slot 255. Selecting Sv39 is
 * therefore not a different set of tables but the same tables entered one
 * level down, which is why almost nothing below here is conditional.
 *
 * The bring-up used Sv39 with four gibibyte leaves, which was right for
 * proving translation could be turned on and wrong for everything after it.
 * That is not what this is.
 *
 * Page table entry, low to high: V R W X U G A D, then the physical page
 * number from bit 10. An entry with none of R, W or X is a pointer to the
 * next level; an entry with any of them is a leaf. That single rule is what
 * makes large and gigantic pages fall out of the same walk rather than
 * needing a separate path.
 *
 * This file owns every table: the static early pool, the shared kernel root,
 * the level a walk starts from, and the per-hart copies a user address space
 * needs. vmm_init lives here with them and is the only writer, which is what
 * lets mmu.c reach the root through a named address instead of through a
 * second copy of the variable -- the split that made a walk start from a null
 * root once already. The entry encoding and the walk live in mmu_map.h and
 * here; the runtime entry points are in mmu.c and the user address spaces in
 * mmu_user.c.
 */
#include <xaios/boot_info.h>
#include <xaios/pmm.h>
#include <xaios/smp.h>
#include <xaios/status.h>
#include <xaios/vmm.h>

#include "mmu_map.h"

extern char __kernel_start[];
extern char __kernel_end[];
extern char __text_start[];
extern char __text_end[];
extern char __rodata_start[];
extern char __rodata_end[];

/* Enough early tables to identity-map the kernel image, the device window and
   the memory the map describes, before the physical allocator can be asked
   for more. Sized rather than grown: this runs before there is anything to
   grow with. */
/* Page-granular kernel sections need a table per 2 MiB of image, plus the
   levels above them. Sized from a ten-megabyte kernel with room to grow. */
/* Sized for the largest memory map this kernel is handed, not the smallest.
   A UEFI boot arrives with about two dozen memory descriptors where an SBI
   boot has two, and each one costs tables. Running out used to be silent --
   the mapping simply did not happen and the fault appeared much later
   somewhere else -- which is why the exhaustion check below is loud. */
#define EARLY_TABLES 192U

static uint64_t g_root[ENTRIES] __attribute__((aligned(4096)));
static uint64_t g_early[EARLY_TABLES][ENTRIES] __attribute__((aligned(4096)));
static uint32_t g_early_used;
static uint64_t g_satp;
/* Which mode this machine ended up in, and the two things that follow from
   it: the level a walk starts at, and the table it starts from. Both are set
   once, in vmm_init, and describe Sv48 until then -- which is what the tables
   are built as, and what Sv39 then enters one level below. */
static uint64_t g_satp_mode = SATP_MODE_SV48;
static uint32_t g_root_level = LEVELS - 1U;
static uint64_t *g_kernel_root;

/* The value a secondary hart writes into satp to join the kernel's address
   space. Read before that hart has an address space, so it is handed over as
   a number rather than reached through a pointer. */
uint64_t riscv64_kernel_satp(void) { return g_satp; }
static uint32_t g_initialized;

static uint64_t *early_table(void) {
  if (g_early_used >= EARLY_TABLES) {
    /* Said out loud, because the alternative is a page that was asked for and
       never mapped: every caller here returns void or ignores the status, so
       exhaustion produced a fault at the unmapped address long afterwards
       with nothing connecting the two. Under UEFI that was a store to the
       interrupt controller, twenty log lines after the mapping that failed. */
    klog("vmm: early page-table pool exhausted after %u tables; some of the "
         "identity map was not created\n", g_early_used);
    return 0;
  }
  uint64_t *table = g_early[g_early_used++];
  for (uint32_t i = 0U; i < ENTRIES; ++i) table[i] = 0U;
  return table;
}

/* A page for a table, from wherever pages come from at this moment.
 *
 * Before the physical allocator is running this has to come out of the static
 * pool; after it, from the allocator, because the static pool is sized for
 * the boot map and nothing more. Asking which is available rather than
 * assuming is what lets the same walk serve both. */
uint64_t *riscv64_mmu_allocate_table(void) {
  if (g_initialized != 0U) {
    void *page = pmm_alloc_page();
    if (page == 0) return 0;
    uint64_t *table = (uint64_t *)page;
    for (uint32_t i = 0U; i < ENTRIES; ++i) table[i] = 0U;
    return table;
  }
  return early_table();
}

/* The paging mode this hart ended up in, named for the shootdown self-test
   rather than handed out as a pointer. The fence and suppression entry points
   that test also calls moved to mmu_tlb.c with the state they read. */
uint32_t riscv64_mmu_root_level(void) { return g_root_level; }

/* Walk to the entry that would describe `virtual_address` at `target_level`,
   creating intermediate tables when asked. Level 0 is a 4 KiB page, 1 is
   2 MiB, 2 is 1 GiB. */
uint64_t *riscv64_mmu_walk(uint64_t *root, uint64_t virtual_address,
                           uint32_t target_level, int create) {
  uint64_t *table = root;
  for (uint32_t level = g_root_level; level > target_level; --level) {
    uint64_t *entry = &table[index_at(virtual_address, level)];
    if ((*entry & PTE_V) == 0U) {
      if (create == 0) return 0;
      uint64_t *next = riscv64_mmu_allocate_table();
      if (next == 0) return 0;
      *entry = pte_for((uint64_t)(uintptr_t)next, 0U);
    } else if ((*entry & PTE_LEAF) != 0U) {
      /* A larger page covers this address, and the caller wants a smaller
         one inside it. Split rather than refuse.
         Refusing was the first version, on the reasoning that an implicit
         split changes a range somebody mapped deliberately. It does not: the
         replacement describes exactly the same memory with exactly the same
         permissions, just at a finer granularity, and every address that
         resolved before resolves identically after. What refusing actually
         produced was a kernel that could not unmap a device page it had
         mapped, because vmm_init covers the device window with gigantic
         leaves and the shared code then works in pages.
         Splitting is only safe because it is total -- every entry of the new
         table is filled from the leaf before the leaf is replaced, so no
         address is briefly unmapped. */
      if (create == 0) return 0;
      uint64_t *split = riscv64_mmu_allocate_table();
      if (split == 0) return 0;
      uint64_t covered = pte_physical(*entry);
      uint64_t child_span = PAGE_SIZE << (9U * (level - 1U));
      uint64_t leaf_bits =
          *entry & (PTE_LEAF | PTE_U | PTE_G | PTE_A | PTE_D | PTE_RSW_DEVICE);
      for (uint32_t i = 0U; i < ENTRIES; ++i) {
        split[i] = pte_for(covered + (uint64_t)i * child_span, leaf_bits);
      }
      *entry = pte_for((uint64_t)(uintptr_t)split, 0U);
      riscv64_mmu_flush_all();
    }
    table = (uint64_t *)(uintptr_t)pte_physical(*entry);
  }
  return &table[index_at(virtual_address, target_level)];
}

typedef struct hart_tables {
  uint64_t *root;           /* this hart's copy of the top level */
  uint64_t *low;            /* this hart's copy of the table under slot 0 */
  uint64_t *user_directory; /* the 2 MiB-level table for userspace's GiB */
  uint64_t satp;
} hart_tables_t;

static hart_tables_t g_hart_tables[VMM_MAX_HARTS];
static uint32_t g_hart_table_count;

/* The root translation currently walks from: this hart's own, once it has
   one, and the shared root before that -- which is also what satp says, so
   satp is what is read. Walking the shared root for a user address would
   answer about tables no hart is using. */
static uint64_t *current_root(void) {
  uint64_t satp = 0U;
  __asm__ volatile("csrr %0, satp" : "=r"(satp));
  if ((satp >> 60) == 0U) return g_kernel_root;
  return (uint64_t *)(uintptr_t)((satp & ((UINT64_C(1) << 44) - 1U)) << 12);
}

uint64_t riscv64_mmu_current_root_address(void) {
  return (uint64_t)(uintptr_t)current_root();
}

uint64_t riscv64_mmu_kernel_root_address(void) {
  return (uint64_t)(uintptr_t)g_kernel_root;
}

/* A kernel mapping that added or replaced an entry at one of the two copied
   levels has to reach every hart's copies, or the hart that did the mapping
   sees it and the others fault on it. Called after every change to the
   shared root; for anything at a lower level it finds nothing to do, because
   those tables are shared by pointer. */
void riscv64_mmu_sync_kernel_hierarchy(uint64_t virtual_address) {
  if (virtual_address >= XAIOS_USER_BASE && virtual_address < XAIOS_USER_LIMIT) {
    return;
  }
  uint32_t l1 = index_at(virtual_address, 2U);
  /* Sv39 has only the one copied level: its root is the table Sv48 reaches
     through slot zero, so there is no level above the user slot to mirror
     and `low` is the root itself. */
  if (g_root_level == 2U) {
    for (uint32_t cpu = 0U; cpu < g_hart_table_count; ++cpu) {
      hart_tables_t *tables = &g_hart_tables[cpu];
      if (tables->root == 0) continue;
      if (l1 != USER_L1_INDEX) tables->root[l1] = g_kernel_root[l1];
    }
    return;
  }
  uint32_t l0 = index_at(virtual_address, 3U);
  for (uint32_t cpu = 0U; cpu < g_hart_table_count; ++cpu) {
    hart_tables_t *tables = &g_hart_tables[cpu];
    if (tables->root == 0) continue;
    if (l0 != 0U) {
      tables->root[l0] = g_root[l0];
      continue;
    }
    if (l1 != USER_L1_INDEX && (g_root[0] & PTE_V) != 0U) {
      uint64_t *shared_low = (uint64_t *)(uintptr_t)pte_physical(g_root[0]);
      tables->low[l1] = shared_low[l1];
    }
  }
}

static void build_per_hart_roots(void) {
  uint32_t capacity = smp_capacity();
  if (capacity > VMM_MAX_HARTS) capacity = VMM_MAX_HARTS;
  uint64_t *shared_low = (g_root[0] & PTE_V) != 0U
                             ? (uint64_t *)(uintptr_t)pte_physical(g_root[0])
                             : 0;
  for (uint32_t cpu = 0U; cpu < capacity; ++cpu) {
    hart_tables_t *tables = &g_hart_tables[cpu];
    tables->root = riscv64_mmu_allocate_table();
    tables->low = riscv64_mmu_allocate_table();
    tables->user_directory = riscv64_mmu_allocate_table();
    if (tables->root == 0 || tables->low == 0 || tables->user_directory == 0) {
      vmm_panic("no memory for hart %u page tables", (uint64_t)cpu);
    }
    if (g_root_level == 2U) {
      /* Sv39: the root is the level Sv48 calls `low`, so the hart needs one
         copied table rather than two and the slot-zero indirection does not
         exist. The table allocated for `low` above is left unused rather
         than special-cased away -- one page per hart, against a boot path
         that would otherwise need a second shape. */
      for (uint32_t i = 0U; i < ENTRIES; ++i) {
        tables->root[i] = g_kernel_root[i];
      }
      tables->low = tables->root;
      tables->root[USER_L1_INDEX] =
          pte_for((uint64_t)(uintptr_t)tables->user_directory, 0U);
    } else {
      for (uint32_t i = 0U; i < ENTRIES; ++i) {
        tables->root[i] = g_root[i];
        tables->low[i] = shared_low != 0 ? shared_low[i] : 0U;
      }
      tables->root[0] = pte_for((uint64_t)(uintptr_t)tables->low, 0U);
      tables->low[USER_L1_INDEX] =
          pte_for((uint64_t)(uintptr_t)tables->user_directory, 0U);
    }
    tables->satp =
        g_satp_mode | ((uint64_t)(uintptr_t)tables->root >> 12);
  }
  g_hart_table_count = capacity;
}

/* What a hart writes into satp: its own root once the per-hart tables exist,
   the shared one before. Secondaries start after vmm_init, so they always get
   their own; the boot hart moves onto its own at the end of vmm_init. */
uint64_t riscv64_mmu_hart_satp_value(uint32_t cpu_id) {
  if (cpu_id < g_hart_table_count && g_hart_tables[cpu_id].root != 0) {
    return g_hart_tables[cpu_id].satp;
  }
  return g_satp;
}

/* This hart's user directory, or zero when the per-hart tables do not name
   one. Handed over as a number so that switching a process's leaf tables in
   and out stays here, where the hart table lives. */
uint64_t riscv64_mmu_user_directory_address(uint32_t cpu_id) {
  if (cpu_id >= g_hart_table_count) return 0U;
  return (uint64_t)(uintptr_t)g_hart_tables[cpu_id].user_directory;
}

void vmm_init(const xaios_boot_info_t *boot) {
  for (uint32_t i = 0U; i < ENTRIES; ++i) g_root[i] = 0U;
  g_early_used = 0U;
  g_initialized = 0U;
  /* Built as Sv48 whatever the hart turns out to support. The tables are the
     same either way; only which of them the hardware is pointed at differs,
     and that is decided below once there is something to point it at. */
  g_kernel_root = g_root;
  g_root_level = LEVELS - 1U;
  g_satp_mode = SATP_MODE_SV48;

  uint32_t kernel_flags =
      XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE | XAIOS_VMM_EXECUTABLE;

  /* The device window below RAM: the UART, the interrupt controller and the
     virtio transports all live there, and a kernel that cannot reach them
     after enabling translation has nothing to report the failure with. */
  riscv64_mmu_identity_map_range(0U, UINT64_C(0x80000000),
                                 kernel_flags | XAIOS_VMM_DEVICE);

  /* The kernel image, one section at a time.
   *
   * Not one RWX range, which is what this did first and what the shared
   * kernel refuses: it checks that .rodata comes back read-only and
   * non-executable and that .text comes back executable, and a uniform
   * mapping fails both. Those checks are right -- a kernel whose constants
   * are writable and whose data is executable has given away most of what
   * page permissions are for -- so the sections are mapped as what they are.
   *
   * In 4 KiB pages, deliberately, because a 2 MiB leaf spanning the boundary
   * between .text and .rodata would have to be granted the union of their
   * permissions and the finer mapping is the whole point here. */
  riscv64_mmu_identity_map_range(UINT64_C(0x80000000),
                                 (uint64_t)(uintptr_t)__text_start,
                                 kernel_flags);
  riscv64_mmu_identity_map_pages((uint64_t)(uintptr_t)__text_start,
                                 (uint64_t)(uintptr_t)__text_end,
                                 XAIOS_VMM_PRESENT | XAIOS_VMM_EXECUTABLE);
  riscv64_mmu_identity_map_pages((uint64_t)(uintptr_t)__rodata_start,
                                 (uint64_t)(uintptr_t)__rodata_end,
                                 XAIOS_VMM_PRESENT);
  riscv64_mmu_identity_map_pages((uint64_t)(uintptr_t)__rodata_end,
                                 (uint64_t)(uintptr_t)__kernel_end,
                                 XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE);

  const uint64_t kernel_image_start = (uint64_t)(uintptr_t)__text_start;
  const uint64_t kernel_image_end = (uint64_t)(uintptr_t)__kernel_end;
  if (boot != 0 && boot->memory_map != 0U && boot->memory_descriptor_size != 0U) {
    const uint8_t *entries = (const uint8_t *)(uintptr_t)boot->memory_map;
    uint64_t count = boot->memory_map_size / boot->memory_descriptor_size;
    for (uint64_t i = 0U; i < count; ++i) {
      const xaios_memory_descriptor_t *descriptor =
          (const xaios_memory_descriptor_t *)(const void *)
              (entries + i * boot->memory_descriptor_size);
      /* Every descriptor, not only conventional memory, which is the
         opposite of what AArch64 does and is deliberate here. A UEFI boot
         hands the kernel its boot_info, its memory map, its device tree and
         the initial filesystem image, and all four sit in loader and boot-
         services memory rather than in conventional RAM. Filtering to
         conventional alone unmaps them and the boot stops earlier, at 35%,
         with the kernel unable to read what it was given. The allocator is
         where conventional-only matters, and the shared NUMA code already
         enforces it there. */
      uint64_t region_start = descriptor->physical_start;
      uint64_t region_end =
          region_start + descriptor->number_of_pages * PAGE_SIZE;
      /* Around the kernel image, not over it.
       *
       * The sections above were mapped with the permissions they are
       * supposed to have -- .rodata read-only, .text non-writable -- and a
       * UEFI memory map describes the kernel's own pages as loader memory
       * like any other, so mapping every descriptor read-write-execute put
       * the blanket mapping back on top and made .rodata writable again. The
       * shared kernel checks for exactly that and refuses. An SBI boot never
       * showed it because the map it builds excludes the kernel to begin
       * with. */
      if (region_start < kernel_image_end && region_end > kernel_image_start) {
        if (region_start < kernel_image_start) {
          riscv64_mmu_identity_map_range(region_start, kernel_image_start,
                                         kernel_flags);
        }
        if (region_end > kernel_image_end) {
          riscv64_mmu_identity_map_range(kernel_image_end, region_end,
                                         kernel_flags);
        }
        continue;
      }
      riscv64_mmu_identity_map_range(region_start, region_end, kernel_flags);
    }
    /* The device tree itself, which sits between those regions and is read
       after translation is on. */
    if (boot->device_tree != 0U) {
      riscv64_mmu_identity_map_range(boot->device_tree,
                                     boot->device_tree + 0x100000U,
                                     kernel_flags);
    }
  }

  /* The page below the kernel stack goes away, so an overflow faults instead
     of writing over whatever the linker put last in .bss. See linker.ld. */
  {
    extern uint8_t __stack_guard[];
    uint64_t guard = (uint64_t)(uintptr_t)__stack_guard;
    if (riscv64_mmu_walk(g_kernel_root, guard, 0U, 1) != 0) {
      uint64_t *entry = riscv64_mmu_walk(g_kernel_root, guard, 0U, 1);
      *entry = 0U;
      klog("vmm: stack guard page at 0x%lx left unmapped\n", guard);
    }
  }

  /* And the same page under every secondary hart's stack.
   *
   * Those stacks had no guard at all, and were a quarter of the size this
   * kernel had already found too small for its deepest chain (see the note in
   * kernel/arch/riscv64/smp.c). A hart that is not the boot hart takes its
   * whole syscall chain on its own stack, so an overflow there did not fault
   * either -- it wrote into whatever the linker had placed next, which is how
   * this kernel has lost a per-CPU table before. Unmapping these makes that a
   * page fault at an address that names itself. */
  {
    extern uint8_t *riscv64_secondary_stack_guard(uint32_t cpu);
    extern uint32_t riscv64_secondary_stack_count(void);
    uint32_t unmapped = 0U;
    for (uint32_t cpu = 0U; cpu < riscv64_secondary_stack_count(); ++cpu) {
      uint64_t guard = (uint64_t)(uintptr_t)riscv64_secondary_stack_guard(cpu);
      if (guard == 0U) continue;
      uint64_t *entry = riscv64_mmu_walk(g_kernel_root, guard, 0U, 1);
      if (entry != 0) {
        *entry = 0U;
        ++unmapped;
      }
    }
    klog("vmm: %u secondary stack guard pages left unmapped\n", unmapped);
  }

  /* Ask for Sv48, take Sv39 if that is what the hart has.
   *
   * satp is WARL: a write naming a mode the implementation does not have is
   * ignored entirely, so the write either turns translation on or does
   * nothing, and reading satp back is what says which happened. Everything
   * executing here is identity-mapped, so both outcomes leave this code
   * running at the same address and the second attempt is safe to make.
   *
   * The Sv39 root is not a second set of tables. It is the level-2 table
   * Sv48 reaches through slot zero, entered directly -- the same entries
   * describing the same memory, one level down. */
  g_satp = SATP_MODE_SV48 | ((uint64_t)(uintptr_t)g_root >> 12);
  vmm_activate_kernel();

  uint64_t observed = 0U;
  __asm__ volatile("csrr %0, satp" : "=r"(observed));
  if (observed != g_satp) {
    if ((g_root[0] & PTE_V) == 0U) {
      vmm_panic("Sv48 refused and no level-2 table to fall back to: satp "
                "reads %lx, wanted %lx", observed, g_satp);
    }
    /* Translation is still off -- the write was ignored -- but say so
       explicitly rather than relying on it, then point the hardware one
       level down. */
    __asm__ volatile("csrw satp, zero" : : : "memory");
    riscv64_mmu_flush_all();
    g_kernel_root = (uint64_t *)(uintptr_t)pte_physical(g_root[0]);
    g_root_level = 2U;
    g_satp_mode = SATP_MODE_SV39;
    g_satp = SATP_MODE_SV39 | ((uint64_t)(uintptr_t)g_kernel_root >> 12);
    vmm_activate_kernel();
    __asm__ volatile("csrr %0, satp" : "=r"(observed));
    if (observed != g_satp) {
      vmm_panic("this hart offers neither Sv48 nor Sv39: satp reads %lx, "
                "wanted %lx", observed, g_satp);
    }
  }
  g_initialized = 1U;
  build_per_hart_roots();
  vmm_activate_kernel();
  klog("vmm: %s enabled root=%lx early_tables=%u/%u harts=%u "
       "mode=per-hart-user-aspace\n",
       g_root_level == 2U ? "sv39" : "sv48",
       (uint64_t)(uintptr_t)g_kernel_root, g_early_used, EARLY_TABLES,
       g_hart_table_count);
}
