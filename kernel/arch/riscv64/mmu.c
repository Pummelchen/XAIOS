/* Sv48 and Sv39 paging for RISC-V.
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
 */
#include <xaios/boot_info.h>
#include <xaios/elf_loader.h>
#include <xaios/pmm.h>
#include <xaios/smp.h>
#include <xaios/status.h>
#include <xaios/vmm.h>

void klog(const char *fmt, ...);
void panic_at(const char *file, int line, const char *fmt, ...)
    __attribute__((noreturn));
#define vmm_panic(...) panic_at(__FILE__, __LINE__, __VA_ARGS__)

extern char __kernel_start[];
extern char __kernel_end[];
extern char __text_start[];
extern char __text_end[];
extern char __rodata_start[];
extern char __rodata_end[];

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
#define PAGE_SIZE UINT64_C(0x1000)
#define ENTRIES 512U
#define LEVELS 4U

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
         "identity map was not created\n", (uint64_t)g_early_used);
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
static uint64_t *allocate_table(void) {
  if (g_initialized != 0U) {
    void *page = pmm_alloc_page();
    if (page == 0) return 0;
    uint64_t *table = (uint64_t *)page;
    for (uint32_t i = 0U; i < ENTRIES; ++i) table[i] = 0U;
    return table;
  }
  return early_table();
}

static uint64_t pte_for(uint64_t physical, uint64_t flags) {
  return ((physical >> 12) << PTE_PPN_SHIFT) | flags | PTE_V;
}

static uint64_t pte_physical(uint64_t entry) {
  return (entry >> PTE_PPN_SHIFT) << 12;
}

static uint32_t index_at(uint64_t virtual_address, uint32_t level) {
  return (uint32_t)((virtual_address >> (12U + 9U * level)) & 0x1ffU);
}

/* Translate the shared flag vocabulary into this architecture's bits.
 *
 * Accessed and Dirty are set unconditionally. The specification permits an
 * implementation to fault when software leaves them clear rather than
 * updating them in hardware, and a kernel that relies on the friendlier
 * behaviour works until it meets a CPU that does not have it. Setting them up
 * front costs nothing and removes the question. */
static uint64_t flags_to_pte(uint32_t flags) {
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
static uint32_t pte_to_flags(uint64_t entry) {
  uint32_t flags = XAIOS_VMM_PRESENT;
  if ((entry & PTE_W) != 0U) flags |= XAIOS_VMM_WRITABLE;
  if ((entry & PTE_X) != 0U) flags |= XAIOS_VMM_EXECUTABLE;
  if ((entry & PTE_U) != 0U) flags |= XAIOS_VMM_USER;
  if ((entry & PTE_RSW_DEVICE) != 0U) flags |= XAIOS_VMM_DEVICE;
  if ((entry & PTE_G) == 0U) flags |= XAIOS_VMM_NG;
  return flags;
}

static void flush_all(void) {
  __asm__ volatile("sfence.vma zero, zero" ::: "memory");
}

static void flush_one(uint64_t virtual_address) {
  __asm__ volatile("sfence.vma %0, zero" : : "r"(virtual_address) : "memory");
}

/* The fence that covers a leaf of the given level, which for anything above
   4 KiB is the global one.
 *
 * `sfence.vma` with an address names one virtual page. The specification is
 * explicit that this is not enough for a superpage: an implementation is
 * permitted to keep translations for the other pages the superpage covers,
 * and is permitted to cache the *absence* of a translation, so both making a
 * 2 MiB leaf valid and taking one away can leave stale entries behind for
 * every address in it except the one named. QEMU flushes generously and never
 * showed this; real hardware is under no such obligation, and the failure it
 * would produce -- a store landing in the memory a mapping used to describe
 * -- is silent and arrives late.
 *
 * The cost is a global fence on operations that are rare by construction:
 * the boot map, which runs before anything can have a stale entry, and the
 * large-page interface, which nothing calls in a loop. 4 KiB mappings, which
 * are the ones on the process-loading path, keep the narrow fence. */
static void flush_leaf(uint64_t virtual_address, uint32_t level) {
  if (level == 0U) {
    flush_one(virtual_address);
    return;
  }
  flush_all();
}

/* Walk to the entry that would describe `virtual_address` at `target_level`,
   creating intermediate tables when asked. Level 0 is a 4 KiB page, 1 is
   2 MiB, 2 is 1 GiB. */
static uint64_t *walk(uint64_t *root, uint64_t virtual_address,
                      uint32_t target_level, int create) {
  uint64_t *table = root;
  for (uint32_t level = g_root_level; level > target_level; --level) {
    uint64_t *entry = &table[index_at(virtual_address, level)];
    if ((*entry & PTE_V) == 0U) {
      if (create == 0) return 0;
      uint64_t *next = allocate_table();
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
      uint64_t *split = allocate_table();
      if (split == 0) return 0;
      uint64_t covered = pte_physical(*entry);
      uint64_t child_span = PAGE_SIZE << (9U * (level - 1U));
      uint64_t leaf_bits =
          *entry & (PTE_LEAF | PTE_U | PTE_G | PTE_A | PTE_D | PTE_RSW_DEVICE);
      for (uint32_t i = 0U; i < ENTRIES; ++i) {
        split[i] = pte_for(covered + (uint64_t)i * child_span, leaf_bits);
      }
      *entry = pte_for((uint64_t)(uintptr_t)split, 0U);
      flush_all();
    }
    table = (uint64_t *)(uintptr_t)pte_physical(*entry);
  }
  return &table[index_at(virtual_address, target_level)];
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
#define VMM_MAX_HARTS 64U

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

/* A kernel mapping that added or replaced an entry at one of the two copied
   levels has to reach every hart's copies, or the hart that did the mapping
   sees it and the others fault on it. Called after every change to the
   shared root; for anything at a lower level it finds nothing to do, because
   those tables are shared by pointer. */
static void sync_kernel_hierarchy(uint64_t virtual_address) {
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
    tables->root = allocate_table();
    tables->low = allocate_table();
    tables->user_directory = allocate_table();
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
uint64_t riscv64_hart_satp(uint32_t cpu_id) {
  if (cpu_id < g_hart_table_count && g_hart_tables[cpu_id].root != 0) {
    return g_hart_tables[cpu_id].satp;
  }
  return g_satp;
}

xaios_status_t vmm_translate(uint64_t virtual_address,
                             uint64_t *physical_address, uint32_t *flags);

static xaios_status_t map_at_level(uint64_t *root, uint64_t virtual_address,
                                   uint64_t physical_address, uint32_t flags,
                                   uint32_t level) {
  uint64_t span = PAGE_SIZE << (9U * level);
  if ((virtual_address & (span - 1U)) != 0U ||
      (physical_address & (span - 1U)) != 0U) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t *entry = walk(root, virtual_address, level, 1);
  if (entry == 0) {
    /* The walk refuses to descend into a larger page, which is right --
       splitting one silently would change the memory type of a range
       somebody mapped deliberately. But refusing outright is wrong when the
       larger page already says exactly what the caller is asking for.
       kmain maps the device window a page at a time after vmm_init has
       already covered it with gigantic identity leaves, and every one of
       those requests is asking for a mapping that is present and correct. So
       a request already satisfied is answered rather than refused; anything
       else -- a different physical address, or flags the existing mapping
       does not grant -- still fails, because that is a real conflict. */
    uint64_t existing_physical = 0U;
    uint32_t existing_flags = 0U;
    if (vmm_translate(virtual_address, &existing_physical, &existing_flags) ==
            XAIOS_OK &&
        existing_physical == physical_address &&
        (existing_flags & flags) == flags) {
      return XAIOS_OK;
    }
    return XAIOS_ERR_NO_MEMORY;
  }
  *entry = pte_for(physical_address, flags_to_pte(flags));
  if (root == g_kernel_root) sync_kernel_hierarchy(virtual_address);
  flush_leaf(virtual_address, level);
  return XAIOS_OK;
}

static xaios_status_t unmap_at_level(uint64_t *root, uint64_t virtual_address,
                                     uint32_t level) {
  /* Splitting is permitted while unmapping, which reads oddly and is right:
     removing one page from inside a larger mapping means the larger mapping
     has to become a table first. Without it, unmapping a device page the
     boot map covered with a gigantic leaf reports not-found on a page that
     is very much mapped. */
  uint64_t *entry = walk(root, virtual_address, level, 1);
  if (entry == 0 || (*entry & PTE_V) == 0U) {
    /* Nothing to remove -- but the walk may have split a larger leaf on the
       way down, and that replaced an entry which may itself sit at a copied
       level, so the harts still have to be told. */
    if (root == g_kernel_root) sync_kernel_hierarchy(virtual_address);
    return XAIOS_ERR_NOT_FOUND;
  }
  *entry = 0U;
  /* Mirrored after the entry is cleared, not before it.
   *
   * This used to be one call above the clear, covering only the split, and
   * that left removal unmirrored: a hart's root is a copy, so zeroing an
   * entry that lives *at* a copied level removed the mapping on the shared
   * root and nowhere else, and every hart -- including the one that asked --
   * went on translating an address the kernel believed it had taken away.
   * Only gigantic entries are at a copied level (Sv39's root holds them
   * directly, Sv48's copied low table one step down), which is why nothing
   * noticed: 4 KiB and 2 MiB entries live in tables the harts share by
   * pointer, and nothing outside this file has ever called the gigantic
   * unmap. The new large-page self-test called it, and the address still
   * translated afterwards.
   *
   * The split case still needs mirroring too, and the clear cannot be undone
   * by doing both, so this one call now covers both paths. */
  if (root == g_kernel_root) sync_kernel_hierarchy(virtual_address);
  flush_leaf(virtual_address, level);
  return XAIOS_OK;
}

/* Page-granular, for ranges whose permissions have to be exact. */
static void identity_map_pages(uint64_t start, uint64_t end, uint32_t flags) {
  start &= ~(PAGE_SIZE - 1U);
  end = (end + PAGE_SIZE - 1U) & ~(PAGE_SIZE - 1U);
  for (uint64_t address = start; address < end; address += PAGE_SIZE) {
    if (map_at_level(g_kernel_root, address, address, flags, 0U) != XAIOS_OK) return;
  }
}

static void identity_map_range(uint64_t start, uint64_t end, uint32_t flags) {
  start &= ~(PAGE_SIZE - 1U);
  end = (end + PAGE_SIZE - 1U) & ~(PAGE_SIZE - 1U);
  /* Never into userspace, whatever the machine has. AArch64 caps its identity
     map at XAIOS_USER_BASE for exactly the reason B-11 records -- the two
     address spaces were literally the same addresses, and which machines
     noticed depended only on how much RAM they had -- and this architecture
     had no such cap. It was unreachable at 511 GiB and it is still
     unreachable at 255, but "no machine is that big yet" is the assumption
     B-11 was, so it is a bound now rather than a hope. */
  if (end > XAIOS_USER_BASE) end = XAIOS_USER_BASE;
  if (start >= end) return;
  for (uint64_t address = start; address < end;) {
    /* Gigantic where it fits, which is what keeps the early table pool small
       enough to be static. A 256 MiB machine mapped in 4 KiB pages would need
       more tables than a kernel has before it can allocate any. */
    uint64_t gigantic = XAIOS_VMM_GIGANTIC_PAGE_SIZE;
    if ((address & (gigantic - 1U)) == 0U && end - address >= gigantic) {
      if (map_at_level(g_kernel_root, address, address, flags, 2U) != XAIOS_OK) return;
      address += gigantic;
      continue;
    }
    uint64_t large = XAIOS_VMM_LARGE_PAGE_SIZE;
    if ((address & (large - 1U)) == 0U && end - address >= large) {
      if (map_at_level(g_kernel_root, address, address, flags, 1U) != XAIOS_OK) return;
      address += large;
      continue;
    }
    if (map_at_level(g_kernel_root, address, address, flags, 0U) != XAIOS_OK) return;
    address += PAGE_SIZE;
  }
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
  identity_map_range(0U, UINT64_C(0x80000000), kernel_flags | XAIOS_VMM_DEVICE);

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
  identity_map_range(UINT64_C(0x80000000), (uint64_t)(uintptr_t)__text_start,
                     kernel_flags);
  identity_map_pages((uint64_t)(uintptr_t)__text_start,
                     (uint64_t)(uintptr_t)__text_end,
                     XAIOS_VMM_PRESENT | XAIOS_VMM_EXECUTABLE);
  identity_map_pages((uint64_t)(uintptr_t)__rodata_start,
                     (uint64_t)(uintptr_t)__rodata_end, XAIOS_VMM_PRESENT);
  identity_map_pages((uint64_t)(uintptr_t)__rodata_end,
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
          identity_map_range(region_start, kernel_image_start, kernel_flags);
        }
        if (region_end > kernel_image_end) {
          identity_map_range(kernel_image_end, region_end, kernel_flags);
        }
        continue;
      }
      identity_map_range(region_start, region_end, kernel_flags);
    }
    /* The device tree itself, which sits between those regions and is read
       after translation is on. */
    if (boot->device_tree != 0U) {
      identity_map_range(boot->device_tree, boot->device_tree + 0x100000U,
                         kernel_flags);
    }
  }

  /* The page below the kernel stack goes away, so an overflow faults instead
     of writing over whatever the linker put last in .bss. See linker.ld. */
  {
    extern uint8_t __stack_guard[];
    uint64_t guard = (uint64_t)(uintptr_t)__stack_guard;
    if (walk(g_kernel_root, guard, 0U, 1) != 0) {
      uint64_t *entry = walk(g_kernel_root, guard, 0U, 1);
      *entry = 0U;
      klog("vmm: stack guard page at 0x%lx left unmapped\n", guard);
    }
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
    flush_all();
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

void vmm_activate_kernel(void) {
  flush_all();
  /* Supervisor access to user pages, which is off after reset.
   *
   * Without this the kernel cannot read or write a single byte of a user
   * process: loading an ELF segment, copying a syscall argument, and reading
   * a path all fault, and the fault reports a user address the kernel plainly
   * has mapped, which reads as a broken page table rather than a permission
   * bit. AArch64 spells the same idea backwards -- it clears PAN around the
   * syscall path and leaves it set elsewhere -- and that narrower window is
   * the better shape. It needs an interface the shared code does not have
   * yet, so this opens the access for the whole kernel and the difference is
   * recorded rather than hidden: on this architecture a stray kernel
   * dereference of a user pointer is not caught by hardware. */
  __asm__ volatile("csrs sstatus, %0" : : "r"(UINT64_C(1) << 18) : "memory");
  __asm__ volatile("csrw satp, %0" : : "r"(riscv64_hart_satp(smp_cpu_id()))
                   : "memory");
  flush_all();
}

/* RISC-V's memory model makes these fences rather than cache maintenance.
   The architecture requires coherent instruction and data caches with respect
   to DMA on any platform that has them, so what is needed is ordering, not
   writeback -- and a fence is what expresses that. */
void vmm_clean_to_memory(const void *buffer, uint64_t bytes) {
  (void)buffer;
  (void)bytes;
  __asm__ volatile("fence ow, ow" ::: "memory");
}

void vmm_invalidate_from_memory(const void *buffer, uint64_t bytes) {
  (void)buffer;
  (void)bytes;
  __asm__ volatile("fence ir, ir" ::: "memory");
}

xaios_status_t vmm_translate(uint64_t virtual_address,
                             uint64_t *physical_address, uint32_t *flags) {
  uint64_t *root = current_root();
  for (uint32_t level = 0U; level < 3U; ++level) {
    uint64_t *entry = walk(root, virtual_address, level, 0);
    if (entry == 0) continue;
    if ((*entry & PTE_V) == 0U) continue;
    if ((*entry & PTE_LEAF) == 0U) continue;
    uint64_t span = PAGE_SIZE << (9U * level);
    if (physical_address != 0) {
      *physical_address = pte_physical(*entry) + (virtual_address & (span - 1U));
    }
    if (flags != 0) *flags = pte_to_flags(*entry);
    return XAIOS_OK;
  }
  return XAIOS_ERR_NOT_FOUND;
}

xaios_status_t vmm_validate_range_flags(uint64_t virtual_address, uint64_t size,
                                        uint32_t required_flags,
                                        uint32_t forbidden_flags) {
  if (size == 0U) return XAIOS_ERR_INVALID;
  uint64_t end = virtual_address + size;
  if (end < virtual_address) return XAIOS_ERR_INVALID;
  for (uint64_t address = virtual_address & ~(PAGE_SIZE - 1U); address < end;
       address += PAGE_SIZE) {
    uint32_t flags = 0U;
    if (vmm_translate(address, 0, &flags) != XAIOS_OK) return XAIOS_ERR_NOT_FOUND;
    if ((flags & required_flags) != required_flags) return XAIOS_ERR_INVALID;
    if ((flags & forbidden_flags) != 0U) return XAIOS_ERR_INVALID;
  }
  return XAIOS_OK;
}

xaios_status_t vmm_map_page(uint64_t virtual_address, uint64_t physical_address,
                            uint32_t flags) {
  return map_at_level(g_kernel_root, virtual_address, physical_address, flags, 0U);
}

xaios_status_t vmm_unmap_page(uint64_t virtual_address) {
  if ((virtual_address & (PAGE_SIZE - 1U)) != 0U) return XAIOS_ERR_INVALID;
  /* Unmapping an address that is already unmapped is success, which this got
     wrong by being stricter than the interface it implements. The other two
     architectures zero the entry and return OK either way, and shared code
     relies on it: a process's stack guard pages are unmapped before they are
     ever mapped, precisely so that nothing is mapped there, and that call is
     asserted. Reporting not-found for a page that is absent describes the
     state accurately and answers a question nobody asked -- the caller wants
     the address to be unmapped afterwards, and it is. */
  xaios_status_t status = unmap_at_level(g_kernel_root, virtual_address, 0U);
  return status == XAIOS_ERR_NOT_FOUND ? XAIOS_OK : status;
}

/* Collision-safe kernel large and gigantic mappings.
 *
 * The shared interface these implement is documented as collision-safe --
 * AArch64 and x86-64 both refuse a second mapping over a live one with
 * XAIOS_ERR_BUSY -- and this port did not. `map_at_level` overwrites whatever
 * entry it finds, so a caller that mapped a gibibyte over something already
 * there was told it had succeeded while the previous mapping silently ceased
 * to exist. Nothing outside this file calls these four functions yet, which
 * is both why it went unnoticed and why correcting it cannot break a boot.
 *
 * The check lives at the public entry points rather than inside
 * `map_at_level`, deliberately. `identity_map_range` builds the boot map
 * through that same function, and a UEFI memory map hands the kernel
 * descriptors that overlap ranges it has already covered; refusing there
 * would abort the remainder of a range -- that loop returns on the first
 * non-OK status -- and leave a machine mapped halfway with nothing said.
 * So the contract belongs to the two entry points the boot map does not use.
 *
 * What it catches, precisely, because the difference matters: a leaf at the
 * requested level, a larger leaf above covering the address, and any table
 * below it that could hold live mappings. What it does not catch is a table
 * below that is entirely empty -- replacing that loses no mapping, only the
 * page the empty table occupies. x86-64 checks only the entry at the target
 * level and has no larger-leaf case to worry about; this is that check plus
 * the one this architecture's splitting walk makes possible.
 */
static xaios_status_t map_leaf_checked(uint64_t virtual_address,
                                       uint64_t physical_address,
                                       uint32_t flags, uint32_t level) {
  uint64_t span = PAGE_SIZE << (9U * level);
  if ((virtual_address & (span - 1U)) != 0U ||
      (physical_address & (span - 1U)) != 0U ||
      (flags & XAIOS_VMM_PRESENT) == 0U) {
    return XAIOS_ERR_INVALID;
  }
  /* Never into the userspace window through a kernel entry point. These write
     into the shared kernel root, and userspace lives in a per-hart directory
     that switching replaces per process -- a user leaf placed here would
     belong to whichever process happened to be running and outlive it. */
  if ((flags & XAIOS_VMM_USER) != 0U ||
      (virtual_address >= XAIOS_USER_BASE &&
       virtual_address < XAIOS_USER_LIMIT)) {
    return XAIOS_ERR_INVALID;
  }
  /* Asked of translate rather than of a creating walk: a creating walk would
     split a larger leaf as a side effect of a request it is about to refuse,
     and translate is the only thing here that sees all three shapes a
     collision can take. */
  if (vmm_translate(virtual_address, 0, 0) == XAIOS_OK) return XAIOS_ERR_BUSY;
  uint64_t *entry = walk(g_kernel_root, virtual_address, level, 0);
  if (entry != 0 && (*entry & PTE_V) != 0U) return XAIOS_ERR_BUSY;
  return map_at_level(g_kernel_root, virtual_address, physical_address, flags,
                      level);
}

xaios_status_t vmm_map_large_page(uint64_t virtual_address,
                                  uint64_t physical_address, uint32_t flags) {
  return map_leaf_checked(virtual_address, physical_address, flags, 1U);
}

xaios_status_t vmm_unmap_large_page(uint64_t virtual_address) {
  return unmap_at_level(g_kernel_root, virtual_address, 1U);
}

xaios_status_t vmm_map_gigantic_page(uint64_t virtual_address,
                                     uint64_t physical_address,
                                     uint32_t flags) {
  return map_leaf_checked(virtual_address, physical_address, flags, 2U);
}

xaios_status_t vmm_unmap_gigantic_page(uint64_t virtual_address) {
  return unmap_at_level(g_kernel_root, virtual_address, 2U);
}

xaios_status_t vmm_validate_user_buffer(uint64_t virtual_address, uint64_t size,
                                        uint32_t required_flags) {
  if (virtual_address < XAIOS_USER_BASE ||
      virtual_address + size > XAIOS_USER_LIMIT ||
      virtual_address + size < virtual_address) {
    return XAIOS_ERR_INVALID;
  }
  return vmm_validate_range_flags(virtual_address, size,
                                  required_flags | XAIOS_VMM_USER, 0U);
}

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
      uint64_t *table = allocate_table();
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
  flush_one(virtual_address);
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
  flush_one(virtual_address);
  return XAIOS_OK;
}

/* Point this hart's user directory at a process's leaf tables, or at nothing.
   Pointer entries carry no permission bits: on RISC-V a non-leaf entry with U
   set is reserved, which is the one place this differs from x86-64. */
void vmm_switch_user_aspace(uint64_t l3_tables[], uint32_t l3_count) {
  uint32_t cpu = smp_cpu_id();
  if (cpu >= g_hart_table_count || g_hart_tables[cpu].user_directory == 0) {
    flush_all();
    return;
  }
  uint64_t *directory = g_hart_tables[cpu].user_directory;
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
  flush_all();
}

void vmm_destroy_user_aspace(uint64_t l3_tables[], uint32_t l3_count) {
  /* Flushed before the pages go back, so no stale translation can point at
     memory the allocator has handed to someone else. */
  flush_all();
  for (uint32_t i = 0U; i < l3_count; ++i) {
    if (l3_tables[i] != 0U) {
      pmm_free_page((void *)(uintptr_t)l3_tables[i]);
      l3_tables[i] = 0U;
    }
  }
}

/* Where the large-page self-test does its work.
 *
 * Three gibibyte-aligned windows, chosen against four constraints at once,
 * which is why they are not the addresses x86-64 uses. They have to be
 * representable in Sv39 -- a 39-bit address space reaches 256 GiB, so
 * x86-64's 0x7000000000 (448 GiB) and 0x8000000000 (512 GiB) simply do not
 * exist on more than half the harts QEMU implements. They have to be clear
 * of the userspace window, which is the last gibibyte below 256 GiB. They
 * have to be clear of the identity map, which covers whatever RAM the machine
 * reports and is capped at XAIOS_USER_BASE. And they have to be a gibibyte
 * apart, so that the 2 MiB test and the 1 GiB test cannot see each other's
 * tables: they share a level-2 slot otherwise, and the gigantic map would
 * then be refused by the collision check for a reason that has nothing to do
 * with what is being tested.
 *
 * 192-194 GiB satisfies all four on any machine this kernel can boot on
 * today. It stops being true on a machine with 192 GiB of RAM, so the test
 * does not assume it -- it asks first, and says so if the window is occupied,
 * rather than mapping over the identity map and failing somewhere else. */
#define SELF_TEST_LARGE_VA UINT64_C(0x3000000000)    /* 192 GiB */
#define SELF_TEST_GIGANTIC_VA UINT64_C(0x3040000000) /* 193 GiB */
#define SELF_TEST_SPLIT_VA UINT64_C(0x3080000000)    /* 194 GiB */
/* Above the first top-level slot, which only Sv48 has. */
#define SELF_TEST_HIGH_VA UINT64_C(0x8000000000) /* 512 GiB */

#define SELF_TEST_LARGE_SIGNATURE UINT64_C(0x5849414f53324d49)    /* XAIOS2MI */
#define SELF_TEST_GIGANTIC_SIGNATURE UINT64_C(0x5849414f53314749) /* XAIOS1GI */

/* 2 MiB and 1 GiB mappings, in whichever paging mode this hart gave us.
 *
 * The two modes are not two spellings of the same test. Sv48 walks four
 * levels and Sv39 three, and because `index_at` is the same arithmetic
 * either way, Sv39's root table *is* the table Sv48 reaches through root slot
 * zero. So a 1 GiB leaf -- a level-2 entry -- is an entry in a table one step
 * below the root under Sv48 and an entry in the root itself under Sv39. That
 * is the only structural difference between the modes in this file and it is
 * exactly the difference a gigantic page lands on, which is why the test
 * asserts where the leaf ended up rather than only that translation worked.
 *
 * Every check here has a second witness where one is available, because the
 * cheap version of this test proves very little. A walk that agrees with a
 * walk is one function agreeing with itself: `vmm_translate` and `walk` read
 * the same tables, so a table built wrongly reads back wrongly and
 * consistently. The mappings are therefore also dereferenced -- a signature
 * written through the identity map and read back through the alias, then
 * written through the alias and read back through the identity map -- which
 * is the hardware's own opinion of the leaf, taken from the same page-table
 * walker a fault would use.
 *
 * What this does not prove, said plainly because it is the gap x86-64 does
 * not have: nothing here says anything about any TLB but this hart's. Both
 * fences this file issues are `sfence.vma`, which is hart-local by
 * definition, and this port sends no SBI remote fence to anybody -- so a
 * kernel mapping withdrawn here is withdrawn from one TLB and the other harts
 * are not told. The mirroring checks below cover the page *tables* reaching
 * every hart, which is a different question and the one that had a bug in it.
 * x86-64's self-test counts its shootdowns; there is nothing to count here
 * yet. */
static void vmm_large_page_self_test(void) {
  const char *mode = (g_root_level == 2U) ? "sv39" : "sv48";

  /* The windows have to be empty before anything is mapped into them. A
     machine large enough for the identity map to reach 192 GiB would
     otherwise have this test quietly replace part of its own RAM mapping,
     and the failure would appear later and elsewhere. */
  static const uint64_t windows[3] = {SELF_TEST_LARGE_VA,
                                      SELF_TEST_GIGANTIC_VA,
                                      SELF_TEST_SPLIT_VA};
  for (uint32_t i = 0U; i < 3U; ++i) {
    if (vmm_translate(windows[i], 0, 0) == XAIOS_OK) {
      vmm_panic("large-page self-test window %lx is already mapped; this "
                "machine is too large for the addresses the test picked",
                windows[i]);
    }
  }

  /* Every mapping made below goes into the shared kernel root, and this hart
     is not running on the shared kernel root -- it is running on its own
     copy, built by build_per_hart_roots. So each `vmm_translate` after a map
     is also a check that sync_kernel_hierarchy mirrored the new top-level
     entry into this hart's copy, which is the failure mode where one hart
     sees a kernel mapping and the others fault on it. That only means
     anything if the two roots really are different pages, so say so. */
  if (current_root() == g_kernel_root) {
    vmm_panic("large-page self-test is running on the shared kernel root, so "
              "its per-hart mirroring checks would prove nothing");
  }

  void *page = pmm_alloc_page();
  if (page == 0) vmm_panic("large-page self-test has no page to alias");
  uint64_t physical = (uint64_t)(uintptr_t)page;
  volatile uint64_t *identity = (volatile uint64_t *)(uintptr_t)physical;
  uint64_t observed = 0U;
  uint32_t flags = 0U;

  /* --- 2 MiB --- */
  /* Aliased onto real memory rather than onto an arbitrary physical address,
     because a leaf pointing at nothing can only be inspected, never used. The
     2 MiB block containing an allocator page is inside RAM by construction:
     RAM starts at a 2 MiB boundary and the page came from inside it. Only the
     one page's worth of that block is ever touched. */
  uint64_t large_pa = physical & ~(XAIOS_VMM_LARGE_PAGE_SIZE - 1U);
  uint64_t large_offset = physical - large_pa;
  *identity = SELF_TEST_LARGE_SIGNATURE;

  if (vmm_map_large_page(SELF_TEST_LARGE_VA, large_pa,
                         XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE) != XAIOS_OK) {
    vmm_panic("could not map a 2 MiB leaf at %lx", SELF_TEST_LARGE_VA);
  }
  /* Collision-safe, as the other two architectures are. Same physical
     address and fewer flags: still a refusal, because the caller does not get
     to find out by accident that something was already there. */
  if (vmm_map_large_page(SELF_TEST_LARGE_VA, large_pa, XAIOS_VMM_PRESENT) !=
      XAIOS_ERR_BUSY) {
    vmm_panic("a second 2 MiB map over a live one was not refused");
  }
  /* The last byte of the leaf, not the first: an entry whose span was
     computed wrongly still translates its own base address correctly. */
  if (vmm_translate(SELF_TEST_LARGE_VA + XAIOS_VMM_LARGE_PAGE_SIZE - 1U,
                    &observed, &flags) != XAIOS_OK ||
      observed != large_pa + XAIOS_VMM_LARGE_PAGE_SIZE - 1U) {
    vmm_panic("2 MiB leaf translated its last byte to %lx not %lx", observed,
              large_pa + XAIOS_VMM_LARGE_PAGE_SIZE - 1U);
  }
  if (vmm_validate_range_flags(SELF_TEST_LARGE_VA, XAIOS_VMM_LARGE_PAGE_SIZE,
                               XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE,
                               XAIOS_VMM_USER | XAIOS_VMM_EXECUTABLE) !=
      XAIOS_OK) {
    vmm_panic("2 MiB leaf did not validate as writable, non-user, "
              "non-executable across its whole span");
  }
  /* Structural: it has to be a leaf at level 1, not a table of 4 KiB pages
     that happens to describe the same memory. Both translate identically. */
  uint64_t *large_entry = walk(g_kernel_root, SELF_TEST_LARGE_VA, 1U, 0);
  if (large_entry == 0 || (*large_entry & PTE_V) == 0U ||
      (*large_entry & PTE_LEAF) == 0U) {
    vmm_panic("the 2 MiB mapping is not a leaf at level 1");
  }
  /* The hardware's opinion, through the alias. */
  volatile uint64_t *large_alias =
      (volatile uint64_t *)(uintptr_t)(SELF_TEST_LARGE_VA + large_offset);
  if (*large_alias != SELF_TEST_LARGE_SIGNATURE) {
    vmm_panic("read through a 2 MiB leaf gave %lx not %lx", *large_alias,
              SELF_TEST_LARGE_SIGNATURE);
  }
  *large_alias = ~SELF_TEST_LARGE_SIGNATURE;
  if (*identity != ~SELF_TEST_LARGE_SIGNATURE) {
    vmm_panic("a write through a 2 MiB leaf did not reach the memory it "
              "claims to describe");
  }
  if (vmm_unmap_large_page(SELF_TEST_LARGE_VA) != XAIOS_OK) {
    vmm_panic("could not unmap the 2 MiB leaf at %lx", SELF_TEST_LARGE_VA);
  }
  if (vmm_translate(SELF_TEST_LARGE_VA, 0, 0) == XAIOS_OK) {
    vmm_panic("a 2 MiB leaf still translates after being unmapped");
  }
  /* A second, independent witness that the entry is gone rather than merely
     unreachable: unmap reports not-found for an address it has nothing to
     remove at. This is deliberately the opposite of vmm_unmap_page, which
     answers OK for an absent page because shared code unmaps guard pages that
     were never mapped; the difference is pinned here so that it stays a
     decision. */
  if (vmm_unmap_large_page(SELF_TEST_LARGE_VA) != XAIOS_ERR_NOT_FOUND) {
    vmm_panic("unmapping an absent 2 MiB leaf did not report not-found");
  }
  klog("vmm: 2 MiB large-page map/unmap self-test passed mode=%s\n", mode);

  /* --- 1 GiB --- */
  uint64_t gigantic_pa = physical & ~(XAIOS_VMM_GIGANTIC_PAGE_SIZE - 1U);
  uint64_t gigantic_offset = physical - gigantic_pa;
  *identity = SELF_TEST_GIGANTIC_SIGNATURE;

  if (vmm_map_gigantic_page(SELF_TEST_GIGANTIC_VA, gigantic_pa,
                            XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE) !=
      XAIOS_OK) {
    vmm_panic("could not map a 1 GiB leaf at %lx", SELF_TEST_GIGANTIC_VA);
  }
  if (vmm_map_gigantic_page(SELF_TEST_GIGANTIC_VA, gigantic_pa,
                            XAIOS_VMM_PRESENT) != XAIOS_ERR_BUSY) {
    vmm_panic("a second 1 GiB map over a live one was not refused");
  }
  if (vmm_translate(SELF_TEST_GIGANTIC_VA + XAIOS_VMM_GIGANTIC_PAGE_SIZE - 1U,
                    &observed, &flags) != XAIOS_OK ||
      observed != gigantic_pa + XAIOS_VMM_GIGANTIC_PAGE_SIZE - 1U) {
    vmm_panic("1 GiB leaf translated its last byte to %lx not %lx", observed,
              gigantic_pa + XAIOS_VMM_GIGANTIC_PAGE_SIZE - 1U);
  }
  /* Where the leaf actually sits, which is the whole reason both modes have
     to be exercised. Sv39 enters at level 2, so a 1 GiB leaf is an entry in
     the root table the hardware is pointed at; Sv48 enters at level 3, so the
     same leaf is one level further down. A test that only asked whether
     translation worked would pass identically on a kernel that had the two
     confused, because `walk` starts from g_root_level and would follow
     whichever shape it built. */
  uint64_t *gigantic_entry = walk(g_kernel_root, SELF_TEST_GIGANTIC_VA, 2U, 0);
  if (gigantic_entry == 0 || (*gigantic_entry & PTE_V) == 0U ||
      (*gigantic_entry & PTE_LEAF) == 0U) {
    vmm_panic("the 1 GiB mapping is not a leaf at level 2");
  }
  uint64_t *root_slot =
      &g_kernel_root[index_at(SELF_TEST_GIGANTIC_VA, 2U)];
  uint32_t leaf_in_root = (gigantic_entry == root_slot) ? 1U : 0U;
  if (g_root_level == 2U && leaf_in_root == 0U) {
    vmm_panic("sv39: a 1 GiB leaf is not in the root table it must be in");
  }
  if (g_root_level != 2U && leaf_in_root != 0U) {
    vmm_panic("sv48: a 1 GiB leaf landed in the root table, which is a "
              "level-3 table and cannot hold one");
  }
  volatile uint64_t *gigantic_alias =
      (volatile uint64_t *)(uintptr_t)(SELF_TEST_GIGANTIC_VA +
                                       gigantic_offset);
  if (*gigantic_alias != SELF_TEST_GIGANTIC_SIGNATURE) {
    vmm_panic("read through a 1 GiB leaf gave %lx not %lx", *gigantic_alias,
              SELF_TEST_GIGANTIC_SIGNATURE);
  }
  *gigantic_alias = ~SELF_TEST_GIGANTIC_SIGNATURE;
  if (*identity != ~SELF_TEST_GIGANTIC_SIGNATURE) {
    vmm_panic("a write through a 1 GiB leaf did not reach the memory it "
              "claims to describe");
  }
  if (vmm_unmap_gigantic_page(SELF_TEST_GIGANTIC_VA) != XAIOS_OK) {
    vmm_panic("could not unmap the 1 GiB leaf at %lx", SELF_TEST_GIGANTIC_VA);
  }
  if (vmm_translate(SELF_TEST_GIGANTIC_VA, 0, 0) == XAIOS_OK) {
    vmm_panic("a 1 GiB leaf still translates after being unmapped");
  }
  klog("vmm: 1 GiB gigantic-page self-test passed mode=%s leaf_in_root=%u\n",
       mode, leaf_in_root);

  /* --- splitting a gigantic leaf --- */
  /* This is the part with no counterpart on the other two architectures, and
     it is the part most likely to be wrong here. AArch64 and x86-64 refuse to
     map a small page inside a large one; this walk splits the large one
     instead, because vmm_init covers the device window in gibibyte leaves and
     kmain then maps that window a page at a time -- refusing meant the kernel
     could not unmap a device page it had itself mapped.
     A split is only safe if it is total. Every entry of the replacement table
     has to be filled from the leaf before the leaf is replaced, or addresses
     that resolved a moment ago stop resolving, and the ones that stop are the
     ones nobody was looking at. So the checks below are about the addresses
     the caller did *not* ask about. */
  void *override_page = pmm_alloc_page();
  if (override_page == 0) {
    vmm_panic("large-page split self-test has no page to override with");
  }
  uint64_t override_physical = (uint64_t)(uintptr_t)override_page;
  /* The far neighbour is chosen in a different 2 MiB child than the page
     under test, rather than fixed at offset zero and the page required to be
     elsewhere.
     
     The check needs two things from one gibibyte: the child holding the 4 KiB
     override, and some other child that a partial split would have lost. It
     used to take offset zero for the second and panic when the page landed in
     that same first 2 MiB -- reasoning that the allocator hands out pages
     above the kernel image, which starts 2 MiB into RAM. That holds under
     -kernel and not under EDK2, where firmware owns the bottom of RAM and the
     first free page sits low in its gibibyte, so the machine booted on one
     firmware and died on a cyan screen on the other over where a page landed.
     Requiring a better page cannot work either: pages come out sequentially,
     so crossing 2 MiB would take five hundred of them.
     
     Picking the child instead is exact rather than lucky. Any child but the
     one the override is in will do, and there are 512 of them. */
  const uint64_t child_index = gigantic_offset / XAIOS_VMM_LARGE_PAGE_SIZE;
  const uint64_t far_child = (child_index == 0U) ? 1U : 0U;
  const uint64_t far_va =
      SELF_TEST_SPLIT_VA + far_child * XAIOS_VMM_LARGE_PAGE_SIZE;
  const uint64_t far_expected =
      gigantic_pa + far_child * XAIOS_VMM_LARGE_PAGE_SIZE;

  if (vmm_map_gigantic_page(SELF_TEST_SPLIT_VA, gigantic_pa,
                            XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE) !=
      XAIOS_OK) {
    vmm_panic("could not map the 1 GiB leaf the split test splits");
  }
  uint64_t inner_va = SELF_TEST_SPLIT_VA + gigantic_offset + PAGE_SIZE;
  uint64_t near_va = SELF_TEST_SPLIT_VA + gigantic_offset;
  if (vmm_translate(inner_va, &observed, 0) != XAIOS_OK) {
    vmm_panic("split self-test's inner address %lx is not inside the gigantic "
              "leaf at all", inner_va);
  }
  if (observed != physical + PAGE_SIZE) {
    vmm_panic("split self-test's inner address started out at %lx not %lx",
              observed, physical + PAGE_SIZE);
  }
  /* One 4 KiB page inside the gibibyte, pointed somewhere else. Reaching it
     costs two splits: level 2 to a table of 2 MiB leaves, then level 1 to a
     table of 4 KiB pages. */
  if (vmm_map_page(inner_va, override_physical,
                   XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE) != XAIOS_OK) {
    vmm_panic("could not map a 4 KiB page inside a 1 GiB leaf");
  }
  if (vmm_translate(inner_va, &observed, 0) != XAIOS_OK) {
    vmm_panic("a 4 KiB page mapped inside a gigantic leaf does not translate");
  }
  if (observed != override_physical) {
    vmm_panic("a 4 KiB page inside a split gigantic leaf translated to %lx "
              "not %lx", observed, override_physical);
  }
  /* The neighbour in the same 2 MiB table: the level-1 to level-0 split has
     to have filled it. Checked by reading the signature back, not only by
     translating, so a table filled with plausible-looking wrong entries is
     caught too. */
  if (vmm_translate(near_va, &observed, 0) != XAIOS_OK) {
    vmm_panic("splitting a gigantic leaf left its neighbour %lx unmapped",
              near_va);
  }
  if (observed != physical) {
    vmm_panic("splitting a gigantic leaf moved its neighbour to %lx not %lx",
              observed, physical);
  }
  if (*(volatile uint64_t *)(uintptr_t)near_va != ~SELF_TEST_GIGANTIC_SIGNATURE) {
    vmm_panic("the neighbour of a split page reads the wrong memory");
  }
  /* The neighbour in a different 2 MiB table: the level-2 to level-1 split
     has to have filled that one too, and it is the one a partial split would
     lose, because nothing ever walked through it. */
  if (vmm_translate(far_va, &observed, 0) != XAIOS_OK) {
    vmm_panic("splitting a gigantic leaf left a distant 2 MiB window "
              "unmapped at %lx", far_va);
  }
  if (observed != far_expected) {
    vmm_panic("splitting a gigantic leaf moved a distant 2 MiB window to %lx "
              "not %lx", observed, far_expected);
  }
  /* Removing the whole gibibyte removes the tables the split produced with
     it. The tables themselves are not returned to the allocator -- three
     pages for the life of the boot, which is the same thing every other
     table this file allocates does. */
  if (vmm_unmap_gigantic_page(SELF_TEST_SPLIT_VA) != XAIOS_OK) {
    vmm_panic("could not unmap a gigantic leaf that had been split");
  }
  if (vmm_translate(SELF_TEST_SPLIT_VA, 0, 0) == XAIOS_OK ||
      vmm_translate(inner_va, 0, 0) == XAIOS_OK) {
    vmm_panic("a split gigantic leaf still translates after being unmapped");
  }
  pmm_free_page(override_page);
  klog("vmm: gigantic-page split self-test passed mode=%s\n", mode);

  /* --- Sv48 only: above the first top-level slot --- */
  /* AArch64 has the same test and the same reason for it. Every address this
     kernel uses on Sv39 lives under one root entry, so a walk that assumed
     slot zero would work everywhere and fail on the first machine that used a
     second. Sv48 is where that can be asked, because its root covers 512 GiB
     a slot; Sv39's whole address space is 512 GiB, so the question does not
     exist there and this is skipped rather than faked.
     It is also the only place `sync_kernel_hierarchy` takes its l0 != 0
     branch, which mirrors a whole root slot into every hart's root instead of
     mirroring one entry of the copied low table. */
  if (g_root_level == 3U) {
    if (vmm_translate(SELF_TEST_HIGH_VA, 0, 0) == XAIOS_OK) {
      vmm_panic("sv48 high-slot window %lx is already mapped",
                SELF_TEST_HIGH_VA);
    }
    if (vmm_map_gigantic_page(SELF_TEST_HIGH_VA, gigantic_pa,
                              XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE) !=
        XAIOS_OK) {
      vmm_panic("could not map a 1 GiB leaf above the first root slot");
    }
    if (vmm_translate(SELF_TEST_HIGH_VA + gigantic_offset, &observed, 0) !=
        XAIOS_OK) {
      vmm_panic("a 1 GiB leaf above the first root slot does not translate; "
                "this hart's root did not receive it");
    }
    if (observed != physical) {
      vmm_panic("a 1 GiB leaf above the first root slot translated to %lx "
                "not %lx", observed, physical);
    }
    if (*(volatile uint64_t *)(uintptr_t)(SELF_TEST_HIGH_VA +
                                          gigantic_offset) !=
        ~SELF_TEST_GIGANTIC_SIGNATURE) {
      vmm_panic("a 1 GiB leaf above the first root slot reads the wrong "
                "memory");
    }
    if (vmm_unmap_gigantic_page(SELF_TEST_HIGH_VA) != XAIOS_OK) {
      vmm_panic("could not unmap a 1 GiB leaf above the first root slot");
    }
    if (vmm_translate(SELF_TEST_HIGH_VA, 0, 0) == XAIOS_OK) {
      vmm_panic("a 1 GiB leaf above the first root slot still translates "
                "after being unmapped");
    }
    klog("vmm: gigantic page above the first root slot passed va=0x%lx\n",
         SELF_TEST_HIGH_VA);
  }

  pmm_free_page(page);
}

void riscv64_isa_self_test(void);

void vmm_self_test(void) {
  /* A mapping made, read back through the same walk a fault would take, and
     removed again. Proving translate agrees with map is the whole point:
     they are separate walks over the same tables, and a kernel where they
     disagree fails only when something dereferences the difference. */
  uint64_t probe = XAIOS_USER_BASE - XAIOS_VMM_LARGE_PAGE_SIZE;
  void *page = pmm_alloc_page();
  if (page == 0) vmm_panic("vmm self-test has no page to map");
  uint64_t physical = (uint64_t)(uintptr_t)page;

  if (vmm_map_page(probe, physical, XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE) !=
      XAIOS_OK) {
    vmm_panic("vmm self-test could not map %lx", probe);
  }
  uint64_t observed = 0U;
  uint32_t flags = 0U;
  if (vmm_translate(probe, &observed, &flags) != XAIOS_OK ||
      observed != physical) {
    vmm_panic("vmm self-test translate mismatch: %lx not %lx", observed,
              physical);
  }
  if ((flags & XAIOS_VMM_WRITABLE) == 0U) {
    vmm_panic("vmm self-test lost the writable flag");
  }
  *(volatile uint64_t *)(uintptr_t)probe = UINT64_C(0x5849414f53525634);
  if (*(volatile uint64_t *)(uintptr_t)probe != UINT64_C(0x5849414f53525634)) {
    vmm_panic("vmm self-test wrote through a mapping and read back nothing");
  }
  if (vmm_unmap_page(probe) != XAIOS_OK) {
    vmm_panic("vmm self-test could not unmap %lx", probe);
  }
  if (vmm_translate(probe, 0, 0) == XAIOS_OK) {
    vmm_panic("vmm self-test unmapped a page that still translates");
  }
  pmm_free_page(page);
  klog("vmm: self-test passed (map, translate, write, unmap)\n");
  /* The large and gigantic leaves the shared interface promises, which this
     port implemented and nothing ever checked. Run after the 4 KiB case
     because it depends on it: every assertion below reads its result back
     through the same translate that has just been shown to agree with map. */
  vmm_large_page_self_test();
  /* What only this architecture has, checked once its page tables are
     live -- the satp mode is part of what is being reported, and a
     reading taken before translation is on says nothing. Shared code
     stays unaware of it, which is the rule. */
  riscv64_isa_self_test();
}

/* Whether translation is on, which the spinlock implementation asks before
   using an atomic.
   Not a formality here. RISC-V's load-reserved/store-conditional pair is only
   guaranteed on memory the hart can address through the MMU, and the same
   question on AArch64 is why every secondary used to announce itself into
   memory the boot CPU was not reading (V-04). Answering it honestly means
   reading satp rather than returning a constant. */
uint32_t xaios_translation_enabled(void) {
  uint64_t satp = 0U;
  __asm__ volatile("csrr %0, satp" : "=r"(satp));
  return (satp >> 60) != 0U ? 1U : 0U;
}
