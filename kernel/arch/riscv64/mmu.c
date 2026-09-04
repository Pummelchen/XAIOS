/* Sv48 paging for RISC-V.
 *
 * Sv48 rather than Sv39, and the reason is the shared kernel rather than any
 * preference. `XAIOS_USER_BASE` is 0x7fc0000000 -- 511 GiB -- and Sv39
 * addresses 256. So a kernel using Sv39 could not place userspace where every
 * other architecture places it, and the choice was between a third paging
 * mode and a per-architecture user layout. The layout is shared on purpose;
 * the paging mode is not visible above this file. Sv48 keeps the constant
 * that matters and hides the difference that does not.
 *
 * The bring-up used Sv39 with four gibibyte leaves, which was right for
 * proving translation could be turned on and wrong for everything after it.
 * This replaces it.
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

/* Walk to the entry that would describe `virtual_address` at `target_level`,
   creating intermediate tables when asked. Level 0 is a 4 KiB page, 1 is
   2 MiB, 2 is 1 GiB. */
static uint64_t *walk(uint64_t *root, uint64_t virtual_address,
                      uint32_t target_level, int create) {
  uint64_t *table = root;
  for (uint32_t level = LEVELS - 1U; level > target_level; --level) {
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
  if ((satp >> 60) == 0U) return g_root;
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
  uint32_t l0 = index_at(virtual_address, 3U);
  uint32_t l1 = index_at(virtual_address, 2U);
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
    for (uint32_t i = 0U; i < ENTRIES; ++i) {
      tables->root[i] = g_root[i];
      tables->low[i] = shared_low != 0 ? shared_low[i] : 0U;
    }
    tables->root[0] = pte_for((uint64_t)(uintptr_t)tables->low, 0U);
    tables->low[USER_L1_INDEX] =
        pte_for((uint64_t)(uintptr_t)tables->user_directory, 0U);
    tables->satp =
        SATP_MODE_SV48 | ((uint64_t)(uintptr_t)tables->root >> 12);
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
  if (root == g_root) sync_kernel_hierarchy(virtual_address);
  flush_one(virtual_address);
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
  /* The walk may have split a larger page, which replaced an entry above
     this one; mirror that whether or not there is anything to unmap. */
  if (root == g_root) sync_kernel_hierarchy(virtual_address);
  if (entry == 0 || (*entry & PTE_V) == 0U) return XAIOS_ERR_NOT_FOUND;
  *entry = 0U;
  flush_one(virtual_address);
  return XAIOS_OK;
}

/* Page-granular, for ranges whose permissions have to be exact. */
static void identity_map_pages(uint64_t start, uint64_t end, uint32_t flags) {
  start &= ~(PAGE_SIZE - 1U);
  end = (end + PAGE_SIZE - 1U) & ~(PAGE_SIZE - 1U);
  for (uint64_t address = start; address < end; address += PAGE_SIZE) {
    if (map_at_level(g_root, address, address, flags, 0U) != XAIOS_OK) return;
  }
}

static void identity_map_range(uint64_t start, uint64_t end, uint32_t flags) {
  start &= ~(PAGE_SIZE - 1U);
  end = (end + PAGE_SIZE - 1U) & ~(PAGE_SIZE - 1U);
  for (uint64_t address = start; address < end;) {
    /* Gigantic where it fits, which is what keeps the early table pool small
       enough to be static. A 256 MiB machine mapped in 4 KiB pages would need
       more tables than a kernel has before it can allocate any. */
    uint64_t gigantic = XAIOS_VMM_GIGANTIC_PAGE_SIZE;
    if ((address & (gigantic - 1U)) == 0U && end - address >= gigantic) {
      if (map_at_level(g_root, address, address, flags, 2U) != XAIOS_OK) return;
      address += gigantic;
      continue;
    }
    uint64_t large = XAIOS_VMM_LARGE_PAGE_SIZE;
    if ((address & (large - 1U)) == 0U && end - address >= large) {
      if (map_at_level(g_root, address, address, flags, 1U) != XAIOS_OK) return;
      address += large;
      continue;
    }
    if (map_at_level(g_root, address, address, flags, 0U) != XAIOS_OK) return;
    address += PAGE_SIZE;
  }
}

void vmm_init(const xaios_boot_info_t *boot) {
  for (uint32_t i = 0U; i < ENTRIES; ++i) g_root[i] = 0U;
  g_early_used = 0U;
  g_initialized = 0U;

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

  g_satp = SATP_MODE_SV48 | ((uint64_t)(uintptr_t)g_root >> 12);
  vmm_activate_kernel();

  uint64_t observed = 0U;
  __asm__ volatile("csrr %0, satp" : "=r"(observed));
  if (observed != g_satp) {
    /* Sv48 declined. Reported rather than silently falling back to Sv39,
       because Sv39 cannot address where this kernel puts userspace -- a
       fallback would boot and then fail somewhere far less obvious. */
    vmm_panic("Sv48 refused by this hart: satp reads %lx, wanted %lx",
              observed, g_satp);
  }
  g_initialized = 1U;
  build_per_hart_roots();
  vmm_activate_kernel();
  klog("vmm: sv48 enabled root=%lx early_tables=%u/%u harts=%u "
       "mode=per-hart-user-aspace\n",
       (uint64_t)(uintptr_t)g_root, g_early_used, EARLY_TABLES,
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
  return map_at_level(g_root, virtual_address, physical_address, flags, 0U);
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
  xaios_status_t status = unmap_at_level(g_root, virtual_address, 0U);
  return status == XAIOS_ERR_NOT_FOUND ? XAIOS_OK : status;
}

xaios_status_t vmm_map_large_page(uint64_t virtual_address,
                                  uint64_t physical_address, uint32_t flags) {
  return map_at_level(g_root, virtual_address, physical_address, flags, 1U);
}

xaios_status_t vmm_unmap_large_page(uint64_t virtual_address) {
  return unmap_at_level(g_root, virtual_address, 1U);
}

xaios_status_t vmm_map_gigantic_page(uint64_t virtual_address,
                                     uint64_t physical_address,
                                     uint32_t flags) {
  return map_at_level(g_root, virtual_address, physical_address, flags, 2U);
}

xaios_status_t vmm_unmap_gigantic_page(uint64_t virtual_address) {
  return unmap_at_level(g_root, virtual_address, 2U);
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
