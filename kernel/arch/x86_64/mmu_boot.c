/* Boot-time x86_64 page tables, and the walk every mapping is built on.
 *
 * build_tables lays down the 4 GiB identity map, the kernel image's own 4 KiB
 * mappings and the user directory slot, build_per_cpu_roots copies that
 * hierarchy into one root per CPU, and vmm_init turns on EFER.NXE and CR0.WP
 * with it. The helpers beside them -- the PTE encoding, the allocate-or-find
 * table walk, the per-CPU mirror -- are what the runtime mapping entry points
 * in mmu.c and the per-process address spaces in mmu_user.c call through
 * mmu_internal.h.
 *
 * vmm_init and vmm_activate_kernel live here because they are the only
 * callers of the table builder and of the CR3 reload, and because that keeps
 * this file's table state private. Nothing here changed order, table layout or
 * invalidation; it moved whole. early_mem.c is a separate x86_64 file with its
 * own early page tables and its own history, and is not part of this map.
 */
#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/pmm.h>
#include <xaios/smp.h>
#include <xaios/vmm.h>

#include "mmu_internal.h"
#include "platform.h"

#define EARLY_IDENTITY_SIZE UINT64_C(0x100000000)
#define EARLY_KERNEL_TABLES 32U
#define EFER_MSR UINT32_C(0xc0000080)
#define EFER_NXE (UINT64_C(1) << 11)
#define CR0_WP (UINT64_C(1) << 16)

/* Which top-level-but-one slot userspace occupies. This was written out as a
   literal 4 in three places, which was correct only while the user window
   began at 4 GiB, and silently wrong the moment it moved: the kernel
   hierarchy sync overwrote the user entry and installed the user directory
   somewhere nothing looked, so the first instruction fetch in userspace
   faulted. Derived from the one constant that defines it. */
#define USER_PDPT_INDEX \
  ((uint32_t)((XAIOS_USER_BASE >> 30U) & UINT64_C(0x1ff)))

extern char __text_start[];
extern char __text_end[];
extern char __rodata_start[];
extern char __rodata_end[];
extern char __data_start[];
extern char __data_end[];
extern char __bss_start[];
extern char __bss_end[];

static uint64_t g_pml4[512] __attribute__((aligned(PAGE_SIZE)));
static uint64_t g_low_pdpt[512] __attribute__((aligned(PAGE_SIZE)));
static uint64_t g_low_pd[4][512] __attribute__((aligned(PAGE_SIZE)));
static uint64_t g_user_pd[512] __attribute__((aligned(PAGE_SIZE)));
static uint64_t g_kernel_pt[EARLY_KERNEL_TABLES][512]
    __attribute__((aligned(PAGE_SIZE)));
static uint32_t g_kernel_pt_count;

uint64_t x86mmu_align_down(uint64_t value, uint64_t alignment) {
  return value & ~(alignment - 1U);
}

static uint64_t align_up(uint64_t value, uint64_t alignment) {
  if (value > UINT64_MAX - (alignment - 1U)) return UINT64_MAX;
  return (value + alignment - 1U) & ~(alignment - 1U);
}

static void zero_page(uint64_t *page) {
  for (uint32_t index = 0U; index < 512U; ++index) page[index] = 0U;
}

static inline uint64_t read_cr0(void) {
  uint64_t value;
  __asm__ volatile("mov %%cr0, %0" : "=r"(value));
  return value;
}

static inline void write_cr0(uint64_t value) {
  __asm__ volatile("mov %0, %%cr0" : : "r"(value) : "memory");
}

static inline void write_cr3(uint64_t value) {
  __asm__ volatile("mov %0, %%cr3" : : "r"(value) : "memory");
}

static inline uint64_t read_msr(uint32_t msr) {
  uint32_t low;
  uint32_t high;
  __asm__ volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(msr));
  return ((uint64_t)high << 32U) | low;
}

static inline void write_msr(uint32_t msr, uint64_t value) {
  __asm__ volatile("wrmsr"
                   :
                   : "c"(msr), "a"((uint32_t)value),
                     "d"((uint32_t)(value >> 32U))
                   : "memory");
}

uint64_t x86mmu_shared_root_address(void) {
  return (uint64_t)(uintptr_t)g_pml4;
}

uint64_t x86mmu_current_root_address(void) {
  uint64_t *root =
      x86_64_platform_page_table_root(x86_64_platform_current_ordinal());
  return (uint64_t)(uintptr_t)(root != 0 ? root : g_pml4);
}

void x86mmu_flush_tlb(void) {
  write_cr3(x86mmu_current_root_address());
}

uint64_t x86mmu_table_entry(const uint64_t *table, uint64_t flags) {
  return ((uint64_t)(uintptr_t)table & PTE_ADDRESS_MASK) | PTE_PRESENT |
         PTE_WRITABLE | flags;
}

uint64_t x86mmu_flags_to_pte(uint32_t flags) {
  uint64_t pte = PTE_PRESENT;
  if ((flags & XAIOS_VMM_WRITABLE) != 0U) pte |= PTE_WRITABLE;
  if ((flags & XAIOS_VMM_USER) != 0U) pte |= PTE_USER;
  if ((flags & XAIOS_VMM_DEVICE) != 0U) pte |= PTE_DEVICE;
  if ((flags & XAIOS_VMM_EXECUTABLE) == 0U) pte |= PTE_NX;
  if ((flags & XAIOS_VMM_NG) == 0U && (flags & XAIOS_VMM_USER) == 0U) {
    pte |= PTE_GLOBAL;
  }
  return pte;
}

static uint32_t kernel_flags(uint64_t address) {
  if (address >= (uint64_t)(uintptr_t)__text_start &&
      address < (uint64_t)(uintptr_t)__text_end) {
    return XAIOS_VMM_PRESENT | XAIOS_VMM_EXECUTABLE;
  }
  if (address >= (uint64_t)(uintptr_t)__rodata_start &&
      address < (uint64_t)(uintptr_t)__rodata_end) {
    return XAIOS_VMM_PRESENT;
  }
  if ((address >= (uint64_t)(uintptr_t)__data_start &&
       address < (uint64_t)(uintptr_t)__data_end) ||
      (address >= (uint64_t)(uintptr_t)__bss_start &&
       address < (uint64_t)(uintptr_t)__bss_end)) {
    return XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE;
  }
  return XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE;
}

uint64_t *x86mmu_allocate_table(void) {
  uint64_t *table = (uint64_t *)pmm_alloc_page();
  if (table != 0) zero_page(table);
  return table;
}

uint64_t *x86mmu_ensure_pt(uint64_t *root, uint64_t virtual_address,
                           uint32_t flags) {
  uint32_t pml4_index = (uint32_t)((virtual_address >> 39U) & 0x1ffU);
  uint32_t pdpt_index = (uint32_t)((virtual_address >> 30U) & 0x1ffU);
  uint32_t pd_index = (uint32_t)((virtual_address >> 21U) & 0x1ffU);
  uint64_t *pdpt;
  uint64_t *pd;
  uint64_t *pt;
  uint64_t hierarchy_flags =
      (flags & XAIOS_VMM_USER) != 0U ? PTE_USER : 0U;

  if ((root[pml4_index] & PTE_PRESENT) == 0U) {
    pdpt = x86mmu_allocate_table();
    kassert(pdpt != 0);
    root[pml4_index] = x86mmu_table_entry(pdpt, hierarchy_flags);
  } else {
    root[pml4_index] |= hierarchy_flags;
    pdpt = (uint64_t *)(uintptr_t)(root[pml4_index] & PTE_ADDRESS_MASK);
  }

  uint64_t pdpt_entry = pdpt[pdpt_index];
  if ((pdpt_entry & PTE_PRESENT) == 0U ||
      (pdpt_entry & PTE_LARGE) != 0U) {
    pd = x86mmu_allocate_table();
    kassert(pd != 0);
    if ((pdpt_entry & (PTE_PRESENT | PTE_LARGE)) ==
        (PTE_PRESENT | PTE_LARGE)) {
      uint64_t base = pdpt_entry & PTE_HUGE_ADDRESS_MASK;
      uint64_t attributes = pdpt_entry & ~PTE_HUGE_ADDRESS_MASK;
      attributes &= ~PTE_LARGE;
      for (uint32_t index = 0U; index < 512U; ++index) {
        pd[index] = (base + (uint64_t)index * LARGE_PAGE_SIZE) |
                    attributes | PTE_LARGE;
      }
    }
    pdpt[pdpt_index] = x86mmu_table_entry(pd, hierarchy_flags);
  } else {
    pdpt[pdpt_index] |= hierarchy_flags;
    pd = (uint64_t *)(uintptr_t)(pdpt_entry & PTE_ADDRESS_MASK);
  }

  uint64_t pd_entry = pd[pd_index];
  if ((pd_entry & PTE_PRESENT) != 0U && (pd_entry & PTE_LARGE) == 0U) {
    pd[pd_index] |= hierarchy_flags;
    return (uint64_t *)(uintptr_t)(pd_entry & PTE_ADDRESS_MASK);
  }
  pt = x86mmu_allocate_table();
  kassert(pt != 0);
  if ((pd_entry & (PTE_PRESENT | PTE_LARGE)) ==
      (PTE_PRESENT | PTE_LARGE)) {
    uint64_t base = pd_entry & PTE_LARGE_ADDRESS_MASK;
    uint64_t attributes = pd_entry & ~PTE_LARGE_ADDRESS_MASK;
    attributes &= ~PTE_LARGE;
    for (uint32_t index = 0U; index < 512U; ++index) {
      pt[index] = base + (uint64_t)index * PAGE_SIZE + attributes;
    }
  }
  pd[pd_index] = x86mmu_table_entry(pt, hierarchy_flags);
  return pt;
}

uint64_t *x86mmu_ensure_pd(uint64_t *root, uint64_t virtual_address) {
  uint32_t pml4_index = (uint32_t)((virtual_address >> 39U) & 0x1ffU);
  uint32_t pdpt_index = (uint32_t)((virtual_address >> 30U) & 0x1ffU);
  uint64_t *pdpt;
  uint64_t *pd;

  if ((root[pml4_index] & PTE_PRESENT) == 0U) {
    pdpt = x86mmu_allocate_table();
    if (pdpt == 0) return 0;
    root[pml4_index] = x86mmu_table_entry(pdpt, 0U);
  } else {
    if ((root[pml4_index] & PTE_LARGE) != 0U) return 0;
    pdpt = (uint64_t *)(uintptr_t)(root[pml4_index] & PTE_ADDRESS_MASK);
  }

  uint64_t pdpt_entry = pdpt[pdpt_index];
  if ((pdpt_entry & PTE_PRESENT) == 0U) {
    pd = x86mmu_allocate_table();
    if (pd == 0) return 0;
    pdpt[pdpt_index] = x86mmu_table_entry(pd, 0U);
    return pd;
  }
  if ((pdpt_entry & PTE_LARGE) != 0U) return 0;
  return (uint64_t *)(uintptr_t)(pdpt_entry & PTE_ADDRESS_MASK);
}

uint64_t *x86mmu_find_pd(uint64_t *root, uint64_t virtual_address) {
  uint64_t pml4e = root[(virtual_address >> 39U) & 0x1ffU];
  if ((pml4e & PTE_PRESENT) == 0U || (pml4e & PTE_LARGE) != 0U) return 0;
  uint64_t *pdpt = (uint64_t *)(uintptr_t)(pml4e & PTE_ADDRESS_MASK);
  uint64_t pdpte = pdpt[(virtual_address >> 30U) & 0x1ffU];
  if ((pdpte & PTE_PRESENT) == 0U || (pdpte & PTE_LARGE) != 0U) return 0;
  return (uint64_t *)(uintptr_t)(pdpte & PTE_ADDRESS_MASK);
}

void x86mmu_sync_kernel_hierarchy(uint64_t virtual_address) {
  uint32_t pml4_index = (uint32_t)((virtual_address >> 39U) & 0x1ffU);
  uint32_t pdpt_index = (uint32_t)((virtual_address >> 30U) & 0x1ffU);
  uint32_t capacity = smp_capacity();
  for (uint32_t cpu = 0U; cpu < capacity; ++cpu) {
    uint64_t *root = x86_64_platform_page_table_root(cpu);
    if (root == 0) continue;
    if (pml4_index != 0U) {
      root[pml4_index] = g_pml4[pml4_index];
      continue;
    }
    uint64_t *pdpt =
        (uint64_t *)(uintptr_t)(root[0] & PTE_ADDRESS_MASK);
    if (pdpt_index != USER_PDPT_INDEX) {
      pdpt[pdpt_index] = g_low_pdpt[pdpt_index];
    }
  }
}

static void build_tables(const xaios_boot_info_t *boot) {
  zero_page(g_pml4);
  zero_page(g_low_pdpt);
  zero_page(g_user_pd);
  for (uint32_t index = 0U; index < 4U; ++index) zero_page(g_low_pd[index]);
  for (uint32_t index = 0U; index < EARLY_KERNEL_TABLES; ++index) {
    zero_page(g_kernel_pt[index]);
  }
  g_kernel_pt_count = 0U;
  /* Lower-level entries keep identity mappings supervisor-only. */
  g_pml4[0] = x86mmu_table_entry(g_low_pdpt, PTE_USER);
  for (uint32_t gib = 0U; gib < 4U; ++gib) {
    g_low_pdpt[gib] = x86mmu_table_entry(g_low_pd[gib], 0U);
    for (uint32_t entry = 0U; entry < 512U; ++entry) {
      uint64_t address = (uint64_t)gib * HUGE_PAGE_SIZE +
                         (uint64_t)entry * LARGE_PAGE_SIZE;
      g_low_pd[gib][entry] = address | PTE_PRESENT | PTE_WRITABLE |
                             PTE_LARGE | PTE_GLOBAL | PTE_NX;
    }
  }
  g_low_pdpt[USER_PDPT_INDEX] = x86mmu_table_entry(g_user_pd, PTE_USER);

  uint64_t kernel_start = x86mmu_align_down(boot->kernel_phys_base,
                                            LARGE_PAGE_SIZE);
  uint64_t kernel_end = align_up(boot->kernel_phys_end, LARGE_PAGE_SIZE);
  for (uint64_t region = kernel_start; region < kernel_end;
       region += LARGE_PAGE_SIZE) {
    kassert(g_kernel_pt_count < EARLY_KERNEL_TABLES);
    uint32_t pdpt_index = (uint32_t)((region >> 30U) & 0x1ffU);
    uint32_t pd_index = (uint32_t)((region >> 21U) & 0x1ffU);
    uint64_t *pt = g_kernel_pt[g_kernel_pt_count++];
    for (uint32_t page = 0U; page < 512U; ++page) {
      uint64_t address = region + (uint64_t)page * PAGE_SIZE;
      pt[page] = address | x86mmu_flags_to_pte(kernel_flags(address));
    }
    g_low_pd[pdpt_index][pd_index] = x86mmu_table_entry(pt, 0U);
  }
}

static void build_per_cpu_roots(void) {
  uint32_t capacity = smp_capacity();
  for (uint32_t cpu = 0U; cpu < capacity; ++cpu) {
    uint64_t *root = x86mmu_allocate_table();
    uint64_t *pdpt = x86mmu_allocate_table();
    uint64_t *user_directory = x86mmu_allocate_table();
    kassert(root != 0 && pdpt != 0 && user_directory != 0);
    for (uint32_t index = 0U; index < 512U; ++index) {
      root[index] = g_pml4[index];
      pdpt[index] = g_low_pdpt[index];
    }
    root[0] = x86mmu_table_entry(pdpt, PTE_USER);
    pdpt[USER_PDPT_INDEX] = x86mmu_table_entry(user_directory, PTE_USER);
    x86_64_platform_set_page_tables(cpu, root, user_directory);
  }
}

void vmm_init(const xaios_boot_info_t *boot) {
  build_tables(boot);
  build_per_cpu_roots();
  write_msr(EFER_MSR, read_msr(EFER_MSR) | EFER_NXE);
  write_cr0(read_cr0() | CR0_WP);
  x86mmu_flush_tlb();
  klog("VMM: x86 4-level paging enabled kernel_tables=%u\n",
       g_kernel_pt_count);
}

void vmm_activate_kernel(void) { x86mmu_flush_tlb(); }
