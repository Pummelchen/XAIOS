#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/pmm.h>
#include <xaios/smp.h>
#include <xaios/vmm.h>
/* x86_64 enters long mode with paging already on -- there is no untranslated
   window here -- so exclusives are always legal. The predicate exists because
   the shared spinlock asks; see kernel/include/xaios/spinlock.h. */
uint32_t xaios_translation_enabled(void) { return 1U; }


#include "platform.h"

#define PAGE_SIZE UINT64_C(4096)
#define LARGE_PAGE_SIZE UINT64_C(0x200000)
#define HUGE_PAGE_SIZE UINT64_C(0x40000000)
#define EARLY_IDENTITY_SIZE UINT64_C(0x100000000)
#define EARLY_KERNEL_TABLES 32U
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
#define EFER_MSR UINT32_C(0xc0000080)
#define EFER_NXE (UINT64_C(1) << 11)
#define CR0_WP (UINT64_C(1) << 16)

#define USER_CODE_PD_INDEX \
  ((uint32_t)((XAIOS_USER_BASE >> 21U) & UINT64_C(0x1ff)))
#define USER_STACK_PD_INDEX \
  ((uint32_t)(((XAIOS_USER_STACK_TOP - PAGE_SIZE) >> 21U) & \
              UINT64_C(0x1ff)))

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

static uint64_t align_down(uint64_t value, uint64_t alignment) {
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

static uint64_t *current_root(void) {
  uint64_t *root =
      x86_64_platform_page_table_root(x86_64_platform_current_ordinal());
  return root != 0 ? root : g_pml4;
}

static uint64_t *current_user_directory(void) {
  return x86_64_platform_user_page_directory(
      x86_64_platform_current_ordinal());
}

static void flush_tlb(void) {
  write_cr3((uint64_t)(uintptr_t)current_root());
}

static void invalidate_page(uint64_t virtual_address) {
  x86_64_platform_invalidate_page_all(virtual_address);
}

static uint64_t table_entry(const uint64_t *table, uint64_t flags) {
  return ((uint64_t)(uintptr_t)table & PTE_ADDRESS_MASK) | PTE_PRESENT |
         PTE_WRITABLE | flags;
}

static uint64_t flags_to_pte(uint32_t flags) {
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

static uint32_t pte_to_flags(uint64_t pte) {
  uint32_t flags = XAIOS_VMM_PRESENT;
  if ((pte & PTE_WRITABLE) != 0U) flags |= XAIOS_VMM_WRITABLE;
  if ((pte & PTE_USER) != 0U) flags |= XAIOS_VMM_USER;
  if ((pte & PTE_DEVICE) != 0U) flags |= XAIOS_VMM_DEVICE;
  if ((pte & PTE_NX) == 0U) flags |= XAIOS_VMM_EXECUTABLE;
  if ((pte & PTE_GLOBAL) == 0U) flags |= XAIOS_VMM_NG;
  return flags;
}

static uint32_t effective_flags(uint64_t pml4e, uint64_t pdpte,
                                uint64_t pde, uint64_t pte) {
  uint32_t flags = pte_to_flags(pte);
  if ((pml4e & PTE_USER) == 0U || (pdpte & PTE_USER) == 0U ||
      (pde & PTE_USER) == 0U) {
    flags &= (uint32_t)~(uint32_t)XAIOS_VMM_USER;
  }
  if ((pml4e & PTE_WRITABLE) == 0U || (pdpte & PTE_WRITABLE) == 0U ||
      (pde & PTE_WRITABLE) == 0U) {
    flags &= (uint32_t)~(uint32_t)XAIOS_VMM_WRITABLE;
  }
  if (((pml4e | pdpte | pde | pte) & PTE_NX) != 0U) {
    flags &= (uint32_t)~(uint32_t)XAIOS_VMM_EXECUTABLE;
  }
  return flags;
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

static uint64_t *allocate_table(void) {
  uint64_t *table = (uint64_t *)pmm_alloc_page();
  if (table != 0) zero_page(table);
  return table;
}

static uint64_t *ensure_pt(uint64_t *root, uint64_t virtual_address,
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
    pdpt = allocate_table();
    kassert(pdpt != 0);
    root[pml4_index] = table_entry(pdpt, hierarchy_flags);
  } else {
    root[pml4_index] |= hierarchy_flags;
    pdpt = (uint64_t *)(uintptr_t)(root[pml4_index] & PTE_ADDRESS_MASK);
  }

  uint64_t pdpt_entry = pdpt[pdpt_index];
  if ((pdpt_entry & PTE_PRESENT) == 0U ||
      (pdpt_entry & PTE_LARGE) != 0U) {
    pd = allocate_table();
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
    pdpt[pdpt_index] = table_entry(pd, hierarchy_flags);
  } else {
    pdpt[pdpt_index] |= hierarchy_flags;
    pd = (uint64_t *)(uintptr_t)(pdpt_entry & PTE_ADDRESS_MASK);
  }

  uint64_t pd_entry = pd[pd_index];
  if ((pd_entry & PTE_PRESENT) != 0U && (pd_entry & PTE_LARGE) == 0U) {
    pd[pd_index] |= hierarchy_flags;
    return (uint64_t *)(uintptr_t)(pd_entry & PTE_ADDRESS_MASK);
  }
  pt = allocate_table();
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
  pd[pd_index] = table_entry(pt, hierarchy_flags);
  return pt;
}

static uint64_t *ensure_pd(uint64_t *root, uint64_t virtual_address) {
  uint32_t pml4_index = (uint32_t)((virtual_address >> 39U) & 0x1ffU);
  uint32_t pdpt_index = (uint32_t)((virtual_address >> 30U) & 0x1ffU);
  uint64_t *pdpt;
  uint64_t *pd;

  if ((root[pml4_index] & PTE_PRESENT) == 0U) {
    pdpt = allocate_table();
    if (pdpt == 0) return 0;
    root[pml4_index] = table_entry(pdpt, 0U);
  } else {
    if ((root[pml4_index] & PTE_LARGE) != 0U) return 0;
    pdpt = (uint64_t *)(uintptr_t)(root[pml4_index] & PTE_ADDRESS_MASK);
  }

  uint64_t pdpt_entry = pdpt[pdpt_index];
  if ((pdpt_entry & PTE_PRESENT) == 0U) {
    pd = allocate_table();
    if (pd == 0) return 0;
    pdpt[pdpt_index] = table_entry(pd, 0U);
    return pd;
  }
  if ((pdpt_entry & PTE_LARGE) != 0U) return 0;
  return (uint64_t *)(uintptr_t)(pdpt_entry & PTE_ADDRESS_MASK);
}

static uint64_t *find_pd(uint64_t *root, uint64_t virtual_address) {
  uint64_t pml4e = root[(virtual_address >> 39U) & 0x1ffU];
  if ((pml4e & PTE_PRESENT) == 0U || (pml4e & PTE_LARGE) != 0U) return 0;
  uint64_t *pdpt = (uint64_t *)(uintptr_t)(pml4e & PTE_ADDRESS_MASK);
  uint64_t pdpte = pdpt[(virtual_address >> 30U) & 0x1ffU];
  if ((pdpte & PTE_PRESENT) == 0U || (pdpte & PTE_LARGE) != 0U) return 0;
  return (uint64_t *)(uintptr_t)(pdpte & PTE_ADDRESS_MASK);
}

static uint32_t user_address(uint64_t virtual_address) {
  return virtual_address >= XAIOS_USER_BASE &&
         virtual_address < XAIOS_USER_LIMIT;
}

static void sync_kernel_hierarchy(uint64_t virtual_address) {
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
    if (pdpt_index != 4U) pdpt[pdpt_index] = g_low_pdpt[pdpt_index];
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
  g_pml4[0] = table_entry(g_low_pdpt, PTE_USER);
  for (uint32_t gib = 0U; gib < 4U; ++gib) {
    g_low_pdpt[gib] = table_entry(g_low_pd[gib], 0U);
    for (uint32_t entry = 0U; entry < 512U; ++entry) {
      uint64_t address = (uint64_t)gib * HUGE_PAGE_SIZE +
                         (uint64_t)entry * LARGE_PAGE_SIZE;
      g_low_pd[gib][entry] = address | PTE_PRESENT | PTE_WRITABLE |
                             PTE_LARGE | PTE_GLOBAL | PTE_NX;
    }
  }
  g_low_pdpt[4] = table_entry(g_user_pd, PTE_USER);

  uint64_t kernel_start = align_down(boot->kernel_phys_base, LARGE_PAGE_SIZE);
  uint64_t kernel_end = align_up(boot->kernel_phys_end, LARGE_PAGE_SIZE);
  for (uint64_t region = kernel_start; region < kernel_end;
       region += LARGE_PAGE_SIZE) {
    kassert(g_kernel_pt_count < EARLY_KERNEL_TABLES);
    uint32_t pdpt_index = (uint32_t)((region >> 30U) & 0x1ffU);
    uint32_t pd_index = (uint32_t)((region >> 21U) & 0x1ffU);
    uint64_t *pt = g_kernel_pt[g_kernel_pt_count++];
    for (uint32_t page = 0U; page < 512U; ++page) {
      uint64_t address = region + (uint64_t)page * PAGE_SIZE;
      pt[page] = address | flags_to_pte(kernel_flags(address));
    }
    g_low_pd[pdpt_index][pd_index] = table_entry(pt, 0U);
  }
}

static void build_per_cpu_roots(void) {
  uint32_t capacity = smp_capacity();
  for (uint32_t cpu = 0U; cpu < capacity; ++cpu) {
    uint64_t *root = allocate_table();
    uint64_t *pdpt = allocate_table();
    uint64_t *user_directory = allocate_table();
    kassert(root != 0 && pdpt != 0 && user_directory != 0);
    for (uint32_t index = 0U; index < 512U; ++index) {
      root[index] = g_pml4[index];
      pdpt[index] = g_low_pdpt[index];
    }
    root[0] = table_entry(pdpt, PTE_USER);
    pdpt[4] = table_entry(user_directory, PTE_USER);
    x86_64_platform_set_page_tables(cpu, root, user_directory);
  }
}

void vmm_init(const xaios_boot_info_t *boot) {
  build_tables(boot);
  build_per_cpu_roots();
  write_msr(EFER_MSR, read_msr(EFER_MSR) | EFER_NXE);
  write_cr0(read_cr0() | CR0_WP);
  flush_tlb();
  klog("VMM: x86 4-level paging enabled kernel_tables=%u\n",
       g_kernel_pt_count);
}

void vmm_activate_kernel(void) { flush_tlb(); }

xaios_status_t vmm_translate(uint64_t virtual_address,
                            uint64_t *physical_address, uint32_t *flags) {
  if (physical_address == 0 || flags == 0) return XAIOS_ERR_INVALID;
  uint64_t pml4e = current_root()[(virtual_address >> 39U) & 0x1ffU];
  if ((pml4e & PTE_PRESENT) == 0U) return XAIOS_ERR_INVALID;
  const uint64_t *pdpt =
      (const uint64_t *)(uintptr_t)(pml4e & PTE_ADDRESS_MASK);
  uint64_t pdpte = pdpt[(virtual_address >> 30U) & 0x1ffU];
  if ((pdpte & PTE_PRESENT) == 0U) return XAIOS_ERR_INVALID;
  if ((pdpte & PTE_LARGE) != 0U) {
    *physical_address = (pdpte & PTE_HUGE_ADDRESS_MASK) +
                        (virtual_address & (HUGE_PAGE_SIZE - 1U));
    *flags = effective_flags(pml4e, pdpte, pdpte, pdpte);
    return XAIOS_OK;
  }
  const uint64_t *pd =
      (const uint64_t *)(uintptr_t)(pdpte & PTE_ADDRESS_MASK);
  uint64_t pde = pd[(virtual_address >> 21U) & 0x1ffU];
  if ((pde & PTE_PRESENT) == 0U) return XAIOS_ERR_INVALID;
  if ((pde & PTE_LARGE) != 0U) {
    *physical_address = (pde & PTE_LARGE_ADDRESS_MASK) +
                        (virtual_address & (LARGE_PAGE_SIZE - 1U));
    *flags = effective_flags(pml4e, pdpte, pde, pde);
    return XAIOS_OK;
  }
  const uint64_t *pt =
      (const uint64_t *)(uintptr_t)(pde & PTE_ADDRESS_MASK);
  uint64_t pte = pt[(virtual_address >> 12U) & 0x1ffU];
  if ((pte & PTE_PRESENT) == 0U) return XAIOS_ERR_INVALID;
  *physical_address =
      (pte & PTE_ADDRESS_MASK) + (virtual_address & (PAGE_SIZE - 1U));
  *flags = effective_flags(pml4e, pdpte, pde, pte);
  return XAIOS_OK;
}

xaios_status_t vmm_validate_range_flags(uint64_t virtual_address,
                                        uint64_t size,
                                        uint32_t required_flags,
                                        uint32_t forbidden_flags) {
  if (size == 0U || size - 1U > UINT64_MAX - virtual_address) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t page = align_down(virtual_address, PAGE_SIZE);
  uint64_t last = align_down(virtual_address + size - 1U, PAGE_SIZE);
  for (;;) {
    uint64_t physical;
    uint32_t actual;
    if (vmm_translate(page, &physical, &actual) != XAIOS_OK ||
        (actual & required_flags) != required_flags ||
        (actual & forbidden_flags) != 0U) {
      return XAIOS_ERR_INVALID;
    }
    if (page == last) return XAIOS_OK;
    page += PAGE_SIZE;
  }
}

xaios_status_t vmm_map_page(uint64_t virtual_address,
                           uint64_t physical_address, uint32_t flags) {
  if ((virtual_address & (PAGE_SIZE - 1U)) != 0U ||
      (physical_address & (PAGE_SIZE - 1U)) != 0U ||
      (flags & XAIOS_VMM_PRESENT) == 0U) {
    return XAIOS_ERR_INVALID;
  }
  uint32_t is_user = user_address(virtual_address);
  uint64_t *pt = ensure_pt(is_user != 0U ? current_root() : g_pml4,
                           virtual_address, flags);
  pt[(virtual_address >> 12U) & 0x1ffU] =
      physical_address | flags_to_pte(flags);
  if (is_user == 0U) sync_kernel_hierarchy(virtual_address);
  invalidate_page(virtual_address);
  return XAIOS_OK;
}

xaios_status_t vmm_unmap_page(uint64_t virtual_address) {
  if ((virtual_address & (PAGE_SIZE - 1U)) != 0U) return XAIOS_ERR_INVALID;
  uint32_t is_user = user_address(virtual_address);
  uint64_t *pt = ensure_pt(is_user != 0U ? current_root() : g_pml4,
                           virtual_address, 0U);
  pt[(virtual_address >> 12U) & 0x1ffU] = 0U;
  if (is_user == 0U) sync_kernel_hierarchy(virtual_address);
  invalidate_page(virtual_address);
  return XAIOS_OK;
}

xaios_status_t vmm_map_large_page(uint64_t virtual_address,
                                 uint64_t physical_address, uint32_t flags) {
  if ((virtual_address & (LARGE_PAGE_SIZE - 1U)) != 0U ||
      (physical_address & (LARGE_PAGE_SIZE - 1U)) != 0U ||
      (flags & XAIOS_VMM_PRESENT) == 0U ||
      (flags & XAIOS_VMM_USER) != 0U || user_address(virtual_address) != 0U) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t *pd = ensure_pd(g_pml4, virtual_address);
  if (pd == 0) return XAIOS_ERR_NO_MEMORY;
  uint32_t pd_index = (uint32_t)((virtual_address >> 21U) & 0x1ffU);
  if ((pd[pd_index] & PTE_PRESENT) != 0U) return XAIOS_ERR_BUSY;
  pd[pd_index] = physical_address | flags_to_pte(flags) | PTE_LARGE;
  sync_kernel_hierarchy(virtual_address);
  invalidate_page(virtual_address);
  return XAIOS_OK;
}

xaios_status_t vmm_map_gigantic_page(uint64_t virtual_address,
                                    uint64_t physical_address,
                                    uint32_t flags) {
  if ((virtual_address & (HUGE_PAGE_SIZE - 1U)) != 0U ||
      (physical_address & (HUGE_PAGE_SIZE - 1U)) != 0U ||
      (flags & XAIOS_VMM_PRESENT) == 0U ||
      (flags & XAIOS_VMM_USER) != 0U || user_address(virtual_address) != 0U) {
    return XAIOS_ERR_INVALID;
  }
  uint32_t pml4_index = (uint32_t)((virtual_address >> 39U) & 0x1ffU);
  uint32_t pdpt_index = (uint32_t)((virtual_address >> 30U) & 0x1ffU);
  uint64_t *pdpt;
  if ((g_pml4[pml4_index] & PTE_PRESENT) == 0U) {
    pdpt = allocate_table();
    if (pdpt == 0) return XAIOS_ERR_NO_MEMORY;
    g_pml4[pml4_index] = table_entry(pdpt, 0U);
  } else {
    pdpt = (uint64_t *)(uintptr_t)(g_pml4[pml4_index] & PTE_ADDRESS_MASK);
  }
  if ((pdpt[pdpt_index] & PTE_PRESENT) != 0U) return XAIOS_ERR_BUSY;
  pdpt[pdpt_index] = physical_address | flags_to_pte(flags) | PTE_LARGE;
  sync_kernel_hierarchy(virtual_address);
  invalidate_page(virtual_address);
  return XAIOS_OK;
}

xaios_status_t vmm_unmap_gigantic_page(uint64_t virtual_address) {
  if ((virtual_address & (HUGE_PAGE_SIZE - 1U)) != 0U ||
      user_address(virtual_address) != 0U) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t pml4e = g_pml4[(virtual_address >> 39U) & 0x1ffU];
  if ((pml4e & PTE_PRESENT) == 0U) return XAIOS_ERR_INVALID;
  uint64_t *pdpt = (uint64_t *)(uintptr_t)(pml4e & PTE_ADDRESS_MASK);
  uint32_t index = (uint32_t)((virtual_address >> 30U) & 0x1ffU);
  if ((pdpt[index] & (PTE_PRESENT | PTE_LARGE)) !=
      (PTE_PRESENT | PTE_LARGE)) {
    return XAIOS_ERR_INVALID;
  }
  pdpt[index] = 0U;
  sync_kernel_hierarchy(virtual_address);
  invalidate_page(virtual_address);
  return XAIOS_OK;
}

xaios_status_t vmm_unmap_large_page(uint64_t virtual_address) {
  if ((virtual_address & (LARGE_PAGE_SIZE - 1U)) != 0U ||
      user_address(virtual_address) != 0U) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t *pd = find_pd(g_pml4, virtual_address);
  if (pd == 0) return XAIOS_ERR_INVALID;
  uint32_t pd_index = (uint32_t)((virtual_address >> 21U) & 0x1ffU);
  if ((pd[pd_index] & (PTE_PRESENT | PTE_LARGE)) !=
      (PTE_PRESENT | PTE_LARGE)) {
    return XAIOS_ERR_INVALID;
  }
  pd[pd_index] = 0U;
  sync_kernel_hierarchy(virtual_address);
  invalidate_page(virtual_address);
  return XAIOS_OK;
}

xaios_status_t vmm_validate_user_buffer(uint64_t virtual_address,
                                       uint64_t size,
                                       uint32_t required_flags) {
  if (size == 0U || virtual_address < XAIOS_USER_BASE ||
      virtual_address + size < virtual_address ||
      virtual_address + size > XAIOS_USER_LIMIT) {
    return XAIOS_ERR_INVALID;
  }
  return vmm_validate_range_flags(virtual_address, size,
                                  required_flags | XAIOS_VMM_USER, 0U);
}

void vmm_self_test(void) {
  void *page = pmm_alloc_page();
  kassert(page != 0);
  uint64_t address = XAIOS_USER_BASE + LARGE_PAGE_SIZE;
  kassert(vmm_map_page(address, (uint64_t)(uintptr_t)page,
                       XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE |
                           XAIOS_VMM_USER) == XAIOS_OK);
  uint64_t physical;
  uint32_t flags;
  kassert(vmm_translate(address, &physical, &flags) == XAIOS_OK);
  klog("VMM: x86 self-test translated phys=0x%lx flags=0x%x\n",
       physical, flags);
  kassert(physical == (uint64_t)(uintptr_t)page);
  kassert((flags & (XAIOS_VMM_USER | XAIOS_VMM_WRITABLE)) ==
          (XAIOS_VMM_USER | XAIOS_VMM_WRITABLE));
  kassert(vmm_unmap_page(address) == XAIOS_OK);
  pmm_free_page(page);

  const uint64_t large_va = UINT64_C(0x7000000000);
  const uint64_t large_pa = UINT64_C(0x200000);
  kassert(vmm_map_large_page(large_va, large_pa,
                             XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE) ==
          XAIOS_OK);
  kassert(vmm_map_large_page(large_va, large_pa, XAIOS_VMM_PRESENT) ==
          XAIOS_ERR_BUSY);
  kassert(vmm_validate_range_flags(
              large_va, XAIOS_VMM_LARGE_PAGE_SIZE,
              XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE,
              XAIOS_VMM_USER | XAIOS_VMM_EXECUTABLE) == XAIOS_OK);
  kassert(vmm_translate(large_va + XAIOS_VMM_LARGE_PAGE_SIZE - 1U,
                        &physical, &flags) == XAIOS_OK);
  kassert(physical == large_pa + XAIOS_VMM_LARGE_PAGE_SIZE - 1U);
  kassert(vmm_unmap_large_page(large_va) == XAIOS_OK);
  kassert(vmm_translate(large_va, &physical, &flags) == XAIOS_ERR_INVALID);
  klog("VMM: x86 2 MiB large-page map/unmap self-test passed\n");

  const uint64_t gigantic_va = UINT64_C(0x8000000000);
  const uint64_t gigantic_pa = UINT64_C(0x40000000);
  kassert(vmm_map_gigantic_page(
              gigantic_va, gigantic_pa,
              XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE) == XAIOS_OK);
  kassert(vmm_translate(gigantic_va + XAIOS_VMM_GIGANTIC_PAGE_SIZE - 1U,
                        &physical, &flags) == XAIOS_OK);
  kassert(physical == gigantic_pa + XAIOS_VMM_GIGANTIC_PAGE_SIZE - 1U);
  kassert(vmm_unmap_gigantic_page(gigantic_va) == XAIOS_OK);
  kassert(vmm_translate(gigantic_va, &physical, &flags) ==
          XAIOS_ERR_INVALID);
  kassert(x86_64_platform_tlb_shootdown_count() >= 2U);
  klog("VMM: x86 1 GiB page and SMP address-specific invalidation self-test passed shootdowns=%lu\n",
       x86_64_platform_tlb_shootdown_count());

  uint64_t process_tables[USER_ASPACE_L3_TABLES];
  uint32_t process_table_count = 0U;
  vmm_create_user_aspace(process_tables, USER_ASPACE_L3_TABLES,
                         &process_table_count);
  kassert(process_table_count == USER_ASPACE_L3_TABLES);
  void *boundary_page = pmm_alloc_page();
  kassert(boundary_page != 0);
  uint64_t boundary_address = XAIOS_USER_BASE + LARGE_PAGE_SIZE;
  kassert(vmm_map_user_page(boundary_address,
                            (uint64_t)(uintptr_t)boundary_page,
                            XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE |
                                XAIOS_VMM_USER,
                            process_tables, process_table_count) == XAIOS_OK);
  uint64_t *second_code_table =
      (uint64_t *)(uintptr_t)process_tables[1];
  kassert((second_code_table[0] & PTE_PRESENT) != 0U);
  kassert(vmm_unmap_user_page(boundary_address, process_tables,
                              process_table_count) == XAIOS_OK);
  kassert(second_code_table[0] == 0U);
  pmm_free_page(boundary_page);
  vmm_destroy_user_aspace(process_tables, process_table_count);
  klog("VMM: x86 map/unmap self-test passed\n");
}

void vmm_create_user_aspace(uint64_t l3_tables[], uint32_t max_tables,
                            uint32_t *out_count) {
  kassert(l3_tables != 0 && out_count != 0 &&
          max_tables >= USER_ASPACE_L3_TABLES);
  for (uint32_t index = 0U; index < max_tables; ++index) l3_tables[index] = 0U;
  for (uint32_t index = 0U; index < USER_ASPACE_L3_TABLES; ++index) {
    uint64_t *pt = allocate_table();
    kassert(pt != 0);
    l3_tables[index] = (uint64_t)(uintptr_t)pt;
  }
  *out_count = USER_ASPACE_L3_TABLES;
}

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
      physical_address | flags_to_pte(flags | XAIOS_VMM_USER);
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
            table_entry((uint64_t *)(uintptr_t)l3_tables[index], PTE_USER);
      }
    }
    if (l3_tables[USER_CODE_WINDOWS] != 0U) {
      user_directory[USER_STACK_PD_INDEX] =
          table_entry((uint64_t *)(uintptr_t)l3_tables[USER_CODE_WINDOWS],
                      PTE_USER);
    }
  }
  flush_tlb();
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
