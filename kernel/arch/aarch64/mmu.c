#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/spinlock.h>
#include <xaios/pmm.h>
#include <xaios/smp.h>
#include <xaios/vmm.h>

#include "platform.h"

#define PAGE_SIZE UINT64_C(4096)
#define L2_BLOCK_SIZE UINT64_C(0x200000)
#define L1_BLOCK_SIZE UINT64_C(0x40000000)
#define EARLY_IDENTITY_SIZE UINT64_C(0x100000000)
#define EARLY_L1_TABLES 4
#define EARLY_KERNEL_L3_TABLES 16
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
#define L0_SPAN UINT64_C(0x8000000000)

#define MAIR_NORMAL_WB UINT64_C(0xff)
#define MAIR_DEVICE_NGNRE UINT64_C(0x04)

extern char __text_start[];
extern char __text_end[];
extern char __rodata_start[];
extern char __rodata_end[];
extern char __data_start[];
extern char __data_end[];
extern char __bss_start[];
extern char __bss_end[];
extern char __user_text_start[];
extern char __user_text_end[];
extern char __user_rodata_start[];
extern char __user_rodata_end[];
extern char __user_stack_start[];
extern char __user_stack_end[];

static uint64_t g_l0_table[512] __attribute__((aligned(PAGE_SIZE)));
static uint64_t g_l1_table[512] __attribute__((aligned(PAGE_SIZE)));
static uint64_t g_l2_tables[EARLY_L1_TABLES][512] __attribute__((aligned(PAGE_SIZE)));
static uint64_t g_kernel_l3_tables[EARLY_KERNEL_L3_TABLES][512]
    __attribute__((aligned(PAGE_SIZE)));
static uint64_t g_mmio_start;
static uint64_t g_mmio_end;

#define USER_CODE_L2_INDEX \
  ((uint32_t)((XAIOS_USER_BASE >> 21U) & UINT64_C(0x1ff)))
#define USER_STACK_L2_INDEX \
  ((uint32_t)(((XAIOS_USER_STACK_TOP - PAGE_SIZE) >> 21U) & UINT64_C(0x1ff)))

static uint64_t align_down(uint64_t value, uint64_t align) {
  return value & ~(align - 1);
}

static uint64_t align_up(uint64_t value, uint64_t align) {
  return (value + align - 1) & ~(align - 1);
}

static void zero_table(uint64_t *table, uint64_t entries) {
  for (uint64_t i = 0; i < entries; ++i) {
    table[i] = 0;
  }
}

static uint64_t table_descriptor(const uint64_t *table) {
  return ((uint64_t)(uintptr_t)table & PTE_ADDR_MASK) | PTE_VALID | PTE_TABLE;
}

static uint64_t *allocate_table(void) {
  uint64_t *table = (uint64_t *)pmm_alloc_page();
  if (table != 0) zero_table(table, 512U);
  return table;
}

static uint64_t *current_root(void) {
  uint64_t *root = aarch64_platform_page_table_root(
      aarch64_platform_current_ordinal());
  return root != 0 ? root : g_l0_table;
}

static uint64_t *current_user_directory(void) {
  return aarch64_platform_user_page_directory(
      aarch64_platform_current_ordinal());
}

static uint64_t page_descriptor(uint64_t physical_address, uint64_t attrs) {
  return (physical_address & PTE_ADDR_MASK) | attrs | PTE_VALID | PTE_TABLE |
         PTE_AF;
}

static uint64_t block_descriptor(uint64_t physical_address, uint64_t attrs) {
  return (physical_address & PTE_BLOCK_L2_ADDR_MASK) | attrs | PTE_VALID | PTE_AF;
}

static uint64_t l1_block_descriptor(uint64_t physical_address,
                                    uint64_t attrs) {
  return (physical_address & PTE_BLOCK_L1_ADDR_MASK) | attrs | PTE_VALID |
         PTE_AF;
}

static uint64_t normal_rw_nx_attrs(void) {
  return PTE_ATTR_NORMAL | PTE_SH_INNER | PTE_PXN | PTE_UXN;
}

static uint64_t device_rw_nx_attrs(void) {
  return PTE_ATTR_DEVICE | PTE_PXN | PTE_UXN;
}

static uint64_t normal_ro_nx_attrs(void) {
  return PTE_ATTR_NORMAL | PTE_SH_INNER | PTE_AP_RO | PTE_PXN | PTE_UXN;
}

static uint64_t normal_rx_attrs(void) {
  return PTE_ATTR_NORMAL | PTE_SH_INNER | PTE_UXN;
}

static uint64_t user_rx_attrs(void) {
  return PTE_ATTR_NORMAL | PTE_SH_INNER | PTE_AP_EL0 | PTE_PXN;
}

static uint64_t user_ro_nx_attrs(void) {
  return PTE_ATTR_NORMAL | PTE_SH_INNER | PTE_AP_EL0 | PTE_AP_RO |
         PTE_PXN | PTE_UXN;
}

static uint64_t user_rw_nx_attrs(void) {
  return PTE_ATTR_NORMAL | PTE_SH_INNER | PTE_AP_EL0 | PTE_PXN | PTE_UXN;
}

static int in_range(uint64_t value, uint64_t start, uint64_t end) {
  return value >= start && value < end;
}

static int overlaps(uint64_t start, uint64_t end, uint64_t used_start,
                    uint64_t used_end) {
  return start < used_end && used_start < end;
}

static uint64_t kernel_page_attrs(uint64_t address) {
  uint64_t page_end = address + PAGE_SIZE;
  uint64_t text_start = (uint64_t)(uintptr_t)__text_start;
  uint64_t text_end = (uint64_t)(uintptr_t)__text_end;
  uint64_t rodata_start = (uint64_t)(uintptr_t)__rodata_start;
  uint64_t rodata_end = (uint64_t)(uintptr_t)__rodata_end;
  uint64_t data_start = (uint64_t)(uintptr_t)__data_start;
  uint64_t data_end = (uint64_t)(uintptr_t)__data_end;
  uint64_t bss_start = (uint64_t)(uintptr_t)__bss_start;
  uint64_t bss_end = (uint64_t)(uintptr_t)__bss_end;
  uint64_t user_text_start = (uint64_t)(uintptr_t)__user_text_start;
  uint64_t user_text_end = (uint64_t)(uintptr_t)__user_text_end;
  uint64_t user_rodata_start = (uint64_t)(uintptr_t)__user_rodata_start;
  uint64_t user_rodata_end = (uint64_t)(uintptr_t)__user_rodata_end;
  uint64_t user_stack_start = (uint64_t)(uintptr_t)__user_stack_start;
  uint64_t user_stack_end = (uint64_t)(uintptr_t)__user_stack_end;

  if (overlaps(address, page_end, user_text_start, user_text_end)) {
    return user_rx_attrs();
  }
  if (overlaps(address, page_end, user_rodata_start, user_rodata_end)) {
    return user_ro_nx_attrs();
  }
  if (overlaps(address, page_end, user_stack_start, user_stack_end)) {
    return user_rw_nx_attrs();
  }

  if (in_range(address, text_start, text_end)) {
    return normal_rx_attrs();
  }
  if (in_range(address, rodata_start, rodata_end)) {
    return normal_ro_nx_attrs();
  }
  if (in_range(address, data_start, data_end) || in_range(address, bss_start, bss_end)) {
    return normal_rw_nx_attrs();
  }

  return normal_rw_nx_attrs();
}

static void map_identity_l2_blocks(uint64_t start, uint64_t end, uint64_t attrs) {
  for (uint64_t address = start; address < end; address += L2_BLOCK_SIZE) {
    uint64_t l1_index = (address >> 30) & 0x1ffU;
    uint64_t l2_index = (address >> 21) & 0x1ffU;
    kassert(l1_index < EARLY_L1_TABLES);
    g_l2_tables[l1_index][l2_index] = block_descriptor(address, attrs);
  }
}

static void map_kernel_pages(uint64_t start, uint64_t end) {
  uint64_t table_index = 0;
  uint64_t table_start = align_down(start, L2_BLOCK_SIZE);
  uint64_t table_end = align_up(end, L2_BLOCK_SIZE);

  for (uint64_t region = table_start; region < table_end; region += L2_BLOCK_SIZE) {
    kassert(table_index < EARLY_KERNEL_L3_TABLES);

    uint64_t l1_index = (region >> 30) & 0x1ffU;
    uint64_t l2_index = (region >> 21) & 0x1ffU;
    uint64_t *l3 = g_kernel_l3_tables[table_index++];

    for (uint64_t page = 0; page < 512; ++page) {
      uint64_t address = region + (page * PAGE_SIZE);
      l3[page] = page_descriptor(address, kernel_page_attrs(address));
    }

    g_l2_tables[l1_index][l2_index] = table_descriptor(l3);
  }
}

static uint64_t attrs_from_flags(uint32_t flags) {
  uint64_t attrs = (flags & XAIOS_VMM_DEVICE) != 0 ? device_rw_nx_attrs()
                                                   : normal_rw_nx_attrs();

  if ((flags & XAIOS_VMM_USER) != 0) {
    attrs |= PTE_AP_EL0;
    attrs |= PTE_NG;
  }
  if ((flags & XAIOS_VMM_WRITABLE) == 0) {
    attrs |= PTE_AP_RO;
  }
  if ((flags & XAIOS_VMM_EXECUTABLE) != 0) {
    attrs &= ~PTE_UXN;
  }

  if ((flags & XAIOS_VMM_USER) == 0 && (flags & XAIOS_VMM_EXECUTABLE) != 0) {
    attrs &= ~PTE_PXN;
  }

  return attrs;
}

static uint64_t *ensure_l3_table(uint64_t virtual_address) {
  uint64_t l0_index = (virtual_address >> 39) & 0x1ffU;
  uint64_t l1_index = (virtual_address >> 30) & 0x1ffU;
  uint64_t l2_index = (virtual_address >> 21) & 0x1ffU;
  /* This kernel maps a single level-0 entry, so nothing above 512 GiB has a
     table to live in. Report that rather than assert: the address usually
     comes from a device BAR the firmware placed, and QEMU's virt machine puts
     64-bit PCI windows up there. A layout this kernel cannot map should cost
     the driver that asked, not the machine. */
  if (l0_index != 0U) {
    return 0;
  }

  /* Ensure L1 entry exists (allocate L2 table if needed) */
  uint64_t l1_desc = g_l1_table[l1_index];
  if ((l1_desc & (PTE_VALID | PTE_TABLE)) != (PTE_VALID | PTE_TABLE)) {
    uint64_t *new_l2 = (uint64_t *)pmm_alloc_page();
    kassert(new_l2 != 0);
    if ((l1_desc & PTE_VALID) != 0U && (l1_desc & PTE_TABLE) == 0U) {
      uint64_t block_base = l1_desc & PTE_BLOCK_L1_ADDR_MASK;
      uint64_t attrs = l1_desc & ~PTE_BLOCK_L1_ADDR_MASK;
      for (uint64_t i = 0; i < 512; ++i) {
        new_l2[i] = block_descriptor(block_base + i * L2_BLOCK_SIZE, attrs);
      }
    } else {
      for (uint64_t i = 0; i < 512; ++i) {
        new_l2[i] = 0;
      }
    }
    g_l1_table[l1_index] = table_descriptor(new_l2);
  }
  uint64_t *l2 = (uint64_t *)(uintptr_t)(g_l1_table[l1_index] & PTE_ADDR_MASK);

  uint64_t l2_desc = l2[l2_index];
  if ((l2_desc & (PTE_VALID | PTE_TABLE)) == (PTE_VALID | PTE_TABLE)) {
    return (uint64_t *)(uintptr_t)(l2_desc & PTE_ADDR_MASK);
  }

  uint64_t *l3 = (uint64_t *)pmm_alloc_page();
  kassert(l3 != 0);
  for (uint64_t i = 0; i < 512; ++i) {
    l3[i] = 0;
  }

  if ((l2_desc & PTE_VALID) != 0 && (l2_desc & PTE_TABLE) == 0) {
    uint64_t block_base = l2_desc & PTE_BLOCK_L2_ADDR_MASK;
    uint64_t attrs = l2_desc & ~PTE_BLOCK_L2_ADDR_MASK;
    for (uint64_t i = 0; i < 512; ++i) {
      l3[i] = page_descriptor(block_base + (i * PAGE_SIZE), attrs);
    }
  }

  l2[l2_index] = table_descriptor(l3);
  return l3;
}

static uint64_t *ensure_l2_table(uint64_t virtual_address) {
  uint64_t l0_index = (virtual_address >> 39U) & 0x1ffU;
  uint64_t l1_index = (virtual_address >> 30U) & 0x1ffU;
  if (l0_index != 0U) return 0;

  uint64_t l1_desc = g_l1_table[l1_index];
  if ((l1_desc & PTE_VALID) == 0U) {
    uint64_t *l2 = allocate_table();
    if (l2 == 0) return 0;
    g_l1_table[l1_index] = table_descriptor(l2);
    return l2;
  }
  if ((l1_desc & PTE_TABLE) == 0U) return 0;
  return (uint64_t *)(uintptr_t)(l1_desc & PTE_ADDR_MASK);
}

static uint64_t *find_l2_table(uint64_t virtual_address) {
  uint64_t l0_index = (virtual_address >> 39U) & 0x1ffU;
  uint64_t l1_index = (virtual_address >> 30U) & 0x1ffU;
  if (l0_index != 0U) return 0;
  uint64_t l1_desc = g_l1_table[l1_index];
  if ((l1_desc & (PTE_VALID | PTE_TABLE)) !=
      (PTE_VALID | PTE_TABLE)) {
    return 0;
  }
  return (uint64_t *)(uintptr_t)(l1_desc & PTE_ADDR_MASK);
}

static void invalidate_tlb_page(uint64_t virtual_address) {
  (void)virtual_address;
  __asm__ volatile(
      "dsb ishst\n"
      "tlbi vmalle1is\n"
      "dsb ish\n"
      "isb\n"
      :
      :
      : "memory");
}

static void build_tables(const xaios_boot_info_t *boot) {
  zero_table(g_l0_table, 512);
  zero_table(g_l1_table, 512);
  for (uint64_t i = 0; i < EARLY_L1_TABLES; ++i) {
    zero_table(g_l2_tables[i], 512);
  }
  for (uint64_t i = 0; i < EARLY_KERNEL_L3_TABLES; ++i) {
    zero_table(g_kernel_l3_tables[i], 512);
  }

  g_l0_table[0] = table_descriptor(g_l1_table);

  for (uint64_t i = 0; i < EARLY_L1_TABLES; ++i) {
    g_l1_table[i] = table_descriptor(g_l2_tables[i]);
  }

  map_identity_l2_blocks(0, EARLY_IDENTITY_SIZE, normal_rw_nx_attrs());
  uint64_t highest_physical = EARLY_IDENTITY_SIZE;
  for (uint64_t offset = 0U;
       offset + sizeof(xaios_memory_descriptor_t) <= boot->memory_map_size;
       offset += boot->memory_descriptor_size) {
    const xaios_memory_descriptor_t *descriptor =
        (const xaios_memory_descriptor_t *)(uintptr_t)(boot->memory_map +
                                                       offset);
    if (descriptor->type != XAIOS_MEMORY_TYPE_CONVENTIONAL ||
        descriptor->number_of_pages > UINT64_MAX / PAGE_SIZE) {
      continue;
    }
    uint64_t bytes = descriptor->number_of_pages * PAGE_SIZE;
    if (descriptor->physical_start <= UINT64_MAX - bytes &&
        descriptor->physical_start + bytes > highest_physical) {
      highest_physical = descriptor->physical_start + bytes;
    }
  }
  if (boot->boot_image_size != 0U &&
      boot->boot_image_base <= UINT64_MAX - boot->boot_image_size &&
      boot->boot_image_base + boot->boot_image_size > highest_physical) {
    highest_physical = boot->boot_image_base + boot->boot_image_size;
  }
  if (highest_physical > L0_SPAN) highest_physical = L0_SPAN;
  uint64_t l1_limit = align_up(highest_physical, L1_BLOCK_SIZE);
  /* Never identity-map into the user window. Physical memory that reaches this
     far is dropped rather than mapped over userspace, because the per-CPU
     roots replace this entry with the user directory and whatever the identity
     map had put there would vanish. Losing the top gibibyte of an enormous
     machine is a cost; handing the kernel's own memory to userspace is a
     fault, and that is what used to happen at 4 GiB. */
  if (l1_limit > XAIOS_USER_BASE) l1_limit = XAIOS_USER_BASE;
  for (uint64_t address = EARLY_IDENTITY_SIZE; address < l1_limit;
       address += L1_BLOCK_SIZE) {
    g_l1_table[address / L1_BLOCK_SIZE] =
        l1_block_descriptor(address, normal_rw_nx_attrs());
  }
  g_mmio_start = align_down(boot->uart_base, L2_BLOCK_SIZE);
  g_mmio_end = align_up(boot->uart_base + PAGE_SIZE, L2_BLOCK_SIZE);
  /* Keep early PL011 serial stable until XAIOS owns exception vectors. */
  map_identity_l2_blocks(g_mmio_start, g_mmio_end, normal_rw_nx_attrs());
  map_kernel_pages(boot->kernel_phys_base, boot->kernel_phys_end);
}

static void build_per_cpu_roots(void) {
  uint32_t capacity = smp_capacity();
  uint32_t user_l1_index =
      (uint32_t)((XAIOS_USER_BASE >> 30U) & UINT64_C(0x1ff));
  for (uint32_t cpu = 0U; cpu < capacity; ++cpu) {
    uint64_t *root = allocate_table();
    uint64_t *l1 = allocate_table();
    uint64_t *user_directory = allocate_table();
    kassert(root != 0 && l1 != 0 && user_directory != 0);
    for (uint32_t index = 0U; index < 512U; ++index) {
      root[index] = g_l0_table[index];
      l1[index] = g_l1_table[index];
    }
    root[0] = table_descriptor(l1);
    /* Safe to overwrite because vmm_init stops the identity map at
       XAIOS_USER_BASE: this slot is never physical memory. */
    l1[user_l1_index] = table_descriptor(user_directory);
    aarch64_platform_set_page_tables(cpu, root, user_directory);
  }
}

static uint32_t user_address(uint64_t virtual_address) {
  return virtual_address >= XAIOS_USER_BASE &&
         virtual_address < XAIOS_USER_LIMIT;
}

static void sync_kernel_hierarchy(uint64_t virtual_address) {
  uint32_t l0_index =
      (uint32_t)((virtual_address >> 39U) & UINT64_C(0x1ff));
  uint32_t l1_index =
      (uint32_t)((virtual_address >> 30U) & UINT64_C(0x1ff));
  for (uint32_t cpu = 0U; cpu < smp_capacity(); ++cpu) {
    uint64_t *root = aarch64_platform_page_table_root(cpu);
    if (root == 0) continue;
    if (l0_index != 0U) {
      root[l0_index] = g_l0_table[l0_index];
      continue;
    }
    uint64_t *l1 =
        (uint64_t *)(uintptr_t)(root[0] & PTE_ADDR_MASK);
    l1[l1_index] = g_l1_table[l1_index];
  }
}

/* Ask the hardware, not our own call path.
 *
 * A flag set by aarch64_enable_mmu below answers the wrong question: firmware
 * may have enabled translation before the kernel ever ran, which QEMU and
 * Apple's hypervisor both do, and secondaries come online before vmm_init. A
 * flag would have read "off" there while four CPUs were running, and the
 * spinlock would have quietly used plain loads and stores where it needed
 * exclusives -- locks that do not lock. SCTLR_EL1.M is the truth on every
 * platform and costs one system register read. */
uint32_t xaios_translation_enabled(void) {
  uint64_t sctlr = 0U;
  __asm__ volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
  return (sctlr & UINT64_C(1)) != 0U ? 1U : 0U;
}

static void aarch64_enable_mmu(uint64_t root_table) {
  uint64_t mair = MAIR_NORMAL_WB | (MAIR_DEVICE_NGNRE << 8U);
  uint64_t tcr = UINT64_C(16) | UINT64_C(1 << 8) | UINT64_C(1 << 10) |
                 UINT64_C(3 << 12) | UINT64_C(2) << 32;
  uint64_t sctlr = 0;

  __asm__ volatile(
      "dsb sy\n"
      "mrs %[sctlr], sctlr_el1\n"
      "msr mair_el1, %[mair]\n"
      "msr tcr_el1, %[tcr]\n"
      "msr ttbr0_el1, %[root]\n"
      "tlbi vmalle1\n"
      "dsb ish\n"
      "isb\n"
      "orr %[sctlr], %[sctlr], #(1 << 0)\n"
      "orr %[sctlr], %[sctlr], #(1 << 2)\n"
      "orr %[sctlr], %[sctlr], #(1 << 12)\n"
      "msr sctlr_el1, %[sctlr]\n"
      "isb\n"
      : [sctlr] "=&r"(sctlr)
      : [mair] "r"(mair), [tcr] "r"(tcr), [root] "r"(root_table)
      : "memory");
}

static xaios_status_t descriptor_to_flags(uint64_t virtual_address,
                                         uint64_t descriptor, uint32_t *flags) {
  if ((descriptor & PTE_VALID) == 0) {
    return XAIOS_ERR_INVALID;
  }

  uint32_t out = XAIOS_VMM_PRESENT;
  uint64_t attr_index = (descriptor >> 2) & 0x7U;
  if (attr_index == 1) {
    out |= XAIOS_VMM_DEVICE;
  }
  if (virtual_address >= g_mmio_start && virtual_address < g_mmio_end) {
    out |= XAIOS_VMM_DEVICE;
  }
  if ((descriptor & PTE_AP_RO) == 0) {
    out |= XAIOS_VMM_WRITABLE;
  }
  if ((descriptor & PTE_UXN) == 0 || (descriptor & PTE_PXN) == 0) {
    out |= XAIOS_VMM_EXECUTABLE;
  }
  if ((descriptor & PTE_AP_EL0) != 0) {
    out |= XAIOS_VMM_USER;
  }

  *flags = out;
  return XAIOS_OK;
}

void vmm_init(const xaios_boot_info_t *boot) {
  build_tables(boot);
  build_per_cpu_roots();

  aarch64_enable_mmu((uint64_t)(uintptr_t)current_root());
  klog("VMM enabled with per-CPU user translation roots cpus=%u\n",
       smp_capacity());
  
  /* Null page guard: map page 0 with minimal permissions so any NULL
   * pointer dereference triggers a page fault. Done after MMU enable
   * because ensure_l3_table() needs dynamic page allocation which
   * requires the MMU to be active. */
  if (vmm_map_page(0, 0, XAIOS_VMM_PRESENT) != XAIOS_OK) {
    klog("VMM: WARNING: failed to map null page protection\n");
  }
}

static uint64_t dcache_line_bytes(void) {
  uint64_t ctr = 0U;
  __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
  return UINT64_C(4) << ((ctr >> 16U) & UINT64_C(0xf));
}

void vmm_clean_to_memory(const void *buffer, uint64_t bytes) {
  if (buffer == 0 || bytes == 0U) return;
  uint64_t line = dcache_line_bytes();
  uintptr_t start = (uintptr_t)buffer & ~(uintptr_t)(line - 1U);
  uintptr_t end = (uintptr_t)buffer + (uintptr_t)bytes;
  for (uintptr_t address = start; address < end; address += line) {
    __asm__ volatile("dc cvac, %0" : : "r"(address) : "memory");
  }
  __asm__ volatile("dsb sy" : : : "memory");
}

void vmm_invalidate_from_memory(const void *buffer, uint64_t bytes) {
  if (buffer == 0 || bytes == 0U) return;
  uint64_t line = dcache_line_bytes();
  uintptr_t start = (uintptr_t)buffer & ~(uintptr_t)(line - 1U);
  uintptr_t end = (uintptr_t)buffer + (uintptr_t)bytes;
  __asm__ volatile("dsb sy" : : : "memory");
  for (uintptr_t address = start; address < end; address += line) {
    __asm__ volatile("dc ivac, %0" : : "r"(address) : "memory");
  }
  __asm__ volatile("dsb sy" : : : "memory");
}

void vmm_activate_kernel(void) {
  aarch64_enable_mmu((uint64_t)(uintptr_t)current_root());
}

xaios_status_t vmm_translate(uint64_t virtual_address, uint64_t *physical_address,
                            uint32_t *flags) {
  uint64_t l0_index = (virtual_address >> 39) & 0x1ffU;
  uint64_t l1_index = (virtual_address >> 30) & 0x1ffU;
  uint64_t l2_index = (virtual_address >> 21) & 0x1ffU;
  uint64_t l3_index = (virtual_address >> 12) & 0x1ffU;
  uint64_t page_offset = virtual_address & UINT64_C(0xfff);
  uint64_t l2_offset = virtual_address & (L2_BLOCK_SIZE - 1);
  uint64_t l1_offset = virtual_address & (L1_BLOCK_SIZE - 1);

  uint64_t l0_desc = current_root()[l0_index];
  if ((l0_desc & (PTE_VALID | PTE_TABLE)) != (PTE_VALID | PTE_TABLE)) {
    return XAIOS_ERR_INVALID;
  }
  const uint64_t *l1 = (const uint64_t *)(uintptr_t)(l0_desc & PTE_ADDR_MASK);

  uint64_t l1_desc = l1[l1_index];
  if ((l1_desc & PTE_VALID) == 0U) {
    return XAIOS_ERR_INVALID;
  }
  if ((l1_desc & PTE_TABLE) == 0U) {
    *physical_address = (l1_desc & PTE_BLOCK_L1_ADDR_MASK) + l1_offset;
    return descriptor_to_flags(virtual_address, l1_desc, flags);
  }
  const uint64_t *l2 = (const uint64_t *)(uintptr_t)(l1_desc & PTE_ADDR_MASK);

  uint64_t l2_desc = l2[l2_index];
  if ((l2_desc & PTE_VALID) == 0) {
    return XAIOS_ERR_INVALID;
  }
  if ((l2_desc & PTE_TABLE) == 0) {
    *physical_address = (l2_desc & PTE_BLOCK_L2_ADDR_MASK) + l2_offset;
    return descriptor_to_flags(virtual_address, l2_desc, flags);
  }

  const uint64_t *l3 = (const uint64_t *)(uintptr_t)(l2_desc & PTE_ADDR_MASK);
  uint64_t l3_desc = l3[l3_index];
  if ((l3_desc & PTE_VALID) == 0) {
    return XAIOS_ERR_INVALID;
  }

  *physical_address = (l3_desc & PTE_ADDR_MASK) + page_offset;
  return descriptor_to_flags(virtual_address, l3_desc, flags);
}

xaios_status_t vmm_validate_range_flags(uint64_t virtual_address, uint64_t size,
                                        uint32_t required_flags,
                                        uint32_t forbidden_flags) {
  if (size == 0U || size - 1U > UINT64_MAX - virtual_address) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t page = align_down(virtual_address, PAGE_SIZE);
  uint64_t last = align_down(virtual_address + size - 1U, PAGE_SIZE);
  for (;;) {
    uint64_t physical = 0U;
    uint32_t flags = 0U;
    if (vmm_translate(page, &physical, &flags) != XAIOS_OK ||
        (flags & required_flags) != required_flags ||
        (flags & forbidden_flags) != 0U) {
      return XAIOS_ERR_INVALID;
    }
    (void)physical;
    if (page == last) break;
    if (page > UINT64_MAX - PAGE_SIZE) return XAIOS_ERR_INVALID;
    page += PAGE_SIZE;
  }
  return XAIOS_OK;
}

xaios_status_t vmm_map_page(uint64_t virtual_address, uint64_t physical_address,
                           uint32_t flags) {
  if ((virtual_address & (PAGE_SIZE - 1)) != 0 ||
      (physical_address & (PAGE_SIZE - 1)) != 0 ||
      (flags & XAIOS_VMM_PRESENT) == 0) {
    return XAIOS_ERR_INVALID;
  }

  uint64_t *l3 = ensure_l3_table(virtual_address);
  if (l3 == 0) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t l3_index = (virtual_address >> 12) & 0x1ffU;
  l3[l3_index] = page_descriptor(physical_address, attrs_from_flags(flags));
  if (user_address(virtual_address) == 0U) {
    sync_kernel_hierarchy(virtual_address);
  }
  invalidate_tlb_page(virtual_address);
  return XAIOS_OK;
}

xaios_status_t vmm_unmap_page(uint64_t virtual_address) {
  if ((virtual_address & (PAGE_SIZE - 1)) != 0) {
    return XAIOS_ERR_INVALID;
  }

  uint64_t *l3 = ensure_l3_table(virtual_address);
  if (l3 == 0) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t l3_index = (virtual_address >> 12) & 0x1ffU;
  l3[l3_index] = 0;
  if (user_address(virtual_address) == 0U) {
    sync_kernel_hierarchy(virtual_address);
  }
  invalidate_tlb_page(virtual_address);
  return XAIOS_OK;
}

xaios_status_t vmm_map_large_page(uint64_t virtual_address,
                                 uint64_t physical_address, uint32_t flags) {
  if ((virtual_address & (L2_BLOCK_SIZE - 1U)) != 0U ||
      (physical_address & (L2_BLOCK_SIZE - 1U)) != 0U ||
      (flags & XAIOS_VMM_PRESENT) == 0U ||
      (flags & XAIOS_VMM_USER) != 0U || user_address(virtual_address) != 0U) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t *l2 = ensure_l2_table(virtual_address);
  if (l2 == 0) return XAIOS_ERR_NO_MEMORY;
  uint64_t l2_index = (virtual_address >> 21U) & 0x1ffU;
  if ((l2[l2_index] & PTE_VALID) != 0U) return XAIOS_ERR_BUSY;
  l2[l2_index] = block_descriptor(physical_address, attrs_from_flags(flags));
  sync_kernel_hierarchy(virtual_address);
  invalidate_tlb_page(virtual_address);
  return XAIOS_OK;
}

xaios_status_t vmm_unmap_large_page(uint64_t virtual_address) {
  if ((virtual_address & (L2_BLOCK_SIZE - 1U)) != 0U ||
      user_address(virtual_address) != 0U) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t *l2 = find_l2_table(virtual_address);
  if (l2 == 0) return XAIOS_ERR_INVALID;
  uint64_t l2_index = (virtual_address >> 21U) & 0x1ffU;
  uint64_t descriptor = l2[l2_index];
  if ((descriptor & PTE_VALID) == 0U || (descriptor & PTE_TABLE) != 0U) {
    return XAIOS_ERR_INVALID;
  }
  l2[l2_index] = 0U;
  sync_kernel_hierarchy(virtual_address);
  invalidate_tlb_page(virtual_address);
  return XAIOS_OK;
}

xaios_status_t vmm_map_gigantic_page(uint64_t virtual_address,
                                    uint64_t physical_address,
                                    uint32_t flags) {
  (void)virtual_address;
  (void)physical_address;
  (void)flags;
  return XAIOS_ERR_UNSUPPORTED;
}

xaios_status_t vmm_unmap_gigantic_page(uint64_t virtual_address) {
  (void)virtual_address;
  return XAIOS_ERR_UNSUPPORTED;
}

xaios_status_t vmm_validate_user_buffer(uint64_t virtual_address, uint64_t size,
                                       uint32_t required_flags) {
  if (size == 0 || virtual_address < XAIOS_USER_BASE ||
      virtual_address + size < virtual_address ||
      virtual_address + size > XAIOS_USER_LIMIT) {
    return XAIOS_ERR_INVALID;
  }

  uint64_t start = align_down(virtual_address, PAGE_SIZE);
  uint64_t end = align_up(virtual_address + size, PAGE_SIZE);
  for (uint64_t page = start; page < end; page += PAGE_SIZE) {
    uint64_t physical = 0;
    uint32_t flags = 0;
    if (vmm_translate(page, &physical, &flags) != XAIOS_OK) {
      return XAIOS_ERR_INVALID;
    }
    (void)physical;
    if ((flags & XAIOS_VMM_USER) == 0 ||
        (flags & required_flags) != required_flags) {
      return XAIOS_ERR_INVALID;
    }
  }
  return XAIOS_OK;
}

void vmm_self_test(void) {
  const uint64_t large_va = UINT64_C(0x7000000000);
  const uint64_t large_pa = UINT64_C(0x40000000);
  uint64_t translated = 0U;
  uint32_t flags = 0U;
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
                        &translated, &flags) == XAIOS_OK);
  kassert(translated == large_pa + XAIOS_VMM_LARGE_PAGE_SIZE - 1U);
  kassert(vmm_unmap_large_page(large_va) == XAIOS_OK);
  kassert(vmm_translate(large_va, &translated, &flags) == XAIOS_ERR_INVALID);
  klog("VMM: ARM64 2 MiB large-page map/unmap self-test passed\n");

  uint64_t process_tables[USER_ASPACE_L3_TABLES];
  uint32_t process_table_count = 0U;
  vmm_create_user_aspace(process_tables, USER_ASPACE_L3_TABLES,
                         &process_table_count);
  kassert(process_table_count == USER_ASPACE_L3_TABLES);
  void *boundary_page = pmm_alloc_page();
  kassert(boundary_page != 0);
  uint64_t boundary_va = XAIOS_USER_BASE + L2_BLOCK_SIZE;
  kassert(vmm_map_user_page(boundary_va,
                            (uint64_t)(uintptr_t)boundary_page,
                            XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE |
                                XAIOS_VMM_USER,
                            process_tables, process_table_count) == XAIOS_OK);
  vmm_switch_user_aspace(process_tables, process_table_count);
  kassert(vmm_translate(boundary_va, &translated, &flags) == XAIOS_OK);
  kassert(translated == (uint64_t)(uintptr_t)boundary_page);
  kassert((flags & (XAIOS_VMM_USER | XAIOS_VMM_WRITABLE)) ==
          (XAIOS_VMM_USER | XAIOS_VMM_WRITABLE));
  kassert(vmm_validate_range_flags(
              boundary_va, 16U,
              XAIOS_VMM_PRESENT | XAIOS_VMM_USER | XAIOS_VMM_WRITABLE,
              XAIOS_VMM_EXECUTABLE) == XAIOS_OK);
  kassert(vmm_validate_user_buffer(boundary_va, 16U,
                                   XAIOS_VMM_WRITABLE) == XAIOS_OK);
  uint64_t *second_code_table =
      (uint64_t *)(uintptr_t)process_tables[1];
  kassert((second_code_table[0] & PTE_VALID) != 0U);
  kassert(vmm_unmap_user_page(boundary_va, process_tables,
                              process_table_count) == XAIOS_OK);
  kassert(second_code_table[0] == 0U);
  invalidate_tlb_page(boundary_va);
  kassert(vmm_translate(boundary_va, &translated, &flags) ==
          XAIOS_ERR_INVALID);
  vmm_switch_user_aspace(0, 0U);
  pmm_free_page(boundary_page);
  vmm_destroy_user_aspace(process_tables, process_table_count);
  klog("VMM map/unmap self-test passed mode=per-cpu-user-aspace\n");
}

/* --- Per-process address space APIs --- */

static xaios_status_t user_l3_slot(uint64_t virtual_address,
                                   uint32_t *out_slot) {
  uint32_t l2_index =
      (uint32_t)((virtual_address >> 21U) & UINT64_C(0x1ff));
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

void vmm_create_user_aspace(uint64_t l3_tables[], uint32_t max_tables,
                            uint32_t *out_count) {
  kassert(l3_tables != 0 && out_count != 0 &&
          max_tables >= USER_ASPACE_L3_TABLES);
  for (uint32_t i = 0; i < max_tables; ++i) {
    l3_tables[i] = 0;
  }
  /* Eight 2 MiB code/data spans and one independent stack span. */
  for (uint32_t i = 0; i < USER_ASPACE_L3_TABLES; ++i) {
    void *page = pmm_alloc_page();
    kassert(page != 0);
    uint64_t *table = (uint64_t *)page;
    for (uint64_t j = 0; j < 512; ++j) {
      table[j] = 0;
    }
    l3_tables[i] = (uint64_t)(uintptr_t)page;
  }
  *out_count = USER_ASPACE_L3_TABLES;
  klog("vmm: created user aspace l3_count=%u\n", *out_count);
}

xaios_status_t vmm_map_user_page(uint64_t virtual_address,
                                uint64_t physical_address, uint32_t flags,
                                uint64_t l3_tables[], uint32_t l3_count) {
  if ((virtual_address & (PAGE_SIZE - 1)) != 0 ||
      (physical_address & (PAGE_SIZE - 1)) != 0 ||
      (flags & XAIOS_VMM_PRESENT) == 0) {
    return XAIOS_ERR_INVALID;
  }
  if (virtual_address < XAIOS_USER_BASE || virtual_address >= XAIOS_USER_LIMIT) {
    return XAIOS_ERR_INVALID;
  }

  uint64_t l3_index = (virtual_address >> 12) & 0x1ffU;
  uint32_t l3_slot = 0U;
  if (user_l3_slot(virtual_address, &l3_slot) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  if (l3_slot >= l3_count || l3_tables[l3_slot] == 0) {
    return XAIOS_ERR_INVALID;
  }

  uint64_t *l3 = (uint64_t *)(uintptr_t)l3_tables[l3_slot];
  l3[l3_index] = page_descriptor(physical_address, attrs_from_flags(flags));
  return XAIOS_OK;
}

xaios_status_t vmm_unmap_user_page(uint64_t virtual_address,
                                  uint64_t l3_tables[], uint32_t l3_count) {
  if ((virtual_address & (PAGE_SIZE - 1)) != 0) {
    return XAIOS_ERR_INVALID;
  }

  uint64_t l3_index = (virtual_address >> 12) & 0x1ffU;
  uint32_t l3_slot = 0U;
  if (user_l3_slot(virtual_address, &l3_slot) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  if (l3_slot < l3_count && l3_tables[l3_slot] != 0) {
    uint64_t *l3 = (uint64_t *)(uintptr_t)l3_tables[l3_slot];
    l3[l3_index] = 0;
  }

  return XAIOS_OK;
}

void vmm_switch_user_aspace(uint64_t l3_tables[], uint32_t l3_count) {
  uint64_t *l2 = current_user_directory();
  kassert(l2 != 0);

  /* Clear every owned slot before installing the next process. */
  for (uint32_t index = 0U; index < USER_CODE_WINDOWS; ++index) {
    l2[USER_CODE_L2_INDEX + index] = 0U;
  }
  l2[USER_STACK_L2_INDEX] = 0;
  if (l3_tables != 0 && l3_count >= USER_ASPACE_L3_TABLES) {
    for (uint32_t index = 0U; index < USER_CODE_WINDOWS; ++index) {
      if (l3_tables[index] != 0U) {
        l2[USER_CODE_L2_INDEX + index] =
            table_descriptor((uint64_t *)(uintptr_t)l3_tables[index]);
      }
    }
    if (l3_tables[USER_CODE_WINDOWS] != 0U) {
      l2[USER_STACK_L2_INDEX] =
          table_descriptor(
              (uint64_t *)(uintptr_t)l3_tables[USER_CODE_WINDOWS]);
    }
  }

  /* Full TLB invalidation */
  __asm__ volatile(
      "dsb ishst\n"
      "tlbi vmalle1is\n"
      "dsb ish\n"
      "isb\n"
      :
      :
      : "memory");
}

void vmm_destroy_user_aspace(uint64_t l3_tables[], uint32_t l3_count) {
  /* Invalidate TLB before freeing pages to prevent stale entries
   * from pointing to reallocated physical memory */
  __asm__ volatile("dsb ishst\n\t"
                   "tlbi vmalle1is\n\t"
                   "dsb ish\n\t"
                   "isb");
  for (uint32_t i = 0; i < l3_count; ++i) {
    if (l3_tables[i] != 0) {
      pmm_free_page((void *)(uintptr_t)l3_tables[i]);
      l3_tables[i] = 0;
    }
  }
}
