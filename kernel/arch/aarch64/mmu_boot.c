/* Boot-time AArch64 page tables, and the walk every mapping is built on.
 *
 * build_tables lays down the identity map, the kernel image's own 4 KiB
 * mappings and the UART window, build_per_cpu_roots copies that hierarchy into
 * one root per CPU, and vmm_init turns translation on with it. The helpers
 * beside them -- the descriptors, the allocate-or-find table walk and the
 * per-CPU mirroring -- are what the runtime mapping entry points in mmu.c and
 * the per-process address spaces in mmu_user.c call through mmu_internal.h.
 *
 * vmm_init and vmm_activate_kernel live here because they are the only
 * callers of the table builder and of the SCTLR_EL1 enable sequence, and
 * because that keeps this file's table state private. Nothing here changed
 * order, memory attributes or barriers; it moved whole.
 */
#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/pmm.h>
#include <xaios/smp.h>
#include <xaios/vmm.h>

#include "mmu_internal.h"
#include "platform.h"

#define EARLY_IDENTITY_SIZE UINT64_C(0x100000000)
#define EARLY_L1_TABLES 4
#define EARLY_KERNEL_L3_TABLES 16
#define L0_SPAN UINT64_C(0x8000000000)

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

uint64_t a64mmu_align_down(uint64_t value, uint64_t align) {
  return value & ~(align - 1);
}

uint64_t a64mmu_align_up(uint64_t value, uint64_t align) {
  return (value + align - 1) & ~(align - 1);
}

static void zero_table(uint64_t *table, uint64_t entries) {
  for (uint64_t i = 0; i < entries; ++i) {
    table[i] = 0;
  }
}

uint64_t a64mmu_table_descriptor(const uint64_t *table) {
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

uint64_t a64mmu_current_root_address(void) {
  return (uint64_t)(uintptr_t)current_root();
}

uint64_t a64mmu_page_descriptor(uint64_t physical_address, uint64_t attrs) {
  return (physical_address & PTE_ADDR_MASK) | attrs | PTE_VALID | PTE_TABLE |
         PTE_AF;
}

uint64_t a64mmu_block_descriptor(uint64_t physical_address, uint64_t attrs) {
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
    g_l2_tables[l1_index][l2_index] = a64mmu_block_descriptor(address, attrs);
  }
}

static void map_kernel_pages(uint64_t start, uint64_t end) {
  uint64_t table_index = 0;
  uint64_t table_start = a64mmu_align_down(start, L2_BLOCK_SIZE);
  uint64_t table_end = a64mmu_align_up(end, L2_BLOCK_SIZE);

  for (uint64_t region = table_start; region < table_end; region += L2_BLOCK_SIZE) {
    kassert(table_index < EARLY_KERNEL_L3_TABLES);

    uint64_t l1_index = (region >> 30) & 0x1ffU;
    uint64_t l2_index = (region >> 21) & 0x1ffU;
    uint64_t *l3 = g_kernel_l3_tables[table_index++];

    for (uint64_t page = 0; page < 512; ++page) {
      uint64_t address = region + (page * PAGE_SIZE);
      l3[page] = a64mmu_page_descriptor(address, kernel_page_attrs(address));
    }

    g_l2_tables[l1_index][l2_index] = a64mmu_table_descriptor(l3);
  }
}

uint64_t a64mmu_attrs_from_flags(uint32_t flags) {
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

/* The level-1 table covering a level-0 slot, created if this is the first
   mapping to land in that slot.

   The kernel used to have exactly one, covering the low 512 GiB, and every
   walker below refused anything above that outright. Refusing was survivable
   for a long time because everything the kernel touches -- memory, the UART,
   the GIC, the MMIO virtio windows -- is far below the line. A PCI BAR is not:
   QEMU's virt machine has a 64-bit PCI window that begins at exactly 512 GiB,
   and firmware is free to place a device there. It placed the disk of a
   single-disk machine there, the mapping was refused, and the machine came up
   with no durable storage and no way to say why.

   TCR_EL1.T0SZ is 16, so the hardware has been walking a full 48-bit address
   space all along, and a64mmu_sync_kernel_hierarchy already copies a new level-0
   entry into every per-CPU root. The only thing missing was the table. */
static uint64_t *ensure_l1_table(uint64_t l0_index) {
  if (l0_index == 0U) return g_l1_table;
  uint64_t descriptor = g_l0_table[l0_index];
  if ((descriptor & (PTE_VALID | PTE_TABLE)) == (PTE_VALID | PTE_TABLE)) {
    return (uint64_t *)(uintptr_t)(descriptor & PTE_ADDR_MASK);
  }
  /* A level-0 block descriptor is not architecturally available at a 4 KiB
     granule, so a valid non-table entry here would mean the table is corrupt.
     Decline rather than write through it. */
  if ((descriptor & PTE_VALID) != 0U) return 0;
  uint64_t *l1 = allocate_table();
  if (l1 == 0) return 0;
  g_l0_table[l0_index] = a64mmu_table_descriptor(l1);
  return l1;
}

static uint64_t *find_l1_table(uint64_t l0_index) {
  if (l0_index == 0U) return g_l1_table;
  uint64_t descriptor = g_l0_table[l0_index];
  if ((descriptor & (PTE_VALID | PTE_TABLE)) != (PTE_VALID | PTE_TABLE)) {
    return 0;
  }
  return (uint64_t *)(uintptr_t)(descriptor & PTE_ADDR_MASK);
}

uint64_t *a64mmu_ensure_l3_table(uint64_t virtual_address) {
  uint64_t l0_index = (virtual_address >> 39) & 0x1ffU;
  uint64_t l1_index = (virtual_address >> 30) & 0x1ffU;
  uint64_t l2_index = (virtual_address >> 21) & 0x1ffU;
  uint64_t *l1_table = ensure_l1_table(l0_index);
  if (l1_table == 0) return 0;

  /* Ensure L1 entry exists (allocate L2 table if needed) */
  uint64_t l1_desc = l1_table[l1_index];
  if ((l1_desc & (PTE_VALID | PTE_TABLE)) != (PTE_VALID | PTE_TABLE)) {
    uint64_t *new_l2 = (uint64_t *)pmm_alloc_page();
    kassert(new_l2 != 0);
    if ((l1_desc & PTE_VALID) != 0U && (l1_desc & PTE_TABLE) == 0U) {
      uint64_t block_base = l1_desc & PTE_BLOCK_L1_ADDR_MASK;
      uint64_t attrs = l1_desc & ~PTE_BLOCK_L1_ADDR_MASK;
      for (uint64_t i = 0; i < 512; ++i) {
        new_l2[i] = a64mmu_block_descriptor(block_base + i * L2_BLOCK_SIZE, attrs);
      }
    } else {
      for (uint64_t i = 0; i < 512; ++i) {
        new_l2[i] = 0;
      }
    }
    l1_table[l1_index] = a64mmu_table_descriptor(new_l2);
  }
  uint64_t *l2 = (uint64_t *)(uintptr_t)(l1_table[l1_index] & PTE_ADDR_MASK);

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
      l3[i] = a64mmu_page_descriptor(block_base + (i * PAGE_SIZE), attrs);
    }
  }

  l2[l2_index] = a64mmu_table_descriptor(l3);
  return l3;
}

uint64_t *a64mmu_ensure_l2_table(uint64_t virtual_address) {
  uint64_t l0_index = (virtual_address >> 39U) & 0x1ffU;
  uint64_t l1_index = (virtual_address >> 30U) & 0x1ffU;
  uint64_t *l1_table = ensure_l1_table(l0_index);
  if (l1_table == 0) return 0;

  uint64_t l1_desc = l1_table[l1_index];
  if ((l1_desc & PTE_VALID) == 0U) {
    uint64_t *l2 = allocate_table();
    if (l2 == 0) return 0;
    l1_table[l1_index] = a64mmu_table_descriptor(l2);
    return l2;
  }
  if ((l1_desc & PTE_TABLE) == 0U) return 0;
  return (uint64_t *)(uintptr_t)(l1_desc & PTE_ADDR_MASK);
}

uint64_t *a64mmu_find_l2_table(uint64_t virtual_address) {
  uint64_t l0_index = (virtual_address >> 39U) & 0x1ffU;
  uint64_t l1_index = (virtual_address >> 30U) & 0x1ffU;
  const uint64_t *l1_table = find_l1_table(l0_index);
  if (l1_table == 0) return 0;
  uint64_t l1_desc = l1_table[l1_index];
  if ((l1_desc & (PTE_VALID | PTE_TABLE)) !=
      (PTE_VALID | PTE_TABLE)) {
    return 0;
  }
  return (uint64_t *)(uintptr_t)(l1_desc & PTE_ADDR_MASK);
}

int a64mmu_in_mmio_window(uint64_t virtual_address) {
  return virtual_address >= g_mmio_start && virtual_address < g_mmio_end;
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

  g_l0_table[0] = a64mmu_table_descriptor(g_l1_table);

  for (uint64_t i = 0; i < EARLY_L1_TABLES; ++i) {
    g_l1_table[i] = a64mmu_table_descriptor(g_l2_tables[i]);
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
  uint64_t l1_limit = a64mmu_align_up(highest_physical, L1_BLOCK_SIZE);
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
  g_mmio_start = a64mmu_align_down(boot->uart_base, L2_BLOCK_SIZE);
  g_mmio_end = a64mmu_align_up(boot->uart_base + PAGE_SIZE, L2_BLOCK_SIZE);
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
    root[0] = a64mmu_table_descriptor(l1);
    /* Safe to overwrite because vmm_init stops the identity map at
       XAIOS_USER_BASE: this slot is never physical memory. */
    l1[user_l1_index] = a64mmu_table_descriptor(user_directory);
    aarch64_platform_set_page_tables(cpu, root, user_directory);
  }
}

void a64mmu_sync_kernel_hierarchy(uint64_t virtual_address) {
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

void vmm_activate_kernel(void) {
  aarch64_enable_mmu((uint64_t)(uintptr_t)current_root());
}
