/* Build the boot structure the shared kernel expects, from a device tree.
 *
 * On AArch64 the UEFI loader fills this in; on x86-64 the loader does it with
 * help from ACPI. RISC-V has neither, so the same structure is assembled here
 * from what the device tree declares. That keeps every layer above this file
 * identical across all three architectures -- which is the point. `kmain` is
 * shared code, and shared code that had to know which architecture it was
 * running on would be the platform-neutrality rule broken at the first step.
 *
 * What is filled in is only what exists. A field left zero means "this
 * machine does not have one", which the kernel already handles: there is no
 * ACPI RSDP here, and pretending otherwise by inventing a pointer would be
 * worse than the absence.
 */
#include <xaios/boot_info.h>
#include <xaios/riscv64_fdt.h>
#include <xaios/riscv64_sbi.h>

extern char __kernel_start[];
extern char __kernel_end[];

void klog(const char *fmt, ...);

/* The memory map handed to the kernel. Static because there is no allocator
   yet -- this runs before the physical memory manager it is describing memory
   for, which is the ordering constraint that makes a boot structure necessary
   in the first place. */
#define RISCV64_MAX_MEMORY_DESCRIPTORS 8U
static xaios_memory_descriptor_t g_memory_map[RISCV64_MAX_MEMORY_DESCRIPTORS];
static xaios_boot_info_t g_boot_info;

static void bytes_zero(void *destination, uint64_t size) {
  uint8_t *out = (uint8_t *)destination;
  for (uint64_t i = 0U; i < size; ++i) out[i] = 0U;
}

xaios_boot_info_t *riscv64_build_boot_info(uint64_t device_tree) {
  bytes_zero(&g_boot_info, sizeof(g_boot_info));
  bytes_zero(g_memory_map, sizeof(g_memory_map));

  g_boot_info.magic = XAIOS_BOOT_INFO_MAGIC;
  g_boot_info.version = XAIOS_BOOT_INFO_VERSION;
  g_boot_info.kernel_phys_base = (uint64_t)(uintptr_t)__kernel_start;
  g_boot_info.kernel_phys_end = (uint64_t)(uintptr_t)__kernel_end;
  g_boot_info.device_tree = device_tree;

  const void *blob = (const void *)(uintptr_t)device_tree;
  if (!fdt_valid(blob)) {
    /* No usable tree. Reported rather than guessed around: every address
       below would have to be invented, and a kernel booting on invented
       addresses fails somewhere far from here. */
    klog("riscv64: no valid device tree at %lx -- cannot describe this "
         "machine\n", device_tree);
    return 0;
  }

  uint64_t memory_base = 0U;
  uint64_t memory_size = 0U;
  if (!fdt_find_memory(blob, &memory_base, &memory_size)) {
    klog("riscv64: the device tree declares no memory\n");
    return 0;
  }

  /* Two holes, not one prefix.
     OpenSBI and this kernel sit at the bottom of RAM, and the device tree
     sits near the top -- on this board at 0x8fe00000 of a 0x90000000 range.
     The first version reserved everything below whichever ended last, which
     is correct and useless: it described 254 MiB of free memory as occupied
     and handed the allocator one megabyte. What is actually unavailable is
     the kernel and everything below it, and the tree itself. The gap between
     them is the bulk of the machine. */
  uint64_t memory_end = memory_base + memory_size;
  uint64_t tree_start = device_tree & ~UINT64_C(0xfff);
  uint64_t tree_end = (device_tree + fdt_total_size(blob) + 0xfffU) &
                      ~UINT64_C(0xfff);
  uint64_t free_start = (g_boot_info.kernel_phys_end + 0xfffU) &
                        ~UINT64_C(0xfff);
  if (free_start < memory_base) free_start = memory_base;

  uint32_t entries = 0U;
  if (tree_start > free_start && tree_start <= memory_end) {
    g_memory_map[entries].type = XAIOS_MEMORY_TYPE_CONVENTIONAL;
    g_memory_map[entries].physical_start = free_start;
    g_memory_map[entries].virtual_start = free_start;
    g_memory_map[entries].number_of_pages = (tree_start - free_start) / 0x1000U;
    ++entries;
  }
  uint64_t after_tree = tree_end > free_start ? tree_end : free_start;
  if (memory_end > after_tree) {
    g_memory_map[entries].type = XAIOS_MEMORY_TYPE_CONVENTIONAL;
    g_memory_map[entries].physical_start = after_tree;
    g_memory_map[entries].virtual_start = after_tree;
    g_memory_map[entries].number_of_pages = (memory_end - after_tree) / 0x1000U;
    ++entries;
  }
  if (entries == 0U) {
    klog("riscv64: no free memory in %lx..%lx around the kernel and tree\n",
         memory_base, memory_end);
    return 0;
  }

  g_boot_info.memory_map = (uint64_t)(uintptr_t)g_memory_map;
  g_boot_info.memory_descriptor_size = sizeof(xaios_memory_descriptor_t);
  g_boot_info.memory_map_size =
      (uint64_t)entries * sizeof(xaios_memory_descriptor_t);
  g_boot_info.memory_descriptor_version = 1U;

  /* The console. QEMU's virt board carries a 16550 and the tree says where;
     a board with a different one says so and this reads that instead. */
  uint64_t uart = 0U;
  if (fdt_find_node_address(blob, "serial", &uart) ||
      fdt_find_node_address(blob, "uart", &uart)) {
    g_boot_info.uart_base = uart;
    g_boot_info.uart_kind = XAIOS_UART_16550_MMIO;
    /* QEMU's 16550 registers are one byte apart. A tree that says otherwise
       carries reg-shift, which is read where it matters rather than assumed
       here. */
    g_boot_info.uart_reg_shift = 0U;
  }

  return &g_boot_info;
}
