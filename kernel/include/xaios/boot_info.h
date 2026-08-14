#ifndef XAIOS_BOOT_INFO_H
#define XAIOS_BOOT_INFO_H

#include <stdint.h>

#define XAIOS_BOOT_INFO_MAGIC UINT64_C(0x4f534149424f4f54)
#define XAIOS_BOOT_INFO_VERSION UINT32_C(7)

#define XAIOS_BOOT_PLATFORM_SMMUV3 UINT32_C(1)

#define XAIOS_UART_NONE UINT32_C(0)
#define XAIOS_UART_PL011 UINT32_C(1)
#define XAIOS_UART_16550_MMIO UINT32_C(2)
#define XAIOS_UART_16550_IO UINT32_C(3)

#define XAIOS_MEMORY_TYPE_CONVENTIONAL UINT32_C(7)

typedef struct xaios_memory_descriptor {
  uint32_t type;
  uint32_t pad;
  uint64_t physical_start;
  uint64_t virtual_start;
  uint64_t number_of_pages;
  uint64_t attribute;
} xaios_memory_descriptor_t;

typedef struct xaios_boot_info {
  uint64_t magic;
  uint32_t version;
  uint32_t platform_flags;
  uint64_t memory_map;
  uint64_t memory_map_size;
  uint64_t memory_descriptor_size;
  uint64_t memory_descriptor_version;
  uint64_t kernel_phys_base;
  uint64_t kernel_phys_end;
  uint64_t uart_base;
  uint32_t uart_kind;
  uint32_t uart_reg_shift;
  uint32_t system_volume_present;
  uint32_t system_slot;
  uint64_t system_generation;
  uint64_t acpi_rsdp;
  uint64_t device_tree;
  uint64_t ap_trampoline;
  uint64_t boot_image_base;
  uint64_t boot_image_size;
  /* ACPI MCFG allocation selected by the UEFI loader. Zero selects the
   * architecture's platform fallback (currently QEMU virt on ARM64). */
  uint64_t pci_ecam_base;
  uint32_t pci_ecam_start_bus;
  uint32_t pci_ecam_end_bus;
} xaios_boot_info_t;

#endif
