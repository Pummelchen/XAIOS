#ifndef XAIOS_BOOT_INFO_H
#define XAIOS_BOOT_INFO_H

#include <stdint.h>

#define XAIOS_BOOT_INFO_MAGIC UINT64_C(0x4f534149424f4f54)
#define XAIOS_BOOT_INFO_VERSION UINT32_C(9)
#define XAIOS_BOOT_INFO_ENTROPY_SEED_BYTES UINT32_C(64)

#define XAIOS_BOOT_PLATFORM_SMMUV3 UINT32_C(1)

#define XAIOS_UART_NONE UINT32_C(0)
#define XAIOS_UART_PL011 UINT32_C(1)
#define XAIOS_UART_16550_MMIO UINT32_C(2)
#define XAIOS_UART_16550_IO UINT32_C(3)

#define XAIOS_MEMORY_TYPE_CONVENTIONAL UINT32_C(7)

#define XAIOS_FRAMEBUFFER_NONE UINT32_C(0)
#define XAIOS_FRAMEBUFFER_RGBX8 UINT32_C(1)
#define XAIOS_FRAMEBUFFER_BGRX8 UINT32_C(2)

#define XAIOS_ENTROPY_SOURCE_NONE 0U
/* A cryptographic random source the firmware vouches for. */
#define XAIOS_ENTROPY_SOURCE_FIRMWARE_RNG 1U
/* A file carried on the EFI System Partition. Reproducible by construction,
   which makes it useful for development and unfit for anything that has to
   stay secret. */
#define XAIOS_ENTROPY_SOURCE_SEED_FILE 2U
/* A random device on the bus -- virtio-rng, today. Not the firmware's, so it
   is named apart from it, but a real source and not a seed file: the machine
   asks the host for entropy at boot and gets it. This exists because RISC-V
   reported source=none while a working virtio-rng sat on its bus and served
   every entropy_read: the pool the report describes was simply never seeded
   from it, and a machine that has a source and says it has none is the exact
   failure the provenance work was meant to end. */
#define XAIOS_ENTROPY_SOURCE_DEVICE_RNG 3U

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
  /* A loader-provided seed, and -- separately -- where it came from.
   *
   * The size alone cannot answer that, and the difference is the whole of
   * F-05. The loader copies a seed file off the EFI System Partition if one
   * is there, then overwrites it from EFI_RNG_PROTOCOL if the firmware
   * offers one. On a machine where it does not -- VMware Fusion 26H1 is one
   * -- what survives is a file baked into the image: identical on every boot
   * and on every machine built from that image. The kernel logged "EFI RNG
   * seed accepted" for both, which is how a development seed comes to look
   * like a hardware one in the record.
   *
   * `entropy_seed_source` is one of XAIOS_ENTROPY_SOURCE_*. It occupies what
   * was reserved padding, so the structure's layout is unchanged. */
  uint32_t entropy_seed_size;
  uint32_t entropy_seed_source;
  uint8_t entropy_seed[XAIOS_BOOT_INFO_ENTROPY_SEED_BYTES];
  /* Optional UEFI GOP framebuffer. Serial remains the universal console. */
  uint64_t framebuffer_base;
  uint64_t framebuffer_size;
  uint32_t framebuffer_width;
  uint32_t framebuffer_height;
  uint32_t framebuffer_pixels_per_scan_line;
  uint32_t framebuffer_format;
  /* The files a self-contained loader carries, for a machine that arrived over
   * the network and has no EFI System Partition to copy from.
   *
   * The loader cannot offer the binary it is running: firmware maps a PE with
   * its sections at their virtual addresses, so the image in memory is not the
   * file it came from, and writing that back out produces something firmware
   * faults on rather than boots. It carries an unmodified copy of itself
   * instead, alongside the kernel and the initial filesystem, and an install
   * writes the three of them as an ordinary EFI System Partition.
   *
   * All zero on a boot from a volume, where those files are on the volume and
   * the installer copies them from there. */
  uint64_t payload_loader_base;
  uint64_t payload_loader_size;
  uint64_t payload_kernel_base;
  uint64_t payload_kernel_size;
  uint64_t payload_initfs_base;
  uint64_t payload_initfs_size;
} xaios_boot_info_t;

#endif
