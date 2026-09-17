#include "loader_common.h"
#include "loader_image.h"
#include "loader_platform.h"
#include "system_volume_loader.h"
#include <xaios/system_slot.h>

/* Firmware tables this file asks for by GUID. */
static const efi_guid_t EFI_ACPI_TABLE_GUID = {
    0xeb9d2d30U,
    0x2d88U,
    0x11d3U,
    {0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d}};

static const efi_guid_t EFI_ACPI_20_TABLE_GUID = {
    0x8868e871U,
    0xe4f1U,
    0x11d3U,
    {0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81}};

static xaios_boot_info_t g_boot_info;
/* UEFI loaders must remain relocatable even when all code/data references are PC-relative. */
static void *g_image_relocation_anchor = &g_image_relocation_anchor;

/*
 * A payload carried inside this loader's own binary.
 *
 * A machine booting over the network has no filesystem to read a kernel from.
 * Firmware fetches one file by TFTP and runs it, and that is the whole of what
 * it will do -- so for network boot to work, the one file has to contain
 * everything. The kernel and the initial filesystem are added to this binary as
 * PE sections after it is linked, and the loader finds them by parsing the
 * headers of the image the firmware just mapped for it.
 *
 * Parsing our own headers rather than exporting symbols from the sections is
 * deliberate. A symbol would have to be linked in whether or not the payload is
 * there, and this same binary boots from a filesystem when there is one: the
 * ordinary image has no such sections, this returns nothing, and the
 * file-reading path runs exactly as before.
 */
static const void *find_embedded_section(const void *image_base,
                                         const char *name,
                                         uint64_t *out_size) {
  if (image_base == 0 || name == 0 || out_size == 0) return 0;
  *out_size = 0U;
  const uint8_t *base = (const uint8_t *)image_base;
  /* MZ, then the offset of the PE header at 0x3c. */
  if (base[0] != 'M' || base[1] != 'Z') return 0;
  uint32_t pe_offset = (uint32_t)base[0x3c] | ((uint32_t)base[0x3d] << 8) |
                       ((uint32_t)base[0x3e] << 16) |
                       ((uint32_t)base[0x3f] << 24);
  /* A bound that keeps a corrupt or hostile header from walking away: the DOS
     header block ahead of the PE signature is small, and anything claiming
     otherwise is not an image this firmware loaded. */
  if (pe_offset < 0x40U || pe_offset > 0x400U) return 0;
  const uint8_t *pe = base + pe_offset;
  if (pe[0] != 'P' || pe[1] != 'E' || pe[2] != 0 || pe[3] != 0) return 0;
  uint16_t sections = (uint16_t)((uint16_t)pe[6] | ((uint16_t)pe[7] << 8));
  uint16_t optional_size =
      (uint16_t)((uint16_t)pe[20] | ((uint16_t)pe[21] << 8));
  if (sections == 0U || sections > 96U) return 0;
  const uint8_t *table = pe + 24U + optional_size;
  for (uint16_t index = 0U; index < sections; ++index) {
    const uint8_t *entry = table + (uint64_t)index * 40U;
    int match = 1;
    for (uint64_t byte = 0U; byte < 8U; ++byte) {
      char wanted = name[byte];
      if ((char)entry[byte] != wanted) { match = 0; break; }
      if (wanted == '\0') break;
    }
    if (!match) continue;
    uint32_t virtual_size = (uint32_t)entry[8] | ((uint32_t)entry[9] << 8) |
                            ((uint32_t)entry[10] << 16) |
                            ((uint32_t)entry[11] << 24);
    uint32_t virtual_address = (uint32_t)entry[12] | ((uint32_t)entry[13] << 8) |
                               ((uint32_t)entry[14] << 16) |
                               ((uint32_t)entry[15] << 24);
    uint32_t raw_size = (uint32_t)entry[16] | ((uint32_t)entry[17] << 8) |
                        ((uint32_t)entry[18] << 16) |
                        ((uint32_t)entry[19] << 24);
    /* VirtualSize is what the section holds; SizeOfRawData is that rounded up
       to file alignment. Trust the smaller of the two that is non-zero, so a
       payload is never read past its end into alignment padding. */
    uint64_t size = virtual_size != 0U ? virtual_size : raw_size;
    if (raw_size != 0U && raw_size < size) size = raw_size;
    if (size == 0U || virtual_address == 0U) return 0;
    *out_size = size;
    return (const void *)(base + virtual_address);
  }
  return 0;
}

static efi_status_t get_memory_map(efi_system_table_t *system_table,
                                   void **memory_map,
                                   uint64_t *memory_map_size,
                                   uint64_t *map_key,
                                   uint64_t *descriptor_size,
                                   uint32_t *descriptor_version) {
  efi_boot_services_t *bs = system_table->boot_services;
  *memory_map_size = 0;

  efi_status_t status = bs->get_memory_map(memory_map_size, 0, map_key,
                                           descriptor_size,
                                           descriptor_version);
  if (status != EFI_BUFFER_TOO_SMALL && !is_error(status)) {
    return EFI_LOAD_ERROR;
  }

  *memory_map_size += (*descriptor_size) * 8;
  status = bs->allocate_pool(EFI_LOADER_DATA, *memory_map_size, memory_map);
  if (is_error(status)) {
    return status;
  }

  return bs->get_memory_map(memory_map_size, *memory_map, map_key,
                            descriptor_size, descriptor_version);
}

/* Make freshly written kernel code visible to instruction fetch.

   Segments are copied as data, so the bytes land in the data cache, and
   instruction fetch does not look there. On real hardware the core can fetch
   stale memory at the entry point; emulation without caches cannot show this.
   Clean to the point of unification and invalidate before handing over. */
static void sync_instruction_cache(uint64_t base, uint64_t end) {
#if !defined(__aarch64__)
  /* x86 keeps instruction and data caches coherent in hardware, and the
     maintenance instructions below do not exist there. */
  (void)base;
  (void)end;
#else
  uint64_t ctr = 0U;
  __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
  uint64_t data_line = (uint64_t)4U << ((ctr >> 16U) & 0xFU);
  uint64_t inst_line = (uint64_t)4U << (ctr & 0xFU);
  if (data_line == 0U || inst_line == 0U || end <= base) return;
  for (uint64_t p = base & ~(data_line - 1U); p < end; p += data_line) {
    __asm__ volatile("dc cvau, %0" :: "r"(p) : "memory");
  }
  __asm__ volatile("dsb ish" ::: "memory");
  for (uint64_t p = base & ~(inst_line - 1U); p < end; p += inst_line) {
    __asm__ volatile("ic ivau, %0" :: "r"(p) : "memory");
  }
  __asm__ volatile("dsb ish" ::: "memory");
  __asm__ volatile("isb" ::: "memory");
#endif
}

efi_status_t EFIAPI efi_main(efi_handle_t image_handle,
                             efi_system_table_t *system_table) {
  if (g_image_relocation_anchor == 0) {
    return EFI_LOAD_ERROR;
  }
#if XAIOS_BOOT_TEST_APPS
  xaios_loader_brand(system_table);
  xaios_loader_puts(system_table, u"XAIOS loader starting\r\n");
  xaios_loader_puts(system_table, XAIOS_LOADER_TARGET_MESSAGE);
#else
  xaios_loader_progress(system_table,
                  u"[........................................] 0%",
                  u"UEFI firmware", u"system image", u"9");
#endif

  /* Whatever this binary carries inside itself. An ordinary loader on an EFI
     System Partition carries nothing and these stay null; a netboot image
     carries the kernel, the initial filesystem and an entropy seed, because
     firmware fetches exactly one file over the network and that file has to be
     the whole system. */
  const void *image_base = xaios_loader_image_base(image_handle, system_table);
  uint64_t embedded_kernel_size = 0U;
  uint64_t embedded_initfs_size = 0U;
  uint64_t embedded_seed_size = 0U;
  const void *embedded_kernel =
      find_embedded_section(image_base, ".xaiosk", &embedded_kernel_size);
  const void *embedded_initfs =
      find_embedded_section(image_base, ".xaiosi", &embedded_initfs_size);
  const void *embedded_seed =
      find_embedded_section(image_base, ".xaiose", &embedded_seed_size);
  uint64_t embedded_loader_size = 0U;
  const void *embedded_loader =
      find_embedded_section(image_base, ".xaiosl", &embedded_loader_size);

  void *kernel_buffer = 0;
  uint64_t kernel_size = 0;
  efi_file_protocol_t *root = 0;
  uint32_t system_slot = XAIOS_SYSTEM_SLOT_NONE;
  uint64_t system_generation = 0U;
  uint32_t rollback_performed = 0U;
  efi_status_t status = system_volume_read_kernel(
      image_handle, system_table, &kernel_buffer, &kernel_size, &system_slot,
      &system_generation, &rollback_performed);
  if (!is_error(status)) {
    if (rollback_performed != 0U) {
      xaios_loader_diagnostic(
          system_table,
          u"XAIOS loader rolled back an unconfirmed system slot\r\n");
    }
    xaios_loader_diagnostic(
        system_table, u"XAIOS loader loaded verified A/B system slot\r\n");
  } else if (embedded_kernel != 0) {
    /* Carried inside this binary, which is how a machine boots with no disk
       and no filesystem: firmware fetched one file over the network and this
       is what was in it. Preferred over the volume only when there is no
       verified A/B slot -- an installed machine still boots the slot it has
       been updated to, and a netboot image simply has none. */
    kernel_buffer = (void *)(uintptr_t)embedded_kernel;
    kernel_size = embedded_kernel_size;
    xaios_loader_diagnostic(system_table,
                      u"XAIOS loader using embedded kernel image\r\n");
  } else {
    status = xaios_loader_open_root(image_handle, system_table, &root);
    if (is_error(status)) {
      xaios_loader_puts(system_table,
                  u"XAIOS loader error: could not open boot volume\r\n");
      return status;
    }
    status = xaios_loader_read_kernel_file(system_table, root, &kernel_buffer, &kernel_size);
    if (is_error(status)) {
      xaios_loader_puts(system_table, u"XAIOS loader error: missing kernel.elf\r\n");
      return status;
    }
    /* Says what happened rather than naming a file. This reported "loaded
       kernel.elf fallback", which reads as a remark about a filename and is
       really about where the kernel came from: there was no verified A/B
       system slot to read it from, so it came off the EFI System Partition.
       That is the normal path for a medium that carries no system volume,
       and the old wording made it look like a degraded one. */
    xaios_loader_diagnostic(
        system_table,
        u"XAIOS loader: no verified system slot; kernel read from the EFI "
        u"System Partition\r\n");
  }
  xaios_loader_progress(system_table,
                  u"[##......................................] 5%",
                  u"system image", u"initial filesystem", u"8");

  uint64_t boot_image_base = 0U;
  uint64_t boot_image_size = 0U;
  uint8_t optional_entropy_seed[XAIOS_BOOT_INFO_ENTROPY_SEED_BYTES];
  uint32_t optional_entropy_seed_size = 0U;
  mem_set(optional_entropy_seed, 0, sizeof(optional_entropy_seed));
  if (embedded_initfs != 0) {
    boot_image_base = (uint64_t)(uintptr_t)embedded_initfs;
    boot_image_size = embedded_initfs_size;
    xaios_loader_diagnostic(system_table,
                      u"XAIOS loader using embedded initfs image\r\n");
  }
  if (embedded_kernel != 0 && root == 0) {
    /* Nothing to open. A machine that arrived over the network has no boot
       volume, and looking for one would fail where there is no failure: the
       entropy seed is optional, and the initfs is already in hand. */
    if (embedded_seed != 0 &&
        embedded_seed_size == XAIOS_BOOT_INFO_ENTROPY_SEED_BYTES) {
      mem_copy(optional_entropy_seed, embedded_seed,
               XAIOS_BOOT_INFO_ENTROPY_SEED_BYTES);
      optional_entropy_seed_size = XAIOS_BOOT_INFO_ENTROPY_SEED_BYTES;
    }
  } else {
    if (root == 0) {
      status = xaios_loader_open_root(image_handle, system_table, &root);
      if (is_error(status)) return status;
    }
    if (boot_image_size == 0U) {
      status = xaios_loader_read_optional_boot_image(system_table, root, &boot_image_base,
                                        &boot_image_size);
      if (is_error(status)) {
        xaios_loader_puts(system_table,
                    u"XAIOS loader error: invalid initfs boot image\r\n");
        return status;
      }
      if (boot_image_size != 0U) {
        xaios_loader_diagnostic(system_table,
                          u"XAIOS loader loaded initfs boot image\r\n");
      }
    }
    status = xaios_loader_read_optional_entropy_seed(root, optional_entropy_seed,
                                        &optional_entropy_seed_size);
    (void)root->close(root);
    if (is_error(status)) {
      xaios_loader_puts(system_table,
                  u"XAIOS loader error: invalid entropy seed\r\n");
      return status;
    }
  }
  xaios_loader_progress(system_table,
                  u"[####....................................] 10%",
                  u"initial filesystem", u"kernel image", u"7");

  const elf64_ehdr_t *ehdr = 0;
  if (!xaios_loader_validate_elf(kernel_buffer, kernel_size, &ehdr)) {
    xaios_loader_puts(system_table, XAIOS_LOADER_INVALID_MESSAGE);
    return EFI_LOAD_ERROR;
  }
  xaios_loader_diagnostic(system_table, u"XAIOS loader validated ELF64 kernel\r\n");
  xaios_loader_progress(system_table,
                  u"[######..................................] 15%",
                  u"kernel image", u"kernel segments", u"6");

  uint64_t kernel_base = 0;
  uint64_t kernel_end = 0;
  uint64_t kernel_vaddr_base = 0;
  status = xaios_loader_load_kernel_segments(system_table, kernel_buffer, kernel_size, ehdr,
                                &kernel_base, &kernel_end,
                                &kernel_vaddr_base);
  if (is_error(status)) {
    xaios_loader_puts(system_table, u"XAIOS loader error: failed to load kernel segments\r\n");
    return status;
  }
  xaios_loader_diagnostic(system_table, u"XAIOS loader copied kernel segments\r\n");
  xaios_loader_progress(system_table,
                  u"[########................................] 20%",
                  u"kernel segments", u"hardware handoff", u"5");
#if XAIOS_BOOT_TEST_APPS
  xaios_loader_puts(system_table, u"XAIOS loader exiting boot services\r\n");
#endif

  uint64_t acpi_rsdp = xaios_loader_configuration_table_pointer(
      system_table, &EFI_ACPI_20_TABLE_GUID, &EFI_ACPI_TABLE_GUID);
  uint64_t device_tree = xaios_loader_dtb_table(system_table);
  /* Said out loud, because a kernel that depends on the device tree for the
     addresses of its interrupt controller and its PCI window has no way to
     report the difference between "firmware published no tree" and "the tree
     said nothing useful". RISC-V depends on it for both. */
  xaios_loader_diagnostic(system_table,
                    device_tree != 0U
                        ? u"XAIOS loader: firmware published a device tree\r\n"
                        : u"XAIOS loader: firmware published no device tree\r\n");
  uint64_t ap_trampoline = 0U;
  uint64_t uart_base = XAIOS_LOADER_UART_BASE;
  uint32_t uart_kind = XAIOS_LOADER_UART_KIND;
  uint32_t uart_reg_shift = 0U;
  uint64_t pci_ecam_base = 0U;
  uint32_t pci_ecam_start_bus = 0U;
  uint32_t pci_ecam_end_bus = 0U;
#if !defined(XAIOS_UEFI_TARGET_X86_64)
  /* The compiled-in default is QEMU's PL011. Firmware that describes its
     hardware in ACPI is authoritative: when it publishes tables but no SPCR,
     the platform has no console UART, and handing the kernel the QEMU address
     makes its first klog() write to a device that is not there. With the MMU
     still off that aborts, and on a platform with no framebuffer it does so
     silently. Report no UART instead; klog treats a zero base as "no
     console". Platforms providing no ACPI at all keep the default, because
     there is nothing better to go on. */
  uint64_t discovered_uart = 0U;
  uint32_t discovered_kind = XAIOS_UART_NONE;
  uint32_t discovered_shift = 0U;
  xaios_loader_discover_uart(acpi_rsdp, &discovered_uart, &discovered_kind,
                &discovered_shift);
  if (discovered_kind != XAIOS_UART_NONE) {
    uart_base = discovered_uart;
    uart_kind = discovered_kind;
    uart_reg_shift = discovered_shift;
  } else if (acpi_rsdp != 0U) {
    uart_base = 0U;
    uart_kind = XAIOS_UART_NONE;
    uart_reg_shift = 0U;
  }
  xaios_loader_discover_pci_ecam(acpi_rsdp, &pci_ecam_base, &pci_ecam_start_bus,
                    &pci_ecam_end_bus);
#endif
#if defined(XAIOS_UEFI_TARGET_X86_64)
  efi_physical_address_t trampoline_page = UINT64_C(0x8000);
  status = system_table->boot_services->allocate_pages(
      EFI_ALLOCATE_ADDRESS, EFI_LOADER_DATA, 1U, &trampoline_page);
  if (is_error(status)) {
    xaios_loader_puts(system_table,
                u"XAIOS loader error: AP trampoline page unavailable\r\n");
    return status;
  }
  ap_trampoline = trampoline_page;
#endif

  void *memory_map = 0;
  uint64_t memory_map_size = 0;
  uint64_t map_key = 0;
  uint64_t descriptor_size = 0;
  uint32_t descriptor_version = 0;
  status = get_memory_map(system_table, &memory_map, &memory_map_size, &map_key,
                          &descriptor_size, &descriptor_version);
  if (is_error(status)) {
    xaios_loader_puts(system_table, u"XAIOS loader error: failed to get memory map\r\n");
    return status;
  }

  g_boot_info.magic = XAIOS_BOOT_INFO_MAGIC;
  g_boot_info.version = XAIOS_BOOT_INFO_VERSION;
  g_boot_info.platform_flags = xaios_loader_platform_flags(system_table);
  g_boot_info.memory_map = (uint64_t)memory_map;
  g_boot_info.memory_map_size = memory_map_size;
  g_boot_info.memory_descriptor_size = descriptor_size;
  g_boot_info.memory_descriptor_version = descriptor_version;
  g_boot_info.kernel_phys_base = kernel_base;
  g_boot_info.kernel_phys_end = kernel_end;
  g_boot_info.uart_base = uart_base;
  g_boot_info.uart_kind = uart_kind;
  g_boot_info.uart_reg_shift = uart_reg_shift;
  g_boot_info.system_volume_present =
      system_slot == XAIOS_SYSTEM_SLOT_NONE ? 0U : 1U;
  g_boot_info.system_slot = system_slot;
  g_boot_info.system_generation = system_generation;
  g_boot_info.acpi_rsdp = acpi_rsdp;
  g_boot_info.device_tree = device_tree;
  g_boot_info.ap_trampoline = ap_trampoline;
  /* Only when this binary is self-contained. On a boot from a volume the
     installer copies the files that are on the volume, and pointing it at a
     loader with no payload inside would produce an EFI System Partition whose
     loader has no kernel to find. */
  if (embedded_loader != 0 && embedded_kernel != 0 && embedded_initfs != 0) {
    g_boot_info.payload_loader_base = (uint64_t)(uintptr_t)embedded_loader;
    g_boot_info.payload_loader_size = embedded_loader_size;
    g_boot_info.payload_kernel_base = (uint64_t)(uintptr_t)embedded_kernel;
    g_boot_info.payload_kernel_size = embedded_kernel_size;
    g_boot_info.payload_initfs_base = (uint64_t)(uintptr_t)embedded_initfs;
    g_boot_info.payload_initfs_size = embedded_initfs_size;
  }
  g_boot_info.boot_image_base = boot_image_base;
  g_boot_info.boot_image_size = boot_image_size;
  g_boot_info.pci_ecam_base = pci_ecam_base;
  g_boot_info.pci_ecam_start_bus = pci_ecam_start_bus;
  g_boot_info.pci_ecam_end_bus = pci_ecam_end_bus;
  if (optional_entropy_seed_size != 0U) {
    mem_copy(g_boot_info.entropy_seed, optional_entropy_seed,
             optional_entropy_seed_size);
    g_boot_info.entropy_seed_size = optional_entropy_seed_size;
    /* Recorded as what it is. The firmware-entropy probe will say
       otherwise if the firmware has a real source, and on a machine where it
       does not this is what the kernel ends up running on. */
    g_boot_info.entropy_seed_source = XAIOS_ENTROPY_SOURCE_SEED_FILE;
  }
  mem_set(optional_entropy_seed, 0, sizeof(optional_entropy_seed));
  xaios_loader_collect_firmware_entropy(system_table, &g_boot_info);
  xaios_loader_collect_framebuffer(system_table, &g_boot_info);

  /* Firmware is permitted to alter the memory map between GetMemoryMap and
   * ExitBootServices. Retry with a fresh key without doing any allocations
   * after the successful map retrieval. Fusion exercises this path. */
  for (uint32_t attempt = 0U; attempt < 3U; ++attempt) {
    status = system_table->boot_services->exit_boot_services(image_handle,
                                                              map_key);
    if (!is_error(status)) break;
    if (status != EFI_INVALID_PARAMETER || attempt == 2U) {
      xaios_loader_puts(system_table,
                  u"XAIOS loader error: ExitBootServices failed\r\n");
      return status;
    }
    (void)system_table->boot_services->free_pool(memory_map);
    memory_map = 0;
    status = get_memory_map(system_table, &memory_map, &memory_map_size,
                            &map_key, &descriptor_size,
                            &descriptor_version);
    if (is_error(status)) {
      xaios_loader_puts(system_table,
                  u"XAIOS loader error: failed to refresh memory map\r\n");
      return status;
    }
    g_boot_info.memory_map = (uint64_t)memory_map;
    g_boot_info.memory_map_size = memory_map_size;
    g_boot_info.memory_descriptor_size = descriptor_size;
    g_boot_info.memory_descriptor_version = descriptor_version;
  }

  sync_instruction_cache(kernel_base, kernel_end);
  /* e_entry is a link-time address. It equals the load address only while the
     kernel is loaded exactly where it was linked, which is true today and
     silently stops being true the moment it is not. Rebase it on where the
     segments actually landed. */
  kernel_entry_t kernel_entry =
      (kernel_entry_t)(kernel_base + (ehdr->e_entry - kernel_vaddr_base));
  kernel_entry(&g_boot_info);

  for (;;) {
  }
}
