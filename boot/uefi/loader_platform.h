#ifndef XAIOS_LOADER_PLATFORM_H
#define XAIOS_LOADER_PLATFORM_H

#include "loader_common.h"

/* Console reporting. These are the only strings the boot gates read from the
   loader, so they stay exactly as they were before the split. */
void xaios_loader_puts(efi_system_table_t *system_table,
                       const efi_char16_t *message);
void xaios_loader_diagnostic(efi_system_table_t *system_table,
                             const efi_char16_t *message);
void xaios_loader_puts_hex(efi_system_table_t *system_table,
                           const efi_char16_t *prefix, uint64_t value);
void xaios_loader_brand(efi_system_table_t *system_table);
void xaios_loader_progress(efi_system_table_t *system_table,
                           const efi_char16_t *bar,
                           const efi_char16_t *loaded,
                           const efi_char16_t *loading,
                           const efi_char16_t *remaining);

/* Firmware facts that end up, field for field, in the boot handoff. */
void xaios_loader_collect_firmware_entropy(efi_system_table_t *system_table,
                                           xaios_boot_info_t *boot_info);
void xaios_loader_collect_framebuffer(efi_system_table_t *system_table,
                                      xaios_boot_info_t *boot_info);
uint32_t xaios_loader_platform_flags(const efi_system_table_t *system_table);
uint64_t xaios_loader_configuration_table_pointer(
    const efi_system_table_t *system_table, const efi_guid_t *preferred,
    const efi_guid_t *fallback);
/* The published device tree, or zero. The DTB GUID stays private to the
   platform translation unit, so the main loader never names it. */
uint64_t xaios_loader_dtb_table(const efi_system_table_t *system_table);
void xaios_loader_discover_uart(uint64_t acpi_rsdp, uint64_t *base,
                                uint32_t *kind, uint32_t *reg_shift);
void xaios_loader_discover_pci_ecam(uint64_t acpi_rsdp, uint64_t *base,
                                    uint32_t *start_bus, uint32_t *end_bus);

/* The second entropy source: the seed file, when the medium carries one. */
efi_status_t xaios_loader_read_optional_entropy_seed(
    efi_file_protocol_t *root,
    uint8_t seed[XAIOS_BOOT_INFO_ENTROPY_SEED_BYTES], uint32_t *seed_size);

#endif
