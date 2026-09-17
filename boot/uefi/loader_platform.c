#include "loader_platform.h"

/* Firmware protocols this unit queries. Each is used here and nowhere else. */
static const efi_guid_t EFI_DTB_TABLE_GUID = {
    0xb1b621d5U,
    0xf19cU,
    0x41a5U,
    {0x83, 0x0b, 0xd9, 0x15, 0x2c, 0x69, 0xaa, 0xe0}};

static const efi_guid_t EFI_RNG_PROTOCOL_GUID = {
    0x3152bca5U,
    0xeadeU,
    0x433dU,
    {0x86, 0x2e, 0xc0, 0x1c, 0xdc, 0x29, 0x1f, 0x44}};

static const efi_guid_t EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID = {
    0x9042a9deU,
    0x23dcU,
    0x4a38U,
    {0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a}};

void xaios_loader_collect_firmware_entropy(efi_system_table_t *system_table,
                                     xaios_boot_info_t *boot_info) {
  if (system_table == 0 || system_table->boot_services == 0 ||
      system_table->boot_services->locate_protocol == 0 || boot_info == 0) {
    return;
  }
  efi_locate_protocol_t locate_protocol =
      (efi_locate_protocol_t)system_table->boot_services->locate_protocol;
  efi_rng_protocol_t *rng = 0;
  efi_status_t status = locate_protocol((efi_guid_t *)&EFI_RNG_PROTOCOL_GUID,
                                        0, (void **)&rng);
  if (is_error(status) || rng == 0 || rng->get_rng == 0) return;
  status = rng->get_rng(rng, 0, XAIOS_BOOT_INFO_ENTROPY_SEED_BYTES,
                        boot_info->entropy_seed);
  if (is_error(status)) {
    mem_set(boot_info->entropy_seed, 0, XAIOS_BOOT_INFO_ENTROPY_SEED_BYTES);
    return;
  }
  boot_info->entropy_seed_size = XAIOS_BOOT_INFO_ENTROPY_SEED_BYTES;
  boot_info->entropy_seed_source = XAIOS_ENTROPY_SOURCE_FIRMWARE_RNG;
}

/* Firmware hands over whatever mode it happened to be in, which on VMware
   Fusion is 1024x768. The console renders an 8x8 font into that, so the guest
   looks like a DOS box on a modern display. Pick the largest mode the firmware
   offers in a directly addressable 32-bit format, bounded so an unusually
   large mode cannot produce a framebuffer the kernel will not map. */
#define LOADER_MAX_DISPLAY_WIDTH UINT32_C(2560)
#define LOADER_MAX_DISPLAY_HEIGHT UINT32_C(1600)

static void select_display_mode(efi_graphics_output_protocol_t *gop) {
  if (gop == 0 || gop->query_mode == 0 || gop->set_mode == 0 ||
      gop->mode == 0 || gop->mode->max_mode == 0U) {
    return;
  }
  uint32_t best_mode = gop->mode->mode;
  uint64_t best_pixels = 0U;
  if (gop->mode->info != 0) {
    best_pixels = (uint64_t)gop->mode->info->horizontal_resolution *
                  (uint64_t)gop->mode->info->vertical_resolution;
  }
  for (uint32_t candidate = 0U; candidate < gop->mode->max_mode; ++candidate) {
    efi_graphics_output_mode_information_t *info = 0;
    uint64_t size_of_info = 0U;
    if (is_error(gop->query_mode(gop, candidate, &size_of_info, &info)) ||
        info == 0) {
      continue;
    }
    /* Only the two packed 32-bit formats are drawable by the kernel. */
    if (info->pixel_format > 1U) continue;
    if (info->horizontal_resolution == 0U || info->vertical_resolution == 0U ||
        info->pixels_per_scan_line < info->horizontal_resolution) {
      continue;
    }
    if (info->horizontal_resolution > LOADER_MAX_DISPLAY_WIDTH ||
        info->vertical_resolution > LOADER_MAX_DISPLAY_HEIGHT) {
      continue;
    }
    uint64_t pixels = (uint64_t)info->horizontal_resolution *
                      (uint64_t)info->vertical_resolution;
    if (pixels > best_pixels) {
      best_pixels = pixels;
      best_mode = candidate;
    }
  }
  /* Firmware need not publish a framebuffer before a mode is set, and
     Apple's Virtualization.framework does not: FrameBufferBase and
     FrameBufferSize both read zero until SetMode runs. Set the mode when it
     differs, and also when no framebuffer has been published yet. */
  if (best_mode != gop->mode->mode || gop->mode->framebuffer_base == 0U ||
      gop->mode->framebuffer_size == 0U) {
    (void)gop->set_mode(gop, best_mode);
  }
}

void xaios_loader_collect_framebuffer(efi_system_table_t *system_table,
                                xaios_boot_info_t *boot_info) {
  if (system_table == 0 || system_table->boot_services == 0 ||
      system_table->boot_services->locate_protocol == 0 || boot_info == 0) {
    return;
  }
  efi_locate_protocol_t locate_protocol =
      (efi_locate_protocol_t)system_table->boot_services->locate_protocol;
  efi_graphics_output_protocol_t *gop = 0;
  efi_status_t status = locate_protocol(
      (efi_guid_t *)&EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID, 0, (void **)&gop);
  if (is_error(status) || gop == 0 || gop->mode == 0 ||
      gop->mode->max_mode == 0U) {
    return;
  }
  select_display_mode(gop);
  /* Validate only after the mode is set, because that is when firmware
     publishes the framebuffer. A PixelBltOnly device never publishes one and
     is correctly rejected here: it has no linear framebuffer to hand on. */
  if (gop->mode->info == 0 || gop->mode->framebuffer_base == 0U ||
      gop->mode->framebuffer_size == 0U) {
    return;
  }
  const efi_graphics_output_mode_information_t *info = gop->mode->info;
  if (info->horizontal_resolution == 0U || info->vertical_resolution == 0U ||
      info->pixels_per_scan_line < info->horizontal_resolution ||
      info->pixel_format > 1U) {
    return;
  }
  uint64_t pixels = (uint64_t)info->pixels_per_scan_line *
                    (uint64_t)info->vertical_resolution;
  if (pixels > UINT64_MAX / 4U || pixels * 4U > gop->mode->framebuffer_size) {
    return;
  }
  boot_info->framebuffer_base = gop->mode->framebuffer_base;
  boot_info->framebuffer_size = gop->mode->framebuffer_size;
  boot_info->framebuffer_width = info->horizontal_resolution;
  boot_info->framebuffer_height = info->vertical_resolution;
  boot_info->framebuffer_pixels_per_scan_line = info->pixels_per_scan_line;
  boot_info->framebuffer_format = info->pixel_format == 0U
                                      ? XAIOS_FRAMEBUFFER_RGBX8
                                      : XAIOS_FRAMEBUFFER_BGRX8;
}

void xaios_loader_puts(efi_system_table_t *system_table,
                        const efi_char16_t *message) {
  if (system_table == 0 || system_table->con_out == 0 ||
      system_table->con_out->output_string == 0) {
    return;
  }

  (void)system_table->con_out->output_string(system_table->con_out, message);
}

void xaios_loader_diagnostic(efi_system_table_t *system_table,
                              const efi_char16_t *message) {
#if XAIOS_BOOT_TEST_APPS
  xaios_loader_puts(system_table, message);
#else
  (void)system_table;
  (void)message;
#endif
}

/* Say a number out loud, because "failed to load kernel segments" on its own
   sends the reader to a bisect. The loader has no formatting library and this
   needs none: sixteen hex digits, leading zeros and all, appended to a fixed
   prefix. */
void xaios_loader_puts_hex(efi_system_table_t *system_table,
                            const efi_char16_t *prefix, uint64_t value) {
  static const char digits[] = "0123456789abcdef";
  efi_char16_t text[24];
  uint32_t at = 0U;
  for (int shift = 60; shift >= 0; shift -= 4) {
    text[at++] = (efi_char16_t)digits[(value >> (uint32_t)shift) & 0xfU];
  }
  text[at++] = u'\r';
  text[at++] = u'\n';
  text[at] = 0;
  xaios_loader_puts(system_table, prefix);
  xaios_loader_puts(system_table, text);
}

static void loader_set_color(efi_system_table_t *system_table,
                             uint64_t color) {
  if (system_table != 0 && system_table->con_out != 0 &&
      system_table->con_out->set_attribute != 0) {
    (void)system_table->con_out->set_attribute(system_table->con_out, color);
  }
}

void xaios_loader_brand(efi_system_table_t *system_table) {
  loader_set_color(system_table, EFI_TEXT_MAGENTA);
  xaios_loader_puts(system_table, u"XAI");
  loader_set_color(system_table, EFI_TEXT_CYAN);
  xaios_loader_puts(system_table, u" OS");
  loader_set_color(system_table, EFI_TEXT_LIGHTGRAY);
  xaios_loader_puts(system_table, u"\r\n\r\n");
}

void xaios_loader_progress(efi_system_table_t *system_table,
                            const efi_char16_t *bar,
                            const efi_char16_t *loaded,
                            const efi_char16_t *loading,
                            const efi_char16_t *remaining) {
#if XAIOS_BOOT_TEST_APPS
  (void)system_table;
  (void)bar;
  (void)loaded;
  (void)loading;
  (void)remaining;
#else
  if (system_table != 0 && system_table->con_out != 0 &&
      system_table->con_out->clear_screen != 0) {
    (void)system_table->con_out->clear_screen(system_table->con_out);
  }
  xaios_loader_brand(system_table);
  xaios_loader_puts(system_table, bar);
  xaios_loader_puts(system_table, u"\r\n\r\nLoaded: ");
  xaios_loader_puts(system_table, loaded);
  xaios_loader_puts(system_table, u"\r\nLoading: ");
  xaios_loader_puts(system_table, loading);
  xaios_loader_puts(system_table, u"\r\nRemaining: ");
  xaios_loader_puts(system_table, remaining);
  xaios_loader_puts(system_table, u" components\r\n");
#endif
}

static uint32_t read_be32(const unsigned char *value) {
  return ((uint32_t)value[0] << 24U) | ((uint32_t)value[1] << 16U) |
         ((uint32_t)value[2] << 8U) | value[3];
}

#if !defined(XAIOS_UEFI_TARGET_X86_64)
static uint32_t read_le32(const unsigned char *value) {
  return (uint32_t)value[0] | ((uint32_t)value[1] << 8U) |
         ((uint32_t)value[2] << 16U) | ((uint32_t)value[3] << 24U);
}

static uint64_t read_le64(const unsigned char *value) {
  return (uint64_t)read_le32(value) |
         ((uint64_t)read_le32(value + 4U) << 32U);
}

static int bytes_equal(const unsigned char *left, const char *right,
                       uint32_t length) {
  for (uint32_t i = 0U; i < length; ++i) {
    if (left[i] != (unsigned char)right[i]) return 0;
  }
  return 1;
}

static int checksum_valid(const unsigned char *bytes, uint32_t length) {
  uint8_t sum = 0U;
  for (uint32_t i = 0U; i < length; ++i) sum = (uint8_t)(sum + bytes[i]);
  return sum == 0U;
}

static const unsigned char *acpi_find_table(uint64_t rsdp_address,
                                            const char signature[4]) {
  const unsigned char *rsdp =
      (const unsigned char *)(uintptr_t)rsdp_address;
  if (rsdp == 0 || !bytes_equal(rsdp, "RSD PTR ", 8U) ||
      !checksum_valid(rsdp, 20U)) {
    return 0;
  }

  uint64_t root_address = read_le32(rsdp + 16U);
  uint32_t entry_size = 4U;
  if (rsdp[15] >= 2U && read_le32(rsdp + 20U) >= 36U &&
      checksum_valid(rsdp, 36U) && read_le64(rsdp + 24U) != 0U) {
    root_address = read_le64(rsdp + 24U);
    entry_size = 8U;
  }
  const unsigned char *root = (const unsigned char *)(uintptr_t)root_address;
  if (root == 0) return 0;
  uint32_t root_length = read_le32(root + 4U);
  if (root_length < ACPI_HEADER_SIZE || root_length > ACPI_MAX_TABLE_SIZE ||
      !checksum_valid(root, root_length)) {
    return 0;
  }
  uint32_t entry_bytes = root_length - ACPI_HEADER_SIZE;
  if (entry_bytes % entry_size != 0U) return 0;

  for (uint32_t offset = ACPI_HEADER_SIZE; offset < root_length;
       offset += entry_size) {
    uint64_t table_address = entry_size == 8U
                                 ? read_le64(root + offset)
                                 : read_le32(root + offset);
    const unsigned char *table =
        (const unsigned char *)(uintptr_t)table_address;
    if (table == 0) continue;
    uint32_t table_length = read_le32(table + 4U);
    if (table_length < ACPI_HEADER_SIZE ||
        table_length > ACPI_MAX_TABLE_SIZE ||
        !checksum_valid(table, table_length)) {
      continue;
    }
    if (bytes_equal(table, signature, 4U)) return table;
  }
  return 0;
}

void xaios_loader_discover_uart(uint64_t acpi_rsdp, uint64_t *base,
                          uint32_t *kind, uint32_t *reg_shift) {
  const unsigned char *spcr = acpi_find_table(acpi_rsdp, "SPCR");
  if (spcr == 0 || read_le32(spcr + 4U) < 52U || spcr[40] != 0U) return;

  uint8_t interface_type = spcr[36];
  uint64_t discovered_base = read_le64(spcr + 44U);
  if (discovered_base == 0U) return;
  if (interface_type == 3U || interface_type == 0x0dU ||
      interface_type == 0x0eU) {
    *base = discovered_base;
    *kind = XAIOS_UART_PL011;
    *reg_shift = 2U;
  } else if (interface_type == 0U || interface_type == 1U ||
             interface_type == 2U || interface_type == 0x12U) {
    uint8_t access_size = spcr[43];
    *base = discovered_base;
    *kind = XAIOS_UART_16550_MMIO;
    *reg_shift = access_size >= 1U && access_size <= 4U
                     ? (uint32_t)(access_size - 1U)
                     : 0U;
  }
}

void xaios_loader_discover_pci_ecam(uint64_t acpi_rsdp, uint64_t *base,
                              uint32_t *start_bus, uint32_t *end_bus) {
  const unsigned char *mcfg = acpi_find_table(acpi_rsdp, "MCFG");
  if (mcfg == 0 || read_le32(mcfg + 4U) < 60U) return;

  /* ACPI MCFG has an eight-byte reserved field after the common header,
   * followed by 16-byte allocation records. Select segment zero because
   * XAIOS currently has one PCI domain. */
  uint32_t length = read_le32(mcfg + 4U);
  for (uint32_t offset = 44U; offset + 16U <= length; offset += 16U) {
    uint64_t candidate = read_le64(mcfg + offset);
    uint16_t segment = (uint16_t)(mcfg[offset + 8U] |
                                  ((uint16_t)mcfg[offset + 9U] << 8U));
    uint8_t first = mcfg[offset + 10U];
    uint8_t last = mcfg[offset + 11U];
    if (segment != 0U || candidate == 0U ||
        (candidate & UINT64_C(0xfffff)) != 0U || last < first) {
      continue;
    }
    *base = candidate;
    *start_bus = first;
    *end_bus = last;
    return;
  }
}
#endif

static int guid_equal(const efi_guid_t *left, const efi_guid_t *right) {
  const unsigned char *a = (const unsigned char *)left;
  const unsigned char *b = (const unsigned char *)right;
  for (uint64_t i = 0U; i < sizeof(*left); ++i) {
    if (a[i] != b[i]) return 0;
  }
  return 1;
}

static int fdt_contains_smmuv3(const void *table) {
  static const unsigned char compatible[] = "arm,smmu-v3";
  const unsigned char *blob = (const unsigned char *)table;
  if (blob == 0 || read_be32(blob) != UINT32_C(0xd00dfeed)) return 0;
  uint32_t total = read_be32(blob + 4U);
  if (total < 40U || total > UINT32_C(16 * 1024 * 1024)) return 0;
  for (uint32_t i = 0U; i + sizeof(compatible) <= total; ++i) {
    uint32_t matched = 1U;
    for (uint32_t j = 0U; j < sizeof(compatible); ++j) {
      if (blob[i + j] != compatible[j]) {
        matched = 0U;
        break;
      }
    }
    if (matched != 0U) return 1;
  }
  return 0;
}

uint32_t xaios_loader_platform_flags(const efi_system_table_t *system_table) {
  if (system_table == 0 || system_table->configuration_table == 0 ||
      system_table->number_of_table_entries > UINT64_C(4096)) {
    return 0U;
  }
  for (uint64_t i = 0U; i < system_table->number_of_table_entries; ++i) {
    const efi_configuration_table_t *entry =
        &system_table->configuration_table[i];
    if (guid_equal(&entry->vendor_guid, &EFI_DTB_TABLE_GUID) &&
        fdt_contains_smmuv3(entry->vendor_table)) {
      return XAIOS_BOOT_PLATFORM_SMMUV3;
    }
  }
  return 0U;
}

uint64_t xaios_loader_configuration_table_pointer(
    const efi_system_table_t *system_table, const efi_guid_t *preferred,
    const efi_guid_t *fallback) {
  uint64_t fallback_pointer = 0U;
  if (system_table == 0 || system_table->configuration_table == 0 ||
      system_table->number_of_table_entries > UINT64_C(4096)) {
    return 0U;
  }
  for (uint64_t i = 0U; i < system_table->number_of_table_entries; ++i) {
    const efi_configuration_table_t *entry =
        &system_table->configuration_table[i];
    if (guid_equal(&entry->vendor_guid, preferred)) {
      return (uint64_t)(uintptr_t)entry->vendor_table;
    }
    if (fallback != 0 && guid_equal(&entry->vendor_guid, fallback)) {
      fallback_pointer = (uint64_t)(uintptr_t)entry->vendor_table;
    }
  }
  return fallback_pointer;
}

/* The device tree the firmware published, or zero. A separate entry point so
   the DTB GUID above stays private to this unit. */
uint64_t xaios_loader_dtb_table(const efi_system_table_t *system_table) {
  return xaios_loader_configuration_table_pointer(
      system_table, &EFI_DTB_TABLE_GUID, 0);
}

efi_status_t xaios_loader_read_optional_entropy_seed(
    efi_file_protocol_t *root,
    uint8_t seed[XAIOS_BOOT_INFO_ENTROPY_SEED_BYTES],
    uint32_t *seed_size) {
  efi_file_protocol_t *seed_file = 0;
  uint64_t read_size = XAIOS_BOOT_INFO_ENTROPY_SEED_BYTES;
  if (root == 0 || seed == 0 || seed_size == 0) return EFI_INVALID_PARAMETER;
  /* Two names, and the shorter one first.
   *
   * "entropy.seed" has a four-character extension, which cannot be written as
   * an 8.3 name -- so on disk it needs a long-name entry, and only tools that
   * implement those can read or write it. XAIOS's own FAT writer is 8.3 only
   * on purpose, that being the subset every implementation agrees on, and it
   * therefore could not copy this file when installing onto another disk. The
   * installed machine came up with no secure entropy and refused to start its
   * SSH server, which is a strange way to learn about a filename.
   *
   * Images now carry "entropy.sed". The old name is still tried, so a disk
   * built before this change still boots with its seed intact. */
  efi_status_t status = root->open(root, &seed_file,
                                   u"\\EFI\\XAIOS\\entropy.sed",
                                   EFI_FILE_MODE_READ, 0);
  if (status == EFI_NOT_FOUND) {
    status = root->open(root, &seed_file, u"\\EFI\\XAIOS\\entropy.seed",
                        EFI_FILE_MODE_READ, 0);
  }
  if (status == EFI_NOT_FOUND) return EFI_SUCCESS;
  if (is_error(status)) return status;
  status = seed_file->read(seed_file, &read_size, seed);
  uint8_t overflow_probe = 0U;
  uint64_t overflow_size =
      read_size == XAIOS_BOOT_INFO_ENTROPY_SEED_BYTES ? 1U : 0U;
  if (!is_error(status) && overflow_size != 0U) {
    status = seed_file->read(seed_file, &overflow_size, &overflow_probe);
  }
  (void)seed_file->close(seed_file);
  if (is_error(status) || read_size != XAIOS_BOOT_INFO_ENTROPY_SEED_BYTES ||
      overflow_size != 0U) {
    mem_set(seed, 0, XAIOS_BOOT_INFO_ENTROPY_SEED_BYTES);
    return is_error(status) ? status : EFI_LOAD_ERROR;
  }
  *seed_size = XAIOS_BOOT_INFO_ENTROPY_SEED_BYTES;
  return EFI_SUCCESS;
}
