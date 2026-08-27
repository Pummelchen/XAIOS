#include "boot_info.h"
#include "include/uefi_min.h"
#include "system_volume_loader.h"
#include <xaios/system_slot.h>

#define EI_NIDENT 16
#define PT_LOAD 1
#define PT_DYNAMIC 2
/* Matches EARLY_IDENTITY_SIZE in kernel/arch/aarch64/mmu.c. */
#define XAIOS_LOADER_MAX_KERNEL_ADDRESS UINT64_C(0x100000000)
#define DT_NULL 0
#define DT_RELA 7
#define DT_RELASZ 8
#define DT_RELAENT 9
/* The only relocation either architecture's kernel emits: add the load bias to
   a stored address. Everything else would need a symbol table the kernel does
   not carry. */
#define R_AARCH64_RELATIVE 1027
#define R_X86_64_RELATIVE 8
#define PF_X 0x1U
#define ELFCLASS64 2
#define ELFDATA2LSB 1
#define EM_X86_64 62
#define EM_AARCH64 183
#define ET_EXEC 2
#define ET_DYN 3
#define KERNEL_MAX_SIZE (16ULL * 1024ULL * 1024ULL)
/*
 * The initfs is loaded by the UEFI path before a block driver is available.
 * Keep this bound finite, but large enough for the complete XAIOS app set.
 */
#define BOOT_IMAGE_MAX_SIZE (32ULL * 1024ULL * 1024ULL)

#if defined(XAIOS_UEFI_TARGET_X86_64)
#define XAIOS_LOADER_TARGET_MESSAGE u"XAIOS loader target: x86_64 UEFI\r\n"
#define XAIOS_LOADER_INVALID_MESSAGE u"XAIOS loader error: invalid x86_64 ELF64 kernel\r\n"
#define XAIOS_LOADER_EXPECTED_MACHINE EM_X86_64
#define XAIOS_LOADER_UART_BASE UINT64_C(0x000003f8)
#define XAIOS_LOADER_UART_KIND XAIOS_UART_16550_IO
#else
#define XAIOS_LOADER_TARGET_MESSAGE u"XAIOS loader target: AArch64 UEFI\r\n"
#define XAIOS_LOADER_INVALID_MESSAGE u"XAIOS loader error: invalid AArch64 ELF64 kernel\r\n"
#define XAIOS_LOADER_EXPECTED_MACHINE EM_AARCH64
#define QEMU_VIRT_PL011_UART0_BASE UINT64_C(0x09000000)
#define XAIOS_LOADER_UART_BASE QEMU_VIRT_PL011_UART0_BASE
#define XAIOS_LOADER_UART_KIND XAIOS_UART_PL011
#endif

#define ACPI_HEADER_SIZE UINT32_C(36)
#define ACPI_MAX_TABLE_SIZE UINT32_C(0x01000000)
#define EFI_TEXT_CYAN UINT64_C(3)
#define EFI_TEXT_MAGENTA UINT64_C(5)
#define EFI_TEXT_LIGHTGRAY UINT64_C(7)

#ifndef XAIOS_BOOT_TEST_APPS
#define XAIOS_BOOT_TEST_APPS 0
#endif

typedef struct elf64_ehdr {
  unsigned char e_ident[EI_NIDENT];
  uint16_t e_type;
  uint16_t e_machine;
  uint32_t e_version;
  uint64_t e_entry;
  uint64_t e_phoff;
  uint64_t e_shoff;
  uint32_t e_flags;
  uint16_t e_ehsize;
  uint16_t e_phentsize;
  uint16_t e_phnum;
  uint16_t e_shentsize;
  uint16_t e_shnum;
  uint16_t e_shstrndx;
} elf64_ehdr_t;

typedef struct elf64_dyn {
  uint64_t d_tag;
  uint64_t d_val;
} elf64_dyn_t;

typedef struct elf64_rela {
  uint64_t r_offset;
  uint64_t r_info;
  int64_t r_addend;
} elf64_rela_t;

typedef struct elf64_phdr {
  uint32_t p_type;
  uint32_t p_flags;
  uint64_t p_offset;
  uint64_t p_vaddr;
  uint64_t p_paddr;
  uint64_t p_filesz;
  uint64_t p_memsz;
  uint64_t p_align;
} elf64_phdr_t;

typedef void (*kernel_entry_t)(const xaios_boot_info_t *boot_info);

static const efi_guid_t EFI_LOADED_IMAGE_PROTOCOL_GUID = {
    0x5b1b31a1U,
    0x9562U,
    0x11d2U,
    {0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b}};

static const efi_guid_t EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID = {
    0x964e5b22U,
    0x6459U,
    0x11d2U,
    {0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b}};

static const efi_guid_t EFI_DTB_TABLE_GUID = {
    0xb1b621d5U,
    0xf19cU,
    0x41a5U,
    {0x83, 0x0b, 0xd9, 0x15, 0x2c, 0x69, 0xaa, 0xe0}};

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

static xaios_boot_info_t g_boot_info;
/* UEFI loaders must remain relocatable even when all code/data references are PC-relative. */
static void *g_image_relocation_anchor = &g_image_relocation_anchor;

static int is_error(efi_status_t status);

static void *mem_copy(void *dst, const void *src, uint64_t size) {
  unsigned char *d = (unsigned char *)dst;
  const unsigned char *s = (const unsigned char *)src;
  for (uint64_t i = 0; i < size; ++i) {
    d[i] = s[i];
  }
  return dst;
}

static void *mem_set(void *dst, int value, uint64_t size) {
  unsigned char *d = (unsigned char *)dst;
  for (uint64_t i = 0; i < size; ++i) {
    d[i] = (unsigned char)value;
  }
  return dst;
}

static void collect_firmware_entropy(efi_system_table_t *system_table,
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

static void collect_framebuffer(efi_system_table_t *system_table,
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

static void loader_puts(efi_system_table_t *system_table,
                        const efi_char16_t *message) {
  if (system_table == 0 || system_table->con_out == 0 ||
      system_table->con_out->output_string == 0) {
    return;
  }

  (void)system_table->con_out->output_string(system_table->con_out, message);
}

static void loader_diagnostic(efi_system_table_t *system_table,
                              const efi_char16_t *message) {
#if XAIOS_BOOT_TEST_APPS
  loader_puts(system_table, message);
#else
  (void)system_table;
  (void)message;
#endif
}

static void loader_set_color(efi_system_table_t *system_table,
                             uint64_t color) {
  if (system_table != 0 && system_table->con_out != 0 &&
      system_table->con_out->set_attribute != 0) {
    (void)system_table->con_out->set_attribute(system_table->con_out, color);
  }
}

static void loader_brand(efi_system_table_t *system_table) {
  loader_set_color(system_table, EFI_TEXT_MAGENTA);
  loader_puts(system_table, u"XAI");
  loader_set_color(system_table, EFI_TEXT_CYAN);
  loader_puts(system_table, u" OS");
  loader_set_color(system_table, EFI_TEXT_LIGHTGRAY);
  loader_puts(system_table, u"\r\n\r\n");
}

static void loader_progress(efi_system_table_t *system_table,
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
  loader_brand(system_table);
  loader_puts(system_table, bar);
  loader_puts(system_table, u"\r\n\r\nLoaded: ");
  loader_puts(system_table, loaded);
  loader_puts(system_table, u"\r\nLoading: ");
  loader_puts(system_table, loading);
  loader_puts(system_table, u"\r\nRemaining: ");
  loader_puts(system_table, remaining);
  loader_puts(system_table, u" components\r\n");
#endif
}

static int is_error(efi_status_t status) {
  return (status & (1ULL << 63)) != 0;
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

static void discover_uart(uint64_t acpi_rsdp, uint64_t *base,
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

static void discover_pci_ecam(uint64_t acpi_rsdp, uint64_t *base,
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

static uint32_t platform_flags(const efi_system_table_t *system_table) {
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

static uint64_t configuration_table_pointer(
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

static efi_status_t open_root(efi_handle_t image_handle,
                              efi_system_table_t *system_table,
                              efi_file_protocol_t **root) {
  efi_loaded_image_protocol_t *loaded_image = 0;
  efi_simple_file_system_protocol_t *file_system = 0;
  efi_boot_services_t *bs = system_table->boot_services;

  efi_status_t status = bs->handle_protocol(
      image_handle, (efi_guid_t *)&EFI_LOADED_IMAGE_PROTOCOL_GUID,
      (void **)&loaded_image);
  if (!is_error(status) && loaded_image != 0 &&
      loaded_image->device_handle != 0) {
    status = bs->handle_protocol(
        loaded_image->device_handle,
        (efi_guid_t *)&EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID,
        (void **)&file_system);
    if (!is_error(status)) {
      status = file_system->open_volume(file_system, root);
      if (!is_error(status)) {
        return status;
      }
    }
  }

  uint64_t handle_count = 0U;
  efi_handle_t *handles = 0;
  status = bs->locate_handle_buffer(
      EFI_LOCATE_BY_PROTOCOL,
      (efi_guid_t *)&EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID, 0,
      &handle_count, &handles);
  if (is_error(status) || handles == 0) {
    return status;
  }
  if (handle_count > UINT64_C(4096)) {
    (void)bs->free_pool(handles);
    return EFI_LOAD_ERROR;
  }

  for (uint64_t i = 0U; i < handle_count; ++i) {
    efi_file_protocol_t *candidate_root = 0;
    efi_file_protocol_t *kernel_file = 0;
    status = bs->handle_protocol(
        handles[i], (efi_guid_t *)&EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID,
        (void **)&file_system);
    if (is_error(status)) {
      continue;
    }
    status = file_system->open_volume(file_system, &candidate_root);
    if (is_error(status) || candidate_root == 0) {
      continue;
    }
    status = candidate_root->open(candidate_root, &kernel_file,
                                  u"\\EFI\\XAIOS\\kernel.elf",
                                  EFI_FILE_MODE_READ, 0);
    if (!is_error(status)) {
      (void)kernel_file->close(kernel_file);
      *root = candidate_root;
      (void)bs->free_pool(handles);
      return EFI_SUCCESS;
    }
    (void)candidate_root->close(candidate_root);
  }

  (void)bs->free_pool(handles);
  return EFI_NOT_FOUND;
}

static efi_status_t read_kernel_file(efi_system_table_t *system_table,
                                     efi_file_protocol_t *root,
                                     void **kernel_buffer,
                                     uint64_t *kernel_size) {
  efi_boot_services_t *bs = system_table->boot_services;
  efi_file_protocol_t *kernel_file = 0;
  efi_physical_address_t kernel_storage = 0;
  uint64_t read_size = KERNEL_MAX_SIZE;

  efi_status_t status = root->open(root, &kernel_file,
                                   u"\\EFI\\XAIOS\\kernel.elf",
                                   EFI_FILE_MODE_READ, 0);
  if (is_error(status)) {
    return status;
  }

  status = bs->allocate_pages(EFI_ALLOCATE_ANY_PAGES, EFI_LOADER_DATA,
                              EFI_SIZE_TO_PAGES(KERNEL_MAX_SIZE),
                              &kernel_storage);
  if (is_error(status)) {
    (void)kernel_file->close(kernel_file);
    return status;
  }

  status = kernel_file->read(kernel_file, &read_size, (void *)kernel_storage);
  (void)kernel_file->close(kernel_file);
  if (is_error(status)) {
    (void)bs->free_pages(kernel_storage,
                         EFI_SIZE_TO_PAGES(KERNEL_MAX_SIZE));
    return status;
  }

  *kernel_buffer = (void *)kernel_storage;
  *kernel_size = read_size;
  return EFI_SUCCESS;
}

static efi_status_t read_optional_boot_image(
    efi_system_table_t *system_table, efi_file_protocol_t *root,
    uint64_t *image_base, uint64_t *image_size) {
  efi_boot_services_t *bs = system_table->boot_services;
  efi_file_protocol_t *image_file = 0;
  efi_physical_address_t image_storage = 0U;
  uint64_t read_size = BOOT_IMAGE_MAX_SIZE;

  *image_base = 0U;
  *image_size = 0U;
  efi_status_t status = root->open(root, &image_file,
                                   u"\\EFI\\XAIOS\\initfs.img",
                                   EFI_FILE_MODE_READ, 0);
  if (status == EFI_NOT_FOUND) return EFI_SUCCESS;
  if (is_error(status)) return status;

  status = bs->allocate_pages(EFI_ALLOCATE_ANY_PAGES, EFI_LOADER_DATA,
                              EFI_SIZE_TO_PAGES(BOOT_IMAGE_MAX_SIZE),
                              &image_storage);
  if (is_error(status)) {
    (void)image_file->close(image_file);
    return status;
  }
  status = image_file->read(image_file, &read_size, (void *)image_storage);
  uint8_t overflow_probe = 0U;
  uint64_t overflow_size = read_size == BOOT_IMAGE_MAX_SIZE ? 1U : 0U;
  if (!is_error(status) && overflow_size != 0U) {
    status = image_file->read(image_file, &overflow_size, &overflow_probe);
  }
  (void)image_file->close(image_file);
  if (is_error(status) || overflow_size != 0U || read_size == 0U ||
      read_size % UINT64_C(512) != 0U) {
    (void)bs->free_pages(image_storage,
                         EFI_SIZE_TO_PAGES(BOOT_IMAGE_MAX_SIZE));
    return is_error(status) ? status : EFI_LOAD_ERROR;
  }
  *image_base = image_storage;
  *image_size = read_size;
  return EFI_SUCCESS;
}

static efi_status_t read_optional_entropy_seed(
    efi_file_protocol_t *root,
    uint8_t seed[XAIOS_BOOT_INFO_ENTROPY_SEED_BYTES],
    uint32_t *seed_size) {
  efi_file_protocol_t *seed_file = 0;
  uint64_t read_size = XAIOS_BOOT_INFO_ENTROPY_SEED_BYTES;
  if (root == 0 || seed == 0 || seed_size == 0) return EFI_INVALID_PARAMETER;
  efi_status_t status = root->open(root, &seed_file,
                                   u"\\EFI\\XAIOS\\entropy.seed",
                                   EFI_FILE_MODE_READ, 0);
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

static int validate_elf(const void *kernel_buffer, uint64_t kernel_size,
                        const elf64_ehdr_t **ehdr_out) {
  if (kernel_size < sizeof(elf64_ehdr_t)) {
    return 0;
  }

  const elf64_ehdr_t *ehdr = (const elf64_ehdr_t *)kernel_buffer;
  if (ehdr->e_ident[0] != 0x7f || ehdr->e_ident[1] != 'E' ||
      ehdr->e_ident[2] != 'L' || ehdr->e_ident[3] != 'F') {
    return 0;
  }
  if (ehdr->e_ident[4] != ELFCLASS64 || ehdr->e_ident[5] != ELFDATA2LSB) {
    return 0;
  }
  /* ET_DYN is what the kernel is built as now: position-independent, so it can
     be placed wherever this machine actually has memory. ET_EXEC is still
     accepted because it loads identically -- it simply has no relocations to
     apply, and its segments land where they always did. */
  if ((ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) ||
      ehdr->e_machine != XAIOS_LOADER_EXPECTED_MACHINE) {
    return 0;
  }
  if (ehdr->e_phoff == 0 || ehdr->e_phnum == 0 ||
      ehdr->e_phentsize != sizeof(elf64_phdr_t)) {
    return 0;
  }
  if (ehdr->e_phoff + ((uint64_t)ehdr->e_phnum * sizeof(elf64_phdr_t)) >
      kernel_size) {
    return 0;
  }

  *ehdr_out = ehdr;
  return 1;
}

static efi_status_t load_kernel_segments(efi_system_table_t *system_table,
                                         const void *kernel_buffer,
                                         uint64_t kernel_size,
                                         const elf64_ehdr_t *ehdr,
                                         uint64_t *kernel_base,
                                         uint64_t *kernel_end,
                                         uint64_t *kernel_vaddr_base) {
  efi_boot_services_t *bs = system_table->boot_services;
  const elf64_phdr_t *phdrs =
      (const elf64_phdr_t *)((const unsigned char *)kernel_buffer + ehdr->e_phoff);

  *kernel_base = UINT64_MAX;
  *kernel_end = 0;
  *kernel_vaddr_base = UINT64_MAX;

  /* Where the kernel was linked, and how much room the whole image needs.
     Nothing is loaded yet: this pass only measures. */
  uint64_t link_low = UINT64_MAX;
  uint64_t link_high = 0;
  for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
    const elf64_phdr_t *phdr = &phdrs[i];
    if (phdr->p_type != PT_LOAD) continue;
    uint64_t start = phdr->p_paddr & ~UINT64_C(0xfff);
    if (start < link_low) link_low = start;
    if (phdr->p_paddr + phdr->p_memsz > link_high) {
      link_high = phdr->p_paddr + phdr->p_memsz;
    }
  }
  if (link_low == UINT64_MAX || link_high <= link_low) {
    return EFI_LOAD_ERROR;
  }

  /* The bias between where the kernel was linked and where it will run.
     Zero for a fixed-address kernel; for a position-independent one it is
     whatever this machine had room for.

     Asking firmware for a specific address is what used to fail: the kernel
     was linked at 0x90000000, and a QEMU guest with a gibibyte of memory has
     none there -- its RAM ends at 0x80000000. The three hypervisors start
     their memory in three different places, so no fixed address could suit
     them all. Let firmware choose, and move the kernel to meet it.

     The span is reserved in one piece and released immediately, purely to
     find a contiguous run that fits. Segments are then placed inside it with
     their own memory types, because firmware that enforces W^X needs
     executable segments to be loader code and writable ones loader data, and
     a single allocation could only be one of the two. Nothing else runs
     between the release and the placement: UEFI boot services are
     single-threaded and this loader is the only thing executing. */
  uint64_t span = link_high - link_low;
  /* Below four gibibytes, because that is how far the kernel's early identity
     map reaches: it maps the first 4 GiB before it has parsed anything, and a
     kernel placed above that cannot address itself while bringing the real
     tables up. Firmware picks the address, this only bounds it -- asked for
     anywhere at all, a machine with plenty of memory puts the kernel high and
     the early self-tests fail with no obvious cause. */
  efi_physical_address_t placement = XAIOS_LOADER_MAX_KERNEL_ADDRESS;
  efi_status_t reserve = bs->allocate_pages(EFI_ALLOCATE_MAX_ADDRESS,
                                            EFI_LOADER_DATA,
                                            EFI_SIZE_TO_PAGES(span),
                                            &placement);
  if (is_error(reserve)) {
    /* A machine with nothing free down there is not one this kernel can boot,
       but say so by failing the allocation rather than by faulting later. */
    return reserve;
  }
  (void)bs->free_pages(placement, EFI_SIZE_TO_PAGES(span));
  uint64_t bias = (uint64_t)placement - link_low;
  if (ehdr->e_type != ET_DYN) {
    /* A fixed-address kernel must still land where it was linked. */
    bias = 0;
  }

  for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
    const elf64_phdr_t *phdr = &phdrs[i];
    if (phdr->p_type != PT_LOAD) {
      continue;
    }
    if (phdr->p_memsz < phdr->p_filesz ||
        phdr->p_offset + phdr->p_filesz > kernel_size) {
      return EFI_LOAD_ERROR;
    }

    uint64_t load_paddr = phdr->p_paddr + bias;
    uint64_t segment_start = load_paddr & ~UINT64_C(0xfff);
    uint64_t segment_offset = load_paddr - segment_start;
    uint64_t allocation_size = segment_offset + phdr->p_memsz;
    efi_physical_address_t segment_address = segment_start;

    /* Executable segments must be loader code, or firmware that enforces W^X
       leaves them execute-never. Writable segments must be loader data, for
       the same reason in reverse. */
    uint32_t segment_memory_type =
        (phdr->p_flags & PF_X) != 0U ? EFI_LOADER_CODE : EFI_LOADER_DATA;
    efi_status_t status = bs->allocate_pages(
        EFI_ALLOCATE_ADDRESS, segment_memory_type,
        EFI_SIZE_TO_PAGES(allocation_size), &segment_address);
    if (is_error(status)) {
      return status;
    }

    mem_set((void *)load_paddr, 0, phdr->p_memsz);
    mem_copy((void *)load_paddr,
             (const unsigned char *)kernel_buffer + phdr->p_offset,
             phdr->p_filesz);

    if (load_paddr < *kernel_base) {
      *kernel_base = load_paddr;
    }
    /* Unbiased on purpose. The caller computes the entry as
       kernel_base + (e_entry - kernel_vaddr_base), where kernel_base already
       carries the bias -- adding it here too cancels it out, and the first
       attempt at this jumped to the link address and took an exception on the
       first instruction. */
    if (phdr->p_vaddr < *kernel_vaddr_base) {
      *kernel_vaddr_base = phdr->p_vaddr;
    }
    if (load_paddr + phdr->p_memsz > *kernel_end) {
      *kernel_end = load_paddr + phdr->p_memsz;
    }
  }

  /* Apply the relocations the kernel carries, now that it is in place. Only
     RELATIVE entries exist -- each says "the value stored here is an address
     that must be moved by the same bias" -- so this needs no symbol table. */
  if (bias != 0U) {
    for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
      const elf64_phdr_t *phdr = &phdrs[i];
      if (phdr->p_type != PT_DYNAMIC) continue;
      const elf64_dyn_t *dyn =
          (const elf64_dyn_t *)(uintptr_t)(phdr->p_vaddr + bias);
      uint64_t rela = 0;
      uint64_t rela_size = 0;
      uint64_t rela_entry = sizeof(elf64_rela_t);
      for (; dyn->d_tag != DT_NULL; ++dyn) {
        if (dyn->d_tag == DT_RELA) rela = dyn->d_val;
        else if (dyn->d_tag == DT_RELASZ) rela_size = dyn->d_val;
        else if (dyn->d_tag == DT_RELAENT) rela_entry = dyn->d_val;
      }
      if (rela == 0 || rela_size == 0 || rela_entry == 0) continue;
      for (uint64_t offset = 0; offset + rela_entry <= rela_size;
           offset += rela_entry) {
        const elf64_rela_t *entry =
            (const elf64_rela_t *)(uintptr_t)(rela + bias + offset);
        uint32_t type = (uint32_t)(entry->r_info & UINT64_C(0xffffffff));
        if (type != R_AARCH64_RELATIVE && type != R_X86_64_RELATIVE) {
          /* Anything else needs information this loader does not have, and
             silently skipping it would produce a kernel that runs with a
             wrong address in it. Refuse instead. */
          return EFI_LOAD_ERROR;
        }
        *(uint64_t *)(uintptr_t)(entry->r_offset + bias) =
            (uint64_t)(entry->r_addend + (int64_t)bias);
      }
    }
  }

  if (*kernel_base == UINT64_MAX || *kernel_end == 0 ||
      *kernel_vaddr_base == UINT64_MAX) {
    return EFI_LOAD_ERROR;
  }

  return EFI_SUCCESS;
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
  loader_brand(system_table);
  loader_puts(system_table, u"XAIOS loader starting\r\n");
  loader_puts(system_table, XAIOS_LOADER_TARGET_MESSAGE);
#else
  loader_progress(system_table,
                  u"[........................................] 0%",
                  u"UEFI firmware", u"system image", u"9");
#endif

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
      loader_diagnostic(
          system_table,
          u"XAIOS loader rolled back an unconfirmed system slot\r\n");
    }
    loader_diagnostic(
        system_table, u"XAIOS loader loaded verified A/B system slot\r\n");
  } else {
    status = open_root(image_handle, system_table, &root);
    if (is_error(status)) {
      loader_puts(system_table,
                  u"XAIOS loader error: could not open boot volume\r\n");
      return status;
    }
    status = read_kernel_file(system_table, root, &kernel_buffer, &kernel_size);
    if (is_error(status)) {
      loader_puts(system_table, u"XAIOS loader error: missing kernel.elf\r\n");
      return status;
    }
    loader_diagnostic(system_table,
                      u"XAIOS loader loaded kernel.elf fallback\r\n");
  }
  loader_progress(system_table,
                  u"[##......................................] 5%",
                  u"system image", u"initial filesystem", u"8");

  uint64_t boot_image_base = 0U;
  uint64_t boot_image_size = 0U;
  uint8_t optional_entropy_seed[XAIOS_BOOT_INFO_ENTROPY_SEED_BYTES];
  uint32_t optional_entropy_seed_size = 0U;
  mem_set(optional_entropy_seed, 0, sizeof(optional_entropy_seed));
  if (root == 0) {
    status = open_root(image_handle, system_table, &root);
    if (is_error(status)) return status;
  }
  status = read_optional_boot_image(system_table, root, &boot_image_base,
                                    &boot_image_size);
  if (is_error(status)) {
    loader_puts(system_table,
                u"XAIOS loader error: invalid initfs boot image\r\n");
    return status;
  }
  if (boot_image_size != 0U) {
    loader_diagnostic(system_table,
                      u"XAIOS loader loaded initfs boot image\r\n");
  }
  status = read_optional_entropy_seed(root, optional_entropy_seed,
                                      &optional_entropy_seed_size);
  (void)root->close(root);
  if (is_error(status)) {
    loader_puts(system_table,
                u"XAIOS loader error: invalid entropy seed\r\n");
    return status;
  }
  loader_progress(system_table,
                  u"[####....................................] 10%",
                  u"initial filesystem", u"kernel image", u"7");

  const elf64_ehdr_t *ehdr = 0;
  if (!validate_elf(kernel_buffer, kernel_size, &ehdr)) {
    loader_puts(system_table, XAIOS_LOADER_INVALID_MESSAGE);
    return EFI_LOAD_ERROR;
  }
  loader_diagnostic(system_table, u"XAIOS loader validated ELF64 kernel\r\n");
  loader_progress(system_table,
                  u"[######..................................] 15%",
                  u"kernel image", u"kernel segments", u"6");

  uint64_t kernel_base = 0;
  uint64_t kernel_end = 0;
  uint64_t kernel_vaddr_base = 0;
  status = load_kernel_segments(system_table, kernel_buffer, kernel_size, ehdr,
                                &kernel_base, &kernel_end,
                                &kernel_vaddr_base);
  if (is_error(status)) {
    loader_puts(system_table, u"XAIOS loader error: failed to load kernel segments\r\n");
    return status;
  }
  loader_diagnostic(system_table, u"XAIOS loader copied kernel segments\r\n");
  loader_progress(system_table,
                  u"[########................................] 20%",
                  u"kernel segments", u"hardware handoff", u"5");
#if XAIOS_BOOT_TEST_APPS
  loader_puts(system_table, u"XAIOS loader exiting boot services\r\n");
#endif

  uint64_t acpi_rsdp = configuration_table_pointer(
      system_table, &EFI_ACPI_20_TABLE_GUID, &EFI_ACPI_TABLE_GUID);
  uint64_t device_tree = configuration_table_pointer(
      system_table, &EFI_DTB_TABLE_GUID, 0);
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
  discover_uart(acpi_rsdp, &discovered_uart, &discovered_kind,
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
  discover_pci_ecam(acpi_rsdp, &pci_ecam_base, &pci_ecam_start_bus,
                    &pci_ecam_end_bus);
#endif
#if defined(XAIOS_UEFI_TARGET_X86_64)
  efi_physical_address_t trampoline_page = UINT64_C(0x8000);
  status = system_table->boot_services->allocate_pages(
      EFI_ALLOCATE_ADDRESS, EFI_LOADER_DATA, 1U, &trampoline_page);
  if (is_error(status)) {
    loader_puts(system_table,
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
    loader_puts(system_table, u"XAIOS loader error: failed to get memory map\r\n");
    return status;
  }

  g_boot_info.magic = XAIOS_BOOT_INFO_MAGIC;
  g_boot_info.version = XAIOS_BOOT_INFO_VERSION;
  g_boot_info.platform_flags = platform_flags(system_table);
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
  g_boot_info.boot_image_base = boot_image_base;
  g_boot_info.boot_image_size = boot_image_size;
  g_boot_info.pci_ecam_base = pci_ecam_base;
  g_boot_info.pci_ecam_start_bus = pci_ecam_start_bus;
  g_boot_info.pci_ecam_end_bus = pci_ecam_end_bus;
  if (optional_entropy_seed_size != 0U) {
    mem_copy(g_boot_info.entropy_seed, optional_entropy_seed,
             optional_entropy_seed_size);
    g_boot_info.entropy_seed_size = optional_entropy_seed_size;
  }
  mem_set(optional_entropy_seed, 0, sizeof(optional_entropy_seed));
  collect_firmware_entropy(system_table, &g_boot_info);
  collect_framebuffer(system_table, &g_boot_info);

  /* Firmware is permitted to alter the memory map between GetMemoryMap and
   * ExitBootServices. Retry with a fresh key without doing any allocations
   * after the successful map retrieval. Fusion exercises this path. */
  for (uint32_t attempt = 0U; attempt < 3U; ++attempt) {
    status = system_table->boot_services->exit_boot_services(image_handle,
                                                              map_key);
    if (!is_error(status)) break;
    if (status != EFI_INVALID_PARAMETER || attempt == 2U) {
      loader_puts(system_table,
                  u"XAIOS loader error: ExitBootServices failed\r\n");
      return status;
    }
    (void)system_table->boot_services->free_pool(memory_map);
    memory_map = 0;
    status = get_memory_map(system_table, &memory_map, &memory_map_size,
                            &map_key, &descriptor_size,
                            &descriptor_version);
    if (is_error(status)) {
      loader_puts(system_table,
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
