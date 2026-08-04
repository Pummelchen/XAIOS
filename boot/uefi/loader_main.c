#include "boot_info.h"
#include "include/uefi_min.h"
#include "system_volume_loader.h"
#include <xaios/system_slot.h>

#define EI_NIDENT 16
#define PT_LOAD 1
#define ELFCLASS64 2
#define ELFDATA2LSB 1
#define EM_X86_64 62
#define EM_AARCH64 183
#define ET_EXEC 2
#define KERNEL_MAX_SIZE (16ULL * 1024ULL * 1024ULL)

#if defined(XAIOS_UEFI_TARGET_X86_64)
#define XAIOS_LOADER_TARGET_MESSAGE u"XAIOS loader target: x86_64 UEFI\r\n"
#define XAIOS_LOADER_INVALID_MESSAGE u"XAIOS loader error: invalid x86_64 ELF64 kernel\r\n"
#define XAIOS_LOADER_EXPECTED_MACHINE EM_X86_64
#define XAIOS_LOADER_UART_BASE UINT64_C(0x000003f8)
#else
#define XAIOS_LOADER_TARGET_MESSAGE u"XAIOS loader target: AArch64 UEFI\r\n"
#define XAIOS_LOADER_INVALID_MESSAGE u"XAIOS loader error: invalid AArch64 ELF64 kernel\r\n"
#define XAIOS_LOADER_EXPECTED_MACHINE EM_AARCH64
#define QEMU_VIRT_PL011_UART0_BASE UINT64_C(0x09000000)
#define XAIOS_LOADER_UART_BASE QEMU_VIRT_PL011_UART0_BASE
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

static xaios_boot_info_t g_boot_info;

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

static void loader_puts(efi_system_table_t *system_table,
                        const efi_char16_t *message) {
  if (system_table == 0 || system_table->con_out == 0 ||
      system_table->con_out->output_string == 0) {
    return;
  }

  (void)system_table->con_out->output_string(system_table->con_out, message);
}

static int is_error(efi_status_t status) {
  return (status & (1ULL << 63)) != 0;
}

static uint32_t read_be32(const unsigned char *value) {
  return ((uint32_t)value[0] << 24U) | ((uint32_t)value[1] << 16U) |
         ((uint32_t)value[2] << 8U) | value[3];
}

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

static efi_status_t open_root(efi_handle_t image_handle,
                              efi_system_table_t *system_table,
                              efi_file_protocol_t **root) {
  efi_loaded_image_protocol_t *loaded_image = 0;
  efi_simple_file_system_protocol_t *file_system = 0;
  efi_boot_services_t *bs = system_table->boot_services;

  efi_status_t status = bs->handle_protocol(
      image_handle, (efi_guid_t *)&EFI_LOADED_IMAGE_PROTOCOL_GUID,
      (void **)&loaded_image);
  if (is_error(status)) {
    return status;
  }

  status = bs->handle_protocol(
      loaded_image->device_handle,
      (efi_guid_t *)&EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID,
      (void **)&file_system);
  if (is_error(status)) {
    return status;
  }

  return file_system->open_volume(file_system, root);
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
    return status;
  }

  *kernel_buffer = (void *)kernel_storage;
  *kernel_size = read_size;
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
  if (ehdr->e_type != ET_EXEC ||
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
                                         uint64_t *kernel_end) {
  efi_boot_services_t *bs = system_table->boot_services;
  const elf64_phdr_t *phdrs =
      (const elf64_phdr_t *)((const unsigned char *)kernel_buffer + ehdr->e_phoff);

  *kernel_base = UINT64_MAX;
  *kernel_end = 0;

  for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
    const elf64_phdr_t *phdr = &phdrs[i];
    if (phdr->p_type != PT_LOAD) {
      continue;
    }
    if (phdr->p_memsz < phdr->p_filesz ||
        phdr->p_offset + phdr->p_filesz > kernel_size) {
      return EFI_LOAD_ERROR;
    }

    uint64_t segment_start = phdr->p_paddr & ~UINT64_C(0xfff);
    uint64_t segment_offset = phdr->p_paddr - segment_start;
    uint64_t allocation_size = segment_offset + phdr->p_memsz;
    efi_physical_address_t segment_address = segment_start;

    efi_status_t status = bs->allocate_pages(
        EFI_ALLOCATE_ADDRESS, EFI_LOADER_DATA,
        EFI_SIZE_TO_PAGES(allocation_size), &segment_address);
    if (is_error(status)) {
      return status;
    }

    mem_set((void *)phdr->p_paddr, 0, phdr->p_memsz);
    mem_copy((void *)phdr->p_paddr,
             (const unsigned char *)kernel_buffer + phdr->p_offset,
             phdr->p_filesz);

    if (phdr->p_paddr < *kernel_base) {
      *kernel_base = phdr->p_paddr;
    }
    if (phdr->p_paddr + phdr->p_memsz > *kernel_end) {
      *kernel_end = phdr->p_paddr + phdr->p_memsz;
    }
  }

  if (*kernel_base == UINT64_MAX || *kernel_end == 0) {
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

efi_status_t EFIAPI efi_main(efi_handle_t image_handle,
                             efi_system_table_t *system_table) {
  loader_puts(system_table, u"XAIOS loader starting\r\n");
  loader_puts(system_table, XAIOS_LOADER_TARGET_MESSAGE);

  void *kernel_buffer = 0;
  uint64_t kernel_size = 0;
  uint32_t system_slot = XAIOS_SYSTEM_SLOT_NONE;
  uint64_t system_generation = 0U;
  uint32_t rollback_performed = 0U;
  efi_status_t status = system_volume_read_kernel(
      image_handle, system_table, &kernel_buffer, &kernel_size, &system_slot,
      &system_generation, &rollback_performed);
  if (!is_error(status)) {
    if (rollback_performed != 0U) {
      loader_puts(system_table,
                  u"XAIOS loader rolled back an unconfirmed system slot\r\n");
    }
    loader_puts(system_table,
                u"XAIOS loader loaded verified A/B system slot\r\n");
  } else {
    efi_file_protocol_t *root = 0;
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
    loader_puts(system_table, u"XAIOS loader loaded kernel.elf fallback\r\n");
  }

  const elf64_ehdr_t *ehdr = 0;
  if (!validate_elf(kernel_buffer, kernel_size, &ehdr)) {
    loader_puts(system_table, XAIOS_LOADER_INVALID_MESSAGE);
    return EFI_LOAD_ERROR;
  }
  loader_puts(system_table, u"XAIOS loader validated ELF64 kernel\r\n");

  uint64_t kernel_base = 0;
  uint64_t kernel_end = 0;
  status = load_kernel_segments(system_table, kernel_buffer, kernel_size, ehdr,
                                &kernel_base, &kernel_end);
  if (is_error(status)) {
    loader_puts(system_table, u"XAIOS loader error: failed to load kernel segments\r\n");
    return status;
  }
  loader_puts(system_table, u"XAIOS loader copied kernel segments\r\n");

  loader_puts(system_table, u"XAIOS loader exiting boot services\r\n");

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
  g_boot_info.uart_base = XAIOS_LOADER_UART_BASE;
  g_boot_info.system_volume_present =
      system_slot == XAIOS_SYSTEM_SLOT_NONE ? 0U : 1U;
  g_boot_info.system_slot = system_slot;
  g_boot_info.system_generation = system_generation;

  status = system_table->boot_services->exit_boot_services(image_handle, map_key);
  if (is_error(status)) {
    loader_puts(system_table, u"XAIOS loader error: ExitBootServices failed\r\n");
    return status;
  }

  kernel_entry_t kernel_entry = (kernel_entry_t)ehdr->e_entry;
  kernel_entry(&g_boot_info);

  for (;;) {
  }
}
