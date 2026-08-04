#include "acpi.h"

#define ACPI_MAX_TABLE_BYTES UINT32_C(0x01000000)
#define ACPI_RSDP_V1_BYTES UINT32_C(20)
#define ACPI_RSDP_V2_BYTES UINT32_C(36)

typedef struct acpi_rsdp {
  char signature[8];
  uint8_t checksum;
  char oem_id[6];
  uint8_t revision;
  uint32_t rsdt_address;
  uint32_t length;
  uint64_t xsdt_address;
  uint8_t extended_checksum;
  uint8_t reserved[3];
} __attribute__((packed)) acpi_rsdp_t;

typedef struct acpi_sdt_header {
  char signature[4];
  uint32_t length;
  uint8_t revision;
  uint8_t checksum;
  char oem_id[6];
  char oem_table_id[8];
  uint32_t oem_revision;
  uint32_t creator_id;
  uint32_t creator_revision;
} __attribute__((packed)) acpi_sdt_header_t;

typedef struct acpi_madt {
  acpi_sdt_header_t header;
  uint32_t local_apic_address;
  uint32_t flags;
  uint8_t entries[];
} __attribute__((packed)) acpi_madt_t;

static uint32_t read_le32(const uint8_t *input) {
  return (uint32_t)input[0] | ((uint32_t)input[1] << 8U) |
         ((uint32_t)input[2] << 16U) | ((uint32_t)input[3] << 24U);
}

static uint64_t read_le64(const uint8_t *input) {
  return (uint64_t)read_le32(input) |
         ((uint64_t)read_le32(input + 4U) << 32U);
}

static int bytes_equal(const void *left, const void *right, uint32_t bytes) {
  const uint8_t *a = (const uint8_t *)left;
  const uint8_t *b = (const uint8_t *)right;
  for (uint32_t i = 0U; i < bytes; ++i) {
    if (a[i] != b[i]) return 0;
  }
  return 1;
}

static int checksum_valid(const void *data, uint32_t bytes) {
  const uint8_t *input = (const uint8_t *)data;
  uint8_t sum = 0U;
  for (uint32_t i = 0U; i < bytes; ++i) sum = (uint8_t)(sum + input[i]);
  return sum == 0U;
}

static int table_valid(const acpi_sdt_header_t *header) {
  return header != 0 && header->length >= sizeof(*header) &&
         header->length <= ACPI_MAX_TABLE_BYTES &&
         checksum_valid(header, header->length);
}

static const acpi_sdt_header_t *find_table(const acpi_sdt_header_t *root,
                                           uint32_t xsdt,
                                           const char signature[4]) {
  if (!table_valid(root)) return 0;
  uint32_t entry_size = xsdt != 0U ? 8U : 4U;
  uint32_t payload = root->length - sizeof(*root);
  if ((payload % entry_size) != 0U) return 0;
  const uint8_t *entries = (const uint8_t *)root + sizeof(*root);
  for (uint32_t offset = 0U; offset < payload; offset += entry_size) {
    uint64_t address = 0U;
    if (entry_size == 8U) {
      address = read_le64(entries + offset);
    } else {
      address = read_le32(entries + offset);
    }
    const acpi_sdt_header_t *table =
        (const acpi_sdt_header_t *)(uintptr_t)address;
    if (table_valid(table) && bytes_equal(table->signature, signature, 4U)) {
      return table;
    }
  }
  return 0;
}

static int madt_next(const acpi_madt_t *madt, uint32_t *offset,
                     const uint8_t **entry) {
  uint32_t entries_offset = (uint32_t)sizeof(*madt);
  if (*offset < entries_offset) *offset = entries_offset;
  if (*offset + 2U > madt->header.length) return 0;
  const uint8_t *candidate = (const uint8_t *)madt + *offset;
  uint32_t length = candidate[1];
  if (length < 2U || length > madt->header.length - *offset) return -1;
  *entry = candidate;
  *offset += length;
  return 1;
}

static int madt_inventory(const acpi_madt_t *madt,
                          x86_64_acpi_info_t *info) {
  if (!table_valid(&madt->header) || madt->header.length < sizeof(*madt)) {
    return 0;
  }
  uint32_t offset = (uint32_t)sizeof(*madt);
  for (;;) {
    const uint8_t *entry = 0;
    int result = madt_next(madt, &offset, &entry);
    if (result == 0) break;
    if (result < 0) return 0;
    if (entry[0] == 0U && entry[1] >= 8U) {
      uint32_t flags = read_le32(entry + 4U);
      if ((flags & 3U) != 0U) ++info->enabled_cpus;
    } else if (entry[0] == 9U && entry[1] >= 16U) {
      uint32_t flags = read_le32(entry + 8U);
      if ((flags & 3U) != 0U) ++info->enabled_cpus;
    } else if (entry[0] == 1U && entry[1] >= 12U) {
      ++info->io_apics;
    }
  }
  return info->enabled_cpus != 0U;
}

static int srat_inventory(const acpi_sdt_header_t *srat,
                          x86_64_acpi_info_t *info) {
  if (srat == 0) return 1;
  if (!table_valid(srat) || srat->length < sizeof(*srat) + 12U) return 0;
  uint32_t offset = (uint32_t)sizeof(*srat) + 12U;
  while (offset + 2U <= srat->length) {
    const uint8_t *entry = (const uint8_t *)srat + offset;
    uint32_t length = entry[1];
    if (length < 2U || length > srat->length - offset) return 0;
    if (entry[0] == 0U && length >= 16U) {
      uint32_t flags = read_le32(entry + 4U);
      if ((flags & 1U) != 0U) ++info->processor_affinities;
    } else if (entry[0] == 1U && length >= 40U) {
      uint32_t flags = read_le32(entry + 28U);
      if ((flags & 1U) != 0U) ++info->memory_affinities;
    } else if (entry[0] == 2U && length >= 24U) {
      uint32_t flags = read_le32(entry + 12U);
      if ((flags & 1U) != 0U) ++info->processor_affinities;
    }
    offset += length;
  }
  return offset == srat->length;
}

int x86_64_acpi_parse(uint64_t rsdp_address, x86_64_acpi_info_t *info) {
  if (rsdp_address == 0U || info == 0) return 0;
  *info = (x86_64_acpi_info_t){0};
  info->rsdp = rsdp_address;
  const acpi_rsdp_t *rsdp = (const acpi_rsdp_t *)(uintptr_t)rsdp_address;
  if (!bytes_equal(rsdp->signature, "RSD PTR ", 8U) ||
      !checksum_valid(rsdp, ACPI_RSDP_V1_BYTES)) {
    return 0;
  }
  uint64_t root_address = rsdp->rsdt_address;
  if (rsdp->revision >= 2U) {
    if (rsdp->length < ACPI_RSDP_V2_BYTES || rsdp->length > UINT32_C(4096) ||
        !checksum_valid(rsdp, rsdp->length)) {
      return 0;
    }
    if (rsdp->xsdt_address != 0U) {
      root_address = rsdp->xsdt_address;
      info->root_is_xsdt = 1U;
    }
  }
  const acpi_sdt_header_t *root =
      (const acpi_sdt_header_t *)(uintptr_t)root_address;
  if (!table_valid(root)) return 0;
  if (info->root_is_xsdt != 0U) {
    if (!bytes_equal(root->signature, "XSDT", 4U)) return 0;
  } else if (!bytes_equal(root->signature, "RSDT", 4U)) {
    return 0;
  }
  info->root_table = root_address;
  const acpi_sdt_header_t *madt =
      find_table(root, info->root_is_xsdt, "APIC");
  if (madt == 0 || !madt_inventory((const acpi_madt_t *)madt, info)) return 0;
  info->madt = (uint64_t)(uintptr_t)madt;
  const acpi_sdt_header_t *srat =
      find_table(root, info->root_is_xsdt, "SRAT");
  const acpi_sdt_header_t *slit =
      find_table(root, info->root_is_xsdt, "SLIT");
  const acpi_sdt_header_t *hmat =
      find_table(root, info->root_is_xsdt, "HMAT");
  if (!srat_inventory(srat, info)) return 0;
  if (slit != 0) {
    if (slit->length < sizeof(*slit) + 8U) return 0;
    uint64_t localities =
        read_le64((const uint8_t *)slit + sizeof(*slit));
    if (localities != 0U &&
        (localities > UINT32_MAX ||
         localities * localities > slit->length - sizeof(*slit) - 8U)) {
      return 0;
    }
    info->slit_localities = localities;
  }
  info->srat = (uint64_t)(uintptr_t)srat;
  info->slit = (uint64_t)(uintptr_t)slit;
  info->hmat = (uint64_t)(uintptr_t)hmat;
  return 1;
}

int x86_64_acpi_cpu_apic_id(const x86_64_acpi_info_t *info,
                            uint32_t ordinal, uint32_t *apic_id) {
  if (info == 0 || info->madt == 0U || apic_id == 0) return 0;
  const acpi_madt_t *madt = (const acpi_madt_t *)(uintptr_t)info->madt;
  uint32_t offset = (uint32_t)sizeof(*madt);
  uint32_t current = 0U;
  for (;;) {
    const uint8_t *entry = 0;
    int result = madt_next(madt, &offset, &entry);
    if (result <= 0) return 0;
    uint32_t id = 0U;
    uint32_t enabled = 0U;
    if (entry[0] == 0U && entry[1] >= 8U) {
      id = entry[3];
      enabled = read_le32(entry + 4U) & 3U;
    } else if (entry[0] == 9U && entry[1] >= 16U) {
      id = read_le32(entry + 4U);
      enabled = read_le32(entry + 8U) & 3U;
    }
    if (enabled != 0U && current++ == ordinal) {
      *apic_id = id;
      return 1;
    }
  }
}
