#include <xaios/aarch64_acpi.h>

#define ACPI_MAX_TABLE_BYTES UINT32_C(0x01000000)
#define ACPI_RSDP_V1_BYTES UINT32_C(20)
#define ACPI_RSDP_V2_BYTES UINT32_C(36)
#define ACPI_SDT_HEADER_BYTES UINT32_C(36)
#define ACPI_MADT_HEADER_BYTES UINT32_C(44)
#define ACPI_MCFG_HEADER_BYTES UINT32_C(44)
#define ACPI_MCFG_ALLOCATION_BYTES UINT32_C(16)
#define ACPI_FADT_ARM_BOOT_FLAGS_OFFSET UINT32_C(125)
#define ACPI_FADT_ARM_BOOT_FLAGS_BYTES UINT32_C(2)
#define ACPI_FADT_PSCI_COMPLIANT UINT32_C(1)
#define ACPI_FADT_PSCI_USE_HVC UINT32_C(2)
#define ACPI_MADT_GICC UINT8_C(11)
#define ACPI_MADT_GICD UINT8_C(12)
#define ACPI_MADT_GICR UINT8_C(14)
#define ACPI_MADT_GIC_ITS UINT8_C(15)
#define ACPI_MADT_GICC_ENABLED UINT32_C(1)
#define ACPI_GIC_VERSION_V3 UINT8_C(3)
#define ACPI_GIC_VERSION_V4 UINT8_C(4)

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

static uint32_t read_le32(const uint8_t *input) {
  return (uint32_t)input[0] | ((uint32_t)input[1] << 8U) |
         ((uint32_t)input[2] << 16U) | ((uint32_t)input[3] << 24U);
}

static uint32_t read_le16(const uint8_t *input) {
  return (uint32_t)input[0] | ((uint32_t)input[1] << 8U);
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

static int table_valid(const acpi_sdt_header_t *table) {
  return table != 0 && table->length >= sizeof(*table) &&
         table->length <= ACPI_MAX_TABLE_BYTES &&
         checksum_valid(table, table->length);
}

static const acpi_sdt_header_t *find_table(const acpi_sdt_header_t *root,
                                           uint32_t root_is_xsdt,
                                           const char signature[4]) {
  if (!table_valid(root)) return 0;
  uint32_t entry_size = root_is_xsdt != 0U ? 8U : 4U;
  uint32_t payload = root->length - sizeof(*root);
  if (payload % entry_size != 0U) return 0;
  const uint8_t *entries = (const uint8_t *)root + sizeof(*root);
  for (uint32_t offset = 0U; offset < payload; offset += entry_size) {
    uint64_t address = entry_size == 8U ? read_le64(entries + offset)
                                        : read_le32(entries + offset);
    const acpi_sdt_header_t *table =
        (const acpi_sdt_header_t *)(uintptr_t)address;
    if (table_valid(table) && bytes_equal(table->signature, signature, 4U)) {
      return table;
    }
  }
  return 0;
}

static int madt_next(const acpi_sdt_header_t *madt, uint32_t *offset,
                     const uint8_t **entry) {
  if (*offset < ACPI_MADT_HEADER_BYTES) *offset = ACPI_MADT_HEADER_BYTES;
  if (*offset + 2U > madt->length) return 0;
  const uint8_t *candidate = (const uint8_t *)madt + *offset;
  uint32_t length = candidate[1];
  if (length < 2U || length > madt->length - *offset) return -1;
  *entry = candidate;
  *offset += length;
  return 1;
}

static int range_valid(uint64_t base, uint64_t length) {
  return base != 0U && length != 0U && base <= UINT64_MAX - length;
}

static int madt_inventory(const acpi_sdt_header_t *madt,
                          aarch64_acpi_info_t *info) {
  if (!table_valid(madt) || madt->length < ACPI_MADT_HEADER_BYTES) return 0;
  uint32_t offset = ACPI_MADT_HEADER_BYTES;
  for (;;) {
    const uint8_t *entry = 0;
    int result = madt_next(madt, &offset, &entry);
    if (result == 0) break;
    if (result < 0) return 0;
    if (entry[0] == ACPI_MADT_GICC) {
      /* MPIDR ends at byte 76 in the ACPI 5.0 GICC layout. */
      if (entry[1] < 76U) return 0;
      if ((read_le32(entry + 12U) & ACPI_MADT_GICC_ENABLED) != 0U) {
        ++info->enabled_cpus;
      }
    } else if (entry[0] == ACPI_MADT_GICD) {
      if (entry[1] < 24U || info->gic_distributor_base != 0U) return 0;
      uint64_t base = read_le64(entry + 8U);
      uint32_t version = entry[20];
      if (base == 0U || (version != ACPI_GIC_VERSION_V3 &&
                         version != ACPI_GIC_VERSION_V4)) {
        return 0;
      }
      info->gic_distributor_base = base;
      info->gic_version = version;
    } else if (entry[0] == ACPI_MADT_GIC_ITS) {
      /* Type 15 carries the translation service base at byte 8. Firmware that
         provides none simply omits the entry, and the hard-coded address that
         stood here before belonged to one particular emulator. */
      if (entry[1] < 16U) return 0;
      uint64_t base = read_le64(entry + 8U);
      if (base != 0U && info->gic_its_base == 0U) {
        info->gic_its_base = base;
      }
    } else if (entry[0] == ACPI_MADT_GICR) {
      if (entry[1] < 16U || info->gic_redistributor_base != 0U) return 0;
      uint64_t base = read_le64(entry + 4U);
      uint64_t length = read_le32(entry + 12U);
      if (!range_valid(base, length)) return 0;
      info->gic_redistributor_base = base;
      info->gic_redistributor_length = length;
    }
  }
  return info->enabled_cpus != 0U && info->gic_distributor_base != 0U &&
         info->gic_redistributor_base != 0U;
}

static int mcfg_inventory(const acpi_sdt_header_t *mcfg,
                          aarch64_acpi_info_t *info) {
  if (mcfg == 0) return 1;
  if (!table_valid(mcfg) || mcfg->length < ACPI_MCFG_HEADER_BYTES ||
      (mcfg->length - ACPI_MCFG_HEADER_BYTES) %
              ACPI_MCFG_ALLOCATION_BYTES !=
          0U) {
    return 0;
  }
  uint32_t allocations =
      (mcfg->length - ACPI_MCFG_HEADER_BYTES) / ACPI_MCFG_ALLOCATION_BYTES;
  for (uint32_t index = 0U; index < allocations; ++index) {
    const uint8_t *entry = (const uint8_t *)mcfg + ACPI_MCFG_HEADER_BYTES +
                           index * ACPI_MCFG_ALLOCATION_BYTES;
    uint64_t base = read_le64(entry);
    uint32_t segment = (uint32_t)entry[8] | ((uint32_t)entry[9] << 8U);
    uint32_t start_bus = entry[10];
    uint32_t end_bus = entry[11];
    uint64_t bus_count = (uint64_t)end_bus - start_bus + 1U;
    if (base == 0U || (base & UINT64_C(0xfffff)) != 0U ||
        end_bus < start_bus || bus_count > UINT64_MAX / UINT64_C(0x100000) ||
        base > UINT64_MAX - bus_count * UINT64_C(0x100000)) {
      return 0;
    }
    if (segment == 0U) {
      if (info->pci_ecam_base != 0U) return 0;
      info->pci_ecam_base = base;
      info->pci_segment = segment;
      info->pci_start_bus = start_bus;
      info->pci_end_bus = end_bus;
    }
  }
  return 1;
}

static int fadt_inventory(const acpi_sdt_header_t *fadt,
                          aarch64_acpi_info_t *info) {
  if (fadt == 0) return 1;
  if (!table_valid(fadt) ||
      fadt->length < ACPI_FADT_ARM_BOOT_FLAGS_OFFSET +
                         ACPI_FADT_ARM_BOOT_FLAGS_BYTES) {
    return 0;
  }
  uint32_t flags = read_le16((const uint8_t *)fadt +
                             ACPI_FADT_ARM_BOOT_FLAGS_OFFSET) & UINT32_C(3);
  info->psci_compliant = (flags & ACPI_FADT_PSCI_COMPLIANT) != 0U;
  info->psci_use_hvc = (flags & ACPI_FADT_PSCI_USE_HVC) != 0U;
  if (info->psci_use_hvc != 0U && info->psci_compliant == 0U) return 0;
  return 1;
}

int aarch64_acpi_parse(uint64_t rsdp_address, aarch64_acpi_info_t *info) {
  if (rsdp_address == 0U || info == 0) return 0;
  *info = (aarch64_acpi_info_t){0};
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
  if ((info->root_is_xsdt != 0U && !bytes_equal(root->signature, "XSDT", 4U)) ||
      (info->root_is_xsdt == 0U && !bytes_equal(root->signature, "RSDT", 4U))) {
    return 0;
  }
  info->root_table = root_address;
  const acpi_sdt_header_t *madt =
      find_table(root, info->root_is_xsdt, "APIC");
  if (madt == 0 || !madt_inventory(madt, info)) return 0;
  info->madt = (uint64_t)(uintptr_t)madt;
  const acpi_sdt_header_t *mcfg =
      find_table(root, info->root_is_xsdt, "MCFG");
  if (!mcfg_inventory(mcfg, info)) return 0;
  info->mcfg = (uint64_t)(uintptr_t)mcfg;
  const acpi_sdt_header_t *fadt =
      find_table(root, info->root_is_xsdt, "FACP");
  if (!fadt_inventory(fadt, info)) return 0;
  return 1;
}

int aarch64_acpi_cpu_mpidr(const aarch64_acpi_info_t *info,
                           uint32_t ordinal, uint64_t *mpidr) {
  if (info == 0 || info->madt == 0U || mpidr == 0) return 0;
  const acpi_sdt_header_t *madt =
      (const acpi_sdt_header_t *)(uintptr_t)info->madt;
  uint32_t offset = ACPI_MADT_HEADER_BYTES;
  uint32_t current = 0U;
  for (;;) {
    const uint8_t *entry = 0;
    int result = madt_next(madt, &offset, &entry);
    if (result <= 0) return 0;
    if (entry[0] != ACPI_MADT_GICC || entry[1] < 76U ||
        (read_le32(entry + 12U) & ACPI_MADT_GICC_ENABLED) == 0U) {
      continue;
    }
    if (current++ == ordinal) {
      *mpidr = read_le64(entry + 68U);
      return 1;
    }
  }
}
