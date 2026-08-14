#ifndef XAIOS_AARCH64_ACPI_H
#define XAIOS_AARCH64_ACPI_H

#include <xaios/types.h>

/*
 * Validated platform resources from ACPI MADT and MCFG. The parser deliberately
 * exposes only resources the ARM64 kernel can consume without AML evaluation.
 */
typedef struct aarch64_acpi_info {
  uint64_t rsdp;
  uint64_t root_table;
  uint64_t madt;
  uint64_t mcfg;
  uint64_t gic_distributor_base;
  uint64_t gic_redistributor_base;
  uint64_t gic_redistributor_length;
  uint64_t pci_ecam_base;
  uint32_t root_is_xsdt;
  uint32_t enabled_cpus;
  uint32_t gic_version;
  uint32_t psci_compliant;
  uint32_t psci_use_hvc;
  uint32_t pci_segment;
  uint32_t pci_start_bus;
  uint32_t pci_end_bus;
} aarch64_acpi_info_t;

int aarch64_acpi_parse(uint64_t rsdp_address, aarch64_acpi_info_t *info);
int aarch64_acpi_cpu_mpidr(const aarch64_acpi_info_t *info,
                           uint32_t ordinal, uint64_t *mpidr);

#endif
