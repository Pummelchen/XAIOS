#ifndef XAIOS_X86_64_ACPI_H
#define XAIOS_X86_64_ACPI_H

#include <xaios/types.h>

typedef struct x86_64_acpi_info {
  uint64_t rsdp;
  uint64_t root_table;
  uint64_t madt;
  uint64_t srat;
  uint64_t slit;
  uint64_t hmat;
  uint64_t slit_localities;
  uint32_t root_is_xsdt;
  uint32_t enabled_cpus;
  uint32_t io_apics;
  uint32_t processor_affinities;
  uint32_t memory_affinities;
} x86_64_acpi_info_t;

int x86_64_acpi_parse(uint64_t rsdp_address, x86_64_acpi_info_t *info);
int x86_64_acpi_cpu_apic_id(const x86_64_acpi_info_t *info,
                            uint32_t ordinal, uint32_t *apic_id);

#endif
