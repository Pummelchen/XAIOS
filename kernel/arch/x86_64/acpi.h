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
  uint32_t hmat_locality_structures;
} x86_64_acpi_info_t;

typedef struct x86_64_acpi_processor_affinity {
  uint32_t proximity_domain;
  uint32_t apic_id;
  uint32_t clock_domain;
} x86_64_acpi_processor_affinity_t;

typedef struct x86_64_acpi_memory_affinity {
  uint32_t proximity_domain;
  uint32_t hot_pluggable;
  uint32_t nonvolatile;
  uint64_t base;
  uint64_t length;
} x86_64_acpi_memory_affinity_t;

int x86_64_acpi_parse(uint64_t rsdp_address, x86_64_acpi_info_t *info);
int x86_64_acpi_cpu_apic_id(const x86_64_acpi_info_t *info,
                            uint32_t ordinal, uint32_t *apic_id);
int x86_64_acpi_processor_affinity_at(
    const x86_64_acpi_info_t *info, uint32_t ordinal,
    x86_64_acpi_processor_affinity_t *affinity);
int x86_64_acpi_memory_affinity_at(
    const x86_64_acpi_info_t *info, uint32_t ordinal,
    x86_64_acpi_memory_affinity_t *affinity);
int x86_64_acpi_slit_distance(const x86_64_acpi_info_t *info,
                              uint32_t from, uint32_t to,
                              uint8_t *distance);
int x86_64_acpi_hmat_metric(const x86_64_acpi_info_t *info,
                            uint32_t initiator_domain,
                            uint32_t target_domain, uint8_t data_type,
                            uint64_t *value);

#endif
