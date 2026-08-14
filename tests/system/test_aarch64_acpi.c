#include "../../kernel/include/xaios/aarch64_acpi.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void put32(uint8_t *output, uint32_t value) {
  output[0] = (uint8_t)value;
  output[1] = (uint8_t)(value >> 8U);
  output[2] = (uint8_t)(value >> 16U);
  output[3] = (uint8_t)(value >> 24U);
}

static void put64(uint8_t *output, uint64_t value) {
  put32(output, (uint32_t)value);
  put32(output + 4U, (uint32_t)(value >> 32U));
}

static void checksum(uint8_t *data, uint32_t length, uint32_t offset) {
  data[offset] = 0U;
  uint8_t sum = 0U;
  for (uint32_t i = 0U; i < length; ++i) sum = (uint8_t)(sum + data[i]);
  data[offset] = (uint8_t)(0U - sum);
}

static void table_header(uint8_t *table, const char signature[4],
                         uint32_t length) {
  memset(table, 0, length);
  memcpy(table, signature, 4U);
  put32(table + 4U, length);
  table[8] = 1U;
  memcpy(table + 10U, "XAIOS ", 6U);
}

int main(void) {
  uint8_t madt[44U + 76U * 2U + 24U + 16U];
  uint8_t mcfg[60];
  uint8_t fadt[127];
  uint8_t xsdt[60];
  uint8_t rsdp[36];
  table_header(madt, "APIC", sizeof(madt));
  uint32_t offset = 44U;
  for (uint32_t cpu = 0U; cpu < 2U; ++cpu) {
    madt[offset] = 11U;
    madt[offset + 1U] = 76U;
    put32(madt + offset + 12U, 1U);
    put64(madt + offset + 60U, UINT64_C(0x080a0000));
    put64(madt + offset + 68U, UINT64_C(0x80000000) + cpu);
    offset += 76U;
  }
  madt[offset] = 12U;
  madt[offset + 1U] = 24U;
  put64(madt + offset + 8U, UINT64_C(0x08000000));
  madt[offset + 20U] = 3U;
  offset += 24U;
  madt[offset] = 14U;
  madt[offset + 1U] = 16U;
  put64(madt + offset + 4U, UINT64_C(0x080a0000));
  put32(madt + offset + 12U, UINT32_C(0x40000));
  checksum(madt, sizeof(madt), 9U);

  table_header(mcfg, "MCFG", sizeof(mcfg));
  put64(mcfg + 44U, UINT64_C(0x4010000000));
  mcfg[54] = 0U;
  mcfg[55] = 0U;
  checksum(mcfg, sizeof(mcfg), 9U);

  table_header(fadt, "FACP", sizeof(fadt));
  fadt[125] = 3U;
  checksum(fadt, sizeof(fadt), 9U);

  table_header(xsdt, "XSDT", sizeof(xsdt));
  put64(xsdt + 36U, (uint64_t)(uintptr_t)madt);
  put64(xsdt + 44U, (uint64_t)(uintptr_t)mcfg);
  put64(xsdt + 52U, (uint64_t)(uintptr_t)fadt);
  checksum(xsdt, sizeof(xsdt), 9U);

  memset(rsdp, 0, sizeof(rsdp));
  memcpy(rsdp, "RSD PTR ", 8U);
  memcpy(rsdp + 9U, "XAIOS ", 6U);
  rsdp[15] = 2U;
  put32(rsdp + 20U, sizeof(rsdp));
  put64(rsdp + 24U, (uint64_t)(uintptr_t)xsdt);
  checksum(rsdp, 20U, 8U);
  checksum(rsdp, sizeof(rsdp), 32U);

  aarch64_acpi_info_t info;
  uint64_t cpu0 = 0U;
  uint64_t cpu1 = 0U;
  if (!aarch64_acpi_parse((uint64_t)(uintptr_t)rsdp, &info) ||
      info.root_is_xsdt != 1U || info.enabled_cpus != 2U ||
      info.gic_version != 3U || info.gic_distributor_base != UINT64_C(0x08000000) ||
      info.gic_redistributor_base != UINT64_C(0x080a0000) ||
      info.gic_redistributor_length != UINT64_C(0x40000) ||
      info.psci_compliant != 1U || info.psci_use_hvc != 1U ||
      info.pci_ecam_base != UINT64_C(0x4010000000) || info.pci_start_bus != 0U ||
      info.pci_end_bus != 0U || !aarch64_acpi_cpu_mpidr(&info, 0U, &cpu0) ||
      !aarch64_acpi_cpu_mpidr(&info, 1U, &cpu1) ||
      cpu0 != UINT64_C(0x80000000) || cpu1 != UINT64_C(0x80000001)) {
    return 1;
  }
  fadt[125] = 2U;
  checksum(fadt, sizeof(fadt), 9U);
  if (aarch64_acpi_parse((uint64_t)(uintptr_t)rsdp, &info)) return 1;
  fadt[125] = 3U;
  checksum(fadt, sizeof(fadt), 9U);
  madt[9] ^= 1U;
  if (aarch64_acpi_parse((uint64_t)(uintptr_t)rsdp, &info)) return 1;
  puts("aarch64-acpi: GICC/GICD/GICR/MCFG/FADT parsing and validation passed");
  return 0;
}
