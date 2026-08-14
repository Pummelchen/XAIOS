#include "../../kernel/arch/x86_64/acpi.h"

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
  uint8_t madt[80];
  uint8_t srat[168];
  uint8_t slit[48];
  uint8_t hmat[96];
  uint8_t xsdt[68];
  uint8_t rsdp[36];

  table_header(madt, "APIC", sizeof(madt));
  put32(madt + 36U, UINT32_C(0xfee00000));
  madt[44] = 0U;
  madt[45] = 8U;
  madt[47] = 1U;
  put32(madt + 48U, 1U);
  madt[52] = 9U;
  madt[53] = 16U;
  put32(madt + 56U, 257U);
  put32(madt + 60U, 1U);
  madt[68] = 1U;
  madt[69] = 12U;
  put32(madt + 72U, 2U);
  checksum(madt, sizeof(madt), 9U);

  table_header(srat, "SRAT", sizeof(srat));
  srat[48] = 0U;
  srat[49] = 16U;
  srat[51] = 1U;
  put32(srat + 52U, 1U);
  put32(srat + 60U, 11U);
  srat[64] = 2U;
  srat[65] = 24U;
  put32(srat + 68U, 1U);
  put32(srat + 72U, 257U);
  put32(srat + 76U, 1U);
  put32(srat + 80U, 22U);
  srat[88] = 1U;
  srat[89] = 40U;
  put32(srat + 90U, 0U);
  put64(srat + 96U, UINT64_C(0x100000));
  put64(srat + 104U, UINT64_C(0x40000000));
  put32(srat + 116U, 1U);
  srat[128] = 1U;
  srat[129] = 40U;
  put32(srat + 130U, 1U);
  put64(srat + 136U, UINT64_C(0x40100000));
  put64(srat + 144U, UINT64_C(0x40000000));
  put32(srat + 156U, 7U);
  checksum(srat, sizeof(srat), 9U);

  table_header(slit, "SLIT", sizeof(slit));
  put64(slit + 36U, 2U);
  slit[44] = 10U;
  slit[45] = 20U;
  slit[46] = 20U;
  slit[47] = 10U;
  checksum(slit, sizeof(slit), 9U);

  table_header(hmat, "HMAT", sizeof(hmat));
  hmat[40] = 1U;
  put32(hmat + 44U, 56U);
  hmat[49] = 0U;
  put32(hmat + 52U, 2U);
  put32(hmat + 56U, 2U);
  put64(hmat + 64U, 100U);
  put32(hmat + 72U, 0U);
  put32(hmat + 76U, 1U);
  put32(hmat + 80U, 0U);
  put32(hmat + 84U, 1U);
  hmat[88] = 10U;
  hmat[90] = 20U;
  hmat[92] = 20U;
  hmat[94] = 10U;
  checksum(hmat, sizeof(hmat), 9U);

  table_header(xsdt, "XSDT", sizeof(xsdt));
  put64(xsdt + 36U, (uint64_t)(uintptr_t)madt);
  put64(xsdt + 44U, (uint64_t)(uintptr_t)srat);
  put64(xsdt + 52U, (uint64_t)(uintptr_t)slit);
  put64(xsdt + 60U, (uint64_t)(uintptr_t)hmat);
  checksum(xsdt, sizeof(xsdt), 9U);

  memset(rsdp, 0, sizeof(rsdp));
  memcpy(rsdp, "RSD PTR ", 8U);
  memcpy(rsdp + 9U, "XAIOS ", 6U);
  rsdp[15] = 2U;
  put32(rsdp + 20U, sizeof(rsdp));
  put64(rsdp + 24U, (uint64_t)(uintptr_t)xsdt);
  checksum(rsdp, 20U, 8U);
  checksum(rsdp, sizeof(rsdp), 32U);

  x86_64_acpi_info_t info;
  x86_64_acpi_processor_affinity_t processor0;
  x86_64_acpi_processor_affinity_t processor1;
  x86_64_acpi_memory_affinity_t memory0;
  x86_64_acpi_memory_affinity_t memory1;
  uint32_t first = 0U;
  uint32_t second = 0U;
  uint8_t distance = 0U;
  uint64_t latency = 0U;
  if (!x86_64_acpi_parse((uint64_t)(uintptr_t)rsdp, &info) ||
      info.root_is_xsdt != 1U || info.enabled_cpus != 2U ||
      info.io_apics != 1U || info.processor_affinities != 2U ||
      info.memory_affinities != 2U || info.slit_localities != 2U ||
      info.hmat == 0U || info.hmat_locality_structures != 1U ||
      !x86_64_acpi_cpu_apic_id(&info, 0U, &first) ||
      !x86_64_acpi_cpu_apic_id(&info, 1U, &second) || first != 1U ||
      second != 257U ||
      !x86_64_acpi_processor_affinity_at(&info, 0U, &processor0) ||
      !x86_64_acpi_processor_affinity_at(&info, 1U, &processor1) ||
      processor0.proximity_domain != 0U || processor0.apic_id != 1U ||
      processor0.clock_domain != 11U ||
      processor1.proximity_domain != 1U || processor1.apic_id != 257U ||
      processor1.clock_domain != 22U ||
      !x86_64_acpi_memory_affinity_at(&info, 0U, &memory0) ||
      !x86_64_acpi_memory_affinity_at(&info, 1U, &memory1) ||
      memory0.proximity_domain != 0U || memory0.base != UINT64_C(0x100000) ||
      memory0.length != UINT64_C(0x40000000) ||
      memory1.proximity_domain != 1U ||
      memory1.base != UINT64_C(0x40100000) ||
      memory1.length != UINT64_C(0x40000000) ||
      memory1.hot_pluggable != 1U || memory1.nonvolatile != 1U ||
      !x86_64_acpi_slit_distance(&info, 0U, 1U, &distance) ||
      distance != 20U ||
      !x86_64_acpi_hmat_metric(&info, 0U, 1U, 0U, &latency) ||
      latency != 2000U) {
    return 1;
  }
  madt[9] ^= 1U;
  if (x86_64_acpi_parse((uint64_t)(uintptr_t)rsdp, &info)) return 1;
  puts("x86-acpi: MADT/SRAT/SLIT/HMAT checksums and dynamic CPU IDs passed");
  return 0;
}
