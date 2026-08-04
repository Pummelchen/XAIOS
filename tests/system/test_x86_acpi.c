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
  uint8_t srat[104];
  uint8_t slit[48];
  uint8_t hmat[36];
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
  srat[64] = 1U;
  srat[65] = 40U;
  put32(srat + 92U, 1U);
  checksum(srat, sizeof(srat), 9U);

  table_header(slit, "SLIT", sizeof(slit));
  put64(slit + 36U, 2U);
  slit[44] = 10U;
  slit[45] = 20U;
  slit[46] = 20U;
  slit[47] = 10U;
  checksum(slit, sizeof(slit), 9U);

  table_header(hmat, "HMAT", sizeof(hmat));
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
  uint32_t first = 0U;
  uint32_t second = 0U;
  if (!x86_64_acpi_parse((uint64_t)(uintptr_t)rsdp, &info) ||
      info.root_is_xsdt != 1U || info.enabled_cpus != 2U ||
      info.io_apics != 1U || info.processor_affinities != 1U ||
      info.memory_affinities != 1U || info.slit_localities != 2U ||
      info.hmat == 0U || !x86_64_acpi_cpu_apic_id(&info, 0U, &first) ||
      !x86_64_acpi_cpu_apic_id(&info, 1U, &second) || first != 1U ||
      second != 257U) {
    return 1;
  }
  madt[9] ^= 1U;
  if (x86_64_acpi_parse((uint64_t)(uintptr_t)rsdp, &info)) return 1;
  puts("x86-acpi: MADT/SRAT/SLIT/HMAT checksums and dynamic CPU IDs passed");
  return 0;
}
