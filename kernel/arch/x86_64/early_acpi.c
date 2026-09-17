/* x86_64 ACPI/MADT parsing and the CPU-record table preparation it feeds.
 *
 * Split out of kernel/arch/x86_64/early.c. Both functions moved verbatim; the
 * only edits are the seam in early_module.h and the out-parameters the record
 * preparation now takes, because early.c keeps owning the record pointer and
 * count that the rest of the file -- the platform hooks, the interrupt entry
 * and the AP bring-up -- reads through.
 *
 * This runs at one well-defined point in x86_64_kmain: after the UEFI memory
 * map is parsed and before the page tables are installed. It touches no AP,
 * no interrupt and no timer, so nothing here can reorder the INIT-SIPI-SIPI
 * path. The ACPI info block is private to this file; early.c never reads it
 * after the parse.
 *
 * early_module.h is the shared seam. It declares the early.c/mem/serial
 * primitives this file must not own; they are aliased below so the moved body
 * is unchanged. */

#include "acpi.h"
#include "early_module.h"

/* early.c's primitives, under the names early_module.h declares. */
#define serial_puts xaios_x86_early_serial_puts
#define serial_dec xaios_x86_early_serial_dec
#define panic_halt xaios_x86_early_panic_halt
#define early_alloc xaios_x86_mem_alloc

/* The parsed ACPI tables live here now. Only the two functions below read
 * them, and both are in this file. */
static x86_64_acpi_info_t g_acpi;

void xaios_x86_early_acpi_parse(uint16_t serial_base,
                                const xaios_boot_info_t *boot) {
  if (!x86_64_acpi_parse(boot->acpi_rsdp, &g_acpi)) {
    panic_halt(serial_base, "ACPI RSDP/root/MADT validation failed");
  }
  serial_puts(serial_base, "x86_64: ACPI root=");
  serial_puts(serial_base, g_acpi.root_is_xsdt != 0U ? "XSDT" : "RSDT");
  serial_puts(serial_base, " enabled_cpus=");
  serial_dec(serial_base, g_acpi.enabled_cpus);
  serial_puts(serial_base, " io_apics=");
  serial_dec(serial_base, g_acpi.io_apics);
  serial_puts(serial_base, " MADT=1 SRAT=");
  serial_dec(serial_base, g_acpi.srat != 0U);
  serial_puts(serial_base, " SLIT=");
  serial_dec(serial_base, g_acpi.slit != 0U);
  serial_puts(serial_base, " HMAT=");
  serial_dec(serial_base, g_acpi.hmat != 0U);
  serial_puts(serial_base, "\n");
  serial_puts(serial_base, "x86_64: NUMA affinity processors=");
  serial_dec(serial_base, g_acpi.processor_affinities);
  serial_puts(serial_base, " memory=");
  serial_dec(serial_base, g_acpi.memory_affinities);
  serial_puts(serial_base, " slit_localities=");
  serial_dec(serial_base, g_acpi.slit_localities);
  serial_puts(serial_base, "\n");
}

/* Fills the caller's record storage from the MADT: allocates it, zeroes it and
 * writes each enabled CPU's APIC id. The pointer and the count are written at
 * the same points, and in the same order, as the file-scope assignments this
 * replaced, so the caller observes the table at exactly the same moment it
 * used to. */
void xaios_x86_early_acpi_prepare_cpu_records(uint16_t serial_base,
                                              x86_64_cpu_record_t **records,
                                              uint32_t *record_count) {
  if (g_acpi.enabled_cpus == 0U) panic_halt(serial_base, "MADT CPU count");
  uint64_t record_bytes =
      (uint64_t)g_acpi.enabled_cpus * sizeof(x86_64_cpu_record_t);
  *records = (x86_64_cpu_record_t *)early_alloc(record_bytes, UINT64_C(64));
  if (*records == 0) panic_halt(serial_base, "AP record allocation");
  *record_count = g_acpi.enabled_cpus;
  for (uint64_t i = 0U; i < record_bytes; ++i) {
    ((uint8_t *)*records)[i] = 0U;
  }
  for (uint32_t i = 0U; i < *record_count; ++i) {
    if (!x86_64_acpi_cpu_apic_id(&g_acpi, i, &(*records)[i].apic_id)) {
      panic_halt(serial_base, "MADT CPU enumeration");
    }
  }
}
