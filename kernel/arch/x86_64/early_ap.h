#ifndef XAIOS_X86_64_EARLY_AP_H
#define XAIOS_X86_64_EARLY_AP_H

/* The private seam between kernel/arch/x86_64/early.c and
 * kernel/arch/x86_64/early_ap.c, the module that patches the AP trampoline,
 * runs the C entry every secondary lands in, and starts the application
 * processors.
 *
 * The AP path reads and writes four objects early.c has always owned: the CPU
 * record table (a pointer and a count), the BSP ordinal and the common-worker
 * release flag. They cannot move with the code -- early.c passes their
 * addresses to xaios_x86_early_acpi_prepare_cpu_records(), reads the BSP
 * ordinal through xaios_x86_early_bsp_ordinal() and writes the release flag
 * through xaios_x86_early_set_worker_release() -- so the storage stays in
 * early.c, only its file-scope `static` is dropped, and both files declare the
 * same objects here and reach them through the aliases below, which keep every
 * statement in the moved code spelling them the way it did.
 *
 * start_application_processors is the one function that crosses back:
 * x86_64_kmain calls it, so it is defined once in early_ap.c under the
 * prefixed name and early.c keeps its call site through the alias.
 *
 * Nothing else is visible outside those two translation units. */

#include <xaios/types.h>

#include "early_module.h"

/* Defined in early.c. The storage stays there; these are the same objects the
 * moved AP path used to reach through its own file-scope names. */
extern x86_64_cpu_record_t *xaios_x86_ap_cpu_records;
extern uint32_t xaios_x86_ap_cpu_record_count;
extern uint32_t xaios_x86_ap_bsp_ordinal;
extern volatile uint32_t xaios_x86_ap_worker_release;

/* The spellings early.c and early_ap.c both use. */
#define g_cpu_records xaios_x86_ap_cpu_records
#define g_cpu_record_count xaios_x86_ap_cpu_record_count
#define g_bsp_ordinal xaios_x86_ap_bsp_ordinal
#define g_common_worker_release xaios_x86_ap_worker_release

/* Defined in early_ap.c: patch the trampoline, send every secondary its
 * INIT-SIPI-SIPI, wait for it to come online and then run the legacy
 * IPI-worker self-test. x86_64_kmain calls it at the one point
 * start_application_processors always was. */
void xaios_x86_ap_start_all(uint16_t serial_base,
                            const xaios_boot_info_t *boot);

#define start_application_processors xaios_x86_ap_start_all

#endif
