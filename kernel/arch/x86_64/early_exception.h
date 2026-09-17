#ifndef XAIOS_X86_64_EARLY_EXCEPTION_H
#define XAIOS_X86_64_EARLY_EXCEPTION_H

/* The private seam between kernel/arch/x86_64/early.c and
 * kernel/arch/x86_64/early_exception.c. Both files include it and nothing in
 * it is visible outside those two translation units.
 *
 * The trap frame is not restated here: it stays in early_module.h, which this
 * header includes so that file remains its single definition. What is declared
 * here is the pair of entry points the moved body defines -- the C half of the
 * trap entry entry.S calls by its exact name, and the controlled round-trip
 * x86_64_kmain calls once -- each defined exactly once, in early_exception.c. */

#include <xaios/types.h>

#include "early_module.h"

/* Defined in early_exception.c. entry.S calls the first by this exact name;
 * early.c's x86_64_kmain calls the second through the alias it defines where
 * the old definition used to be. */
uint64_t x86_64_exception_entry(const x86_64_exception_frame_t *frame);
void xaios_x86_early_exception_round_trip(uint16_t serial_base);

#endif
