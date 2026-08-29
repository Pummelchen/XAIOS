#ifndef XAIOS_RAM_RESIDENCY_H
#define XAIOS_RAM_RESIDENCY_H

#include <xaios/types.h>

/*
 * The RAM the system itself occupies, budgeted rather than merely spent.
 *
 * XAIOS already runs from memory: every file in /bin -- each application, the
 * C library, every utility -- is copied off the boot medium at start-up,
 * hash-checked, and served from RAM for the rest of the machine's life.
 * Nothing reads an executable off a disk after boot.
 *
 * What this adds is a figure. That residency was an unbounded allocation per
 * file: it worked, and if it ever stopped working the failure would have been
 * a boot that died with "allocation failed" and no sense of how close it had
 * been. A budget makes the amount deliberate, reports it, and grows in steps
 * when a system genuinely needs more rather than either failing at the first
 * shortfall or taking whatever it likes.
 */

/* Start the budget at its first step. Call before anything reserves. */
void ram_residency_init(void);

/* Take `bytes` of resident system memory, growing the budget a step if this
   would exceed it and a step remains. Returns null when the ceiling is
   reached, having said which file asked and how much was already held --
   which is the diagnosis that used to be missing. */
void *ram_residency_alloc(uint64_t bytes, uint64_t align, const char *what);

/* What the system is holding, and out of how much. */
void ram_residency_report(void);

uint64_t ram_residency_bytes(void);

#endif
