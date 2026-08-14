#ifndef XAIOS_ARCH_RANDOM_H
#define XAIOS_ARCH_RANDOM_H

#include <xaios/status.h>
#include <xaios/types.h>

/* Returns bytes sourced directly from a CPU architectural random instruction.
 * Unsupported CPUs return XAIOS_ERR_UNSUPPORTED without executing it. */
xaios_status_t arch_random_read(void *buffer, uint64_t size);

#endif
