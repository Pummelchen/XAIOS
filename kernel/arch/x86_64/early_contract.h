#ifndef XAIOS_X86_64_EARLY_CONTRACT_H
#define XAIOS_X86_64_EARLY_CONTRACT_H

/* The private seam between kernel/arch/x86_64/early.c and
 * kernel/arch/x86_64/early_contract.c. Both files include it, and it declares
 * only the two report entry points x86_64_kmain calls at the very end of the
 * non-common-runtime x86_64 bring-up path:
 * xaios_x86_early_validate_os_contract() and
 * xaios_x86_early_validate_hardware_gate(). Their report state and their
 * bodies live in early_contract.c, which defines each exactly once; nothing
 * here is visible outside those two translation units. */

#include <xaios/types.h>

void xaios_x86_early_validate_os_contract(uint16_t serial_base);
void xaios_x86_early_validate_hardware_gate(uint16_t serial_base);

#endif
