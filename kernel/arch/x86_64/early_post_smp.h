#ifndef XAIOS_X86_64_EARLY_POST_SMP_H
#define XAIOS_X86_64_EARLY_POST_SMP_H

/* The private seam between kernel/arch/x86_64/early.c and
 * kernel/arch/x86_64/early_post_smp.c. Both files include it, and it declares
 * only the one entry point x86_64_kmain calls after
 * start_application_processors() has returned: the non-common-runtime
 * milestone 48-51 platform-services sequence (or, in the common-runtime
 * configuration, that kernel's own entry) and the halt that ends the boot.
 * The body lives in early_post_smp.c, which defines it exactly once; nothing
 * here is visible outside those two translation units. */

#include <xaios/boot_info.h>
#include <xaios/types.h>

void xaios_x86_early_post_smp_bringup(uint16_t serial_base,
                                      const xaios_boot_info_t *boot);

#endif
