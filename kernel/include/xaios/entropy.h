#ifndef XAIOS_ENTROPY_H
#define XAIOS_ENTROPY_H

#include <xaios/boot_info.h>
#include <xaios/status.h>
#include <xaios/types.h>

/* Initializes the runtime entropy provider. VirtIO RNG is preferred when it
 * is present; a loader seed is used only when supplied by EFI_RNG_PROTOCOL. */
void entropy_init(const xaios_boot_info_t *boot);
xaios_status_t entropy_read(void *buffer, uint64_t size);
void entropy_self_test(void);

#endif
