#ifndef XAIOS_AHCI_H
#define XAIOS_AHCI_H

#include <xaios/status.h>

/* Capability-gated SATA AHCI discovery. On Fusion ARM64 this provides the
 * writable disk consumed by MutableFS; absence is a normal platform result. */
xaios_status_t ahci_init(void);

#endif
