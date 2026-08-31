#ifndef XAIOS_RAM_BLOCK_H
#define XAIOS_RAM_BLOCK_H

#include <xaios/block_device.h>
#include <xaios/status.h>

/* Register a block device backed by memory under `identifier`.

   For a machine with no disk to keep state on. Everything above the block
   layer then works as it does on a real volume, and the one difference --
   that none of it survives the power going off -- stays the only one. */
xaios_status_t ram_block_create(const char *identifier);

int ram_block_present(void);

#endif
