#ifndef XAIOS_PARTITION_DEVICE_H
#define XAIOS_PARTITION_DEVICE_H

#include <xaios/block_device.h>
#include <xaios/gpt.h>

typedef struct xaios_partition_device {
  xaios_block_device_t block_device;
  xaios_block_device_t *parent;
  uint64_t parent_byte_offset;
  uint64_t length_bytes;
  xaios_guid_t type_guid;
  xaios_guid_t unique_guid;
  uint32_t parent_held;
} xaios_partition_device_t;

xaios_status_t partition_device_register(
    xaios_partition_device_t *partition, xaios_block_device_t *parent,
    const char *identifier, const xaios_gpt_partition_t *descriptor,
    uint32_t read_only);
xaios_status_t partition_device_unregister(
    xaios_partition_device_t *partition);

#endif
