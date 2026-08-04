#include <xaios/partition_device.h>

static uint64_t string_length(const char *value, uint64_t capacity) {
  uint64_t length = 0U;
  if (value == 0) return capacity;
  while (length < capacity && value[length] != '\0') ++length;
  return length;
}

static void bytes_zero(void *buffer, uint64_t length) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0U; i < length; ++i) bytes[i] = 0U;
}

static void string_copy(char *destination, uint64_t capacity,
                        const char *source) {
  uint64_t index = 0U;
  while (index + 1U < capacity && source[index] != '\0') {
    destination[index] = source[index];
    ++index;
  }
  destination[index] = '\0';
}

static xaios_status_t partition_read(void *context, uint64_t offset,
                                     void *buffer, uint64_t length) {
  xaios_partition_device_t *partition =
      (xaios_partition_device_t *)context;
  if (offset > UINT64_MAX - partition->parent_byte_offset) {
    return XAIOS_ERR_INVALID;
  }
  return block_read(partition->parent,
                    partition->parent_byte_offset + offset, buffer, length);
}

static xaios_status_t partition_write(void *context, uint64_t offset,
                                      const void *buffer, uint64_t length) {
  xaios_partition_device_t *partition =
      (xaios_partition_device_t *)context;
  if (offset > UINT64_MAX - partition->parent_byte_offset) {
    return XAIOS_ERR_INVALID;
  }
  return block_write(partition->parent,
                     partition->parent_byte_offset + offset, buffer, length);
}

static xaios_status_t partition_flush(void *context) {
  return block_flush(((xaios_partition_device_t *)context)->parent);
}

static xaios_status_t partition_discard(void *context, uint64_t offset,
                                        uint64_t length) {
  xaios_partition_device_t *partition =
      (xaios_partition_device_t *)context;
  if (offset > UINT64_MAX - partition->parent_byte_offset) {
    return XAIOS_ERR_INVALID;
  }
  return block_discard(partition->parent,
                       partition->parent_byte_offset + offset, length);
}

static xaios_status_t partition_write_zeroes(void *context, uint64_t offset,
                                             uint64_t length) {
  xaios_partition_device_t *partition =
      (xaios_partition_device_t *)context;
  if (offset > UINT64_MAX - partition->parent_byte_offset) {
    return XAIOS_ERR_INVALID;
  }
  return block_write_zeroes(partition->parent,
                            partition->parent_byte_offset + offset, length);
}

static const xaios_block_backend_ops_t k_partition_ops = {
    partition_read, partition_write, partition_flush, partition_discard,
    partition_write_zeroes};

xaios_status_t partition_device_register(
    xaios_partition_device_t *partition, xaios_block_device_t *parent,
    const char *identifier, const xaios_gpt_partition_t *descriptor,
    uint32_t read_only) {
  if (partition == 0 || parent == 0 || identifier == 0 || descriptor == 0 ||
      read_only > 1U || descriptor->first_lba > descriptor->last_lba ||
      string_length(identifier, XAIOS_BLOCK_DEVICE_ID_MAX) == 0U ||
      string_length(identifier, XAIOS_BLOCK_DEVICE_ID_MAX) ==
          XAIOS_BLOCK_DEVICE_ID_MAX ||
      gpt_guid_is_zero(&descriptor->type_guid) ||
      gpt_guid_is_zero(&descriptor->unique_guid)) {
    return XAIOS_ERR_INVALID;
  }
  xaios_block_device_info_t parent_info;
  if (block_device_info(parent, &parent_info) != XAIOS_OK ||
      descriptor->last_lba >= parent_info.capacity_logical_sectors) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t lba_count = descriptor->last_lba - descriptor->first_lba + 1U;
  if (descriptor->first_lba >
          UINT64_MAX / parent_info.logical_sector_size ||
      lba_count > UINT64_MAX / parent_info.logical_sector_size) {
    return XAIOS_ERR_INVALID;
  }
  bytes_zero(partition, sizeof(*partition));
  partition->parent_byte_offset =
      descriptor->first_lba * parent_info.logical_sector_size;
  partition->length_bytes = lba_count * parent_info.logical_sector_size;
  partition->type_guid = descriptor->type_guid;
  partition->unique_guid = descriptor->unique_guid;
  xaios_block_device_t *held_parent = 0;
  if (block_device_open(parent_info.identifier, &held_parent) != XAIOS_OK ||
      held_parent != parent) {
    return XAIOS_ERR_BUSY;
  }
  partition->parent = held_parent;
  partition->parent_held = 1U;

  xaios_block_device_info_t info;
  bytes_zero(&info, sizeof(info));
  string_copy(info.identifier, sizeof(info.identifier), identifier);
  string_copy(info.backend, sizeof(info.backend), "partition");
  info.capacity_bytes = partition->length_bytes;
  info.logical_sector_size = parent_info.logical_sector_size;
  info.capacity_logical_sectors = lba_count;
  info.physical_block_size = parent_info.physical_block_size;
  info.max_transfer_bytes = parent_info.max_transfer_bytes;
  info.read_only = parent_info.read_only != 0U || read_only != 0U;
  info.flush_supported = parent_info.flush_supported;
  info.discard_supported = parent_info.discard_supported;
  info.write_zeroes_supported = parent_info.write_zeroes_supported;
  info.discard_granularity = parent_info.discard_granularity;
  info.max_discard_bytes = parent_info.max_discard_bytes;
  info.max_discard_ranges = parent_info.max_discard_ranges;
  info.max_write_zeroes_bytes = parent_info.max_write_zeroes_bytes;
  if (info.discard_supported != 0U) {
    uint64_t parent_phase =
        partition->parent_byte_offset % info.discard_granularity;
    info.discard_alignment =
        (parent_info.discard_alignment + info.discard_granularity -
         parent_phase) %
        info.discard_granularity;
  }
  xaios_status_t status = block_device_register(
      &partition->block_device, &info, &k_partition_ops, partition);
  if (status != XAIOS_OK) {
    (void)block_device_close(parent);
    partition->parent_held = 0U;
    partition->parent = 0;
  }
  return status;
}

xaios_status_t partition_device_unregister(
    xaios_partition_device_t *partition) {
  if (partition == 0 || partition->parent_held == 0U ||
      partition->parent == 0) {
    return XAIOS_ERR_INVALID;
  }
  xaios_status_t status = block_device_unregister(&partition->block_device);
  if (status != XAIOS_OK) return status;
  status = block_device_close(partition->parent);
  if (status == XAIOS_OK) {
    partition->parent_held = 0U;
    partition->parent = 0;
  }
  return status;
}
