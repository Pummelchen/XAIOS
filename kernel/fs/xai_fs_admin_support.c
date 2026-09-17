#include "xai_fs_admin_internal.h"

#include <string.h>

extern int xaios_ed25519_verify(const uint8_t signature[64],
                                const uint8_t *message,
                                uint32_t message_len,
                                const uint8_t public_key[32]);

model_admin_io_t xai_fs_admin_io;

static void bytes_zero(void *buffer, uint64_t length) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t index = 0U; index < length; ++index) bytes[index] = 0U;
}

xaios_engine_status_t xai_fs_admin_verify_signature(
    void *context, const uint8_t public_key[32], const uint8_t signature[64],
    const uint8_t message[32]) {
  (void)context;
  return xaios_ed25519_verify(signature, message, 32U, public_key) == 0
             ? XAIOS_ENGINE_OK
             : XAIOS_ENGINE_ERR_CHECKSUM;
}

xaios_status_t xai_fs_admin_map_engine_status(xaios_engine_status_t status) {
  if (status == XAIOS_ENGINE_OK) return XAIOS_OK;
  if (status == XAIOS_ENGINE_ERR_IO || status == XAIOS_ENGINE_ERR_CHECKSUM) {
    return XAIOS_ERR_IO;
  }
  if (status == XAIOS_ENGINE_ERR_UNSUPPORTED ||
      status == XAIOS_ENGINE_ERR_CAPABILITY) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  return XAIOS_ERR_INVALID;
}

xaios_engine_status_t xai_fs_admin_read_at(void *context, uint64_t offset,
                                           void *destination, size_t length) {
  model_admin_io_t *io = (model_admin_io_t *)context;
  uint64_t sector_size = io->info.logical_sector_size;
  if (destination == 0 || length == 0U || sector_size == 0U ||
      sector_size > sizeof(io->bounce) || offset > UINT64_MAX - length ||
      offset + length > io->info.capacity_bytes) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  uint8_t *output = (uint8_t *)destination;
  uint64_t remaining = (uint64_t)length;
  while (remaining != 0U) {
    uint64_t within = offset % sector_size;
    if (within == 0U && remaining >= sector_size) {
      uint64_t count = remaining;
      if (io->info.max_transfer_bytes != 0U &&
          count > io->info.max_transfer_bytes) {
        count = io->info.max_transfer_bytes;
      }
      count -= count % sector_size;
      if (block_read(io->device, offset, output, count) != XAIOS_OK) {
        return XAIOS_ENGINE_ERR_IO;
      }
      offset += count;
      output += count;
      remaining -= count;
    } else {
      uint64_t sector_offset = offset - within;
      if (block_read(io->device, sector_offset, io->bounce, sector_size) !=
          XAIOS_OK) {
        return XAIOS_ENGINE_ERR_IO;
      }
      uint64_t count = sector_size - within;
      if (count > remaining) count = remaining;
      memcpy(output, io->bounce + within, count);
      offset += count;
      output += count;
      remaining -= count;
    }
  }
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xai_fs_admin_write_at(void *context, uint64_t offset,
                                            const void *source,
                                            size_t length) {
  model_admin_io_t *io = (model_admin_io_t *)context;
  uint64_t sector_size = io->info.logical_sector_size;
  if (source == 0 || length == 0U || sector_size == 0U ||
      sector_size > sizeof(io->bounce) || offset > UINT64_MAX - length ||
      offset + length > io->info.capacity_bytes) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  const uint8_t *input = (const uint8_t *)source;
  uint64_t remaining = (uint64_t)length;
  while (remaining != 0U) {
    uint64_t within = offset % sector_size;
    if (within == 0U && remaining >= sector_size) {
      uint64_t count = remaining;
      if (io->info.max_transfer_bytes != 0U &&
          count > io->info.max_transfer_bytes) {
        count = io->info.max_transfer_bytes;
      }
      count -= count % sector_size;
      if (block_write(io->device, offset, input, count) != XAIOS_OK) {
        return XAIOS_ENGINE_ERR_IO;
      }
      offset += count;
      input += count;
      remaining -= count;
    } else {
      uint64_t sector_offset = offset - within;
      if (block_read(io->device, sector_offset, io->bounce, sector_size) !=
          XAIOS_OK) {
        return XAIOS_ENGINE_ERR_IO;
      }
      uint64_t count = sector_size - within;
      if (count > remaining) count = remaining;
      memcpy(io->bounce + within, input, count);
      if (block_write(io->device, sector_offset, io->bounce, sector_size) !=
          XAIOS_OK) {
        return XAIOS_ENGINE_ERR_IO;
      }
      offset += count;
      input += count;
      remaining -= count;
    }
  }
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xai_fs_admin_flush(void *context) {
  model_admin_io_t *io = (model_admin_io_t *)context;
  return block_flush(io->device) == XAIOS_OK ? XAIOS_ENGINE_OK
                                              : XAIOS_ENGINE_ERR_IO;
}

xaios_status_t xai_fs_admin_confirmation_matches(
    const char *confirmation, const char *expected) {
  xaios_guid_t supplied;
  xaios_guid_t target;
  return gpt_guid_parse(confirmation, &supplied) == XAIOS_OK &&
                 gpt_guid_parse(expected, &target) == XAIOS_OK &&
                 gpt_guid_equal(&supplied, &target)
             ? XAIOS_OK
             : XAIOS_ERR_INVALID;
}

void xai_fs_admin_derive_volume_uuid(const char *partition_uuid,
                                     uint8_t volume_uuid[16]) {
  static const uint8_t domain[16] = {
      0x58U, 0x41U, 0x49U, 0x4fU, 0x53U, 0x2dU, 0x4dU, 0x4fU,
      0x44U, 0x45U, 0x4cU, 0x46U, 0x53U, 0x2dU, 0x31U, 0x00U};
  xaios_guid_t partition;
  (void)gpt_guid_parse(partition_uuid, &partition);
  for (uint32_t index = 0U; index < 16U; ++index) {
    volume_uuid[index] = partition.bytes[index] ^ domain[index];
  }
  volume_uuid[6] = (uint8_t)((volume_uuid[6] & 0x0fU) | 0x50U);
  volume_uuid[8] = (uint8_t)((volume_uuid[8] & 0x3fU) | 0x80U);
}

xaios_status_t xai_fs_admin_open_partition_into(
    model_admin_io_t *io, const char *identifier, uint32_t require_idle,
    uint32_t require_writable, xaios_storage_partition_record_t *partition) {
  if (io == 0) return XAIOS_ERR_INVALID;
  bytes_zero(io, sizeof(*io));
  xaios_status_t status = storage_admin_partition_open(
      identifier, XAIOS_STORAGE_PARTITION_MODEL, require_idle,
      &io->device, partition);
  if (status != XAIOS_OK) return status;
  status = block_device_info(io->device, &io->info);
  if (status != XAIOS_OK ||
      io->info.logical_sector_size > sizeof(io->bounce) ||
      (require_writable != 0U &&
       (io->info.read_only != 0U || io->info.flush_supported == 0U))) {
    (void)storage_admin_partition_close(io->device);
    bytes_zero(io, sizeof(*io));
    return status != XAIOS_OK ? status : XAIOS_ERR_UNSUPPORTED;
  }
  return XAIOS_OK;
}

xaios_status_t xai_fs_admin_open_partition(
    const char *identifier, uint32_t require_idle,
    xaios_storage_partition_record_t *partition) {
  return xai_fs_admin_open_partition_into(&xai_fs_admin_io, identifier,
                                          require_idle, 1U, partition);
}

void xai_fs_admin_close_partition_io(model_admin_io_t *io) {
  if (io != 0 && io->device != 0) {
    (void)storage_admin_partition_close(io->device);
  }
  if (io != 0) bytes_zero(io, sizeof(*io));
}

void xai_fs_admin_close_partition(void) {
  xai_fs_admin_close_partition_io(&xai_fs_admin_io);
}

void xai_fs_admin_hex_id(const uint8_t id[32], char output[65]) {
  static const char digits[] = "0123456789abcdef";
  for (uint32_t index = 0U; index < 32U; ++index) {
    output[index * 2U] = digits[id[index] >> 4U];
    output[index * 2U + 1U] = digits[id[index] & 0x0fU];
  }
  output[64] = '\0';
}

void xai_fs_admin_fill_base_report(
    const xaios_storage_partition_record_t *partition,
    xaios_xai_fs_admin_report_t *report) {
  bytes_zero(report, sizeof(*report));
  memcpy(report->target, partition->identifier, sizeof(report->target));
  memcpy(report->partition_uuid, partition->unique_guid,
         sizeof(report->partition_uuid));
  report->partition_bytes = xai_fs_admin_io.info.capacity_bytes;
  report->discard_supported = xai_fs_admin_io.info.discard_supported;
  report->bad_logical_offset = UINT64_MAX;
}

xaios_status_t xai_fs_admin_fill_volume_report(
    const xaios_storage_partition_record_t *partition,
    const xaios_xai_fs_t *volume, const xaios_xai_fs_probe_t *probe,
    xaios_xai_fs_admin_report_t *report) {
  xai_fs_admin_fill_base_report(partition, report);
  xaios_guid_t volume_guid;
  memcpy(volume_guid.bytes, volume->volume_uuid, sizeof(volume_guid.bytes));
  if (gpt_guid_format(&volume_guid, report->volume_uuid) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  report->volume_bytes = volume->volume_size;
  report->allocated_bytes = volume->data_tail;
  report->free_bytes = volume->volume_size - volume->data_tail;
  report->chunk_size = volume->chunk_size;
  report->generation = volume->generation;
  report->package_count = volume->package_count;
  report->first_superblock_valid = probe->first_valid;
  report->second_superblock_valid = probe->second_valid;
  report->copies_compatible = probe->copies_compatible;
  for (uint64_t index = 0U; index < volume->package_count; ++index) {
    xaios_xai_fs_package_t package;
    xaios_engine_status_t status =
        xaios_xai_fs_read_package(volume, index, &package);
    if (status != XAIOS_ENGINE_OK)
      return xai_fs_admin_map_engine_status(status);
    if (package.state == XAIOS_XAI_FS_PACKAGE_ACTIVE) {
      ++report->active_packages;
    } else if (package.state == XAIOS_XAI_FS_PACKAGE_STAGING) {
      ++report->staging_packages;
    } else if (package.state == XAIOS_XAI_FS_PACKAGE_QUARANTINED) {
      ++report->quarantined_packages;
    }
  }
  return XAIOS_OK;
}

xaios_status_t xai_fs_admin_open_volume_into(model_admin_io_t *io,
                                             xaios_xai_fs_t *volume,
                                             xaios_xai_fs_probe_t *probe) {
  if (io == 0 || volume == 0 || probe == 0) return XAIOS_ERR_INVALID;
  xaios_xai_fs_reader_t reader = {
      io, xai_fs_admin_read_at, io->info.capacity_bytes};
  xaios_engine_status_t status = xaios_xai_fs_probe(
      &reader, io->scratch, sizeof(io->scratch), probe);
  if (status != XAIOS_ENGINE_OK)
    return xai_fs_admin_map_engine_status(status);
  status = xaios_xai_fs_open(&reader, xai_fs_admin_verify_signature, 0,
                             io->scratch, sizeof(io->scratch), volume);
  return xai_fs_admin_map_engine_status(status);
}

xaios_status_t xai_fs_admin_open_volume(xaios_xai_fs_t *volume,
                                        xaios_xai_fs_probe_t *probe) {
  return xai_fs_admin_open_volume_into(&xai_fs_admin_io, volume, probe);
}

int xai_fs_admin_parse_package_id(const char *text, uint8_t package_id[32]) {
  if (text == 0 || package_id == 0) return 0;
  for (uint32_t index = 0U; index < 32U; ++index) {
    uint8_t high = (uint8_t)text[index * 2U];
    uint8_t low = (uint8_t)text[index * 2U + 1U];
    uint8_t value = 0U;
    if (high >= '0' && high <= '9') {
      value = (uint8_t)(high - '0');
    } else if (high >= 'a' && high <= 'f') {
      value = (uint8_t)(high - 'a' + 10U);
    } else if (high >= 'A' && high <= 'F') {
      value = (uint8_t)(high - 'A' + 10U);
    } else {
      return 0;
    }
    value = (uint8_t)(value << 4U);
    if (low >= '0' && low <= '9') {
      value |= (uint8_t)(low - '0');
    } else if (low >= 'a' && low <= 'f') {
      value |= (uint8_t)(low - 'a' + 10U);
    } else if (low >= 'A' && low <= 'F') {
      value |= (uint8_t)(low - 'A' + 10U);
    } else {
      return 0;
    }
    package_id[index] = value;
  }
  return text[64] == '\0';
}

xaios_status_t xai_fs_admin_find_package(const xaios_xai_fs_t *volume,
                                         const uint8_t package_id[32],
                                         xaios_xai_fs_package_t *package) {
  if (volume == 0 || package_id == 0 || package == 0) return XAIOS_ERR_INVALID;
  for (uint64_t index = 0U; index < volume->package_count; ++index) {
    xaios_engine_status_t status =
        xaios_xai_fs_read_package(volume, index, package);
    if (status != XAIOS_ENGINE_OK)
      return xai_fs_admin_map_engine_status(status);
    if (memcmp(package->package_id, package_id, 32U) == 0) return XAIOS_OK;
  }
  return XAIOS_ERR_NOT_FOUND;
}
