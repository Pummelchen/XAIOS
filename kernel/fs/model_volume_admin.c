#include <xaios/model_volume_admin.h>

#include <xaios/gpt.h>

#include <xaios_engine/model_volume.h>

#include <string.h>

#define MODEL_ADMIN_SCRATCH_SIZE UINT64_C(65536)
#define MODEL_ADMIN_MAX_SECTOR_SIZE UINT64_C(4096)
#define MODEL_ADMIN_DEFAULT_CHUNK_SIZE UINT64_C(4194304)

typedef struct model_admin_io {
  xaios_block_device_t *device;
  xaios_block_device_info_t info;
  uint8_t bounce[MODEL_ADMIN_MAX_SECTOR_SIZE];
  uint8_t scratch[MODEL_ADMIN_SCRATCH_SIZE];
} model_admin_io_t;

static model_admin_io_t g_admin_io;

extern int xaios_ed25519_verify(const uint8_t signature[64],
                                const uint8_t *message,
                                uint32_t message_len,
                                const uint8_t public_key[32]);

static void bytes_zero(void *buffer, uint64_t length) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t index = 0U; index < length; ++index) bytes[index] = 0U;
}

static xaios_engine_status_t verify_signature(
    void *context, const uint8_t public_key[32], const uint8_t signature[64],
    const uint8_t message[32]) {
  (void)context;
  return xaios_ed25519_verify(signature, message, 32U, public_key) == 0
             ? XAIOS_ENGINE_OK
             : XAIOS_ENGINE_ERR_CHECKSUM;
}

static xaios_status_t map_engine_status(xaios_engine_status_t status) {
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

static xaios_engine_status_t read_at(void *context, uint64_t offset,
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

static xaios_engine_status_t write_at(void *context, uint64_t offset,
                                      const void *source, size_t length) {
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

static xaios_engine_status_t flush(void *context) {
  model_admin_io_t *io = (model_admin_io_t *)context;
  return block_flush(io->device) == XAIOS_OK ? XAIOS_ENGINE_OK
                                              : XAIOS_ENGINE_ERR_IO;
}

static xaios_status_t confirmation_matches(
    const char *confirmation, const char *expected) {
  xaios_guid_t supplied;
  xaios_guid_t target;
  return gpt_guid_parse(confirmation, &supplied) == XAIOS_OK &&
                 gpt_guid_parse(expected, &target) == XAIOS_OK &&
                 gpt_guid_equal(&supplied, &target)
             ? XAIOS_OK
             : XAIOS_ERR_INVALID;
}

static void derive_volume_uuid(const char *partition_uuid,
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

static xaios_status_t open_partition_into(
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

static xaios_status_t open_partition(
    const char *identifier, uint32_t require_idle,
    xaios_storage_partition_record_t *partition) {
  return open_partition_into(&g_admin_io, identifier, require_idle, 1U,
                             partition);
}

static void close_partition_io(model_admin_io_t *io) {
  if (io != 0 && io->device != 0) {
    (void)storage_admin_partition_close(io->device);
  }
  if (io != 0) bytes_zero(io, sizeof(*io));
}

static void close_partition(void) {
  close_partition_io(&g_admin_io);
}

static void hex_id(const uint8_t id[32], char output[65]) {
  static const char digits[] = "0123456789abcdef";
  for (uint32_t index = 0U; index < 32U; ++index) {
    output[index * 2U] = digits[id[index] >> 4U];
    output[index * 2U + 1U] = digits[id[index] & 0x0fU];
  }
  output[64] = '\0';
}

static void fill_base_report(
    const xaios_storage_partition_record_t *partition,
    xaios_model_volume_admin_report_t *report) {
  bytes_zero(report, sizeof(*report));
  memcpy(report->target, partition->identifier, sizeof(report->target));
  memcpy(report->partition_uuid, partition->unique_guid,
         sizeof(report->partition_uuid));
  report->partition_bytes = g_admin_io.info.capacity_bytes;
  report->discard_supported = g_admin_io.info.discard_supported;
  report->bad_logical_offset = UINT64_MAX;
}

static xaios_status_t fill_volume_report(
    const xaios_storage_partition_record_t *partition,
    const xaios_model_volume_t *volume,
    const xaios_model_volume_probe_t *probe,
    xaios_model_volume_admin_report_t *report) {
  fill_base_report(partition, report);
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
    xaios_model_volume_package_t package;
    xaios_engine_status_t status =
        xaios_model_volume_read_package(volume, index, &package);
    if (status != XAIOS_ENGINE_OK) return map_engine_status(status);
    if (package.state == XAIOS_MODEL_VOLUME_PACKAGE_ACTIVE) {
      ++report->active_packages;
    } else if (package.state == XAIOS_MODEL_VOLUME_PACKAGE_STAGING) {
      ++report->staging_packages;
    } else if (package.state == XAIOS_MODEL_VOLUME_PACKAGE_QUARANTINED) {
      ++report->quarantined_packages;
    }
  }
  return XAIOS_OK;
}

static xaios_status_t open_volume_into(model_admin_io_t *io,
                                       xaios_model_volume_t *volume,
                                       xaios_model_volume_probe_t *probe) {
  if (io == 0 || volume == 0 || probe == 0) return XAIOS_ERR_INVALID;
  xaios_model_volume_reader_t reader = {
      io, read_at, io->info.capacity_bytes};
  xaios_engine_status_t status = xaios_model_volume_probe(
      &reader, io->scratch, sizeof(io->scratch), probe);
  if (status != XAIOS_ENGINE_OK) return map_engine_status(status);
  status = xaios_model_volume_open(
      &reader, verify_signature, 0, io->scratch, sizeof(io->scratch), volume);
  return map_engine_status(status);
}

static xaios_status_t open_volume(xaios_model_volume_t *volume,
                                  xaios_model_volume_probe_t *probe) {
  return open_volume_into(&g_admin_io, volume, probe);
}

static int parse_package_id(const char *text, uint8_t package_id[32]) {
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

static xaios_status_t find_package(
    const xaios_model_volume_t *volume, const uint8_t package_id[32],
    xaios_model_volume_package_t *package) {
  if (volume == 0 || package_id == 0 || package == 0) return XAIOS_ERR_INVALID;
  for (uint64_t index = 0U; index < volume->package_count; ++index) {
    xaios_engine_status_t status =
        xaios_model_volume_read_package(volume, index, package);
    if (status != XAIOS_ENGINE_OK) return map_engine_status(status);
    if (memcmp(package->package_id, package_id, 32U) == 0) return XAIOS_OK;
  }
  return XAIOS_ERR_NOT_FOUND;
}

xaios_status_t model_volume_admin_format_plan(
    const char *partition_identifier, uint64_t chunk_size,
    xaios_model_volume_admin_report_t *report) {
  if (report == 0) return XAIOS_ERR_INVALID;
  if (chunk_size == 0U) chunk_size = MODEL_ADMIN_DEFAULT_CHUNK_SIZE;
  xaios_storage_partition_record_t partition;
  xaios_status_t status = open_partition(partition_identifier, 1U, &partition);
  if (status != XAIOS_OK) return status;
  fill_base_report(&partition, report);
  report->chunk_size = chunk_size;
  report->volume_bytes = g_admin_io.info.capacity_bytes;
  report->allocated_bytes = XAIOS_MODEL_VOLUME_DATA_START;
  report->free_bytes = report->volume_bytes > report->allocated_bytes
                           ? report->volume_bytes - report->allocated_bytes
                           : 0U;
  report->generation = 1U;
  report->dry_run = 1U;
  uint8_t uuid[16];
  derive_volume_uuid(partition.unique_guid, uuid);
  xaios_guid_t guid;
  memcpy(guid.bytes, uuid, sizeof(guid.bytes));
  if (gpt_guid_format(&guid, report->volume_uuid) != XAIOS_OK ||
      chunk_size < UINT64_C(2097152) || chunk_size > UINT64_C(16777216) ||
      (chunk_size & (chunk_size - 1U)) != 0U ||
      chunk_size > report->volume_bytes / 4U) {
    status = XAIOS_ERR_INVALID;
  }
  xaios_model_volume_t existing;
  xaios_model_volume_probe_t probe;
  if (status == XAIOS_OK && open_volume(&existing, &probe) == XAIOS_OK &&
      existing.package_count != 0U) {
    status = XAIOS_ERR_BUSY;
  }
  close_partition();
  return status;
}

xaios_status_t model_volume_admin_format(
    const char *partition_identifier, const char *partition_confirmation,
    uint64_t chunk_size, xaios_model_volume_admin_report_t *report) {
  xaios_model_volume_admin_report_t plan;
  xaios_status_t status = model_volume_admin_format_plan(
      partition_identifier, chunk_size, &plan);
  if (status != XAIOS_OK ||
      confirmation_matches(partition_confirmation, plan.partition_uuid) !=
          XAIOS_OK) {
    return status != XAIOS_OK ? status : XAIOS_ERR_INVALID;
  }
  xaios_storage_partition_record_t partition;
  status = open_partition(partition_identifier, 1U, &partition);
  if (status != XAIOS_OK) return status;
  if (confirmation_matches(partition_confirmation, partition.unique_guid) !=
      XAIOS_OK) {
    close_partition();
    return XAIOS_ERR_BUSY;
  }
  if (chunk_size == 0U) chunk_size = MODEL_ADMIN_DEFAULT_CHUNK_SIZE;
  uint8_t volume_uuid[16];
  derive_volume_uuid(partition.unique_guid, volume_uuid);
  xaios_model_volume_writer_t writer = {&g_admin_io, write_at, flush};
  status = map_engine_status(xaios_model_volume_format(
      &writer, g_admin_io.info.capacity_bytes, chunk_size, volume_uuid,
      g_admin_io.scratch, sizeof(g_admin_io.scratch)));
  if (status == XAIOS_OK) {
    xaios_model_volume_t volume;
    xaios_model_volume_probe_t probe;
    status = open_volume(&volume, &probe);
    if (status == XAIOS_OK &&
        (probe.first_valid == 0U || probe.second_valid == 0U ||
         probe.copies_compatible == 0U || volume.package_count != 0U)) {
      status = XAIOS_ERR_IO;
    }
    if (status == XAIOS_OK && report != 0) {
      status = fill_volume_report(&partition, &volume, &probe, report);
      if (status == XAIOS_OK) {
        report->check_state = XAIOS_MODEL_VOLUME_CHECK_CLEAN;
        report->dry_run = 0U;
      }
    }
  }
  close_partition();
  return status;
}

xaios_status_t model_volume_admin_fsck(
    const char *partition_identifier, uint32_t verify_data,
    xaios_model_volume_admin_report_t *report) {
  if (report == 0 || verify_data > 1U) return XAIOS_ERR_INVALID;
  xaios_storage_partition_record_t partition;
  xaios_status_t status = open_partition(partition_identifier, 1U, &partition);
  if (status != XAIOS_OK) return status;
  fill_base_report(&partition, report);
  xaios_model_volume_reader_t reader = {
      &g_admin_io, read_at, g_admin_io.info.capacity_bytes};
  xaios_model_volume_probe_t probe;
  xaios_engine_status_t engine_status = xaios_model_volume_probe(
      &reader, g_admin_io.scratch, sizeof(g_admin_io.scratch), &probe);
  if (engine_status != XAIOS_ENGINE_OK) {
    report->check_state = XAIOS_MODEL_VOLUME_CHECK_CORRUPT_UNREPAIRABLE;
    close_partition();
    return XAIOS_OK;
  }
  xaios_model_volume_t volume;
  engine_status = xaios_model_volume_open(
      &reader, verify_signature, 0, g_admin_io.scratch,
      sizeof(g_admin_io.scratch), &volume);
  if (engine_status != XAIOS_ENGINE_OK ||
      fill_volume_report(&partition, &volume, &probe, report) != XAIOS_OK) {
    report->check_state = XAIOS_MODEL_VOLUME_CHECK_CORRUPT_UNREPAIRABLE;
    close_partition();
    return XAIOS_OK;
  }
  report->check_state =
      probe.first_valid != 0U && probe.second_valid != 0U &&
              probe.copies_compatible != 0U
          ? XAIOS_MODEL_VOLUME_CHECK_CLEAN
          : XAIOS_MODEL_VOLUME_CHECK_REPAIRABLE;
  if (verify_data != 0U) {
    for (uint64_t index = 0U; index < volume.package_count; ++index) {
      xaios_model_volume_package_t package;
      engine_status = xaios_model_volume_read_package(&volume, index, &package);
      if (engine_status != XAIOS_ENGINE_OK) {
        report->check_state = XAIOS_MODEL_VOLUME_CHECK_CORRUPT_UNREPAIRABLE;
        break;
      }
      if (package.state == XAIOS_MODEL_VOLUME_PACKAGE_STAGING) {
        uint32_t complete = 1U;
        for (uint64_t relative = 0U; relative < package.chunk_count;
             ++relative) {
          xaios_model_volume_chunk_t chunk;
          engine_status = xaios_model_volume_read_chunk(
              &volume, package.chunk_start + relative, &chunk);
          if (engine_status != XAIOS_ENGINE_OK ||
              (chunk.flags & XAIOS_MODEL_VOLUME_CHUNK_COMPLETE) == 0U) {
            complete = 0U;
            break;
          }
        }
        if (complete == 0U) continue;
      }
      uint64_t bad_offset = UINT64_MAX;
      engine_status = xaios_model_volume_verify_package(
          &volume, &package, g_admin_io.scratch, sizeof(g_admin_io.scratch),
          &bad_offset);
      if (engine_status != XAIOS_ENGINE_OK) {
        report->check_state = XAIOS_MODEL_VOLUME_CHECK_CORRUPT_UNREPAIRABLE;
        report->bad_logical_offset = bad_offset;
        hex_id(package.package_id, report->bad_package_id);
        break;
      }
      if (report->checked_bytes > UINT64_MAX - package.logical_size) {
        report->check_state = XAIOS_MODEL_VOLUME_CHECK_CORRUPT_UNREPAIRABLE;
        break;
      }
      report->checked_bytes += package.logical_size;
    }
  }
  close_partition();
  return XAIOS_OK;
}

xaios_status_t model_volume_admin_repair(
    const char *partition_identifier, const char *partition_confirmation,
    xaios_model_volume_admin_report_t *report) {
  if (report == 0) return XAIOS_ERR_INVALID;
  xaios_storage_partition_record_t partition;
  xaios_status_t status = open_partition(partition_identifier, 1U, &partition);
  if (status != XAIOS_OK) return status;
  if (confirmation_matches(partition_confirmation, partition.unique_guid) !=
      XAIOS_OK) {
    close_partition();
    return XAIOS_ERR_INVALID;
  }
  xaios_model_volume_t volume;
  xaios_model_volume_probe_t probe;
  status = open_volume(&volume, &probe);
  if (status != XAIOS_OK || probe.first_valid == probe.second_valid) {
    close_partition();
    return status != XAIOS_OK ? status : XAIOS_ERR_UNSUPPORTED;
  }
  xaios_model_volume_writer_t writer = {&g_admin_io, write_at, flush};
  status = map_engine_status(xaios_model_volume_repair_superblock(
      &volume, &writer, g_admin_io.scratch, sizeof(g_admin_io.scratch)));
  if (status == XAIOS_OK) {
    status = open_volume(&volume, &probe);
  }
  if (status == XAIOS_OK &&
      (probe.first_valid == 0U || probe.second_valid == 0U ||
       probe.copies_compatible == 0U)) {
    status = XAIOS_ERR_IO;
  }
  if (status == XAIOS_OK) {
    status = fill_volume_report(&partition, &volume, &probe, report);
    if (status == XAIOS_OK) {
      report->check_state = XAIOS_MODEL_VOLUME_CHECK_REPAIRED;
    }
  }
  close_partition();
  return status;
}

xaios_status_t model_volume_admin_repair_from_replica(
    const char *target_identifier, const char *target_confirmation,
    const char *replica_identifier, const char *package_id,
    xaios_model_volume_admin_report_t *report) {
  if (report == 0 || target_identifier == 0 || replica_identifier == 0 ||
      package_id == 0 || strcmp(target_identifier, replica_identifier) == 0) {
    return XAIOS_ERR_INVALID;
  }
  uint8_t requested_package_id[32];
  if (!parse_package_id(package_id, requested_package_id)) {
    return XAIOS_ERR_INVALID;
  }

  xaios_storage_partition_record_t target_partition;
  xaios_status_t status =
      open_partition(target_identifier, 1U, &target_partition);
  if (status != XAIOS_OK) return status;
  if (confirmation_matches(target_confirmation, target_partition.unique_guid) !=
      XAIOS_OK) {
    close_partition();
    return XAIOS_ERR_INVALID;
  }

  model_admin_io_t replica_io;
  xaios_storage_partition_record_t replica_partition;
  status = open_partition_into(&replica_io, replica_identifier, 1U, 0U,
                               &replica_partition);
  if (status != XAIOS_OK) {
    close_partition();
    return status;
  }
  if (strcmp(target_partition.unique_guid, replica_partition.unique_guid) ==
      0) {
    close_partition_io(&replica_io);
    close_partition();
    return XAIOS_ERR_INVALID;
  }

  xaios_model_volume_t target;
  xaios_model_volume_t replica;
  xaios_model_volume_probe_t target_probe;
  xaios_model_volume_probe_t replica_probe;
  status = open_volume(&target, &target_probe);
  if (status == XAIOS_OK) {
    status = open_volume_into(&replica_io, &replica, &replica_probe);
  }
  xaios_model_volume_package_t target_package;
  xaios_model_volume_package_t replica_package;
  if (status == XAIOS_OK) {
    status = find_package(&target, requested_package_id, &target_package);
  }
  if (status == XAIOS_OK) {
    status = find_package(&replica, requested_package_id, &replica_package);
  }
  if (status == XAIOS_OK) {
    xaios_model_volume_writer_t writer = {&g_admin_io, write_at, flush};
    uint64_t copied = 0U;
    status = map_engine_status(xaios_model_volume_repair_from_replica(
        &target, &target_package, &replica, &replica_package, &writer,
        g_admin_io.scratch, sizeof(g_admin_io.scratch), &copied));
    if (status == XAIOS_OK) {
      status = open_volume(&target, &target_probe);
    }
    if (status == XAIOS_OK) {
      status = fill_volume_report(&target_partition, &target, &target_probe,
                                  report);
    }
    if (status == XAIOS_OK) {
      report->checked_bytes = copied;
      report->check_state = XAIOS_MODEL_VOLUME_CHECK_REPAIRED;
    }
  }
  close_partition_io(&replica_io);
  close_partition();
  return status;
}

xaios_status_t model_volume_admin_grow(
    const char *partition_identifier, const char *partition_confirmation,
    uint64_t new_size, xaios_model_volume_admin_report_t *report) {
  if (report == 0) return XAIOS_ERR_INVALID;
  xaios_storage_partition_record_t partition;
  xaios_status_t status = open_partition(partition_identifier, 1U, &partition);
  if (status != XAIOS_OK) return status;
  if (confirmation_matches(partition_confirmation, partition.unique_guid) !=
      XAIOS_OK) {
    close_partition();
    return XAIOS_ERR_INVALID;
  }
  xaios_model_volume_t volume;
  xaios_model_volume_probe_t probe;
  status = open_volume(&volume, &probe);
  if (status != XAIOS_OK) {
    close_partition();
    return status;
  }
  if (new_size == 0U) new_size = g_admin_io.info.capacity_bytes;
  xaios_model_volume_writer_t writer = {&g_admin_io, write_at, flush};
  status = map_engine_status(xaios_model_volume_grow(
      &volume, &writer, new_size, g_admin_io.scratch,
      sizeof(g_admin_io.scratch)));
  if (status == XAIOS_OK) status = open_volume(&volume, &probe);
  if (status == XAIOS_OK && volume.volume_size != new_size) {
    status = XAIOS_ERR_IO;
  }
  if (status == XAIOS_OK) {
    status = fill_volume_report(&partition, &volume, &probe, report);
    if (status == XAIOS_OK) report->check_state = XAIOS_MODEL_VOLUME_CHECK_CLEAN;
  }
  close_partition();
  return status;
}

xaios_status_t model_volume_admin_grow_plan(
    const char *partition_identifier, uint64_t new_size,
    xaios_model_volume_admin_report_t *report) {
  if (report == 0) return XAIOS_ERR_INVALID;
  xaios_storage_partition_record_t partition;
  xaios_status_t status = open_partition(partition_identifier, 1U, &partition);
  if (status != XAIOS_OK) return status;
  xaios_model_volume_t volume;
  xaios_model_volume_probe_t probe;
  status = open_volume(&volume, &probe);
  if (status == XAIOS_OK) {
    if (new_size == 0U) new_size = g_admin_io.info.capacity_bytes;
    if (new_size <= volume.volume_size ||
        new_size > g_admin_io.info.capacity_bytes) {
      status = new_size < volume.volume_size ? XAIOS_ERR_UNSUPPORTED
                                             : XAIOS_ERR_INVALID;
    }
  }
  if (status == XAIOS_OK) {
    status = fill_volume_report(&partition, &volume, &probe, report);
    if (status == XAIOS_OK) {
      report->volume_bytes = new_size;
      report->free_bytes = new_size - report->allocated_bytes;
      report->generation = volume.generation + 1U;
      report->dry_run = 1U;
      report->check_state = XAIOS_MODEL_VOLUME_CHECK_CLEAN;
    }
  }
  close_partition();
  return status;
}
