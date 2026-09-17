#include <xaios/xai_fs_admin.h>

#include <xaios/gpt.h>

#include <xaios_engine/xai_fs.h>

#include <string.h>

#include "xai_fs_admin_internal.h"

xaios_status_t xai_fs_admin_format_plan(
    const char *partition_identifier, uint64_t chunk_size,
    xaios_xai_fs_admin_report_t *report) {
  if (report == 0) return XAIOS_ERR_INVALID;
  if (chunk_size == 0U) chunk_size = MODEL_ADMIN_DEFAULT_CHUNK_SIZE;
  xaios_storage_partition_record_t partition;
  xaios_status_t status =
      xai_fs_admin_open_partition(partition_identifier, 1U, &partition);
  if (status != XAIOS_OK) return status;
  xai_fs_admin_fill_base_report(&partition, report);
  report->chunk_size = chunk_size;
  report->volume_bytes = xai_fs_admin_io.info.capacity_bytes;
  report->allocated_bytes = XAIOS_XAI_FS_DATA_START;
  report->free_bytes = report->volume_bytes > report->allocated_bytes
                           ? report->volume_bytes - report->allocated_bytes
                           : 0U;
  report->generation = 1U;
  report->dry_run = 1U;
  uint8_t uuid[16];
  xai_fs_admin_derive_volume_uuid(partition.unique_guid, uuid);
  xaios_guid_t guid;
  memcpy(guid.bytes, uuid, sizeof(guid.bytes));
  if (gpt_guid_format(&guid, report->volume_uuid) != XAIOS_OK ||
      chunk_size < UINT64_C(2097152) || chunk_size > UINT64_C(16777216) ||
      (chunk_size & (chunk_size - 1U)) != 0U ||
      chunk_size > report->volume_bytes / 4U) {
    status = XAIOS_ERR_INVALID;
  }
  xaios_xai_fs_t existing;
  xaios_xai_fs_probe_t probe;
  if (status == XAIOS_OK &&
      xai_fs_admin_open_volume(&existing, &probe) == XAIOS_OK &&
      existing.package_count != 0U) {
    status = XAIOS_ERR_BUSY;
  }
  xai_fs_admin_close_partition();
  return status;
}

xaios_status_t xai_fs_admin_format(
    const char *partition_identifier, const char *partition_confirmation,
    uint64_t chunk_size, xaios_xai_fs_admin_report_t *report) {
  xaios_xai_fs_admin_report_t plan;
  xaios_status_t status = xai_fs_admin_format_plan(
      partition_identifier, chunk_size, &plan);
  if (status != XAIOS_OK ||
      xai_fs_admin_confirmation_matches(partition_confirmation,
                                        plan.partition_uuid) != XAIOS_OK) {
    return status != XAIOS_OK ? status : XAIOS_ERR_INVALID;
  }
  xaios_storage_partition_record_t partition;
  status = xai_fs_admin_open_partition(partition_identifier, 1U, &partition);
  if (status != XAIOS_OK) return status;
  if (xai_fs_admin_confirmation_matches(partition_confirmation,
                                        partition.unique_guid) != XAIOS_OK) {
    xai_fs_admin_close_partition();
    return XAIOS_ERR_BUSY;
  }
  if (chunk_size == 0U) chunk_size = MODEL_ADMIN_DEFAULT_CHUNK_SIZE;
  uint8_t volume_uuid[16];
  xai_fs_admin_derive_volume_uuid(partition.unique_guid, volume_uuid);
  xaios_xai_fs_writer_t writer = {
      &xai_fs_admin_io, xai_fs_admin_write_at, xai_fs_admin_flush};
  status = xai_fs_admin_map_engine_status(xaios_xai_fs_format(
      &writer, xai_fs_admin_io.info.capacity_bytes, chunk_size, volume_uuid,
      xai_fs_admin_io.scratch, sizeof(xai_fs_admin_io.scratch)));
  if (status == XAIOS_OK) {
    xaios_xai_fs_t volume;
    xaios_xai_fs_probe_t probe;
    status = xai_fs_admin_open_volume(&volume, &probe);
    if (status == XAIOS_OK &&
        (probe.first_valid == 0U || probe.second_valid == 0U ||
         probe.copies_compatible == 0U || volume.package_count != 0U)) {
      status = XAIOS_ERR_IO;
    }
    if (status == XAIOS_OK && report != 0) {
      status = xai_fs_admin_fill_volume_report(&partition, &volume, &probe,
                                               report);
      if (status == XAIOS_OK) {
        report->check_state = XAIOS_XAI_FS_CHECK_CLEAN;
        report->dry_run = 0U;
      }
    }
  }
  xai_fs_admin_close_partition();
  return status;
}

xaios_status_t xai_fs_admin_fsck(
    const char *partition_identifier, uint32_t verify_data,
    xaios_xai_fs_admin_report_t *report) {
  if (report == 0 || verify_data > 1U) return XAIOS_ERR_INVALID;
  xaios_storage_partition_record_t partition;
  xaios_status_t status =
      xai_fs_admin_open_partition(partition_identifier, 1U, &partition);
  if (status != XAIOS_OK) return status;
  xai_fs_admin_fill_base_report(&partition, report);
  xaios_xai_fs_reader_t reader = {
      &xai_fs_admin_io, xai_fs_admin_read_at,
      xai_fs_admin_io.info.capacity_bytes};
  xaios_xai_fs_probe_t probe;
  xaios_engine_status_t engine_status = xaios_xai_fs_probe(
      &reader, xai_fs_admin_io.scratch, sizeof(xai_fs_admin_io.scratch),
      &probe);
  if (engine_status != XAIOS_ENGINE_OK) {
    report->check_state = XAIOS_XAI_FS_CHECK_CORRUPT_UNREPAIRABLE;
    xai_fs_admin_close_partition();
    return XAIOS_OK;
  }
  xaios_xai_fs_t volume;
  engine_status = xaios_xai_fs_open(
      &reader, xai_fs_admin_verify_signature, 0, xai_fs_admin_io.scratch,
      sizeof(xai_fs_admin_io.scratch), &volume);
  if (engine_status != XAIOS_ENGINE_OK ||
      xai_fs_admin_fill_volume_report(&partition, &volume, &probe, report) !=
          XAIOS_OK) {
    report->check_state = XAIOS_XAI_FS_CHECK_CORRUPT_UNREPAIRABLE;
    xai_fs_admin_close_partition();
    return XAIOS_OK;
  }
  report->check_state =
      probe.first_valid != 0U && probe.second_valid != 0U &&
              probe.copies_compatible != 0U
          ? XAIOS_XAI_FS_CHECK_CLEAN
          : XAIOS_XAI_FS_CHECK_REPAIRABLE;
  if (verify_data != 0U) {
    for (uint64_t index = 0U; index < volume.package_count; ++index) {
      xaios_xai_fs_package_t package;
      engine_status = xaios_xai_fs_read_package(&volume, index, &package);
      if (engine_status != XAIOS_ENGINE_OK) {
        report->check_state = XAIOS_XAI_FS_CHECK_CORRUPT_UNREPAIRABLE;
        break;
      }
      if (package.state == XAIOS_XAI_FS_PACKAGE_STAGING) {
        uint32_t complete = 1U;
        for (uint64_t relative = 0U; relative < package.chunk_count;
             ++relative) {
          xaios_xai_fs_chunk_t chunk;
          engine_status = xaios_xai_fs_read_chunk(
              &volume, package.chunk_start + relative, &chunk);
          if (engine_status != XAIOS_ENGINE_OK ||
              (chunk.flags & XAIOS_XAI_FS_CHUNK_COMPLETE) == 0U) {
            complete = 0U;
            break;
          }
        }
        if (complete == 0U) continue;
      }
      uint64_t bad_offset = UINT64_MAX;
      engine_status = xaios_xai_fs_verify_package(
          &volume, &package, xai_fs_admin_io.scratch,
          sizeof(xai_fs_admin_io.scratch), &bad_offset);
      if (engine_status != XAIOS_ENGINE_OK) {
        report->check_state = XAIOS_XAI_FS_CHECK_CORRUPT_UNREPAIRABLE;
        report->bad_logical_offset = bad_offset;
        xai_fs_admin_hex_id(package.package_id, report->bad_package_id);
        break;
      }
      if (report->checked_bytes > UINT64_MAX - package.logical_size) {
        report->check_state = XAIOS_XAI_FS_CHECK_CORRUPT_UNREPAIRABLE;
        break;
      }
      report->checked_bytes += package.logical_size;
    }
  }
  xai_fs_admin_close_partition();
  return XAIOS_OK;
}

xaios_status_t xai_fs_admin_repair(
    const char *partition_identifier, const char *partition_confirmation,
    xaios_xai_fs_admin_report_t *report) {
  if (report == 0) return XAIOS_ERR_INVALID;
  xaios_storage_partition_record_t partition;
  xaios_status_t status =
      xai_fs_admin_open_partition(partition_identifier, 1U, &partition);
  if (status != XAIOS_OK) return status;
  if (xai_fs_admin_confirmation_matches(partition_confirmation,
                                        partition.unique_guid) != XAIOS_OK) {
    xai_fs_admin_close_partition();
    return XAIOS_ERR_INVALID;
  }
  xaios_xai_fs_t volume;
  xaios_xai_fs_probe_t probe;
  status = xai_fs_admin_open_volume(&volume, &probe);
  if (status != XAIOS_OK || probe.first_valid == probe.second_valid) {
    xai_fs_admin_close_partition();
    return status != XAIOS_OK ? status : XAIOS_ERR_UNSUPPORTED;
  }
  xaios_xai_fs_writer_t writer = {
      &xai_fs_admin_io, xai_fs_admin_write_at, xai_fs_admin_flush};
  status = xai_fs_admin_map_engine_status(xaios_xai_fs_repair_superblock(
      &volume, &writer, xai_fs_admin_io.scratch,
      sizeof(xai_fs_admin_io.scratch)));
  if (status == XAIOS_OK) {
    status = xai_fs_admin_open_volume(&volume, &probe);
  }
  if (status == XAIOS_OK &&
      (probe.first_valid == 0U || probe.second_valid == 0U ||
       probe.copies_compatible == 0U)) {
    status = XAIOS_ERR_IO;
  }
  if (status == XAIOS_OK) {
    status = xai_fs_admin_fill_volume_report(&partition, &volume, &probe,
                                             report);
    if (status == XAIOS_OK) {
      report->check_state = XAIOS_XAI_FS_CHECK_REPAIRED;
    }
  }
  xai_fs_admin_close_partition();
  return status;
}

xaios_status_t xai_fs_admin_repair_from_replica(
    const char *target_identifier, const char *target_confirmation,
    const char *replica_identifier, const char *package_id,
    xaios_xai_fs_admin_report_t *report) {
  if (report == 0 || target_identifier == 0 || replica_identifier == 0 ||
      package_id == 0 || strcmp(target_identifier, replica_identifier) == 0) {
    return XAIOS_ERR_INVALID;
  }
  uint8_t requested_package_id[32];
  if (!xai_fs_admin_parse_package_id(package_id, requested_package_id)) {
    return XAIOS_ERR_INVALID;
  }

  xaios_storage_partition_record_t target_partition;
  xaios_status_t status =
      xai_fs_admin_open_partition(target_identifier, 1U, &target_partition);
  if (status != XAIOS_OK) return status;
  if (xai_fs_admin_confirmation_matches(target_confirmation,
                                        target_partition.unique_guid) !=
      XAIOS_OK) {
    xai_fs_admin_close_partition();
    return XAIOS_ERR_INVALID;
  }

  model_admin_io_t replica_io;
  xaios_storage_partition_record_t replica_partition;
  status = xai_fs_admin_open_partition_into(&replica_io, replica_identifier,
                                            1U, 0U, &replica_partition);
  if (status != XAIOS_OK) {
    xai_fs_admin_close_partition();
    return status;
  }
  if (strcmp(target_partition.unique_guid, replica_partition.unique_guid) ==
      0) {
    xai_fs_admin_close_partition_io(&replica_io);
    xai_fs_admin_close_partition();
    return XAIOS_ERR_INVALID;
  }

  xaios_xai_fs_t target;
  xaios_xai_fs_t replica;
  xaios_xai_fs_probe_t target_probe;
  xaios_xai_fs_probe_t replica_probe;
  status = xai_fs_admin_open_volume(&target, &target_probe);
  if (status == XAIOS_OK) {
    status = xai_fs_admin_open_volume_into(&replica_io, &replica,
                                           &replica_probe);
  }
  xaios_xai_fs_package_t target_package;
  xaios_xai_fs_package_t replica_package;
  if (status == XAIOS_OK) {
    status = xai_fs_admin_find_package(&target, requested_package_id,
                                       &target_package);
  }
  if (status == XAIOS_OK) {
    status = xai_fs_admin_find_package(&replica, requested_package_id,
                                       &replica_package);
  }
  if (status == XAIOS_OK) {
    xaios_xai_fs_writer_t writer = {
        &xai_fs_admin_io, xai_fs_admin_write_at, xai_fs_admin_flush};
    uint64_t copied = 0U;
    status = xai_fs_admin_map_engine_status(xaios_xai_fs_repair_from_replica(
        &target, &target_package, &replica, &replica_package, &writer,
        xai_fs_admin_io.scratch, sizeof(xai_fs_admin_io.scratch), &copied));
    if (status == XAIOS_OK) {
      status = xai_fs_admin_open_volume(&target, &target_probe);
    }
    if (status == XAIOS_OK) {
      status = xai_fs_admin_fill_volume_report(&target_partition, &target,
                                               &target_probe, report);
    }
    if (status == XAIOS_OK) {
      report->checked_bytes = copied;
      report->check_state = XAIOS_XAI_FS_CHECK_REPAIRED;
    }
  }
  xai_fs_admin_close_partition_io(&replica_io);
  xai_fs_admin_close_partition();
  return status;
}

xaios_status_t xai_fs_admin_grow(
    const char *partition_identifier, const char *partition_confirmation,
    uint64_t new_size, xaios_xai_fs_admin_report_t *report) {
  if (report == 0) return XAIOS_ERR_INVALID;
  xaios_storage_partition_record_t partition;
  xaios_status_t status =
      xai_fs_admin_open_partition(partition_identifier, 1U, &partition);
  if (status != XAIOS_OK) return status;
  if (xai_fs_admin_confirmation_matches(partition_confirmation,
                                        partition.unique_guid) != XAIOS_OK) {
    xai_fs_admin_close_partition();
    return XAIOS_ERR_INVALID;
  }
  xaios_xai_fs_t volume;
  xaios_xai_fs_probe_t probe;
  status = xai_fs_admin_open_volume(&volume, &probe);
  if (status != XAIOS_OK) {
    xai_fs_admin_close_partition();
    return status;
  }
  if (new_size == 0U) new_size = xai_fs_admin_io.info.capacity_bytes;
  xaios_xai_fs_writer_t writer = {
      &xai_fs_admin_io, xai_fs_admin_write_at, xai_fs_admin_flush};
  status = xai_fs_admin_map_engine_status(xaios_xai_fs_grow(
      &volume, &writer, new_size, xai_fs_admin_io.scratch,
      sizeof(xai_fs_admin_io.scratch)));
  if (status == XAIOS_OK) status = xai_fs_admin_open_volume(&volume, &probe);
  if (status == XAIOS_OK && volume.volume_size != new_size) {
    status = XAIOS_ERR_IO;
  }
  if (status == XAIOS_OK) {
    status = xai_fs_admin_fill_volume_report(&partition, &volume, &probe,
                                             report);
    if (status == XAIOS_OK) report->check_state = XAIOS_XAI_FS_CHECK_CLEAN;
  }
  xai_fs_admin_close_partition();
  return status;
}

xaios_status_t xai_fs_admin_grow_plan(
    const char *partition_identifier, uint64_t new_size,
    xaios_xai_fs_admin_report_t *report) {
  if (report == 0) return XAIOS_ERR_INVALID;
  xaios_storage_partition_record_t partition;
  xaios_status_t status =
      xai_fs_admin_open_partition(partition_identifier, 1U, &partition);
  if (status != XAIOS_OK) return status;
  xaios_xai_fs_t volume;
  xaios_xai_fs_probe_t probe;
  status = xai_fs_admin_open_volume(&volume, &probe);
  if (status == XAIOS_OK) {
    if (new_size == 0U) new_size = xai_fs_admin_io.info.capacity_bytes;
    if (new_size <= volume.volume_size ||
        new_size > xai_fs_admin_io.info.capacity_bytes) {
      status = new_size < volume.volume_size ? XAIOS_ERR_UNSUPPORTED
                                             : XAIOS_ERR_INVALID;
    }
  }
  if (status == XAIOS_OK) {
    status = xai_fs_admin_fill_volume_report(&partition, &volume, &probe,
                                             report);
    if (status == XAIOS_OK) {
      report->volume_bytes = new_size;
      report->free_bytes = new_size - report->allocated_bytes;
      report->generation = volume.generation + 1U;
      report->dry_run = 1U;
      report->check_state = XAIOS_XAI_FS_CHECK_CLEAN;
    }
  }
  xai_fs_admin_close_partition();
  return status;
}
