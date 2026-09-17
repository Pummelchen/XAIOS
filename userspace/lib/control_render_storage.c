/*
 * The control client's storage renderers: the device table, the filesystem
 * table and the partition table a storage query returns.
 *
 * These are the read-only storage views. Each turns one decoded reply payload
 * into the text or JSON a caller prints, validates the fixed-width records it
 * was handed, and calls only the primitives declared in
 * xaios_control_internal.h. They were the first half of the storage group to
 * leave xaios_control_client.c; the install, partition-plan, maintenance and
 * audit renderers that followed them stayed behind or moved to
 * control_render_ops.c.
 */

#include "xaios_control_internal.h"

int storage_boolean_valid(u32 value) { return value <= 1U; }

int render_storage_devices(const void *payload, u64 payload_length,
                                  int json, char *output, u64 capacity,
                                  u64 *offset, u64 request_id) {
  xaios_control_storage_devices_payload_user_t metadata;
  if (payload_length < sizeof(metadata)) return -1;
  bytes_copy(&metadata, payload, sizeof(metadata));
  if (metadata.record_count > XAIOS_CONTROL_STORAGE_MAX_DEVICES ||
      metadata.total_count < metadata.record_count || metadata.truncated > 1U ||
      metadata.reserved != 0U ||
      payload_length != sizeof(metadata) +
                            (u64)metadata.record_count *
                                sizeof(xaios_control_storage_device_record_user_t)) {
    return -1;
  }
  const xaios_control_storage_device_record_user_t *records =
      (const xaios_control_storage_device_record_user_t *)(
          (const unsigned char *)payload + sizeof(metadata));
  for (u32 index = 0U; index < metadata.record_count; ++index) {
    if (!fixed_string_valid(records[index].identifier,
                            sizeof(records[index].identifier)) ||
        !fixed_string_valid(records[index].backend,
                            sizeof(records[index].backend)) ||
        !storage_boolean_valid(records[index].read_only) ||
        !storage_boolean_valid(records[index].flush_supported) ||
        !storage_boolean_valid(records[index].discard_supported) ||
        !storage_boolean_valid(records[index].write_zeroes_supported)) {
      return -1;
    }
  }
  if (json != 0) {
    int first = 1;
    if (json_envelope_begin(output, capacity, offset, request_id) != 0 ||
        json_field_u64(output, capacity, offset, &first, "record_count",
                       metadata.record_count) != 0 ||
        json_field_u64(output, capacity, offset, &first, "total_count",
                       metadata.total_count) != 0 ||
        json_field_u64(output, capacity, offset, &first, "truncated",
                       metadata.truncated) != 0 ||
        json_field_prefix(output, capacity, offset, &first, "devices") != 0 ||
        append_char(output, capacity, offset, '[') != 0) {
      return -1;
    }
    for (u32 index = 0U; index < metadata.record_count; ++index) {
      const xaios_control_storage_device_record_user_t *record =
          &records[index];
      if ((index != 0U && append_char(output, capacity, offset, ',') != 0) ||
          append_text(output, capacity, offset, "{\"identifier\":") != 0 ||
          append_json_string(output, capacity, offset, record->identifier,
                             xaios_strlen(record->identifier)) != 0 ||
          append_text(output, capacity, offset, ",\"backend\":") != 0 ||
          append_json_string(output, capacity, offset, record->backend,
                             xaios_strlen(record->backend)) != 0 ||
          append_text(output, capacity, offset, ",\"capacity_bytes\":") != 0 ||
          append_u64(output, capacity, offset, record->capacity_bytes) != 0 ||
          append_text(output, capacity, offset,
                      ",\"capacity_logical_sectors\":") != 0 ||
          append_u64(output, capacity, offset,
                     record->capacity_logical_sectors) != 0 ||
          append_text(output, capacity, offset,
                      ",\"logical_sector_size\":") != 0 ||
          append_u64(output, capacity, offset, record->logical_sector_size) != 0 ||
          append_text(output, capacity, offset,
                      ",\"physical_block_size\":") != 0 ||
          append_u64(output, capacity, offset,
                     record->physical_block_size) != 0 ||
          append_text(output, capacity, offset,
                      ",\"max_transfer_bytes\":") != 0 ||
          append_u64(output, capacity, offset, record->max_transfer_bytes) != 0 ||
          append_text(output, capacity, offset,
                      ",\"discard_granularity\":") != 0 ||
          append_u64(output, capacity, offset,
                     record->discard_granularity) != 0 ||
          append_text(output, capacity, offset,
                      ",\"max_discard_bytes\":") != 0 ||
          append_u64(output, capacity, offset, record->max_discard_bytes) != 0 ||
          append_text(output, capacity, offset, ",\"read_bytes\":") != 0 ||
          append_u64(output, capacity, offset, record->read_bytes) != 0 ||
          append_text(output, capacity, offset, ",\"write_bytes\":") != 0 ||
          append_u64(output, capacity, offset, record->write_bytes) != 0 ||
          append_text(output, capacity, offset, ",\"discarded_bytes\":") != 0 ||
          append_u64(output, capacity, offset, record->discarded_bytes) != 0 ||
          append_text(output, capacity, offset, ",\"io_errors\":") != 0 ||
          append_u64(output, capacity, offset, record->io_errors) != 0 ||
          append_text(output, capacity, offset, ",\"read_only\":") != 0 ||
          append_u64(output, capacity, offset, record->read_only) != 0 ||
          append_text(output, capacity, offset,
                      ",\"flush_supported\":") != 0 ||
          append_u64(output, capacity, offset, record->flush_supported) != 0 ||
          append_text(output, capacity, offset,
                      ",\"discard_supported\":") != 0 ||
          append_u64(output, capacity, offset, record->discard_supported) != 0 ||
          append_text(output, capacity, offset,
                      ",\"write_zeroes_supported\":") != 0 ||
          append_u64(output, capacity, offset,
                     record->write_zeroes_supported) != 0 ||
          append_char(output, capacity, offset, '}') != 0) {
        return -1;
      }
    }
    return append_char(output, capacity, offset, ']') ||
           json_envelope_end(output, capacity, offset);
  }
  if (human_field_u64(output, capacity, offset, "record_count",
                      metadata.record_count) != 0 ||
      human_field_u64(output, capacity, offset, "total_count",
                      metadata.total_count) != 0 ||
      human_field_u64(output, capacity, offset, "truncated",
                      metadata.truncated) != 0) {
    return -1;
  }
  for (u32 index = 0U; index < metadata.record_count; ++index) {
    const xaios_control_storage_device_record_user_t *record = &records[index];
    if (append_text(output, capacity, offset, "device=") != 0 ||
        append_text(output, capacity, offset, record->identifier) != 0 ||
        append_text(output, capacity, offset, " backend=") != 0 ||
        append_text(output, capacity, offset, record->backend) != 0 ||
        append_text(output, capacity, offset, " capacity_bytes=") != 0 ||
        append_u64(output, capacity, offset, record->capacity_bytes) != 0 ||
        append_text(output, capacity, offset, " logical_sector_size=") != 0 ||
        append_u64(output, capacity, offset, record->logical_sector_size) != 0 ||
        append_text(output, capacity, offset, " read_only=") != 0 ||
        append_u64(output, capacity, offset, record->read_only) != 0 ||
        append_text(output, capacity, offset, " discard_supported=") != 0 ||
        append_u64(output, capacity, offset, record->discard_supported) != 0 ||
        append_char(output, capacity, offset, '\n') != 0) {
      return -1;
    }
  }
  return 0;
}

int render_storage_filesystems(const void *payload, u64 payload_length,
                                      int json, char *output, u64 capacity,
                                      u64 *offset, u64 request_id) {
  xaios_control_storage_filesystems_payload_user_t metadata;
  if (payload_length < sizeof(metadata)) return -1;
  bytes_copy(&metadata, payload, sizeof(metadata));
  if (metadata.record_count > XAIOS_CONTROL_STORAGE_MAX_FILESYSTEMS ||
      metadata.total_count < metadata.record_count || metadata.truncated > 1U ||
      metadata.reserved != 0U ||
      payload_length != sizeof(metadata) +
                            (u64)metadata.record_count *
                                sizeof(xaios_control_storage_filesystem_record_user_t)) {
    return -1;
  }
  const xaios_control_storage_filesystem_record_user_t *records =
      (const xaios_control_storage_filesystem_record_user_t *)(
          (const unsigned char *)payload + sizeof(metadata));
  for (u32 index = 0U; index < metadata.record_count; ++index) {
    if (!fixed_string_valid(records[index].mount_path,
                            sizeof(records[index].mount_path)) ||
        !fixed_string_valid(records[index].filesystem,
                            sizeof(records[index].filesystem)) ||
        !fixed_string_valid(records[index].device_identifier,
                            sizeof(records[index].device_identifier)) ||
        !storage_boolean_valid(records[index].mounted) ||
        !storage_boolean_valid(records[index].read_only) ||
        !storage_boolean_valid(records[index].staging_writable)) {
      return -1;
    }
  }
  if (json != 0) {
    int first = 1;
    if (json_envelope_begin(output, capacity, offset, request_id) != 0 ||
        json_field_u64(output, capacity, offset, &first, "record_count",
                       metadata.record_count) != 0 ||
        json_field_u64(output, capacity, offset, &first, "total_count",
                       metadata.total_count) != 0 ||
        json_field_u64(output, capacity, offset, &first, "truncated",
                       metadata.truncated) != 0 ||
        json_field_prefix(output, capacity, offset, &first, "filesystems") != 0 ||
        append_char(output, capacity, offset, '[') != 0) {
      return -1;
    }
    for (u32 index = 0U; index < metadata.record_count; ++index) {
      const xaios_control_storage_filesystem_record_user_t *record =
          &records[index];
      if ((index != 0U && append_char(output, capacity, offset, ',') != 0) ||
          append_text(output, capacity, offset, "{\"mount_path\":") != 0 ||
          append_json_string(output, capacity, offset, record->mount_path,
                             xaios_strlen(record->mount_path)) != 0 ||
          append_text(output, capacity, offset, ",\"filesystem\":") != 0 ||
          append_json_string(output, capacity, offset, record->filesystem,
                             xaios_strlen(record->filesystem)) != 0 ||
          append_text(output, capacity, offset,
                      ",\"device_identifier\":") != 0 ||
          append_json_string(output, capacity, offset, record->device_identifier,
                             xaios_strlen(record->device_identifier)) != 0 ||
          append_text(output, capacity, offset, ",\"total_bytes\":") != 0 ||
          append_u64(output, capacity, offset, record->total_bytes) != 0 ||
          append_text(output, capacity, offset, ",\"allocated_bytes\":") != 0 ||
          append_u64(output, capacity, offset, record->allocated_bytes) != 0 ||
          append_text(output, capacity, offset, ",\"free_bytes\":") != 0 ||
          append_u64(output, capacity, offset, record->free_bytes) != 0 ||
          append_text(output, capacity, offset, ",\"reserved_bytes\":") != 0 ||
          append_u64(output, capacity, offset, record->reserved_bytes) != 0 ||
          append_text(output, capacity, offset, ",\"file_count\":") != 0 ||
          append_u64(output, capacity, offset, record->file_count) != 0 ||
          append_text(output, capacity, offset, ",\"directory_count\":") != 0 ||
          append_u64(output, capacity, offset, record->directory_count) != 0 ||
          append_text(output, capacity, offset, ",\"generation\":") != 0 ||
          append_u64(output, capacity, offset, record->generation) != 0 ||
          append_text(output, capacity, offset, ",\"block_size\":") != 0 ||
          append_u64(output, capacity, offset, record->block_size) != 0 ||
          append_text(output, capacity, offset, ",\"format_version\":") != 0 ||
          append_u64(output, capacity, offset, record->format_version) != 0 ||
          append_text(output, capacity, offset, ",\"package_count\":") != 0 ||
          append_u64(output, capacity, offset, record->package_count) != 0 ||
          append_text(output, capacity, offset, ",\"active_packages\":") != 0 ||
          append_u64(output, capacity, offset, record->active_packages) != 0 ||
          append_text(output, capacity, offset, ",\"staging_packages\":") != 0 ||
          append_u64(output, capacity, offset, record->staging_packages) != 0 ||
          append_text(output, capacity, offset,
                      ",\"quarantined_packages\":") != 0 ||
          append_u64(output, capacity, offset,
                     record->quarantined_packages) != 0 ||
          append_text(output, capacity, offset, ",\"mounted\":") != 0 ||
          append_u64(output, capacity, offset, record->mounted) != 0 ||
          append_text(output, capacity, offset, ",\"read_only\":") != 0 ||
          append_u64(output, capacity, offset, record->read_only) != 0 ||
          append_text(output, capacity, offset,
                      ",\"staging_writable\":") != 0 ||
          append_u64(output, capacity, offset, record->staging_writable) != 0 ||
          append_char(output, capacity, offset, '}') != 0) {
        return -1;
      }
    }
    return append_char(output, capacity, offset, ']') ||
           json_envelope_end(output, capacity, offset);
  }
  if (human_field_u64(output, capacity, offset, "record_count",
                      metadata.record_count) != 0 ||
      human_field_u64(output, capacity, offset, "total_count",
                      metadata.total_count) != 0) {
    return -1;
  }
  for (u32 index = 0U; index < metadata.record_count; ++index) {
    const xaios_control_storage_filesystem_record_user_t *record =
        &records[index];
    if (append_text(output, capacity, offset, "mount=") != 0 ||
        append_text(output, capacity, offset, record->mount_path) != 0 ||
        append_text(output, capacity, offset, " filesystem=") != 0 ||
        append_text(output, capacity, offset, record->filesystem) != 0 ||
        append_text(output, capacity, offset, " device=") != 0 ||
        append_text(output, capacity, offset, record->device_identifier) != 0 ||
        append_text(output, capacity, offset, " total_bytes=") != 0 ||
        append_u64(output, capacity, offset, record->total_bytes) != 0 ||
        append_text(output, capacity, offset, " allocated_bytes=") != 0 ||
        append_u64(output, capacity, offset, record->allocated_bytes) != 0 ||
        append_text(output, capacity, offset, " free_bytes=") != 0 ||
        append_u64(output, capacity, offset, record->free_bytes) != 0 ||
        append_text(output, capacity, offset, " generation=") != 0 ||
        append_u64(output, capacity, offset, record->generation) != 0 ||
        append_char(output, capacity, offset, '\n') != 0) {
      return -1;
    }
  }
  return 0;
}

static const char *partition_type_name(u32 type) {
  if (type == XAIOS_STORAGE_PARTITION_STATE) return "state";
  if (type == XAIOS_STORAGE_PARTITION_MODEL) return "model";
  if (type == XAIOS_STORAGE_PARTITION_RECOVERY) return "recovery";
  if (type == XAIOS_STORAGE_PARTITION_ESP) return "esp";
  return "unknown";
}

int partition_report_valid(
    const xaios_storage_partition_report_user_t *report) {
  return fixed_string_valid(report->device_identifier,
                            sizeof(report->device_identifier)) &&
         fixed_string_valid(report->disk_guid, sizeof(report->disk_guid)) &&
         storage_boolean_valid(report->primary_valid) &&
         storage_boolean_valid(report->backup_valid) &&
         storage_boolean_valid(report->copies_consistent) &&
         storage_boolean_valid(report->mutation_allowed) &&
         report->selected_copy <= 2U && report->reserved == 0U;
}

int partition_record_valid(
    const xaios_storage_partition_record_user_t *record) {
  return fixed_string_valid(record->identifier, sizeof(record->identifier)) &&
         fixed_string_valid(record->name, sizeof(record->name)) &&
         fixed_string_valid(record->type_guid, sizeof(record->type_guid)) &&
         fixed_string_valid(record->unique_guid,
                            sizeof(record->unique_guid)) &&
         record->first_lba <= record->last_lba &&
         record->known_type <= XAIOS_STORAGE_PARTITION_ESP;
}

int append_partition_record_json(
    char *output, u64 capacity, u64 *offset,
    const xaios_storage_partition_record_user_t *record) {
  const char *type = partition_type_name(record->known_type);
  return append_text(output, capacity, offset, "{\"identifier\":") ||
         append_json_string(output, capacity, offset, record->identifier,
                            xaios_strlen(record->identifier)) ||
         append_text(output, capacity, offset, ",\"name\":") ||
         append_json_string(output, capacity, offset, record->name,
                            xaios_strlen(record->name)) ||
         append_text(output, capacity, offset, ",\"type\":") ||
         append_json_string(output, capacity, offset, type,
                            xaios_strlen(type)) ||
         append_text(output, capacity, offset, ",\"type_guid\":") ||
         append_json_string(output, capacity, offset, record->type_guid,
                            xaios_strlen(record->type_guid)) ||
         append_text(output, capacity, offset, ",\"unique_guid\":") ||
         append_json_string(output, capacity, offset, record->unique_guid,
                            xaios_strlen(record->unique_guid)) ||
         append_text(output, capacity, offset, ",\"first_lba\":") ||
         append_u64(output, capacity, offset, record->first_lba) ||
         append_text(output, capacity, offset, ",\"last_lba\":") ||
         append_u64(output, capacity, offset, record->last_lba) ||
         append_text(output, capacity, offset, ",\"size_bytes\":") ||
         append_u64(output, capacity, offset, record->size_bytes) ||
         append_text(output, capacity, offset, ",\"attributes\":") ||
         append_u64(output, capacity, offset, record->attributes) ||
         append_text(output, capacity, offset, ",\"table_index\":") ||
         append_u64(output, capacity, offset, record->table_index) ||
         append_char(output, capacity, offset, '}');
}

int append_partition_report_json(
    char *output, u64 capacity, u64 *offset, int *first,
    const xaios_storage_partition_report_user_t *report) {
  return json_field_string(output, capacity, offset, first,
                           "device_identifier", report->device_identifier) ||
         json_field_string(output, capacity, offset, first, "disk_guid",
                           report->disk_guid) ||
         json_field_u64(output, capacity, offset, first, "capacity_bytes",
                        report->capacity_bytes) ||
         json_field_u64(output, capacity, offset, first,
                        "logical_sector_size", report->logical_sector_size) ||
         json_field_u64(output, capacity, offset, first, "first_usable_lba",
                        report->first_usable_lba) ||
         json_field_u64(output, capacity, offset, first, "last_usable_lba",
                        report->last_usable_lba) ||
         json_field_u64(output, capacity, offset, first, "partition_count",
                        report->partition_count) ||
         json_field_u64(output, capacity, offset, first, "primary_valid",
                        report->primary_valid) ||
         json_field_u64(output, capacity, offset, first, "backup_valid",
                        report->backup_valid) ||
         json_field_u64(output, capacity, offset, first, "copies_consistent",
                        report->copies_consistent) ||
         json_field_u64(output, capacity, offset, first, "selected_copy",
                        report->selected_copy) ||
         json_field_u64(output, capacity, offset, first, "mutation_allowed",
                        report->mutation_allowed);
}

int append_partition_report_human(
    char *output, u64 capacity, u64 *offset,
    const xaios_storage_partition_report_user_t *report) {
  return append_text(output, capacity, offset, "device=") ||
         append_text(output, capacity, offset, report->device_identifier) ||
         append_text(output, capacity, offset, " disk_guid=") ||
         append_text(output, capacity, offset, report->disk_guid) ||
         append_text(output, capacity, offset, " capacity_bytes=") ||
         append_u64(output, capacity, offset, report->capacity_bytes) ||
         append_text(output, capacity, offset, " partitions=") ||
         append_u64(output, capacity, offset, report->partition_count) ||
         append_text(output, capacity, offset, " primary_valid=") ||
         append_u64(output, capacity, offset, report->primary_valid) ||
         append_text(output, capacity, offset, " backup_valid=") ||
         append_u64(output, capacity, offset, report->backup_valid) ||
         append_text(output, capacity, offset, " copies_consistent=") ||
         append_u64(output, capacity, offset, report->copies_consistent) ||
         append_text(output, capacity, offset, " mutation_allowed=") ||
         append_u64(output, capacity, offset, report->mutation_allowed) ||
         append_char(output, capacity, offset, '\n');
}

int render_storage_partitions(const void *payload, u64 payload_length,
                                     int json, char *output, u64 capacity,
                                     u64 *offset, u64 request_id) {
  xaios_control_storage_partitions_payload_user_t metadata;
  if (payload_length < sizeof(metadata)) return -1;
  bytes_copy(&metadata, payload, sizeof(metadata));
  if (!partition_report_valid(&metadata.report) ||
      metadata.record_count > XAIOS_CONTROL_STORAGE_MAX_PARTITIONS ||
      metadata.total_count < metadata.record_count || metadata.truncated > 1U ||
      metadata.reserved != 0U ||
      payload_length != sizeof(metadata) +
                            (u64)metadata.record_count *
                                sizeof(xaios_storage_partition_record_user_t)) {
    return -1;
  }
  const xaios_storage_partition_record_user_t *records =
      (const xaios_storage_partition_record_user_t *)(
          (const unsigned char *)payload + sizeof(metadata));
  for (u32 index = 0U; index < metadata.record_count; ++index) {
    if (!partition_record_valid(&records[index])) return -1;
  }
  if (json != 0) {
    int first = 1;
    if (json_envelope_begin(output, capacity, offset, request_id) != 0 ||
        append_partition_report_json(output, capacity, offset, &first,
                                     &metadata.report) != 0 ||
        json_field_u64(output, capacity, offset, &first, "record_count",
                       metadata.record_count) != 0 ||
        json_field_u64(output, capacity, offset, &first, "total_count",
                       metadata.total_count) != 0 ||
        json_field_u64(output, capacity, offset, &first, "truncated",
                       metadata.truncated) != 0 ||
        json_field_prefix(output, capacity, offset, &first, "partitions") != 0 ||
        append_char(output, capacity, offset, '[') != 0) {
      return -1;
    }
    for (u32 index = 0U; index < metadata.record_count; ++index) {
      if ((index != 0U && append_char(output, capacity, offset, ',') != 0) ||
          append_partition_record_json(output, capacity, offset,
                                       &records[index]) != 0) {
        return -1;
      }
    }
    return append_char(output, capacity, offset, ']') ||
           json_envelope_end(output, capacity, offset);
  }
  if (append_partition_report_human(output, capacity, offset,
                                    &metadata.report) != 0) {
    return -1;
  }
  for (u32 index = 0U; index < metadata.record_count; ++index) {
    const xaios_storage_partition_record_user_t *record = &records[index];
    if (append_text(output, capacity, offset, "partition=") != 0 ||
        append_text(output, capacity, offset, record->identifier) != 0 ||
        append_text(output, capacity, offset, " name=") != 0 ||
        append_text(output, capacity, offset, record->name) != 0 ||
        append_text(output, capacity, offset, " type=") != 0 ||
        append_text(output, capacity, offset,
                    partition_type_name(record->known_type)) != 0 ||
        append_text(output, capacity, offset, " unique_guid=") != 0 ||
        append_text(output, capacity, offset, record->unique_guid) != 0 ||
        append_text(output, capacity, offset, " size_bytes=") != 0 ||
        append_u64(output, capacity, offset, record->size_bytes) != 0 ||
        append_char(output, capacity, offset, '\n') != 0) {
      return -1;
    }
  }
  return 0;
}
