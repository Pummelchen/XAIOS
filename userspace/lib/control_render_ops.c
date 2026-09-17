/*
 * The control client's operation renderers: what an install, a partition
 * plan, a mutation, a model cleanup, a volume check/repair, a scrub and a
 * trim did.
 *
 * Each turns one decoded reply payload into the text or JSON a caller prints
 * and calls only the primitives declared in xaios_control_internal.h. The
 * read-only storage tables are in control_render_storage.c; the audit
 * renderer is still in xaios_control_client.c.
 */

#include "xaios_control_internal.h"

/* What an install did, in the terms an operator would check it by: which
   partitions now exist on the target, and how much was actually copied. */
int render_storage_install(const void *payload, u64 payload_length,
                                  int json, char *output, u64 capacity,
                                  u64 *offset, u64 request_id) {
  xaios_control_storage_install_result_user_t result;
  if (payload_length != sizeof(result)) return -1;
  bytes_copy(&result, payload, sizeof(result));
  if (result.esp_identifier[0] == '\0' ||
      result.state_identifier[0] == '\0' || result.files_copied == 0ULL) {
    return -1;
  }
  if (json != 0) {
    int first = 1;
    if (json_envelope_begin(output, capacity, offset, request_id) != 0 ||
        json_field_string(output, capacity, offset, &first, "esp",
                          result.esp_identifier) != 0 ||
        json_field_string(output, capacity, offset, &first, "state",
                          result.state_identifier) != 0 ||
        json_field_u64(output, capacity, offset, &first, "files_copied",
                       result.files_copied) != 0 ||
        json_field_u64(output, capacity, offset, &first, "bytes_copied",
                       result.bytes_copied) != 0 ||
        json_field_u64(output, capacity, offset, &first, "esp_bytes",
                       result.esp_bytes) != 0 ||
        json_field_u64(output, capacity, offset, &first, "state_bytes",
                       result.state_bytes) != 0) {
      return -1;
    }
    return json_envelope_end(output, capacity, offset);
  }
  if (append_text(output, capacity, offset, "esp=") != 0 ||
      append_text(output, capacity, offset, result.esp_identifier) != 0 ||
      append_text(output, capacity, offset, " state=") != 0 ||
      append_text(output, capacity, offset, result.state_identifier) != 0 ||
      append_text(output, capacity, offset, "\n") != 0 ||
      human_field_u64(output, capacity, offset, "files_copied",
                      result.files_copied) != 0 ||
      human_field_u64(output, capacity, offset, "bytes_copied",
                      result.bytes_copied) != 0 ||
      human_field_u64(output, capacity, offset, "esp_bytes",
                      result.esp_bytes) != 0 ||
      human_field_u64(output, capacity, offset, "state_bytes",
                      result.state_bytes) != 0) {
    return -1;
  }
  return 0;
}

int render_storage_partition_plan(
    const void *payload, u64 payload_length, int json, char *output,
    u64 capacity, u64 *offset, u64 request_id) {
  xaios_storage_partition_plan_user_t plan;
  if (payload_length != sizeof(plan)) return -1;
  bytes_copy(&plan, payload, sizeof(plan));
  if (!partition_report_valid(&plan.report) || plan.changed > 1U ||
      plan.dry_run > 1U ||
      (plan.partition.identifier[0] != '\0' &&
       !partition_record_valid(&plan.partition))) {
    return -1;
  }
  if (json != 0) {
    int first = 1;
    if (json_envelope_begin(output, capacity, offset, request_id) != 0 ||
        append_partition_report_json(output, capacity, offset, &first,
                                     &plan.report) != 0 ||
        json_field_u64(output, capacity, offset, &first,
                       "resulting_partition_count",
                       plan.resulting_partition_count) != 0 ||
        json_field_u64(output, capacity, offset, &first, "affected_bytes",
                       plan.affected_bytes) != 0 ||
        json_field_u64(output, capacity, offset, &first, "changed",
                       plan.changed) != 0 ||
        json_field_u64(output, capacity, offset, &first, "dry_run",
                       plan.dry_run) != 0 ||
        json_field_prefix(output, capacity, offset, &first, "partition") != 0) {
      return -1;
    }
    if (plan.partition.identifier[0] == '\0') {
      if (append_text(output, capacity, offset, "null") != 0) return -1;
    } else if (append_partition_record_json(output, capacity, offset,
                                            &plan.partition) != 0) {
      return -1;
    }
    return json_envelope_end(output, capacity, offset);
  }
  if (append_partition_report_human(output, capacity, offset, &plan.report) !=
          0 ||
      human_field_u64(output, capacity, offset, "resulting_partition_count",
                      plan.resulting_partition_count) != 0 ||
      human_field_u64(output, capacity, offset, "affected_bytes",
                      plan.affected_bytes) != 0 ||
      human_field_u64(output, capacity, offset, "changed", plan.changed) != 0 ||
      human_field_u64(output, capacity, offset, "dry_run", plan.dry_run) != 0) {
    return -1;
  }
  if (plan.partition.identifier[0] != '\0' &&
      (append_text(output, capacity, offset, "partition=") != 0 ||
       append_text(output, capacity, offset, plan.partition.identifier) != 0 ||
       append_text(output, capacity, offset, " unique_guid=") != 0 ||
       append_text(output, capacity, offset, plan.partition.unique_guid) != 0 ||
       append_text(output, capacity, offset, " size_bytes=") != 0 ||
       append_u64(output, capacity, offset, plan.partition.size_bytes) != 0 ||
       append_char(output, capacity, offset, '\n') != 0)) {
    return -1;
  }
  return 0;
}

static const char *xai_fs_check_name(u32 state) {
  if (state == XAIOS_XAI_FS_CHECK_CLEAN) return "clean";
  if (state == XAIOS_XAI_FS_CHECK_REPAIRABLE) return "repairable";
  if (state == XAIOS_XAI_FS_CHECK_CORRUPT_UNREPAIRABLE) {
    return "corrupt_unrepairable";
  }
  if (state == XAIOS_XAI_FS_CHECK_REPAIRED) return "repaired";
  return "unknown";
}

int render_storage_volume_report(
    const void *payload, u64 payload_length, int json, char *output,
    u64 capacity, u64 *offset, u64 request_id) {
  xaios_xai_fs_admin_report_user_t report;
  if (payload_length != sizeof(report)) return -1;
  bytes_copy(&report, payload, sizeof(report));
  if (!fixed_string_valid(report.target, sizeof(report.target)) ||
      !fixed_string_terminated(report.partition_uuid,
                               sizeof(report.partition_uuid)) ||
      !fixed_string_terminated(report.volume_uuid,
                               sizeof(report.volume_uuid)) ||
      !fixed_string_terminated(report.bad_package_id,
                               sizeof(report.bad_package_id)) ||
      !storage_boolean_valid(report.first_superblock_valid) ||
      !storage_boolean_valid(report.second_superblock_valid) ||
      !storage_boolean_valid(report.copies_compatible) ||
      !storage_boolean_valid(report.discard_supported) ||
      !storage_boolean_valid(report.dry_run) ||
      report.check_state > XAIOS_XAI_FS_CHECK_REPAIRED) {
    return -1;
  }
  const char *check = xai_fs_check_name(report.check_state);
  if (json != 0) {
    int first = 1;
    return json_envelope_begin(output, capacity, offset, request_id) ||
           json_field_string(output, capacity, offset, &first, "target",
                             report.target) ||
           json_field_string(output, capacity, offset, &first,
                             "partition_uuid", report.partition_uuid) ||
           json_field_string(output, capacity, offset, &first, "volume_uuid",
                             report.volume_uuid) ||
           json_field_string(output, capacity, offset, &first, "check_state",
                             check) ||
           json_field_u64(output, capacity, offset, &first, "partition_bytes",
                          report.partition_bytes) ||
           json_field_u64(output, capacity, offset, &first, "volume_bytes",
                          report.volume_bytes) ||
           json_field_u64(output, capacity, offset, &first, "allocated_bytes",
                          report.allocated_bytes) ||
           json_field_u64(output, capacity, offset, &first, "free_bytes",
                          report.free_bytes) ||
           json_field_u64(output, capacity, offset, &first, "chunk_size",
                          report.chunk_size) ||
           json_field_u64(output, capacity, offset, &first, "generation",
                          report.generation) ||
           json_field_u64(output, capacity, offset, &first, "package_count",
                          report.package_count) ||
           json_field_u64(output, capacity, offset, &first, "active_packages",
                          report.active_packages) ||
           json_field_u64(output, capacity, offset, &first, "staging_packages",
                          report.staging_packages) ||
           json_field_u64(output, capacity, offset, &first,
                          "quarantined_packages",
                          report.quarantined_packages) ||
           json_field_u64(output, capacity, offset, &first, "checked_bytes",
                          report.checked_bytes) ||
           json_field_string(output, capacity, offset, &first,
                             "bad_package_id", report.bad_package_id) ||
           json_field_u64(output, capacity, offset, &first,
                          "bad_logical_offset", report.bad_logical_offset) ||
           json_field_u64(output, capacity, offset, &first,
                          "first_superblock_valid",
                          report.first_superblock_valid) ||
           json_field_u64(output, capacity, offset, &first,
                          "second_superblock_valid",
                          report.second_superblock_valid) ||
           json_field_u64(output, capacity, offset, &first,
                          "copies_compatible", report.copies_compatible) ||
           json_field_u64(output, capacity, offset, &first,
                          "discard_supported", report.discard_supported) ||
           json_field_u64(output, capacity, offset, &first, "dry_run",
                          report.dry_run) ||
           json_envelope_end(output, capacity, offset);
  }
  return append_text(output, capacity, offset, "target=") ||
         append_text(output, capacity, offset, report.target) ||
         append_text(output, capacity, offset, " partition_uuid=") ||
         append_text(output, capacity, offset, report.partition_uuid) ||
         append_text(output, capacity, offset, " volume_uuid=") ||
         append_text(output, capacity, offset, report.volume_uuid) ||
         append_text(output, capacity, offset, " check_state=") ||
         append_text(output, capacity, offset, check) ||
         append_char(output, capacity, offset, '\n') ||
         human_field_u64(output, capacity, offset, "partition_bytes",
                         report.partition_bytes) ||
         human_field_u64(output, capacity, offset, "volume_bytes",
                         report.volume_bytes) ||
         human_field_u64(output, capacity, offset, "allocated_bytes",
                         report.allocated_bytes) ||
         human_field_u64(output, capacity, offset, "free_bytes",
                         report.free_bytes) ||
         human_field_u64(output, capacity, offset, "chunk_size",
                         report.chunk_size) ||
         human_field_u64(output, capacity, offset, "generation",
                         report.generation) ||
         human_field_u64(output, capacity, offset, "package_count",
                         report.package_count) ||
         human_field_u64(output, capacity, offset, "active_packages",
                         report.active_packages) ||
         human_field_u64(output, capacity, offset, "staging_packages",
                         report.staging_packages) ||
         human_field_u64(output, capacity, offset, "quarantined_packages",
                         report.quarantined_packages) ||
         human_field_u64(output, capacity, offset, "checked_bytes",
                         report.checked_bytes) ||
         human_field_u64(output, capacity, offset, "first_superblock_valid",
                         report.first_superblock_valid) ||
         human_field_u64(output, capacity, offset, "second_superblock_valid",
                         report.second_superblock_valid) ||
         human_field_u64(output, capacity, offset, "copies_compatible",
                         report.copies_compatible) ||
         human_field_u64(output, capacity, offset, "discard_supported",
                         report.discard_supported) ||
         human_field_u64(output, capacity, offset, "dry_run", report.dry_run);
}

int render_mutation(const void *payload, int json, char *output,
                           u64 capacity, u64 *offset, u64 request_id) {
  xaios_control_mutation_payload_user_t value;
  bytes_copy(&value, payload, sizeof(value));
  if (json != 0) {
    int first = 1;
    return json_envelope_begin(output, capacity, offset, request_id) ||
           json_field_u64(output, capacity, offset, &first, "operation_id",
                          value.operation_id) ||
           json_field_u64(output, capacity, offset, &first, "generation",
                          value.generation) ||
           json_field_u64(output, capacity, offset, &first, "changed",
                          value.changed) ||
           json_envelope_end(output, capacity, offset);
  }
  return human_field_u64(output, capacity, offset, "operation_id",
                         value.operation_id) ||
         human_field_u64(output, capacity, offset, "generation",
                         value.generation) ||
         human_field_u64(output, capacity, offset, "changed", value.changed);
}

int render_model_cleanup(const void *payload, int json, char *output,
                                u64 capacity, u64 *offset, u64 request_id) {
  xaios_control_model_cleanup_report_user_t value;
  bytes_copy(&value, payload, sizeof(value));
  if (value.changed > 1U || value.reserved != 0U) return -1;
  if (json != 0) {
    int first = 1;
    return json_envelope_begin(output, capacity, offset, request_id) ||
           json_field_u64(output, capacity, offset, &first, "operation_id",
                          value.operation_id) ||
           json_field_u64(output, capacity, offset, &first, "generation",
                          value.generation) ||
           json_field_u64(output, capacity, offset, &first,
                          "reclaimed_bytes", value.reclaimed_bytes) ||
           json_field_u64(output, capacity, offset, &first, "changed",
                          value.changed) ||
           json_envelope_end(output, capacity, offset);
  }
  return human_field_u64(output, capacity, offset, "operation_id",
                         value.operation_id) ||
         human_field_u64(output, capacity, offset, "generation",
                         value.generation) ||
         human_field_u64(output, capacity, offset, "reclaimed_bytes",
                         value.reclaimed_bytes) ||
         human_field_u64(output, capacity, offset, "changed", value.changed);
}

static const char *maintenance_state_name(u32 state) {
  switch (state) {
  case XAIOS_MODEL_MAINTENANCE_IDLE: return "idle";
  case XAIOS_MODEL_MAINTENANCE_RUNNING: return "running";
  case XAIOS_MODEL_MAINTENANCE_PAUSED: return "paused";
  case XAIOS_MODEL_MAINTENANCE_COMPLETE: return "complete";
  case XAIOS_MODEL_MAINTENANCE_CANCELLED: return "cancelled";
  case XAIOS_MODEL_MAINTENANCE_FAILED: return "failed";
  default: return "unknown";
  }
}

int render_storage_scrub(const void *payload, int json, char *output,
                                u64 capacity, u64 *offset, u64 request_id) {
  xaios_control_storage_scrub_report_user_t report;
  bytes_copy(&report, payload, sizeof(report));
  if (report.state > XAIOS_MODEL_MAINTENANCE_FAILED ||
      report.checked_bytes > report.total_bytes) {
    return -1;
  }
  const char *state = maintenance_state_name(report.state);
  if (json != 0) {
    int first = 1;
    if (json_envelope_begin(output, capacity, offset, request_id) != 0 ||
        json_field_prefix(output, capacity, offset, &first, "volume_uuid") !=
            0 ||
        append_quoted_hex(output, capacity, offset, report.volume_uuid, 16U) !=
            0 ||
        json_field_string(output, capacity, offset, &first, "state", state) !=
            0 ||
        json_field_u64(output, capacity, offset, &first, "generation",
                       report.generation) != 0 ||
        json_field_u64(output, capacity, offset, &first, "package_index",
                       report.package_index) != 0 ||
        json_field_u64(output, capacity, offset, &first, "chunk_index",
                       report.chunk_index) != 0 ||
        json_field_u64(output, capacity, offset, &first, "checked_bytes",
                       report.checked_bytes) != 0 ||
        json_field_u64(output, capacity, offset, &first, "total_bytes",
                       report.total_bytes) != 0 ||
        json_field_u64(output, capacity, offset, &first, "error_count",
                       report.error_count) != 0 ||
        json_field_u64(output, capacity, offset, &first,
                       "bad_logical_offset", report.bad_logical_offset) != 0 ||
        json_field_prefix(output, capacity, offset, &first,
                          "bad_package_id") != 0 ||
        append_quoted_hex(output, capacity, offset, report.bad_package_id,
                          32U) != 0) {
      return -1;
    }
    return json_envelope_end(output, capacity, offset);
  }
  return append_text(output, capacity, offset, "volume_uuid=") ||
         append_hex(output, capacity, offset, report.volume_uuid, 16U) ||
         append_char(output, capacity, offset, '\n') ||
         append_text(output, capacity, offset, "state=") ||
         append_text(output, capacity, offset, state) ||
         append_char(output, capacity, offset, '\n') ||
         human_field_u64(output, capacity, offset, "generation",
                         report.generation) ||
         human_field_u64(output, capacity, offset, "package_index",
                         report.package_index) ||
         human_field_u64(output, capacity, offset, "chunk_index",
                         report.chunk_index) ||
         human_field_u64(output, capacity, offset, "checked_bytes",
                         report.checked_bytes) ||
         human_field_u64(output, capacity, offset, "total_bytes",
                         report.total_bytes) ||
         human_field_u64(output, capacity, offset, "error_count",
                         report.error_count) ||
         human_field_u64(output, capacity, offset, "bad_logical_offset",
                         report.bad_logical_offset);
}

int render_storage_trim(const void *payload, int json, char *output,
                               u64 capacity, u64 *offset, u64 request_id) {
  xaios_control_storage_trim_report_user_t report;
  bytes_copy(&report, payload, sizeof(report));
  if (report.state > XAIOS_MODEL_MAINTENANCE_FAILED || report.dry_run > 1U ||
      report.all_free > 1U || report.trimmed_bytes > report.eligible_bytes) {
    return -1;
  }
  const char *state = maintenance_state_name(report.state);
  if (json != 0) {
    int first = 1;
    return json_envelope_begin(output, capacity, offset, request_id) ||
           json_field_prefix(output, capacity, offset, &first,
                             "volume_uuid") ||
           append_quoted_hex(output, capacity, offset, report.volume_uuid,
                             sizeof(report.volume_uuid)) ||
           json_field_string(output, capacity, offset, &first, "state", state) ||
           json_field_u64(output, capacity, offset, &first, "generation",
                          report.generation) ||
           json_field_u64(output, capacity, offset, &first, "chunk_index",
                          report.chunk_index) ||
           json_field_u64(output, capacity, offset, &first, "cursor_offset",
                          report.cursor_offset) ||
           json_field_u64(output, capacity, offset, &first,
                          "requested_offset", report.requested_offset) ||
           json_field_u64(output, capacity, offset, &first,
                          "requested_length", report.requested_length) ||
           json_field_u64(output, capacity, offset, &first, "eligible_bytes",
                          report.eligible_bytes) ||
           json_field_u64(output, capacity, offset, &first, "processed_bytes",
                          report.trimmed_bytes) ||
           json_field_u64(output, capacity, offset, &first,
                          "processed_ranges", report.trimmed_ranges) ||
           json_field_u64(output, capacity, offset, &first, "error_count",
                          report.error_count) ||
           json_field_u64(output, capacity, offset, &first, "dry_run",
                          report.dry_run) ||
           json_field_u64(output, capacity, offset, &first, "all_free",
                          report.all_free) ||
           json_envelope_end(output, capacity, offset);
  }
  return append_text(output, capacity, offset, "volume_uuid=") ||
         append_hex(output, capacity, offset, report.volume_uuid,
                    sizeof(report.volume_uuid)) ||
         append_char(output, capacity, offset, '\n') ||
         append_text(output, capacity, offset, "state=") ||
         append_text(output, capacity, offset, state) ||
         append_char(output, capacity, offset, '\n') ||
         human_field_u64(output, capacity, offset, "generation",
                         report.generation) ||
         human_field_u64(output, capacity, offset, "chunk_index",
                         report.chunk_index) ||
         human_field_u64(output, capacity, offset, "cursor_offset",
                         report.cursor_offset) ||
         human_field_u64(output, capacity, offset, "requested_offset",
                         report.requested_offset) ||
         human_field_u64(output, capacity, offset, "requested_length",
                         report.requested_length) ||
         human_field_u64(output, capacity, offset, "eligible_bytes",
                         report.eligible_bytes) ||
         human_field_u64(output, capacity, offset, "processed_bytes",
                         report.trimmed_bytes) ||
         human_field_u64(output, capacity, offset, "processed_ranges",
                         report.trimmed_ranges) ||
         human_field_u64(output, capacity, offset, "error_count",
                         report.error_count) ||
         human_field_u64(output, capacity, offset, "dry_run", report.dry_run) ||
         human_field_u64(output, capacity, offset, "all_free",
                         report.all_free);
}
