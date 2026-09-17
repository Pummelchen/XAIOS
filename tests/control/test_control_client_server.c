#include <stdint.h>
#include <string.h>
#include <xaios_control_client.h>

#include "test_control_client_internal.h"

/* The fake control service the control client talks to: it enforces
   the same node, role and confirmation rules as the kernel surface,
   so the client's typed behaviour can be checked on the host. */

int xaios_control_query(const void *request_bytes, u64 request_size,
                        void *response, u64 response_size, u64 *out_size) {
  xaios_control_request_header_user_t request;
  if (request_size < sizeof(request)) return -1;
  tcc_copy_bytes(&request, request_bytes, sizeof(request));
  if (request.node_id != 0U) {
    return tcc_respond_status(&request, XAIOS_CONTROL_STATUS_UNKNOWN_NODE,
                          response, response_size, out_size);
  }
  if (request.principal_role < XAIOS_CONTROL_ROLE_OBSERVER ||
      request.principal_role > XAIOS_CONTROL_ROLE_ADMIN) {
    return tcc_respond_status(&request, XAIOS_CONTROL_STATUS_DENIED, response,
                          response_size, out_size);
  }
  if (request.operation == XAIOS_CONTROL_OP_STORAGE_REPAIR_FROM_REPLICA) {
    xaios_control_storage_replica_repair_request_payload_user_t repair;
    if (request_size != sizeof(request) + sizeof(repair)) return -1;
    tcc_copy_bytes(&repair, (const unsigned char *)request_bytes + sizeof(request),
               sizeof(repair));
    if (strcmp(repair.target, "/dev/vblk5p1") != 0 ||
        strcmp(repair.replica, "/dev/vblk6p1") != 0 ||
        strcmp(repair.confirmation,
               "aaaaaaaa-bbbb-5ccc-8ddd-eeeeeeeeeeee") != 0 ||
        strcmp(repair.package_id,
               "da3246a8df558dd6d9da385adb58976cd964a76d413f9a5f395f65a861e1333f") !=
            0 ||
        strcmp(repair.actor, "ci-admin") != 0 || repair.operation_id != 606U) {
      return -1;
    }
  }
  if (request.operation == XAIOS_CONTROL_OP_CONFIG_APPLY &&
      request.principal_role < XAIOS_CONTROL_ROLE_OPERATOR) {
    return tcc_respond_status(&request, XAIOS_CONTROL_STATUS_DENIED, response,
                          response_size, out_size);
  }
  if ((request.operation == XAIOS_CONTROL_OP_AUTH_KEY_ADD ||
       request.operation == XAIOS_CONTROL_OP_AUTH_KEY_REMOVE ||
       request.operation == XAIOS_CONTROL_OP_AUTH_HOST_KEY_ROTATE ||
       request.operation == XAIOS_CONTROL_OP_MODEL_VERIFY ||
       request.operation == XAIOS_CONTROL_OP_MODEL_REGISTER ||
       request.operation == XAIOS_CONTROL_OP_MODEL_ACTIVATE ||
       request.operation == XAIOS_CONTROL_OP_MODEL_CLEANUP ||
       request.operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_CREATE ||
       request.operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_DELETE ||
       request.operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_RESIZE ||
       request.operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_REPAIR ||
       request.operation == XAIOS_CONTROL_OP_STORAGE_REPAIR_FROM_REPLICA ||
       request.operation == XAIOS_CONTROL_OP_STORAGE_SCRUB_START ||
       request.operation == XAIOS_CONTROL_OP_STORAGE_SCRUB_PAUSE ||
       request.operation == XAIOS_CONTROL_OP_STORAGE_SCRUB_RESUME ||
       request.operation == XAIOS_CONTROL_OP_STORAGE_SCRUB_CANCEL ||
       request.operation == XAIOS_CONTROL_OP_STORAGE_TRIM_CANCEL) &&
      request.principal_role < XAIOS_CONTROL_ROLE_ADMIN) {
    return tcc_respond_status(&request, XAIOS_CONTROL_STATUS_DENIED, response,
                          response_size, out_size);
  }

  if (request.operation == XAIOS_CONTROL_OP_VERSION) {
    xaios_control_version_payload_user_t value;
    xaios_memzero(&value, sizeof(value));
    strcpy(value.product_version, "9.9.9");
    strcpy(value.build_identifier, "host-test");
    strcpy(value.git_commit, "abc123");
    strcpy(value.architecture, "aarch64");
    strcpy(value.build_mode, "development");
    value.kernel_abi_version = 1U;
    value.control_protocol_version = 1U;
    value.model_package_version = 2U;
    value.xai_fs_version = 1U;
    return tcc_respond(&request, XAIOS_CONTROL_PAYLOAD_VERSION, &value,
                   sizeof(value), response, response_size, out_size);
  }
  if (request.operation == XAIOS_CONTROL_OP_STATUS) {
    xaios_control_status_payload_user_t value;
    xaios_memzero(&value, sizeof(value));
    value.uptime_ns = 10ULL;
    value.online_cpus = 4U;
    value.readiness_state = XAIOS_CONTROL_STATE_DEGRADED;
    value.model_state = XAIOS_CONTROL_STATE_FIXTURE_ONLY;
    value.queue_depth = XAIOS_CONTROL_UNKNOWN_U64;
    value.active_requests = XAIOS_CONTROL_UNKNOWN_U64;
    return tcc_respond(&request, XAIOS_CONTROL_PAYLOAD_STATUS, &value,
                   sizeof(value), response, response_size, out_size);
  }
  if (request.operation == XAIOS_CONTROL_OP_HEALTH) {
    xaios_control_health_payload_user_t value;
    xaios_memzero(&value, sizeof(value));
    value.overall_state = XAIOS_CONTROL_STATE_DEGRADED;
    value.model_readiness = XAIOS_CONTROL_STATE_FIXTURE_ONLY;
    return tcc_respond(&request, XAIOS_CONTROL_PAYLOAD_HEALTH, &value,
                   sizeof(value), response, response_size, out_size);
  }
  if (request.operation == XAIOS_CONTROL_OP_CAPABILITIES) {
    xaios_control_capabilities_payload_user_t value;
    xaios_memzero(&value, sizeof(value));
    value.ssh = XAIOS_CONTROL_STATE_AVAILABLE;
    value.model_v2 = XAIOS_CONTROL_STATE_INTERFACE_ONLY;
    value.real_model_inference = XAIOS_CONTROL_STATE_UNSUPPORTED;
    return tcc_respond(&request, XAIOS_CONTROL_PAYLOAD_CAPABILITIES, &value,
                   sizeof(value), response, response_size, out_size);
  }
  if (request.operation == XAIOS_CONTROL_OP_HARDWARE) {
    xaios_control_hardware_payload_user_t value;
    xaios_memzero(&value, sizeof(value));
    strcpy(value.architecture, "aarch64");
    strcpy(value.cpu_vendor, "unknown");
    strcpy(value.cpu_model, "unknown");
    strcpy(value.selected_backend, "fixture-only");
    value.core_count = 4U;
    value.neon = XAIOS_CONTROL_STATE_UNKNOWN;
    return tcc_respond(&request, XAIOS_CONTROL_PAYLOAD_HARDWARE, &value,
                   sizeof(value), response, response_size, out_size);
  }
  if (request.operation == XAIOS_CONTROL_OP_METRICS) {
    xaios_control_metrics_payload_user_t value;
    memset(&value, 0xff, sizeof(value));
    value.uptime_ns = 10ULL;
    value.control_requests = 1ULL;
    value.per_worker_health = XAIOS_CONTROL_STATE_UNKNOWN;
    return tcc_respond(&request, XAIOS_CONTROL_PAYLOAD_METRICS, &value,
                   sizeof(value), response, response_size, out_size);
  }
  if (request.operation == XAIOS_CONTROL_OP_LOGS) {
    struct logs_response {
      xaios_control_logs_payload_user_t metadata;
      char records[96];
    } value;
    static const char record[] =
        "seq=7 time=unknown level=info component=test request_id=unknown "
        "message=ok\n";
    xaios_memzero(&value, sizeof(value));
    value.metadata.next_cursor = 7ULL;
    value.metadata.latest_cursor = 7ULL;
    value.metadata.record_count = 1U;
    tcc_copy_bytes(value.records, record, sizeof(record) - 1ULL);
    return tcc_respond(&request, XAIOS_CONTROL_PAYLOAD_LOGS, &value,
                   sizeof(value.metadata) + sizeof(record) - 1ULL, response,
                   response_size, out_size);
  }
  if (request.operation >= XAIOS_CONTROL_OP_CONFIG_SHOW &&
      request.operation <= XAIOS_CONTROL_OP_CONFIG_APPLY) {
    xaios_control_config_payload_user_t value;
    xaios_memzero(&value, sizeof(value));
    value.config.magic = XAIOS_ADMIN_CONFIG_MAGIC;
    value.config.version = XAIOS_ADMIN_SCHEMA_VERSION;
    value.config.size = (u16)sizeof(value.config);
    value.config.generation = 7ULL;
    value.config.max_connections = 4U;
    value.config.max_channels_per_connection = 2U;
    value.config.max_auth_attempts = 5U;
    value.config.command_rate_per_minute = 60U;
    value.config.password_auth = XAIOS_ADMIN_PASSWORD_DISABLED;
    value.change_mask = request.operation == XAIOS_CONTROL_OP_CONFIG_SHOW
                            ? 0U
                            : 8U;
    value.validated = 1U;
    return tcc_respond(&request, XAIOS_CONTROL_PAYLOAD_CONFIG, &value,
                   sizeof(value), response, response_size, out_size);
  }
  if (request.operation >= XAIOS_CONTROL_OP_AUTH_KEY_LIST &&
      request.operation <= XAIOS_CONTROL_OP_AUTH_KEY_REMOVE) {
    struct auth_response {
      xaios_control_auth_keys_payload_user_t metadata;
      xaios_admin_key_view_user_t key;
    } value;
    xaios_memzero(&value, sizeof(value));
    value.metadata.generation = 4ULL;
    value.metadata.key_count = 1U;
    value.metadata.revoked_count =
        request.operation == XAIOS_CONTROL_OP_AUTH_KEY_REMOVE ? 1U : 0U;
    for (u32 i = 0U; i < sizeof(value.key.fingerprint); ++i) {
      value.key.fingerprint[i] = (unsigned char)i;
    }
    strcpy(value.key.principal, "ci-admin");
    value.key.role = XAIOS_CONTROL_ROLE_ADMIN;
    return tcc_respond(&request, XAIOS_CONTROL_PAYLOAD_AUTH_KEYS, &value,
                   sizeof(value), response, response_size, out_size);
  }
  if (request.operation == XAIOS_CONTROL_OP_AUTH_HOST_KEY_ROTATE) {
    xaios_control_mutation_payload_user_t value;
    xaios_memzero(&value, sizeof(value));
    value.operation_id = 44ULL;
    value.generation = 8ULL;
    value.changed = 1U;
    return tcc_respond(&request, XAIOS_CONTROL_PAYLOAD_MUTATION, &value,
                   sizeof(value), response, response_size, out_size);
  }
  if (request.operation == XAIOS_CONTROL_OP_MODEL_VERIFY ||
      request.operation == XAIOS_CONTROL_OP_MODEL_REGISTER ||
      request.operation == XAIOS_CONTROL_OP_MODEL_ACTIVATE) {
    xaios_control_mutation_payload_user_t value;
    xaios_memzero(&value, sizeof(value));
    value.generation = request.operation == XAIOS_CONTROL_OP_MODEL_REGISTER
                           ? 9ULL
                           : (request.operation == XAIOS_CONTROL_OP_MODEL_VERIFY
                                  ? 10ULL
                                  : 11ULL);
    if (request.operation == XAIOS_CONTROL_OP_MODEL_REGISTER) {
      value.operation_id = 46ULL;
      value.changed = 1U;
    } else if (request.operation == XAIOS_CONTROL_OP_MODEL_ACTIVATE) {
      value.operation_id = 47ULL;
      value.changed = 1U;
    }
    return tcc_respond(&request, XAIOS_CONTROL_PAYLOAD_MUTATION, &value,
                   sizeof(value), response, response_size, out_size);
  }
  if (request.operation == XAIOS_CONTROL_OP_MODEL_CLEANUP) {
    xaios_control_model_cleanup_report_user_t value;
    xaios_memzero(&value, sizeof(value));
    value.operation_id = 49ULL;
    value.generation = 13ULL;
    value.reclaimed_bytes = 4194304ULL;
    value.changed = 1U;
    return tcc_respond(&request, XAIOS_CONTROL_PAYLOAD_MODEL_CLEANUP_REPORT, &value,
                   sizeof(value), response, response_size, out_size);
  }
  if (request.operation == XAIOS_CONTROL_OP_STORAGE_DEVICE_LIST ||
      request.operation == XAIOS_CONTROL_OP_STORAGE_DEVICE_SHOW) {
    struct storage_device_response {
      xaios_control_storage_devices_payload_user_t metadata;
      xaios_control_storage_device_record_user_t record;
    } value;
    xaios_memzero(&value, sizeof(value));
    value.metadata.record_count = 1U;
    value.metadata.total_count = 1U;
    strcpy(value.record.identifier, "/dev/vblk4");
    strcpy(value.record.backend, "virtio-blk");
    value.record.capacity_bytes = 137438953472ULL;
    value.record.capacity_logical_sectors = 268435456ULL;
    value.record.logical_sector_size = 512ULL;
    value.record.physical_block_size = 4096ULL;
    value.record.max_transfer_bytes = 512ULL;
    value.record.flush_supported = 1U;
    value.record.discard_supported = 1U;
    return tcc_respond(&request, XAIOS_CONTROL_PAYLOAD_STORAGE_DEVICES, &value,
                   sizeof(value), response, response_size, out_size);
  }
  if (request.operation == XAIOS_CONTROL_OP_STORAGE_FILESYSTEM_LIST ||
      request.operation == XAIOS_CONTROL_OP_STORAGE_FILESYSTEM_SHOW) {
    struct storage_filesystem_response {
      xaios_control_storage_filesystems_payload_user_t metadata;
      xaios_control_storage_filesystem_record_user_t record;
    } value;
    xaios_memzero(&value, sizeof(value));
    value.metadata.record_count = 1U;
    value.metadata.total_count = 1U;
    strcpy(value.record.mount_path, "/models");
    strcpy(value.record.filesystem, "xaiFS");
    strcpy(value.record.device_identifier, "/dev/vblk4");
    value.record.total_bytes = 137438953472ULL;
    value.record.allocated_bytes = 2097152ULL;
    value.record.free_bytes = value.record.total_bytes -
                              value.record.allocated_bytes;
    value.record.generation = 9ULL;
    value.record.block_size = 4096ULL;
    value.record.package_count = 2ULL;
    value.record.active_packages = 1ULL;
    value.record.staging_packages = 1ULL;
    value.record.format_version = 1U;
    value.record.mounted = 1U;
    value.record.staging_writable = 1U;
    return tcc_respond(&request, XAIOS_CONTROL_PAYLOAD_STORAGE_FILESYSTEMS, &value,
                   sizeof(value), response, response_size, out_size);
  }
  if (request.operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_LIST ||
      request.operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_VERIFY) {
    struct partition_response {
      xaios_control_storage_partitions_payload_user_t metadata;
      xaios_storage_partition_record_user_t record;
    } value;
    xaios_memzero(&value, sizeof(value));
    strcpy(value.metadata.report.device_identifier, "/dev/vblk5");
    strcpy(value.metadata.report.disk_guid,
           "11111111-2222-5333-8444-555555555555");
    value.metadata.report.capacity_bytes = 8589934592ULL;
    value.metadata.report.logical_sector_size = 512ULL;
    value.metadata.report.first_usable_lba = 34ULL;
    value.metadata.report.last_usable_lba = 16777182ULL;
    value.metadata.report.partition_count = 1ULL;
    value.metadata.report.primary_valid = 1U;
    value.metadata.report.backup_valid = 1U;
    value.metadata.report.copies_consistent = 1U;
    value.metadata.report.selected_copy = 1U;
    value.metadata.report.mutation_allowed = 1U;
    if (request.operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_LIST) {
      value.metadata.record_count = 1U;
      value.metadata.total_count = 1U;
      strcpy(value.record.identifier, "/dev/vblk5p1");
      strcpy(value.record.name, "models");
      strcpy(value.record.type_guid,
             "1f3b2d7a-6e91-4a52-9c7d-5841494f5302");
      strcpy(value.record.unique_guid,
             "aaaaaaaa-bbbb-5ccc-8ddd-eeeeeeeeeeee");
      value.record.first_lba = 2048ULL;
      value.record.last_lba = 4196351ULL;
      value.record.size_bytes = 2147483648ULL;
      value.record.known_type = XAIOS_STORAGE_PARTITION_MODEL;
    }
    u64 bytes = sizeof(value.metadata) +
                (u64)value.metadata.record_count * sizeof(value.record);
    return tcc_respond(&request, XAIOS_CONTROL_PAYLOAD_STORAGE_PARTITIONS, &value,
                   bytes, response, response_size, out_size);
  }
  if (request.operation >= XAIOS_CONTROL_OP_STORAGE_PARTITION_PLAN_CREATE &&
      request.operation <= XAIOS_CONTROL_OP_STORAGE_PARTITION_REPAIR) {
    xaios_storage_partition_plan_user_t value;
    xaios_memzero(&value, sizeof(value));
    strcpy(value.report.device_identifier, "/dev/vblk5");
    strcpy(value.report.disk_guid,
           "11111111-2222-5333-8444-555555555555");
    value.report.capacity_bytes = 8589934592ULL;
    value.report.logical_sector_size = 512ULL;
    value.report.first_usable_lba = 34ULL;
    value.report.last_usable_lba = 16777182ULL;
    value.report.partition_count = 1ULL;
    value.report.primary_valid = 1U;
    value.report.backup_valid = 1U;
    value.report.copies_consistent = 1U;
    value.report.selected_copy = 1U;
    value.report.mutation_allowed = 1U;
    value.resulting_partition_count = 1ULL;
    value.changed = 1U;
    value.dry_run =
        request.operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_PLAN_CREATE ||
                request.operation ==
                    XAIOS_CONTROL_OP_STORAGE_PARTITION_PLAN_DELETE ||
                request.operation ==
                    XAIOS_CONTROL_OP_STORAGE_PARTITION_PLAN_RESIZE
            ? 1U
            : 0U;
    if (request.operation != XAIOS_CONTROL_OP_STORAGE_PARTITION_REPAIR) {
      strcpy(value.partition.identifier, "/dev/vblk5p1");
      strcpy(value.partition.name, "models");
      strcpy(value.partition.type_guid,
             "1f3b2d7a-6e91-4a52-9c7d-5841494f5302");
      strcpy(value.partition.unique_guid,
             "aaaaaaaa-bbbb-5ccc-8ddd-eeeeeeeeeeee");
      value.partition.first_lba = 2048ULL;
      value.partition.last_lba = 4196351ULL;
      value.partition.size_bytes = 2147483648ULL;
      value.partition.known_type = XAIOS_STORAGE_PARTITION_MODEL;
      value.affected_bytes = value.partition.size_bytes;
    }
    return tcc_respond(&request, XAIOS_CONTROL_PAYLOAD_STORAGE_PARTITION_PLAN,
                   &value, sizeof(value), response, response_size, out_size);
  }
  if ((request.operation >= XAIOS_CONTROL_OP_STORAGE_FORMAT_PLAN &&
       request.operation <= XAIOS_CONTROL_OP_STORAGE_FS_RESIZE) ||
      request.operation == XAIOS_CONTROL_OP_STORAGE_REPAIR_FROM_REPLICA) {
    xaios_xai_fs_admin_report_user_t value;
    xaios_memzero(&value, sizeof(value));
    strcpy(value.target, request.operation == XAIOS_CONTROL_OP_STORAGE_UNMOUNT
                             ? "/models"
                             : "/dev/vblk5p1");
    strcpy(value.partition_uuid,
           "aaaaaaaa-bbbb-5ccc-8ddd-eeeeeeeeeeee");
    strcpy(value.volume_uuid,
           "bbbbbbbb-cccc-5ddd-8eee-ffffffffffff");
    value.partition_bytes = 2147483648ULL;
    value.volume_bytes = 2147483648ULL;
    value.allocated_bytes = 1048576ULL;
    value.free_bytes = value.volume_bytes - value.allocated_bytes;
    value.chunk_size = 4194304ULL;
    value.generation = request.operation == XAIOS_CONTROL_OP_STORAGE_FS_RESIZE
                           ? 2ULL
                           : 1ULL;
    value.first_superblock_valid = 1U;
    value.second_superblock_valid = 1U;
    value.copies_compatible = 1U;
    value.check_state =
        request.operation == XAIOS_CONTROL_OP_STORAGE_FS_REPAIR ||
                request.operation == XAIOS_CONTROL_OP_STORAGE_REPAIR_FROM_REPLICA
            ? XAIOS_XAI_FS_CHECK_REPAIRED
            : XAIOS_XAI_FS_CHECK_CLEAN;
    value.discard_supported = 1U;
    value.dry_run =
        request.operation == XAIOS_CONTROL_OP_STORAGE_FORMAT_PLAN ||
                request.operation ==
                    XAIOS_CONTROL_OP_STORAGE_FS_RESIZE_PLAN
            ? 1U
            : 0U;
    return tcc_respond(&request, XAIOS_CONTROL_PAYLOAD_STORAGE_VOLUME_REPORT,
                   &value, sizeof(value), response, response_size, out_size);
  }
  if (request.operation >= XAIOS_CONTROL_OP_STORAGE_SCRUB_START &&
      request.operation <= XAIOS_CONTROL_OP_STORAGE_SCRUB_CANCEL) {
    xaios_control_storage_scrub_report_user_t value;
    xaios_memzero(&value, sizeof(value));
    for (u32 i = 0U; i < sizeof(value.volume_uuid); ++i) {
      value.volume_uuid[i] = (unsigned char)(0x80U + i);
    }
    value.generation = 12ULL;
    value.total_bytes = 4194304ULL;
    value.checked_bytes = 2097152ULL;
    value.bad_logical_offset = XAIOS_CONTROL_UNKNOWN_U64;
    if (request.operation == XAIOS_CONTROL_OP_STORAGE_SCRUB_STATUS) {
      value.state = XAIOS_MODEL_MAINTENANCE_COMPLETE;
      value.checked_bytes = value.total_bytes;
    } else if (request.operation == XAIOS_CONTROL_OP_STORAGE_SCRUB_PAUSE) {
      value.state = XAIOS_MODEL_MAINTENANCE_PAUSED;
    } else if (request.operation == XAIOS_CONTROL_OP_STORAGE_SCRUB_CANCEL) {
      value.state = XAIOS_MODEL_MAINTENANCE_CANCELLED;
    } else {
      value.state = XAIOS_MODEL_MAINTENANCE_RUNNING;
    }
    return tcc_respond(&request, XAIOS_CONTROL_PAYLOAD_STORAGE_SCRUB_REPORT,
                   &value, sizeof(value), response, response_size, out_size);
  }
  if (request.operation >= XAIOS_CONTROL_OP_STORAGE_TRIM_START &&
      request.operation <= XAIOS_CONTROL_OP_STORAGE_TRIM_CANCEL) {
    xaios_control_storage_trim_request_payload_user_t query;
    xaios_control_storage_trim_report_user_t value;
    if (request.payload_type != XAIOS_CONTROL_PAYLOAD_STORAGE_TRIM_REQUEST ||
        request.payload_length != sizeof(query) ||
        request_size != sizeof(request) + sizeof(query)) {
      return -1;
    }
    tcc_copy_bytes(&query, (const unsigned char *)request_bytes + sizeof(request),
               sizeof(query));
    xaios_memzero(&value, sizeof(value));
    for (u32 i = 0U; i < sizeof(value.volume_uuid); ++i) {
      value.volume_uuid[i] = (unsigned char)(0x90U + i);
    }
    value.generation = 12ULL;
    value.requested_offset = query.offset;
    value.requested_length = query.length;
    value.eligible_bytes = 134217728ULL;
    value.trimmed_bytes = 67108864ULL;
    value.trimmed_ranges = 1ULL;
    value.dry_run = query.dry_run;
    value.all_free = query.all_free;
    if (request.operation == XAIOS_CONTROL_OP_STORAGE_TRIM_STATUS) {
      value.state = XAIOS_MODEL_MAINTENANCE_COMPLETE;
      value.trimmed_bytes = value.eligible_bytes;
    } else if (request.operation == XAIOS_CONTROL_OP_STORAGE_TRIM_CANCEL) {
      value.state = XAIOS_MODEL_MAINTENANCE_CANCELLED;
    } else {
      value.state = XAIOS_MODEL_MAINTENANCE_RUNNING;
    }
    return tcc_respond(&request, XAIOS_CONTROL_PAYLOAD_STORAGE_TRIM_REPORT, &value,
                   sizeof(value), response, response_size, out_size);
  }
  if (request.operation == XAIOS_CONTROL_OP_AUDIT_SHOW) {
    struct audit_response {
      xaios_control_audit_payload_user_t metadata;
      xaios_admin_audit_record_user_t record;
    } value;
    xaios_memzero(&value, sizeof(value));
    value.metadata.next_sequence = 3ULL;
    value.metadata.latest_sequence = 3ULL;
    value.metadata.record_count = 1U;
    value.record.sequence = 3ULL;
    value.record.operation_id = 42ULL;
    strcpy(value.record.principal, "ci-admin");
    strcpy(value.record.operation, "config.apply");
    value.record.role = XAIOS_CONTROL_ROLE_ADMIN;
    value.record.result = 0U;
    memset(value.record.object_hash, 0xab, sizeof(value.record.object_hash));
    return tcc_respond(&request, XAIOS_CONTROL_PAYLOAD_AUDIT, &value,
                   sizeof(value), response, response_size, out_size);
  }
  return -1;
}
