#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <xaios_control_client.h>

static u64 g_clock_ns;

u64 xaios_strlen(const char *text) {
  u64 length = 0;
  while (text != 0 && text[length] != '\0') ++length;
  return length;
}

void xaios_memzero(void *buffer, u64 size) {
  unsigned char *bytes = (unsigned char *)buffer;
  for (u64 i = 0; i < size; ++i) bytes[i] = 0;
}

u64 xaios_clock_nanos(void) {
  g_clock_ns += 1000000ULL;
  return g_clock_ns;
}

static void copy_bytes(void *dst, const void *src, u64 size) {
  unsigned char *out = (unsigned char *)dst;
  const unsigned char *in = (const unsigned char *)src;
  for (u64 i = 0; i < size; ++i) out[i] = in[i];
}

static int respond(const xaios_control_request_header_user_t *request,
                   u32 payload_type, const void *payload, u64 payload_size,
                   void *response, u64 response_size, u64 *out_size) {
  xaios_control_response_header_user_t header;
  if (response_size < sizeof(header) + payload_size) return -1;
  xaios_memzero(&header, sizeof(header));
  header.magic = XAIOS_CONTROL_MAGIC;
  header.version = XAIOS_CONTROL_VERSION;
  header.header_size = (u16)sizeof(header);
  header.operation = request->operation;
  header.status = XAIOS_CONTROL_STATUS_OK;
  header.request_id = request->request_id;
  header.payload_type = payload_type;
  header.payload_length = payload_size;
  copy_bytes(response, &header, sizeof(header));
  copy_bytes((unsigned char *)response + sizeof(header), payload, payload_size);
  *out_size = sizeof(header) + payload_size;
  return 0;
}

static int respond_status(const xaios_control_request_header_user_t *request,
                          u32 status, void *response, u64 response_size,
                          u64 *out_size) {
  xaios_control_response_header_user_t header;
  if (response_size < sizeof(header)) return -1;
  xaios_memzero(&header, sizeof(header));
  header.magic = XAIOS_CONTROL_MAGIC;
  header.version = XAIOS_CONTROL_VERSION;
  header.header_size = (u16)sizeof(header);
  header.operation = request->operation;
  header.status = status;
  header.request_id = request->request_id;
  copy_bytes(response, &header, sizeof(header));
  *out_size = sizeof(header);
  return 0;
}

int xaios_control_query(const void *request_bytes, u64 request_size,
                        void *response, u64 response_size, u64 *out_size) {
  xaios_control_request_header_user_t request;
  if (request_size < sizeof(request)) return -1;
  copy_bytes(&request, request_bytes, sizeof(request));
  if (request.node_id != 0U) {
    return respond_status(&request, XAIOS_CONTROL_STATUS_UNKNOWN_NODE,
                          response, response_size, out_size);
  }
  if (request.principal_role < XAIOS_CONTROL_ROLE_OBSERVER ||
      request.principal_role > XAIOS_CONTROL_ROLE_ADMIN) {
    return respond_status(&request, XAIOS_CONTROL_STATUS_DENIED, response,
                          response_size, out_size);
  }
  if (request.operation == XAIOS_CONTROL_OP_STORAGE_REPAIR_FROM_REPLICA) {
    xaios_control_storage_replica_repair_request_payload_user_t repair;
    if (request_size != sizeof(request) + sizeof(repair)) return -1;
    copy_bytes(&repair, (const unsigned char *)request_bytes + sizeof(request),
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
    return respond_status(&request, XAIOS_CONTROL_STATUS_DENIED, response,
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
    return respond_status(&request, XAIOS_CONTROL_STATUS_DENIED, response,
                          response_size, out_size);
  }

  if (request.operation == XAIOS_CONTROL_OP_VERSION) {
    xaios_control_version_payload_user_t value;
    xaios_memzero(&value, sizeof(value));
    strcpy(value.build_identifier, "host-test");
    strcpy(value.git_commit, "abc123");
    strcpy(value.architecture, "aarch64");
    strcpy(value.build_mode, "development");
    value.kernel_abi_version = 1U;
    value.control_protocol_version = 1U;
    value.model_package_version = 2U;
    value.model_volume_version = 1U;
    return respond(&request, XAIOS_CONTROL_PAYLOAD_VERSION, &value,
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
    return respond(&request, XAIOS_CONTROL_PAYLOAD_STATUS, &value,
                   sizeof(value), response, response_size, out_size);
  }
  if (request.operation == XAIOS_CONTROL_OP_HEALTH) {
    xaios_control_health_payload_user_t value;
    xaios_memzero(&value, sizeof(value));
    value.overall_state = XAIOS_CONTROL_STATE_DEGRADED;
    value.model_readiness = XAIOS_CONTROL_STATE_FIXTURE_ONLY;
    return respond(&request, XAIOS_CONTROL_PAYLOAD_HEALTH, &value,
                   sizeof(value), response, response_size, out_size);
  }
  if (request.operation == XAIOS_CONTROL_OP_CAPABILITIES) {
    xaios_control_capabilities_payload_user_t value;
    xaios_memzero(&value, sizeof(value));
    value.ssh = XAIOS_CONTROL_STATE_AVAILABLE;
    value.model_v2 = XAIOS_CONTROL_STATE_INTERFACE_ONLY;
    value.real_model_inference = XAIOS_CONTROL_STATE_UNSUPPORTED;
    return respond(&request, XAIOS_CONTROL_PAYLOAD_CAPABILITIES, &value,
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
    return respond(&request, XAIOS_CONTROL_PAYLOAD_HARDWARE, &value,
                   sizeof(value), response, response_size, out_size);
  }
  if (request.operation == XAIOS_CONTROL_OP_METRICS) {
    xaios_control_metrics_payload_user_t value;
    memset(&value, 0xff, sizeof(value));
    value.uptime_ns = 10ULL;
    value.control_requests = 1ULL;
    value.per_worker_health = XAIOS_CONTROL_STATE_UNKNOWN;
    return respond(&request, XAIOS_CONTROL_PAYLOAD_METRICS, &value,
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
    copy_bytes(value.records, record, sizeof(record) - 1ULL);
    return respond(&request, XAIOS_CONTROL_PAYLOAD_LOGS, &value,
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
    return respond(&request, XAIOS_CONTROL_PAYLOAD_CONFIG, &value,
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
    return respond(&request, XAIOS_CONTROL_PAYLOAD_AUTH_KEYS, &value,
                   sizeof(value), response, response_size, out_size);
  }
  if (request.operation == XAIOS_CONTROL_OP_AUTH_HOST_KEY_ROTATE) {
    xaios_control_mutation_payload_user_t value;
    xaios_memzero(&value, sizeof(value));
    value.operation_id = 44ULL;
    value.generation = 8ULL;
    value.changed = 1U;
    return respond(&request, XAIOS_CONTROL_PAYLOAD_MUTATION, &value,
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
    return respond(&request, XAIOS_CONTROL_PAYLOAD_MUTATION, &value,
                   sizeof(value), response, response_size, out_size);
  }
  if (request.operation == XAIOS_CONTROL_OP_MODEL_CLEANUP) {
    xaios_control_model_cleanup_report_user_t value;
    xaios_memzero(&value, sizeof(value));
    value.operation_id = 49ULL;
    value.generation = 13ULL;
    value.reclaimed_bytes = 4194304ULL;
    value.changed = 1U;
    return respond(&request, XAIOS_CONTROL_PAYLOAD_MODEL_CLEANUP_REPORT, &value,
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
    return respond(&request, XAIOS_CONTROL_PAYLOAD_STORAGE_DEVICES, &value,
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
    strcpy(value.record.filesystem, "ModelFS");
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
    return respond(&request, XAIOS_CONTROL_PAYLOAD_STORAGE_FILESYSTEMS, &value,
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
    return respond(&request, XAIOS_CONTROL_PAYLOAD_STORAGE_PARTITIONS, &value,
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
    return respond(&request, XAIOS_CONTROL_PAYLOAD_STORAGE_PARTITION_PLAN,
                   &value, sizeof(value), response, response_size, out_size);
  }
  if ((request.operation >= XAIOS_CONTROL_OP_STORAGE_FORMAT_PLAN &&
       request.operation <= XAIOS_CONTROL_OP_STORAGE_FS_RESIZE) ||
      request.operation == XAIOS_CONTROL_OP_STORAGE_REPAIR_FROM_REPLICA) {
    xaios_model_volume_admin_report_user_t value;
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
            ? XAIOS_MODEL_VOLUME_CHECK_REPAIRED
            : XAIOS_MODEL_VOLUME_CHECK_CLEAN;
    value.discard_supported = 1U;
    value.dry_run =
        request.operation == XAIOS_CONTROL_OP_STORAGE_FORMAT_PLAN ||
                request.operation ==
                    XAIOS_CONTROL_OP_STORAGE_FS_RESIZE_PLAN
            ? 1U
            : 0U;
    return respond(&request, XAIOS_CONTROL_PAYLOAD_STORAGE_VOLUME_REPORT,
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
    return respond(&request, XAIOS_CONTROL_PAYLOAD_STORAGE_SCRUB_REPORT,
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
    copy_bytes(&query, (const unsigned char *)request_bytes + sizeof(request),
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
    return respond(&request, XAIOS_CONTROL_PAYLOAD_STORAGE_TRIM_REPORT, &value,
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
    return respond(&request, XAIOS_CONTROL_PAYLOAD_AUDIT, &value,
                   sizeof(value), response, response_size, out_size);
  }
  return -1;
}

static int contains(const char *text, const char *needle) {
  return strstr(text, needle) != NULL;
}

static int run_case(const char *command, int expected_result,
                    const char *marker) {
  char output[XAIOS_CONTROL_MAX_RESPONSE_BYTES];
  u64 output_size = 0ULL;
  int result = xaios_control_run(command, output, sizeof(output), &output_size);
  if (result != expected_result || output_size == 0ULL ||
      !contains(output, marker)) {
    fprintf(stderr, "control client case failed: %s rc=%d output=%s\n",
            command, result, output);
    return -1;
  }
  return 0;
}

static int run_case_as(const char *command, u32 role, const char *principal,
                       int expected_result, const char *marker) {
  char output[XAIOS_CONTROL_MAX_RESPONSE_BYTES];
  u64 output_size = 0ULL;
  int result = xaios_control_run_as(command, role, principal, output,
                                    sizeof(output), &output_size);
  if (result != expected_result || output_size == 0ULL ||
      !contains(output, marker)) {
    fprintf(stderr, "control client role case failed: %s rc=%d output=%s\n",
            command, result, output);
    return -1;
  }
  return 0;
}

int main(void) {
  char exact[XAIOS_CONTROL_MAX_RESPONSE_BYTES];
  u64 exact_size = 0ULL;
  static const char expected[] =
      "{\"schema_version\":1,\"request_id\":\"1\",\"status\":\"ok\","
      "\"data\":{\"build_identifier\":\"host-test\",\"git_commit\":"
      "\"abc123\",\"kernel_abi_version\":1,\"control_protocol_version\":1,"
      "\"model_package_version\":2,\"model_volume_version\":1,"
      "\"architecture\":\"aarch64\",\"build_mode\":\"development\"}}\n";
  static const char expected_error[] =
      "{\"schema_version\":1,\"request_id\":\"2\",\"status\":\"error\","
      "\"data\":null,\"error\":{\"code\":\"unknown_operation\","
      "\"message\":\"Unknown xaiosctl command.\"}}\n";
  if (xaios_control_run("xaiosctl version --json", exact, sizeof(exact),
                        &exact_size) != 0 ||
      strcmp(exact, expected) != 0 || exact_size != strlen(expected)) {
    fprintf(stderr, "deterministic JSON mismatch: %s\n", exact);
    return 1;
  }
  if (xaios_control_run("xaiosctl bogus --json", exact, sizeof(exact),
                        &exact_size) != -1 ||
      strcmp(exact, expected_error) != 0 ||
      exact_size != strlen(expected_error)) {
    fprintf(stderr, "deterministic error JSON mismatch: %s\n", exact);
    return 1;
  }
  if (run_case("xaiosctl version", 0, "git_commit=abc123") != 0 ||
      run_case("xaiosctl status --json", 0, "\"queue_depth\":null") != 0 ||
      run_case("xaiosctl health --json", 1,
               "\"overall\":\"degraded\"") != 0 ||
      run_case("xaiosctl capabilities --json", 0,
               "\"model_v2\":\"interface-only\"") != 0 ||
      run_case("xaiosctl hardware --json", 0,
               "\"cpu_vendor\":\"unknown\"") != 0 ||
      run_case("xaiosctl metrics --json", 0,
               "\"tokens_generated\":null") != 0 ||
      run_case("xaiosctl logs --json --limit 1", 0,
               "\"records\":\"seq=7") != 0 ||
      run_case("xaiosctl config show --json", 0,
               "\"command_rate_per_minute\":60") != 0 ||
      run_case("xaiosctl config validate /tmp/config --json", 0,
               "\"validated\":1") != 0 ||
      run_case("xaiosctl config diff /tmp/config", 0,
               "change_mask=8") != 0 ||
      run_case("xaiosctl auth key list --json", 0,
               "\"principal\":\"ci-admin\"") != 0 ||
      run_case("xaiosctl audit show --json --limit 1", 0,
               "\"operation\":\"config.apply\"") != 0 ||
      run_case_as("xaiosctl config apply /tmp/config --operation-id 41 --json",
                  XAIOS_CONTROL_ROLE_OPERATOR, "ci-operator", 0,
                  "\"validated\":1") != 0 ||
      run_case_as("xaiosctl auth key add /tmp/key.pub --principal ci-admin-2 "
                  "--role administrator --operation-id 42 --json",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "\"key_count\":1") != 0 ||
      run_case_as("xaiosctl auth key remove "
                  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f "
                  "--operation-id 43 --json",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "\"revoked_count\":1") != 0 ||
      run_case_as("xaiosctl auth host-key rotate --operation-id 44 --json",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "\"changed\":1") != 0 ||
      run_case_as(
          "xaiosctl model register "
          "da3246a8df558dd6d9da385adb58976cd964a76d413f9a5f395f65a861e1333f "
          "--model-uuid 00112233445566778899aabbccddeeff "
          "--signer-key 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f "
          "--signature 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
          "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f "
          "--source-revision ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100 "
          "--architecture qwen-test --target portable --size 5GiB "
          "--operation-id 46 --json",
          XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0, "\"generation\":9") != 0 ||
      run_case_as("xaiosctl model verify "
                  "da3246a8df558dd6d9da385adb58976cd964a76d413f9a5f395f65a861e1333f "
                  "--json",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "\"generation\":10") != 0 ||
      run_case_as("xaiosctl model activate "
                  "da3246a8df558dd6d9da385adb58976cd964a76d413f9a5f395f65a861e1333f "
                  "--operation-id 47 --json",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "\"changed\":1") != 0 ||
      run_case_as("xaiosctl model cleanup "
                  "da3246a8df558dd6d9da385adb58976cd964a76d413f9a5f395f65a861e1333f "
                  "--operation-id 49 --json",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "\"reclaimed_bytes\":4194304") != 0 ||
      run_case("xaiosctl storage device list --json", 0,
               "\"identifier\":\"/dev/vblk4\"") != 0 ||
      run_case("xaiosctl storage device show /dev/vblk4", 0,
               "capacity_bytes=137438953472") != 0 ||
      run_case("xaiosctl storage filesystem list --json", 0,
               "\"filesystem\":\"ModelFS\"") != 0 ||
      run_case("xaiosctl storage mount-status", 0,
               "mount=/models") != 0 ||
      run_case("xaiosctl storage filesystem show /models --json", 0,
               "\"staging_writable\":1") != 0 ||
      run_case("xaiosctl storage usage /models", 0,
               "free_bytes=137436856320") != 0 ||
      run_case("xaiosctl storage partition list /dev/vblk5 --json", 0,
               "\"identifier\":\"/dev/vblk5p1\"") != 0 ||
      run_case("xaiosctl storage partition verify /dev/vblk5", 0,
               "copies_consistent=1") != 0 ||
      run_case("xaiosctl storage format-plan /dev/vblk5p1 --type modelfs "
               "--label models --block-size 4096 --checksum-data "
               "--chunk-size 4MiB --json",
               0, "\"dry_run\":1") != 0 ||
      run_case("xaiosctl storage format /dev/vblk5p1 --type modelfs "
               "--label models --block-size 4096 --checksum-data --dry-run",
               0, "dry_run=1") != 0 ||
      run_case_as("xaiosctl storage format /dev/vblk5p1 --type modelfs "
                  "--label models --block-size 4096 --checksum-data "
                  "--confirm-partition aaaaaaaa-bbbb-5ccc-8ddd-eeeeeeeeeeee "
                  "--operation-id 601 --json",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "\"check_state\":\"clean\"") != 0 ||
      run_case_as("xaiosctl storage mount /dev/vblk5p1 /models "
                  "--read-only --operation-id 602",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "target=/dev/vblk5p1") != 0 ||
      run_case_as("xaiosctl storage unmount /models --operation-id 603 --json",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "\"target\":\"/models\"") != 0 ||
      run_case("xaiosctl storage fsck /dev/vblk5p1 --check --verify-data --json",
               0, "\"checked_bytes\":0") != 0 ||
      run_case_as("xaiosctl storage fsck /dev/vblk5p1 --repair "
                  "--confirm-partition aaaaaaaa-bbbb-5ccc-8ddd-eeeeeeeeeeee "
                  "--operation-id 604",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "check_state=repaired") != 0 ||
      run_case_as("xaiosctl storage repair-from-replica /dev/vblk5p1 "
                  "/dev/vblk6p1 "
                  "da3246a8df558dd6d9da385adb58976cd964a76d413f9a5f395f65a861e1333f "
                  "--confirm-partition aaaaaaaa-bbbb-5ccc-8ddd-eeeeeeeeeeee "
                  "--operation-id 606",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "check_state=repaired") != 0 ||
      run_case("xaiosctl storage resize-plan /dev/vblk5p1 --grow-to max --json",
               0, "\"dry_run\":1") != 0 ||
      run_case_as("xaiosctl storage resize /dev/vblk5p1 --grow-to 2GiB "
                  "--confirm-partition aaaaaaaa-bbbb-5ccc-8ddd-eeeeeeeeeeee "
                  "--operation-id 605",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "generation=2") != 0 ||
      run_case_as("xaiosctl storage scrub /models --start "
                  "--operation-id 606 --json",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "\"state\":\"running\"") != 0 ||
      run_case("xaiosctl storage scrub /models --status --json", 0,
               "\"checked_bytes\":4194304") != 0 ||
      run_case_as("xaiosctl storage scrub /models --pause "
                  "--operation-id 607",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "state=paused") != 0 ||
      run_case_as("xaiosctl storage scrub /models --resume "
                  "--operation-id 608 --json",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "\"state\":\"running\"") != 0 ||
      run_case_as("xaiosctl storage scrub /models --cancel "
                  "--operation-id 609",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "state=cancelled") != 0 ||
      run_case("xaiosctl storage trim /models --all-free --dry-run --json", 0,
               "\"dry_run\":1") != 0 ||
      run_case("xaiosctl storage trim /models --dry-run --json", 0,
               "\"all_free\":1") != 0 ||
      run_case_as("xaiosctl storage trim /models --range 1MiB:2MiB "
                  "--operation-id 610",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "requested_offset=1048576") != 0 ||
      run_case("xaiosctl storage trim-status /models --json", 0,
               "\"state\":\"complete\"") != 0 ||
      run_case_as("xaiosctl storage trim-cancel /models --operation-id 611",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "state=cancelled") != 0 ||
      run_case("xaiosctl storage partition plan-create /dev/vblk5 "
               "--type model --size 2GiB --name models --json",
               0, "\"dry_run\":1") != 0 ||
      run_case("xaiosctl storage partition create /dev/vblk5 "
               "--type model --size 2GiB --name models --dry-run --json",
               0, "\"dry_run\":1") != 0 ||
      run_case_as("xaiosctl storage partition create /dev/vblk5 "
                  "--type model --size 2GiB --name models "
                  "--confirm-device 11111111-2222-5333-8444-555555555555 "
                  "--operation-id 51 --json",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "\"dry_run\":0") != 0 ||
      run_case_as("xaiosctl storage partition resize /dev/vblk5p1 "
                  "--grow-to 3GiB "
                  "--confirm-partition aaaaaaaa-bbbb-5ccc-8ddd-eeeeeeeeeeee "
                  "--operation-id 52 --json",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "\"affected_bytes\":2147483648") != 0 ||
      run_case_as("xaiosctl storage partition delete /dev/vblk5p1 "
                  "--confirm-partition aaaaaaaa-bbbb-5ccc-8ddd-eeeeeeeeeeee "
                  "--operation-id 53 --json",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "\"changed\":1") != 0 ||
      run_case_as("xaiosctl storage partition repair /dev/vblk5 "
                  "--confirm-device 11111111-2222-5333-8444-555555555555 "
                  "--operation-id 54 --json",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "\"partition\":null") != 0 ||
      run_case_as("xaiosctl model activate "
                  "da3246a8df558dd6d9da385adb58976cd964a76d413f9a5f395f65a861e1333f "
                  "--operation-id 48 --json",
                  XAIOS_CONTROL_ROLE_OPERATOR, "ci-operator", -1,
                  "\"code\":\"permission_denied\"") != 0 ||
      run_case_as("xaiosctl auth host-key rotate --operation-id 45 --json",
                  XAIOS_CONTROL_ROLE_OPERATOR, "ci-operator", -1,
                  "\"code\":\"permission_denied\"") != 0 ||
      run_case("xaiosctl config apply /tmp/config --json", -1,
               "\"code\":\"operation_id_required\"") != 0 ||
      run_case("xaiosctl model activate "
               "da3246a8df558dd6d9da385adb58976cd964a76d413f9a5f395f65a861e1333f "
               "--json",
               -1, "\"code\":\"operation_id_required\"") != 0 ||
      run_case("xaiosctl storage trim /models --json", -1,
               "\"code\":\"trim_scope_required\"") != 0 ||
      run_case("xaiosctl storage partition create /dev/vblk5 --type model "
               "--size 2GiB --name models --json",
               -1, "\"code\":\"confirmation_required\"") != 0 ||
      run_case("xaiosctl storage partition resize /dev/vblk5p1 --json", -1,
               "\"code\":\"resize_target_required\"") != 0 ||
      run_case("xaiosctl storage partition plan-create /dev/vblk5 "
               "--type invalid --size 2GiB --name models --json",
               -1, "\"code\":\"invalid_partition_type\"") != 0 ||
      run_case("xaiosctl auth key add /tmp/key.pub --principal bad "
               "--role invalid --operation-id 46 --json",
               -1, "\"code\":\"invalid_role\"") != 0 ||
      run_case("xaiosctl bogus --json", -1,
               "\"code\":\"unknown_operation\"") != 0 ||
      run_case("xaiosctl version --node 8 --json", -1,
               "\"code\":\"unknown_node\"") != 0 ||
      run_case("xaiosctl version --timeout 61s --json", -1,
               "\"code\":\"invalid_timeout\"") != 0) {
    return 1;
  }
  char fuzz_command[160];
  char fuzz_output[2048];
  uint32_t fuzz_state = UINT32_C(0x4354524c);
  for (uint32_t case_id = 0U; case_id < 4096U; ++case_id) {
    fuzz_state = fuzz_state * UINT32_C(1664525) + UINT32_C(1013904223);
    uint32_t length = fuzz_state % (sizeof(fuzz_command) - 1U);
    for (uint32_t index = 0U; index < length; ++index) {
      fuzz_state =
          fuzz_state * UINT32_C(1664525) + UINT32_C(1013904223);
      fuzz_command[index] = (char)(32U + ((fuzz_state >> 24U) % 95U));
    }
    fuzz_command[length] = '\0';
    u64 output_size = 0U;
    (void)xaios_control_run_as(fuzz_command, XAIOS_CONTROL_ROLE_OBSERVER,
                               "fuzz-observer", fuzz_output,
                               sizeof(fuzz_output), &output_size);
    if (output_size > sizeof(fuzz_output)) return 1;
  }
  puts("control-client: typed behavior and deterministic malformed corpus passed");
  return 0;
}
