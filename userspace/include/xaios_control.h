#ifndef XAIOS_USERSPACE_CONTROL_H
#define XAIOS_USERSPACE_CONTROL_H

#define XAIOS_CONTROL_MAGIC 0x58414350U
/* 2 adds product_version to the version payload; must match the kernel. */
#define XAIOS_CONTROL_VERSION 2U
#define XAIOS_CONTROL_KERNEL_ABI_VERSION 1U
#define XAIOS_CONTROL_MODEL_PACKAGE_VERSION 2U
#define XAIOS_CONTROL_MODEL_VOLUME_VERSION 1U
#define XAIOS_CONTROL_MAX_REQUEST_BYTES 512U
#define XAIOS_CONTROL_MAX_RESPONSE_BYTES 8192U
#define XAIOS_CONTROL_LOG_COMPONENT_MAX 32U
#define XAIOS_CONTROL_PATH_MAX 96U
#define XAIOS_CONTROL_STORAGE_MAX_DEVICES 8U
#define XAIOS_CONTROL_STORAGE_MAX_FILESYSTEMS 4U
#define XAIOS_CONTROL_STORAGE_MAX_PARTITIONS 24U
#define XAIOS_CONTROL_STORAGE_MOUNT_MAX 32U
#define XAIOS_CONTROL_STORAGE_FILESYSTEM_MAX 24U
#define XAIOS_CONTROL_UNKNOWN_U64 (~0ULL)

#define XAIOS_ADMIN_CONFIG_MAGIC 0x58414346U
#define XAIOS_ADMIN_AUTH_MAGIC 0x58414155U
#define XAIOS_ADMIN_SCHEMA_VERSION 1U
#define XAIOS_ADMIN_CONFIG_PATH "/state/control/config.bin"
#define XAIOS_ADMIN_AUTH_PATH "/state/control/authorized.bin"
#define XAIOS_ADMIN_MAX_KEYS 16U
#define XAIOS_ADMIN_MAX_REVOKED_KEYS 16U
#define XAIOS_ADMIN_PRINCIPAL_MAX 32U
#define XAIOS_ADMIN_OPERATION_MAX 24U
#define XAIOS_ADMIN_PASSWORD_DISABLED 0U
#define XAIOS_ADMIN_PASSWORD_DEVELOPMENT 1U

#define XAIOS_CONTROL_OP_VERSION 1U
#define XAIOS_CONTROL_OP_STATUS 2U
#define XAIOS_CONTROL_OP_HEALTH 3U
#define XAIOS_CONTROL_OP_CAPABILITIES 4U
#define XAIOS_CONTROL_OP_HARDWARE 5U
#define XAIOS_CONTROL_OP_METRICS 6U
#define XAIOS_CONTROL_OP_LOGS 7U
#define XAIOS_CONTROL_OP_CONFIG_SHOW 8U
#define XAIOS_CONTROL_OP_CONFIG_VALIDATE 9U
#define XAIOS_CONTROL_OP_CONFIG_DIFF 10U
#define XAIOS_CONTROL_OP_CONFIG_APPLY 11U
#define XAIOS_CONTROL_OP_AUTH_KEY_LIST 12U
#define XAIOS_CONTROL_OP_AUTH_KEY_ADD 13U
#define XAIOS_CONTROL_OP_AUTH_KEY_REMOVE 14U
#define XAIOS_CONTROL_OP_AUTH_HOST_KEY_ROTATE 15U
#define XAIOS_CONTROL_OP_AUDIT_SHOW 16U
#define XAIOS_CONTROL_OP_MODEL_VERIFY 17U
#define XAIOS_CONTROL_OP_MODEL_ACTIVATE 18U
#define XAIOS_CONTROL_OP_STORAGE_DEVICE_LIST 19U
#define XAIOS_CONTROL_OP_STORAGE_DEVICE_SHOW 20U
#define XAIOS_CONTROL_OP_STORAGE_FILESYSTEM_LIST 21U
#define XAIOS_CONTROL_OP_STORAGE_FILESYSTEM_SHOW 22U
#define XAIOS_CONTROL_OP_STORAGE_PARTITION_LIST 23U
#define XAIOS_CONTROL_OP_STORAGE_PARTITION_VERIFY 24U
#define XAIOS_CONTROL_OP_STORAGE_PARTITION_PLAN_CREATE 25U
#define XAIOS_CONTROL_OP_STORAGE_PARTITION_CREATE 26U
#define XAIOS_CONTROL_OP_STORAGE_PARTITION_PLAN_DELETE 27U
#define XAIOS_CONTROL_OP_STORAGE_PARTITION_DELETE 28U
#define XAIOS_CONTROL_OP_STORAGE_PARTITION_PLAN_RESIZE 29U
#define XAIOS_CONTROL_OP_STORAGE_PARTITION_RESIZE 30U
#define XAIOS_CONTROL_OP_STORAGE_PARTITION_REPAIR 31U
#define XAIOS_CONTROL_OP_STORAGE_FORMAT_PLAN 32U
#define XAIOS_CONTROL_OP_STORAGE_FORMAT 33U
#define XAIOS_CONTROL_OP_STORAGE_MOUNT 34U
#define XAIOS_CONTROL_OP_STORAGE_UNMOUNT 35U
#define XAIOS_CONTROL_OP_STORAGE_FSCK 36U
#define XAIOS_CONTROL_OP_STORAGE_FS_REPAIR 37U
#define XAIOS_CONTROL_OP_STORAGE_FS_RESIZE_PLAN 38U
#define XAIOS_CONTROL_OP_STORAGE_FS_RESIZE 39U
#define XAIOS_CONTROL_OP_MODEL_REGISTER 40U
#define XAIOS_CONTROL_OP_STORAGE_SCRUB_START 41U
#define XAIOS_CONTROL_OP_STORAGE_SCRUB_STATUS 42U
#define XAIOS_CONTROL_OP_STORAGE_SCRUB_PAUSE 43U
#define XAIOS_CONTROL_OP_STORAGE_SCRUB_RESUME 44U
#define XAIOS_CONTROL_OP_STORAGE_SCRUB_CANCEL 45U
#define XAIOS_CONTROL_OP_STORAGE_TRIM_START 46U
#define XAIOS_CONTROL_OP_STORAGE_TRIM_STATUS 47U
#define XAIOS_CONTROL_OP_STORAGE_TRIM_CANCEL 48U
#define XAIOS_CONTROL_OP_MODEL_CLEANUP 49U
#define XAIOS_CONTROL_OP_APP_ACTIVATE 50U
#define XAIOS_CONTROL_OP_APP_REMOVE 51U
#define XAIOS_CONTROL_OP_APP_ROLLBACK 52U
#define XAIOS_CONTROL_OP_CATALOG_ACTIVATE 53U
#define XAIOS_CONTROL_OP_SYSTEM_UPDATE_BEGIN 54U
#define XAIOS_CONTROL_OP_SYSTEM_UPDATE_CHUNK 55U
#define XAIOS_CONTROL_OP_SYSTEM_UPDATE_COMMIT 56U
#define XAIOS_CONTROL_OP_SYSTEM_UPDATE_ABORT 57U
#define XAIOS_CONTROL_OP_RUNTIME_SNAPSHOT 58U
#define XAIOS_CONTROL_OP_STORAGE_REPAIR_FROM_REPLICA 59U

#define XAIOS_CONTROL_PAYLOAD_NONE 0U
#define XAIOS_CONTROL_PAYLOAD_VERSION 1U
#define XAIOS_CONTROL_PAYLOAD_STATUS 2U
#define XAIOS_CONTROL_PAYLOAD_HEALTH 3U
#define XAIOS_CONTROL_PAYLOAD_CAPABILITIES 4U
#define XAIOS_CONTROL_PAYLOAD_HARDWARE 5U
#define XAIOS_CONTROL_PAYLOAD_METRICS 6U
#define XAIOS_CONTROL_PAYLOAD_LOG_REQUEST 7U
#define XAIOS_CONTROL_PAYLOAD_LOGS 8U
#define XAIOS_CONTROL_PAYLOAD_PATH_REQUEST 9U
#define XAIOS_CONTROL_PAYLOAD_MUTATION_REQUEST 10U
#define XAIOS_CONTROL_PAYLOAD_AUDIT_REQUEST 11U
#define XAIOS_CONTROL_PAYLOAD_CONFIG 12U
#define XAIOS_CONTROL_PAYLOAD_AUTH_KEYS 13U
#define XAIOS_CONTROL_PAYLOAD_MUTATION 14U
#define XAIOS_CONTROL_PAYLOAD_AUDIT 15U
#define XAIOS_CONTROL_PAYLOAD_STORAGE_DEVICES 16U
#define XAIOS_CONTROL_PAYLOAD_STORAGE_FILESYSTEMS 17U
#define XAIOS_CONTROL_PAYLOAD_STORAGE_PARTITION_REQUEST 18U
#define XAIOS_CONTROL_PAYLOAD_STORAGE_PARTITIONS 19U
#define XAIOS_CONTROL_PAYLOAD_STORAGE_PARTITION_PLAN 20U
#define XAIOS_CONTROL_PAYLOAD_STORAGE_VOLUME_REQUEST 21U
#define XAIOS_CONTROL_PAYLOAD_STORAGE_VOLUME_REPORT 22U
#define XAIOS_CONTROL_PAYLOAD_MODEL_REGISTER_REQUEST 23U
#define XAIOS_CONTROL_PAYLOAD_STORAGE_SCRUB_REPORT 24U
#define XAIOS_CONTROL_PAYLOAD_STORAGE_TRIM_REQUEST 25U
#define XAIOS_CONTROL_PAYLOAD_STORAGE_TRIM_REPORT 26U
#define XAIOS_CONTROL_PAYLOAD_MODEL_CLEANUP_REPORT 27U
#define XAIOS_CONTROL_PAYLOAD_APP_REQUEST 28U
#define XAIOS_CONTROL_PAYLOAD_SYSTEM_UPDATE_BEGIN 29U
#define XAIOS_CONTROL_PAYLOAD_SYSTEM_UPDATE_CHUNK 30U
#define XAIOS_CONTROL_PAYLOAD_RUNTIME_SNAPSHOT_REQUEST 31U
#define XAIOS_CONTROL_PAYLOAD_RUNTIME_SNAPSHOT 32U
#define XAIOS_CONTROL_PAYLOAD_STORAGE_REPLICA_REPAIR_REQUEST 33U

#define XAIOS_MODEL_MAINTENANCE_IDLE 0U
#define XAIOS_MODEL_MAINTENANCE_RUNNING 1U
#define XAIOS_MODEL_MAINTENANCE_PAUSED 2U
#define XAIOS_MODEL_MAINTENANCE_COMPLETE 3U
#define XAIOS_MODEL_MAINTENANCE_CANCELLED 4U
#define XAIOS_MODEL_MAINTENANCE_FAILED 5U

#define XAIOS_STORAGE_PARTITION_STATE 1U
#define XAIOS_STORAGE_PARTITION_MODEL 2U
#define XAIOS_STORAGE_PARTITION_RECOVERY 3U

#define XAIOS_MODEL_VOLUME_CHECK_UNKNOWN 0U
#define XAIOS_MODEL_VOLUME_CHECK_CLEAN 1U
#define XAIOS_MODEL_VOLUME_CHECK_REPAIRABLE 2U
#define XAIOS_MODEL_VOLUME_CHECK_CORRUPT_UNREPAIRABLE 3U
#define XAIOS_MODEL_VOLUME_CHECK_REPAIRED 4U

#define XAIOS_CONTROL_STATUS_OK 0U
#define XAIOS_CONTROL_STATUS_INVALID_REQUEST 1U
#define XAIOS_CONTROL_STATUS_UNSUPPORTED_VERSION 2U
#define XAIOS_CONTROL_STATUS_UNKNOWN_OPERATION 3U
#define XAIOS_CONTROL_STATUS_DENIED 4U
#define XAIOS_CONTROL_STATUS_BUFFER_TOO_SMALL 5U
#define XAIOS_CONTROL_STATUS_TIMEOUT 6U
#define XAIOS_CONTROL_STATUS_INTERNAL 7U
#define XAIOS_CONTROL_STATUS_UNKNOWN_NODE 8U
#define XAIOS_CONTROL_STATUS_NOT_FOUND 9U
#define XAIOS_CONTROL_STATUS_REPLAYED 10U
#define XAIOS_CONTROL_STATUS_CONFLICT 11U

#define XAIOS_CONTROL_ROLE_NONE 0U
#define XAIOS_CONTROL_ROLE_OBSERVER 1U
#define XAIOS_CONTROL_ROLE_OPERATOR 2U
#define XAIOS_CONTROL_ROLE_ADMIN 3U

#define XAIOS_CONTROL_STATE_UNKNOWN 0U
#define XAIOS_CONTROL_STATE_STOPPED 1U
#define XAIOS_CONTROL_STATE_RUNNING 2U
#define XAIOS_CONTROL_STATE_READY 3U
#define XAIOS_CONTROL_STATE_DEGRADED 4U
#define XAIOS_CONTROL_STATE_FATAL 5U
#define XAIOS_CONTROL_STATE_UNSUPPORTED 6U
#define XAIOS_CONTROL_STATE_INTERFACE_ONLY 7U
#define XAIOS_CONTROL_STATE_FIXTURE_ONLY 8U
#define XAIOS_CONTROL_STATE_AVAILABLE 9U

#define XAIOS_CONTROL_READINESS_SSH 1ULL
#define XAIOS_CONTROL_READINESS_NETWORK 2ULL
#define XAIOS_CONTROL_READINESS_STORAGE 4ULL
#define XAIOS_CONTROL_READINESS_MODEL 8ULL
#define XAIOS_CONTROL_READINESS_INFERENCE 16ULL
#define XAIOS_CONTROL_READINESS_CLUSTER 32ULL

typedef struct xaios_control_request_header_user {
  u32 magic;
  u16 version;
  u16 header_size;
  u16 operation;
  u16 flags;
  u32 payload_type;
  u64 request_id;
  u32 principal_role;
  u32 node_id;
  u64 timeout_ms;
  u64 payload_length;
} xaios_control_request_header_user_t;

typedef struct xaios_control_response_header_user {
  u32 magic;
  u16 version;
  u16 header_size;
  u16 operation;
  u16 flags;
  u32 status;
  u64 request_id;
  u32 payload_type;
  u32 reserved;
  u64 payload_length;
} xaios_control_response_header_user_t;

typedef struct xaios_control_app_request_payload_user {
  char name[32];
} xaios_control_app_request_payload_user_t;

typedef struct xaios_control_system_update_begin_payload_user {
  u64 payload_size;
  u32 generation;
  u32 reserved;
  unsigned char payload_hash[32];
  char signature[320];
} xaios_control_system_update_begin_payload_user_t;

#define XAIOS_CONTROL_SYSTEM_UPDATE_CHUNK_MAX 400U
typedef struct xaios_control_system_update_chunk_payload_user {
  u32 size;
  u32 reserved;
  unsigned char data[XAIOS_CONTROL_SYSTEM_UPDATE_CHUNK_MAX];
} xaios_control_system_update_chunk_payload_user_t;

typedef char xaios_control_request_header_user_must_be_48_bytes[
    sizeof(xaios_control_request_header_user_t) == 48U ? 1 : -1];
typedef char xaios_control_response_header_user_must_be_40_bytes[
    sizeof(xaios_control_response_header_user_t) == 40U ? 1 : -1];

typedef struct xaios_control_version_payload_user {
  /* Must match xaios_control_version_payload in the kernel field for field:
     this is the same wire payload seen from the other side. */
  char product_version[16];
  char build_identifier[32];
  char git_commit[48];
  char architecture[16];
  char build_mode[16];
  u32 kernel_abi_version;
  u32 control_protocol_version;
  u32 model_package_version;
  u32 model_volume_version;
} xaios_control_version_payload_user_t;

typedef struct xaios_control_status_payload_user {
  u64 uptime_ns;
  u64 physical_pages;
  u64 managed_pages;
  u64 free_pages;
  u64 production_models_loaded;
  u64 queue_depth;
  u64 active_requests;
  u64 readiness_reasons;
  u32 online_cpus;
  u32 worker_count;
  u32 init_service_state;
  u32 manager_service_state;
  u32 ssh_service_state;
  u32 network_state;
  u32 storage_state;
  u32 model_state;
  u32 cluster_state;
  u32 readiness_state;
} xaios_control_status_payload_user_t;

typedef struct xaios_control_health_payload_user {
  u64 readiness_reasons;
  u64 process_failures;
  u64 memory_free_pages;
  u64 network_packet_drops;
  u64 log_overflows;
  u32 process_liveness;
  u32 node_readiness;
  u32 model_readiness;
  u32 cluster_readiness;
  u32 overall_state;
  u32 fatal;
} xaios_control_health_payload_user_t;

typedef struct xaios_control_capabilities_payload_user {
  u32 ssh;
  u32 sftp;
  u32 ipv4;
  u32 ipv6;
  u32 udp;
  u32 mutable_fs;
  u32 model_v1_fixture;
  u32 model_v2;
  u32 real_model_inference;
  u32 native_macos;
  u32 distributed_inference;
  u32 production_inference_service;
} xaios_control_capabilities_payload_user_t;

typedef struct xaios_control_hardware_payload_user {
  char architecture[16];
  char cpu_vendor[24];
  char cpu_model[40];
  char selected_backend[24];
  u64 physical_pages;
  u64 managed_pages;
  u64 free_pages;
  u64 model_reserved_bytes;
  u64 kv_reserved_bytes;
  u64 timer_frequency_hz;
  u32 core_count;
  u32 thread_count;
  u32 numa_nodes;
  u32 page_size;
  u32 neon;
  u32 sve;
  u32 avx2;
  u32 avx512;
  u32 vnni;
  u32 amx;
} xaios_control_hardware_payload_user_t;

typedef struct xaios_control_metrics_payload_user {
  u64 uptime_ns;
  u64 control_requests;
  u64 control_failures;
  u64 control_denials;
  u64 requests_accepted;
  u64 requests_completed;
  u64 requests_failed;
  u64 requests_cancelled;
  u64 queue_depth;
  u64 active_sessions;
  u64 tokens_generated;
  u64 prefill_tokens_per_second;
  u64 decode_tokens_per_second;
  u64 time_to_first_token_ns;
  u64 user_cpu_utilization_tenths;
  u64 physical_pages;
  u64 managed_pages;
  u64 free_pages;
  u64 model_resident_bytes;
  u64 kv_cache_bytes;
  u64 kv_cache_evictions;
  u64 storage_reads;
  u64 storage_read_bytes;
  u64 network_rx_packets;
  u64 network_tx_packets;
  u64 network_rx_bytes;
  u64 network_tx_bytes;
  u64 network_errors;
  u64 cluster_rpc_retries;
  u64 cluster_rpc_timeouts;
  u64 fixture_inferences;
  u64 log_buffer_bytes;
  u64 log_overflows;
  u32 worker_count;
  u32 per_worker_health;
} xaios_control_metrics_payload_user_t;

#define XAIOS_CONTROL_RUNTIME_CPU_MAX 64U
#define XAIOS_CONTROL_RUNTIME_PROCESS_MAX 56U
#define XAIOS_CONTROL_RUNTIME_PROCESS_NAME_MAX 64U

#define XAIOS_RUNTIME_PROCESS_EMPTY 0U
#define XAIOS_RUNTIME_PROCESS_LOADED 1U
#define XAIOS_RUNTIME_PROCESS_RUNNABLE 2U
#define XAIOS_RUNTIME_PROCESS_RUNNING 3U
#define XAIOS_RUNTIME_PROCESS_WAITING 4U
#define XAIOS_RUNTIME_PROCESS_EXITED 5U
#define XAIOS_RUNTIME_PROCESS_FAILED 6U

#define XAIOS_RUNTIME_CPU_OFFLINE 0U
#define XAIOS_RUNTIME_CPU_HOUSEKEEPING 1U
#define XAIOS_RUNTIME_CPU_SCHEDULING 2U
#define XAIOS_RUNTIME_CPU_AI_HOT 3U

typedef struct xaios_control_runtime_snapshot_request_user {
  u32 cpu_start;
  u32 cpu_limit;
  u32 process_start;
  u32 process_limit;
  u32 wait_ms;
  u32 reserved;
} xaios_control_runtime_snapshot_request_user_t;

typedef struct xaios_control_runtime_cpu_record_user {
  u32 cpu_id;
  u32 active_pid;
  u32 role;
  u32 reserved;
  u64 busy_ns;
  u64 elapsed_ns;
} xaios_control_runtime_cpu_record_user_t;

typedef struct xaios_control_runtime_process_record_user {
  u32 pid;
  u32 parent_pid;
  u32 cpu_id;
  u32 state;
  u64 runtime_ns;
  u64 resident_pages;
  u64 syscall_count;
  char name[XAIOS_CONTROL_RUNTIME_PROCESS_NAME_MAX];
} xaios_control_runtime_process_record_user_t;

typedef struct xaios_control_runtime_snapshot_payload_user {
  u64 sampled_at_ns;
  u64 cpu_busy_total_ns;
  u64 physical_pages;
  u64 managed_pages;
  u64 free_pages;
  u32 cpu_total;
  u32 cpu_start;
  u32 cpu_count;
  u32 cpu_next;
  u32 process_capacity;
  u32 process_start;
  u32 process_count;
  u32 process_next;
  u32 process_active;
  u32 process_failed;
  u32 load_average_hundredths[3];
  u32 reserved;
  xaios_control_runtime_cpu_record_user_t cpus[XAIOS_CONTROL_RUNTIME_CPU_MAX];
  xaios_control_runtime_process_record_user_t
      processes[XAIOS_CONTROL_RUNTIME_PROCESS_MAX];
} xaios_control_runtime_snapshot_payload_user_t;

typedef char xaios_control_runtime_snapshot_user_must_fit_response[
    sizeof(xaios_control_response_header_user_t) +
                sizeof(xaios_control_runtime_snapshot_payload_user_t) <=
            XAIOS_CONTROL_MAX_RESPONSE_BYTES
        ? 1
        : -1];

typedef struct xaios_control_log_request_payload_user {
  u64 since_cursor;
  u32 limit;
  u32 follow;
  char component[XAIOS_CONTROL_LOG_COMPONENT_MAX];
} xaios_control_log_request_payload_user_t;

typedef struct xaios_control_logs_payload_user {
  u64 start_cursor;
  u64 next_cursor;
  u64 latest_cursor;
  u32 record_count;
  u32 redacted_count;
  u32 timed_out;
  u32 reserved;
} xaios_control_logs_payload_user_t;

typedef struct xaios_admin_config_user {
  u32 magic;
  u16 version;
  u16 size;
  u64 generation;
  u32 max_connections;
  u32 max_channels_per_connection;
  u32 max_auth_attempts;
  u32 command_rate_per_minute;
  u32 password_auth;
  u32 reserved;
  u64 checksum;
} xaios_admin_config_user_t;

typedef struct xaios_admin_key_record_user {
  unsigned char public_key[32];
  unsigned char fingerprint[32];
  char principal[XAIOS_ADMIN_PRINCIPAL_MAX];
  u32 role;
  u32 reserved;
} xaios_admin_key_record_user_t;

typedef struct xaios_admin_auth_database_user {
  u32 magic;
  u16 version;
  u16 header_size;
  u64 generation;
  u32 key_count;
  u32 revoked_count;
  u64 checksum;
  xaios_admin_key_record_user_t keys[XAIOS_ADMIN_MAX_KEYS];
  unsigned char revoked[XAIOS_ADMIN_MAX_REVOKED_KEYS][32];
} xaios_admin_auth_database_user_t;

typedef struct xaios_admin_key_view_user {
  unsigned char fingerprint[32];
  char principal[XAIOS_ADMIN_PRINCIPAL_MAX];
  u32 role;
  u32 reserved;
} xaios_admin_key_view_user_t;

typedef struct xaios_admin_audit_record_user {
  u64 sequence;
  u64 operation_id;
  unsigned char object_hash[32];
  char principal[XAIOS_ADMIN_PRINCIPAL_MAX];
  char operation[XAIOS_ADMIN_OPERATION_MAX];
  u32 role;
  u32 result;
} xaios_admin_audit_record_user_t;

typedef struct xaios_control_path_request_payload_user {
  char path[XAIOS_CONTROL_PATH_MAX];
} xaios_control_path_request_payload_user_t;

typedef struct xaios_control_mutation_request_payload_user {
  u64 operation_id;
  u32 assigned_role;
  u32 reserved;
  char actor[XAIOS_ADMIN_PRINCIPAL_MAX];
  char argument[XAIOS_CONTROL_PATH_MAX];
  char target_principal[XAIOS_ADMIN_PRINCIPAL_MAX];
} xaios_control_mutation_request_payload_user_t;

typedef struct xaios_control_audit_request_payload_user {
  u64 since_sequence;
  u32 limit;
  u32 reserved;
} xaios_control_audit_request_payload_user_t;

typedef struct xaios_control_config_payload_user {
  xaios_admin_config_user_t config;
  u32 change_mask;
  u32 validated;
} xaios_control_config_payload_user_t;

typedef struct xaios_control_auth_keys_payload_user {
  u64 generation;
  u32 key_count;
  u32 revoked_count;
} xaios_control_auth_keys_payload_user_t;

typedef struct xaios_control_mutation_payload_user {
  u64 operation_id;
  u64 generation;
  u32 changed;
  u32 reserved;
} xaios_control_mutation_payload_user_t;

typedef struct xaios_control_audit_payload_user {
  u64 next_sequence;
  u64 latest_sequence;
  u32 record_count;
  u32 reserved;
} xaios_control_audit_payload_user_t;

typedef struct xaios_control_storage_device_record_user {
  char identifier[48];
  char backend[24];
  u64 capacity_bytes;
  u64 capacity_logical_sectors;
  u64 logical_sector_size;
  u64 physical_block_size;
  u64 max_transfer_bytes;
  u64 discard_granularity;
  u64 max_discard_bytes;
  u64 read_bytes;
  u64 write_bytes;
  u64 discarded_bytes;
  u64 io_errors;
  u32 read_only;
  u32 flush_supported;
  u32 discard_supported;
  u32 write_zeroes_supported;
} xaios_control_storage_device_record_user_t;

typedef struct xaios_control_storage_devices_payload_user {
  u32 record_count;
  u32 total_count;
  u32 truncated;
  u32 reserved;
} xaios_control_storage_devices_payload_user_t;

typedef struct xaios_control_storage_filesystem_record_user {
  char mount_path[XAIOS_CONTROL_STORAGE_MOUNT_MAX];
  char filesystem[XAIOS_CONTROL_STORAGE_FILESYSTEM_MAX];
  char device_identifier[48];
  u64 total_bytes;
  u64 allocated_bytes;
  u64 free_bytes;
  u64 reserved_bytes;
  u64 file_count;
  u64 directory_count;
  u64 generation;
  u64 block_size;
  u64 package_count;
  u64 active_packages;
  u64 staging_packages;
  u64 quarantined_packages;
  u32 format_version;
  u32 mounted;
  u32 read_only;
  u32 staging_writable;
} xaios_control_storage_filesystem_record_user_t;

typedef struct xaios_control_storage_filesystems_payload_user {
  u32 record_count;
  u32 total_count;
  u32 truncated;
  u32 reserved;
} xaios_control_storage_filesystems_payload_user_t;

typedef struct xaios_storage_partition_request_user {
  char target[48];
  char confirmation[37];
  char name[37];
  u64 size_bytes;
  u64 operation_id;
  u32 partition_type;
  u32 reserved;
} xaios_storage_partition_request_user_t;

typedef struct xaios_control_storage_partition_request_payload_user {
  xaios_storage_partition_request_user_t request;
  char actor[XAIOS_ADMIN_PRINCIPAL_MAX];
} xaios_control_storage_partition_request_payload_user_t;

typedef struct xaios_storage_partition_record_user {
  char identifier[48];
  char name[37];
  char type_guid[37];
  char unique_guid[37];
  u64 first_lba;
  u64 last_lba;
  u64 size_bytes;
  u64 attributes;
  u32 table_index;
  u32 known_type;
} xaios_storage_partition_record_user_t;

typedef struct xaios_storage_partition_report_user {
  char device_identifier[48];
  char disk_guid[37];
  u64 capacity_bytes;
  u64 logical_sector_size;
  u64 first_usable_lba;
  u64 last_usable_lba;
  u64 partition_count;
  u32 primary_valid;
  u32 backup_valid;
  u32 copies_consistent;
  u32 selected_copy;
  u32 mutation_allowed;
  u32 reserved;
} xaios_storage_partition_report_user_t;

typedef struct xaios_control_storage_partitions_payload_user {
  xaios_storage_partition_report_user_t report;
  u32 record_count;
  u32 total_count;
  u32 truncated;
  u32 reserved;
} xaios_control_storage_partitions_payload_user_t;

typedef struct xaios_storage_partition_plan_user {
  xaios_storage_partition_report_user_t report;
  xaios_storage_partition_record_user_t partition;
  u64 resulting_partition_count;
  u64 affected_bytes;
  u32 changed;
  u32 dry_run;
} xaios_storage_partition_plan_user_t;

typedef struct xaios_control_storage_volume_request_payload_user {
  char target[48];
  char confirmation[37];
  char mount_path[XAIOS_CONTROL_STORAGE_MOUNT_MAX];
  char actor[XAIOS_ADMIN_PRINCIPAL_MAX];
  u64 size_bytes;
  u64 chunk_size;
  u64 operation_id;
  u32 verify_data;
  u32 read_only;
  u32 reserved;
} xaios_control_storage_volume_request_payload_user_t;

typedef struct xaios_control_storage_replica_repair_request_payload_user {
  char target[48];
  char replica[48];
  char confirmation[37];
  char package_id[65];
  char actor[XAIOS_ADMIN_PRINCIPAL_MAX];
  u64 operation_id;
} xaios_control_storage_replica_repair_request_payload_user_t;

typedef struct xaios_control_model_register_request_payload_user {
  u64 operation_id;
  u64 logical_size;
  unsigned char model_uuid[16];
  unsigned char package_id[32];
  unsigned char signer_public_key[32];
  unsigned char signature[64];
  unsigned char source_revision[32];
  char architecture_id[33];
  char target_id[33];
  char actor[XAIOS_ADMIN_PRINCIPAL_MAX];
} xaios_control_model_register_request_payload_user_t;

typedef struct xaios_control_storage_scrub_report_user {
  unsigned char volume_uuid[16];
  unsigned char bad_package_id[32];
  u64 generation;
  u64 package_index;
  u64 chunk_index;
  u64 checked_bytes;
  u64 total_bytes;
  u64 error_count;
  u64 bad_logical_offset;
  u32 state;
} xaios_control_storage_scrub_report_user_t;

typedef struct xaios_control_storage_trim_request_payload_user {
  char target[XAIOS_CONTROL_STORAGE_MOUNT_MAX];
  char actor[XAIOS_ADMIN_PRINCIPAL_MAX];
  u64 offset;
  u64 length;
  u64 operation_id;
  u32 dry_run;
  u32 all_free;
} xaios_control_storage_trim_request_payload_user_t;

typedef struct xaios_control_storage_trim_report_user {
  unsigned char volume_uuid[16];
  u64 generation;
  u64 chunk_index;
  u64 cursor_offset;
  u64 requested_offset;
  u64 requested_length;
  u64 eligible_bytes;
  u64 trimmed_bytes;
  u64 trimmed_ranges;
  u64 error_count;
  u32 state;
  u32 dry_run;
  u32 all_free;
} xaios_control_storage_trim_report_user_t;

typedef struct xaios_control_model_cleanup_report_user {
  u64 operation_id;
  u64 generation;
  u64 reclaimed_bytes;
  u32 changed;
  u32 reserved;
} xaios_control_model_cleanup_report_user_t;

typedef struct xaios_model_volume_admin_report_user {
  char target[48];
  char partition_uuid[37];
  char volume_uuid[37];
  char bad_package_id[65];
  u64 partition_bytes;
  u64 volume_bytes;
  u64 allocated_bytes;
  u64 free_bytes;
  u64 chunk_size;
  u64 generation;
  u64 package_count;
  u64 active_packages;
  u64 staging_packages;
  u64 quarantined_packages;
  u64 checked_bytes;
  u64 bad_logical_offset;
  u32 first_superblock_valid;
  u32 second_superblock_valid;
  u32 copies_compatible;
  u32 check_state;
  u32 discard_supported;
  u32 dry_run;
} xaios_model_volume_admin_report_user_t;

typedef char xaios_admin_config_user_must_be_48_bytes[
    sizeof(xaios_admin_config_user_t) == 48U ? 1 : -1];
typedef char xaios_admin_key_record_user_must_be_104_bytes[
    sizeof(xaios_admin_key_record_user_t) == 104U ? 1 : -1];
typedef char xaios_admin_audit_record_user_must_be_112_bytes[
    sizeof(xaios_admin_audit_record_user_t) == 112U ? 1 : -1];
typedef char xaios_control_mutation_request_user_must_be_176_bytes[
    sizeof(xaios_control_mutation_request_payload_user_t) == 176U ? 1 : -1];
typedef char xaios_control_storage_device_record_user_must_be_176_bytes[
    sizeof(xaios_control_storage_device_record_user_t) == 176U ? 1 : -1];
typedef char xaios_control_storage_filesystem_record_user_must_be_216_bytes[
    sizeof(xaios_control_storage_filesystem_record_user_t) == 216U ? 1 : -1];
typedef char xaios_control_storage_volume_request_user_must_fit[
    sizeof(xaios_control_storage_volume_request_payload_user_t) <=
            XAIOS_CONTROL_MAX_REQUEST_BYTES -
                sizeof(xaios_control_request_header_user_t)
        ? 1
        : -1];
typedef char xaios_control_storage_replica_repair_request_user_must_fit[
    sizeof(xaios_control_storage_replica_repair_request_payload_user_t) <=
            XAIOS_CONTROL_MAX_REQUEST_BYTES -
                sizeof(xaios_control_request_header_user_t)
        ? 1
        : -1];
typedef char xaios_control_model_register_request_user_must_fit[
    sizeof(xaios_control_model_register_request_payload_user_t) <=
            XAIOS_CONTROL_MAX_REQUEST_BYTES -
                sizeof(xaios_control_request_header_user_t)
        ? 1
        : -1];

#endif
