#ifndef XAIOS_CONTROL_PROTOCOL_PAYLOADS_H
#define XAIOS_CONTROL_PROTOCOL_PAYLOADS_H

/* The control protocol payload structs: version, status, health,
   capabilities, hardware, metrics, the runtime snapshot, logs,
   config/audit, auth keys, mutation, storage, model and update payloads.
   Private sub-header of control_protocol.h -- include that, not this.
   It is included after the protocol constants and the request/response
   headers, so the declarations keep their original order. */

typedef struct xaios_control_version_payload {
  /* The product version, as in VERSION and the changelog. A build identifier
     and a commit say which tree this came from; neither tells a customer what
     they are running or lets an advisory name affected releases. */
  char product_version[16];
  char build_identifier[32];
  char git_commit[48];
  char architecture[16];
  char build_mode[16];
  uint32_t kernel_abi_version;
  uint32_t control_protocol_version;
  uint32_t model_package_version;
  uint32_t xai_fs_version;
} xaios_control_version_payload_t;

typedef struct xaios_control_status_payload {
  uint64_t uptime_ns;
  uint64_t physical_pages;
  uint64_t managed_pages;
  uint64_t free_pages;
  uint64_t production_models_loaded;
  uint64_t queue_depth;
  uint64_t active_requests;
  uint64_t readiness_reasons;
  uint32_t online_cpus;
  uint32_t worker_count;
  uint32_t init_service_state;
  uint32_t manager_service_state;
  uint32_t ssh_service_state;
  uint32_t network_state;
  uint32_t storage_state;
  uint32_t model_state;
  uint32_t cluster_state;
  uint32_t readiness_state;
} xaios_control_status_payload_t;

typedef struct xaios_control_health_payload {
  uint64_t readiness_reasons;
  uint64_t process_failures;
  uint64_t memory_free_pages;
  uint64_t network_packet_drops;
  uint64_t log_overflows;
  uint32_t process_liveness;
  uint32_t node_readiness;
  uint32_t model_readiness;
  uint32_t cluster_readiness;
  uint32_t overall_state;
  uint32_t fatal;
} xaios_control_health_payload_t;

typedef struct xaios_control_capabilities_payload {
  uint32_t ssh;
  uint32_t sftp;
  uint32_t ipv4;
  uint32_t ipv6;
  uint32_t udp;
  uint32_t xaiboot_fs;
  uint32_t model_v1_fixture;
  uint32_t model_v2;
  uint32_t real_model_inference;
  uint32_t native_macos;
  uint32_t distributed_inference;
  uint32_t production_inference_service;
} xaios_control_capabilities_payload_t;

typedef struct xaios_control_hardware_payload {
  char architecture[16];
  char cpu_vendor[24];
  char cpu_model[40];
  char selected_backend[24];
  uint64_t physical_pages;
  uint64_t managed_pages;
  uint64_t free_pages;
  uint64_t model_reserved_bytes;
  uint64_t kv_reserved_bytes;
  uint64_t timer_frequency_hz;
  uint32_t core_count;
  uint32_t thread_count;
  uint32_t numa_nodes;
  uint32_t page_size;
  uint32_t neon;
  uint32_t sve;
  uint32_t avx2;
  uint32_t avx512;
  uint32_t vnni;
  uint32_t amx;
  uint32_t rvv;
  uint32_t sstc;
} xaios_control_hardware_payload_t;

typedef struct xaios_control_metrics_payload {
  uint64_t uptime_ns;
  uint64_t control_requests;
  uint64_t control_failures;
  uint64_t control_denials;
  uint64_t requests_accepted;
  uint64_t requests_completed;
  uint64_t requests_failed;
  uint64_t requests_cancelled;
  uint64_t queue_depth;
  uint64_t active_sessions;
  uint64_t tokens_generated;
  uint64_t prefill_tokens_per_second;
  uint64_t decode_tokens_per_second;
  uint64_t time_to_first_token_ns;
  uint64_t user_cpu_utilization_tenths;
  uint64_t physical_pages;
  uint64_t managed_pages;
  uint64_t free_pages;
  uint64_t model_resident_bytes;
  uint64_t kv_cache_bytes;
  uint64_t kv_cache_evictions;
  uint64_t storage_reads;
  uint64_t storage_read_bytes;
  uint64_t storage_writes;
  uint64_t storage_write_bytes;
  uint64_t network_rx_packets;
  uint64_t network_tx_packets;
  uint64_t network_rx_bytes;
  uint64_t network_tx_bytes;
  uint64_t network_errors;
  uint64_t cluster_rpc_retries;
  uint64_t cluster_rpc_timeouts;
  uint64_t fixture_inferences;
  uint64_t log_buffer_bytes;
  uint64_t log_overflows;
  uint32_t worker_count;
  uint32_t per_worker_health;
} xaios_control_metrics_payload_t;

#define XAIOS_CONTROL_RUNTIME_CPU_MAX UINT32_C(64)
#define XAIOS_CONTROL_RUNTIME_PROCESS_MAX UINT32_C(56)
#define XAIOS_CONTROL_RUNTIME_PROCESS_NAME_MAX UINT32_C(64)

typedef struct xaios_control_runtime_snapshot_request {
  uint32_t cpu_start;
  uint32_t cpu_limit;
  uint32_t process_start;
  uint32_t process_limit;
  uint32_t wait_ms;
  uint32_t reserved;
} xaios_control_runtime_snapshot_request_t;

typedef struct xaios_control_runtime_cpu_record {
  uint32_t cpu_id;
  uint32_t active_pid;
  uint32_t role;
  uint32_t reserved;
  uint64_t busy_ns;
  uint64_t elapsed_ns;
} xaios_control_runtime_cpu_record_t;

typedef struct xaios_control_runtime_process_record {
  uint32_t pid;
  uint32_t parent_pid;
  uint32_t cpu_id;
  uint32_t state;
  uint64_t runtime_ns;
  uint64_t resident_pages;
  uint64_t syscall_count;
  char name[XAIOS_CONTROL_RUNTIME_PROCESS_NAME_MAX];
} xaios_control_runtime_process_record_t;

typedef struct xaios_control_runtime_snapshot_payload {
  uint64_t sampled_at_ns;
  uint64_t cpu_busy_total_ns;
  uint64_t physical_pages;
  uint64_t managed_pages;
  uint64_t free_pages;
  uint32_t cpu_total;
  uint32_t cpu_start;
  uint32_t cpu_count;
  uint32_t cpu_next;
  uint32_t process_capacity;
  uint32_t process_start;
  uint32_t process_count;
  uint32_t process_next;
  uint32_t process_active;
  uint32_t process_failed;
  uint32_t load_average_hundredths[3];
  uint32_t reserved;
  xaios_control_runtime_cpu_record_t cpus[XAIOS_CONTROL_RUNTIME_CPU_MAX];
  xaios_control_runtime_process_record_t
      processes[XAIOS_CONTROL_RUNTIME_PROCESS_MAX];
} xaios_control_runtime_snapshot_payload_t;

typedef char xaios_control_runtime_snapshot_must_fit_response[
    sizeof(xaios_control_response_header_t) +
                sizeof(xaios_control_runtime_snapshot_payload_t) <=
            XAIOS_CONTROL_MAX_RESPONSE_BYTES
        ? 1
        : -1];

typedef struct xaios_control_log_request_payload {
  uint64_t since_cursor;
  uint32_t limit;
  uint32_t follow;
  char component[XAIOS_CONTROL_LOG_COMPONENT_MAX];
} xaios_control_log_request_payload_t;

typedef struct xaios_control_logs_payload {
  uint64_t start_cursor;
  uint64_t next_cursor;
  uint64_t latest_cursor;
  uint32_t record_count;
  uint32_t redacted_count;
  uint32_t timed_out;
  uint32_t reserved;
} xaios_control_logs_payload_t;

typedef struct xaios_control_path_request_payload {
  char path[XAIOS_CONTROL_PATH_MAX];
} xaios_control_path_request_payload_t;

typedef struct xaios_control_mutation_request_payload {
  uint64_t operation_id;
  uint32_t assigned_role;
  uint32_t reserved;
  char actor[XAIOS_ADMIN_PRINCIPAL_MAX];
  char argument[XAIOS_CONTROL_PATH_MAX];
  char target_principal[XAIOS_ADMIN_PRINCIPAL_MAX];
} xaios_control_mutation_request_payload_t;

typedef struct xaios_control_audit_request_payload {
  uint64_t since_sequence;
  uint32_t limit;
  uint32_t reserved;
} xaios_control_audit_request_payload_t;

typedef struct xaios_control_config_payload {
  xaios_admin_config_t config;
  uint32_t change_mask;
  uint32_t validated;
} xaios_control_config_payload_t;

typedef struct xaios_control_auth_keys_payload {
  uint64_t generation;
  uint32_t key_count;
  uint32_t revoked_count;
} xaios_control_auth_keys_payload_t;

typedef struct xaios_control_mutation_payload {
  uint64_t operation_id;
  uint64_t generation;
  uint32_t changed;
  uint32_t reserved;
} xaios_control_mutation_payload_t;

typedef struct xaios_control_app_request_payload {
  char name[32];
} xaios_control_app_request_payload_t;

typedef struct xaios_control_system_update_begin_payload {
  uint64_t payload_size;
  uint32_t generation;
  uint32_t reserved;
  uint8_t payload_hash[32];
  char signature[320];
} xaios_control_system_update_begin_payload_t;

#define XAIOS_CONTROL_SYSTEM_UPDATE_CHUNK_MAX 400U
typedef struct xaios_control_system_update_chunk_payload {
  uint32_t size;
  uint32_t reserved;
  uint8_t data[XAIOS_CONTROL_SYSTEM_UPDATE_CHUNK_MAX];
} xaios_control_system_update_chunk_payload_t;

typedef struct xaios_control_audit_payload {
  uint64_t next_sequence;
  uint64_t latest_sequence;
  uint32_t record_count;
  uint32_t reserved;
} xaios_control_audit_payload_t;

typedef struct xaios_control_storage_device_record {
  char identifier[48];
  char backend[24];
  uint64_t capacity_bytes;
  uint64_t capacity_logical_sectors;
  uint64_t logical_sector_size;
  uint64_t physical_block_size;
  uint64_t max_transfer_bytes;
  uint64_t discard_granularity;
  uint64_t max_discard_bytes;
  uint64_t read_bytes;
  uint64_t write_bytes;
  uint64_t discarded_bytes;
  uint64_t io_errors;
  uint32_t read_only;
  uint32_t flush_supported;
  uint32_t discard_supported;
  uint32_t write_zeroes_supported;
} xaios_control_storage_device_record_t;

typedef struct xaios_control_storage_devices_payload {
  uint32_t record_count;
  uint32_t total_count;
  uint32_t truncated;
  uint32_t reserved;
} xaios_control_storage_devices_payload_t;

typedef struct xaios_control_storage_filesystem_record {
  char mount_path[XAIOS_CONTROL_STORAGE_MOUNT_MAX];
  char filesystem[XAIOS_CONTROL_STORAGE_FILESYSTEM_MAX];
  char device_identifier[48];
  uint64_t total_bytes;
  uint64_t allocated_bytes;
  uint64_t free_bytes;
  uint64_t reserved_bytes;
  uint64_t file_count;
  uint64_t directory_count;
  uint64_t generation;
  uint64_t block_size;
  uint64_t package_count;
  uint64_t active_packages;
  uint64_t staging_packages;
  uint64_t quarantined_packages;
  uint32_t format_version;
  uint32_t mounted;
  uint32_t read_only;
  uint32_t staging_writable;
} xaios_control_storage_filesystem_record_t;

typedef struct xaios_control_storage_filesystems_payload {
  uint32_t record_count;
  uint32_t total_count;
  uint32_t truncated;
  uint32_t reserved;
} xaios_control_storage_filesystems_payload_t;

typedef struct xaios_control_storage_partition_request_payload {
  xaios_storage_partition_request_t request;
  char actor[XAIOS_ADMIN_PRINCIPAL_MAX];
} xaios_control_storage_partition_request_payload_t;

/* What an install needs: the disk to install onto, the EFI System Partition to
   copy from, and the target disk's own GUID as confirmation. The source is
   named rather than inferred -- a machine can have more than one, and the most
   destructive argument of an operation should not be a guess. */
typedef struct xaios_control_storage_install_request {
  char target[XAIOS_BLOCK_DEVICE_ID_MAX];
  char source[XAIOS_BLOCK_DEVICE_ID_MAX];
  char confirmation[XAIOS_STORAGE_GUID_TEXT_MAX];
  uint64_t operation_id;
} xaios_control_storage_install_request_t;

typedef struct xaios_control_storage_install_request_payload {
  xaios_control_storage_install_request_t request;
  char actor[XAIOS_ADMIN_PRINCIPAL_MAX];
} xaios_control_storage_install_request_payload_t;

typedef struct xaios_control_storage_install_result {
  char esp_identifier[XAIOS_BLOCK_DEVICE_ID_MAX];
  char state_identifier[XAIOS_BLOCK_DEVICE_ID_MAX];
  uint64_t files_copied;
  uint64_t bytes_copied;
  uint64_t esp_bytes;
  uint64_t state_bytes;
} xaios_control_storage_install_result_t;

typedef struct xaios_control_storage_partitions_payload {
  xaios_storage_partition_report_t report;
  uint32_t record_count;
  uint32_t total_count;
  uint32_t truncated;
  uint32_t reserved;
} xaios_control_storage_partitions_payload_t;

typedef struct xaios_control_storage_volume_request_payload {
  char target[XAIOS_BLOCK_DEVICE_ID_MAX];
  char confirmation[XAIOS_STORAGE_GUID_TEXT_MAX];
  char mount_path[XAIOS_CONTROL_STORAGE_MOUNT_MAX];
  char actor[XAIOS_ADMIN_PRINCIPAL_MAX];
  uint64_t size_bytes;
  uint64_t chunk_size;
  uint64_t operation_id;
  uint32_t verify_data;
  uint32_t read_only;
  uint32_t reserved;
} xaios_control_storage_volume_request_payload_t;

typedef struct xaios_control_storage_replica_repair_request_payload {
  char target[XAIOS_BLOCK_DEVICE_ID_MAX];
  char replica[XAIOS_BLOCK_DEVICE_ID_MAX];
  char confirmation[XAIOS_STORAGE_GUID_TEXT_MAX];
  char package_id[65];
  char actor[XAIOS_ADMIN_PRINCIPAL_MAX];
  uint64_t operation_id;
} xaios_control_storage_replica_repair_request_payload_t;

typedef struct xaios_control_model_register_request_payload {
  uint64_t operation_id;
  uint64_t logical_size;
  uint8_t model_uuid[16];
  uint8_t package_id[32];
  uint8_t signer_public_key[32];
  uint8_t signature[64];
  uint8_t source_revision[32];
  char architecture_id[33];
  char target_id[33];
  char actor[XAIOS_ADMIN_PRINCIPAL_MAX];
} xaios_control_model_register_request_payload_t;

typedef struct xaios_control_storage_scrub_report {
  xaios_model_scrub_status_t status;
} xaios_control_storage_scrub_report_t;

typedef struct xaios_control_storage_trim_request_payload {
  char target[XAIOS_CONTROL_STORAGE_MOUNT_MAX];
  char actor[XAIOS_ADMIN_PRINCIPAL_MAX];
  uint64_t offset;
  uint64_t length;
  uint64_t operation_id;
  uint32_t dry_run;
  uint32_t all_free;
} xaios_control_storage_trim_request_payload_t;

typedef struct xaios_control_storage_trim_report {
  xaios_model_trim_status_t status;
} xaios_control_storage_trim_report_t;

typedef struct xaios_control_model_cleanup_report {
  uint64_t operation_id;
  uint64_t generation;
  uint64_t reclaimed_bytes;
  uint32_t changed;
  uint32_t reserved;
} xaios_control_model_cleanup_report_t;

#endif
