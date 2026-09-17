#ifndef XAIOS_USERSPACE_CONTROL_PAYLOADS_H
#define XAIOS_USERSPACE_CONTROL_PAYLOADS_H

/* The core response payloads: version, status, health, capabilities,
   hardware, metrics and the runtime snapshot. Private sub-header of
   xaios_control.h, included after the request/response headers it follows
   in the original declaration order. */

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
  u32 xai_fs_version;
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
  u32 xaiboot_fs;
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
  u32 rvv;
  u32 sstc;
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
  u64 storage_writes;
  u64 storage_write_bytes;
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

#endif
