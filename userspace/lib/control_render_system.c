/*
 * The control client's system and status renderers: version, status, health,
 * capabilities, hardware, metrics and logs.
 *
 * Each turns one decoded reply payload into the text or JSON a caller prints,
 * and calls nothing but the primitives in control_render_primitives.c. They are
 * declared in xaios_control_internal.h. The configuration, auth-key and storage
 * renderers are still in xaios_control_client.c; the block above 500 lines was
 * cut at the boundary between observability and configuration.
 */

#include "xaios_control_internal.h"

int render_version(const void *payload, int json, char *output,
                          u64 capacity, u64 *offset, u64 request_id) {
  xaios_control_version_payload_user_t value;
  bytes_copy(&value, payload, sizeof(value));
  if (json != 0) {
    int first = 1;
    return json_envelope_begin(output, capacity, offset, request_id) ||
           json_field_string(output, capacity, offset, &first,
                             "product_version", value.product_version) ||
           json_field_string(output, capacity, offset, &first,
                             "build_identifier", value.build_identifier) ||
           json_field_string(output, capacity, offset, &first, "git_commit",
                             value.git_commit) ||
           json_field_u64(output, capacity, offset, &first,
                          "kernel_abi_version", value.kernel_abi_version) ||
           json_field_u64(output, capacity, offset, &first,
                          "control_protocol_version",
                          value.control_protocol_version) ||
           json_field_u64(output, capacity, offset, &first,
                          "model_package_version",
                          value.model_package_version) ||
           json_field_u64(output, capacity, offset, &first,
                          "xai_fs_version",
                          value.xai_fs_version == 0U
                              ? XAIOS_CONTROL_UNKNOWN_U64
                              : value.xai_fs_version) ||
           json_field_string(output, capacity, offset, &first,
                             "architecture", value.architecture) ||
           json_field_string(output, capacity, offset, &first, "build_mode",
                             value.build_mode) ||
           json_envelope_end(output, capacity, offset);
  }
  return append_text(output, capacity, offset, "XAIOS version\n") ||
         append_text(output, capacity, offset, "product_version=") ||
         append_text(output, capacity, offset, value.product_version) ||
         append_char(output, capacity, offset, '\n') ||
         append_text(output, capacity, offset, "build_identifier=") ||
         append_text(output, capacity, offset, value.build_identifier) ||
         append_char(output, capacity, offset, '\n') ||
         append_text(output, capacity, offset, "git_commit=") ||
         append_text(output, capacity, offset, value.git_commit) ||
         append_char(output, capacity, offset, '\n') ||
         human_field_u64(output, capacity, offset, "kernel_abi_version",
                         value.kernel_abi_version) ||
         human_field_u64(output, capacity, offset, "control_protocol_version",
                         value.control_protocol_version) ||
         human_field_u64(output, capacity, offset, "model_package_version",
                         value.model_package_version) ||
         human_field_u64(output, capacity, offset, "xai_fs_version",
                         value.xai_fs_version == 0U
                             ? XAIOS_CONTROL_UNKNOWN_U64
                             : value.xai_fs_version) ||
         append_text(output, capacity, offset, "architecture=") ||
         append_text(output, capacity, offset, value.architecture) ||
         append_char(output, capacity, offset, '\n') ||
         append_text(output, capacity, offset, "build_mode=") ||
         append_text(output, capacity, offset, value.build_mode) ||
         append_char(output, capacity, offset, '\n');
}

int render_status(const void *payload, int json, char *output,
                         u64 capacity, u64 *offset, u64 request_id) {
  xaios_control_status_payload_user_t value;
  bytes_copy(&value, payload, sizeof(value));
  if (json != 0) {
    int first = 1;
    return json_envelope_begin(output, capacity, offset, request_id) ||
           json_field_u64(output, capacity, offset, &first, "uptime_ns",
                          value.uptime_ns) ||
           json_field_u64(output, capacity, offset, &first, "online_cpus",
                          value.online_cpus) ||
           json_field_u64(output, capacity, offset, &first, "worker_count",
                          value.worker_count) ||
           json_field_state(output, capacity, offset, &first, "init_service",
                            value.init_service_state) ||
           json_field_state(output, capacity, offset, &first,
                            "service_manager", value.manager_service_state) ||
           json_field_state(output, capacity, offset, &first, "ssh",
                            value.ssh_service_state) ||
           json_field_state(output, capacity, offset, &first, "network",
                            value.network_state) ||
           json_field_state(output, capacity, offset, &first, "storage",
                            value.storage_state) ||
           json_field_state(output, capacity, offset, &first, "model",
                            value.model_state) ||
           json_field_state(output, capacity, offset, &first, "cluster",
                            value.cluster_state) ||
           json_field_state(output, capacity, offset, &first, "readiness",
                            value.readiness_state) ||
           json_field_u64(output, capacity, offset, &first,
                          "readiness_reasons", value.readiness_reasons) ||
           json_field_u64(output, capacity, offset, &first,
                          "production_models_loaded",
                          value.production_models_loaded) ||
           json_field_u64(output, capacity, offset, &first, "queue_depth",
                          value.queue_depth) ||
           json_field_u64(output, capacity, offset, &first, "active_requests",
                          value.active_requests) ||
           json_field_u64(output, capacity, offset, &first, "physical_pages",
                          value.physical_pages) ||
           json_field_u64(output, capacity, offset, &first, "managed_pages",
                          value.managed_pages) ||
           json_field_u64(output, capacity, offset, &first, "free_pages",
                          value.free_pages) ||
           json_envelope_end(output, capacity, offset);
  }
  return human_field_u64(output, capacity, offset, "uptime_ns",
                         value.uptime_ns) ||
         human_field_state(output, capacity, offset, "init_service",
                           value.init_service_state) ||
         human_field_state(output, capacity, offset, "service_manager",
                           value.manager_service_state) ||
         human_field_state(output, capacity, offset, "ssh",
                           value.ssh_service_state) ||
         human_field_state(output, capacity, offset, "network",
                           value.network_state) ||
         human_field_state(output, capacity, offset, "storage",
                           value.storage_state) ||
         human_field_state(output, capacity, offset, "model",
                           value.model_state) ||
         human_field_state(output, capacity, offset, "cluster",
                           value.cluster_state) ||
         human_field_state(output, capacity, offset, "readiness",
                           value.readiness_state) ||
         human_field_u64(output, capacity, offset, "readiness_reasons",
                         value.readiness_reasons) ||
         human_field_u64(output, capacity, offset, "online_cpus",
                         value.online_cpus) ||
         human_field_u64(output, capacity, offset, "worker_count",
                         value.worker_count) ||
         human_field_u64(output, capacity, offset, "production_models_loaded",
                         value.production_models_loaded) ||
         human_field_u64(output, capacity, offset, "queue_depth",
                         value.queue_depth) ||
         human_field_u64(output, capacity, offset, "active_requests",
                         value.active_requests) ||
         human_field_u64(output, capacity, offset, "physical_pages",
                         value.physical_pages) ||
         human_field_u64(output, capacity, offset, "managed_pages",
                         value.managed_pages) ||
         human_field_u64(output, capacity, offset, "free_pages",
                         value.free_pages);
}

int render_health(const void *payload, int json, char *output,
                         u64 capacity, u64 *offset, u64 request_id) {
  xaios_control_health_payload_user_t value;
  bytes_copy(&value, payload, sizeof(value));
  if (json != 0) {
    int first = 1;
    return json_envelope_begin(output, capacity, offset, request_id) ||
           json_field_state(output, capacity, offset, &first, "overall",
                            value.overall_state) ||
           json_field_state(output, capacity, offset, &first,
                            "process_liveness", value.process_liveness) ||
           json_field_state(output, capacity, offset, &first,
                            "node_readiness", value.node_readiness) ||
           json_field_state(output, capacity, offset, &first,
                            "model_readiness", value.model_readiness) ||
           json_field_state(output, capacity, offset, &first,
                            "cluster_readiness", value.cluster_readiness) ||
           json_field_u64(output, capacity, offset, &first, "fatal",
                          value.fatal) ||
           json_field_u64(output, capacity, offset, &first,
                          "readiness_reasons", value.readiness_reasons) ||
           json_field_u64(output, capacity, offset, &first,
                          "process_failures", value.process_failures) ||
           json_field_u64(output, capacity, offset, &first,
                          "memory_free_pages", value.memory_free_pages) ||
           json_field_u64(output, capacity, offset, &first,
                          "network_packet_drops",
                          value.network_packet_drops) ||
           json_field_u64(output, capacity, offset, &first, "log_overflows",
                          value.log_overflows) ||
           json_envelope_end(output, capacity, offset);
  }
  return human_field_state(output, capacity, offset, "overall",
                           value.overall_state) ||
         human_field_state(output, capacity, offset, "process_liveness",
                           value.process_liveness) ||
         human_field_state(output, capacity, offset, "node_readiness",
                           value.node_readiness) ||
         human_field_state(output, capacity, offset, "model_readiness",
                           value.model_readiness) ||
         human_field_state(output, capacity, offset, "cluster_readiness",
                           value.cluster_readiness) ||
         human_field_u64(output, capacity, offset, "fatal", value.fatal) ||
         human_field_u64(output, capacity, offset, "readiness_reasons",
                         value.readiness_reasons) ||
         human_field_u64(output, capacity, offset, "process_failures",
                         value.process_failures) ||
         human_field_u64(output, capacity, offset, "memory_free_pages",
                         value.memory_free_pages) ||
         human_field_u64(output, capacity, offset, "network_packet_drops",
                         value.network_packet_drops) ||
         human_field_u64(output, capacity, offset, "log_overflows",
                         value.log_overflows);
}

int render_capabilities(const void *payload, int json, char *output,
                               u64 capacity, u64 *offset, u64 request_id) {
  xaios_control_capabilities_payload_user_t value;
  bytes_copy(&value, payload, sizeof(value));
  if (json != 0) {
    int first = 1;
    return json_envelope_begin(output, capacity, offset, request_id) ||
           json_field_state(output, capacity, offset, &first, "ssh",
                            value.ssh) ||
           json_field_state(output, capacity, offset, &first, "sftp",
                            value.sftp) ||
           json_field_state(output, capacity, offset, &first, "ipv4",
                            value.ipv4) ||
           json_field_state(output, capacity, offset, &first, "ipv6",
                            value.ipv6) ||
           json_field_state(output, capacity, offset, &first, "udp",
                            value.udp) ||
           json_field_state(output, capacity, offset, &first, "xaiboot_fs",
                            value.xaiboot_fs) ||
           json_field_state(output, capacity, offset, &first,
                            "model_v1_fixture", value.model_v1_fixture) ||
           json_field_state(output, capacity, offset, &first, "model_v2",
                            value.model_v2) ||
           json_field_state(output, capacity, offset, &first,
                            "real_model_inference",
                            value.real_model_inference) ||
           json_field_state(output, capacity, offset, &first,
                            "native_macos", value.native_macos) ||
           json_field_state(output, capacity, offset, &first,
                            "distributed_inference",
                            value.distributed_inference) ||
           json_field_state(output, capacity, offset, &first,
                            "production_inference_service",
                            value.production_inference_service) ||
           json_envelope_end(output, capacity, offset);
  }
  return human_field_state(output, capacity, offset, "ssh", value.ssh) ||
         human_field_state(output, capacity, offset, "sftp", value.sftp) ||
         human_field_state(output, capacity, offset, "ipv4", value.ipv4) ||
         human_field_state(output, capacity, offset, "ipv6", value.ipv6) ||
         human_field_state(output, capacity, offset, "udp", value.udp) ||
         human_field_state(output, capacity, offset, "xaiboot_fs",
                           value.xaiboot_fs) ||
         human_field_state(output, capacity, offset, "model_v1_fixture",
                           value.model_v1_fixture) ||
         human_field_state(output, capacity, offset, "model_v2",
                           value.model_v2) ||
         human_field_state(output, capacity, offset, "real_model_inference",
                           value.real_model_inference) ||
         human_field_state(output, capacity, offset, "native_macos",
                           value.native_macos) ||
         human_field_state(output, capacity, offset, "distributed_inference",
                           value.distributed_inference) ||
         human_field_state(output, capacity, offset,
                           "production_inference_service",
                           value.production_inference_service);
}

int render_hardware(const void *payload, int json, char *output,
                           u64 capacity, u64 *offset, u64 request_id) {
  xaios_control_hardware_payload_user_t value;
  bytes_copy(&value, payload, sizeof(value));
  if (json != 0) {
    int first = 1;
    return json_envelope_begin(output, capacity, offset, request_id) ||
           json_field_string(output, capacity, offset, &first, "architecture",
                             value.architecture) ||
           json_field_string(output, capacity, offset, &first, "cpu_vendor",
                             value.cpu_vendor) ||
           json_field_string(output, capacity, offset, &first, "cpu_model",
                             value.cpu_model) ||
           json_field_u64(output, capacity, offset, &first, "core_count",
                          value.core_count) ||
           json_field_u64(output, capacity, offset, &first, "thread_count",
                          value.thread_count) ||
           json_field_u64(output, capacity, offset, &first, "numa_nodes",
                          value.numa_nodes) ||
           json_field_u64(output, capacity, offset, &first, "page_size",
                          value.page_size) ||
           json_field_u64(output, capacity, offset, &first, "physical_pages",
                          value.physical_pages) ||
           json_field_u64(output, capacity, offset, &first, "managed_pages",
                          value.managed_pages) ||
           json_field_u64(output, capacity, offset, &first, "free_pages",
                          value.free_pages) ||
           json_field_u64(output, capacity, offset, &first,
                          "model_reserved_bytes",
                          value.model_reserved_bytes) ||
           json_field_u64(output, capacity, offset, &first,
                          "kv_reserved_bytes", value.kv_reserved_bytes) ||
           json_field_u64(output, capacity, offset, &first,
                          "timer_frequency_hz", value.timer_frequency_hz) ||
           json_field_state(output, capacity, offset, &first, "neon",
                            value.neon) ||
           json_field_state(output, capacity, offset, &first, "sve",
                            value.sve) ||
           json_field_state(output, capacity, offset, &first, "avx2",
                            value.avx2) ||
           json_field_state(output, capacity, offset, &first, "avx512",
                            value.avx512) ||
           json_field_state(output, capacity, offset, &first, "vnni",
                            value.vnni) ||
           json_field_state(output, capacity, offset, &first, "amx",
                            value.amx) ||
           json_field_string(output, capacity, offset, &first,
                             "selected_backend", value.selected_backend) ||
           json_envelope_end(output, capacity, offset);
  }
  return append_text(output, capacity, offset, "architecture=") ||
         append_text(output, capacity, offset, value.architecture) ||
         append_char(output, capacity, offset, '\n') ||
         append_text(output, capacity, offset, "cpu_vendor=") ||
         append_text(output, capacity, offset, value.cpu_vendor) ||
         append_char(output, capacity, offset, '\n') ||
         append_text(output, capacity, offset, "cpu_model=") ||
         append_text(output, capacity, offset, value.cpu_model) ||
         append_char(output, capacity, offset, '\n') ||
         human_field_u64(output, capacity, offset, "core_count",
                         value.core_count) ||
         human_field_u64(output, capacity, offset, "thread_count",
                         value.thread_count) ||
         human_field_u64(output, capacity, offset, "numa_nodes",
                         value.numa_nodes) ||
         human_field_u64(output, capacity, offset, "page_size",
                         value.page_size) ||
         human_field_u64(output, capacity, offset, "physical_pages",
                         value.physical_pages) ||
         human_field_u64(output, capacity, offset, "managed_pages",
                         value.managed_pages) ||
         human_field_u64(output, capacity, offset, "free_pages",
                         value.free_pages) ||
         human_field_u64(output, capacity, offset, "model_reserved_bytes",
                         value.model_reserved_bytes) ||
         human_field_u64(output, capacity, offset, "kv_reserved_bytes",
                         value.kv_reserved_bytes) ||
         human_field_u64(output, capacity, offset, "timer_frequency_hz",
                         value.timer_frequency_hz) ||
         human_field_state(output, capacity, offset, "neon", value.neon) ||
         human_field_state(output, capacity, offset, "sve", value.sve) ||
         human_field_state(output, capacity, offset, "avx2", value.avx2) ||
         human_field_state(output, capacity, offset, "avx512", value.avx512) ||
         human_field_state(output, capacity, offset, "vnni", value.vnni) ||
         human_field_state(output, capacity, offset, "amx", value.amx) ||
         append_text(output, capacity, offset, "selected_backend=") ||
         append_text(output, capacity, offset, value.selected_backend) ||
         append_char(output, capacity, offset, '\n');
}

int render_metrics(const void *payload, int json, char *output,
                          u64 capacity, u64 *offset, u64 request_id) {
  xaios_control_metrics_payload_user_t value;
  bytes_copy(&value, payload, sizeof(value));
  struct metric_field {
    const char *name;
    u64 value;
  } fields[] = {
      {"uptime_ns", value.uptime_ns},
      {"control_requests", value.control_requests},
      {"control_failures", value.control_failures},
      {"control_denials", value.control_denials},
      {"requests_accepted", value.requests_accepted},
      {"requests_completed", value.requests_completed},
      {"requests_failed", value.requests_failed},
      {"requests_cancelled", value.requests_cancelled},
      {"queue_depth", value.queue_depth},
      {"active_sessions", value.active_sessions},
      {"tokens_generated", value.tokens_generated},
      {"prefill_tokens_per_second", value.prefill_tokens_per_second},
      {"decode_tokens_per_second", value.decode_tokens_per_second},
      {"time_to_first_token_ns", value.time_to_first_token_ns},
      {"user_cpu_utilization_tenths", value.user_cpu_utilization_tenths},
      {"physical_pages", value.physical_pages},
      {"managed_pages", value.managed_pages},
      {"free_pages", value.free_pages},
      {"model_resident_bytes", value.model_resident_bytes},
      {"kv_cache_bytes", value.kv_cache_bytes},
      {"kv_cache_evictions", value.kv_cache_evictions},
      {"storage_reads", value.storage_reads},
      {"storage_read_bytes", value.storage_read_bytes},
      {"network_rx_packets", value.network_rx_packets},
      {"network_tx_packets", value.network_tx_packets},
      {"network_rx_bytes", value.network_rx_bytes},
      {"network_tx_bytes", value.network_tx_bytes},
      {"network_errors", value.network_errors},
      {"cluster_rpc_retries", value.cluster_rpc_retries},
      {"cluster_rpc_timeouts", value.cluster_rpc_timeouts},
      {"fixture_inferences", value.fixture_inferences},
      {"log_buffer_bytes", value.log_buffer_bytes},
      {"log_overflows", value.log_overflows},
      {"worker_count", value.worker_count},
  };
  if (json != 0) {
    int first = 1;
    if (json_envelope_begin(output, capacity, offset, request_id) != 0) {
      return -1;
    }
    for (u64 i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i) {
      if (json_field_u64(output, capacity, offset, &first, fields[i].name,
                         fields[i].value) != 0) {
        return -1;
      }
    }
    if (json_field_state(output, capacity, offset, &first,
                         "per_worker_health", value.per_worker_health) != 0) {
      return -1;
    }
    return json_envelope_end(output, capacity, offset);
  }
  for (u64 i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i) {
    if (human_field_u64(output, capacity, offset, fields[i].name,
                        fields[i].value) != 0) {
      return -1;
    }
  }
  return human_field_state(output, capacity, offset, "per_worker_health",
                           value.per_worker_health);
}

int render_logs(const void *payload, u64 payload_length, int json,
                       char *output, u64 capacity, u64 *offset,
                       u64 request_id) {
  xaios_control_logs_payload_user_t value;
  if (payload_length < sizeof(value)) {
    return -1;
  }
  bytes_copy(&value, payload, sizeof(value));
  const char *records = (const char *)payload + sizeof(value);
  u64 records_size = payload_length - sizeof(value);
  if (json != 0) {
    int first = 1;
    return json_envelope_begin(output, capacity, offset, request_id) ||
           json_field_u64(output, capacity, offset, &first, "start_cursor",
                          value.start_cursor) ||
           json_field_u64(output, capacity, offset, &first, "next_cursor",
                          value.next_cursor) ||
           json_field_u64(output, capacity, offset, &first, "latest_cursor",
                          value.latest_cursor) ||
           json_field_u64(output, capacity, offset, &first, "record_count",
                          value.record_count) ||
           json_field_u64(output, capacity, offset, &first, "redacted_count",
                          value.redacted_count) ||
           json_field_u64(output, capacity, offset, &first, "timed_out",
                          value.timed_out) ||
           json_field_prefix(output, capacity, offset, &first, "records") ||
           append_json_string(output, capacity, offset, records, records_size) ||
           json_envelope_end(output, capacity, offset);
  }
  if (human_field_u64(output, capacity, offset, "start_cursor",
                      value.start_cursor) != 0 ||
      human_field_u64(output, capacity, offset, "next_cursor",
                      value.next_cursor) != 0 ||
      human_field_u64(output, capacity, offset, "latest_cursor",
                      value.latest_cursor) != 0 ||
      human_field_u64(output, capacity, offset, "record_count",
                      value.record_count) != 0 ||
      human_field_u64(output, capacity, offset, "redacted_count",
                      value.redacted_count) != 0 ||
      human_field_u64(output, capacity, offset, "timed_out",
                      value.timed_out) != 0) {
    return -1;
  }
  for (u64 i = 0; i < records_size; ++i) {
    if (append_char(output, capacity, offset, records[i]) != 0) {
      return -1;
    }
  }
  return 0;
}
