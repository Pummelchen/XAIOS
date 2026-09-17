/* Version, status, health, capability, hardware and metric operations of the
 * control protocol.
 *
 * Split out of control_protocol.c so no source file exceeds 500 lines. The
 * dispatch table, the self-test and the runtime-snapshot operation stay
 * behind: the snapshot takes a request payload and returns a paged reply,
 * unlike the fixed-size answers here. The bodies below were written against
 * control_protocol.c's file-local helper names; the aliases bind them to the
 * prefixed exports the private header declares.
 */

#include "control_protocol_internal.h"

#include <xaios/cpu_ai_runtime.h>
#include <xaios/cpu_features.h>
#include <xaios/klog_ring.h>
#include <xaios/network_stack.h>
#include <xaios/numa.h>
#include <xaios/pmm.h>
#include <xaios/scheduler.h>
#include <xaios/service.h>
#include <xaios/smp.h>
#include <xaios/timer.h>
#include <xaios/user.h>
#include <xaios/version.h>
#include <xaios/xaiboot_fs.h>

#ifndef XAIOS_BUILD_REVISION
#define XAIOS_BUILD_REVISION "unknown"
#endif

#ifndef XAIOS_BUILD_IDENTIFIER
#define XAIOS_BUILD_IDENTIFIER "xaios-admin-control-dirty"
#endif

#ifndef XAIOS_BUILD_MODE
#define XAIOS_BUILD_MODE "development"
#endif

#define bytes_zero control_protocol_bytes_zero
#define string_copy control_protocol_string_copy
#define string_equal control_protocol_string_equal
#define write_error control_protocol_write_error
#define write_response control_protocol_write_response

static uint32_t service_control_state(const char *name) {
  xaios_service_t service;
  if (service_snapshot(name, &service) != XAIOS_OK) {
    return XAIOS_CONTROL_STATE_UNKNOWN;
  }
  if (service.state == XAIOS_SERVICE_RUNNING ||
      service.state == XAIOS_SERVICE_STARTING) {
    return XAIOS_CONTROL_STATE_RUNNING;
  }
  if (service.state == XAIOS_SERVICE_FAILED) {
    return XAIOS_CONTROL_STATE_FATAL;
  }
  return XAIOS_CONTROL_STATE_STOPPED;
}

static uint32_t process_control_state(const char *name) {
  xaios_user_process_t process;
  for (uint32_t pid = 1U; pid <= XAIOS_MAX_USER_PROCESSES; ++pid) {
    if (user_process_snapshot(pid, &process) != XAIOS_OK ||
        !string_equal(process.name, name)) {
      continue;
    }
    if (process.state == XAIOS_USER_PROCESS_LOADED ||
        process.state == XAIOS_USER_PROCESS_RUNNABLE ||
        process.state == XAIOS_USER_PROCESS_RUNNING ||
        process.state == XAIOS_USER_PROCESS_WAITING) {
      return XAIOS_CONTROL_STATE_RUNNING;
    }
    if (process.state == XAIOS_USER_PROCESS_FAILED) {
      return XAIOS_CONTROL_STATE_FATAL;
    }
    return XAIOS_CONTROL_STATE_STOPPED;
  }
  return XAIOS_CONTROL_STATE_UNKNOWN;
}

static uint32_t active_process_count(const char *name) {
  uint32_t count = 0;
  xaios_user_process_t process;
  for (uint32_t pid = 1U; pid <= XAIOS_MAX_USER_PROCESSES; ++pid) {
    if (user_process_snapshot(pid, &process) == XAIOS_OK &&
        string_equal(process.name, name) &&
        (process.state == XAIOS_USER_PROCESS_LOADED ||
         process.state == XAIOS_USER_PROCESS_RUNNABLE ||
         process.state == XAIOS_USER_PROCESS_RUNNING ||
         process.state == XAIOS_USER_PROCESS_WAITING)) {
      ++count;
    }
  }
  return count;
}

static uint64_t readiness_reasons(void) {
  uint64_t reasons = XAIOS_CONTROL_READINESS_MODEL |
                     XAIOS_CONTROL_READINESS_INFERENCE |
                     XAIOS_CONTROL_READINESS_CLUSTER;
  if (process_control_state("/bin/sshd") != XAIOS_CONTROL_STATE_RUNNING) {
    reasons |= XAIOS_CONTROL_READINESS_SSH;
  }
  if (!network_stack_has_listener(2222U)) {
    reasons |= XAIOS_CONTROL_READINESS_NETWORK;
  }
  if (xaiboot_fs_persistent_mount_count() == 0U) {
    reasons |= XAIOS_CONTROL_READINESS_STORAGE;
  }
  return reasons;
}

static void fill_version(xaios_control_version_payload_t *payload) {
  bytes_zero(payload, sizeof(*payload));
  string_copy(payload->product_version, sizeof(payload->product_version),
              XAIOS_BUILD_LABEL);
  string_copy(payload->build_identifier, sizeof(payload->build_identifier),
              XAIOS_BUILD_IDENTIFIER);
  string_copy(payload->git_commit, sizeof(payload->git_commit),
              XAIOS_BUILD_REVISION);
#if defined(__aarch64__)
  string_copy(payload->architecture, sizeof(payload->architecture),
              "aarch64");
#elif defined(__x86_64__)
  string_copy(payload->architecture, sizeof(payload->architecture),
              "x86_64");
#elif defined(__riscv)
  /* This answered "unknown" on a machine that knows perfectly well what it
     is, because the list was written when there were two architectures and
     never revisited. An external client asking a RISC-V guest what it was
     got a shrug. */
  string_copy(payload->architecture, sizeof(payload->architecture),
              "riscv64");
#else
  string_copy(payload->architecture, sizeof(payload->architecture),
              "unknown");
#endif
  string_copy(payload->build_mode, sizeof(payload->build_mode),
              XAIOS_BUILD_MODE);
  payload->kernel_abi_version = XAIOS_CONTROL_KERNEL_ABI_VERSION;
  payload->control_protocol_version = XAIOS_CONTROL_VERSION;
  payload->model_package_version = XAIOS_CONTROL_MODEL_PACKAGE_VERSION;
  payload->xai_fs_version = XAIOS_CONTROL_XAI_FS_VERSION;
}

static void fill_status(xaios_control_status_payload_t *payload) {
  bytes_zero(payload, sizeof(*payload));
  payload->uptime_ns = timer_now_ns();
  payload->physical_pages = pmm_total_pages();
  payload->managed_pages = pmm_managed_pages();
  payload->free_pages = pmm_free_pages();
  payload->production_models_loaded = 0U;
  payload->queue_depth = XAIOS_CONTROL_UNKNOWN_U64;
  payload->active_requests = XAIOS_CONTROL_UNKNOWN_U64;
  payload->readiness_reasons = readiness_reasons();
  payload->online_cpus = smp_online_count();
  payload->worker_count = active_process_count("/bin/xaios-worker");
  payload->init_service_state = service_control_state("/init");
  payload->manager_service_state =
      service_control_state("/bin/service-manager");
  payload->ssh_service_state = process_control_state("/bin/sshd");
  payload->network_state = network_stack_has_listener(2222U)
                               ? XAIOS_CONTROL_STATE_RUNNING
                               : XAIOS_CONTROL_STATE_STOPPED;
  payload->storage_state = xaiboot_fs_persistent_mount_count() != 0U
                               ? XAIOS_CONTROL_STATE_READY
                               : XAIOS_CONTROL_STATE_STOPPED;
  payload->model_state = XAIOS_CONTROL_STATE_FIXTURE_ONLY;
  payload->cluster_state = XAIOS_CONTROL_STATE_UNSUPPORTED;
  payload->readiness_state = payload->readiness_reasons == 0U
                                 ? XAIOS_CONTROL_STATE_READY
                                 : XAIOS_CONTROL_STATE_DEGRADED;
}

static void fill_health(xaios_control_health_payload_t *payload) {
  const xaios_user_process_t *current = user_current_process();
  bytes_zero(payload, sizeof(*payload));
  payload->readiness_reasons = readiness_reasons();
  payload->process_failures = user_process_failed_count();
  payload->memory_free_pages = pmm_free_pages();
  payload->network_packet_drops = network_stack_packet_drop_count();
  payload->log_overflows = klog_ring_overflow_count();
  payload->process_liveness =
      current != 0 ? XAIOS_CONTROL_STATE_RUNNING : XAIOS_CONTROL_STATE_UNKNOWN;
  payload->node_readiness =
      smp_online_count() != 0U && payload->memory_free_pages != 0U &&
              xaiboot_fs_persistent_mount_count() != 0U
          ? XAIOS_CONTROL_STATE_READY
          : XAIOS_CONTROL_STATE_DEGRADED;
  payload->model_readiness = XAIOS_CONTROL_STATE_FIXTURE_ONLY;
  payload->cluster_readiness = XAIOS_CONTROL_STATE_UNSUPPORTED;
  payload->fatal = smp_online_count() == 0U || payload->memory_free_pages == 0U;
  payload->overall_state = payload->fatal != 0U
                               ? XAIOS_CONTROL_STATE_FATAL
                               : XAIOS_CONTROL_STATE_DEGRADED;
}

static void fill_capabilities(xaios_control_capabilities_payload_t *payload) {
  bytes_zero(payload, sizeof(*payload));
  payload->ssh = XAIOS_CONTROL_STATE_AVAILABLE;
  payload->sftp = XAIOS_CONTROL_STATE_AVAILABLE;
  payload->ipv4 = XAIOS_CONTROL_STATE_AVAILABLE;
  payload->ipv6 = XAIOS_CONTROL_STATE_AVAILABLE;
  payload->udp = XAIOS_CONTROL_STATE_AVAILABLE;
  payload->xaiboot_fs = XAIOS_CONTROL_STATE_AVAILABLE;
  payload->model_v1_fixture = XAIOS_CONTROL_STATE_FIXTURE_ONLY;
  payload->model_v2 = XAIOS_CONTROL_STATE_INTERFACE_ONLY;
  payload->real_model_inference = XAIOS_CONTROL_STATE_UNSUPPORTED;
  payload->native_macos = XAIOS_CONTROL_STATE_UNSUPPORTED;
  payload->distributed_inference = XAIOS_CONTROL_STATE_UNSUPPORTED;
  payload->production_inference_service = XAIOS_CONTROL_STATE_UNSUPPORTED;
}

static void fill_hardware(xaios_control_hardware_payload_t *payload) {
  bytes_zero(payload, sizeof(*payload));
#if defined(__aarch64__)
  string_copy(payload->architecture, sizeof(payload->architecture),
              "aarch64");
#elif defined(__x86_64__)
  string_copy(payload->architecture, sizeof(payload->architecture),
              "x86_64");
#elif defined(__riscv)
  /* This answered "unknown" on a machine that knows perfectly well what it
     is, because the list was written when there were two architectures and
     never revisited. An external client asking a RISC-V guest what it was
     got a shrug. */
  string_copy(payload->architecture, sizeof(payload->architecture),
              "riscv64");
#else
  string_copy(payload->architecture, sizeof(payload->architecture),
              "unknown");
#endif
  string_copy(payload->cpu_vendor, sizeof(payload->cpu_vendor), "unknown");
  string_copy(payload->cpu_model, sizeof(payload->cpu_model), "unknown");
  string_copy(payload->selected_backend, sizeof(payload->selected_backend),
              "fixture-only");
  payload->physical_pages = pmm_total_pages();
  payload->managed_pages = pmm_managed_pages();
  payload->free_pages = pmm_free_pages();
  payload->model_reserved_bytes = XAIOS_CONTROL_UNKNOWN_U64;
  payload->kv_reserved_bytes = XAIOS_CONTROL_UNKNOWN_U64;
  payload->timer_frequency_hz = timer_frequency_hz();
  payload->core_count = smp_online_count();
  payload->thread_count = smp_online_count();
  payload->numa_nodes = numa_node_count();
  payload->page_size = 4096U;
  /* Asked of the hardware. These were "unknown" on every architecture,
     which is the one answer a machine can always improve on. */
  xaios_cpu_features_t features;
  cpu_features_query(&features);
  payload->neon = features.neon;
  payload->sve = features.sve;
  payload->avx2 = features.avx2;
  payload->avx512 = features.avx512;
  payload->vnni = features.vnni;
  payload->amx = features.amx;
  payload->rvv = features.rvv;
  payload->sstc = features.sstc;
}

static uint64_t cpu_utilization_tenths(uint64_t now_ns) {
  uint64_t cpu_count = user_cpu_usage_count();
  uint64_t busy = 0U;
  uint64_t capacity = 0U;
  if (cpu_count == 0U || now_ns == 0U) {
    return XAIOS_CONTROL_UNKNOWN_U64;
  }
  for (uint32_t ordinal = 0U; ordinal < cpu_count; ++ordinal) {
    xaios_cpu_usage_snapshot_t snapshot;
    if (user_cpu_usage_snapshot(ordinal, now_ns, &snapshot) != XAIOS_OK ||
        UINT64_MAX - busy < snapshot.busy_ns ||
        UINT64_MAX - capacity < snapshot.elapsed_ns) {
      return XAIOS_CONTROL_UNKNOWN_U64;
    }
    busy += snapshot.busy_ns;
    capacity += snapshot.elapsed_ns;
  }
  if (busy > UINT64_MAX / UINT64_C(1000)) {
    busy /= UINT64_C(1000);
    capacity /= UINT64_C(1000);
  }
  return capacity == 0U ? XAIOS_CONTROL_UNKNOWN_U64
                        : (busy * UINT64_C(1000)) / capacity;
}

static void fill_metrics(xaios_control_metrics_payload_t *payload) {
  uint64_t now_ns = timer_now_ns();
  bytes_zero(payload, sizeof(*payload));
  payload->uptime_ns = now_ns;
  payload->control_requests = control_protocol_request_count();
  payload->control_failures = control_protocol_failure_count();
  payload->control_denials = control_protocol_denial_count();
  payload->requests_accepted = XAIOS_CONTROL_UNKNOWN_U64;
  payload->requests_completed = XAIOS_CONTROL_UNKNOWN_U64;
  payload->requests_failed = XAIOS_CONTROL_UNKNOWN_U64;
  payload->requests_cancelled = XAIOS_CONTROL_UNKNOWN_U64;
  payload->queue_depth = XAIOS_CONTROL_UNKNOWN_U64;
  payload->active_sessions = XAIOS_CONTROL_UNKNOWN_U64;
  payload->tokens_generated = XAIOS_CONTROL_UNKNOWN_U64;
  payload->prefill_tokens_per_second = XAIOS_CONTROL_UNKNOWN_U64;
  payload->decode_tokens_per_second = XAIOS_CONTROL_UNKNOWN_U64;
  payload->time_to_first_token_ns = XAIOS_CONTROL_UNKNOWN_U64;
  payload->user_cpu_utilization_tenths = cpu_utilization_tenths(now_ns);
  payload->physical_pages = pmm_total_pages();
  payload->managed_pages = pmm_managed_pages();
  payload->free_pages = pmm_free_pages();
  payload->model_resident_bytes = XAIOS_CONTROL_UNKNOWN_U64;
  payload->kv_cache_bytes = XAIOS_CONTROL_UNKNOWN_U64;
  payload->kv_cache_evictions = XAIOS_CONTROL_UNKNOWN_U64;
  payload->storage_reads = xaiboot_fs_read_count();
  payload->storage_read_bytes = XAIOS_CONTROL_UNKNOWN_U64;
  payload->storage_writes = xaiboot_fs_write_count();
  payload->storage_write_bytes = XAIOS_CONTROL_UNKNOWN_U64;
  payload->network_rx_packets = network_stack_rx_packet_count();
  payload->network_tx_packets = network_stack_tx_packet_count();
  payload->network_rx_bytes = XAIOS_CONTROL_UNKNOWN_U64;
  payload->network_tx_bytes = XAIOS_CONTROL_UNKNOWN_U64;
  payload->network_errors = network_stack_packet_drop_count() +
                            network_stack_tcp_reset_count() +
                            network_stack_tcp_timeout_count();
  payload->cluster_rpc_retries = XAIOS_CONTROL_UNKNOWN_U64;
  payload->cluster_rpc_timeouts = XAIOS_CONTROL_UNKNOWN_U64;
  payload->fixture_inferences = cpu_ai_runtime_inference_count();
  payload->log_buffer_bytes = klog_ring_count();
  payload->log_overflows = klog_ring_overflow_count();
  payload->worker_count = active_process_count("/bin/xaios-worker");
  payload->per_worker_health = XAIOS_CONTROL_STATE_UNKNOWN;
}

xaios_status_t control_protocol_handle_observability_operation(
    const xaios_control_request_header_t *request, void *response,
    uint64_t response_capacity, uint64_t *response_bytes) {
  switch ((xaios_control_operation_t)request->operation) {
  case XAIOS_CONTROL_OP_VERSION: {
    xaios_control_version_payload_t value;
    if (request->payload_type != XAIOS_CONTROL_PAYLOAD_NONE ||
        request->payload_length != 0U) {
      return write_error(response, response_capacity, response_bytes,
                         request->operation, request->request_id,
                         XAIOS_CONTROL_STATUS_INVALID_REQUEST);
    }
    fill_version(&value);
    return write_response(response, response_capacity, response_bytes,
                          request->operation, request->request_id,
                          XAIOS_CONTROL_STATUS_OK,
                          XAIOS_CONTROL_PAYLOAD_VERSION, &value,
                          sizeof(value));
  }
  case XAIOS_CONTROL_OP_STATUS: {
    xaios_control_status_payload_t value;
    if (request->payload_type != XAIOS_CONTROL_PAYLOAD_NONE ||
        request->payload_length != 0U) {
      return write_error(response, response_capacity, response_bytes,
                         request->operation, request->request_id,
                         XAIOS_CONTROL_STATUS_INVALID_REQUEST);
    }
    fill_status(&value);
    return write_response(response, response_capacity, response_bytes,
                          request->operation, request->request_id,
                          XAIOS_CONTROL_STATUS_OK,
                          XAIOS_CONTROL_PAYLOAD_STATUS, &value,
                          sizeof(value));
  }
  case XAIOS_CONTROL_OP_HEALTH: {
    xaios_control_health_payload_t value;
    if (request->payload_type != XAIOS_CONTROL_PAYLOAD_NONE ||
        request->payload_length != 0U) {
      return write_error(response, response_capacity, response_bytes,
                         request->operation, request->request_id,
                         XAIOS_CONTROL_STATUS_INVALID_REQUEST);
    }
    fill_health(&value);
    return write_response(response, response_capacity, response_bytes,
                          request->operation, request->request_id,
                          XAIOS_CONTROL_STATUS_OK,
                          XAIOS_CONTROL_PAYLOAD_HEALTH, &value,
                          sizeof(value));
  }
  case XAIOS_CONTROL_OP_CAPABILITIES: {
    xaios_control_capabilities_payload_t value;
    if (request->payload_type != XAIOS_CONTROL_PAYLOAD_NONE ||
        request->payload_length != 0U) {
      return write_error(response, response_capacity, response_bytes,
                         request->operation, request->request_id,
                         XAIOS_CONTROL_STATUS_INVALID_REQUEST);
    }
    fill_capabilities(&value);
    return write_response(response, response_capacity, response_bytes,
                          request->operation, request->request_id,
                          XAIOS_CONTROL_STATUS_OK,
                          XAIOS_CONTROL_PAYLOAD_CAPABILITIES, &value,
                          sizeof(value));
  }
  case XAIOS_CONTROL_OP_HARDWARE: {
    xaios_control_hardware_payload_t value;
    if (request->payload_type != XAIOS_CONTROL_PAYLOAD_NONE ||
        request->payload_length != 0U) {
      return write_error(response, response_capacity, response_bytes,
                         request->operation, request->request_id,
                         XAIOS_CONTROL_STATUS_INVALID_REQUEST);
    }
    fill_hardware(&value);
    return write_response(response, response_capacity, response_bytes,
                          request->operation, request->request_id,
                          XAIOS_CONTROL_STATUS_OK,
                          XAIOS_CONTROL_PAYLOAD_HARDWARE, &value,
                          sizeof(value));
  }
  case XAIOS_CONTROL_OP_METRICS: {
    xaios_control_metrics_payload_t value;
    if (request->payload_type != XAIOS_CONTROL_PAYLOAD_NONE ||
        request->payload_length != 0U) {
      return write_error(response, response_capacity, response_bytes,
                         request->operation, request->request_id,
                         XAIOS_CONTROL_STATUS_INVALID_REQUEST);
    }
    fill_metrics(&value);
    return write_response(response, response_capacity, response_bytes,
                          request->operation, request->request_id,
                          XAIOS_CONTROL_STATUS_OK,
                          XAIOS_CONTROL_PAYLOAD_METRICS, &value,
                          sizeof(value));
  }
  default:
    return write_error(response, response_capacity, response_bytes,
                       request->operation, request->request_id,
                       XAIOS_CONTROL_STATUS_UNKNOWN_OPERATION);
  }
}
