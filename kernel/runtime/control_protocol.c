#include <xaios/ai_cell.h>
#include <xaios/app_store.h>
#include <xaios/assert.h>
#include <xaios/block_device.h>
#include <xaios/control_protocol.h>
#include <xaios/cpu_features.h>
#include <xaios/install.h>
#include <xaios/cpu_ai_runtime.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/version.h>
#include <xaios/klog_ring.h>
#include <xaios/xaiboot_fs.h>
#include <xaios/network_stack.h>
#include <xaios/numa.h>
#include <xaios/pmm.h>
#include <xaios/remote_login.h>
#include <xaios/scheduler.h>
#include <xaios/service.h>
#include <xaios/smp.h>
#include <xaios/timer.h>
#include <xaios/user.h>
#include <xaios/update.h>
#include <xaios/vfs.h>
#include <xaios/vfs_xaifs.h>

#ifndef XAIOS_BUILD_REVISION
#define XAIOS_BUILD_REVISION "unknown"
#endif

#ifndef XAIOS_BUILD_IDENTIFIER
#define XAIOS_BUILD_IDENTIFIER "xaios-admin-control-dirty"
#endif

#ifndef XAIOS_BUILD_MODE
#define XAIOS_BUILD_MODE "development"
#endif

static uint64_t g_control_requests;
static uint64_t g_control_failures;
static uint64_t g_control_denials;

/* A word that may alias anything: these helpers fill structs that are
   then read through their own types, and a plain uint64_t store could
   be reordered past those reads under strict aliasing. */
typedef uint64_t __attribute__((may_alias)) xaios_copy_word_t;

static void bytes_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  uint64_t i = 0;
  if (((uintptr_t)bytes & 7U) == 0U) {
    for (; i + 8U <= size; i += 8U) *(xaios_copy_word_t *)(void *)(bytes + i) = 0U;
  }
  for (; i < size; ++i) {
    bytes[i] = 0;
  }
}

static void bytes_copy(void *dst, const void *src, uint64_t size) {
  uint8_t *out = (uint8_t *)dst;
  const uint8_t *in = (const uint8_t *)src;
  uint64_t i = 0;
  /* A word at a time where both sides allow it: the control plane moves
     several kilobytes per query, and under emulation a byte loop over them
     was a measurable part of every query. */
  if ((((uintptr_t)out | (uintptr_t)in) & 7U) == 0U) {
    for (; i + 8U <= size; i += 8U) {
      *(xaios_copy_word_t *)(void *)(out + i) =
          *(const xaios_copy_word_t *)(const void *)(in + i);
    }
  }
  for (; i < size; ++i) {
    out[i] = in[i];
  }
}

static uint64_t string_length(const char *text) {
  uint64_t length = 0;
  if (text == 0) {
    return 0;
  }
  while (text[length] != '\0') {
    ++length;
  }
  return length;
}

static int string_equal(const char *lhs, const char *rhs) {
  if (lhs == 0 || rhs == 0) {
    return 0;
  }
  for (uint64_t i = 0;; ++i) {
    if (lhs[i] != rhs[i]) {
      return 0;
    }
    if (lhs[i] == '\0') {
      return 1;
    }
  }
}

static void string_copy(char *dst, uint64_t capacity, const char *src) {
  uint64_t offset = 0;
  if (dst == 0 || capacity == 0) {
    return;
  }
  while (src != 0 && src[offset] != '\0' && offset + 1U < capacity) {
    dst[offset] = src[offset];
    ++offset;
  }
  dst[offset] = '\0';
}

static char ascii_lower(char value) {
  if (value >= 'A' && value <= 'Z') {
    return (char)(value + ('a' - 'A'));
  }
  return value;
}

static int line_contains_case_insensitive(const char *line, uint64_t line_size,
                                          const char *needle) {
  uint64_t needle_size = string_length(needle);
  if (line == 0 || needle_size == 0U || needle_size > line_size) {
    return 0;
  }
  for (uint64_t i = 0; i + needle_size <= line_size; ++i) {
    uint64_t j = 0;
    while (j < needle_size &&
           ascii_lower(line[i + j]) == ascii_lower(needle[j])) {
      ++j;
    }
    if (j == needle_size) {
      return 1;
    }
  }
  return 0;
}

static int log_line_sensitive(const char *line, uint64_t line_size) {
  static const char *patterns[] = {
      "password", "passwd", "secret", "authorization", "bearer ",
      "private key", "private_key", "access_token", "api_key"};
  for (uint32_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); ++i) {
    if (line_contains_case_insensitive(line, line_size, patterns[i])) {
      return 1;
    }
  }
  return 0;
}

static uint64_t counter_increment(uint64_t *counter) {
  return __atomic_add_fetch(counter, UINT64_C(1), __ATOMIC_RELAXED);
}

static uint64_t counter_read(const uint64_t *counter) {
  return __atomic_load_n(counter, __ATOMIC_RELAXED);
}

static xaios_status_t write_response(
    void *response, uint64_t response_capacity, uint64_t *response_bytes,
    uint16_t operation, uint64_t request_id, xaios_control_status_t status,
    xaios_control_payload_type_t payload_type, const void *payload,
    uint64_t payload_length) {
  xaios_control_response_header_t header;
  uint64_t required = sizeof(header) + payload_length;
  if (response == 0 || response_bytes == 0 ||
      response_capacity < sizeof(header)) {
    return XAIOS_ERR_NO_MEMORY;
  }
  if (payload_length > response_capacity - sizeof(header)) {
    payload = 0;
    payload_length = 0;
    required = sizeof(header);
    status = XAIOS_CONTROL_STATUS_BUFFER_TOO_SMALL;
    payload_type = XAIOS_CONTROL_PAYLOAD_NONE;
  }
  bytes_zero(&header, sizeof(header));
  header.magic = XAIOS_CONTROL_MAGIC;
  header.version = XAIOS_CONTROL_VERSION;
  header.header_size = (uint16_t)sizeof(header);
  header.operation = operation;
  header.status = (uint32_t)status;
  header.request_id = request_id;
  header.payload_type = (uint32_t)payload_type;
  header.payload_length = payload_length;
  bytes_copy(response, &header, sizeof(header));
  if (payload != 0 && payload_length != 0U) {
    bytes_copy((uint8_t *)response + sizeof(header), payload, payload_length);
  }
  *response_bytes = required;
  return XAIOS_OK;
}

static xaios_status_t write_error(void *response, uint64_t response_capacity,
                                  uint64_t *response_bytes,
                                  uint16_t operation, uint64_t request_id,
                                  xaios_control_status_t status) {
  counter_increment(&g_control_failures);
  if (status == XAIOS_CONTROL_STATUS_DENIED) {
    counter_increment(&g_control_denials);
  }
  return write_response(response, response_capacity, response_bytes, operation,
                        request_id, status, XAIOS_CONTROL_PAYLOAD_NONE, 0, 0);
}

static xaios_status_t write_mutation_result(
    const xaios_control_request_header_t *request, void *response,
    uint64_t response_capacity, uint64_t *response_bytes,
    xaios_status_t operation_status) {
  xaios_control_mutation_payload_t result;
  bytes_zero(&result, sizeof(result));
  result.operation_id = request->request_id;
  result.changed = operation_status == XAIOS_OK ? 1U : 0U;
  if (operation_status != XAIOS_OK) {
    return write_error(response, response_capacity, response_bytes,
                       request->operation, request->request_id,
                       operation_status == XAIOS_ERR_NOT_FOUND
                           ? XAIOS_CONTROL_STATUS_NOT_FOUND
                           : XAIOS_CONTROL_STATUS_CONFLICT);
  }
  return write_response(response, response_capacity, response_bytes,
                        request->operation, request->request_id,
                        XAIOS_CONTROL_STATUS_OK,
                        XAIOS_CONTROL_PAYLOAD_MUTATION, &result,
                        sizeof(result));
}

static xaios_status_t handle_package_operation(
    const xaios_control_request_header_t *request, const uint8_t *payload,
    void *response, uint64_t response_capacity, uint64_t *response_bytes,
    xaios_control_role_t authenticated_role) {
  xaios_status_t status = XAIOS_ERR_INVALID;
  if (authenticated_role != XAIOS_CONTROL_ROLE_ADMIN ||
      request->principal_role != XAIOS_CONTROL_ROLE_ADMIN) {
    return write_error(response, response_capacity, response_bytes,
                       request->operation, request->request_id,
                       XAIOS_CONTROL_STATUS_DENIED);
  }
  if (request->operation == XAIOS_CONTROL_OP_CATALOG_ACTIVATE) {
    if (request->payload_type != XAIOS_CONTROL_PAYLOAD_NONE ||
        request->payload_length != 0U) {
      return write_error(response, response_capacity, response_bytes,
                         request->operation, request->request_id,
                         XAIOS_CONTROL_STATUS_INVALID_REQUEST);
    }
    status = app_store_activate_catalog();
  } else {
    xaios_control_app_request_payload_t app;
    if (request->payload_type != XAIOS_CONTROL_PAYLOAD_APP_REQUEST ||
        request->payload_length != sizeof(app)) {
      return write_error(response, response_capacity, response_bytes,
                         request->operation, request->request_id,
                         XAIOS_CONTROL_STATUS_INVALID_REQUEST);
    }
    bytes_copy(&app, payload, sizeof(app));
    if (app.name[sizeof(app.name) - 1U] != '\0') {
      return write_error(response, response_capacity, response_bytes,
                         request->operation, request->request_id,
                         XAIOS_CONTROL_STATUS_INVALID_REQUEST);
    }
    if (request->operation == XAIOS_CONTROL_OP_APP_ACTIVATE)
      status = app_store_activate(app.name);
    else if (request->operation == XAIOS_CONTROL_OP_APP_REMOVE)
      status = app_store_remove(app.name);
    else if (request->operation == XAIOS_CONTROL_OP_APP_ROLLBACK)
      status = app_store_rollback(app.name);
  }
  return write_mutation_result(request, response, response_capacity,
                               response_bytes, status);
}

static xaios_status_t handle_system_update_operation(
    const xaios_control_request_header_t *request, const uint8_t *payload,
    void *response, uint64_t response_capacity, uint64_t *response_bytes,
    xaios_control_role_t authenticated_role) {
  xaios_status_t status = XAIOS_ERR_INVALID;
  if (authenticated_role != XAIOS_CONTROL_ROLE_ADMIN ||
      request->principal_role != XAIOS_CONTROL_ROLE_ADMIN) {
    return write_error(response, response_capacity, response_bytes,
                       request->operation, request->request_id,
                       XAIOS_CONTROL_STATUS_DENIED);
  }
  if (request->operation == XAIOS_CONTROL_OP_SYSTEM_UPDATE_BEGIN) {
    xaios_control_system_update_begin_payload_t begin;
    if (request->payload_type != XAIOS_CONTROL_PAYLOAD_SYSTEM_UPDATE_BEGIN ||
        request->payload_length != sizeof(begin)) {
      return write_error(response, response_capacity, response_bytes,
                         request->operation, request->request_id,
                         XAIOS_CONTROL_STATUS_INVALID_REQUEST);
    }
    bytes_copy(&begin, payload, sizeof(begin));
    if (begin.reserved != 0U || begin.signature[sizeof(begin.signature) - 1U] !=
                                   '\0') {
      return write_error(response, response_capacity, response_bytes,
                         request->operation, request->request_id,
                         XAIOS_CONTROL_STATUS_INVALID_REQUEST);
    }
    status = update_begin_system(begin.generation, begin.payload_size,
                                 begin.payload_hash, begin.signature);
  } else if (request->operation == XAIOS_CONTROL_OP_SYSTEM_UPDATE_CHUNK) {
    xaios_control_system_update_chunk_payload_t chunk;
    if (request->payload_type != XAIOS_CONTROL_PAYLOAD_SYSTEM_UPDATE_CHUNK ||
        request->payload_length != sizeof(chunk)) {
      return write_error(response, response_capacity, response_bytes,
                         request->operation, request->request_id,
                         XAIOS_CONTROL_STATUS_INVALID_REQUEST);
    }
    bytes_copy(&chunk, payload, sizeof(chunk));
    if (chunk.reserved != 0U || chunk.size == 0U ||
        chunk.size > sizeof(chunk.data)) {
      return write_error(response, response_capacity, response_bytes,
                         request->operation, request->request_id,
                         XAIOS_CONTROL_STATUS_INVALID_REQUEST);
    }
    status = update_stage_chunk(chunk.data, chunk.size);
  } else {
    if (request->payload_type != XAIOS_CONTROL_PAYLOAD_NONE ||
        request->payload_length != 0U) {
      return write_error(response, response_capacity, response_bytes,
                         request->operation, request->request_id,
                         XAIOS_CONTROL_STATUS_INVALID_REQUEST);
    }
    status = request->operation == XAIOS_CONTROL_OP_SYSTEM_UPDATE_COMMIT
                 ? update_finish_system()
                 : update_abort_delivery();
  }
  return write_mutation_result(request, response, response_capacity,
                               response_bytes, status);
}

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

static xaios_status_t fill_runtime_snapshot(
    const xaios_control_runtime_snapshot_request_t *request,
    xaios_control_runtime_snapshot_payload_t *payload) {
  uint64_t now_ns;
  uint32_t next_cpu;
  uint32_t next_process;
  if (request == 0 || payload == 0 || request->reserved != 0U ||
      request->cpu_limit > XAIOS_CONTROL_RUNTIME_CPU_MAX ||
      request->process_limit > XAIOS_CONTROL_RUNTIME_PROCESS_MAX ||
      request->process_start > XAIOS_MAX_USER_PROCESSES ||
      request->wait_ms > 1000U) {
    return XAIOS_ERR_INVALID;
  }
  if (request->wait_ms != 0U) {
    uint64_t start_ns = timer_now_ns();
    uint64_t wait_ns = (uint64_t)request->wait_ms * UINT64_C(1000000);
    uint64_t deadline_ns = start_ns > UINT64_MAX - wait_ns
                               ? UINT64_MAX
                               : start_ns + wait_ns;
    user_process_idle_until(deadline_ns);
  }
  now_ns = timer_now_ns();
  bytes_zero(payload, sizeof(*payload));
  payload->sampled_at_ns = now_ns;
  payload->cpu_busy_total_ns = user_cpu_busy_total(now_ns);
  payload->physical_pages = pmm_total_pages();
  payload->managed_pages = pmm_managed_pages();
  payload->free_pages = pmm_free_pages();
  payload->cpu_total = user_cpu_usage_count();
  payload->cpu_start = request->cpu_start > payload->cpu_total
                           ? payload->cpu_total
                           : request->cpu_start;
  payload->process_capacity = XAIOS_MAX_USER_PROCESSES;
  payload->process_start = request->process_start;
  payload->process_active = (uint32_t)user_process_active_count();
  payload->process_failed = (uint32_t)user_process_current_failed_count();
  scheduler_load_average_hundredths(payload->load_average_hundredths);

  next_cpu = payload->cpu_start;
  while (next_cpu < payload->cpu_total &&
         payload->cpu_count < request->cpu_limit) {
    xaios_cpu_usage_snapshot_t usage;
    xaios_control_runtime_cpu_record_t *record =
        &payload->cpus[payload->cpu_count];
    uint32_t ordinal = next_cpu++;
    if (user_cpu_usage_snapshot(ordinal, now_ns, &usage) != XAIOS_OK) {
      continue;
    }
    const xaios_cpu_state_t *state = smp_cpu_state(usage.cpu_id);
    record->cpu_id = usage.cpu_id;
    record->active_pid = usage.active_pid;
    record->role = state == 0 ? XAIOS_CPU_ROLE_OFFLINE : (uint32_t)state->role;
    record->busy_ns = usage.busy_ns;
    record->elapsed_ns = usage.elapsed_ns;
    ++payload->cpu_count;
  }
  payload->cpu_next =
      request->cpu_limit != 0U && next_cpu < payload->cpu_total
          ? next_cpu
          : UINT32_MAX;

  next_process = request->process_start;
  for (uint32_t pid = request->process_start + 1U;
       pid <= XAIOS_MAX_USER_PROCESSES &&
       payload->process_count < request->process_limit;
       ++pid) {
    xaios_user_process_t process;
    next_process = pid;
    if (user_process_snapshot_at(pid, now_ns, &process) != XAIOS_OK) {
      continue;
    }
    xaios_control_runtime_process_record_t *record =
        &payload->processes[payload->process_count++];
    record->pid = process.pid;
    record->parent_pid = process.parent_pid;
    record->cpu_id = process.running_cpu_id;
    record->state = (uint32_t)process.state;
    record->runtime_ns = process.runtime_ns;
    record->resident_pages = process.resident_pages;
    record->syscall_count = process.syscall_count;
    string_copy(record->name, sizeof(record->name),
                process.name == 0 ? "(unknown)" : process.name);
  }
  payload->process_next =
      request->process_limit != 0U && next_process < XAIOS_MAX_USER_PROCESSES
          ? next_process
          : UINT32_MAX;
  return XAIOS_OK;
}

static xaios_status_t append_text(char *output, uint64_t capacity,
                                  uint64_t *offset, const char *text) {
  if (output == 0 || offset == 0 || text == 0) {
    return XAIOS_ERR_INVALID;
  }
  for (uint64_t i = 0; text[i] != '\0'; ++i) {
    if (*offset >= capacity) {
      return XAIOS_ERR_NO_MEMORY;
    }
    output[*offset] = text[i];
    ++(*offset);
  }
  return XAIOS_OK;
}

static xaios_status_t append_u64(char *output, uint64_t capacity,
                                 uint64_t *offset, uint64_t value) {
  char digits[24];
  uint64_t count = 0;
  if (value == 0U) {
    return append_text(output, capacity, offset, "0");
  }
  while (value != 0U && count < sizeof(digits)) {
    digits[count++] = (char)('0' + value % 10U);
    value /= 10U;
  }
  while (count != 0U) {
    if (*offset >= capacity) {
      return XAIOS_ERR_NO_MEMORY;
    }
    output[*offset] = digits[--count];
    ++(*offset);
  }
  return XAIOS_OK;
}

static void log_component(const char *line, uint64_t line_size, char *component,
                          uint64_t component_capacity) {
  uint64_t colon = UINT64_MAX;
  uint64_t start = 0U;
  for (uint64_t i = 0; i < line_size; ++i) {
    if (line[i] == ':') {
      colon = i;
      break;
    }
  }
  if (colon == UINT64_MAX || colon == 0U) {
    string_copy(component, component_capacity, "kernel");
    return;
  }
  for (uint64_t i = 0; i < colon; ++i) {
    if (line[i] == ' ' || line[i] == ']') {
      start = i + 1U;
    }
  }
  uint64_t length = colon - start;
  if (length == 0U || length + 1U > component_capacity) {
    string_copy(component, component_capacity, "kernel");
    return;
  }
  for (uint64_t i = 0; i < length; ++i) {
    component[i] = line[start + i];
  }
  component[length] = '\0';
}

static const char *log_level(const char *line, uint64_t line_size) {
  if (line_contains_case_insensitive(line, line_size, "[panic]")) {
    return "panic";
  }
  if (line_contains_case_insensitive(line, line_size, "[error]")) {
    return "error";
  }
  if (line_contains_case_insensitive(line, line_size, "[warn]")) {
    return "warn";
  }
  if (line_contains_case_insensitive(line, line_size, "[info]")) {
    return "info";
  }
  if (line_contains_case_insensitive(line, line_size, "[debug]")) {
    return "debug";
  }
  return "unknown";
}

static int component_matches(const char *requested, const char *actual) {
  return requested[0] == '\0' || string_equal(requested, actual);
}

static xaios_control_status_t admin_status(xaios_admin_result_t result) {
  switch (result) {
  case XAIOS_ADMIN_RESULT_OK:
    return XAIOS_CONTROL_STATUS_OK;
  case XAIOS_ADMIN_RESULT_DENIED:
    return XAIOS_CONTROL_STATUS_DENIED;
  case XAIOS_ADMIN_RESULT_NOT_FOUND:
    return XAIOS_CONTROL_STATUS_NOT_FOUND;
  case XAIOS_ADMIN_RESULT_REPLAY:
    return XAIOS_CONTROL_STATUS_REPLAYED;
  case XAIOS_ADMIN_RESULT_CONFLICT:
    return XAIOS_CONTROL_STATUS_CONFLICT;
  case XAIOS_ADMIN_RESULT_NO_MEMORY:
    return XAIOS_CONTROL_STATUS_BUFFER_TOO_SMALL;
  case XAIOS_ADMIN_RESULT_IO:
    return XAIOS_CONTROL_STATUS_INTERNAL;
  case XAIOS_ADMIN_RESULT_INVALID:
  default:
    return XAIOS_CONTROL_STATUS_INVALID_REQUEST;
  }
}

static int fixed_string_valid(const char *text, uint64_t capacity) {
  if (text == 0 || capacity == 0U || text[capacity - 1U] != '\0') {
    return 0;
  }
  for (uint64_t i = 0U; i < capacity; ++i) {
    if (text[i] == '\0') return i != 0U;
  }
  return 0;
}

static int fixed_string_terminated(const char *text, uint64_t capacity) {
  if (text == 0 || capacity == 0U || text[capacity - 1U] != '\0') return 0;
  for (uint64_t index = 0U; index < capacity; ++index) {
    if (text[index] == '\0') return 1;
  }
  return 0;
}

static xaios_status_t write_admin_error(
    const xaios_control_request_header_t *request,
    xaios_admin_result_t admin_result, void *response,
    uint64_t response_capacity, uint64_t *response_bytes) {
  return write_error(response, response_capacity, response_bytes,
                     request->operation, request->request_id,
                     admin_status(admin_result));
}

static xaios_status_t handle_config_operation(
    const xaios_control_request_header_t *request, const uint8_t *payload,
    void *response, uint64_t response_capacity, uint64_t *response_bytes,
    xaios_control_role_t authenticated_role) {
  xaios_control_config_payload_t value;
  xaios_admin_result_t result = XAIOS_ADMIN_RESULT_INVALID;
  bytes_zero(&value, sizeof(value));
  if (request->operation == XAIOS_CONTROL_OP_CONFIG_SHOW) {
    if (request->payload_type != XAIOS_CONTROL_PAYLOAD_NONE ||
        request->payload_length != 0U) {
      return write_admin_error(request, result, response, response_capacity,
                               response_bytes);
    }
    result = admin_control_config_get(&value.config);
    value.validated = result == XAIOS_ADMIN_RESULT_OK ? 1U : 0U;
  } else if (request->operation == XAIOS_CONTROL_OP_CONFIG_VALIDATE ||
             request->operation == XAIOS_CONTROL_OP_CONFIG_DIFF) {
    xaios_control_path_request_payload_t query;
    if (request->payload_type != XAIOS_CONTROL_PAYLOAD_PATH_REQUEST ||
        request->payload_length != sizeof(query)) {
      return write_admin_error(request, result, response, response_capacity,
                               response_bytes);
    }
    bytes_copy(&query, payload, sizeof(query));
    if (!fixed_string_valid(query.path, sizeof(query.path))) {
      return write_admin_error(request, result, response, response_capacity,
                               response_bytes);
    }
    result = admin_control_config_validate(query.path, &value.config,
                                           &value.change_mask);
    value.validated = result == XAIOS_ADMIN_RESULT_OK ? 1U : 0U;
  } else {
    xaios_control_mutation_request_payload_t mutation;
    if (authenticated_role < XAIOS_CONTROL_ROLE_ADMIN ||
        request->payload_type != XAIOS_CONTROL_PAYLOAD_MUTATION_REQUEST ||
        request->payload_length != sizeof(mutation)) {
      return write_admin_error(
          request,
          authenticated_role < XAIOS_CONTROL_ROLE_ADMIN
              ? XAIOS_ADMIN_RESULT_DENIED
              : XAIOS_ADMIN_RESULT_INVALID,
          response, response_capacity, response_bytes);
    }
    bytes_copy(&mutation, payload, sizeof(mutation));
    if (mutation.reserved != 0U || mutation.assigned_role != 0U ||
        !fixed_string_valid(mutation.actor, sizeof(mutation.actor)) ||
        !fixed_string_valid(mutation.argument, sizeof(mutation.argument)) ||
        mutation.target_principal[0] != '\0') {
      return write_admin_error(request, XAIOS_ADMIN_RESULT_INVALID, response,
                               response_capacity, response_bytes);
    }
    result = admin_control_config_apply(
        mutation.argument, mutation.actor, request->principal_role,
        mutation.operation_id, &value.config, &value.change_mask);
    value.validated = result == XAIOS_ADMIN_RESULT_OK ? 1U : 0U;
  }
  if (result != XAIOS_ADMIN_RESULT_OK) {
    return write_admin_error(request, result, response, response_capacity,
                             response_bytes);
  }
  return write_response(response, response_capacity, response_bytes,
                        request->operation, request->request_id,
                        XAIOS_CONTROL_STATUS_OK, XAIOS_CONTROL_PAYLOAD_CONFIG,
                        &value, sizeof(value));
}

static xaios_status_t write_key_views(
    const xaios_control_request_header_t *request,
    const xaios_admin_key_view_t *views, uint32_t key_count,
    uint32_t revoked_count, uint64_t generation, void *response,
    uint64_t response_capacity, uint64_t *response_bytes) {
  uint8_t payload[sizeof(xaios_control_auth_keys_payload_t) +
                  sizeof(xaios_admin_key_view_t) * XAIOS_ADMIN_MAX_KEYS];
  xaios_control_auth_keys_payload_t metadata;
  uint64_t payload_size = sizeof(metadata) +
                          ((uint64_t)key_count * sizeof(views[0]));
  bytes_zero(&metadata, sizeof(metadata));
  metadata.generation = generation;
  metadata.key_count = key_count;
  metadata.revoked_count = revoked_count;
  bytes_copy(payload, &metadata, sizeof(metadata));
  if (key_count != 0U) {
    bytes_copy(payload + sizeof(metadata), views,
               (uint64_t)key_count * sizeof(views[0]));
  }
  return write_response(response, response_capacity, response_bytes,
                        request->operation, request->request_id,
                        XAIOS_CONTROL_STATUS_OK,
                        XAIOS_CONTROL_PAYLOAD_AUTH_KEYS, payload,
                        payload_size);
}

static xaios_status_t handle_auth_operation(
    const xaios_control_request_header_t *request, const uint8_t *payload,
    void *response, uint64_t response_capacity, uint64_t *response_bytes,
    xaios_control_role_t authenticated_role) {
  xaios_admin_key_view_t views[XAIOS_ADMIN_MAX_KEYS];
  uint32_t key_count = 0U;
  uint32_t revoked_count = 0U;
  uint64_t generation = 0U;
  bytes_zero(views, sizeof(views));
  if (request->operation == XAIOS_CONTROL_OP_AUTH_KEY_LIST) {
    if (request->payload_type != XAIOS_CONTROL_PAYLOAD_NONE ||
        request->payload_length != 0U) {
      return write_admin_error(request, XAIOS_ADMIN_RESULT_INVALID, response,
                               response_capacity, response_bytes);
    }
    xaios_admin_result_t result = admin_control_auth_list(
        views, XAIOS_ADMIN_MAX_KEYS, &key_count, &revoked_count, &generation);
    if (result != XAIOS_ADMIN_RESULT_OK) {
      return write_admin_error(request, result, response, response_capacity,
                               response_bytes);
    }
    return write_key_views(request, views, key_count, revoked_count, generation,
                           response, response_capacity, response_bytes);
  }
  if (authenticated_role < XAIOS_CONTROL_ROLE_ADMIN ||
      request->payload_type != XAIOS_CONTROL_PAYLOAD_MUTATION_REQUEST ||
      request->payload_length !=
          sizeof(xaios_control_mutation_request_payload_t)) {
    return write_admin_error(
        request,
        authenticated_role < XAIOS_CONTROL_ROLE_ADMIN
            ? XAIOS_ADMIN_RESULT_DENIED
            : XAIOS_ADMIN_RESULT_INVALID,
        response, response_capacity, response_bytes);
  }
  xaios_control_mutation_request_payload_t mutation;
  bytes_copy(&mutation, payload, sizeof(mutation));
  if (mutation.reserved != 0U ||
      !fixed_string_valid(mutation.actor, sizeof(mutation.actor))) {
    return write_admin_error(request, XAIOS_ADMIN_RESULT_INVALID, response,
                             response_capacity, response_bytes);
  }
  xaios_admin_result_t result = XAIOS_ADMIN_RESULT_INVALID;
  if (request->operation == XAIOS_CONTROL_OP_AUTH_KEY_ADD) {
    if (!fixed_string_valid(mutation.argument, sizeof(mutation.argument)) ||
        !fixed_string_valid(mutation.target_principal,
                            sizeof(mutation.target_principal))) {
      return write_admin_error(request, result, response, response_capacity,
                               response_bytes);
    }
    result = admin_control_auth_add(
        mutation.argument, mutation.target_principal, mutation.assigned_role,
        mutation.actor, request->principal_role, mutation.operation_id,
        0);
  } else if (request->operation == XAIOS_CONTROL_OP_AUTH_KEY_REMOVE) {
    if (mutation.assigned_role != 0U ||
        !fixed_string_valid(mutation.argument, sizeof(mutation.argument)) ||
        mutation.target_principal[0] != '\0') {
      return write_admin_error(request, result, response, response_capacity,
                               response_bytes);
    }
    result = admin_control_auth_remove(
        mutation.argument, mutation.actor, request->principal_role,
        mutation.operation_id, 0);
  } else {
    if (mutation.assigned_role != 0U || mutation.argument[0] != '\0' ||
        mutation.target_principal[0] != '\0') {
      return write_admin_error(request, result, response, response_capacity,
                               response_bytes);
    }
    result = admin_control_host_key_rotate(
        mutation.actor, request->principal_role, mutation.operation_id);
    if (result == XAIOS_ADMIN_RESULT_OK) {
      xaios_control_mutation_payload_t value;
      bytes_zero(&value, sizeof(value));
      value.operation_id = mutation.operation_id;
      value.changed = 1U;
      return write_response(
          response, response_capacity, response_bytes, request->operation,
          request->request_id, XAIOS_CONTROL_STATUS_OK,
          XAIOS_CONTROL_PAYLOAD_MUTATION, &value, sizeof(value));
    }
  }
  if (result != XAIOS_ADMIN_RESULT_OK) {
    return write_admin_error(request, result, response, response_capacity,
                             response_bytes);
  }
  xaios_admin_result_t list_result = admin_control_auth_list(
      views, XAIOS_ADMIN_MAX_KEYS, &key_count, &revoked_count,
      &generation);
  if (list_result != XAIOS_ADMIN_RESULT_OK) {
    return write_admin_error(request, list_result, response,
                             response_capacity, response_bytes);
  }
  return write_key_views(request, views, key_count, revoked_count, generation,
                         response, response_capacity, response_bytes);
}

static xaios_status_t handle_audit(
    const xaios_control_request_header_t *request, const uint8_t *payload,
    void *response, uint64_t response_capacity, uint64_t *response_bytes) {
  xaios_control_audit_request_payload_t query;
  if (request->payload_type != XAIOS_CONTROL_PAYLOAD_AUDIT_REQUEST ||
      request->payload_length != sizeof(query)) {
    return write_admin_error(request, XAIOS_ADMIN_RESULT_INVALID, response,
                             response_capacity, response_bytes);
  }
  bytes_copy(&query, payload, sizeof(query));
  if (query.reserved != 0U || query.limit > XAIOS_ADMIN_MAX_AUDIT_RECORDS) {
    return write_admin_error(request, XAIOS_ADMIN_RESULT_INVALID, response,
                             response_capacity, response_bytes);
  }
  uint32_t limit = query.limit == 0U ? 16U : query.limit;
  uint64_t payload_capacity = sizeof(xaios_control_audit_payload_t) +
                              ((uint64_t)limit *
                               sizeof(xaios_admin_audit_record_t));
  uint8_t *value = (uint8_t *)kheap_calloc(payload_capacity, 16U);
  if (value == 0) {
    return write_admin_error(request, XAIOS_ADMIN_RESULT_NO_MEMORY, response,
                             response_capacity, response_bytes);
  }
  xaios_control_audit_payload_t *metadata =
      (xaios_control_audit_payload_t *)(void *)value;
  xaios_admin_audit_record_t *records =
      (xaios_admin_audit_record_t *)(void *)(value + sizeof(*metadata));
  xaios_admin_result_t result = admin_control_audit_read(
      query.since_sequence, limit, records, limit, &metadata->record_count,
      &metadata->next_sequence, &metadata->latest_sequence);
  if (result != XAIOS_ADMIN_RESULT_OK) {
    kheap_free(value);
    return write_admin_error(request, result, response, response_capacity,
                             response_bytes);
  }
  uint64_t payload_size = sizeof(*metadata) +
                          ((uint64_t)metadata->record_count * sizeof(*records));
  xaios_status_t status = write_response(
      response, response_capacity, response_bytes, request->operation,
      request->request_id, XAIOS_CONTROL_STATUS_OK,
      XAIOS_CONTROL_PAYLOAD_AUDIT, value, payload_size);
  kheap_free(value);
  return status;
}

static xaios_admin_result_t model_control_result(xaios_status_t status) {
  if (status == XAIOS_OK) return XAIOS_ADMIN_RESULT_OK;
  if (status == XAIOS_ERR_NOT_FOUND) return XAIOS_ADMIN_RESULT_NOT_FOUND;
  if (status == XAIOS_ERR_BUSY || status == XAIOS_ERR_UNSUPPORTED) {
    return XAIOS_ADMIN_RESULT_CONFLICT;
  }
  if (status == XAIOS_ERR_IO) return XAIOS_ADMIN_RESULT_IO;
  return XAIOS_ADMIN_RESULT_INVALID;
}

static xaios_status_t handle_model_operation(
    const xaios_control_request_header_t *request, const uint8_t *payload,
    void *response, uint64_t response_capacity, uint64_t *response_bytes,
    xaios_control_role_t authenticated_role) {
  if (authenticated_role < XAIOS_CONTROL_ROLE_ADMIN ||
      request->principal_role < XAIOS_CONTROL_ROLE_ADMIN) {
    return write_admin_error(request, XAIOS_ADMIN_RESULT_DENIED, response,
                             response_capacity, response_bytes);
  }
  xaios_control_mutation_payload_t value;
  xaios_control_model_cleanup_report_t cleanup;
  bytes_zero(&value, sizeof(value));
  bytes_zero(&cleanup, sizeof(cleanup));
  xaios_admin_result_t result = XAIOS_ADMIN_RESULT_INVALID;
  if (request->operation == XAIOS_CONTROL_OP_MODEL_REGISTER) {
    xaios_control_model_register_request_payload_t query;
    if (request->payload_type !=
            XAIOS_CONTROL_PAYLOAD_MODEL_REGISTER_REQUEST ||
        request->payload_length != sizeof(query)) {
      return write_admin_error(request, result, response, response_capacity,
                               response_bytes);
    }
    bytes_copy(&query, payload, sizeof(query));
    if (query.operation_id == 0U ||
        !fixed_string_valid(query.actor, sizeof(query.actor)) ||
        !fixed_string_valid(query.architecture_id,
                            sizeof(query.architecture_id)) ||
        !fixed_string_valid(query.target_id, sizeof(query.target_id))) {
      return write_admin_error(request, result, response, response_capacity,
                               response_bytes);
    }
    result = admin_control_mutation_begin(
        query.actor, request->principal_role, XAIOS_CONTROL_ROLE_ADMIN,
        query.operation_id, "model.package.stage");
    if (result != XAIOS_ADMIN_RESULT_OK) {
      return write_admin_error(request, result, response, response_capacity,
                               response_bytes);
    }
    xaios_model_registration_t registration;
    bytes_zero(&registration, sizeof(registration));
    bytes_copy(registration.model_uuid, query.model_uuid, 16U);
    bytes_copy(registration.package_id, query.package_id, 32U);
    bytes_copy(registration.signer_public_key, query.signer_public_key, 32U);
    bytes_copy(registration.signature, query.signature, 64U);
    bytes_copy(registration.source_revision, query.source_revision, 32U);
    registration.logical_size = query.logical_size;
    bytes_copy(registration.architecture_id, query.architecture_id,
               sizeof(registration.architecture_id));
    bytes_copy(registration.target_id, query.target_id,
               sizeof(registration.target_id));
    value.operation_id = query.operation_id;
    result = model_control_result(
        vfs_xaifs_register_staging(&registration, &value.generation));
    if (result != XAIOS_ADMIN_RESULT_OK) {
      result = admin_control_mutation_fail(
          query.actor, request->principal_role, query.operation_id,
          "model.package.stage", result);
      return write_admin_error(request, result, response, response_capacity,
                               response_bytes);
    }
    result = admin_control_mutation_complete(
        query.actor, request->principal_role, query.operation_id,
        "model.package.stage", query.package_id);
    value.changed = result == XAIOS_ADMIN_RESULT_OK ? 1U : 0U;
  } else if (request->operation == XAIOS_CONTROL_OP_MODEL_VERIFY) {
    xaios_control_path_request_payload_t query;
    if (request->payload_type != XAIOS_CONTROL_PAYLOAD_PATH_REQUEST ||
        request->payload_length != sizeof(query)) {
      return write_admin_error(request, result, response, response_capacity,
                               response_bytes);
    }
    bytes_copy(&query, payload, sizeof(query));
    if (!fixed_string_valid(query.path, sizeof(query.path))) {
      return write_admin_error(request, result, response, response_capacity,
                               response_bytes);
    }
    result = model_control_result(
        vfs_xaifs_verify_staging(query.path, &value.generation));
  } else {
    xaios_control_mutation_request_payload_t mutation;
    if (request->payload_type != XAIOS_CONTROL_PAYLOAD_MUTATION_REQUEST ||
        request->payload_length != sizeof(mutation)) {
      return write_admin_error(request, result, response, response_capacity,
                               response_bytes);
    }
    bytes_copy(&mutation, payload, sizeof(mutation));
    if (mutation.operation_id == 0U || mutation.assigned_role != 0U ||
        mutation.reserved != 0U ||
        !fixed_string_valid(mutation.actor, sizeof(mutation.actor)) ||
        !fixed_string_valid(mutation.argument, sizeof(mutation.argument)) ||
        mutation.target_principal[0] != '\0') {
      return write_admin_error(request, result, response, response_capacity,
                               response_bytes);
    }
    if (request->operation == XAIOS_CONTROL_OP_MODEL_CLEANUP) {
      result = admin_control_mutation_begin(
          mutation.actor, request->principal_role, XAIOS_CONTROL_ROLE_ADMIN,
          mutation.operation_id, "model.package.cleanup");
      if (result != XAIOS_ADMIN_RESULT_OK) {
        return write_admin_error(request, result, response, response_capacity,
                                 response_bytes);
      }
      cleanup.operation_id = mutation.operation_id;
      result = model_control_result(vfs_xaifs_cleanup_staging(
          mutation.argument, &cleanup.generation, &cleanup.reclaimed_bytes));
      if (result != XAIOS_ADMIN_RESULT_OK) {
        result = admin_control_mutation_fail(
            mutation.actor, request->principal_role, mutation.operation_id,
            "model.package.cleanup", result);
        return write_admin_error(request, result, response, response_capacity,
                                 response_bytes);
      }
      result = admin_control_mutation_complete(
          mutation.actor, request->principal_role, mutation.operation_id,
          "model.package.cleanup", (const uint8_t *)mutation.argument);
      cleanup.changed = result == XAIOS_ADMIN_RESULT_OK ? 1U : 0U;
    } else {
      value.operation_id = mutation.operation_id;
      result = admin_control_model_activate(
          mutation.argument, mutation.actor, request->principal_role,
          mutation.operation_id, &value.generation);
      value.changed = result == XAIOS_ADMIN_RESULT_OK ? 1U : 0U;
    }
  }
  if (result != XAIOS_ADMIN_RESULT_OK) {
    return write_admin_error(request, result, response, response_capacity,
                             response_bytes);
  }
  if (request->operation == XAIOS_CONTROL_OP_MODEL_CLEANUP) {
    return write_response(response, response_capacity, response_bytes,
                          request->operation, request->request_id,
                          XAIOS_CONTROL_STATUS_OK,
                          XAIOS_CONTROL_PAYLOAD_MODEL_CLEANUP_REPORT, &cleanup,
                          sizeof(cleanup));
  }
  return write_response(response, response_capacity, response_bytes,
                        request->operation, request->request_id,
                        XAIOS_CONTROL_STATUS_OK,
                        XAIOS_CONTROL_PAYLOAD_MUTATION, &value,
                        sizeof(value));
}

static void storage_device_record(
    xaios_control_storage_device_record_t *record,
    const xaios_block_device_info_t *info) {
  bytes_zero(record, sizeof(*record));
  string_copy(record->identifier, sizeof(record->identifier), info->identifier);
  string_copy(record->backend, sizeof(record->backend), info->backend);
  record->capacity_bytes = info->capacity_bytes;
  record->capacity_logical_sectors = info->capacity_logical_sectors;
  record->logical_sector_size = info->logical_sector_size;
  record->physical_block_size = info->physical_block_size;
  record->max_transfer_bytes = info->max_transfer_bytes;
  record->discard_granularity = info->discard_granularity;
  record->max_discard_bytes = info->max_discard_bytes;
  record->read_bytes = info->read_bytes;
  record->write_bytes = info->write_bytes;
  record->discarded_bytes = info->discarded_bytes;
  record->io_errors = info->io_errors;
  record->read_only = info->read_only;
  record->flush_supported = info->flush_supported;
  record->discard_supported = info->discard_supported;
  record->write_zeroes_supported = info->write_zeroes_supported;
}

static xaios_status_t handle_storage_devices(
    const xaios_control_request_header_t *request, const uint8_t *payload,
    void *response, uint64_t response_capacity, uint64_t *response_bytes) {
  struct storage_device_response {
    xaios_control_storage_devices_payload_t metadata;
    xaios_control_storage_device_record_t
        records[XAIOS_CONTROL_STORAGE_MAX_DEVICES];
  } value;
  xaios_block_device_info_t infos[XAIOS_CONTROL_STORAGE_MAX_DEVICES];
  bytes_zero(&value, sizeof(value));
  bytes_zero(infos, sizeof(infos));

  if (request->operation == XAIOS_CONTROL_OP_STORAGE_DEVICE_LIST) {
    if (request->payload_type != XAIOS_CONTROL_PAYLOAD_NONE ||
        request->payload_length != 0U) {
      return write_error(response, response_capacity, response_bytes,
                         request->operation, request->request_id,
                         XAIOS_CONTROL_STATUS_INVALID_REQUEST);
    }
    uint64_t total = 0U;
    xaios_status_t status = block_device_list(
        infos, XAIOS_CONTROL_STORAGE_MAX_DEVICES, &total);
    if (status != XAIOS_OK) {
      return write_error(response, response_capacity, response_bytes,
                         request->operation, request->request_id,
                         XAIOS_CONTROL_STATUS_INTERNAL);
    }
    value.metadata.total_count =
        total > UINT32_MAX ? UINT32_MAX : (uint32_t)total;
    value.metadata.record_count =
        total > XAIOS_CONTROL_STORAGE_MAX_DEVICES
            ? XAIOS_CONTROL_STORAGE_MAX_DEVICES
            : (uint32_t)total;
    value.metadata.truncated =
        total > XAIOS_CONTROL_STORAGE_MAX_DEVICES ? 1U : 0U;
    for (uint32_t index = 0U; index < value.metadata.record_count; ++index) {
      storage_device_record(&value.records[index], &infos[index]);
    }
  } else {
    xaios_control_path_request_payload_t query;
    if (request->payload_type != XAIOS_CONTROL_PAYLOAD_PATH_REQUEST ||
        request->payload_length != sizeof(query)) {
      return write_error(response, response_capacity, response_bytes,
                         request->operation, request->request_id,
                         XAIOS_CONTROL_STATUS_INVALID_REQUEST);
    }
    bytes_copy(&query, payload, sizeof(query));
    if (!fixed_string_valid(query.path, sizeof(query.path))) {
      return write_error(response, response_capacity, response_bytes,
                         request->operation, request->request_id,
                         XAIOS_CONTROL_STATUS_INVALID_REQUEST);
    }
    xaios_block_device_t *device = 0;
    xaios_status_t status = block_device_open(query.path, &device);
    if (status == XAIOS_ERR_NOT_FOUND) {
      return write_error(response, response_capacity, response_bytes,
                         request->operation, request->request_id,
                         XAIOS_CONTROL_STATUS_NOT_FOUND);
    }
    if (status != XAIOS_OK) {
      return write_error(response, response_capacity, response_bytes,
                         request->operation, request->request_id,
                         XAIOS_CONTROL_STATUS_INTERNAL);
    }
    status = block_device_info(device, &infos[0]);
    xaios_status_t close_status = block_device_close(device);
    if (status != XAIOS_OK || close_status != XAIOS_OK) {
      return write_error(response, response_capacity, response_bytes,
                         request->operation, request->request_id,
                         XAIOS_CONTROL_STATUS_INTERNAL);
    }
    value.metadata.record_count = 1U;
    value.metadata.total_count = 1U;
    storage_device_record(&value.records[0], &infos[0]);
  }

  uint64_t payload_size = sizeof(value.metadata) +
                          (uint64_t)value.metadata.record_count *
                              sizeof(value.records[0]);
  return write_response(response, response_capacity, response_bytes,
                        request->operation, request->request_id,
                        XAIOS_CONTROL_STATUS_OK,
                        XAIOS_CONTROL_PAYLOAD_STORAGE_DEVICES, &value,
                        payload_size);
}

static xaios_status_t fill_storage_filesystem(
    const char *path, xaios_control_storage_filesystem_record_t *record) {
  const char *mount_path = 0;
  const char *filesystem = 0;
  const char *stat_path = 0;
  xaios_model_mount_status_t model;
  bytes_zero(&model, sizeof(model));
  bytes_zero(record, sizeof(*record));
  if (string_equal(path, "/") || string_equal(path, "/config") ||
      string_equal(path, "/state") || string_equal(path, "/logs")) {
    mount_path = "/";
    filesystem = "xaibootFS";
    stat_path = "/";
    string_copy(record->device_identifier, sizeof(record->device_identifier),
                "unknown");
  } else if (string_equal(path, "/models")) {
    if (vfs_xaifs_mount_status(&model) != XAIOS_OK) {
      return XAIOS_ERR_NOT_FOUND;
    }
    mount_path = "/models";
    filesystem = "xaiFS";
    stat_path = "/models";
    string_copy(record->device_identifier, sizeof(record->device_identifier),
                model.device.identifier);
  } else {
    return XAIOS_ERR_NOT_FOUND;
  }
  xaios_vfs_statfs_t statfs;
  bytes_zero(&statfs, sizeof(statfs));
  xaios_status_t status = vfs_statfs(stat_path, &statfs);
  if (status != XAIOS_OK) return status;
  string_copy(record->mount_path, sizeof(record->mount_path), mount_path);
  string_copy(record->filesystem, sizeof(record->filesystem), filesystem);
  record->total_bytes = statfs.total_bytes;
  record->allocated_bytes = statfs.allocated_bytes;
  record->free_bytes = statfs.free_bytes;
  record->reserved_bytes = statfs.reserved_bytes;
  record->file_count = statfs.file_count;
  record->directory_count = statfs.directory_count;
  record->generation = statfs.generation;
  record->block_size = statfs.block_size;
  record->package_count = model.package_count;
  record->active_packages = model.active_packages;
  record->staging_packages = model.staging_packages;
  record->quarantined_packages = model.quarantined_packages;
  record->format_version = statfs.format_version;
  record->mounted = 1U;
  record->read_only = statfs.read_only;
  record->staging_writable = string_equal(mount_path, "/models") &&
                                     statfs.read_only == 0U
                                 ? 1U
                                 : 0U;
  return XAIOS_OK;
}

static xaios_status_t handle_storage_filesystems(
    const xaios_control_request_header_t *request, const uint8_t *payload,
    void *response, uint64_t response_capacity, uint64_t *response_bytes) {
  struct storage_filesystem_response {
    xaios_control_storage_filesystems_payload_t metadata;
    xaios_control_storage_filesystem_record_t
        records[XAIOS_CONTROL_STORAGE_MAX_FILESYSTEMS];
  } value;
  bytes_zero(&value, sizeof(value));
  if (request->operation == XAIOS_CONTROL_OP_STORAGE_FILESYSTEM_LIST) {
    if (request->payload_type != XAIOS_CONTROL_PAYLOAD_NONE ||
        request->payload_length != 0U) {
      return write_error(response, response_capacity, response_bytes,
                         request->operation, request->request_id,
                         XAIOS_CONTROL_STATUS_INVALID_REQUEST);
    }
    if (fill_storage_filesystem("/", &value.records[0]) != XAIOS_OK) {
      return write_error(response, response_capacity, response_bytes,
                         request->operation, request->request_id,
                         XAIOS_CONTROL_STATUS_INTERNAL);
    }
    value.metadata.record_count = 1U;
    value.metadata.total_count = 1U;
    xaios_status_t model_status =
        fill_storage_filesystem("/models", &value.records[1]);
    if (model_status == XAIOS_OK) {
      value.metadata.record_count = 2U;
      value.metadata.total_count = 2U;
    } else if (model_status != XAIOS_ERR_NOT_FOUND) {
      return write_error(response, response_capacity, response_bytes,
                         request->operation, request->request_id,
                         XAIOS_CONTROL_STATUS_INTERNAL);
    }
  } else {
    xaios_control_path_request_payload_t query;
    if (request->payload_type != XAIOS_CONTROL_PAYLOAD_PATH_REQUEST ||
        request->payload_length != sizeof(query)) {
      return write_error(response, response_capacity, response_bytes,
                         request->operation, request->request_id,
                         XAIOS_CONTROL_STATUS_INVALID_REQUEST);
    }
    bytes_copy(&query, payload, sizeof(query));
    if (!fixed_string_valid(query.path, sizeof(query.path))) {
      return write_error(response, response_capacity, response_bytes,
                         request->operation, request->request_id,
                         XAIOS_CONTROL_STATUS_INVALID_REQUEST);
    }
    xaios_status_t status = fill_storage_filesystem(query.path, &value.records[0]);
    if (status == XAIOS_ERR_NOT_FOUND) {
      return write_error(response, response_capacity, response_bytes,
                         request->operation, request->request_id,
                         XAIOS_CONTROL_STATUS_NOT_FOUND);
    }
    if (status != XAIOS_OK) {
      return write_error(response, response_capacity, response_bytes,
                         request->operation, request->request_id,
                         XAIOS_CONTROL_STATUS_INTERNAL);
    }
    value.metadata.record_count = 1U;
    value.metadata.total_count = 1U;
  }
  uint64_t payload_size = sizeof(value.metadata) +
                          (uint64_t)value.metadata.record_count *
                              sizeof(value.records[0]);
  return write_response(response, response_capacity, response_bytes,
                        request->operation, request->request_id,
                        XAIOS_CONTROL_STATUS_OK,
                        XAIOS_CONTROL_PAYLOAD_STORAGE_FILESYSTEMS, &value,
                        payload_size);
}

static xaios_control_status_t storage_control_status(xaios_status_t status) {
  if (status == XAIOS_ERR_NOT_FOUND) return XAIOS_CONTROL_STATUS_NOT_FOUND;
  if (status == XAIOS_ERR_BUSY || status == XAIOS_ERR_UNSUPPORTED) {
    return XAIOS_CONTROL_STATUS_CONFLICT;
  }
  if (status == XAIOS_ERR_INVALID) return XAIOS_CONTROL_STATUS_INVALID_REQUEST;
  return XAIOS_CONTROL_STATUS_INTERNAL;
}

static xaios_admin_result_t storage_admin_result(xaios_status_t status) {
  if (status == XAIOS_OK) return XAIOS_ADMIN_RESULT_OK;
  if (status == XAIOS_ERR_NOT_FOUND) return XAIOS_ADMIN_RESULT_NOT_FOUND;
  if (status == XAIOS_ERR_BUSY || status == XAIOS_ERR_UNSUPPORTED) {
    return XAIOS_ADMIN_RESULT_CONFLICT;
  }
  if (status == XAIOS_ERR_IO) return XAIOS_ADMIN_RESULT_IO;
  return XAIOS_ADMIN_RESULT_INVALID;
}

static int storage_partition_mutation(uint16_t operation) {
  return operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_CREATE ||
         operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_DELETE ||
         operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_RESIZE ||
         operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_REPAIR;
}

static const char *storage_partition_audit_name(uint16_t operation) {
  if (operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_CREATE) {
    return "storage.part.create";
  }
  if (operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_DELETE) {
    return "storage.part.delete";
  }
  if (operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_RESIZE) {
    return "storage.part.resize";
  }
  return "storage.gpt.repair";
}

static xaios_status_t handle_storage_partition_read(
    const xaios_control_request_header_t *request, const uint8_t *payload,
    void *response, uint64_t response_capacity, uint64_t *response_bytes) {
  xaios_control_path_request_payload_t query;
  if (request->payload_type != XAIOS_CONTROL_PAYLOAD_PATH_REQUEST ||
      request->payload_length != sizeof(query)) {
    return write_error(response, response_capacity, response_bytes,
                       request->operation, request->request_id,
                       XAIOS_CONTROL_STATUS_INVALID_REQUEST);
  }
  bytes_copy(&query, payload, sizeof(query));
  if (!fixed_string_valid(query.path, sizeof(query.path))) {
    return write_error(response, response_capacity, response_bytes,
                       request->operation, request->request_id,
                       XAIOS_CONTROL_STATUS_INVALID_REQUEST);
  }
  struct storage_partition_response {
    xaios_control_storage_partitions_payload_t metadata;
    xaios_storage_partition_record_t
        records[XAIOS_CONTROL_STORAGE_MAX_PARTITIONS];
  } value;
  bytes_zero(&value, sizeof(value));
  uint64_t total = 0U;
  xaios_status_t status;
  if (request->operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_LIST) {
    status = storage_admin_partition_list(
        query.path, value.records, XAIOS_CONTROL_STORAGE_MAX_PARTITIONS,
        &total, &value.metadata.report);
  } else {
    status = storage_admin_partition_verify(query.path,
                                            &value.metadata.report);
  }
  if (status != XAIOS_OK) {
    return write_error(response, response_capacity, response_bytes,
                       request->operation, request->request_id,
                       storage_control_status(status));
  }
  value.metadata.total_count =
      total > UINT32_MAX ? UINT32_MAX : (uint32_t)total;
  value.metadata.record_count =
      total > XAIOS_CONTROL_STORAGE_MAX_PARTITIONS
          ? XAIOS_CONTROL_STORAGE_MAX_PARTITIONS
          : (uint32_t)total;
  value.metadata.truncated =
      total > XAIOS_CONTROL_STORAGE_MAX_PARTITIONS ? 1U : 0U;
  uint64_t payload_size = sizeof(value.metadata) +
                          (uint64_t)value.metadata.record_count *
                              sizeof(value.records[0]);
  return write_response(response, response_capacity, response_bytes,
                        request->operation, request->request_id,
                        XAIOS_CONTROL_STATUS_OK,
                        XAIOS_CONTROL_PAYLOAD_STORAGE_PARTITIONS, &value,
                        payload_size);
}

/* Install XAIOS onto another disk.
 *
 * The most destructive operation this protocol exposes: it writes a partition
 * table over whatever the target held. It therefore takes the same shape as the
 * partition mutations -- an admin role on both the connection and the
 * principal, a named actor, an operation id, an audited begin and end, and the
 * target disk's own GUID as confirmation. install_to_disk refuses outright to
 * install onto the disk the source partition lives on, so the running system
 * cannot be overwritten by a mistyped device name.
 */
static xaios_status_t handle_storage_install(
    const xaios_control_request_header_t *request, const uint8_t *payload,
    void *response, uint64_t response_capacity, uint64_t *response_bytes,
    xaios_control_role_t authenticated_role) {
  xaios_control_storage_install_request_payload_t query;
  if (request->payload_type !=
          XAIOS_CONTROL_PAYLOAD_STORAGE_INSTALL_REQUEST ||
      request->payload_length != sizeof(query)) {
    return write_error(response, response_capacity, response_bytes,
                       request->operation, request->request_id,
                       XAIOS_CONTROL_STATUS_INVALID_REQUEST);
  }
  bytes_copy(&query, payload, sizeof(query));
  if (!fixed_string_valid(query.request.target,
                          sizeof(query.request.target)) ||
      !fixed_string_valid(query.request.source,
                          sizeof(query.request.source)) ||
      !fixed_string_terminated(query.request.confirmation,
                               sizeof(query.request.confirmation)) ||
      !fixed_string_terminated(query.actor, sizeof(query.actor))) {
    return write_error(response, response_capacity, response_bytes,
                       request->operation, request->request_id,
                       XAIOS_CONTROL_STATUS_INVALID_REQUEST);
  }
  if (authenticated_role < XAIOS_CONTROL_ROLE_ADMIN ||
      request->principal_role < XAIOS_CONTROL_ROLE_ADMIN ||
      query.actor[0] == '\0') {
    return write_admin_error(request, XAIOS_ADMIN_RESULT_DENIED, response,
                             response_capacity, response_bytes);
  }
  xaios_admin_result_t begin = admin_control_mutation_begin(
      query.actor, request->principal_role, XAIOS_CONTROL_ROLE_ADMIN,
      query.request.operation_id, "storage.install");
  if (begin != XAIOS_ADMIN_RESULT_OK) {
    return write_admin_error(request, begin, response, response_capacity,
                             response_bytes);
  }

  xaios_install_report_t report;
  xaios_status_t status =
      install_to_disk(query.request.target, query.request.source,
                      query.request.confirmation,
                      query.request.operation_id, &report);
  if (status != XAIOS_OK) {
    xaios_admin_result_t failed = admin_control_mutation_fail(
        query.actor, request->principal_role, query.request.operation_id,
        "storage.install", XAIOS_ADMIN_RESULT_DENIED);
    (void)failed;
    return write_error(response, response_capacity, response_bytes,
                       request->operation, request->request_id,
                       XAIOS_CONTROL_STATUS_INVALID_REQUEST);
  }
  /* The audit record identifies the disk that was written, which is the thing
     an operator would later need to account for. */
  uint8_t object_hash[32];
  bytes_zero(object_hash, sizeof(object_hash));
  string_copy((char *)object_hash, sizeof(object_hash), query.request.target);
  xaios_admin_result_t completed = admin_control_mutation_complete(
      query.actor, request->principal_role, query.request.operation_id,
      "storage.install", object_hash);
  if (completed != XAIOS_ADMIN_RESULT_OK) {
    return write_admin_error(request, completed, response, response_capacity,
                             response_bytes);
  }

  xaios_control_storage_install_result_t result;
  bytes_zero(&result, sizeof(result));
  string_copy(result.esp_identifier, sizeof(result.esp_identifier),
              report.esp_identifier);
  string_copy(result.state_identifier, sizeof(result.state_identifier),
              report.state_identifier);
  result.files_copied = report.file_count;
  result.bytes_copied = report.bytes_copied;
  result.esp_bytes = report.esp_bytes;
  result.state_bytes = report.state_bytes;
  return write_response(response, response_capacity, response_bytes,
                        request->operation, request->request_id,
                        XAIOS_CONTROL_STATUS_OK,
                        XAIOS_CONTROL_PAYLOAD_STORAGE_INSTALL_RESULT, &result,
                        sizeof(result));
}

static xaios_status_t handle_storage_partition_operation(
    const xaios_control_request_header_t *request, const uint8_t *payload,
    void *response, uint64_t response_capacity, uint64_t *response_bytes,
    xaios_control_role_t authenticated_role) {
  xaios_control_storage_partition_request_payload_t query;
  if (request->payload_type !=
          XAIOS_CONTROL_PAYLOAD_STORAGE_PARTITION_REQUEST ||
      request->payload_length != sizeof(query)) {
    return write_error(response, response_capacity, response_bytes,
                       request->operation, request->request_id,
                       XAIOS_CONTROL_STATUS_INVALID_REQUEST);
  }
  bytes_copy(&query, payload, sizeof(query));
  if (!fixed_string_valid(query.request.target,
                          sizeof(query.request.target)) ||
      !fixed_string_terminated(query.request.confirmation,
                               sizeof(query.request.confirmation)) ||
      !fixed_string_terminated(query.request.name,
                               sizeof(query.request.name)) ||
      !fixed_string_terminated(query.actor, sizeof(query.actor))) {
    return write_error(response, response_capacity, response_bytes,
                       request->operation, request->request_id,
                       XAIOS_CONTROL_STATUS_INVALID_REQUEST);
  }
  int mutation = storage_partition_mutation(request->operation);
  if (mutation != 0 &&
      (authenticated_role < XAIOS_CONTROL_ROLE_ADMIN ||
       request->principal_role < XAIOS_CONTROL_ROLE_ADMIN ||
       query.actor[0] == '\0')) {
    return write_admin_error(request, XAIOS_ADMIN_RESULT_DENIED, response,
                             response_capacity, response_bytes);
  }

  xaios_storage_partition_plan_t plan;
  bytes_zero(&plan, sizeof(plan));
  const char *audit_name = storage_partition_audit_name(request->operation);
  if (mutation != 0) {
    xaios_admin_result_t begin = admin_control_mutation_begin(
        query.actor, request->principal_role, XAIOS_CONTROL_ROLE_ADMIN,
        query.request.operation_id, audit_name);
    if (begin != XAIOS_ADMIN_RESULT_OK) {
      return write_admin_error(request, begin, response, response_capacity,
                               response_bytes);
    }
  }

  xaios_status_t status = XAIOS_ERR_INVALID;
  if (request->operation ==
      XAIOS_CONTROL_OP_STORAGE_PARTITION_PLAN_CREATE) {
    status = storage_admin_partition_plan_create(&query.request, &plan);
  } else if (request->operation ==
             XAIOS_CONTROL_OP_STORAGE_PARTITION_CREATE) {
    status = storage_admin_partition_create(&query.request, &plan);
  } else if (request->operation ==
             XAIOS_CONTROL_OP_STORAGE_PARTITION_PLAN_DELETE) {
    status = storage_admin_partition_plan_delete(&query.request, &plan);
  } else if (request->operation ==
             XAIOS_CONTROL_OP_STORAGE_PARTITION_DELETE) {
    status = storage_admin_partition_delete(&query.request, &plan);
  } else if (request->operation ==
             XAIOS_CONTROL_OP_STORAGE_PARTITION_PLAN_RESIZE) {
    status = storage_admin_partition_plan_resize(&query.request, &plan);
  } else if (request->operation ==
             XAIOS_CONTROL_OP_STORAGE_PARTITION_RESIZE) {
    status = storage_admin_partition_resize(&query.request, &plan);
  } else if (request->operation ==
             XAIOS_CONTROL_OP_STORAGE_PARTITION_REPAIR) {
    status = storage_admin_partition_repair(&query.request, &plan);
  }
  if (status != XAIOS_OK) {
    if (mutation != 0) {
      xaios_admin_result_t failed = admin_control_mutation_fail(
          query.actor, request->principal_role, query.request.operation_id,
          audit_name, storage_admin_result(status));
      return write_admin_error(request, failed, response, response_capacity,
                               response_bytes);
    }
    return write_error(response, response_capacity, response_bytes,
                       request->operation, request->request_id,
                       storage_control_status(status));
  }
  if (mutation != 0) {
    uint8_t object_hash[32];
    bytes_zero(object_hash, sizeof(object_hash));
    const char *identity = plan.partition.unique_guid[0] != '\0'
                               ? plan.partition.unique_guid
                               : plan.report.disk_guid;
    for (uint32_t index = 0U; index < sizeof(object_hash) &&
                             identity[index] != '\0';
         ++index) {
      object_hash[index] = (uint8_t)identity[index];
    }
    xaios_admin_result_t completed = admin_control_mutation_complete(
        query.actor, request->principal_role, query.request.operation_id,
        audit_name, object_hash);
    if (completed != XAIOS_ADMIN_RESULT_OK) {
      return write_admin_error(request, completed, response,
                               response_capacity, response_bytes);
    }
  }
  return write_response(response, response_capacity, response_bytes,
                        request->operation, request->request_id,
                        XAIOS_CONTROL_STATUS_OK,
                        XAIOS_CONTROL_PAYLOAD_STORAGE_PARTITION_PLAN, &plan,
                        sizeof(plan));
}

static int storage_volume_mutation(uint16_t operation) {
  return operation == XAIOS_CONTROL_OP_STORAGE_FORMAT ||
         operation == XAIOS_CONTROL_OP_STORAGE_MOUNT ||
         operation == XAIOS_CONTROL_OP_STORAGE_UNMOUNT ||
         operation == XAIOS_CONTROL_OP_STORAGE_FS_REPAIR ||
         operation == XAIOS_CONTROL_OP_STORAGE_FS_RESIZE;
}

static const char *storage_volume_audit_name(uint16_t operation) {
  if (operation == XAIOS_CONTROL_OP_STORAGE_FORMAT) return "storage.fs.format";
  if (operation == XAIOS_CONTROL_OP_STORAGE_MOUNT) return "storage.fs.mount";
  if (operation == XAIOS_CONTROL_OP_STORAGE_UNMOUNT) {
    return "storage.fs.unmount";
  }
  if (operation == XAIOS_CONTROL_OP_STORAGE_FS_REPAIR) {
    return "storage.fs.repair";
  }
  return "storage.fs.resize";
}

static xaios_status_t handle_storage_volume_operation(
    const xaios_control_request_header_t *request, const uint8_t *payload,
    void *response, uint64_t response_capacity, uint64_t *response_bytes,
    xaios_control_role_t authenticated_role) {
  xaios_control_storage_volume_request_payload_t query;
  if (request->payload_type != XAIOS_CONTROL_PAYLOAD_STORAGE_VOLUME_REQUEST ||
      request->payload_length != sizeof(query)) {
    return write_error(response, response_capacity, response_bytes,
                       request->operation, request->request_id,
                       XAIOS_CONTROL_STATUS_INVALID_REQUEST);
  }
  bytes_copy(&query, payload, sizeof(query));
  if (!fixed_string_valid(query.target, sizeof(query.target)) ||
      !fixed_string_terminated(query.confirmation,
                               sizeof(query.confirmation)) ||
      !fixed_string_terminated(query.mount_path, sizeof(query.mount_path)) ||
      !fixed_string_terminated(query.actor, sizeof(query.actor)) ||
      query.verify_data > 1U || query.read_only > 1U ||
      query.reserved != 0U) {
    return write_error(response, response_capacity, response_bytes,
                       request->operation, request->request_id,
                       XAIOS_CONTROL_STATUS_INVALID_REQUEST);
  }
  int mutation = storage_volume_mutation(request->operation);
  if (mutation != 0 &&
      (authenticated_role < XAIOS_CONTROL_ROLE_ADMIN ||
       request->principal_role < XAIOS_CONTROL_ROLE_ADMIN ||
       query.actor[0] == '\0' || query.operation_id == 0U)) {
    return write_admin_error(request, XAIOS_ADMIN_RESULT_DENIED, response,
                             response_capacity, response_bytes);
  }

  const char *audit_name = storage_volume_audit_name(request->operation);
  if (mutation != 0) {
    xaios_admin_result_t begin = admin_control_mutation_begin(
        query.actor, request->principal_role, XAIOS_CONTROL_ROLE_ADMIN,
        query.operation_id, audit_name);
    if (begin != XAIOS_ADMIN_RESULT_OK) {
      return write_admin_error(request, begin, response, response_capacity,
                               response_bytes);
    }
  }

  xaios_xai_fs_admin_report_t report;
  bytes_zero(&report, sizeof(report));
  xaios_status_t status = XAIOS_ERR_INVALID;
  if (request->operation == XAIOS_CONTROL_OP_STORAGE_FORMAT_PLAN) {
    status = xai_fs_admin_format_plan(query.target, query.chunk_size,
                                            &report);
  } else if (request->operation == XAIOS_CONTROL_OP_STORAGE_FORMAT) {
    status = xai_fs_admin_format(query.target, query.confirmation,
                                       query.chunk_size, &report);
  } else if (request->operation == XAIOS_CONTROL_OP_STORAGE_MOUNT) {
    if (string_equal(query.mount_path, "/models")) {
      status = xai_fs_admin_fsck(query.target, 0U, &report);
      if (status == XAIOS_OK &&
          report.check_state != XAIOS_XAI_FS_CHECK_CLEAN) {
        status = XAIOS_ERR_IO;
      }
      if (status == XAIOS_OK) {
        status = vfs_mount_model_device(query.target, query.mount_path,
                                        query.read_only);
      }
    }
  } else if (request->operation == XAIOS_CONTROL_OP_STORAGE_UNMOUNT) {
    if (string_equal(query.target, "/models")) {
      status = vfs_unmount_xai_fs(query.target);
      if (status == XAIOS_OK) {
        bytes_copy(report.target, query.target, sizeof(report.target));
      }
    }
  } else if (request->operation == XAIOS_CONTROL_OP_STORAGE_FSCK) {
    status = xai_fs_admin_fsck(query.target, query.verify_data, &report);
  } else if (request->operation == XAIOS_CONTROL_OP_STORAGE_FS_REPAIR) {
    status = xai_fs_admin_repair(query.target, query.confirmation,
                                       &report);
  } else if (request->operation ==
             XAIOS_CONTROL_OP_STORAGE_FS_RESIZE_PLAN) {
    status = xai_fs_admin_grow_plan(query.target, query.size_bytes,
                                          &report);
  } else if (request->operation == XAIOS_CONTROL_OP_STORAGE_FS_RESIZE) {
    status = xai_fs_admin_grow(query.target, query.confirmation,
                                     query.size_bytes, &report);
  }

  if (status != XAIOS_OK) {
    if (mutation != 0) {
      xaios_admin_result_t failed = admin_control_mutation_fail(
          query.actor, request->principal_role, query.operation_id,
          audit_name, storage_admin_result(status));
      return write_admin_error(request, failed, response, response_capacity,
                               response_bytes);
    }
    return write_error(response, response_capacity, response_bytes,
                       request->operation, request->request_id,
                       storage_control_status(status));
  }
  if (mutation != 0) {
    uint8_t object_hash[32];
    bytes_zero(object_hash, sizeof(object_hash));
    const char *identity = report.volume_uuid[0] != '\0'
                               ? report.volume_uuid
                               : report.target;
    for (uint32_t index = 0U;
         index < sizeof(object_hash) && identity[index] != '\0'; ++index) {
      object_hash[index] = (uint8_t)identity[index];
    }
    xaios_admin_result_t completed = admin_control_mutation_complete(
        query.actor, request->principal_role, query.operation_id, audit_name,
        object_hash);
    if (completed != XAIOS_ADMIN_RESULT_OK) {
      return write_admin_error(request, completed, response,
                               response_capacity, response_bytes);
    }
  }
  return write_response(response, response_capacity, response_bytes,
                        request->operation, request->request_id,
                        XAIOS_CONTROL_STATUS_OK,
                        XAIOS_CONTROL_PAYLOAD_STORAGE_VOLUME_REPORT, &report,
                        sizeof(report));
}

static xaios_status_t handle_storage_replica_repair(
    const xaios_control_request_header_t *request, const uint8_t *payload,
    void *response, uint64_t response_capacity, uint64_t *response_bytes,
    xaios_control_role_t authenticated_role) {
  xaios_control_storage_replica_repair_request_payload_t query;
  if (request->payload_type !=
          XAIOS_CONTROL_PAYLOAD_STORAGE_REPLICA_REPAIR_REQUEST ||
      request->payload_length != sizeof(query)) {
    return write_error(response, response_capacity, response_bytes,
                       request->operation, request->request_id,
                       XAIOS_CONTROL_STATUS_INVALID_REQUEST);
  }
  bytes_copy(&query, payload, sizeof(query));
  if (!fixed_string_valid(query.target, sizeof(query.target)) ||
      !fixed_string_valid(query.replica, sizeof(query.replica)) ||
      !fixed_string_terminated(query.confirmation,
                               sizeof(query.confirmation)) ||
      !fixed_string_terminated(query.package_id, sizeof(query.package_id)) ||
      !fixed_string_terminated(query.actor, sizeof(query.actor)) ||
      string_equal(query.target, query.replica) || query.actor[0] == '\0' ||
      query.operation_id == 0U ||
      authenticated_role < XAIOS_CONTROL_ROLE_ADMIN ||
      request->principal_role < XAIOS_CONTROL_ROLE_ADMIN) {
    return write_admin_error(request, XAIOS_ADMIN_RESULT_DENIED, response,
                             response_capacity, response_bytes);
  }
  const char *audit_name = "storage.fs.replica-repair";
  xaios_admin_result_t begin = admin_control_mutation_begin(
      query.actor, request->principal_role, XAIOS_CONTROL_ROLE_ADMIN,
      query.operation_id, audit_name);
  if (begin != XAIOS_ADMIN_RESULT_OK) {
    return write_admin_error(request, begin, response, response_capacity,
                             response_bytes);
  }
  xaios_xai_fs_admin_report_t report;
  bytes_zero(&report, sizeof(report));
  xaios_status_t status = xai_fs_admin_repair_from_replica(
      query.target, query.confirmation, query.replica, query.package_id,
      &report);
  if (status != XAIOS_OK) {
    xaios_admin_result_t failed = admin_control_mutation_fail(
        query.actor, request->principal_role, query.operation_id, audit_name,
        storage_admin_result(status));
    return write_admin_error(request, failed, response, response_capacity,
                             response_bytes);
  }
  uint8_t object_hash[32];
  bytes_zero(object_hash, sizeof(object_hash));
  for (uint32_t index = 0U;
       index < sizeof(object_hash) && query.package_id[index] != '\0';
       ++index) {
    object_hash[index] = (uint8_t)query.package_id[index];
  }
  xaios_admin_result_t completed = admin_control_mutation_complete(
      query.actor, request->principal_role, query.operation_id, audit_name,
      object_hash);
  if (completed != XAIOS_ADMIN_RESULT_OK) {
    return write_admin_error(request, completed, response, response_capacity,
                             response_bytes);
  }
  return write_response(response, response_capacity, response_bytes,
                        request->operation, request->request_id,
                        XAIOS_CONTROL_STATUS_OK,
                        XAIOS_CONTROL_PAYLOAD_STORAGE_VOLUME_REPORT, &report,
                        sizeof(report));
}

static int storage_scrub_mutation(uint16_t operation) {
  return operation != XAIOS_CONTROL_OP_STORAGE_SCRUB_STATUS;
}

static const char *storage_scrub_audit_name(uint16_t operation) {
  if (operation == XAIOS_CONTROL_OP_STORAGE_SCRUB_START) {
    return "storage.scrub.start";
  }
  if (operation == XAIOS_CONTROL_OP_STORAGE_SCRUB_PAUSE) {
    return "storage.scrub.pause";
  }
  if (operation == XAIOS_CONTROL_OP_STORAGE_SCRUB_RESUME) {
    return "storage.scrub.resume";
  }
  return "storage.scrub.cancel";
}

static xaios_status_t handle_storage_scrub_operation(
    const xaios_control_request_header_t *request, const uint8_t *payload,
    void *response, uint64_t response_capacity, uint64_t *response_bytes,
    xaios_control_role_t authenticated_role) {
  xaios_control_storage_volume_request_payload_t query;
  if (request->payload_type != XAIOS_CONTROL_PAYLOAD_STORAGE_VOLUME_REQUEST ||
      request->payload_length != sizeof(query)) {
    return write_error(response, response_capacity, response_bytes,
                       request->operation, request->request_id,
                       XAIOS_CONTROL_STATUS_INVALID_REQUEST);
  }
  bytes_copy(&query, payload, sizeof(query));
  if (!fixed_string_valid(query.target, sizeof(query.target)) ||
      !string_equal(query.target, "/models") ||
      !fixed_string_terminated(query.actor, sizeof(query.actor)) ||
      query.confirmation[0] != '\0' || query.mount_path[0] != '\0' ||
      query.size_bytes != 0U || query.chunk_size != 0U ||
      query.verify_data != 0U || query.read_only != 0U ||
      query.reserved != 0U) {
    return write_error(response, response_capacity, response_bytes,
                       request->operation, request->request_id,
                       XAIOS_CONTROL_STATUS_INVALID_REQUEST);
  }
  int mutation = storage_scrub_mutation(request->operation);
  if (mutation != 0 &&
      (authenticated_role < XAIOS_CONTROL_ROLE_ADMIN ||
       request->principal_role < XAIOS_CONTROL_ROLE_ADMIN ||
       query.operation_id == 0U || query.actor[0] == '\0')) {
    return write_admin_error(request, XAIOS_ADMIN_RESULT_DENIED, response,
                             response_capacity, response_bytes);
  }
  const char *audit_name = storage_scrub_audit_name(request->operation);
  if (mutation != 0) {
    xaios_admin_result_t begin = admin_control_mutation_begin(
        query.actor, request->principal_role, XAIOS_CONTROL_ROLE_ADMIN,
        query.operation_id, audit_name);
    if (begin != XAIOS_ADMIN_RESULT_OK) {
      return write_admin_error(request, begin, response, response_capacity,
                               response_bytes);
    }
  }
  xaios_control_storage_scrub_report_t report;
  bytes_zero(&report, sizeof(report));
  xaios_status_t status = XAIOS_ERR_INVALID;
  if (request->operation == XAIOS_CONTROL_OP_STORAGE_SCRUB_START) {
    status = vfs_xaifs_scrub_start(&report.status);
    if (status == XAIOS_OK) status = vfs_xaifs_scrub_step(&report.status);
  } else if (request->operation == XAIOS_CONTROL_OP_STORAGE_SCRUB_STATUS) {
    status = vfs_xaifs_scrub_step(&report.status);
  } else if (request->operation == XAIOS_CONTROL_OP_STORAGE_SCRUB_PAUSE) {
    status = vfs_xaifs_scrub_pause(&report.status);
  } else if (request->operation == XAIOS_CONTROL_OP_STORAGE_SCRUB_RESUME) {
    status = vfs_xaifs_scrub_resume(&report.status);
  } else if (request->operation == XAIOS_CONTROL_OP_STORAGE_SCRUB_CANCEL) {
    status = vfs_xaifs_scrub_cancel(&report.status);
  }
  if (status != XAIOS_OK &&
      report.status.state != XAIOS_MODEL_MAINTENANCE_FAILED) {
    if (mutation != 0) {
      xaios_admin_result_t failed = admin_control_mutation_fail(
          query.actor, request->principal_role, query.operation_id, audit_name,
          storage_admin_result(status));
      return write_admin_error(request, failed, response, response_capacity,
                               response_bytes);
    }
    return write_error(response, response_capacity, response_bytes,
                       request->operation, request->request_id,
                       storage_control_status(status));
  }
  if (mutation != 0) {
    xaios_admin_result_t completed = admin_control_mutation_complete(
        query.actor, request->principal_role, query.operation_id, audit_name,
        report.status.volume_uuid);
    if (completed != XAIOS_ADMIN_RESULT_OK) {
      return write_admin_error(request, completed, response,
                               response_capacity, response_bytes);
    }
  }
  return write_response(response, response_capacity, response_bytes,
                        request->operation, request->request_id,
                        XAIOS_CONTROL_STATUS_OK,
                        XAIOS_CONTROL_PAYLOAD_STORAGE_SCRUB_REPORT, &report,
                        sizeof(report));
}

static const char *storage_trim_audit_name(uint16_t operation) {
  return operation == XAIOS_CONTROL_OP_STORAGE_TRIM_CANCEL
             ? "storage.trim.cancel"
             : "storage.trim.start";
}

static xaios_status_t handle_storage_trim_operation(
    const xaios_control_request_header_t *request, const uint8_t *payload,
    void *response, uint64_t response_capacity, uint64_t *response_bytes,
    xaios_control_role_t authenticated_role) {
  xaios_control_storage_trim_request_payload_t query;
  if (request->payload_type != XAIOS_CONTROL_PAYLOAD_STORAGE_TRIM_REQUEST ||
      request->payload_length != sizeof(query)) {
    return write_error(response, response_capacity, response_bytes,
                       request->operation, request->request_id,
                       XAIOS_CONTROL_STATUS_INVALID_REQUEST);
  }
  bytes_copy(&query, payload, sizeof(query));
  if (!fixed_string_valid(query.target, sizeof(query.target)) ||
      !string_equal(query.target, "/models") ||
      !fixed_string_terminated(query.actor, sizeof(query.actor)) ||
      query.dry_run > 1U || query.all_free > 1U ||
      (request->operation != XAIOS_CONTROL_OP_STORAGE_TRIM_START &&
       (query.offset != 0U || query.length != 0U || query.dry_run != 0U ||
        query.all_free != 0U))) {
    return write_error(response, response_capacity, response_bytes,
                       request->operation, request->request_id,
                       XAIOS_CONTROL_STATUS_INVALID_REQUEST);
  }
  int mutation =
      request->operation == XAIOS_CONTROL_OP_STORAGE_TRIM_CANCEL ||
      (request->operation == XAIOS_CONTROL_OP_STORAGE_TRIM_START &&
       query.dry_run == 0U);
  if (mutation != 0 &&
      (authenticated_role < XAIOS_CONTROL_ROLE_ADMIN ||
       request->principal_role < XAIOS_CONTROL_ROLE_ADMIN ||
       query.operation_id == 0U || query.actor[0] == '\0')) {
    return write_admin_error(request, XAIOS_ADMIN_RESULT_DENIED, response,
                             response_capacity, response_bytes);
  }
  if (mutation == 0 && query.operation_id != 0U) {
    return write_error(response, response_capacity, response_bytes,
                       request->operation, request->request_id,
                       XAIOS_CONTROL_STATUS_INVALID_REQUEST);
  }
  const char *audit_name = storage_trim_audit_name(request->operation);
  if (mutation != 0) {
    xaios_admin_result_t begin = admin_control_mutation_begin(
        query.actor, request->principal_role, XAIOS_CONTROL_ROLE_ADMIN,
        query.operation_id, audit_name);
    if (begin != XAIOS_ADMIN_RESULT_OK) {
      return write_admin_error(request, begin, response, response_capacity,
                               response_bytes);
    }
  }
  xaios_control_storage_trim_report_t report;
  bytes_zero(&report, sizeof(report));
  xaios_status_t status = XAIOS_ERR_INVALID;
  if (request->operation == XAIOS_CONTROL_OP_STORAGE_TRIM_START) {
    status = vfs_xaifs_trim_start(query.dry_run, query.all_free, query.offset,
                                  query.length, &report.status);
    if (status == XAIOS_OK) status = vfs_xaifs_trim_step(&report.status);
  } else if (request->operation == XAIOS_CONTROL_OP_STORAGE_TRIM_STATUS) {
    status = vfs_xaifs_trim_step(&report.status);
  } else if (request->operation == XAIOS_CONTROL_OP_STORAGE_TRIM_CANCEL) {
    status = vfs_xaifs_trim_cancel(&report.status);
  }
  if (status != XAIOS_OK &&
      report.status.state != XAIOS_MODEL_MAINTENANCE_FAILED) {
    if (mutation != 0) {
      xaios_admin_result_t failed = admin_control_mutation_fail(
          query.actor, request->principal_role, query.operation_id, audit_name,
          storage_admin_result(status));
      return write_admin_error(request, failed, response, response_capacity,
                               response_bytes);
    }
    return write_error(response, response_capacity, response_bytes,
                       request->operation, request->request_id,
                       storage_control_status(status));
  }
  if (mutation != 0) {
    xaios_admin_result_t completed = admin_control_mutation_complete(
        query.actor, request->principal_role, query.operation_id, audit_name,
        report.status.volume_uuid);
    if (completed != XAIOS_ADMIN_RESULT_OK) {
      return write_admin_error(request, completed, response,
                               response_capacity, response_bytes);
    }
  }
  return write_response(response, response_capacity, response_bytes,
                        request->operation, request->request_id,
                        XAIOS_CONTROL_STATUS_OK,
                        XAIOS_CONTROL_PAYLOAD_STORAGE_TRIM_REPORT, &report,
                        sizeof(report));
}

static xaios_status_t append_log_record(
    char *output, uint64_t capacity, uint64_t *offset, uint64_t sequence,
    const char *component, const char *level, const char *line,
    uint64_t line_size, int redact) {
  if (append_text(output, capacity, offset, "seq=") != XAIOS_OK ||
      append_u64(output, capacity, offset, sequence) != XAIOS_OK ||
      append_text(output, capacity, offset,
                  " time=unknown level=") != XAIOS_OK ||
      append_text(output, capacity, offset, level) != XAIOS_OK ||
      append_text(output, capacity, offset, " component=") != XAIOS_OK ||
      append_text(output, capacity, offset, component) != XAIOS_OK ||
      append_text(output, capacity, offset,
                  " request_id=unknown message=") != XAIOS_OK) {
    return XAIOS_ERR_NO_MEMORY;
  }
  if (redact != 0) {
    if (append_text(output, capacity, offset, "[redacted]") != XAIOS_OK) {
      return XAIOS_ERR_NO_MEMORY;
    }
  } else {
    for (uint64_t i = 0; i < line_size; ++i) {
      char value = line[i];
      if ((uint8_t)value < UINT8_C(32) && value != '\t') {
        value = '?';
      }
      if (*offset >= capacity) {
        return XAIOS_ERR_NO_MEMORY;
      }
      output[*offset] = value;
      ++(*offset);
    }
  }
  return append_text(output, capacity, offset, "\n");
}

static xaios_status_t handle_logs(
    const xaios_control_request_header_t *request,
    const xaios_control_log_request_payload_t *query, void *response,
    uint64_t response_capacity, uint64_t *response_bytes) {
  xaios_control_response_header_t header;
  xaios_control_logs_payload_t metadata;
  char *snapshot = (char *)kheap_calloc(XAIOS_KLOG_RING_SIZE, 16U);
  uint64_t response_prefix = sizeof(header) + sizeof(metadata);
  if (snapshot == 0 || response_capacity < response_prefix) {
    kheap_free(snapshot);
    return write_error(response, response_capacity, response_bytes,
                       request->operation, request->request_id,
                       XAIOS_CONTROL_STATUS_BUFFER_TOO_SMALL);
  }

  bytes_zero(&metadata, sizeof(metadata));
  uint64_t snapshot_start = 0U;
  uint64_t snapshot_next = 0U;
  uint64_t snapshot_latest = 0U;
  uint32_t snapshot_bytes = klog_ring_snapshot(
      snapshot, XAIOS_KLOG_RING_SIZE, query->since_cursor, &snapshot_start,
      &snapshot_next, &snapshot_latest);
  metadata.start_cursor = snapshot_start;
  metadata.next_cursor = snapshot_start;
  metadata.latest_cursor = snapshot_latest;

  char *records = (char *)response + response_prefix;
  uint64_t records_capacity = response_capacity - response_prefix;
  uint64_t records_bytes = 0U;
  uint64_t line_start = 0U;
  uint32_t limit = query->limit == 0U ? 100U : query->limit;
  while (line_start < snapshot_bytes && metadata.record_count < limit) {
    uint64_t line_end = line_start;
    while (line_end < snapshot_bytes && snapshot[line_end] != '\n') {
      ++line_end;
    }
    uint64_t next_line = line_end < snapshot_bytes ? line_end + 1U : line_end;
    char component[XAIOS_CONTROL_LOG_COMPONENT_MAX];
    log_component(snapshot + line_start, line_end - line_start, component,
                  sizeof(component));
    if (component_matches(query->component, component)) {
      int redact =
          log_line_sensitive(snapshot + line_start, line_end - line_start);
      uint64_t before = records_bytes;
      if (append_log_record(records, records_capacity, &records_bytes,
                            snapshot_start + next_line, component,
                            log_level(snapshot + line_start,
                                      line_end - line_start),
                            snapshot + line_start, line_end - line_start,
                            redact) != XAIOS_OK) {
        records_bytes = before;
        break;
      }
      ++metadata.record_count;
      if (redact != 0) {
        ++metadata.redacted_count;
      }
    }
    metadata.next_cursor = snapshot_start + next_line;
    line_start = next_line;
  }
  if (line_start >= snapshot_bytes) {
    metadata.next_cursor = snapshot_next;
  }

  bytes_zero(&header, sizeof(header));
  header.magic = XAIOS_CONTROL_MAGIC;
  header.version = XAIOS_CONTROL_VERSION;
  header.header_size = (uint16_t)sizeof(header);
  header.operation = request->operation;
  header.status = XAIOS_CONTROL_STATUS_OK;
  header.request_id = request->request_id;
  header.payload_type = XAIOS_CONTROL_PAYLOAD_LOGS;
  header.payload_length = sizeof(metadata) + records_bytes;
  bytes_copy(response, &header, sizeof(header));
  bytes_copy((uint8_t *)response + sizeof(header), &metadata,
             sizeof(metadata));
  *response_bytes = response_prefix + records_bytes;
  kheap_free(snapshot);
  return XAIOS_OK;
}

xaios_status_t control_protocol_dispatch(
    const void *request_bytes, uint64_t request_size, void *response,
    uint64_t response_capacity, uint64_t *response_bytes,
    xaios_control_role_t authenticated_role) {
  xaios_control_request_header_t request;
  counter_increment(&g_control_requests);
  /* Every handler's success path writes the response and its size without
     rechecking these, so the guarantee has to be made once here. Tolerating
     a null response_bytes at entry while handlers dereference it was an
     inconsistency waiting for a caller to find it. */
  if (response == 0 || response_bytes == 0) {
    return XAIOS_ERR_INVALID;
  }
  *response_bytes = 0U;
  if (request_bytes == 0 || request_size < sizeof(request)) {
    return write_error(response, response_capacity, response_bytes, 0U, 0U,
                       XAIOS_CONTROL_STATUS_INVALID_REQUEST);
  }
  bytes_copy(&request, request_bytes, sizeof(request));
  if (request.magic != XAIOS_CONTROL_MAGIC) {
    return write_error(response, response_capacity, response_bytes,
                       request.operation, request.request_id,
                       XAIOS_CONTROL_STATUS_INVALID_REQUEST);
  }
  if (request.version != XAIOS_CONTROL_VERSION) {
    return write_error(response, response_capacity, response_bytes,
                       request.operation, request.request_id,
                       XAIOS_CONTROL_STATUS_UNSUPPORTED_VERSION);
  }
  if (request.header_size != sizeof(request) || request.flags != 0U ||
      request.payload_length > XAIOS_CONTROL_MAX_REQUEST_BYTES - sizeof(request) ||
      request_size != sizeof(request) + request.payload_length ||
      request.timeout_ms > UINT64_C(60000)) {
    return write_error(response, response_capacity, response_bytes,
                       request.operation, request.request_id,
                       XAIOS_CONTROL_STATUS_INVALID_REQUEST);
  }
  if (request.principal_role == XAIOS_CONTROL_ROLE_NONE ||
      request.principal_role > XAIOS_CONTROL_ROLE_ADMIN ||
      request.principal_role > (uint32_t)authenticated_role) {
    return write_error(response, response_capacity, response_bytes,
                       request.operation, request.request_id,
                       XAIOS_CONTROL_STATUS_DENIED);
  }
  if (request.node_id != 0U) {
    return write_error(response, response_capacity, response_bytes,
                       request.operation, request.request_id,
                       XAIOS_CONTROL_STATUS_UNKNOWN_NODE);
  }

  const uint8_t *payload =
      (const uint8_t *)request_bytes + sizeof(request);
  switch ((xaios_control_operation_t)request.operation) {
  case XAIOS_CONTROL_OP_VERSION: {
    xaios_control_version_payload_t value;
    if (request.payload_type != XAIOS_CONTROL_PAYLOAD_NONE ||
        request.payload_length != 0U) {
      return write_error(response, response_capacity, response_bytes,
                         request.operation, request.request_id,
                         XAIOS_CONTROL_STATUS_INVALID_REQUEST);
    }
    fill_version(&value);
    return write_response(response, response_capacity, response_bytes,
                          request.operation, request.request_id,
                          XAIOS_CONTROL_STATUS_OK,
                          XAIOS_CONTROL_PAYLOAD_VERSION, &value,
                          sizeof(value));
  }
  case XAIOS_CONTROL_OP_STATUS: {
    xaios_control_status_payload_t value;
    if (request.payload_type != XAIOS_CONTROL_PAYLOAD_NONE ||
        request.payload_length != 0U) {
      return write_error(response, response_capacity, response_bytes,
                         request.operation, request.request_id,
                         XAIOS_CONTROL_STATUS_INVALID_REQUEST);
    }
    fill_status(&value);
    return write_response(response, response_capacity, response_bytes,
                          request.operation, request.request_id,
                          XAIOS_CONTROL_STATUS_OK,
                          XAIOS_CONTROL_PAYLOAD_STATUS, &value,
                          sizeof(value));
  }
  case XAIOS_CONTROL_OP_HEALTH: {
    xaios_control_health_payload_t value;
    if (request.payload_type != XAIOS_CONTROL_PAYLOAD_NONE ||
        request.payload_length != 0U) {
      return write_error(response, response_capacity, response_bytes,
                         request.operation, request.request_id,
                         XAIOS_CONTROL_STATUS_INVALID_REQUEST);
    }
    fill_health(&value);
    return write_response(response, response_capacity, response_bytes,
                          request.operation, request.request_id,
                          XAIOS_CONTROL_STATUS_OK,
                          XAIOS_CONTROL_PAYLOAD_HEALTH, &value,
                          sizeof(value));
  }
  case XAIOS_CONTROL_OP_CAPABILITIES: {
    xaios_control_capabilities_payload_t value;
    if (request.payload_type != XAIOS_CONTROL_PAYLOAD_NONE ||
        request.payload_length != 0U) {
      return write_error(response, response_capacity, response_bytes,
                         request.operation, request.request_id,
                         XAIOS_CONTROL_STATUS_INVALID_REQUEST);
    }
    fill_capabilities(&value);
    return write_response(response, response_capacity, response_bytes,
                          request.operation, request.request_id,
                          XAIOS_CONTROL_STATUS_OK,
                          XAIOS_CONTROL_PAYLOAD_CAPABILITIES, &value,
                          sizeof(value));
  }
  case XAIOS_CONTROL_OP_HARDWARE: {
    xaios_control_hardware_payload_t value;
    if (request.payload_type != XAIOS_CONTROL_PAYLOAD_NONE ||
        request.payload_length != 0U) {
      return write_error(response, response_capacity, response_bytes,
                         request.operation, request.request_id,
                         XAIOS_CONTROL_STATUS_INVALID_REQUEST);
    }
    fill_hardware(&value);
    return write_response(response, response_capacity, response_bytes,
                          request.operation, request.request_id,
                          XAIOS_CONTROL_STATUS_OK,
                          XAIOS_CONTROL_PAYLOAD_HARDWARE, &value,
                          sizeof(value));
  }
  case XAIOS_CONTROL_OP_METRICS: {
    xaios_control_metrics_payload_t value;
    if (request.payload_type != XAIOS_CONTROL_PAYLOAD_NONE ||
        request.payload_length != 0U) {
      return write_error(response, response_capacity, response_bytes,
                         request.operation, request.request_id,
                         XAIOS_CONTROL_STATUS_INVALID_REQUEST);
    }
    fill_metrics(&value);
    return write_response(response, response_capacity, response_bytes,
                          request.operation, request.request_id,
                          XAIOS_CONTROL_STATUS_OK,
                          XAIOS_CONTROL_PAYLOAD_METRICS, &value,
                          sizeof(value));
  }
  case XAIOS_CONTROL_OP_RUNTIME_SNAPSHOT: {
    xaios_control_runtime_snapshot_request_t query;
    xaios_control_runtime_snapshot_payload_t value;
    if (request.payload_type !=
            XAIOS_CONTROL_PAYLOAD_RUNTIME_SNAPSHOT_REQUEST ||
        request.payload_length != sizeof(query)) {
      return write_error(response, response_capacity, response_bytes,
                         request.operation, request.request_id,
                         XAIOS_CONTROL_STATUS_INVALID_REQUEST);
    }
    bytes_copy(&query, payload, sizeof(query));
    if (fill_runtime_snapshot(&query, &value) != XAIOS_OK) {
      return write_error(response, response_capacity, response_bytes,
                         request.operation, request.request_id,
                         XAIOS_CONTROL_STATUS_INVALID_REQUEST);
    }
    return write_response(response, response_capacity, response_bytes,
                          request.operation, request.request_id,
                          XAIOS_CONTROL_STATUS_OK,
                          XAIOS_CONTROL_PAYLOAD_RUNTIME_SNAPSHOT, &value,
                          sizeof(value));
  }
  case XAIOS_CONTROL_OP_LOGS: {
    xaios_control_log_request_payload_t query;
    if (request.payload_type != XAIOS_CONTROL_PAYLOAD_LOG_REQUEST ||
        request.payload_length != sizeof(query)) {
      return write_error(response, response_capacity, response_bytes,
                         request.operation, request.request_id,
                         XAIOS_CONTROL_STATUS_INVALID_REQUEST);
    }
    bytes_copy(&query, payload, sizeof(query));
    if (query.limit > 1000U || query.follow > 1U ||
        query.component[sizeof(query.component) - 1U] != '\0') {
      return write_error(response, response_capacity, response_bytes,
                         request.operation, request.request_id,
                         XAIOS_CONTROL_STATUS_INVALID_REQUEST);
    }
    return handle_logs(&request, &query, response, response_capacity,
                       response_bytes);
  }
  case XAIOS_CONTROL_OP_CONFIG_SHOW:
  case XAIOS_CONTROL_OP_CONFIG_VALIDATE:
  case XAIOS_CONTROL_OP_CONFIG_DIFF:
  case XAIOS_CONTROL_OP_CONFIG_APPLY:
    return handle_config_operation(&request, payload, response,
                                   response_capacity, response_bytes,
                                   authenticated_role);
  case XAIOS_CONTROL_OP_AUTH_KEY_LIST:
  case XAIOS_CONTROL_OP_AUTH_KEY_ADD:
  case XAIOS_CONTROL_OP_AUTH_KEY_REMOVE:
  case XAIOS_CONTROL_OP_AUTH_HOST_KEY_ROTATE:
    return handle_auth_operation(&request, payload, response,
                                 response_capacity, response_bytes,
                                 authenticated_role);
  case XAIOS_CONTROL_OP_AUDIT_SHOW:
    return handle_audit(&request, payload, response, response_capacity,
                        response_bytes);
  case XAIOS_CONTROL_OP_MODEL_VERIFY:
  case XAIOS_CONTROL_OP_MODEL_ACTIVATE:
  case XAIOS_CONTROL_OP_MODEL_REGISTER:
  case XAIOS_CONTROL_OP_MODEL_CLEANUP:
    return handle_model_operation(&request, payload, response,
                                  response_capacity, response_bytes,
                                  authenticated_role);
  case XAIOS_CONTROL_OP_STORAGE_DEVICE_LIST:
  case XAIOS_CONTROL_OP_STORAGE_DEVICE_SHOW:
    return handle_storage_devices(&request, payload, response,
                                  response_capacity, response_bytes);
  case XAIOS_CONTROL_OP_STORAGE_FILESYSTEM_LIST:
  case XAIOS_CONTROL_OP_STORAGE_FILESYSTEM_SHOW:
    return handle_storage_filesystems(&request, payload, response,
                                      response_capacity, response_bytes);
  case XAIOS_CONTROL_OP_STORAGE_PARTITION_LIST:
  case XAIOS_CONTROL_OP_STORAGE_PARTITION_VERIFY:
    return handle_storage_partition_read(&request, payload, response,
                                         response_capacity, response_bytes);
  case XAIOS_CONTROL_OP_STORAGE_PARTITION_PLAN_CREATE:
  case XAIOS_CONTROL_OP_STORAGE_PARTITION_CREATE:
  case XAIOS_CONTROL_OP_STORAGE_PARTITION_PLAN_DELETE:
  case XAIOS_CONTROL_OP_STORAGE_PARTITION_DELETE:
  case XAIOS_CONTROL_OP_STORAGE_PARTITION_PLAN_RESIZE:
  case XAIOS_CONTROL_OP_STORAGE_PARTITION_RESIZE:
  case XAIOS_CONTROL_OP_STORAGE_INSTALL:
    return handle_storage_install(&request, payload, response,
                                  response_capacity, response_bytes,
                                  authenticated_role);
  case XAIOS_CONTROL_OP_STORAGE_PARTITION_REPAIR:
    return handle_storage_partition_operation(
        &request, payload, response, response_capacity, response_bytes,
        authenticated_role);
  case XAIOS_CONTROL_OP_STORAGE_FORMAT_PLAN:
  case XAIOS_CONTROL_OP_STORAGE_FORMAT:
  case XAIOS_CONTROL_OP_STORAGE_MOUNT:
  case XAIOS_CONTROL_OP_STORAGE_UNMOUNT:
  case XAIOS_CONTROL_OP_STORAGE_FSCK:
  case XAIOS_CONTROL_OP_STORAGE_FS_REPAIR:
  case XAIOS_CONTROL_OP_STORAGE_FS_RESIZE_PLAN:
  case XAIOS_CONTROL_OP_STORAGE_FS_RESIZE:
    return handle_storage_volume_operation(
        &request, payload, response, response_capacity, response_bytes,
        authenticated_role);
  case XAIOS_CONTROL_OP_STORAGE_REPAIR_FROM_REPLICA:
    return handle_storage_replica_repair(
        &request, payload, response, response_capacity, response_bytes,
        authenticated_role);
  case XAIOS_CONTROL_OP_STORAGE_SCRUB_START:
  case XAIOS_CONTROL_OP_STORAGE_SCRUB_STATUS:
  case XAIOS_CONTROL_OP_STORAGE_SCRUB_PAUSE:
  case XAIOS_CONTROL_OP_STORAGE_SCRUB_RESUME:
  case XAIOS_CONTROL_OP_STORAGE_SCRUB_CANCEL:
    return handle_storage_scrub_operation(
        &request, payload, response, response_capacity, response_bytes,
        authenticated_role);
  case XAIOS_CONTROL_OP_STORAGE_TRIM_START:
  case XAIOS_CONTROL_OP_STORAGE_TRIM_STATUS:
  case XAIOS_CONTROL_OP_STORAGE_TRIM_CANCEL:
    return handle_storage_trim_operation(
        &request, payload, response, response_capacity, response_bytes,
        authenticated_role);
  case XAIOS_CONTROL_OP_APP_ACTIVATE:
  case XAIOS_CONTROL_OP_APP_REMOVE:
  case XAIOS_CONTROL_OP_APP_ROLLBACK:
  case XAIOS_CONTROL_OP_CATALOG_ACTIVATE:
    return handle_package_operation(&request, payload, response,
                                    response_capacity, response_bytes,
                                    authenticated_role);
  case XAIOS_CONTROL_OP_SYSTEM_UPDATE_BEGIN:
  case XAIOS_CONTROL_OP_SYSTEM_UPDATE_CHUNK:
  case XAIOS_CONTROL_OP_SYSTEM_UPDATE_COMMIT:
  case XAIOS_CONTROL_OP_SYSTEM_UPDATE_ABORT:
    return handle_system_update_operation(
        &request, payload, response, response_capacity, response_bytes,
        authenticated_role);
  default:
    return write_error(response, response_capacity, response_bytes,
                       request.operation, request.request_id,
                       XAIOS_CONTROL_STATUS_UNKNOWN_OPERATION);
  }
}

uint64_t control_protocol_request_count(void) {
  return counter_read(&g_control_requests);
}

uint64_t control_protocol_failure_count(void) {
  return counter_read(&g_control_failures);
}

uint64_t control_protocol_denial_count(void) {
  return counter_read(&g_control_denials);
}

void control_protocol_self_test(void) {
  xaios_control_request_header_t request;
  uint8_t response[XAIOS_CONTROL_MAX_RESPONSE_BYTES];
  uint64_t response_bytes = 0U;
  xaios_control_response_header_t header;

  bytes_zero(&request, sizeof(request));
  request.magic = XAIOS_CONTROL_MAGIC;
  request.version = XAIOS_CONTROL_VERSION;
  request.header_size = sizeof(request);
  request.operation = XAIOS_CONTROL_OP_VERSION;
  request.request_id = UINT64_C(42);
  request.principal_role = XAIOS_CONTROL_ROLE_OBSERVER;
  request.timeout_ms = 1000U;
  kassert(control_protocol_dispatch(
              &request, sizeof(request), response, sizeof(response),
              &response_bytes, XAIOS_CONTROL_ROLE_OBSERVER) == XAIOS_OK);
  bytes_copy(&header, response, sizeof(header));
  kassert(header.status == XAIOS_CONTROL_STATUS_OK);
  kassert(header.request_id == request.request_id);
  kassert(header.payload_type == XAIOS_CONTROL_PAYLOAD_VERSION);

  request.magic = 0U;
  kassert(control_protocol_dispatch(
              &request, sizeof(request), response, sizeof(response),
              &response_bytes, XAIOS_CONTROL_ROLE_OBSERVER) == XAIOS_OK);
  bytes_copy(&header, response, sizeof(header));
  kassert(header.status == XAIOS_CONTROL_STATUS_INVALID_REQUEST);

  request.magic = XAIOS_CONTROL_MAGIC;
  request.version = XAIOS_CONTROL_VERSION + 1U;
  kassert(control_protocol_dispatch(
              &request, sizeof(request), response, sizeof(response),
              &response_bytes, XAIOS_CONTROL_ROLE_OBSERVER) == XAIOS_OK);
  bytes_copy(&header, response, sizeof(header));
  kassert(header.status == XAIOS_CONTROL_STATUS_UNSUPPORTED_VERSION);

  request.version = XAIOS_CONTROL_VERSION;
  request.flags = 1U;
  kassert(control_protocol_dispatch(
              &request, sizeof(request), response, sizeof(response),
              &response_bytes, XAIOS_CONTROL_ROLE_OBSERVER) == XAIOS_OK);
  bytes_copy(&header, response, sizeof(header));
  kassert(header.status == XAIOS_CONTROL_STATUS_INVALID_REQUEST);

  request.flags = 0U;
  kassert(control_protocol_dispatch(
              &request, sizeof(request) - 1U, response, sizeof(response),
              &response_bytes, XAIOS_CONTROL_ROLE_OBSERVER) == XAIOS_OK);
  bytes_copy(&header, response, sizeof(header));
  kassert(header.status == XAIOS_CONTROL_STATUS_INVALID_REQUEST);

  request.payload_length = XAIOS_CONTROL_MAX_REQUEST_BYTES;
  kassert(control_protocol_dispatch(
              &request, sizeof(request), response, sizeof(response),
              &response_bytes, XAIOS_CONTROL_ROLE_OBSERVER) == XAIOS_OK);
  bytes_copy(&header, response, sizeof(header));
  kassert(header.status == XAIOS_CONTROL_STATUS_INVALID_REQUEST);

  request.payload_length = 0U;
  request.principal_role = XAIOS_CONTROL_ROLE_ADMIN;
  kassert(control_protocol_dispatch(
              &request, sizeof(request), response, sizeof(response),
              &response_bytes, XAIOS_CONTROL_ROLE_OBSERVER) == XAIOS_OK);
  bytes_copy(&header, response, sizeof(header));
  kassert(header.status == XAIOS_CONTROL_STATUS_DENIED);

  request.principal_role = XAIOS_CONTROL_ROLE_OBSERVER;
  kassert(control_protocol_dispatch(
              &request, sizeof(request), response, sizeof(response),
              &response_bytes, XAIOS_CONTROL_ROLE_ADMIN) == XAIOS_OK);
  bytes_copy(&header, response, sizeof(header));
  kassert(header.status == XAIOS_CONTROL_STATUS_OK);

  kassert(log_line_sensitive("authorization: Bearer abc", 25U) != 0);
  kassert(log_line_sensitive("network: packet received", 24U) == 0);
  char redacted[160];
  uint64_t redacted_bytes = 0U;
  kassert(append_log_record(redacted, sizeof(redacted), &redacted_bytes, 9U,
                            "auth", "info", "password=hunter2", 16U,
                            1) == XAIOS_OK);
  kassert(!line_contains_case_insensitive(redacted, redacted_bytes,
                                          "hunter2"));
  kassert(line_contains_case_insensitive(redacted, redacted_bytes,
                                         "[redacted]"));
  klog("control: protocol self-test passed version=%u malformed=5 denied=1 "
       "redaction=1\n",
       XAIOS_CONTROL_VERSION);
}
