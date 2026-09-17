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

#include "control_protocol_internal.h"

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

/* The split modules share these helpers through the private header. The
   forwarding keeps the file-local names unexported: string_equal in
   particular is already a global symbol in remote_login.c. */

void control_protocol_bytes_zero(void *buffer, uint64_t size) {
  bytes_zero(buffer, size);
}
void control_protocol_bytes_copy(void *dst, const void *src, uint64_t size) {
  bytes_copy(dst, src, size);
}

xaios_status_t control_protocol_write_response(
    void *response, uint64_t response_capacity, uint64_t *response_bytes,
    uint16_t operation, uint64_t request_id, xaios_control_status_t status,
    xaios_control_payload_type_t payload_type, const void *payload,
    uint64_t payload_length) {
  return write_response(response, response_capacity, response_bytes, operation,
                        request_id, status, payload_type, payload,
                        payload_length);
}
xaios_status_t control_protocol_write_error(
    void *response, uint64_t response_capacity, uint64_t *response_bytes,
    uint16_t operation, uint64_t request_id, xaios_control_status_t status) {
  return write_error(response, response_capacity, response_bytes, operation,
                     request_id, status);
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
  case XAIOS_CONTROL_OP_VERSION:
  case XAIOS_CONTROL_OP_STATUS:
  case XAIOS_CONTROL_OP_HEALTH:
  case XAIOS_CONTROL_OP_CAPABILITIES:
  case XAIOS_CONTROL_OP_HARDWARE:
  case XAIOS_CONTROL_OP_METRICS:
    return control_protocol_handle_observability_operation(
        &request, response, response_capacity, response_bytes);
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
    if (control_protocol_fill_runtime_snapshot(&query, &value) != XAIOS_OK) {
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
    return control_protocol_handle_logs(&request, &query, response,
                                        response_capacity, response_bytes);
  }
  case XAIOS_CONTROL_OP_CONFIG_SHOW:
  case XAIOS_CONTROL_OP_CONFIG_VALIDATE:
  case XAIOS_CONTROL_OP_CONFIG_DIFF:
  case XAIOS_CONTROL_OP_CONFIG_APPLY:
    return control_protocol_handle_config_operation(
        &request, payload, response, response_capacity, response_bytes,
        authenticated_role);
  case XAIOS_CONTROL_OP_AUTH_KEY_LIST:
  case XAIOS_CONTROL_OP_AUTH_KEY_ADD:
  case XAIOS_CONTROL_OP_AUTH_KEY_REMOVE:
  case XAIOS_CONTROL_OP_AUTH_HOST_KEY_ROTATE:
    return control_protocol_handle_auth_operation(
        &request, payload, response, response_capacity, response_bytes,
        authenticated_role);
  case XAIOS_CONTROL_OP_AUDIT_SHOW:
    return control_protocol_handle_audit(&request, payload, response,
                                         response_capacity, response_bytes);
  case XAIOS_CONTROL_OP_MODEL_VERIFY:
  case XAIOS_CONTROL_OP_MODEL_ACTIVATE:
  case XAIOS_CONTROL_OP_MODEL_REGISTER:
  case XAIOS_CONTROL_OP_MODEL_CLEANUP:
    return control_protocol_handle_model_operation(
        &request, payload, response, response_capacity, response_bytes,
        authenticated_role);
  case XAIOS_CONTROL_OP_STORAGE_DEVICE_LIST:
  case XAIOS_CONTROL_OP_STORAGE_DEVICE_SHOW:
    return control_protocol_handle_storage_devices(
        &request, payload, response, response_capacity, response_bytes);
  case XAIOS_CONTROL_OP_STORAGE_FILESYSTEM_LIST:
  case XAIOS_CONTROL_OP_STORAGE_FILESYSTEM_SHOW:
    return control_protocol_handle_storage_filesystems(
        &request, payload, response, response_capacity, response_bytes);
  case XAIOS_CONTROL_OP_STORAGE_PARTITION_LIST:
  case XAIOS_CONTROL_OP_STORAGE_PARTITION_VERIFY:
    return control_protocol_handle_storage_partition_read(
        &request, payload, response, response_capacity, response_bytes);
  case XAIOS_CONTROL_OP_STORAGE_PARTITION_PLAN_CREATE:
  case XAIOS_CONTROL_OP_STORAGE_PARTITION_CREATE:
  case XAIOS_CONTROL_OP_STORAGE_PARTITION_PLAN_DELETE:
  case XAIOS_CONTROL_OP_STORAGE_PARTITION_DELETE:
  case XAIOS_CONTROL_OP_STORAGE_PARTITION_PLAN_RESIZE:
  case XAIOS_CONTROL_OP_STORAGE_PARTITION_RESIZE:
  case XAIOS_CONTROL_OP_STORAGE_INSTALL:
    return control_protocol_handle_storage_install(
        &request, payload, response, response_capacity, response_bytes,
        authenticated_role);
  case XAIOS_CONTROL_OP_STORAGE_PARTITION_REPAIR:
    return control_protocol_handle_storage_partition_operation(
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
    return control_protocol_handle_storage_volume_operation(
        &request, payload, response, response_capacity, response_bytes,
        authenticated_role);
  case XAIOS_CONTROL_OP_STORAGE_REPAIR_FROM_REPLICA:
    return control_protocol_handle_storage_replica_repair(
        &request, payload, response, response_capacity, response_bytes,
        authenticated_role);
  case XAIOS_CONTROL_OP_STORAGE_SCRUB_START:
  case XAIOS_CONTROL_OP_STORAGE_SCRUB_STATUS:
  case XAIOS_CONTROL_OP_STORAGE_SCRUB_PAUSE:
  case XAIOS_CONTROL_OP_STORAGE_SCRUB_RESUME:
  case XAIOS_CONTROL_OP_STORAGE_SCRUB_CANCEL:
    return control_protocol_handle_storage_scrub_operation(
        &request, payload, response, response_capacity, response_bytes,
        authenticated_role);
  case XAIOS_CONTROL_OP_STORAGE_TRIM_START:
  case XAIOS_CONTROL_OP_STORAGE_TRIM_STATUS:
  case XAIOS_CONTROL_OP_STORAGE_TRIM_CANCEL:
    return control_protocol_handle_storage_trim_operation(
        &request, payload, response, response_capacity, response_bytes,
        authenticated_role);
  case XAIOS_CONTROL_OP_APP_ACTIVATE:
  case XAIOS_CONTROL_OP_APP_REMOVE:
  case XAIOS_CONTROL_OP_APP_ROLLBACK:
  case XAIOS_CONTROL_OP_CATALOG_ACTIVATE:
    return control_protocol_handle_package_operation(
        &request, payload, response, response_capacity, response_bytes,
        authenticated_role);
  case XAIOS_CONTROL_OP_SYSTEM_UPDATE_BEGIN:
  case XAIOS_CONTROL_OP_SYSTEM_UPDATE_CHUNK:
  case XAIOS_CONTROL_OP_SYSTEM_UPDATE_COMMIT:
  case XAIOS_CONTROL_OP_SYSTEM_UPDATE_ABORT:
    return control_protocol_handle_system_update_operation(
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

  kassert(control_protocol_log_line_sensitive("authorization: Bearer abc",
                                              25U) != 0);
  kassert(control_protocol_log_line_sensitive("network: packet received",
                                              24U) == 0);
  char redacted[160];
  uint64_t redacted_bytes = 0U;
  kassert(control_protocol_append_log_record(
              redacted, sizeof(redacted), &redacted_bytes, 9U, "auth", "info",
              "password=hunter2", 16U, 1) == XAIOS_OK);
  kassert(!control_protocol_line_contains_case_insensitive(
      redacted, redacted_bytes, "hunter2"));
  kassert(control_protocol_line_contains_case_insensitive(
      redacted, redacted_bytes, "[redacted]"));
  klog("control: protocol self-test passed version=%u malformed=5 denied=1 "
       "redaction=1\n",
       XAIOS_CONTROL_VERSION);
}
