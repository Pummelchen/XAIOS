/* Log, configuration, identity and audit operations of the control protocol.
 *
 * Split out of control_protocol.c so no source file exceeds 500 lines. The
 * dispatch table and the self-test stay behind. The self-test asserts log
 * redaction and formatting through log_line_sensitive, append_log_record and
 * line_contains_case_insensitive, so those helpers (and their private
 * dependencies) stay with it and cross back through
 * control_protocol_internal.h.
 */

#include "control_protocol_internal.h"

#include <xaios/kheap.h>
#include <xaios/klog_ring.h>

/* The bodies below were written against control_protocol.c's file-local
   helper names. These aliases bind them to the prefixed exports the header
   declares, so the moved code reads exactly as it did in its old home. */
#define bytes_zero control_protocol_bytes_zero
#define bytes_copy control_protocol_bytes_copy
#define string_copy control_protocol_string_copy
#define string_equal control_protocol_string_equal
#define fixed_string_valid control_protocol_fixed_string_valid
#define write_response control_protocol_write_response
#define write_error control_protocol_write_error
#define write_admin_error control_protocol_write_admin_error
#define line_contains_case_insensitive \
  control_protocol_line_contains_case_insensitive
#define log_line_sensitive control_protocol_log_line_sensitive
#define append_log_record control_protocol_append_log_record

xaios_status_t control_protocol_handle_config_operation(
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

xaios_status_t control_protocol_handle_auth_operation(
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

xaios_status_t control_protocol_handle_audit(
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

xaios_status_t control_protocol_handle_logs(
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
