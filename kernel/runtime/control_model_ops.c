/* Model, package and system-update operations of the control protocol.
 *
 * Split out of control_protocol.c so no source file exceeds 500 lines. The
 * dispatch table, the self-test and the byte/write primitives stay behind.
 * This file also carries the fixed-string and mutation/admin result helpers
 * the model, package and system-update handlers share with control_ops.c and
 * the storage modules, which reach them through control_protocol_internal.h.
 * The bodies below were written against control_protocol.c's file-local helper
 * names; the aliases bind them to the prefixed exports the private header
 * declares.
 */

#include "control_protocol_internal.h"

#include <xaios/admin_control.h>
#include <xaios/app_store.h>
#include <xaios/update.h>
#include <xaios/vfs_xaifs.h>

#define bytes_zero control_protocol_bytes_zero
#define bytes_copy control_protocol_bytes_copy
#define write_response control_protocol_write_response
#define write_error control_protocol_write_error

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

static xaios_admin_result_t model_control_result(xaios_status_t status) {
  if (status == XAIOS_OK) return XAIOS_ADMIN_RESULT_OK;
  if (status == XAIOS_ERR_NOT_FOUND) return XAIOS_ADMIN_RESULT_NOT_FOUND;
  if (status == XAIOS_ERR_BUSY || status == XAIOS_ERR_UNSUPPORTED) {
    return XAIOS_ADMIN_RESULT_CONFLICT;
  }
  if (status == XAIOS_ERR_IO) return XAIOS_ADMIN_RESULT_IO;
  return XAIOS_ADMIN_RESULT_INVALID;
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

xaios_status_t control_protocol_handle_package_operation(
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

xaios_status_t control_protocol_handle_system_update_operation(
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

xaios_status_t control_protocol_handle_model_operation(
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

int control_protocol_fixed_string_valid(const char *text, uint64_t capacity) {
  return fixed_string_valid(text, capacity);
}
int control_protocol_fixed_string_terminated(const char *text,
                                             uint64_t capacity) {
  return fixed_string_terminated(text, capacity);
}

xaios_status_t control_protocol_write_admin_error(
    const xaios_control_request_header_t *request,
    xaios_admin_result_t admin_result, void *response,
    uint64_t response_capacity, uint64_t *response_bytes) {
  return write_admin_error(request, admin_result, response, response_capacity,
                           response_bytes);
}
