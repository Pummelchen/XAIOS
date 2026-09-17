/* Filesystem and partition operations of the control protocol.
 *
 * Split out of control_protocol.c so no source file exceeds 500 lines. The
 * block-device list/show pair stays behind, as do the storage status and
 * result converters, which this file reaches through the private header. The
 * bodies below were written against control_protocol.c's file-local helper
 * names; the aliases bind them to the prefixed exports the private header
 * declares.
 */

#include "control_protocol_internal.h"

#include <xaios/admin_control.h>
#include <xaios/block_device.h>
#include <xaios/install.h>
#include <xaios/storage_admin.h>
#include <xaios/vfs.h>
#include <xaios/vfs_xaifs.h>

#define bytes_zero control_protocol_bytes_zero
#define bytes_copy control_protocol_bytes_copy
#define string_copy control_protocol_string_copy
#define string_equal control_protocol_string_equal
#define write_error control_protocol_write_error
#define write_response control_protocol_write_response
#define fixed_string_valid control_protocol_fixed_string_valid
#define fixed_string_terminated control_protocol_fixed_string_terminated
#define write_admin_error control_protocol_write_admin_error
#define storage_control_status control_protocol_storage_status
#define storage_admin_result control_protocol_storage_admin_result

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

xaios_status_t control_protocol_handle_storage_filesystems(
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

xaios_status_t control_protocol_handle_storage_partition_read(
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
xaios_status_t control_protocol_handle_storage_install(
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

xaios_status_t control_protocol_handle_storage_partition_operation(
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
