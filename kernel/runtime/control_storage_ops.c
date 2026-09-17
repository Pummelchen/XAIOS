/* Storage-operation half of the control protocol.
 *
 * Split out of control_protocol.c so no source file exceeds 500 lines. This is
 * the tail of the storage region: the volume and filesystem mutations, replica
 * repair, scrub and trim. The storage queries (devices, filesystems,
 * partitions), the dispatch table and the self-test stay in control_protocol.c.
 *
 * The helpers the moved code calls back into are declared in
 * control_protocol_internal.h and defined in control_protocol.c. The error
 * writers there are what keep the protocol's request, failure and denial
 * counters accurate, so this file never touches those counters itself.
 */

#include "control_protocol_internal.h"

#include <xaios/vfs.h>
#include <xaios/vfs_xaifs.h>

/* The bodies below were written against control_protocol.c's file-local helper
   names. These aliases bind them to the prefixed exports the header declares,
   so the moved code reads exactly as it did in its old home. */
#define bytes_zero control_protocol_bytes_zero
#define bytes_copy control_protocol_bytes_copy
#define string_equal control_protocol_string_equal
#define fixed_string_valid control_protocol_fixed_string_valid
#define fixed_string_terminated control_protocol_fixed_string_terminated
#define storage_control_status control_protocol_storage_status
#define storage_admin_result control_protocol_storage_admin_result
#define write_response control_protocol_write_response
#define write_error control_protocol_write_error
#define write_admin_error control_protocol_write_admin_error

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

xaios_status_t control_protocol_handle_storage_volume_operation(
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

xaios_status_t control_protocol_handle_storage_replica_repair(
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

xaios_status_t control_protocol_handle_storage_scrub_operation(
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

xaios_status_t control_protocol_handle_storage_trim_operation(
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

