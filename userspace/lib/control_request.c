/*
 * The control client's request and response machinery: build one framed
 * request from the parsed command line, send it, check the reply's
 * framing against the request that produced it, and follow a logs reply
 * to its deadline. The option parser stays in xaios_control_client.c
 * because the strings it dispatches on -- "install", "--confirm-device"
 * and "from" -- must remain in that file.
 */

#include "control_request_internal.h"

#include "xaios_control_internal.h"

u64 req_build_request(const xaios_control_options_t *options,
                         u64 request_id, unsigned char *request) {
  xaios_control_request_header_user_t header;
  xaios_memzero(&header, sizeof(header));
  header.magic = XAIOS_CONTROL_MAGIC;
  header.version = XAIOS_CONTROL_VERSION;
  header.header_size = (u16)sizeof(header);
  header.operation = options->operation;
  header.request_id = request_id;
  header.principal_role = options->principal_role;
  header.node_id = options->node_id;
  header.timeout_ms = options->timeout_ms;
  bytes_copy(request, &header, sizeof(header));
  if (options->operation == XAIOS_CONTROL_OP_LOGS) {
    xaios_control_log_request_payload_user_t logs;
    xaios_memzero(&logs, sizeof(logs));
    logs.since_cursor = options->since_cursor;
    logs.limit = options->limit;
    logs.follow = options->follow;
    bytes_copy(logs.component, options->component,
               xaios_strlen(options->component) + 1ULL);
    header.payload_type = XAIOS_CONTROL_PAYLOAD_LOG_REQUEST;
    header.payload_length = sizeof(logs);
    bytes_copy(request, &header, sizeof(header));
    bytes_copy(request + sizeof(header), &logs, sizeof(logs));
    return sizeof(header) + sizeof(logs);
  }
  if (options->operation == XAIOS_CONTROL_OP_CONFIG_VALIDATE ||
      options->operation == XAIOS_CONTROL_OP_CONFIG_DIFF ||
      options->operation == XAIOS_CONTROL_OP_MODEL_VERIFY ||
      options->operation == XAIOS_CONTROL_OP_STORAGE_DEVICE_SHOW ||
      options->operation == XAIOS_CONTROL_OP_STORAGE_FILESYSTEM_SHOW ||
      options->operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_LIST ||
      options->operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_VERIFY) {
    xaios_control_path_request_payload_user_t path;
    xaios_memzero(&path, sizeof(path));
    bytes_copy(path.path, options->argument,
               xaios_strlen(options->argument) + 1ULL);
    header.payload_type = XAIOS_CONTROL_PAYLOAD_PATH_REQUEST;
    header.payload_length = sizeof(path);
    bytes_copy(request, &header, sizeof(header));
    bytes_copy(request + sizeof(header), &path, sizeof(path));
    return sizeof(header) + sizeof(path);
  }
  if (options->operation >=
          XAIOS_CONTROL_OP_STORAGE_PARTITION_PLAN_CREATE &&
      options->operation <= XAIOS_CONTROL_OP_STORAGE_PARTITION_REPAIR) {
    xaios_control_storage_partition_request_payload_user_t storage;
    xaios_memzero(&storage, sizeof(storage));
    bytes_copy(storage.request.target, options->argument,
               xaios_strlen(options->argument) + 1ULL);
    bytes_copy(storage.request.confirmation, options->confirmation,
               xaios_strlen(options->confirmation) + 1ULL);
    bytes_copy(storage.request.name, options->storage_name,
               xaios_strlen(options->storage_name) + 1ULL);
    storage.request.size_bytes = options->size_bytes;
    storage.request.operation_id = options->operation_id;
    storage.request.partition_type = options->storage_partition_type;
    bytes_copy(storage.actor, options->principal,
               xaios_strlen(options->principal) + 1ULL);
    header.payload_type = XAIOS_CONTROL_PAYLOAD_STORAGE_PARTITION_REQUEST;
    header.payload_length = sizeof(storage);
    bytes_copy(request, &header, sizeof(header));
    bytes_copy(request + sizeof(header), &storage, sizeof(storage));
    return sizeof(header) + sizeof(storage);
  }
  if (options->operation >= XAIOS_CONTROL_OP_STORAGE_FORMAT_PLAN &&
      options->operation <= XAIOS_CONTROL_OP_STORAGE_FS_RESIZE) {
    xaios_control_storage_volume_request_payload_user_t storage;
    xaios_memzero(&storage, sizeof(storage));
    bytes_copy(storage.target, options->argument,
               xaios_strlen(options->argument) + 1ULL);
    bytes_copy(storage.confirmation, options->confirmation,
               xaios_strlen(options->confirmation) + 1ULL);
    bytes_copy(storage.mount_path, options->mount_path,
               xaios_strlen(options->mount_path) + 1ULL);
    bytes_copy(storage.actor, options->principal,
               xaios_strlen(options->principal) + 1ULL);
    storage.size_bytes = options->size_bytes;
    storage.chunk_size = options->chunk_size;
    storage.operation_id = options->operation_id;
    storage.verify_data = options->verify_data;
    storage.read_only = options->read_only;
    header.payload_type = XAIOS_CONTROL_PAYLOAD_STORAGE_VOLUME_REQUEST;
    header.payload_length = sizeof(storage);
    bytes_copy(request, &header, sizeof(header));
    bytes_copy(request + sizeof(header), &storage, sizeof(storage));
    return sizeof(header) + sizeof(storage);
  }
  if (options->operation == XAIOS_CONTROL_OP_STORAGE_INSTALL) {
    xaios_control_storage_install_request_payload_user_t install;
    xaios_memzero(&install, sizeof(install));
    bytes_copy(install.request.target, options->argument,
               xaios_strlen(options->argument) + 1ULL);
    bytes_copy(install.request.source, options->install_source,
               xaios_strlen(options->install_source) + 1ULL);
    bytes_copy(install.request.confirmation, options->confirmation,
               xaios_strlen(options->confirmation) + 1ULL);
    bytes_copy(install.actor, options->principal,
               xaios_strlen(options->principal) + 1ULL);
    install.request.operation_id = options->operation_id;
    header.payload_type = XAIOS_CONTROL_PAYLOAD_STORAGE_INSTALL_REQUEST;
    header.payload_length = sizeof(install);
    bytes_copy(request, &header, sizeof(header));
    bytes_copy(request + sizeof(header), &install, sizeof(install));
    return sizeof(header) + sizeof(install);
  }
  if (options->operation == XAIOS_CONTROL_OP_STORAGE_REPAIR_FROM_REPLICA) {
    xaios_control_storage_replica_repair_request_payload_user_t repair;
    xaios_memzero(&repair, sizeof(repair));
    bytes_copy(repair.target, options->argument,
               xaios_strlen(options->argument) + 1ULL);
    bytes_copy(repair.replica, options->replica,
               xaios_strlen(options->replica) + 1ULL);
    bytes_copy(repair.confirmation, options->confirmation,
               xaios_strlen(options->confirmation) + 1ULL);
    bytes_copy(repair.package_id, options->replica_package_id,
               xaios_strlen(options->replica_package_id) + 1ULL);
    bytes_copy(repair.actor, options->principal,
               xaios_strlen(options->principal) + 1ULL);
    repair.operation_id = options->operation_id;
    header.payload_type = XAIOS_CONTROL_PAYLOAD_STORAGE_REPLICA_REPAIR_REQUEST;
    header.payload_length = sizeof(repair);
    bytes_copy(request, &header, sizeof(header));
    bytes_copy(request + sizeof(header), &repair, sizeof(repair));
    return sizeof(header) + sizeof(repair);
  }
  if (options->operation == XAIOS_CONTROL_OP_MODEL_REGISTER) {
    xaios_control_model_register_request_payload_user_t registration;
    xaios_memzero(&registration, sizeof(registration));
    registration.operation_id = options->operation_id;
    registration.logical_size = options->size_bytes;
    bytes_copy(registration.model_uuid, options->model_uuid,
               sizeof(registration.model_uuid));
    bytes_copy(registration.package_id, options->package_id,
               sizeof(registration.package_id));
    bytes_copy(registration.signer_public_key, options->signer_public_key,
               sizeof(registration.signer_public_key));
    bytes_copy(registration.signature, options->signature,
               sizeof(registration.signature));
    bytes_copy(registration.source_revision, options->source_revision,
               sizeof(registration.source_revision));
    bytes_copy(registration.architecture_id, options->architecture_id,
               xaios_strlen(options->architecture_id) + 1ULL);
    bytes_copy(registration.target_id, options->target_id,
               xaios_strlen(options->target_id) + 1ULL);
    bytes_copy(registration.actor, options->principal,
               xaios_strlen(options->principal) + 1ULL);
    header.payload_type = XAIOS_CONTROL_PAYLOAD_MODEL_REGISTER_REQUEST;
    header.payload_length = sizeof(registration);
    bytes_copy(request, &header, sizeof(header));
    bytes_copy(request + sizeof(header), &registration, sizeof(registration));
    return sizeof(header) + sizeof(registration);
  }
  if (options->operation >= XAIOS_CONTROL_OP_STORAGE_SCRUB_START &&
      options->operation <= XAIOS_CONTROL_OP_STORAGE_SCRUB_CANCEL) {
    xaios_control_storage_volume_request_payload_user_t storage;
    xaios_memzero(&storage, sizeof(storage));
    bytes_copy(storage.target, options->argument,
               xaios_strlen(options->argument) + 1ULL);
    bytes_copy(storage.actor, options->principal,
               xaios_strlen(options->principal) + 1ULL);
    storage.operation_id = options->operation_id;
    header.payload_type = XAIOS_CONTROL_PAYLOAD_STORAGE_VOLUME_REQUEST;
    header.payload_length = sizeof(storage);
    bytes_copy(request, &header, sizeof(header));
    bytes_copy(request + sizeof(header), &storage, sizeof(storage));
    return sizeof(header) + sizeof(storage);
  }
  if (options->operation >= XAIOS_CONTROL_OP_STORAGE_TRIM_START &&
      options->operation <= XAIOS_CONTROL_OP_STORAGE_TRIM_CANCEL) {
    xaios_control_storage_trim_request_payload_user_t trim;
    xaios_memzero(&trim, sizeof(trim));
    bytes_copy(trim.target, options->argument,
               xaios_strlen(options->argument) + 1ULL);
    bytes_copy(trim.actor, options->principal,
               xaios_strlen(options->principal) + 1ULL);
    trim.offset = options->trim_offset;
    trim.length = options->trim_length;
    trim.operation_id = options->operation_id;
    trim.dry_run = options->dry_run;
    trim.all_free = options->trim_all_free;
    header.payload_type = XAIOS_CONTROL_PAYLOAD_STORAGE_TRIM_REQUEST;
    header.payload_length = sizeof(trim);
    bytes_copy(request, &header, sizeof(header));
    bytes_copy(request + sizeof(header), &trim, sizeof(trim));
    return sizeof(header) + sizeof(trim);
  }
  if (options->operation == XAIOS_CONTROL_OP_AUDIT_SHOW) {
    xaios_control_audit_request_payload_user_t audit;
    xaios_memzero(&audit, sizeof(audit));
    audit.since_sequence = options->since_cursor;
    audit.limit = options->limit;
    header.payload_type = XAIOS_CONTROL_PAYLOAD_AUDIT_REQUEST;
    header.payload_length = sizeof(audit);
    bytes_copy(request, &header, sizeof(header));
    bytes_copy(request + sizeof(header), &audit, sizeof(audit));
    return sizeof(header) + sizeof(audit);
  }
  if (options->operation == XAIOS_CONTROL_OP_CONFIG_APPLY ||
      options->operation == XAIOS_CONTROL_OP_AUTH_KEY_ADD ||
      options->operation == XAIOS_CONTROL_OP_AUTH_KEY_REMOVE ||
      options->operation == XAIOS_CONTROL_OP_AUTH_HOST_KEY_ROTATE ||
      options->operation == XAIOS_CONTROL_OP_MODEL_ACTIVATE ||
      options->operation == XAIOS_CONTROL_OP_MODEL_CLEANUP) {
    xaios_control_mutation_request_payload_user_t mutation;
    xaios_memzero(&mutation, sizeof(mutation));
    mutation.operation_id = options->operation_id;
    mutation.assigned_role = options->assigned_role;
    bytes_copy(mutation.actor, options->principal,
               xaios_strlen(options->principal) + 1ULL);
    if (options->argument[0] != '\0') {
      bytes_copy(mutation.argument, options->argument,
                 xaios_strlen(options->argument) + 1ULL);
    }
    if (options->target_principal[0] != '\0') {
      bytes_copy(mutation.target_principal, options->target_principal,
                 xaios_strlen(options->target_principal) + 1ULL);
    }
    header.payload_type = XAIOS_CONTROL_PAYLOAD_MUTATION_REQUEST;
    header.payload_length = sizeof(mutation);
    bytes_copy(request, &header, sizeof(header));
    bytes_copy(request + sizeof(header), &mutation, sizeof(mutation));
    return sizeof(header) + sizeof(mutation);
  }
  return sizeof(header);
}

int req_query_once(const xaios_control_options_t *options, u64 request_id,
                      unsigned char *response, u64 *response_size) {
  unsigned char request[XAIOS_CONTROL_MAX_REQUEST_BYTES];
  u64 request_size = req_build_request(options, request_id, request);
  return xaios_control_query(request, request_size, response,
                             XAIOS_CONTROL_MAX_RESPONSE_BYTES, response_size);
}

int req_validate_response(const unsigned char *response, u64 response_size,
                             u64 request_id, u16 operation,
                             xaios_control_response_header_user_t *header) {
  if (response_size < sizeof(*header)) {
    return -1;
  }
  bytes_copy(header, response, sizeof(*header));
  if (header->magic != XAIOS_CONTROL_MAGIC ||
      header->version != XAIOS_CONTROL_VERSION ||
      header->header_size != sizeof(*header) ||
      header->operation != operation || header->flags != 0U ||
      header->request_id != request_id ||
      header->payload_length > response_size - sizeof(*header) ||
      response_size != sizeof(*header) + header->payload_length) {
    return -1;
  }
  return 0;
}

int req_follow_logs(xaios_control_options_t *options, u64 request_id,
                       unsigned char *response, u64 *response_size) {
  xaios_control_response_header_user_t header;
  xaios_control_logs_payload_user_t logs;
  if (req_validate_response(response, *response_size, request_id,
                        options->operation, &header) != 0 ||
      header.status != XAIOS_CONTROL_STATUS_OK ||
      header.payload_type != XAIOS_CONTROL_PAYLOAD_LOGS ||
      header.payload_length < sizeof(logs)) {
    return 0;
  }
  bytes_copy(&logs, response + sizeof(header), sizeof(logs));
  if (options->since_set == 0U) {
    options->since_cursor = logs.latest_cursor;
    options->since_set = 1U;
    logs.record_count = 0U;
  } else if (logs.record_count != 0U) {
    return 0;
  }
  u64 started = xaios_clock_nanos();
  u64 duration_ns = options->timeout_ms * 1000000ULL;
  u64 deadline = started + duration_ns;
  if (deadline < started) deadline = ~0ULL;
  while (xaios_clock_nanos() < deadline) {
    if (req_query_once(options, request_id, response, response_size) != 0 ||
        req_validate_response(response, *response_size, request_id,
                          options->operation, &header) != 0 ||
        header.status != XAIOS_CONTROL_STATUS_OK ||
        header.payload_type != XAIOS_CONTROL_PAYLOAD_LOGS ||
        header.payload_length < sizeof(logs)) {
      return -1;
    }
    bytes_copy(&logs, response + sizeof(header), sizeof(logs));
    if (logs.record_count != 0U) {
      return 0;
    }
    options->since_cursor = logs.next_cursor;
  }
  logs.timed_out = 1U;
  bytes_copy(response + sizeof(header), &logs, sizeof(logs));
  return 0;
}
