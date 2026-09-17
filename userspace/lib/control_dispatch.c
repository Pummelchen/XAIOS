/*
 * The control client's reply dispatcher, split out of xaios_control_client.c.
 *
 * It takes a response whose framing and status the caller has already
 * checked and picks the renderer for the operation and payload type. Every
 * branch is a render_ function from control_render_system.c,
 * control_render_storage.c, control_render_ops.c or control_render_config.c;
 * a reply that matches no branch returns -1, which the caller reports as an
 * invalid response.
 */

#include "control_dispatch_internal.h"
#include "xaios_control_internal.h"
#include "control_render_config_internal.h"

int control_dispatch_response(
    const xaios_control_options_t *options,
    const xaios_control_response_header_user_t *header, const void *payload,
    int json, char *output, u64 output_capacity, u64 *offset, u64 request_id) {
  int render_result = -1;
  if (options->operation == XAIOS_CONTROL_OP_VERSION &&
      header->payload_type == XAIOS_CONTROL_PAYLOAD_VERSION &&
      header->payload_length == sizeof(xaios_control_version_payload_user_t)) {
    render_result = render_version(payload, json, output, output_capacity,
                                   offset, request_id);
  } else if (options->operation == XAIOS_CONTROL_OP_STATUS &&
             header->payload_type == XAIOS_CONTROL_PAYLOAD_STATUS &&
             header->payload_length ==
                 sizeof(xaios_control_status_payload_user_t)) {
    render_result = render_status(payload, json, output, output_capacity,
                                  offset, request_id);
  } else if (options->operation == XAIOS_CONTROL_OP_HEALTH &&
             header->payload_type == XAIOS_CONTROL_PAYLOAD_HEALTH &&
             header->payload_length ==
                 sizeof(xaios_control_health_payload_user_t)) {
    render_result = render_health(payload, json, output, output_capacity,
                                  offset, request_id);
  } else if (options->operation == XAIOS_CONTROL_OP_CAPABILITIES &&
             header->payload_type == XAIOS_CONTROL_PAYLOAD_CAPABILITIES &&
             header->payload_length ==
                 sizeof(xaios_control_capabilities_payload_user_t)) {
    render_result = render_capabilities(payload, json, output, output_capacity,
                                        offset, request_id);
  } else if (options->operation == XAIOS_CONTROL_OP_HARDWARE &&
             header->payload_type == XAIOS_CONTROL_PAYLOAD_HARDWARE &&
             header->payload_length ==
                 sizeof(xaios_control_hardware_payload_user_t)) {
    render_result = render_hardware(payload, json, output, output_capacity,
                                    offset, request_id);
  } else if (options->operation == XAIOS_CONTROL_OP_METRICS &&
             header->payload_type == XAIOS_CONTROL_PAYLOAD_METRICS &&
             header->payload_length ==
                 sizeof(xaios_control_metrics_payload_user_t)) {
    render_result = render_metrics(payload, json, output, output_capacity,
                                   offset, request_id);
  } else if (options->operation == XAIOS_CONTROL_OP_LOGS &&
             header->payload_type == XAIOS_CONTROL_PAYLOAD_LOGS) {
    render_result = render_logs(payload, header->payload_length, json, output,
                                output_capacity, offset, request_id);
  } else if ((options->operation == XAIOS_CONTROL_OP_CONFIG_SHOW ||
              options->operation == XAIOS_CONTROL_OP_CONFIG_VALIDATE ||
              options->operation == XAIOS_CONTROL_OP_CONFIG_DIFF ||
              options->operation == XAIOS_CONTROL_OP_CONFIG_APPLY) &&
             header->payload_type == XAIOS_CONTROL_PAYLOAD_CONFIG &&
             header->payload_length ==
                 sizeof(xaios_control_config_payload_user_t)) {
    render_result = cfg_render_config(payload, json, output, output_capacity,
                                  offset, request_id);
  } else if ((options->operation == XAIOS_CONTROL_OP_AUTH_KEY_LIST ||
              options->operation == XAIOS_CONTROL_OP_AUTH_KEY_ADD ||
              options->operation == XAIOS_CONTROL_OP_AUTH_KEY_REMOVE) &&
             header->payload_type == XAIOS_CONTROL_PAYLOAD_AUTH_KEYS) {
    render_result = cfg_render_auth_keys(payload, header->payload_length, json,
                                     output, output_capacity, offset,
                                     request_id);
  } else if ((options->operation == XAIOS_CONTROL_OP_AUTH_HOST_KEY_ROTATE ||
              options->operation == XAIOS_CONTROL_OP_MODEL_VERIFY ||
              options->operation == XAIOS_CONTROL_OP_MODEL_REGISTER ||
              options->operation == XAIOS_CONTROL_OP_MODEL_ACTIVATE) &&
             header->payload_type == XAIOS_CONTROL_PAYLOAD_MUTATION &&
             header->payload_length ==
                 sizeof(xaios_control_mutation_payload_user_t)) {
    render_result = render_mutation(payload, json, output, output_capacity,
                                    offset, request_id);
  } else if (options->operation == XAIOS_CONTROL_OP_MODEL_CLEANUP &&
             header->payload_type ==
                 XAIOS_CONTROL_PAYLOAD_MODEL_CLEANUP_REPORT &&
             header->payload_length ==
                 sizeof(xaios_control_model_cleanup_report_user_t)) {
    render_result = render_model_cleanup(payload, json, output,
                                         output_capacity, offset, request_id);
  } else if (options->operation == XAIOS_CONTROL_OP_AUDIT_SHOW &&
             header->payload_type == XAIOS_CONTROL_PAYLOAD_AUDIT) {
    render_result = cfg_render_audit(payload, header->payload_length, json, output,
                                 output_capacity, offset, request_id);
  } else if ((options->operation == XAIOS_CONTROL_OP_STORAGE_DEVICE_LIST ||
              options->operation == XAIOS_CONTROL_OP_STORAGE_DEVICE_SHOW) &&
             header->payload_type == XAIOS_CONTROL_PAYLOAD_STORAGE_DEVICES) {
    render_result = render_storage_devices(
        payload, header->payload_length, json, output, output_capacity, offset,
        request_id);
  } else if ((options->operation == XAIOS_CONTROL_OP_STORAGE_FILESYSTEM_LIST ||
              options->operation == XAIOS_CONTROL_OP_STORAGE_FILESYSTEM_SHOW) &&
             header->payload_type ==
                 XAIOS_CONTROL_PAYLOAD_STORAGE_FILESYSTEMS) {
    render_result = render_storage_filesystems(
        payload, header->payload_length, json, output, output_capacity, offset,
        request_id);
  } else if ((options->operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_LIST ||
              options->operation ==
                  XAIOS_CONTROL_OP_STORAGE_PARTITION_VERIFY) &&
             header->payload_type ==
                 XAIOS_CONTROL_PAYLOAD_STORAGE_PARTITIONS) {
    render_result = render_storage_partitions(
        payload, header->payload_length, json, output, output_capacity, offset,
        request_id);
  } else if (options->operation == XAIOS_CONTROL_OP_STORAGE_INSTALL &&
             header->payload_type ==
                 XAIOS_CONTROL_PAYLOAD_STORAGE_INSTALL_RESULT) {
    render_result = render_storage_install(payload, header->payload_length,
                                           json, output, output_capacity,
                                           offset, request_id);
  } else if (options->operation >=
                 XAIOS_CONTROL_OP_STORAGE_PARTITION_PLAN_CREATE &&
             options->operation <= XAIOS_CONTROL_OP_STORAGE_PARTITION_REPAIR &&
             header->payload_type ==
                 XAIOS_CONTROL_PAYLOAD_STORAGE_PARTITION_PLAN) {
    render_result = render_storage_partition_plan(
        payload, header->payload_length, json, output, output_capacity, offset,
        request_id);
  } else if (options->operation >= XAIOS_CONTROL_OP_STORAGE_FORMAT_PLAN &&
             options->operation <= XAIOS_CONTROL_OP_STORAGE_FS_RESIZE &&
             header->payload_type ==
                 XAIOS_CONTROL_PAYLOAD_STORAGE_VOLUME_REPORT) {
    render_result = render_storage_volume_report(
        payload, header->payload_length, json, output, output_capacity, offset,
        request_id);
  } else if (options->operation ==
                 XAIOS_CONTROL_OP_STORAGE_REPAIR_FROM_REPLICA &&
             header->payload_type == XAIOS_CONTROL_PAYLOAD_STORAGE_VOLUME_REPORT) {
    render_result = render_storage_volume_report(
        payload, header->payload_length, json, output, output_capacity, offset,
        request_id);
  } else if (options->operation >= XAIOS_CONTROL_OP_STORAGE_SCRUB_START &&
             options->operation <= XAIOS_CONTROL_OP_STORAGE_SCRUB_CANCEL &&
             header->payload_type ==
                 XAIOS_CONTROL_PAYLOAD_STORAGE_SCRUB_REPORT &&
             header->payload_length ==
                 sizeof(xaios_control_storage_scrub_report_user_t)) {
    render_result = render_storage_scrub(payload, json, output,
                                         output_capacity, offset, request_id);
  } else if (options->operation >= XAIOS_CONTROL_OP_STORAGE_TRIM_START &&
             options->operation <= XAIOS_CONTROL_OP_STORAGE_TRIM_CANCEL &&
             header->payload_type == XAIOS_CONTROL_PAYLOAD_STORAGE_TRIM_REPORT &&
             header->payload_length ==
                 sizeof(xaios_control_storage_trim_report_user_t)) {
    render_result = render_storage_trim(payload, json, output, output_capacity,
                                        offset, request_id);
  }
  return render_result;
}
