/* Private interface for the storage half of the control protocol.
 *
 * control_protocol.c was split so no source file exceeds 500 lines. The
 * helpers below stay in control_protocol.c because the dispatch table and the
 * self-test do. They are exported under a control_protocol_ prefix because
 * generic names such as string_equal already exist as global symbols
 * elsewhere in the kernel (remote_login.c), and a bare name here would
 * collide at link time.
 */
#ifndef XAIOS_RUNTIME_CONTROL_PROTOCOL_INTERNAL_H
#define XAIOS_RUNTIME_CONTROL_PROTOCOL_INTERNAL_H

#include <xaios/control_protocol.h>

/* Shared helpers, defined in control_protocol.c. */
void control_protocol_bytes_zero(void *buffer, uint64_t size);
void control_protocol_bytes_copy(void *dst, const void *src, uint64_t size);
int control_protocol_string_equal(const char *lhs, const char *rhs);
int control_protocol_fixed_string_valid(const char *text, uint64_t capacity);
int control_protocol_fixed_string_terminated(const char *text,
                                             uint64_t capacity);
xaios_control_status_t control_protocol_storage_status(xaios_status_t status);
xaios_admin_result_t control_protocol_storage_admin_result(
    xaios_status_t status);
xaios_status_t control_protocol_write_response(
    void *response, uint64_t response_capacity, uint64_t *response_bytes,
    uint16_t operation, uint64_t request_id, xaios_control_status_t status,
    xaios_control_payload_type_t payload_type, const void *payload,
    uint64_t payload_length);
xaios_status_t control_protocol_write_error(
    void *response, uint64_t response_capacity, uint64_t *response_bytes,
    uint16_t operation, uint64_t request_id, xaios_control_status_t status);
xaios_status_t control_protocol_write_admin_error(
    const xaios_control_request_header_t *request,
    xaios_admin_result_t admin_result, void *response,
    uint64_t response_capacity, uint64_t *response_bytes);

/* Storage-operation handlers, defined in control_storage_ops.c. */
xaios_status_t control_protocol_handle_storage_volume_operation(
    const xaios_control_request_header_t *request, const uint8_t *payload,
    void *response, uint64_t response_capacity, uint64_t *response_bytes,
    xaios_control_role_t authenticated_role);
xaios_status_t control_protocol_handle_storage_replica_repair(
    const xaios_control_request_header_t *request, const uint8_t *payload,
    void *response, uint64_t response_capacity, uint64_t *response_bytes,
    xaios_control_role_t authenticated_role);
xaios_status_t control_protocol_handle_storage_scrub_operation(
    const xaios_control_request_header_t *request, const uint8_t *payload,
    void *response, uint64_t response_capacity, uint64_t *response_bytes,
    xaios_control_role_t authenticated_role);
xaios_status_t control_protocol_handle_storage_trim_operation(
    const xaios_control_request_header_t *request, const uint8_t *payload,
    void *response, uint64_t response_capacity, uint64_t *response_bytes,
    xaios_control_role_t authenticated_role);

#endif /* XAIOS_RUNTIME_CONTROL_PROTOCOL_INTERNAL_H */
