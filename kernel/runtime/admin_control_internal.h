/* Private interface shared by the split modules of the admin control plane.
 *
 * admin_control.c was split so no source file exceeds 500 lines. The byte and
 * string primitives and the audit/mutation transaction framework stay in
 * admin_control.c; the configuration subsystem (with the host-key identity
 * gate and the active-configuration state) lives in admin_control_config.c;
 * the authentication key database lives in admin_control_auth.c. Everything
 * that crosses a file boundary is declared here under a xaios_admin_ prefix,
 * because generic names such as string_equal already exist as global symbols
 * elsewhere in the kernel (remote_login.c) and a bare name would collide at
 * link time.
 */
#ifndef XAIOS_RUNTIME_ADMIN_CONTROL_INTERNAL_H
#define XAIOS_RUNTIME_ADMIN_CONTROL_INTERNAL_H

#include <xaios/admin_control.h>

/* Role and buffer limits the modules must agree on. */
#define XAIOS_ADMIN_ROLE_OBSERVER UINT32_C(1)
#define XAIOS_ADMIN_ROLE_OPERATOR UINT32_C(2)
#define XAIOS_ADMIN_ROLE_ADMIN UINT32_C(3)
#define XAIOS_ADMIN_SOURCE_BYTES UINT64_C(2048)

/* Byte and string primitives, defined once in admin_control.c. */
void xaios_admin_bytes_zero(void *buffer, uint64_t size);
void xaios_admin_bytes_copy(void *dst, const void *src, uint64_t size);
int xaios_admin_bytes_equal(const void *left, const void *right, uint64_t size);
uint64_t xaios_admin_string_length(const char *text);
int xaios_admin_string_equal(const char *left, const char *right);
int xaios_admin_string_equal_range(const char *text, uint64_t length,
                                   const char *expected);
void xaios_admin_string_copy(char *dst, uint64_t capacity, const char *src);
uint64_t xaios_admin_fnv1a64(const void *data, uint64_t size);

/* Transaction framework, defined once in admin_control.c. */
xaios_admin_result_t xaios_admin_mutation_begin(
    const char *actor, uint32_t role, uint32_t required_role,
    uint64_t operation_id, const char *operation);
xaios_admin_result_t xaios_admin_mutation_finish(
    const char *actor, uint32_t role, uint64_t operation_id,
    const char *operation, const uint8_t object_hash[32]);
xaios_admin_result_t xaios_admin_mutation_abort_and_audit(
    const char *actor, uint32_t role, uint64_t operation_id,
    const char *operation, xaios_admin_result_t result);
xaios_admin_result_t xaios_admin_audit_only(
    const char *actor, uint32_t role, uint64_t operation_id,
    const char *operation, xaios_admin_result_t result);

/* Configuration and identity, defined in admin_control_config.c. */
int xaios_admin_principal_valid(const char *principal);
int xaios_admin_staging_path_valid(const char *path);
int xaios_admin_config_valid(const xaios_admin_config_t *config);
int xaios_admin_parse_config_text(const char *text, uint64_t size,
                                  xaios_admin_config_t *candidate);
xaios_admin_result_t xaios_admin_host_key_entropy_gate(void);
uint32_t xaios_admin_control_initialized(void);

#endif /* XAIOS_RUNTIME_ADMIN_CONTROL_INTERNAL_H */
