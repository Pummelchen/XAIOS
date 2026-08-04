#ifndef XAIOS_ADMIN_CONTROL_H
#define XAIOS_ADMIN_CONTROL_H

#include <xaios/status.h>
#include <xaios/types.h>

#define XAIOS_ADMIN_CONFIG_MAGIC UINT32_C(0x58414346)
#define XAIOS_ADMIN_AUTH_MAGIC UINT32_C(0x58414155)
#define XAIOS_ADMIN_AUDIT_MAGIC UINT32_C(0x58414144)
#define XAIOS_ADMIN_SCHEMA_VERSION UINT16_C(1)

#define XAIOS_ADMIN_CONFIG_PATH "/state/control/config.bin"
#define XAIOS_ADMIN_AUTH_PATH "/state/control/authorized.bin"
#define XAIOS_ADMIN_AUDIT_PATH "/state/control/audit.bin"
#define XAIOS_ADMIN_HOST_KEY_PATH "/state/xaios_host_key"

#define XAIOS_ADMIN_MAX_KEYS 16U
#define XAIOS_ADMIN_MAX_REVOKED_KEYS 16U
#define XAIOS_ADMIN_MAX_AUDIT_RECORDS 64U
#define XAIOS_ADMIN_PRINCIPAL_MAX 32U
#define XAIOS_ADMIN_OPERATION_MAX 24U
#define XAIOS_ADMIN_FINGERPRINT_BYTES 32U

#define XAIOS_ADMIN_CONFIG_CHANGE_CONNECTIONS UINT32_C(1)
#define XAIOS_ADMIN_CONFIG_CHANGE_CHANNELS UINT32_C(2)
#define XAIOS_ADMIN_CONFIG_CHANGE_AUTH_ATTEMPTS UINT32_C(4)
#define XAIOS_ADMIN_CONFIG_CHANGE_COMMAND_RATE UINT32_C(8)
#define XAIOS_ADMIN_CONFIG_CHANGE_PASSWORD_AUTH UINT32_C(16)

#define XAIOS_ADMIN_PASSWORD_DISABLED UINT32_C(0)
#define XAIOS_ADMIN_PASSWORD_DEVELOPMENT UINT32_C(1)

typedef enum xaios_admin_result {
  XAIOS_ADMIN_RESULT_OK = 0,
  XAIOS_ADMIN_RESULT_INVALID = 1,
  XAIOS_ADMIN_RESULT_DENIED = 2,
  XAIOS_ADMIN_RESULT_NOT_FOUND = 3,
  XAIOS_ADMIN_RESULT_REPLAY = 4,
  XAIOS_ADMIN_RESULT_CONFLICT = 5,
  XAIOS_ADMIN_RESULT_NO_MEMORY = 6,
  XAIOS_ADMIN_RESULT_IO = 7,
} xaios_admin_result_t;

typedef struct xaios_admin_config {
  uint32_t magic;
  uint16_t version;
  uint16_t size;
  uint64_t generation;
  uint32_t max_connections;
  uint32_t max_channels_per_connection;
  uint32_t max_auth_attempts;
  uint32_t command_rate_per_minute;
  uint32_t password_auth;
  uint32_t reserved;
  uint64_t checksum;
} xaios_admin_config_t;

typedef struct xaios_admin_key_record {
  uint8_t public_key[32];
  uint8_t fingerprint[32];
  char principal[XAIOS_ADMIN_PRINCIPAL_MAX];
  uint32_t role;
  uint32_t reserved;
} xaios_admin_key_record_t;

typedef struct xaios_admin_auth_database {
  uint32_t magic;
  uint16_t version;
  uint16_t header_size;
  uint64_t generation;
  uint32_t key_count;
  uint32_t revoked_count;
  uint64_t checksum;
  xaios_admin_key_record_t keys[XAIOS_ADMIN_MAX_KEYS];
  uint8_t revoked[XAIOS_ADMIN_MAX_REVOKED_KEYS][32];
} xaios_admin_auth_database_t;

typedef struct xaios_admin_key_view {
  uint8_t fingerprint[32];
  char principal[XAIOS_ADMIN_PRINCIPAL_MAX];
  uint32_t role;
  uint32_t reserved;
} xaios_admin_key_view_t;

typedef struct xaios_admin_audit_record {
  uint64_t sequence;
  uint64_t operation_id;
  uint8_t object_hash[32];
  char principal[XAIOS_ADMIN_PRINCIPAL_MAX];
  char operation[XAIOS_ADMIN_OPERATION_MAX];
  uint32_t role;
  uint32_t result;
} xaios_admin_audit_record_t;

typedef struct xaios_admin_audit_log {
  uint32_t magic;
  uint16_t version;
  uint16_t header_size;
  uint32_t record_size;
  uint32_t record_count;
  uint64_t next_sequence;
  uint64_t checksum;
  xaios_admin_audit_record_t records[XAIOS_ADMIN_MAX_AUDIT_RECORDS];
} xaios_admin_audit_log_t;

typedef char xaios_admin_config_must_be_48_bytes[
    sizeof(xaios_admin_config_t) == 48U ? 1 : -1];
typedef char xaios_admin_key_record_must_be_104_bytes[
    sizeof(xaios_admin_key_record_t) == 104U ? 1 : -1];
typedef char xaios_admin_audit_record_must_be_112_bytes[
    sizeof(xaios_admin_audit_record_t) == 112U ? 1 : -1];

void admin_control_init(void);
xaios_admin_result_t admin_control_config_get(xaios_admin_config_t *config);
xaios_admin_result_t admin_control_config_validate(
    const char *path, xaios_admin_config_t *candidate, uint32_t *change_mask);
xaios_admin_result_t admin_control_config_apply(
    const char *path, const char *actor, uint32_t role, uint64_t operation_id,
    xaios_admin_config_t *applied, uint32_t *change_mask);
xaios_admin_result_t admin_control_auth_list(
    xaios_admin_key_view_t *keys, uint32_t capacity, uint32_t *key_count,
    uint32_t *revoked_count, uint64_t *generation);
xaios_admin_result_t admin_control_auth_add(
    const char *path, const char *principal, uint32_t assigned_role,
    const char *actor, uint32_t actor_role, uint64_t operation_id,
    xaios_admin_key_view_t *added);
xaios_admin_result_t admin_control_auth_remove(
    const char *fingerprint, const char *actor, uint32_t actor_role,
    uint64_t operation_id, xaios_admin_key_view_t *removed);
xaios_admin_result_t admin_control_host_key_rotate(
    const char *actor, uint32_t actor_role, uint64_t operation_id);
xaios_admin_result_t admin_control_model_activate(
    const char *package_id, const char *actor, uint32_t actor_role,
    uint64_t operation_id, uint64_t *generation);
xaios_admin_result_t admin_control_mutation_begin(
    const char *actor, uint32_t role, uint32_t required_role,
    uint64_t operation_id, const char *operation);
xaios_admin_result_t admin_control_mutation_complete(
    const char *actor, uint32_t role, uint64_t operation_id,
    const char *operation, const uint8_t object_hash[32]);
xaios_admin_result_t admin_control_mutation_fail(
    const char *actor, uint32_t role, uint64_t operation_id,
    const char *operation, xaios_admin_result_t result);
xaios_admin_result_t admin_control_audit_read(
    uint64_t since_sequence, uint32_t limit,
    xaios_admin_audit_record_t *records, uint32_t capacity,
    uint32_t *record_count, uint64_t *next_sequence,
    uint64_t *latest_sequence);
void admin_control_self_test(void);

#endif
