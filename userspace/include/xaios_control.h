#ifndef XAIOS_USERSPACE_CONTROL_H
#define XAIOS_USERSPACE_CONTROL_H

#define XAIOS_CONTROL_MAGIC 0x58414350U
/* 2 adds product_version to the version payload; must match the kernel. */
#define XAIOS_CONTROL_VERSION 2U
#define XAIOS_CONTROL_KERNEL_ABI_VERSION 1U
#define XAIOS_CONTROL_MODEL_PACKAGE_VERSION 2U
#define XAIOS_CONTROL_XAI_FS_VERSION 1U
#define XAIOS_CONTROL_MAX_REQUEST_BYTES 512U
#define XAIOS_CONTROL_MAX_RESPONSE_BYTES 8192U
#define XAIOS_CONTROL_LOG_COMPONENT_MAX 32U
#define XAIOS_CONTROL_PATH_MAX 96U
#define XAIOS_CONTROL_STORAGE_MAX_DEVICES 8U
#define XAIOS_CONTROL_STORAGE_MAX_FILESYSTEMS 4U
#define XAIOS_CONTROL_STORAGE_MAX_PARTITIONS 24U
#define XAIOS_CONTROL_STORAGE_MOUNT_MAX 32U
#define XAIOS_CONTROL_STORAGE_FILESYSTEM_MAX 24U
#define XAIOS_CONTROL_UNKNOWN_U64 (~0ULL)

#define XAIOS_ADMIN_CONFIG_MAGIC 0x58414346U
#define XAIOS_ADMIN_AUTH_MAGIC 0x58414155U
#define XAIOS_ADMIN_SCHEMA_VERSION 1U
#define XAIOS_ADMIN_CONFIG_PATH "/state/control/config.bin"
#define XAIOS_ADMIN_AUTH_PATH "/state/control/authorized.bin"
#define XAIOS_ADMIN_MAX_KEYS 16U
#define XAIOS_ADMIN_MAX_REVOKED_KEYS 16U
#define XAIOS_ADMIN_PRINCIPAL_MAX 32U
#define XAIOS_ADMIN_OPERATION_MAX 24U
#define XAIOS_ADMIN_PASSWORD_DISABLED 0U
#define XAIOS_ADMIN_PASSWORD_DEVELOPMENT 1U

/* Every name this header declared it still declares; the operation/payload
   codes, the core payloads and the admin/storage payloads now live in the
   three sub-headers beside this file, included below in the order their
   declarations had here. This file remains the one public include path and
   still defines the ABI literals and the compile-time size assertions, so
   no includer and no reader of this path changes. */
#include "xaios_control_codes.h"

typedef struct xaios_control_request_header_user {
  u32 magic;
  u16 version;
  u16 header_size;
  u16 operation;
  u16 flags;
  u32 payload_type;
  u64 request_id;
  u32 principal_role;
  u32 node_id;
  u64 timeout_ms;
  u64 payload_length;
} xaios_control_request_header_user_t;

typedef struct xaios_control_response_header_user {
  u32 magic;
  u16 version;
  u16 header_size;
  u16 operation;
  u16 flags;
  u32 status;
  u64 request_id;
  u32 payload_type;
  u32 reserved;
  u64 payload_length;
} xaios_control_response_header_user_t;

typedef struct xaios_control_app_request_payload_user {
  char name[32];
} xaios_control_app_request_payload_user_t;

typedef struct xaios_control_system_update_begin_payload_user {
  u64 payload_size;
  u32 generation;
  u32 reserved;
  unsigned char payload_hash[32];
  char signature[320];
} xaios_control_system_update_begin_payload_user_t;

#define XAIOS_CONTROL_SYSTEM_UPDATE_CHUNK_MAX 400U
typedef struct xaios_control_system_update_chunk_payload_user {
  u32 size;
  u32 reserved;
  unsigned char data[XAIOS_CONTROL_SYSTEM_UPDATE_CHUNK_MAX];
} xaios_control_system_update_chunk_payload_user_t;

typedef char xaios_control_request_header_user_must_be_48_bytes[
    sizeof(xaios_control_request_header_user_t) == 48U ? 1 : -1];
typedef char xaios_control_response_header_user_must_be_40_bytes[
    sizeof(xaios_control_response_header_user_t) == 40U ? 1 : -1];

#include "xaios_control_payloads.h"
#include "xaios_control_admin.h"

typedef char xaios_admin_config_user_must_be_48_bytes[
    sizeof(xaios_admin_config_user_t) == 48U ? 1 : -1];
typedef char xaios_admin_key_record_user_must_be_104_bytes[
    sizeof(xaios_admin_key_record_user_t) == 104U ? 1 : -1];
typedef char xaios_admin_audit_record_user_must_be_112_bytes[
    sizeof(xaios_admin_audit_record_user_t) == 112U ? 1 : -1];
typedef char xaios_control_mutation_request_user_must_be_176_bytes[
    sizeof(xaios_control_mutation_request_payload_user_t) == 176U ? 1 : -1];
typedef char xaios_control_storage_device_record_user_must_be_176_bytes[
    sizeof(xaios_control_storage_device_record_user_t) == 176U ? 1 : -1];
typedef char xaios_control_storage_filesystem_record_user_must_be_216_bytes[
    sizeof(xaios_control_storage_filesystem_record_user_t) == 216U ? 1 : -1];
typedef char xaios_control_storage_volume_request_user_must_fit[
    sizeof(xaios_control_storage_volume_request_payload_user_t) <=
            XAIOS_CONTROL_MAX_REQUEST_BYTES -
                sizeof(xaios_control_request_header_user_t)
        ? 1
        : -1];
typedef char xaios_control_storage_replica_repair_request_user_must_fit[
    sizeof(xaios_control_storage_replica_repair_request_payload_user_t) <=
            XAIOS_CONTROL_MAX_REQUEST_BYTES -
                sizeof(xaios_control_request_header_user_t)
        ? 1
        : -1];
typedef char xaios_control_model_register_request_user_must_fit[
    sizeof(xaios_control_model_register_request_payload_user_t) <=
            XAIOS_CONTROL_MAX_REQUEST_BYTES -
                sizeof(xaios_control_request_header_user_t)
        ? 1
        : -1];

#endif
