#ifndef XAIOS_CONTROL_PROTOCOL_H
#define XAIOS_CONTROL_PROTOCOL_H

#include <xaios/admin_control.h>
#include <xaios/xaiboot_fs.h>
#include <xaios/xai_fs_admin.h>
#include <xaios/status.h>
#include <xaios/storage_admin.h>
#include <xaios/types.h>
#include <xaios/vfs_xaifs.h>

#define XAIOS_CONTROL_MAGIC UINT32_C(0x58414350)
/* 2 adds product_version to the version payload. */
#define XAIOS_CONTROL_VERSION UINT16_C(2)
#define XAIOS_CONTROL_KERNEL_ABI_VERSION UINT32_C(1)
#define XAIOS_CONTROL_MODEL_PACKAGE_VERSION UINT32_C(2)
#define XAIOS_CONTROL_XAI_FS_VERSION UINT32_C(1)
#define XAIOS_CONTROL_MAX_REQUEST_BYTES UINT32_C(512)
#define XAIOS_CONTROL_MAX_RESPONSE_BYTES UINT32_C(8192)
#define XAIOS_CONTROL_LOG_COMPONENT_MAX UINT32_C(32)
#define XAIOS_CONTROL_PATH_MAX UINT32_C(96)
#define XAIOS_CONTROL_STORAGE_MAX_DEVICES UINT32_C(8)
#define XAIOS_CONTROL_STORAGE_MAX_FILESYSTEMS UINT32_C(4)
#define XAIOS_CONTROL_STORAGE_MAX_PARTITIONS UINT32_C(24)
#define XAIOS_CONTROL_STORAGE_MOUNT_MAX UINT32_C(32)
#define XAIOS_CONTROL_STORAGE_FILESYSTEM_MAX UINT32_C(24)
#define XAIOS_CONTROL_UNKNOWN_U64 UINT64_MAX

/* Every name this header declared it still declares. The operation, payload
   type, status, role and state codes and the readiness bits now live in
   control_protocol_codes.h, and the request/response payload structs in
   control_protocol_payloads.h. Both are private sub-headers beside this
   file, included below at the position their declarations had here, so the
   declaration order and every wire value are unchanged. This file remains
   the one public include path and still defines the ABI literals and the
   48/40-byte header assertions that qemu-abi-contract.py reads from it. */
#include "control_protocol_codes.h"

typedef struct xaios_control_request_header {
  uint32_t magic;
  uint16_t version;
  uint16_t header_size;
  uint16_t operation;
  uint16_t flags;
  uint32_t payload_type;
  uint64_t request_id;
  uint32_t principal_role;
  uint32_t node_id;
  uint64_t timeout_ms;
  uint64_t payload_length;
} xaios_control_request_header_t;

typedef struct xaios_control_response_header {
  uint32_t magic;
  uint16_t version;
  uint16_t header_size;
  uint16_t operation;
  uint16_t flags;
  uint32_t status;
  uint64_t request_id;
  uint32_t payload_type;
  uint32_t reserved;
  uint64_t payload_length;
} xaios_control_response_header_t;

typedef char xaios_control_request_header_must_be_48_bytes[
    sizeof(xaios_control_request_header_t) == 48U ? 1 : -1];
typedef char xaios_control_response_header_must_be_40_bytes[
    sizeof(xaios_control_response_header_t) == 40U ? 1 : -1];

#include "control_protocol_payloads.h"

typedef char xaios_control_mutation_request_must_be_176_bytes[
    sizeof(xaios_control_mutation_request_payload_t) == 176U ? 1 : -1];
typedef char xaios_control_storage_device_record_must_be_176_bytes[
    sizeof(xaios_control_storage_device_record_t) == 176U ? 1 : -1];
typedef char xaios_control_storage_filesystem_record_must_be_216_bytes[
    sizeof(xaios_control_storage_filesystem_record_t) == 216U ? 1 : -1];
typedef char xaios_control_storage_partition_request_must_fit[
    sizeof(xaios_control_storage_partition_request_payload_t) <=
            XAIOS_CONTROL_MAX_REQUEST_BYTES -
                sizeof(xaios_control_request_header_t)
        ? 1
        : -1];
typedef char xaios_control_storage_volume_request_must_fit[
    sizeof(xaios_control_storage_volume_request_payload_t) <=
            XAIOS_CONTROL_MAX_REQUEST_BYTES -
                sizeof(xaios_control_request_header_t)
        ? 1
        : -1];
typedef char xaios_control_storage_replica_repair_request_must_fit[
    sizeof(xaios_control_storage_replica_repair_request_payload_t) <=
            XAIOS_CONTROL_MAX_REQUEST_BYTES -
                sizeof(xaios_control_request_header_t)
        ? 1
        : -1];
typedef char xaios_control_model_register_request_must_fit[
    sizeof(xaios_control_model_register_request_payload_t) <=
            XAIOS_CONTROL_MAX_REQUEST_BYTES -
                sizeof(xaios_control_request_header_t)
        ? 1
        : -1];

xaios_status_t control_protocol_dispatch(
    const void *request, uint64_t request_bytes, void *response,
    uint64_t response_capacity, uint64_t *response_bytes,
    xaios_control_role_t authenticated_role);
uint64_t control_protocol_request_count(void);
uint64_t control_protocol_failure_count(void);
uint64_t control_protocol_denial_count(void);
void control_protocol_self_test(void);

#endif
