/*
 * Declarations shared between xaios_control_client.c and
 * control_request.c.
 *
 * xaios_control_options_t is the parsed command line: parse_options fills
 * it in xaios_control_client.c, and the request builder and the response
 * validator here read it. The struct lives in this header because both
 * translation units need its layout; the parser itself stays beside the
 * command verbs it dispatches on.
 */

#ifndef XAIOS_USERSPACE_LIB_CONTROL_REQUEST_INTERNAL_H
#define XAIOS_USERSPACE_LIB_CONTROL_REQUEST_INTERNAL_H

#include <xaios_control_client.h>

typedef struct xaios_control_options {
  u16 operation;
  u32 json;
  u32 node_id;
  u64 timeout_ms;
  u64 operation_id;
  u64 since_cursor;
  u32 since_set;
  u32 limit;
  u32 follow;
  u32 assigned_role;
  u32 principal_role;
  u32 storage_partition_type;
  u32 dry_run;
  u32 verify_data;
  u32 read_only;
  u32 checksum_data;
  u32 trim_all_free;
  u64 size_bytes;
  u64 chunk_size;
  u64 block_size;
  u64 trim_offset;
  u64 trim_length;
  char component[XAIOS_CONTROL_LOG_COMPONENT_MAX];
  char argument[XAIOS_CONTROL_PATH_MAX];
  char replica[XAIOS_CONTROL_PATH_MAX];
  /* The EFI System Partition an install copies from. Named rather
     than inferred: a machine can have more than one. */
  char install_source[XAIOS_CONTROL_PATH_MAX];
  char replica_package_id[65];
  char storage_name[37];
  char confirmation[37];
  char mount_path[XAIOS_CONTROL_STORAGE_MOUNT_MAX];
  char target_principal[XAIOS_ADMIN_PRINCIPAL_MAX];
  char principal[XAIOS_ADMIN_PRINCIPAL_MAX];
  unsigned char model_uuid[16];
  unsigned char package_id[32];
  unsigned char signer_public_key[32];
  unsigned char signature[64];
  unsigned char source_revision[32];
  char architecture_id[33];
  char target_id[33];
} xaios_control_options_t;

/* Frame one request into request; returns its byte length. */
u64 req_build_request(const xaios_control_options_t *options, u64 request_id,
                      unsigned char *request);

/* Send that request once and report the transport result. */
int req_query_once(const xaios_control_options_t *options, u64 request_id,
                   unsigned char *response, u64 *response_size);

/* Check a reply's framing against the request that produced it. */
int req_validate_response(const unsigned char *response, u64 response_size,
                          u64 request_id, u16 operation,
                          xaios_control_response_header_user_t *header);

/* Follow a logs reply to its deadline, updating options->since_cursor. */
int req_follow_logs(xaios_control_options_t *options, u64 request_id,
                    unsigned char *response, u64 *response_size);

#endif /* XAIOS_USERSPACE_LIB_CONTROL_REQUEST_INTERNAL_H */
