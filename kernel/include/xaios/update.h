#ifndef XAIOS_UPDATE_H
#define XAIOS_UPDATE_H

#include <xaios/status.h>
#include <xaios/types.h>

#define XAIOS_UPDATE_CHUNK_MAX UINT32_C(4096)
#define XAIOS_UPDATE_STAGING_PATH "/update/staging.bin"
#define XAIOS_UPDATE_MANIFEST_PATH "/update/manifest.conf"

#define XAIOS_UPDATE_TARGET_MAX 32U

typedef struct xaios_update_manifest {
  uint32_t version;
  char target[XAIOS_UPDATE_TARGET_MAX];
  uint64_t payload_size;
  uint8_t payload_hash[32];
  uint32_t generation;
} xaios_update_manifest_t;

typedef struct xaios_update_delivery_status {
  uint64_t bytes_received;
  uint64_t bytes_expected;
  uint32_t chunks_written;
  uint32_t hash_verified;
  xaios_status_t last_error;
} xaios_update_delivery_status_t;

typedef struct xaios_update_status {
  uint32_t active;
  uint32_t generation;
  uint32_t state;
  char target[XAIOS_UPDATE_TARGET_MAX];
  xaios_update_delivery_status_t delivery;
} xaios_update_status_t;

void update_runtime_init(void);
xaios_status_t update_begin(uint32_t generation, const char *target,
                           const char *signature);
xaios_status_t update_stage(void);
xaios_status_t update_commit(void);
xaios_status_t update_fail(void);
xaios_status_t update_recover_boot(void);
xaios_status_t update_rollback(void);

xaios_status_t update_stage_chunk(const void *data, uint32_t size);
xaios_status_t update_verify_hash(const uint8_t expected_hash[32]);
xaios_status_t update_parse_manifest(const char *manifest_data, uint32_t size,
                                     xaios_update_manifest_t *out);
xaios_update_delivery_status_t update_delivery_status(void);
xaios_update_status_t update_status_snapshot(void);
void update_delivery_self_test(void);

uint64_t update_transaction_count(void);
uint64_t update_stage_count(void);
uint64_t update_commit_count(void);
uint64_t update_failure_count(void);
uint64_t update_recovery_count(void);
uint64_t update_rollback_count(void);
uint64_t update_boot_fallback_count(void);
uint64_t update_record_persist_count(void);
uint64_t update_rollback_point_count(void);
uint64_t update_reject_count(void);

void update_self_test(void);

#endif
