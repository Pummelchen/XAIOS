/* Private declarations shared by the update translation units.
 *
 * kernel/runtime/update.c keeps the update entry points, the transaction state
 * machine, the rollback points and the boot-fallback path.
 * kernel/runtime/update_delivery.c owns the chunked delivery path, the running
 * SHA-256 and system-slot writes, the manifest reader, the delivery status
 * accessor and the delivery self-test.
 *
 * The transaction state and its counters are defined exactly once, in
 * update.c; the delivery state is defined exactly once, in update_delivery.c.
 * Only the names below cross a translation unit, so they carry the update_
 * module prefix. Nothing declared here is public kernel API. */
#ifndef XAIOS_KERNEL_RUNTIME_UPDATE_INTERNAL_H
#define XAIOS_KERNEL_RUNTIME_UPDATE_INTERNAL_H

#include <xaios/sha256.h>
#include <xaios/status.h>
#include <xaios/system_slot.h>
#include <xaios/types.h>
#include <xaios/update.h>

#define UPDATE_TARGET_MAX 32U
#define UPDATE_LABEL_MAX 32U

typedef enum xaios_update_state {
  XAIOS_UPDATE_IDLE = 0,
  XAIOS_UPDATE_PENDING = 1,
  XAIOS_UPDATE_STAGED = 2,
  XAIOS_UPDATE_COMMITTED = 3,
  XAIOS_UPDATE_FAILED = 4,
  XAIOS_UPDATE_RECOVERED = 5,
  XAIOS_UPDATE_ROLLED_BACK = 6,
} xaios_update_state_t;

typedef struct xaios_update_transaction {
  uint32_t active;
  uint32_t generation;
  xaios_update_state_t state;
  char target[UPDATE_TARGET_MAX];
  char rollback_label[UPDATE_LABEL_MAX];
  uint8_t expected_hash[32];
  char signature[XAIOS_SYSTEM_SIGNATURE_MAX];
} xaios_update_transaction_t;

/* Transaction state and counters, defined in update.c. */
extern xaios_update_transaction_t g_update_transaction;
extern uint64_t g_update_transactions;
extern uint64_t g_update_stages;
extern uint64_t g_update_commits;
extern uint64_t g_update_failures;
extern uint64_t g_update_recoveries;
extern uint64_t g_update_rollbacks;
extern uint64_t g_update_boot_fallbacks;
extern uint64_t g_update_records_persisted;
extern uint64_t g_update_rollback_points;
extern uint64_t g_update_rejects;

/* Chunked-delivery state, defined in update_delivery.c. */
extern xaios_update_delivery_status_t g_update_delivery;
extern xaios_sha256_ctx_t g_update_chunk_hash_ctx;
extern uint32_t g_update_chunk_staging_active;

/* Shared helpers, defined once in update.c. */
void update_bytes_zero(void *buffer, uint64_t size);
int update_system_target(void);
xaios_status_t update_persist_state(void);

#endif
