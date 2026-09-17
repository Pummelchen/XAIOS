#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/xaiboot_fs.h>
#include <xaios/persistence.h>
#include <xaios/security.h>
#include <xaios/sha256.h>
#include <xaios/syscall.h>
#include <xaios/system_slot.h>
#include <xaios/update.h>

#include "update_internal.h"

xaios_update_transaction_t g_update_transaction;
uint64_t g_update_transactions;
uint64_t g_update_stages;
uint64_t g_update_commits;
uint64_t g_update_failures;
uint64_t g_update_recoveries;
uint64_t g_update_rollbacks;
uint64_t g_update_boot_fallbacks;
uint64_t g_update_records_persisted;
uint64_t g_update_rollback_points;
uint64_t g_update_rejects;

void update_bytes_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0; i < size; ++i) {
    bytes[i] = 0;
  }
}

static uint64_t cstr_len(const char *value) {
  uint64_t len = 0;
  if (value == 0) {
    return 0;
  }
  while (value[len] != '\0') {
    ++len;
  }
  return len;
}

static int token_valid(const char *value, uint64_t max_len) {
  uint64_t len = cstr_len(value);
  if (len == 0 || len >= max_len) {
    return 0;
  }
  for (uint64_t i = 0; i < len; ++i) {
    char ch = value[i];
    if (ch < '!' || ch > '~' || ch == ':' || ch == '*' || ch == '?' ||
        ch == '"' || ch == '<' || ch == '>' || ch == '|') {
      return 0;
    }
  }
  return 1;
}

static int target_valid(const char *target) {
  uint64_t len = cstr_len(target);
  if (!token_valid(target, UPDATE_TARGET_MAX) || len < 2U ||
      target[0] != '/' || target[len - 1U] == '/') {
    return 0;
  }
  for (uint64_t i = 0; i < len; ++i) {
    if (target[i] == '/' && target[i + 1U] == '/') {
      return 0;
    }
    if (target[i] == '.' && target[i + 1U] == '.' &&
        (i == 0 || target[i - 1U] == '/') &&
        (target[i + 2U] == '/' || target[i + 2U] == '\0')) {
      return 0;
    }
  }
  return 1;
}

static int target_equal(const char *left, const char *right) {
  uint64_t index = 0U;
  if (left == 0 || right == 0) return 0;
  while (left[index] != '\0' && right[index] != '\0') {
    if (left[index] != right[index]) return 0;
    ++index;
  }
  return left[index] == right[index];
}

int update_system_target(void) {
  return target_equal(g_update_transaction.target, "/system/xaios");
}

static void reset_transaction(void) { update_bytes_zero(&g_update_transaction, sizeof(g_update_transaction)); }

static void copy_token(char *dst, uint64_t capacity, const char *src) {
  uint64_t i = 0;
  while (i + 1U < capacity && src[i] != '\0') {
    dst[i] = src[i];
    ++i;
  }
  dst[i] = '\0';
}

static const char *state_name(xaios_update_state_t state) {
  switch (state) {
    case XAIOS_UPDATE_IDLE:
      return "idle";
    case XAIOS_UPDATE_PENDING:
      return "pending";
    case XAIOS_UPDATE_STAGED:
      return "staged";
    case XAIOS_UPDATE_COMMITTED:
      return "committed";
    case XAIOS_UPDATE_FAILED:
      return "failed";
    case XAIOS_UPDATE_RECOVERED:
      return "recovered";
    case XAIOS_UPDATE_ROLLED_BACK:
      return "rolled-back";
  }
  return "invalid";
}

xaios_status_t update_persist_state(void) {
  if (xaiboot_fs_record_update_transaction(
          g_update_transaction.generation, state_name(g_update_transaction.state), g_update_transaction.target,
          g_update_transaction.rollback_label) != XAIOS_OK) {
    ++g_update_rejects;
    return XAIOS_ERR_IO;
  }
  ++g_update_records_persisted;
  return XAIOS_OK;
}

void update_runtime_init(void) {
  update_bytes_zero(&g_update_transaction, sizeof(g_update_transaction));
  g_update_transactions = 0;
  g_update_stages = 0;
  g_update_commits = 0;
  g_update_failures = 0;
  g_update_recoveries = 0;
  g_update_rollbacks = 0;
  g_update_boot_fallbacks = 0;
  g_update_records_persisted = 0;
  g_update_rollback_points = 0;
  g_update_rejects = 0;
  g_update_delivery.bytes_received = 0;
  g_update_delivery.bytes_expected = 0;
  g_update_delivery.chunks_written = 0;
  g_update_delivery.hash_verified = 0;
  g_update_delivery.last_error = XAIOS_OK;
  g_update_chunk_staging_active = 0;
  xaiboot_fs_mkdir("/update");
  klog("update: runtime initialized\n");
}

xaios_status_t update_begin(uint32_t generation, const char *target,
                           const char *signature) {
  if (g_update_transaction.active != 0 || generation == 0 ||
      !target_valid(target) ||
      security_authorize_update_signature_for_generation(
          signature, XAIOS_CAP_UPDATE | XAIOS_CAP_ADMIN, generation,
          g_update_transaction.expected_hash) != XAIOS_OK) {
    ++g_update_rejects;
    return XAIOS_ERR_INVALID;
  }

  g_update_transaction.active = 1;
  g_update_transaction.generation = generation;
  g_update_transaction.state = XAIOS_UPDATE_PENDING;
  copy_token(g_update_transaction.target, sizeof(g_update_transaction.target), target);
  copy_token(g_update_transaction.signature, sizeof(g_update_transaction.signature), signature);
  copy_token(g_update_transaction.rollback_label, sizeof(g_update_transaction.rollback_label),
             "update-rp");
  if (persistence_snapshot_create(XAIOS_SNAPSHOT_UPDATE, 0,
                                  g_update_transaction.rollback_label) != XAIOS_OK) {
    reset_transaction();
    ++g_update_rejects;
    return XAIOS_ERR_IO;
  }
  if (update_persist_state() != XAIOS_OK) {
    reset_transaction();
    return XAIOS_ERR_IO;
  }

  ++g_update_transactions;
  ++g_update_rollback_points;
  klog("update: transaction begin generation=%u target=%s rollback=%s\n",
       generation, g_update_transaction.target, g_update_transaction.rollback_label);
  return XAIOS_OK;
}

xaios_status_t update_begin_system(uint32_t generation, uint64_t payload_size,
                                  const uint8_t payload_hash[32],
                                  const char *signature) {
  if (payload_size == 0U || payload_hash == 0 ||
      update_begin(generation, "/system/xaios", signature) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  for (uint32_t i = 0U; i < 32U; ++i) {
    if (g_update_transaction.expected_hash[i] != payload_hash[i]) {
      reset_transaction();
      ++g_update_rejects;
      return XAIOS_ERR_INVALID;
    }
  }
  g_update_delivery.bytes_received = 0U;
  g_update_delivery.bytes_expected = payload_size;
  g_update_delivery.chunks_written = 0U;
  g_update_delivery.hash_verified = 0U;
  g_update_delivery.last_error = XAIOS_OK;
  g_update_chunk_staging_active = 0U;
  return XAIOS_OK;
}

xaios_status_t update_finish_system(void) {
  if (!update_system_target() ||
      update_verify_hash(g_update_transaction.expected_hash) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  return update_commit();
}

xaios_status_t update_abort_delivery(void) {
  if (g_update_transaction.active == 0U) return XAIOS_ERR_INVALID;
  if (update_system_target()) (void)system_slot_cancel_pending();
  g_update_transaction.state = XAIOS_UPDATE_FAILED;
  g_update_delivery.last_error = XAIOS_ERR_INVALID;
  g_update_chunk_staging_active = 0U;
  (void)update_persist_state();
  ++g_update_failures;
  g_update_transaction.active = 0U;
  return XAIOS_OK;
}

xaios_status_t update_stage(void) {
  if (g_update_transaction.active == 0 || g_update_transaction.state != XAIOS_UPDATE_PENDING) {
    ++g_update_rejects;
    return XAIOS_ERR_INVALID;
  }
  g_update_transaction.state = XAIOS_UPDATE_STAGED;
  if (update_persist_state() != XAIOS_OK ||
      xaiboot_fs_commit("update-stage") != XAIOS_OK) {
    ++g_update_rejects;
    return XAIOS_ERR_IO;
  }
  ++g_update_stages;
  klog("update: staged generation=%u target=%s\n", g_update_transaction.generation,
       g_update_transaction.target);
  return XAIOS_OK;
}

xaios_status_t update_commit(void) {
  if (g_update_transaction.active == 0 || g_update_transaction.state != XAIOS_UPDATE_STAGED) {
    ++g_update_rejects;
    return XAIOS_ERR_INVALID;
  }
  if (update_system_target() && system_slot_activate() != XAIOS_OK) {
    ++g_update_rejects;
    return XAIOS_ERR_IO;
  }
  g_update_transaction.state = XAIOS_UPDATE_COMMITTED;
  if (update_persist_state() != XAIOS_OK ||
      xaiboot_fs_commit("update-commit") != XAIOS_OK) {
    ++g_update_rejects;
    return XAIOS_ERR_IO;
  }
  ++g_update_commits;
  klog("update: committed generation=%u target=%s\n", g_update_transaction.generation,
       g_update_transaction.target);
  return XAIOS_OK;
}

xaios_status_t update_fail(void) {
  if (g_update_transaction.active == 0 || g_update_transaction.state != XAIOS_UPDATE_STAGED) {
    ++g_update_rejects;
    return XAIOS_ERR_INVALID;
  }
  g_update_transaction.state = XAIOS_UPDATE_FAILED;
  if (update_system_target()) (void)system_slot_cancel_pending();
  if (update_persist_state() != XAIOS_OK) {
    ++g_update_rejects;
    return XAIOS_ERR_IO;
  }
  ++g_update_failures;
  klog("update: failed generation=%u target=%s\n", g_update_transaction.generation,
       g_update_transaction.target);
  return XAIOS_OK;
}

xaios_status_t update_recover_boot(void) {
  if (g_update_transaction.active == 0 || g_update_transaction.state != XAIOS_UPDATE_FAILED) {
    ++g_update_rejects;
    return XAIOS_ERR_INVALID;
  }
  if (persistence_rollback(XAIOS_SNAPSHOT_UPDATE, 0) != XAIOS_OK ||
      xaiboot_fs_rollback() != XAIOS_OK) {
    ++g_update_rejects;
    return XAIOS_ERR_IO;
  }
  g_update_transaction.state = XAIOS_UPDATE_RECOVERED;
  if (update_persist_state() != XAIOS_OK) {
    ++g_update_rejects;
    return XAIOS_ERR_IO;
  }
  ++g_update_recoveries;
  ++g_update_boot_fallbacks;
  klog("update: boot fallback recovered generation=%u rollback=%s\n",
       g_update_transaction.generation, g_update_transaction.rollback_label);
  g_update_transaction.active = 0;
  return XAIOS_OK;
}

xaios_status_t update_rollback(void) {
  if (g_update_transaction.active == 0 || g_update_transaction.state != XAIOS_UPDATE_COMMITTED ||
      security_authorize_rollback(g_update_transaction.target, 1) != XAIOS_OK) {
    ++g_update_rejects;
    return XAIOS_ERR_INVALID;
  }
  if (update_system_target() && system_slot_cancel_pending() != XAIOS_OK) {
    ++g_update_rejects;
    return XAIOS_ERR_IO;
  }
  if (persistence_rollback(XAIOS_SNAPSHOT_UPDATE, 0) != XAIOS_OK ||
      xaiboot_fs_rollback() != XAIOS_OK) {
    ++g_update_rejects;
    return XAIOS_ERR_IO;
  }
  g_update_transaction.state = XAIOS_UPDATE_ROLLED_BACK;
  if (update_persist_state() != XAIOS_OK) {
    ++g_update_rejects;
    return XAIOS_ERR_IO;
  }
  ++g_update_rollbacks;
  klog("update: rollback complete generation=%u target=%s\n",
       g_update_transaction.generation, g_update_transaction.target);
  g_update_transaction.active = 0;
  return XAIOS_OK;
}

uint64_t update_transaction_count(void) { return g_update_transactions; }
uint64_t update_stage_count(void) { return g_update_stages; }
uint64_t update_commit_count(void) { return g_update_commits; }
uint64_t update_failure_count(void) { return g_update_failures; }
uint64_t update_recovery_count(void) { return g_update_recoveries; }
uint64_t update_rollback_count(void) { return g_update_rollbacks; }
uint64_t update_boot_fallback_count(void) { return g_update_boot_fallbacks; }
uint64_t update_record_persist_count(void) { return g_update_records_persisted; }
uint64_t update_rollback_point_count(void) { return g_update_rollback_points; }
uint64_t update_reject_count(void) { return g_update_rejects; }

xaios_update_status_t update_status_snapshot(void) {
  xaios_update_status_t status;
  update_bytes_zero(&status, sizeof(status));
  status.active = g_update_transaction.active;
  status.generation = g_update_transaction.generation;
  status.state = (uint32_t)g_update_transaction.state;
  copy_token(status.target, sizeof(status.target), g_update_transaction.target);
  status.delivery = g_update_delivery;
  return status;
}

void update_self_test(void) {
  static const char k_sig2[] =
      "xaios-update:v2:gen=2:sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:key=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a:sig=2109de7470806ae4bea29d412e467ff0958f00971825b8303782f10794be21c50ffbe4fa3e26664dd63946c03095c75a72512239cbeb9a462b6a98108468490b";
  static const char k_sig3[] =
      "xaios-update:v2:gen=3:sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:key=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a:sig=28273854fc11ce45725079471d80bba69381ad8167193c60eed0b11267cf548b868dec6f2283ae36ada9bb4f6e092098d700387461a294f10cc40ed3bfaa280a";

  update_runtime_init();
  kassert(update_stage() == XAIOS_ERR_INVALID);
  kassert(update_begin(2, "/", k_sig2) == XAIOS_ERR_INVALID);
  kassert(update_begin(2, "/fixture/xaios", k_sig2) == XAIOS_OK);
  kassert(update_stage() == XAIOS_OK);
  kassert(update_fail() == XAIOS_OK);
  kassert(update_recover_boot() == XAIOS_OK);
  kassert(update_begin(3, "/fixture/xaios", k_sig3) == XAIOS_OK);
  kassert(update_stage() == XAIOS_OK);
  kassert(update_commit() == XAIOS_OK);
  kassert(update_rollback() == XAIOS_OK);

  kassert(g_update_transactions == 2);
  kassert(g_update_stages == 2);
  kassert(g_update_commits == 1);
  kassert(g_update_failures == 1);
  kassert(g_update_recoveries == 1);
  kassert(g_update_rollbacks == 1);
  kassert(g_update_boot_fallbacks == 1);
  kassert(g_update_records_persisted == 8);
  kassert(g_update_rollback_points == 2);
  kassert(g_update_rejects == 2);
  klog("update: self-test passed transactions=%lu staged=%lu committed=%lu failed=%lu recovered=%lu rollbacks=%lu boot_fallbacks=%lu records=%lu rollback_points=%lu rejects=%lu\n",
       g_update_transactions, g_update_stages, g_update_commits, g_update_failures, g_update_recoveries,
       g_update_rollbacks, g_update_boot_fallbacks, g_update_records_persisted,
       g_update_rollback_points, g_update_rejects);
}
