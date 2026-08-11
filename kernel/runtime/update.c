#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/mutable_fs.h>
#include <xaios/persistence.h>
#include <xaios/security.h>
#include <xaios/sha256.h>
#include <xaios/syscall.h>
#include <xaios/system_slot.h>
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

static xaios_update_transaction_t g_update;
static uint64_t g_transactions;
static uint64_t g_stages;
static uint64_t g_commits;
static uint64_t g_failures;
static uint64_t g_recoveries;
static uint64_t g_rollbacks;
static uint64_t g_boot_fallbacks;
static uint64_t g_records_persisted;
static uint64_t g_rollback_points;
static uint64_t g_rejects;

/* Delivery tracking */
static xaios_update_delivery_status_t g_delivery;
static xaios_sha256_ctx_t g_chunk_hash_ctx;
static uint32_t g_chunk_staging_active;

static void bytes_zero(void *buffer, uint64_t size) {
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

static int system_target(void) {
  return target_equal(g_update.target, "/system/xaios");
}

static void reset_transaction(void) { bytes_zero(&g_update, sizeof(g_update)); }

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

static xaios_status_t persist_update_state(void) {
  if (mutable_fs_record_update_transaction(
          g_update.generation, state_name(g_update.state), g_update.target,
          g_update.rollback_label) != XAIOS_OK) {
    ++g_rejects;
    return XAIOS_ERR_IO;
  }
  ++g_records_persisted;
  return XAIOS_OK;
}

void update_runtime_init(void) {
  bytes_zero(&g_update, sizeof(g_update));
  g_transactions = 0;
  g_stages = 0;
  g_commits = 0;
  g_failures = 0;
  g_recoveries = 0;
  g_rollbacks = 0;
  g_boot_fallbacks = 0;
  g_records_persisted = 0;
  g_rollback_points = 0;
  g_rejects = 0;
  g_delivery.bytes_received = 0;
  g_delivery.bytes_expected = 0;
  g_delivery.chunks_written = 0;
  g_delivery.hash_verified = 0;
  g_delivery.last_error = XAIOS_OK;
  g_chunk_staging_active = 0;
  mutable_fs_mkdir("/update");
  klog("update: runtime initialized\n");
}

xaios_status_t update_begin(uint32_t generation, const char *target,
                           const char *signature) {
  if (g_update.active != 0 || generation == 0 ||
      !target_valid(target) ||
      security_authorize_update_signature_for_generation(
          signature, XAIOS_CAP_UPDATE | XAIOS_CAP_ADMIN, generation,
          g_update.expected_hash) != XAIOS_OK) {
    ++g_rejects;
    return XAIOS_ERR_INVALID;
  }

  g_update.active = 1;
  g_update.generation = generation;
  g_update.state = XAIOS_UPDATE_PENDING;
  copy_token(g_update.target, sizeof(g_update.target), target);
  copy_token(g_update.signature, sizeof(g_update.signature), signature);
  copy_token(g_update.rollback_label, sizeof(g_update.rollback_label),
             "update-rp");
  if (persistence_snapshot_create(XAIOS_SNAPSHOT_UPDATE, 0,
                                  g_update.rollback_label) != XAIOS_OK) {
    reset_transaction();
    ++g_rejects;
    return XAIOS_ERR_IO;
  }
  if (persist_update_state() != XAIOS_OK) {
    reset_transaction();
    return XAIOS_ERR_IO;
  }

  ++g_transactions;
  ++g_rollback_points;
  klog("update: transaction begin generation=%u target=%s rollback=%s\n",
       generation, g_update.target, g_update.rollback_label);
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
    if (g_update.expected_hash[i] != payload_hash[i]) {
      reset_transaction();
      ++g_rejects;
      return XAIOS_ERR_INVALID;
    }
  }
  g_delivery.bytes_received = 0U;
  g_delivery.bytes_expected = payload_size;
  g_delivery.chunks_written = 0U;
  g_delivery.hash_verified = 0U;
  g_delivery.last_error = XAIOS_OK;
  g_chunk_staging_active = 0U;
  return XAIOS_OK;
}

xaios_status_t update_finish_system(void) {
  if (!system_target() ||
      update_verify_hash(g_update.expected_hash) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  return update_commit();
}

xaios_status_t update_abort_delivery(void) {
  if (g_update.active == 0U) return XAIOS_ERR_INVALID;
  if (system_target()) (void)system_slot_cancel_pending();
  g_update.state = XAIOS_UPDATE_FAILED;
  g_delivery.last_error = XAIOS_ERR_INVALID;
  g_chunk_staging_active = 0U;
  (void)persist_update_state();
  ++g_failures;
  g_update.active = 0U;
  return XAIOS_OK;
}

xaios_status_t update_stage(void) {
  if (g_update.active == 0 || g_update.state != XAIOS_UPDATE_PENDING) {
    ++g_rejects;
    return XAIOS_ERR_INVALID;
  }
  g_update.state = XAIOS_UPDATE_STAGED;
  if (persist_update_state() != XAIOS_OK ||
      mutable_fs_commit("update-stage") != XAIOS_OK) {
    ++g_rejects;
    return XAIOS_ERR_IO;
  }
  ++g_stages;
  klog("update: staged generation=%u target=%s\n", g_update.generation,
       g_update.target);
  return XAIOS_OK;
}

xaios_status_t update_commit(void) {
  if (g_update.active == 0 || g_update.state != XAIOS_UPDATE_STAGED) {
    ++g_rejects;
    return XAIOS_ERR_INVALID;
  }
  if (system_target() && system_slot_activate() != XAIOS_OK) {
    ++g_rejects;
    return XAIOS_ERR_IO;
  }
  g_update.state = XAIOS_UPDATE_COMMITTED;
  if (persist_update_state() != XAIOS_OK ||
      mutable_fs_commit("update-commit") != XAIOS_OK) {
    ++g_rejects;
    return XAIOS_ERR_IO;
  }
  ++g_commits;
  klog("update: committed generation=%u target=%s\n", g_update.generation,
       g_update.target);
  return XAIOS_OK;
}

xaios_status_t update_fail(void) {
  if (g_update.active == 0 || g_update.state != XAIOS_UPDATE_STAGED) {
    ++g_rejects;
    return XAIOS_ERR_INVALID;
  }
  g_update.state = XAIOS_UPDATE_FAILED;
  if (system_target()) (void)system_slot_cancel_pending();
  if (persist_update_state() != XAIOS_OK) {
    ++g_rejects;
    return XAIOS_ERR_IO;
  }
  ++g_failures;
  klog("update: failed generation=%u target=%s\n", g_update.generation,
       g_update.target);
  return XAIOS_OK;
}

xaios_status_t update_recover_boot(void) {
  if (g_update.active == 0 || g_update.state != XAIOS_UPDATE_FAILED) {
    ++g_rejects;
    return XAIOS_ERR_INVALID;
  }
  if (persistence_rollback(XAIOS_SNAPSHOT_UPDATE, 0) != XAIOS_OK ||
      mutable_fs_rollback() != XAIOS_OK) {
    ++g_rejects;
    return XAIOS_ERR_IO;
  }
  g_update.state = XAIOS_UPDATE_RECOVERED;
  if (persist_update_state() != XAIOS_OK) {
    ++g_rejects;
    return XAIOS_ERR_IO;
  }
  ++g_recoveries;
  ++g_boot_fallbacks;
  klog("update: boot fallback recovered generation=%u rollback=%s\n",
       g_update.generation, g_update.rollback_label);
  g_update.active = 0;
  return XAIOS_OK;
}

xaios_status_t update_rollback(void) {
  if (g_update.active == 0 || g_update.state != XAIOS_UPDATE_COMMITTED ||
      security_authorize_rollback(g_update.target, 1) != XAIOS_OK) {
    ++g_rejects;
    return XAIOS_ERR_INVALID;
  }
  if (system_target() && system_slot_cancel_pending() != XAIOS_OK) {
    ++g_rejects;
    return XAIOS_ERR_IO;
  }
  if (persistence_rollback(XAIOS_SNAPSHOT_UPDATE, 0) != XAIOS_OK ||
      mutable_fs_rollback() != XAIOS_OK) {
    ++g_rejects;
    return XAIOS_ERR_IO;
  }
  g_update.state = XAIOS_UPDATE_ROLLED_BACK;
  if (persist_update_state() != XAIOS_OK) {
    ++g_rejects;
    return XAIOS_ERR_IO;
  }
  ++g_rollbacks;
  klog("update: rollback complete generation=%u target=%s\n",
       g_update.generation, g_update.target);
  g_update.active = 0;
  return XAIOS_OK;
}

uint64_t update_transaction_count(void) { return g_transactions; }
uint64_t update_stage_count(void) { return g_stages; }
uint64_t update_commit_count(void) { return g_commits; }
uint64_t update_failure_count(void) { return g_failures; }
uint64_t update_recovery_count(void) { return g_recoveries; }
uint64_t update_rollback_count(void) { return g_rollbacks; }
uint64_t update_boot_fallback_count(void) { return g_boot_fallbacks; }
uint64_t update_record_persist_count(void) { return g_records_persisted; }
uint64_t update_rollback_point_count(void) { return g_rollback_points; }
uint64_t update_reject_count(void) { return g_rejects; }

/* ---- Chunked delivery ---- */

xaios_status_t update_stage_chunk(const void *data, uint32_t size) {
  if (g_update.active == 0 || g_update.state != XAIOS_UPDATE_PENDING) {
    ++g_rejects;
    g_delivery.last_error = XAIOS_ERR_INVALID;
    return XAIOS_ERR_INVALID;
  }
  if (data == 0 || size == 0 || size > XAIOS_UPDATE_CHUNK_MAX) {
    ++g_rejects;
    g_delivery.last_error = XAIOS_ERR_INVALID;
    return XAIOS_ERR_INVALID;
  }
  if (g_delivery.bytes_expected > 0 &&
      g_delivery.bytes_received + size > g_delivery.bytes_expected) {
    ++g_rejects;
    g_delivery.last_error = XAIOS_ERR_INVALID;
    return XAIOS_ERR_INVALID;
  }

  /* Initialize hash context and the inactive system slot on first chunk. */
  if (g_chunk_staging_active == 0) {
    if (system_target() &&
        (g_delivery.bytes_expected == 0U ||
         system_slot_begin(g_update.generation, g_delivery.bytes_expected,
                           g_update.expected_hash,
                           g_update.signature) != XAIOS_OK)) {
      ++g_rejects;
      g_delivery.last_error = XAIOS_ERR_INVALID;
      return XAIOS_ERR_INVALID;
    }
    xaios_sha256_init(&g_chunk_hash_ctx);
    g_chunk_staging_active = 1;
  }

  if (system_target()) {
    if (system_slot_write(g_delivery.bytes_received, data, size) != XAIOS_OK) {
      ++g_rejects;
      g_delivery.last_error = XAIOS_ERR_IO;
      return XAIOS_ERR_IO;
    }
  } else {
  /* Append fixture/non-system chunks to MutableFS. */
  uint32_t open_flags = XAIOS_MFS_OPEN_WRITE | XAIOS_MFS_OPEN_CREATE;
  if (g_delivery.bytes_received == 0U) {
    open_flags |= XAIOS_MFS_OPEN_TRUNCATE;
  }
  int64_t fd = mutable_fs_open(XAIOS_UPDATE_STAGING_PATH, open_flags);
  if (fd < 0) {
    ++g_rejects;
    g_delivery.last_error = XAIOS_ERR_IO;
    return XAIOS_ERR_IO;
  }

  if (mutable_fs_seek((uint32_t)fd, g_delivery.bytes_received) != XAIOS_OK) {
    mutable_fs_close((uint32_t)fd);
    ++g_rejects;
    g_delivery.last_error = XAIOS_ERR_IO;
    return XAIOS_ERR_IO;
  }
  int64_t written = mutable_fs_write_fd((uint32_t)fd, data, size);
  mutable_fs_close((uint32_t)fd);

  if (written < 0 || (uint32_t)written != size) {
    ++g_rejects;
    g_delivery.last_error = XAIOS_ERR_IO;
    return XAIOS_ERR_IO;
  }
  }

  /* Update running hash */
  xaios_sha256_update(&g_chunk_hash_ctx, data, size);
  g_delivery.bytes_received += size;
  ++g_delivery.chunks_written;

  klog("update: chunk staged size=%u total=%lu chunks=%u\n",
       size, g_delivery.bytes_received, g_delivery.chunks_written);
  return XAIOS_OK;
}

xaios_status_t update_verify_hash(const uint8_t expected_hash[32]) {
  if (g_update.active == 0 || g_chunk_staging_active == 0 ||
      expected_hash == 0) {
    ++g_rejects;
    g_delivery.last_error = XAIOS_ERR_INVALID;
    return XAIOS_ERR_INVALID;
  }

  uint8_t computed[32];
  xaios_sha256_final(&g_chunk_hash_ctx, computed);
  g_chunk_staging_active = 0;

  int match = g_delivery.bytes_expected == 0U ||
              g_delivery.bytes_received == g_delivery.bytes_expected;
  for (uint32_t i = 0; i < 32; ++i) {
    if (computed[i] != expected_hash[i] ||
        expected_hash[i] != g_update.expected_hash[i]) {
      match = 0;
      break;
    }
  }

  if (match == 0) {
    g_delivery.hash_verified = 0;
    g_delivery.last_error = XAIOS_ERR_INVALID;
    g_update.state = XAIOS_UPDATE_FAILED;
    persist_update_state();
    ++g_rejects;
    klog("update: hash verification FAILED\n");
    return XAIOS_ERR_INVALID;
  }

  if (system_target() && system_slot_finish() != XAIOS_OK) {
    g_delivery.hash_verified = 0;
    g_delivery.last_error = XAIOS_ERR_IO;
    g_update.state = XAIOS_UPDATE_FAILED;
    (void)persist_update_state();
    ++g_rejects;
    return XAIOS_ERR_IO;
  }

  g_delivery.hash_verified = 1;
  g_update.state = XAIOS_UPDATE_STAGED;
  if (persist_update_state() != XAIOS_OK ||
      mutable_fs_commit("update-stage-verified") != XAIOS_OK) {
    ++g_rejects;
    g_delivery.last_error = XAIOS_ERR_IO;
    return XAIOS_ERR_IO;
  }
  ++g_stages;
  klog("update: hash verified generation=%u chunks=%u bytes=%lu\n",
       g_update.generation, g_delivery.chunks_written,
       g_delivery.bytes_received);
  return XAIOS_OK;
}

static int hex_digit(char ch) {
  if (ch >= '0' && ch <= '9') {
    return ch - '0';
  }
  if (ch >= 'a' && ch <= 'f') {
    return 10 + (ch - 'a');
  }
  if (ch >= 'A' && ch <= 'F') {
    return 10 + (ch - 'A');
  }
  return -1;
}

xaios_status_t update_parse_manifest(const char *manifest_data, uint32_t size,
                                     xaios_update_manifest_t *out) {
  if (manifest_data == 0 || size == 0 || out == 0) {
    return XAIOS_ERR_INVALID;
  }

  bytes_zero(out, sizeof(*out));
  uint32_t fields_seen = 0;
  uint32_t pos = 0;

  while (pos < size) {
    /* Skip whitespace/newlines */
    while (pos < size && (manifest_data[pos] == '\n' ||
                          manifest_data[pos] == '\r' ||
                          manifest_data[pos] == ' ')) {
      ++pos;
    }
    if (pos >= size) {
      break;
    }

    /* Find '=' separator */
    uint32_t key_start = pos;
    while (pos < size && manifest_data[pos] != '=') {
      ++pos;
    }
    if (pos >= size) {
      break;
    }
    uint32_t key_len = pos - key_start;
    ++pos; /* skip '=' */

    /* Find end of value (newline or end) */
    uint32_t val_start = pos;
    while (pos < size && manifest_data[pos] != '\n' &&
           manifest_data[pos] != '\r') {
      ++pos;
    }
    uint32_t val_len = pos - val_start;

    /* Parse known keys */
    const char *key = manifest_data + key_start;
    const char *val = manifest_data + val_start;

    if (key_len == 7 && key[0] == 'v' && key[1] == 'e' && key[2] == 'r') {
      /* version */
      uint32_t v = 0;
      for (uint32_t i = 0; i < val_len; ++i) {
        if (val[i] >= '0' && val[i] <= '9') {
          v = v * 10U + (uint32_t)(val[i] - '0');
        }
      }
      out->version = v;
      fields_seen |= 1U;
    } else if (key_len == 6 && key[0] == 't' && key[1] == 'a') {
      /* target */
      uint32_t copy_len = val_len < XAIOS_UPDATE_TARGET_MAX - 1U
                              ? val_len
                              : XAIOS_UPDATE_TARGET_MAX - 1U;
      for (uint32_t i = 0; i < copy_len; ++i) {
        out->target[i] = val[i];
      }
      out->target[copy_len] = '\0';
      fields_seen |= 2U;
    } else if (key_len == 4 && key[0] == 's' && key[1] == 'i') {
      /* size */
      uint64_t sz = 0;
      for (uint32_t i = 0; i < val_len; ++i) {
        if (val[i] >= '0' && val[i] <= '9') {
          sz = sz * 10U + (uint64_t)(val[i] - '0');
        }
      }
      out->payload_size = sz;
      fields_seen |= 4U;
    } else if (key_len == 4 && key[0] == 'h' && key[1] == 'a') {
      /* hash (64 hex chars -> 32 bytes) */
      if (val_len >= 64U) {
        for (uint32_t i = 0; i < 32; ++i) {
          int hi = hex_digit(val[i * 2U]);
          int lo = hex_digit(val[i * 2U + 1U]);
          if (hi < 0 || lo < 0) {
            return XAIOS_ERR_INVALID;
          }
          out->payload_hash[i] = (uint8_t)((hi << 4) | lo);
        }
        fields_seen |= 8U;
      }
    } else if (key_len == 10 && key[0] == 'g' && key[1] == 'e') {
      /* generation */
      uint32_t gen = 0;
      for (uint32_t i = 0; i < val_len; ++i) {
        if (val[i] >= '0' && val[i] <= '9') {
          gen = gen * 10U + (uint32_t)(val[i] - '0');
        }
      }
      out->generation = gen;
      fields_seen |= 16U;
    }
  }

  if ((fields_seen & 31U) != 31U) {
    return XAIOS_ERR_INVALID;
  }

  g_delivery.bytes_expected = out->payload_size;
  klog("update: manifest parsed version=%u target=%s size=%lu generation=%u\n",
       out->version, out->target, out->payload_size, out->generation);
  return XAIOS_OK;
}

xaios_update_delivery_status_t update_delivery_status(void) {
  return g_delivery;
}

xaios_update_status_t update_status_snapshot(void) {
  xaios_update_status_t status;
  bytes_zero(&status, sizeof(status));
  status.active = g_update.active;
  status.generation = g_update.generation;
  status.state = (uint32_t)g_update.state;
  copy_token(status.target, sizeof(status.target), g_update.target);
  status.delivery = g_delivery;
  return status;
}

void update_delivery_self_test(void) {
  xaios_update_transaction_t saved_update = g_update;
  xaios_update_delivery_status_t saved_delivery = g_delivery;
  uint32_t saved_chunk_staging_active = g_chunk_staging_active;
  uint64_t saved_transactions = g_transactions;
  uint64_t saved_stages = g_stages;
  uint64_t saved_commits = g_commits;
  uint64_t saved_failures = g_failures;
  uint64_t saved_recoveries = g_recoveries;
  uint64_t saved_rollbacks = g_rollbacks;
  uint64_t saved_boot_fallbacks = g_boot_fallbacks;
  uint64_t saved_records_persisted = g_records_persisted;
  uint64_t saved_rollback_points = g_rollback_points;
  uint64_t saved_rejects = g_rejects;

  /* Test SHA-256 first */
  sha256_self_test();

  /* Test manifest parsing */
  xaios_update_manifest_t manifest;
  static const char test_manifest[] =
      "version=1\n"
      "target=/system/xaios\n"
      "size=1024\n"
      "hash=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n"
      "generation=42\n";
  uint32_t mlen = 0;
  for (uint32_t i = 0; test_manifest[i] != '\0'; ++i) {
    ++mlen;
  }
  kassert(update_parse_manifest(test_manifest, mlen, &manifest) == XAIOS_OK);
  kassert(manifest.version == 1);
  kassert(manifest.generation == 42);
  kassert(manifest.payload_size == 1024);
  kassert(manifest.payload_hash[0] == 0xba);
  kassert(manifest.payload_hash[1] == 0x78);

  /* Test chunked staging + hash verification */
  update_runtime_init();
  static const char k_sig_test[] =
      "xaios-update:v2:gen=10:sha256=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad:key=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a:sig=376af08bf94b0642df5e321a0ca9ff5ed411c7cd3a1cee4fd1cbde041f8d3da1712e8377d0b6e512d3d984b697eef101657d45f2c8397bbdfc011b4698b50b09";
  static const char k_sig_test_11[] =
      "xaios-update:v2:gen=11:sha256=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad:key=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a:sig=5847d54245b962f813875984c61f23baadad3ab5206f37725ddc8192b658ba0d257eea200f862e1e769848e32c684e6f9da16d3d515e66d1037e06566cd58604";
  kassert(update_begin(10, "/fixture/delivery", k_sig_test) == XAIOS_OK);
  kassert(update_stage_chunk("ab", 2) == XAIOS_OK);
  kassert(update_stage_chunk("c", 1) == XAIOS_OK);

  /* Verify with correct hash */
  static const uint8_t correct_hash[32] = {
      0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
      0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
      0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
  kassert(update_verify_hash(correct_hash) == XAIOS_OK);

  xaios_update_delivery_status_t status = update_delivery_status();
  kassert(status.bytes_received == 3);
  kassert(status.chunks_written == 2);
  kassert(status.hash_verified == 1);
  int64_t staged_fd = mutable_fs_open(XAIOS_UPDATE_STAGING_PATH,
                                      XAIOS_MFS_OPEN_READ);
  char staged_bytes[3] = {0, 0, 0};
  kassert(staged_fd > 0);
  kassert(mutable_fs_read_fd((uint32_t)staged_fd, staged_bytes,
                             sizeof(staged_bytes)) == 3);
  kassert(mutable_fs_close((uint32_t)staged_fd) == XAIOS_OK);
  kassert(staged_bytes[0] == 'a' && staged_bytes[1] == 'b' &&
          staged_bytes[2] == 'c');

  /* Test bad hash rejection */
  update_runtime_init();
  kassert(update_begin(11, "/fixture/delivery", k_sig_test_11) == XAIOS_OK);
  kassert(update_stage_chunk("abc", 3) == XAIOS_OK);
  static const uint8_t bad_hash[32] = {0};
  kassert(update_verify_hash(bad_hash) == XAIOS_ERR_INVALID);

  g_update = saved_update;
  g_delivery = saved_delivery;
  g_chunk_staging_active = saved_chunk_staging_active;
  g_transactions = saved_transactions;
  g_stages = saved_stages;
  g_commits = saved_commits;
  g_failures = saved_failures;
  g_recoveries = saved_recoveries;
  g_rollbacks = saved_rollbacks;
  g_boot_fallbacks = saved_boot_fallbacks;
  g_records_persisted = saved_records_persisted;
  g_rollback_points = saved_rollback_points;
  g_rejects = saved_rejects;

  klog("update: delivery self-test passed\n");
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

  kassert(g_transactions == 2);
  kassert(g_stages == 2);
  kassert(g_commits == 1);
  kassert(g_failures == 1);
  kassert(g_recoveries == 1);
  kassert(g_rollbacks == 1);
  kassert(g_boot_fallbacks == 1);
  kassert(g_records_persisted == 8);
  kassert(g_rollback_points == 2);
  kassert(g_rejects == 2);
  klog("update: self-test passed transactions=%lu staged=%lu committed=%lu failed=%lu recovered=%lu rollbacks=%lu boot_fallbacks=%lu records=%lu rollback_points=%lu rejects=%lu\n",
       g_transactions, g_stages, g_commits, g_failures, g_recoveries,
       g_rollbacks, g_boot_fallbacks, g_records_persisted,
       g_rollback_points, g_rejects);
}
