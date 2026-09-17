/* Chunked update delivery for XAIOS.
 *
 * Split out of kernel/runtime/update.c: this translation unit owns the chunked
 * staging path, the running SHA-256 and the system-slot writes, the manifest
 * reader, the delivery status accessor and the delivery self-test. The
 * transaction state machine, the rollback points and the boot-fallback path
 * stay in update.c; the two files share update_internal.h. */

#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/sha256.h>
#include <xaios/update.h>
#include <xaios/xaiboot_fs.h>

#include "update_internal.h"

xaios_update_delivery_status_t g_update_delivery;
xaios_sha256_ctx_t g_update_chunk_hash_ctx;
uint32_t g_update_chunk_staging_active;

/* ---- Chunked delivery ---- */

xaios_status_t update_stage_chunk(const void *data, uint32_t size) {
  if (g_update_transaction.active == 0 || g_update_transaction.state != XAIOS_UPDATE_PENDING) {
    ++g_update_rejects;
    g_update_delivery.last_error = XAIOS_ERR_INVALID;
    return XAIOS_ERR_INVALID;
  }
  if (data == 0 || size == 0 || size > XAIOS_UPDATE_CHUNK_MAX) {
    ++g_update_rejects;
    g_update_delivery.last_error = XAIOS_ERR_INVALID;
    return XAIOS_ERR_INVALID;
  }
  if (g_update_delivery.bytes_expected > 0 &&
      g_update_delivery.bytes_received + size > g_update_delivery.bytes_expected) {
    ++g_update_rejects;
    g_update_delivery.last_error = XAIOS_ERR_INVALID;
    return XAIOS_ERR_INVALID;
  }

  /* Initialize hash context and the inactive system slot on first chunk. */
  if (g_update_chunk_staging_active == 0) {
    if (update_system_target() &&
        (g_update_delivery.bytes_expected == 0U ||
         system_slot_begin(g_update_transaction.generation, g_update_delivery.bytes_expected,
                           g_update_transaction.expected_hash,
                           g_update_transaction.signature) != XAIOS_OK)) {
      ++g_update_rejects;
      g_update_delivery.last_error = XAIOS_ERR_INVALID;
      return XAIOS_ERR_INVALID;
    }
    xaios_sha256_init(&g_update_chunk_hash_ctx);
    g_update_chunk_staging_active = 1;
  }

  if (update_system_target()) {
    if (system_slot_write(g_update_delivery.bytes_received, data, size) != XAIOS_OK) {
      ++g_update_rejects;
      g_update_delivery.last_error = XAIOS_ERR_IO;
      return XAIOS_ERR_IO;
    }
  } else {
  /* Append fixture/non-system chunks to xaibootFS. */
  uint32_t open_flags = XAIOS_XBFS_OPEN_WRITE | XAIOS_XBFS_OPEN_CREATE;
  if (g_update_delivery.bytes_received == 0U) {
    open_flags |= XAIOS_XBFS_OPEN_TRUNCATE;
  }
  int64_t fd = xaiboot_fs_open(XAIOS_UPDATE_STAGING_PATH, open_flags);
  if (fd < 0) {
    ++g_update_rejects;
    g_update_delivery.last_error = XAIOS_ERR_IO;
    return XAIOS_ERR_IO;
  }

  if (xaiboot_fs_seek((uint32_t)fd, g_update_delivery.bytes_received) != XAIOS_OK) {
    xaiboot_fs_close((uint32_t)fd);
    ++g_update_rejects;
    g_update_delivery.last_error = XAIOS_ERR_IO;
    return XAIOS_ERR_IO;
  }
  int64_t written = xaiboot_fs_write_fd((uint32_t)fd, data, size);
  xaiboot_fs_close((uint32_t)fd);

  if (written < 0 || (uint32_t)written != size) {
    ++g_update_rejects;
    g_update_delivery.last_error = XAIOS_ERR_IO;
    return XAIOS_ERR_IO;
  }
  }

  /* Update running hash */
  xaios_sha256_update(&g_update_chunk_hash_ctx, data, size);
  g_update_delivery.bytes_received += size;
  ++g_update_delivery.chunks_written;

  klog("update: chunk staged size=%u total=%lu chunks=%u\n",
       size, g_update_delivery.bytes_received, g_update_delivery.chunks_written);
  return XAIOS_OK;
}

xaios_status_t update_verify_hash(const uint8_t expected_hash[32]) {
  if (g_update_transaction.active == 0 || g_update_chunk_staging_active == 0 ||
      expected_hash == 0) {
    ++g_update_rejects;
    g_update_delivery.last_error = XAIOS_ERR_INVALID;
    return XAIOS_ERR_INVALID;
  }

  uint8_t computed[32];
  xaios_sha256_final(&g_update_chunk_hash_ctx, computed);
  g_update_chunk_staging_active = 0;

  int match = g_update_delivery.bytes_expected == 0U ||
              g_update_delivery.bytes_received == g_update_delivery.bytes_expected;
  for (uint32_t i = 0; i < 32; ++i) {
    if (computed[i] != expected_hash[i] ||
        expected_hash[i] != g_update_transaction.expected_hash[i]) {
      match = 0;
      break;
    }
  }

  if (match == 0) {
    g_update_delivery.hash_verified = 0;
    g_update_delivery.last_error = XAIOS_ERR_INVALID;
    g_update_transaction.state = XAIOS_UPDATE_FAILED;
    update_persist_state();
    ++g_update_rejects;
    klog("update: hash verification FAILED\n");
    return XAIOS_ERR_INVALID;
  }

  if (update_system_target() && system_slot_finish() != XAIOS_OK) {
    g_update_delivery.hash_verified = 0;
    g_update_delivery.last_error = XAIOS_ERR_IO;
    g_update_transaction.state = XAIOS_UPDATE_FAILED;
    (void)update_persist_state();
    ++g_update_rejects;
    return XAIOS_ERR_IO;
  }

  g_update_delivery.hash_verified = 1;
  g_update_transaction.state = XAIOS_UPDATE_STAGED;
  if (update_persist_state() != XAIOS_OK ||
      xaiboot_fs_commit("update-stage-verified") != XAIOS_OK) {
    ++g_update_rejects;
    g_update_delivery.last_error = XAIOS_ERR_IO;
    return XAIOS_ERR_IO;
  }
  ++g_update_stages;
  klog("update: hash verified generation=%u chunks=%u bytes=%lu\n",
       g_update_transaction.generation, g_update_delivery.chunks_written,
       g_update_delivery.bytes_received);
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

  update_bytes_zero(out, sizeof(*out));
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

  g_update_delivery.bytes_expected = out->payload_size;
  klog("update: manifest parsed version=%u target=%s size=%lu generation=%u\n",
       out->version, out->target, out->payload_size, out->generation);
  return XAIOS_OK;
}

xaios_update_delivery_status_t update_delivery_status(void) {
  return g_update_delivery;
}

void update_delivery_self_test(void) {
  xaios_update_transaction_t saved_update = g_update_transaction;
  xaios_update_delivery_status_t saved_delivery = g_update_delivery;
  uint32_t saved_chunk_staging_active = g_update_chunk_staging_active;
  uint64_t saved_transactions = g_update_transactions;
  uint64_t saved_stages = g_update_stages;
  uint64_t saved_commits = g_update_commits;
  uint64_t saved_failures = g_update_failures;
  uint64_t saved_recoveries = g_update_recoveries;
  uint64_t saved_rollbacks = g_update_rollbacks;
  uint64_t saved_boot_fallbacks = g_update_boot_fallbacks;
  uint64_t saved_records_persisted = g_update_records_persisted;
  uint64_t saved_rollback_points = g_update_rollback_points;
  uint64_t saved_rejects = g_update_rejects;

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
  int64_t staged_fd = xaiboot_fs_open(XAIOS_UPDATE_STAGING_PATH,
                                      XAIOS_XBFS_OPEN_READ);
  char staged_bytes[3] = {0, 0, 0};
  kassert(staged_fd > 0);
  kassert(xaiboot_fs_read_fd((uint32_t)staged_fd, staged_bytes,
                             sizeof(staged_bytes)) == 3);
  kassert(xaiboot_fs_close((uint32_t)staged_fd) == XAIOS_OK);
  kassert(staged_bytes[0] == 'a' && staged_bytes[1] == 'b' &&
          staged_bytes[2] == 'c');

  /* Test bad hash rejection */
  update_runtime_init();
  kassert(update_begin(11, "/fixture/delivery", k_sig_test_11) == XAIOS_OK);
  kassert(update_stage_chunk("abc", 3) == XAIOS_OK);
  static const uint8_t bad_hash[32] = {0};
  kassert(update_verify_hash(bad_hash) == XAIOS_ERR_INVALID);

  g_update_transaction = saved_update;
  g_update_delivery = saved_delivery;
  g_update_chunk_staging_active = saved_chunk_staging_active;
  g_update_transactions = saved_transactions;
  g_update_stages = saved_stages;
  g_update_commits = saved_commits;
  g_update_failures = saved_failures;
  g_update_recoveries = saved_recoveries;
  g_update_rollbacks = saved_rollbacks;
  g_update_boot_fallbacks = saved_boot_fallbacks;
  g_update_records_persisted = saved_records_persisted;
  g_update_rollback_points = saved_rollback_points;
  g_update_rejects = saved_rejects;

  klog("update: delivery self-test passed\n");
}
