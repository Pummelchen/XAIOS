/*
 * sshd's authorized-key store.
 *
 * The two files that can hold keys -- the managed database the control plane
 * writes and the bootstrap authorized_keys file -- their parsers, and the
 * generation-keyed cache that keeps authentication from reading the durable
 * volume on every attempt. Split whole out of sshd.c: the cache and the loader
 * share the parsed table, so they move together.
 *
 * sshd.c keeps process_connection(), which asks for one key by its public key
 * and receives a copy (see sshd_auth.h), never a pointer into this module's
 * table. The durable-cost counters stay here with the cache that owns them; the
 * service loop reads them through sshd_keys_load_stats().
 */

#include "sshd_auth.h"

#include "sshd_audit.h"
#include "sshd_internal.h"
#include "ssh_crypto.h"
#include "ssh_utils.h"

/* The authorized-key loader's share of the durable cost. log_durable_cost()
   takes them as arguments rather than reaching across into this section. */
static uint32_t g_key_load_calls;
static uint32_t g_key_load_file_reads;
static uint64_t g_key_load_ns;

/* ---- Authorized Keys for Public Key Auth ---- */
#define AUTHORIZED_KEYS_PATH "/etc/xaios_authorized_keys"
#define MAX_AUTHORIZED_KEYS 16

typedef struct {
  uint8_t key[32];
  uint8_t fingerprint[32];
  char principal[XAIOS_ADMIN_PRINCIPAL_MAX];
  uint32_t role;
  int active;
} authorized_key_t;

static authorized_key_t g_authorized_keys[MAX_AUTHORIZED_KEYS];
static uint32_t g_authorized_key_count = 0;
static uint32_t g_authorized_database_invalid;

int sshd_keys_blob_parse(const uint8_t *blob, uint32_t blob_len,
                         uint8_t key[32]) {
  static const uint8_t algorithm[] = "ssh-ed25519";
  if (blob == 0 || blob_len != 51U || ssh_read_u32_be(blob) != 11U ||
      !sshd_bytes_equal(blob + 4U, algorithm, 11U) ||
      ssh_read_u32_be(blob + 15U) != 32U) {
    return -1;
  }
  ssh_mem_copy(key, blob + 19U, 32U);
  return 0;
}

static int base64_value(char value) {
  if (value >= 'A' && value <= 'Z') return value - 'A';
  if (value >= 'a' && value <= 'z') return 26 + value - 'a';
  if (value >= '0' && value <= '9') return 52 + value - '0';
  if (value == '+') return 62;
  if (value == '/') return 63;
  return -1;
}

static int decode_base64(const char *text, uint32_t text_len, uint8_t *output,
                         uint32_t output_capacity, uint32_t *output_len) {
  uint32_t accumulator = 0;
  uint32_t bits = 0;
  uint32_t written = 0;
  if (text_len == 0U || (text_len & 3U) != 0U) return -1;
  for (uint32_t i = 0; i < text_len; ++i) {
    char value = text[i];
    if (value == '=') {
      if (i < text_len - 2U ||
          (i == text_len - 2U && text[i + 1U] != '=')) return -1;
      continue;
    }
    if (i > 0U && text[i - 1U] == '=') return -1;
    int decoded = base64_value(value);
    if (decoded < 0) return -1;
    accumulator = (accumulator << 6U) | (uint32_t)decoded;
    bits += 6U;
    if (bits >= 8U) {
      bits -= 8U;
      if (written >= output_capacity) return -1;
      output[written++] = (uint8_t)(accumulator >> bits);
      if (bits != 0U) accumulator &= (UINT32_C(1) << bits) - 1U;
      else accumulator = 0U;
    }
  }
  *output_len = written;
  return 0;
}

static int parse_authorized_key_line(const char *line, uint32_t line_len,
                                     uint8_t key[32]) {
  static const char algorithm[] = "ssh-ed25519";
  uint32_t position = 0;
  while (position < line_len) {
    while (position < line_len &&
           (line[position] == ' ' || line[position] == '\t')) ++position;
    if (position == line_len || line[position] == '#') return -1;
    uint32_t token_start = position;
    while (position < line_len && line[position] != ' ' &&
           line[position] != '\t' && line[position] != '\r') ++position;
    uint32_t token_len = position - token_start;
    if (token_len == sizeof(algorithm) - 1U &&
        sshd_bytes_equal((const uint8_t *)line + token_start,
                    (const uint8_t *)algorithm, token_len)) {
      while (position < line_len &&
             (line[position] == ' ' || line[position] == '\t')) ++position;
      uint32_t key_start = position;
      while (position < line_len && line[position] != ' ' &&
             line[position] != '\t' && line[position] != '\r') ++position;
      uint8_t blob[96];
      uint32_t blob_len = 0;
      if (decode_base64(line + key_start, position - key_start, blob,
                        sizeof(blob), &blob_len) != 0) return -1;
      int result = sshd_keys_blob_parse(blob, blob_len, key);
      ssh_mem_zero(blob, sizeof(blob));
      return result;
    }
  }
  return -1;
}

static int managed_auth_database_valid(
    const xaios_admin_auth_database_user_t *database) {
  uint64_t checksum_offset =
      (uint64_t)((const uint8_t *)&database->checksum -
                 (const uint8_t *)database);
  if (database->magic != XAIOS_ADMIN_AUTH_MAGIC ||
      database->version != XAIOS_ADMIN_SCHEMA_VERSION ||
      database->header_size !=
          sizeof(*database) - sizeof(database->keys) -
              sizeof(database->revoked) ||
      database->generation == 0U ||
      database->key_count > XAIOS_ADMIN_MAX_KEYS ||
      database->revoked_count > XAIOS_ADMIN_MAX_REVOKED_KEYS ||
      database->checksum !=
          sshd_fnv1a64_zero_range(database, sizeof(*database), checksum_offset,
                                  sizeof(database->checksum))) {
    return 0;
  }
  for (uint32_t i = 0U; i < database->key_count; ++i) {
    const xaios_admin_key_record_user_t *record = &database->keys[i];
    uint32_t terminated = 0U;
    for (uint32_t j = 0U; j < sizeof(record->principal); ++j) {
      if (record->principal[j] == '\0') {
        terminated = j != 0U;
        break;
      }
    }
    uint8_t fingerprint[32];
    sha256_hash(record->public_key, sizeof(record->public_key), fingerprint);
    int fingerprint_valid =
        sshd_bytes_equal(fingerprint, record->fingerprint, sizeof(fingerprint));
    ssh_mem_zero(fingerprint, sizeof(fingerprint));
    if (terminated == 0U || fingerprint_valid == 0 ||
        record->role < XAIOS_CONTROL_ROLE_OBSERVER ||
        record->role > XAIOS_CONTROL_ROLE_ADMIN || record->reserved != 0U) {
      return 0;
    }
  }
  return 1;
}

static int load_authorized_keys_from_volume(void) {
  xaios_xbfs_stat_user_t stat;
  ssh_mem_zero(g_authorized_keys, sizeof(g_authorized_keys));
  g_authorized_key_count = 0U;
  g_authorized_database_invalid = 0U;
  if (xaios_fs_stat(XAIOS_ADMIN_AUTH_PATH, &stat) == 0) {
    xaios_admin_auth_database_user_t database;
    if (stat.size != sizeof(database) ||
        sshd_read_exact_file(XAIOS_ADMIN_AUTH_PATH, &database,
                             sizeof(database)) != 0 ||
        !managed_auth_database_valid(&database)) {
      ssh_mem_zero(&database, sizeof(database));
      g_authorized_database_invalid = 1U;
      ssh_log(SSH_LOG_ERROR, "Managed authorized-key database rejected\n");
      return -1;
    }
    for (uint32_t i = 0U; i < database.key_count; ++i) {
      authorized_key_t *key = &g_authorized_keys[i];
      ssh_mem_copy(key->key, database.keys[i].public_key, sizeof(key->key));
      ssh_mem_copy(key->fingerprint, database.keys[i].fingerprint,
                   sizeof(key->fingerprint));
      ssh_mem_copy(key->principal, database.keys[i].principal,
                   sizeof(key->principal));
      key->role = database.keys[i].role;
      key->active = 1;
    }
    g_authorized_key_count = database.key_count;
    ssh_mem_zero(&database, sizeof(database));
    ssh_log(SSH_LOG_INFO, "Loaded %u managed authorized keys\n",
            g_authorized_key_count);
    return g_authorized_key_count != 0U ? 0 : -1;
  }
  char buf[4096];
  int ret = xaios_read_file(AUTHORIZED_KEYS_PATH, buf, sizeof(buf));
  if (ret < 0) {
    ssh_log(SSH_LOG_INFO, "No authorized keys file\n");
    return -1;
  }
  if (ret <= 0) return -1;
  uint32_t line_start = 0;
  uint32_t key_idx = 0;
  for (uint32_t i = 0; i <= (uint32_t)ret && key_idx < MAX_AUTHORIZED_KEYS;
       ++i) {
    if (i == (uint32_t)ret || buf[i] == '\n') {
      uint32_t line_len = i - line_start;
      if (parse_authorized_key_line(buf + line_start, line_len,
                                    g_authorized_keys[key_idx].key) == 0) {
        g_authorized_keys[key_idx].active = 1;
        sha256_hash(g_authorized_keys[key_idx].key,
                    sizeof(g_authorized_keys[key_idx].key),
                    g_authorized_keys[key_idx].fingerprint);
        static const char bootstrap[] = "bootstrap-admin";
        uint32_t principal_length = sizeof(bootstrap) - 1U;
        ssh_mem_copy(g_authorized_keys[key_idx].principal, bootstrap,
                     principal_length);
        if (key_idx != 0U) {
          uint32_t number = key_idx + 1U;
          g_authorized_keys[key_idx].principal[principal_length++] = '-';
          if (number >= 10U) {
            g_authorized_keys[key_idx].principal[principal_length++] =
                (char)('0' + number / 10U);
          }
          g_authorized_keys[key_idx].principal[principal_length++] =
              (char)('0' + number % 10U);
        }
        g_authorized_keys[key_idx].principal[principal_length] = '\0';
        g_authorized_keys[key_idx].role = XAIOS_CONTROL_ROLE_ADMIN;
        ++key_idx;
      }
      line_start = i + 1;
    }
  }
  g_authorized_key_count = key_idx;
  if (g_authorized_key_count != 0U) {
    xaios_log("sshd: authorized key parser accepted input\n");
  }
  ssh_log(SSH_LOG_INFO, "Loaded %u authorized keys\n", g_authorized_key_count);
  return (g_authorized_key_count > 0) ? 0 : -1;
}

/* The authorized keys, and the one thing that makes not re-reading them safe.
 *
 * Every publickey attempt called the loader, and the loader reads the key file
 * off the durable volume -- twice per connection, measured. That is a read of
 * the volume in the middle of authentication, and by B-44 sshd's loop is the
 * machine's network thread, so it is a read of the volume with the guest's
 * networking stopped behind it. The keys change when an administrator changes
 * them, which is approximately never, and the attempts happen on every
 * connection.
 *
 * A cache is obvious. A cache that goes stale is worse than the re-read, and
 * worse in the direction that matters: a revoked key that still opens the
 * machine, or a key just added that does not. So the question is not whether
 * to cache but what the cache is keyed on, and the answer has to be something
 * that changes whenever the file does, from any writer, without anyone having
 * remembered to tell sshd.
 *
 * xaibootFS gives exactly that. Every write to a file assigns the node a fresh
 * generation from a volume-wide counter, and `xaios_fs_stat` reports it along
 * with the size and the content hash. So the cache holds the (present,
 * generation, size, hash) of *both* files the loader consults -- the managed
 * database and the bootstrap file -- and serves the parsed keys only while all
 * eight numbers still match. Both, because which file wins is itself a
 * function of whether the managed one exists: a managed database appearing has
 * to invalidate the keys parsed from the bootstrap file, and that is a change
 * of presence rather than of content.
 *
 * `xaios_fs_stat` is a lookup in the resident node table. It reads no block
 * and does no IO, which is the entire difference between it and what it
 * replaces.
 *
 * Note what this deliberately does *not* rely on: `sshd_reload_control_state`
 * calls the loader after an `xaiosctl auth key add`, and that hook is not the
 * invalidation. Keying on the generation catches every writer, including the
 * ones that do not go through that hook -- the kernel writing the database for
 * a local-console administrator, a restored snapshot, a rollback. A cache that
 * trusted the hook would be correct only for the paths someone remembered. */
#ifndef SSHD_KEY_CACHE
#define SSHD_KEY_CACHE 1
#endif
#ifndef SSHD_KEY_CACHE_INVALIDATES
#define SSHD_KEY_CACHE_INVALIDATES 1
#endif

#if SSHD_KEY_CACHE
typedef struct {
  int present;
  uint64_t generation;
  uint64_t size;
  uint64_t content_hash;
} key_source_sample_t;

typedef struct {
  int valid;
  int result;
  key_source_sample_t managed;
  key_source_sample_t bootstrap;
} authorized_keys_cache_t;

static authorized_keys_cache_t g_authorized_keys_cache;

static void sample_key_source(const char *path, key_source_sample_t *out) {
  xaios_xbfs_stat_user_t stat;
  ssh_mem_zero(out, sizeof(*out));
  if (xaios_fs_stat(path, &stat) != 0) return;
  out->present = 1;
  out->generation = stat.generation;
  out->size = stat.size;
  out->content_hash = stat.content_hash;
}

#if SSHD_KEY_CACHE_INVALIDATES
static int key_source_same(const key_source_sample_t *a,
                           const key_source_sample_t *b) {
  return a->present == b->present && a->generation == b->generation &&
         a->size == b->size && a->content_hash == b->content_hash;
}
#endif

static int authorized_keys_cache_current(const key_source_sample_t *managed,
                                         const key_source_sample_t *bootstrap) {
  if (g_authorized_keys_cache.valid == 0) return 0;
#if SSHD_KEY_CACHE_INVALIDATES
  return key_source_same(&g_authorized_keys_cache.managed, managed) &&
         key_source_same(&g_authorized_keys_cache.bootstrap, bootstrap);
#else
  /* The control, built only by the gate. A cache that never looks at the file
     again is faster than one that does and is wrong from the first key an
     administrator adds or revokes -- which is why the real one is keyed on the
     generation, and why "it is faster now" is not on its own a result. */
  (void)managed;
  (void)bootstrap;
  return 1;
#endif
}
#endif /* SSHD_KEY_CACHE */

int sshd_keys_load(void) {
  uint64_t started = xaios_clock_nanos();
  uint64_t audit_before = ssh_audit_write_ns();
  int result;
  ++g_key_load_calls;
#if SSHD_KEY_CACHE
  key_source_sample_t managed;
  key_source_sample_t bootstrap;
  sample_key_source(XAIOS_ADMIN_AUTH_PATH, &managed);
  sample_key_source(AUTHORIZED_KEYS_PATH, &bootstrap);
  if (authorized_keys_cache_current(&managed, &bootstrap) != 0) {
    result = g_authorized_keys_cache.result;
  } else {
    ++g_key_load_file_reads;
    result = load_authorized_keys_from_volume();
    g_authorized_keys_cache.valid = 1;
    g_authorized_keys_cache.result = result;
    g_authorized_keys_cache.managed = managed;
    g_authorized_keys_cache.bootstrap = bootstrap;
  }
#else
  ++g_key_load_file_reads;
  result = load_authorized_keys_from_volume();
#endif
  /* The loader writes an audit line of its own, and that write is already
     counted as audit cost. Subtracting it keeps the two totals disjoint, so
     they can be added up without counting the same nanoseconds twice. */
  g_key_load_ns += (xaios_clock_nanos() - started) -
                   (ssh_audit_write_ns() - audit_before);
  return result;
}

int sshd_keys_lookup(const uint8_t *pubkey, sshd_keys_entry_t *out) {
  for (uint32_t i = 0; i < g_authorized_key_count; ++i) {
    if (!g_authorized_keys[i].active) continue;
    if (sshd_bytes_equal(g_authorized_keys[i].key, pubkey, 32U)) {
      if (out != 0) {
        ssh_mem_copy(out->key, g_authorized_keys[i].key, sizeof(out->key));
        ssh_mem_copy(out->fingerprint, g_authorized_keys[i].fingerprint,
                     sizeof(out->fingerprint));
        ssh_mem_copy(out->principal, g_authorized_keys[i].principal,
                     sizeof(out->principal));
        out->role = g_authorized_keys[i].role;
      }
      return 0;
    }
  }
  return -1;
}

int sshd_keys_database_invalid(void) {
  return g_authorized_database_invalid != 0U;
}

void sshd_keys_load_stats(uint32_t *calls, uint32_t *file_reads, uint64_t *ns) {
  if (calls != 0) *calls = g_key_load_calls;
  if (file_reads != 0) *file_reads = g_key_load_file_reads;
  if (ns != 0) *ns = g_key_load_ns;
}
