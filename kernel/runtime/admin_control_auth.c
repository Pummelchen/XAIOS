/* Authentication key database for the admin control plane.
 *
 * Split out of admin_control.c so no source file exceeds 500 lines. This is
 * the on-disk authorized-key record: its base64/SSH wire parsing, its
 * fingerprint index and revocation list, and the auth.key.list/add/remove
 * operations that mutate it. The configuration subsystem and the host-key
 * identity gate live in admin_control_config.c; the byte and string
 * primitives and the audit/mutation transaction framework stay in
 * admin_control.c and cross back through admin_control_internal.h.
 */

#include "admin_control_internal.h"

#include <xaios/kheap.h>
#include <xaios/sha256.h>
#include <xaios/xaiboot_fs.h>

#define XAIOS_ADMIN_LEGACY_KEYS_PATH "/etc/xaios_authorized_keys"

/* The bodies below were written against admin_control.c's file-local helper
   names. These aliases bind them to the prefixed exports the internal header
   declares, so the moved code reads exactly as it did in its old home. */
#define bytes_zero xaios_admin_bytes_zero
#define bytes_copy xaios_admin_bytes_copy
#define bytes_equal xaios_admin_bytes_equal
#define string_length xaios_admin_string_length
#define string_equal xaios_admin_string_equal
#define string_copy xaios_admin_string_copy
#define fnv1a64 xaios_admin_fnv1a64
#define staging_path_valid xaios_admin_staging_path_valid
#define principal_valid xaios_admin_principal_valid
#define begin_mutation xaios_admin_mutation_begin
#define finish_mutation xaios_admin_mutation_finish
#define abort_and_audit xaios_admin_mutation_abort_and_audit
#define audit_only xaios_admin_audit_only

static void key_fingerprint(const uint8_t public_key[32],
                            uint8_t fingerprint[32]);

static uint64_t auth_checksum(const xaios_admin_auth_database_t *database) {
  xaios_admin_auth_database_t *copy =
      (xaios_admin_auth_database_t *)kheap_alloc(sizeof(*copy), 16U);
  if (copy == 0) {
    return 0U;
  }
  bytes_copy(copy, database, sizeof(*copy));
  copy->checksum = 0U;
  uint64_t checksum = fnv1a64(copy, sizeof(*copy));
  kheap_free(copy);
  return checksum;
}

static int auth_valid(const xaios_admin_auth_database_t *database) {
  uint64_t checksum;
  if (database == 0 || database->magic != XAIOS_ADMIN_AUTH_MAGIC ||
      database->version != XAIOS_ADMIN_SCHEMA_VERSION ||
      database->header_size !=
          sizeof(*database) - sizeof(database->keys) -
              sizeof(database->revoked) ||
      database->generation == 0U ||
      database->key_count > XAIOS_ADMIN_MAX_KEYS ||
      database->revoked_count > XAIOS_ADMIN_MAX_REVOKED_KEYS) {
    return 0;
  }
  for (uint32_t i = 0U; i < database->key_count; ++i) {
    uint8_t fingerprint[32];
    key_fingerprint(database->keys[i].public_key, fingerprint);
    if (!principal_valid(database->keys[i].principal) ||
        database->keys[i].role < XAIOS_ADMIN_ROLE_OBSERVER ||
        database->keys[i].role > XAIOS_ADMIN_ROLE_ADMIN ||
        database->keys[i].reserved != 0U ||
        !bytes_equal(fingerprint, database->keys[i].fingerprint, 32U)) {
      bytes_zero(fingerprint, sizeof(fingerprint));
      return 0;
    }
    bytes_zero(fingerprint, sizeof(fingerprint));
    for (uint32_t j = 0U; j < i; ++j) {
      if (string_equal(database->keys[i].principal,
                       database->keys[j].principal) ||
          bytes_equal(database->keys[i].fingerprint,
                      database->keys[j].fingerprint, 32U)) {
        return 0;
      }
    }
    for (uint32_t j = 0U; j < database->revoked_count; ++j) {
      if (bytes_equal(database->keys[i].fingerprint, database->revoked[j],
                      32U)) {
        return 0;
      }
    }
  }
  checksum = auth_checksum(database);
  return checksum != 0U && checksum == database->checksum;
}

static void initialize_auth_database(xaios_admin_auth_database_t *database) {
  bytes_zero(database, sizeof(*database));
  database->magic = XAIOS_ADMIN_AUTH_MAGIC;
  database->version = XAIOS_ADMIN_SCHEMA_VERSION;
  database->header_size =
      (uint16_t)(sizeof(*database) - sizeof(database->keys) -
                 sizeof(database->revoked));
  database->generation = 1U;
}

static int base64_value(char value) {
  if (value >= 'A' && value <= 'Z') return value - 'A';
  if (value >= 'a' && value <= 'z') return 26 + value - 'a';
  if (value >= '0' && value <= '9') return 52 + value - '0';
  if (value == '+') return 62;
  if (value == '/') return 63;
  return -1;
}

static int decode_base64(const char *text, uint32_t text_length,
                         uint8_t *output, uint32_t capacity,
                         uint32_t *output_length) {
  uint32_t accumulator = 0U;
  uint32_t bits = 0U;
  uint32_t written = 0U;
  if (text == 0 || output == 0 || output_length == 0 || text_length == 0U ||
      (text_length & 3U) != 0U) {
    return -1;
  }
  for (uint32_t i = 0U; i < text_length; ++i) {
    char value = text[i];
    if (value == '=') {
      if (i < text_length - 2U ||
          (i == text_length - 2U && text[i + 1U] != '=')) {
        return -1;
      }
      continue;
    }
    if (i != 0U && text[i - 1U] == '=') return -1;
    int decoded = base64_value(value);
    if (decoded < 0) return -1;
    accumulator = (accumulator << 6U) | (uint32_t)decoded;
    bits += 6U;
    if (bits >= 8U) {
      bits -= 8U;
      if (written >= capacity) return -1;
      output[written++] = (uint8_t)(accumulator >> bits);
      accumulator = bits == 0U ? 0U : accumulator & ((1U << bits) - 1U);
    }
  }
  *output_length = written;
  return 0;
}

static uint32_t read_be32(const uint8_t *bytes) {
  return ((uint32_t)bytes[0] << 24U) | ((uint32_t)bytes[1] << 16U) |
         ((uint32_t)bytes[2] << 8U) | (uint32_t)bytes[3];
}

static int parse_public_key_line(const char *line, uint64_t length,
                                 uint8_t public_key[32]) {
  static const char algorithm[] = "ssh-ed25519";
  uint64_t position = 0U;
  while (position < length && (line[position] == ' ' || line[position] == '\t')) {
    ++position;
  }
  if (position + sizeof(algorithm) - 1U >= length ||
      !bytes_equal(line + position, algorithm, sizeof(algorithm) - 1U)) {
    return -1;
  }
  position += sizeof(algorithm) - 1U;
  if (position >= length || (line[position] != ' ' && line[position] != '\t')) {
    return -1;
  }
  while (position < length && (line[position] == ' ' || line[position] == '\t')) {
    ++position;
  }
  uint64_t encoded_start = position;
  while (position < length && line[position] != ' ' && line[position] != '\t' &&
         line[position] != '\r') {
    ++position;
  }
  if (position - encoded_start > UINT32_MAX) return -1;
  uint8_t blob[96];
  uint32_t blob_length = 0U;
  if (decode_base64(line + encoded_start,
                    (uint32_t)(position - encoded_start), blob, sizeof(blob),
                    &blob_length) != 0 ||
      blob_length != 51U || read_be32(blob) != 11U ||
      !bytes_equal(blob + 4U, algorithm, 11U) ||
      read_be32(blob + 15U) != 32U) {
    bytes_zero(blob, sizeof(blob));
    return -1;
  }
  bytes_copy(public_key, blob + 19U, 32U);
  bytes_zero(blob, sizeof(blob));
  return 0;
}

static int parse_single_key_file(const char *path, uint8_t public_key[32]) {
  char source[XAIOS_ADMIN_SOURCE_BYTES];
  uint64_t size = 0U;
  uint32_t found = 0U;
  if (!staging_path_valid(path) ||
      xaiboot_fs_read(path, source, sizeof(source), &size) != XAIOS_OK ||
      size == 0U) {
    return -1;
  }
  for (uint64_t start = 0U; start <= size;) {
    uint64_t end = start;
    while (end < size && source[end] != '\n') ++end;
    uint64_t length = end - start;
    while (length != 0U && source[start + length - 1U] == '\r') --length;
    if (length != 0U && source[start] != '#') {
      if (found != 0U ||
          parse_public_key_line(source + start, length, public_key) != 0) {
        bytes_zero(source, sizeof(source));
        return -1;
      }
      found = 1U;
    }
    if (end == size) break;
    start = end + 1U;
  }
  bytes_zero(source, sizeof(source));
  return found == 1U ? 0 : -1;
}

static void key_fingerprint(const uint8_t public_key[32],
                            uint8_t fingerprint[32]) {
  xaios_sha256(public_key, 32U, fingerprint);
}

static void import_legacy_keys(xaios_admin_auth_database_t *database) {
  char source[4096];
  uint64_t size = 0U;
  if (xaiboot_fs_read(XAIOS_ADMIN_LEGACY_KEYS_PATH, source, sizeof(source),
                      &size) != XAIOS_OK) {
    return;
  }
  for (uint64_t start = 0U; start <= size &&
                           database->key_count < XAIOS_ADMIN_MAX_KEYS;) {
    uint64_t end = start;
    while (end < size && source[end] != '\n') ++end;
    uint64_t length = end - start;
    while (length != 0U && source[start + length - 1U] == '\r') --length;
    uint8_t public_key[32];
    if (length != 0U && source[start] != '#' &&
        parse_public_key_line(source + start, length, public_key) == 0) {
      xaios_admin_key_record_t *record =
          &database->keys[database->key_count];
      bytes_copy(record->public_key, public_key, sizeof(record->public_key));
      key_fingerprint(record->public_key, record->fingerprint);
      char principal[XAIOS_ADMIN_PRINCIPAL_MAX] = "bootstrap-admin";
      if (database->key_count != 0U) {
        uint32_t number = database->key_count + 1U;
        uint64_t offset = string_length(principal);
        principal[offset++] = '-';
        if (number >= 10U) principal[offset++] = (char)('0' + number / 10U);
        principal[offset++] = (char)('0' + number % 10U);
        principal[offset] = '\0';
      }
      string_copy(record->principal, sizeof(record->principal), principal);
      record->role = XAIOS_ADMIN_ROLE_ADMIN;
      ++database->key_count;
    }
    bytes_zero(public_key, sizeof(public_key));
    if (end == size) break;
    start = end + 1U;
  }
  bytes_zero(source, sizeof(source));
}

static xaios_admin_result_t load_auth_database(
    xaios_admin_auth_database_t *database) {
  uint64_t size = 0U;
  if (database == 0) return XAIOS_ADMIN_RESULT_INVALID;
  if (xaiboot_fs_read(XAIOS_ADMIN_AUTH_PATH, database, sizeof(*database),
                      &size) == XAIOS_OK) {
    return size == sizeof(*database) && auth_valid(database)
               ? XAIOS_ADMIN_RESULT_OK
               : XAIOS_ADMIN_RESULT_INVALID;
  }
  initialize_auth_database(database);
  import_legacy_keys(database);
  database->checksum = auth_checksum(database);
  return database->checksum != 0U ? XAIOS_ADMIN_RESULT_OK
                                  : XAIOS_ADMIN_RESULT_NO_MEMORY;
}

xaios_admin_result_t admin_control_auth_list(
    xaios_admin_key_view_t *keys, uint32_t capacity, uint32_t *key_count,
    uint32_t *revoked_count, uint64_t *generation) {
  xaios_admin_auth_database_t *database =
      (xaios_admin_auth_database_t *)kheap_alloc(sizeof(*database), 16U);
  if (database == 0) return XAIOS_ADMIN_RESULT_NO_MEMORY;
  xaios_admin_result_t result = load_auth_database(database);
  if (result == XAIOS_ADMIN_RESULT_OK &&
      (keys == 0 || key_count == 0 || revoked_count == 0 || generation == 0 ||
       capacity < database->key_count)) {
    result = XAIOS_ADMIN_RESULT_INVALID;
  }
  if (result == XAIOS_ADMIN_RESULT_OK) {
    for (uint32_t i = 0U; i < database->key_count; ++i) {
      bytes_zero(&keys[i], sizeof(keys[i]));
      bytes_copy(keys[i].fingerprint, database->keys[i].fingerprint, 32U);
      string_copy(keys[i].principal, sizeof(keys[i].principal),
                  database->keys[i].principal);
      keys[i].role = database->keys[i].role;
    }
    *key_count = database->key_count;
    *revoked_count = database->revoked_count;
    *generation = database->generation;
  }
  kheap_free(database);
  return result;
}

xaios_admin_result_t admin_control_auth_add(
    const char *path, const char *principal, uint32_t assigned_role,
    const char *actor, uint32_t actor_role, uint64_t operation_id,
    xaios_admin_key_view_t *added) {
  uint8_t public_key[32];
  uint8_t fingerprint[32];
  bytes_zero(public_key, sizeof(public_key));
  bytes_zero(fingerprint, sizeof(fingerprint));
  xaios_admin_result_t begin = begin_mutation(
      actor, actor_role, XAIOS_ADMIN_ROLE_ADMIN, operation_id, "auth.key.add");
  if (begin != XAIOS_ADMIN_RESULT_OK) return begin;
  if (!principal_valid(principal) || assigned_role < XAIOS_ADMIN_ROLE_OBSERVER ||
      assigned_role > XAIOS_ADMIN_ROLE_ADMIN ||
      parse_single_key_file(path, public_key) != 0) {
    bytes_zero(public_key, sizeof(public_key));
    return abort_and_audit(actor, actor_role, operation_id, "auth.key.add",
                           XAIOS_ADMIN_RESULT_INVALID);
  }
  key_fingerprint(public_key, fingerprint);
  xaios_admin_auth_database_t *database =
      (xaios_admin_auth_database_t *)kheap_alloc(sizeof(*database), 16U);
  if (database == 0) {
    bytes_zero(public_key, sizeof(public_key));
    return abort_and_audit(actor, actor_role, operation_id, "auth.key.add",
                           XAIOS_ADMIN_RESULT_NO_MEMORY);
  }
  xaios_admin_result_t result = load_auth_database(database);
  if (result == XAIOS_ADMIN_RESULT_OK) {
    for (uint32_t i = 0U; i < database->key_count; ++i) {
      if (bytes_equal(database->keys[i].fingerprint, fingerprint, 32U) ||
          string_equal(database->keys[i].principal, principal)) {
        result = XAIOS_ADMIN_RESULT_CONFLICT;
      }
    }
    for (uint32_t i = 0U; i < database->revoked_count; ++i) {
      if (bytes_equal(database->revoked[i], fingerprint, 32U)) {
        result = XAIOS_ADMIN_RESULT_CONFLICT;
      }
    }
    if (database->key_count >= XAIOS_ADMIN_MAX_KEYS) {
      result = XAIOS_ADMIN_RESULT_NO_MEMORY;
    }
  }
  if (result != XAIOS_ADMIN_RESULT_OK) {
    kheap_free(database);
    bytes_zero(public_key, sizeof(public_key));
    return abort_and_audit(actor, actor_role, operation_id, "auth.key.add",
                           result);
  }
  xaios_admin_key_record_t *record =
      &database->keys[database->key_count++];
  bytes_zero(record, sizeof(*record));
  bytes_copy(record->public_key, public_key, 32U);
  bytes_copy(record->fingerprint, fingerprint, 32U);
  string_copy(record->principal, sizeof(record->principal), principal);
  record->role = assigned_role;
  ++database->generation;
  database->checksum = auth_checksum(database);
  if (database->checksum == 0U ||
      xaiboot_fs_write(XAIOS_ADMIN_AUTH_PATH, database, sizeof(*database)) !=
          XAIOS_OK) {
    kheap_free(database);
    bytes_zero(public_key, sizeof(public_key));
    return abort_and_audit(actor, actor_role, operation_id, "auth.key.add",
                           XAIOS_ADMIN_RESULT_IO);
  }
  result = finish_mutation(actor, actor_role, operation_id, "auth.key.add",
                           fingerprint);
  if (result == XAIOS_ADMIN_RESULT_OK && added != 0) {
    bytes_zero(added, sizeof(*added));
    bytes_copy(added->fingerprint, fingerprint, 32U);
    string_copy(added->principal, sizeof(added->principal), principal);
    added->role = assigned_role;
  }
  kheap_free(database);
  bytes_zero(public_key, sizeof(public_key));
  if (result != XAIOS_ADMIN_RESULT_OK) {
    return audit_only(actor, actor_role, operation_id, "auth.key.add", result);
  }
  return result;
}

static int hex_nibble(char value) {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return 10 + value - 'a';
  if (value >= 'A' && value <= 'F') return 10 + value - 'A';
  return -1;
}

static int parse_fingerprint(const char *text, uint8_t fingerprint[32]) {
  if (string_length(text) != 64U) return -1;
  for (uint32_t i = 0U; i < 32U; ++i) {
    int high = hex_nibble(text[i * 2U]);
    int low = hex_nibble(text[i * 2U + 1U]);
    if (high < 0 || low < 0) return -1;
    fingerprint[i] = (uint8_t)(((uint32_t)high << 4U) | (uint32_t)low);
  }
  return 0;
}

xaios_admin_result_t admin_control_auth_remove(
    const char *fingerprint_text, const char *actor, uint32_t actor_role,
    uint64_t operation_id, xaios_admin_key_view_t *removed) {
  uint8_t fingerprint[32];
  bytes_zero(fingerprint, sizeof(fingerprint));
  xaios_admin_result_t begin = begin_mutation(
      actor, actor_role, XAIOS_ADMIN_ROLE_ADMIN, operation_id,
      "auth.key.remove");
  if (begin != XAIOS_ADMIN_RESULT_OK) return begin;
  if (parse_fingerprint(fingerprint_text, fingerprint) != 0) {
    return abort_and_audit(actor, actor_role, operation_id,
                           "auth.key.remove", XAIOS_ADMIN_RESULT_INVALID);
  }
  xaios_admin_auth_database_t *database =
      (xaios_admin_auth_database_t *)kheap_alloc(sizeof(*database), 16U);
  if (database == 0) {
    return abort_and_audit(actor, actor_role, operation_id,
                           "auth.key.remove",
                           XAIOS_ADMIN_RESULT_NO_MEMORY);
  }
  xaios_admin_result_t result = load_auth_database(database);
  uint32_t found = UINT32_MAX;
  uint32_t administrators = 0U;
  if (result == XAIOS_ADMIN_RESULT_OK) {
    for (uint32_t i = 0U; i < database->key_count; ++i) {
      if (database->keys[i].role == XAIOS_ADMIN_ROLE_ADMIN) ++administrators;
      if (bytes_equal(database->keys[i].fingerprint, fingerprint, 32U)) {
        found = i;
      }
    }
    if (found == UINT32_MAX) result = XAIOS_ADMIN_RESULT_NOT_FOUND;
    else if (database->keys[found].role == XAIOS_ADMIN_ROLE_ADMIN &&
             administrators <= 1U) result = XAIOS_ADMIN_RESULT_DENIED;
    else if (database->revoked_count >= XAIOS_ADMIN_MAX_REVOKED_KEYS)
      result = XAIOS_ADMIN_RESULT_NO_MEMORY;
  }
  if (result != XAIOS_ADMIN_RESULT_OK) {
    kheap_free(database);
    return abort_and_audit(actor, actor_role, operation_id,
                           "auth.key.remove", result);
  }
  if (removed != 0) {
    bytes_zero(removed, sizeof(*removed));
    bytes_copy(removed->fingerprint, database->keys[found].fingerprint, 32U);
    string_copy(removed->principal, sizeof(removed->principal),
                database->keys[found].principal);
    removed->role = database->keys[found].role;
  }
  bytes_copy(database->revoked[database->revoked_count++], fingerprint, 32U);
  for (uint32_t i = found + 1U; i < database->key_count; ++i) {
    database->keys[i - 1U] = database->keys[i];
  }
  --database->key_count;
  bytes_zero(&database->keys[database->key_count],
             sizeof(database->keys[0]));
  ++database->generation;
  database->checksum = auth_checksum(database);
  if (database->checksum == 0U ||
      xaiboot_fs_write(XAIOS_ADMIN_AUTH_PATH, database, sizeof(*database)) !=
          XAIOS_OK) {
    kheap_free(database);
    return abort_and_audit(actor, actor_role, operation_id,
                           "auth.key.remove", XAIOS_ADMIN_RESULT_IO);
  }
  result = finish_mutation(actor, actor_role, operation_id,
                           "auth.key.remove", fingerprint);
  kheap_free(database);
  if (result != XAIOS_ADMIN_RESULT_OK) {
    return audit_only(actor, actor_role, operation_id, "auth.key.remove",
                      result);
  }
  return result;
}

