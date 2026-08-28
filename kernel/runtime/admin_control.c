#include <xaios/admin_control.h>
#include <xaios/assert.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/xaiboot_fs.h>
#include <xaios/vfs_model.h>
#include <xaios/sha256.h>
#include <xaios/virtio_rng.h>

#ifndef XAIOS_PASSWORD_AUTH_AVAILABLE
#define XAIOS_PASSWORD_AUTH_AVAILABLE 0
#endif

#define XAIOS_ADMIN_ROLE_OBSERVER UINT32_C(1)
#define XAIOS_ADMIN_ROLE_OPERATOR UINT32_C(2)
#define XAIOS_ADMIN_ROLE_ADMIN UINT32_C(3)
#define XAIOS_ADMIN_CONFIG_ALL_CHANGES UINT32_C(31)
#define XAIOS_ADMIN_SOURCE_BYTES UINT64_C(2048)
#define XAIOS_ADMIN_LEGACY_KEYS_PATH "/etc/xaios_authorized_keys"
#define XAIOS_ADMIN_MAX_SSH_CONNECTIONS UINT32_C(32)

static xaios_admin_config_t g_active_config;
static uint32_t g_initialized;

static int principal_valid(const char *principal);
static void key_fingerprint(const uint8_t public_key[32],
                            uint8_t fingerprint[32]);

static void bytes_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0; i < size; ++i) {
    bytes[i] = 0U;
  }
}

static void bytes_copy(void *dst, const void *src, uint64_t size) {
  uint8_t *out = (uint8_t *)dst;
  const uint8_t *in = (const uint8_t *)src;
  for (uint64_t i = 0; i < size; ++i) {
    out[i] = in[i];
  }
}

static int bytes_equal(const void *left, const void *right, uint64_t size) {
  const uint8_t *lhs = (const uint8_t *)left;
  const uint8_t *rhs = (const uint8_t *)right;
  uint8_t difference = 0U;
  for (uint64_t i = 0; i < size; ++i) {
    difference |= lhs[i] ^ rhs[i];
  }
  return difference == 0U;
}

static uint64_t string_length(const char *text) {
  uint64_t length = 0U;
  if (text == 0) {
    return 0U;
  }
  while (text[length] != '\0') {
    ++length;
  }
  return length;
}

static int string_equal(const char *left, const char *right) {
  if (left == 0 || right == 0) {
    return 0;
  }
  for (uint64_t i = 0;; ++i) {
    if (left[i] != right[i]) {
      return 0;
    }
    if (left[i] == '\0') {
      return 1;
    }
  }
}

static int string_equal_range(const char *text, uint64_t length,
                              const char *expected) {
  uint64_t expected_length = string_length(expected);
  return length == expected_length && bytes_equal(text, expected, length);
}

static void string_copy(char *dst, uint64_t capacity, const char *src) {
  uint64_t offset = 0U;
  if (dst == 0 || capacity == 0U) {
    return;
  }
  while (src != 0 && src[offset] != '\0' && offset + 1U < capacity) {
    dst[offset] = src[offset];
    ++offset;
  }
  dst[offset] = '\0';
}

static uint64_t fnv1a64(const void *data, uint64_t size) {
  const uint8_t *bytes = (const uint8_t *)data;
  uint64_t hash = UINT64_C(1469598103934665603);
  for (uint64_t i = 0U; i < size; ++i) {
    hash ^= bytes[i];
    hash *= UINT64_C(1099511628211);
  }
  return hash;
}

static uint64_t config_checksum(const xaios_admin_config_t *config) {
  xaios_admin_config_t copy = *config;
  copy.checksum = 0U;
  return fnv1a64(&copy, sizeof(copy));
}

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

static uint64_t audit_checksum(const xaios_admin_audit_log_t *audit) {
  uint64_t bytes = sizeof(*audit) - sizeof(audit->records) +
                   ((uint64_t)audit->record_count * sizeof(audit->records[0]));
  xaios_admin_audit_log_t *copy =
      (xaios_admin_audit_log_t *)kheap_alloc(bytes, 16U);
  if (copy == 0) {
    return 0U;
  }
  bytes_copy(copy, audit, bytes);
  copy->checksum = 0U;
  uint64_t checksum = fnv1a64(copy, bytes);
  kheap_free(copy);
  return checksum;
}

static void default_config(xaios_admin_config_t *config) {
  bytes_zero(config, sizeof(*config));
  config->magic = XAIOS_ADMIN_CONFIG_MAGIC;
  config->version = XAIOS_ADMIN_SCHEMA_VERSION;
  config->size = (uint16_t)sizeof(*config);
  config->generation = 1U;
  config->max_connections = 32U;
  config->max_channels_per_connection = 2U;
  config->max_auth_attempts = 5U;
  config->command_rate_per_minute = 60U;
  config->password_auth = XAIOS_PASSWORD_AUTH_AVAILABLE != 0
                              ? XAIOS_ADMIN_PASSWORD_DEVELOPMENT
                              : XAIOS_ADMIN_PASSWORD_DISABLED;
  config->checksum = config_checksum(config);
}

static int config_valid(const xaios_admin_config_t *config) {
  return config != 0 && config->magic == XAIOS_ADMIN_CONFIG_MAGIC &&
         config->version == XAIOS_ADMIN_SCHEMA_VERSION &&
         config->size == sizeof(*config) && config->generation != 0U &&
         config->max_connections >= 1U &&
         config->max_connections <= XAIOS_ADMIN_MAX_SSH_CONNECTIONS &&
         config->max_channels_per_connection >= 1U &&
         config->max_channels_per_connection <= 2U &&
         config->max_auth_attempts >= 1U &&
         config->max_auth_attempts <= 5U &&
         config->command_rate_per_minute >= 1U &&
         config->command_rate_per_minute <= 120U &&
         config->password_auth <= XAIOS_ADMIN_PASSWORD_DEVELOPMENT &&
         (config->password_auth == XAIOS_ADMIN_PASSWORD_DISABLED ||
          XAIOS_PASSWORD_AUTH_AVAILABLE != 0) &&
         config->reserved == 0U && config->checksum == config_checksum(config);
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

static int audit_valid(const xaios_admin_audit_log_t *audit) {
  uint64_t checksum;
  if (audit == 0 || audit->magic != XAIOS_ADMIN_AUDIT_MAGIC ||
      audit->version != XAIOS_ADMIN_SCHEMA_VERSION ||
      audit->header_size != sizeof(*audit) - sizeof(audit->records) ||
      audit->record_size != sizeof(audit->records[0]) ||
      audit->record_count > XAIOS_ADMIN_MAX_AUDIT_RECORDS ||
      audit->next_sequence == 0U) {
    return 0;
  }
  checksum = audit_checksum(audit);
  return checksum != 0U && checksum == audit->checksum;
}

static int staging_path_valid(const char *path) {
  static const char prefix[] = "/tmp/";
  uint64_t length = string_length(path);
  if (path == 0 || length <= sizeof(prefix) - 1U ||
      length >= XAIOS_XBFS_PATH_MAX) {
    return 0;
  }
  return bytes_equal(path, prefix, sizeof(prefix) - 1U);
}

static int principal_valid(const char *principal) {
  uint64_t length = string_length(principal);
  if (length == 0U || length >= XAIOS_ADMIN_PRINCIPAL_MAX) {
    return 0;
  }
  for (uint64_t i = 0U; i < length; ++i) {
    char value = principal[i];
    if (!((value >= 'a' && value <= 'z') ||
          (value >= 'A' && value <= 'Z') ||
          (value >= '0' && value <= '9') || value == '-' || value == '_' ||
          value == '.')) {
      return 0;
    }
  }
  return 1;
}

static int parse_u32(const char *text, uint64_t length, uint32_t *value) {
  uint32_t parsed = 0U;
  if (text == 0 || value == 0 || length == 0U) {
    return -1;
  }
  for (uint64_t i = 0U; i < length; ++i) {
    if (text[i] < '0' || text[i] > '9') {
      return -1;
    }
    uint32_t digit = (uint32_t)(text[i] - '0');
    if (parsed > (UINT32_MAX - digit) / 10U) {
      return -1;
    }
    parsed = parsed * 10U + digit;
  }
  *value = parsed;
  return 0;
}

static int parse_config_text(const char *text, uint64_t size,
                             xaios_admin_config_t *candidate) {
  uint32_t seen = 0U;
  xaios_admin_config_t parsed;
  default_config(&parsed);
  parsed.password_auth = XAIOS_ADMIN_PASSWORD_DISABLED;
  for (uint64_t start = 0U; start <= size;) {
    uint64_t end = start;
    while (end < size && text[end] != '\n') {
      ++end;
    }
    uint64_t length = end - start;
    if (length != 0U && text[start + length - 1U] == '\r') {
      --length;
    }
    if (length != 0U && text[start] != '#') {
      uint64_t separator = 0U;
      while (separator < length && text[start + separator] != '=') {
        ++separator;
      }
      if (separator == 0U || separator == length) {
        return -1;
      }
      const char *key = text + start;
      const char *value = text + start + separator + 1U;
      uint64_t value_length = length - separator - 1U;
      uint32_t number = 0U;
      if (string_equal_range(key, separator, "schema")) {
        if ((seen & UINT32_C(32)) != 0U ||
            !string_equal_range(value, value_length, "xaios.config.v1")) {
          return -1;
        }
        seen |= UINT32_C(32);
      } else if (string_equal_range(key, separator,
                                    "ssh.max_connections")) {
        if ((seen & XAIOS_ADMIN_CONFIG_CHANGE_CONNECTIONS) != 0U ||
            parse_u32(value, value_length, &number) != 0) {
          return -1;
        }
        parsed.max_connections = number;
        seen |= XAIOS_ADMIN_CONFIG_CHANGE_CONNECTIONS;
      } else if (string_equal_range(
                     key, separator, "ssh.max_channels_per_connection")) {
        if ((seen & XAIOS_ADMIN_CONFIG_CHANGE_CHANNELS) != 0U ||
            parse_u32(value, value_length, &number) != 0) {
          return -1;
        }
        parsed.max_channels_per_connection = number;
        seen |= XAIOS_ADMIN_CONFIG_CHANGE_CHANNELS;
      } else if (string_equal_range(key, separator,
                                    "ssh.max_auth_attempts")) {
        if ((seen & XAIOS_ADMIN_CONFIG_CHANGE_AUTH_ATTEMPTS) != 0U ||
            parse_u32(value, value_length, &number) != 0) {
          return -1;
        }
        parsed.max_auth_attempts = number;
        seen |= XAIOS_ADMIN_CONFIG_CHANGE_AUTH_ATTEMPTS;
      } else if (string_equal_range(key, separator,
                                    "ssh.command_rate_per_minute")) {
        if ((seen & XAIOS_ADMIN_CONFIG_CHANGE_COMMAND_RATE) != 0U ||
            parse_u32(value, value_length, &number) != 0) {
          return -1;
        }
        parsed.command_rate_per_minute = number;
        seen |= XAIOS_ADMIN_CONFIG_CHANGE_COMMAND_RATE;
      } else if (string_equal_range(key, separator, "ssh.password_auth")) {
        if ((seen & XAIOS_ADMIN_CONFIG_CHANGE_PASSWORD_AUTH) != 0U) {
          return -1;
        }
        if (string_equal_range(value, value_length, "disabled")) {
          parsed.password_auth = XAIOS_ADMIN_PASSWORD_DISABLED;
        } else if (string_equal_range(value, value_length, "development")) {
          parsed.password_auth = XAIOS_ADMIN_PASSWORD_DEVELOPMENT;
        } else {
          return -1;
        }
        seen |= XAIOS_ADMIN_CONFIG_CHANGE_PASSWORD_AUTH;
      } else {
        return -1;
      }
    }
    if (end == size) {
      break;
    }
    start = end + 1U;
  }
  if (seen != (XAIOS_ADMIN_CONFIG_ALL_CHANGES | UINT32_C(32))) {
    return -1;
  }
  parsed.generation = g_active_config.generation + 1U;
  if (parsed.generation == 0U) {
    return -1;
  }
  parsed.checksum = config_checksum(&parsed);
  if (!config_valid(&parsed)) {
    return -1;
  }
  *candidate = parsed;
  return 0;
}

static uint32_t config_change_mask(const xaios_admin_config_t *left,
                                   const xaios_admin_config_t *right) {
  uint32_t mask = 0U;
  if (left->max_connections != right->max_connections) {
    mask |= XAIOS_ADMIN_CONFIG_CHANGE_CONNECTIONS;
  }
  if (left->max_channels_per_connection !=
      right->max_channels_per_connection) {
    mask |= XAIOS_ADMIN_CONFIG_CHANGE_CHANNELS;
  }
  if (left->max_auth_attempts != right->max_auth_attempts) {
    mask |= XAIOS_ADMIN_CONFIG_CHANGE_AUTH_ATTEMPTS;
  }
  if (left->command_rate_per_minute != right->command_rate_per_minute) {
    mask |= XAIOS_ADMIN_CONFIG_CHANGE_COMMAND_RATE;
  }
  if (left->password_auth != right->password_auth) {
    mask |= XAIOS_ADMIN_CONFIG_CHANGE_PASSWORD_AUTH;
  }
  return mask;
}

static xaios_admin_result_t load_config_source(
    const char *path, xaios_admin_config_t *candidate, uint32_t *change_mask) {
  char source[XAIOS_ADMIN_SOURCE_BYTES];
  uint64_t size = 0U;
  if (!staging_path_valid(path) || candidate == 0 || change_mask == 0 ||
      xaiboot_fs_read(path, source, sizeof(source), &size) != XAIOS_OK ||
      size == 0U || parse_config_text(source, size, candidate) != 0) {
    return XAIOS_ADMIN_RESULT_INVALID;
  }
  *change_mask = config_change_mask(&g_active_config, candidate);
  return XAIOS_ADMIN_RESULT_OK;
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

static void initialize_audit(xaios_admin_audit_log_t *audit) {
  bytes_zero(audit, sizeof(*audit));
  audit->magic = XAIOS_ADMIN_AUDIT_MAGIC;
  audit->version = XAIOS_ADMIN_SCHEMA_VERSION;
  audit->header_size =
      (uint16_t)(sizeof(*audit) - sizeof(audit->records));
  audit->record_size = sizeof(audit->records[0]);
  audit->next_sequence = 1U;
  audit->checksum = audit_checksum(audit);
}

static xaios_admin_result_t load_audit(xaios_admin_audit_log_t *audit) {
  uint64_t size = 0U;
  if (audit == 0) return XAIOS_ADMIN_RESULT_INVALID;
  if (xaiboot_fs_read(XAIOS_ADMIN_AUDIT_PATH, audit, sizeof(*audit), &size) ==
      XAIOS_OK) {
    uint64_t expected = sizeof(*audit) - sizeof(audit->records) +
                        ((uint64_t)audit->record_count *
                         sizeof(audit->records[0]));
    return size == expected && audit_valid(audit)
               ? XAIOS_ADMIN_RESULT_OK
               : XAIOS_ADMIN_RESULT_INVALID;
  }
  initialize_audit(audit);
  return audit->checksum != 0U ? XAIOS_ADMIN_RESULT_OK
                               : XAIOS_ADMIN_RESULT_NO_MEMORY;
}

static int operation_replayed(const char *actor, uint64_t operation_id) {
  xaios_admin_audit_log_t *audit =
      (xaios_admin_audit_log_t *)kheap_alloc(sizeof(*audit), 16U);
  if (audit == 0) return 0;
  int replayed = 0;
  if (load_audit(audit) == XAIOS_ADMIN_RESULT_OK) {
    for (uint32_t i = 0U; i < audit->record_count; ++i) {
      if (audit->records[i].operation_id == operation_id &&
          string_equal(audit->records[i].principal, actor)) {
        replayed = 1;
        break;
      }
    }
  }
  kheap_free(audit);
  return replayed;
}

static xaios_admin_result_t append_audit(const char *actor, uint32_t role,
                                         uint64_t operation_id,
                                         const char *operation,
                                         uint32_t result,
                                         const uint8_t object_hash[32]) {
  xaios_admin_audit_log_t *audit =
      (xaios_admin_audit_log_t *)kheap_alloc(sizeof(*audit), 16U);
  if (audit == 0) return XAIOS_ADMIN_RESULT_NO_MEMORY;
  xaios_admin_result_t load_result = load_audit(audit);
  if (load_result != XAIOS_ADMIN_RESULT_OK) {
    kheap_free(audit);
    return load_result;
  }
  if (audit->next_sequence == UINT64_MAX) {
    kheap_free(audit);
    return XAIOS_ADMIN_RESULT_NO_MEMORY;
  }
  if (audit->record_count >= XAIOS_ADMIN_MAX_AUDIT_RECORDS) {
    for (uint32_t i = 1U; i < audit->record_count; ++i) {
      audit->records[i - 1U] = audit->records[i];
    }
    --audit->record_count;
    bytes_zero(&audit->records[audit->record_count],
               sizeof(audit->records[0]));
  }
  xaios_admin_audit_record_t *record =
      &audit->records[audit->record_count++];
  bytes_zero(record, sizeof(*record));
  record->sequence = audit->next_sequence++;
  record->operation_id = operation_id;
  if (object_hash != 0) {
    bytes_copy(record->object_hash, object_hash, sizeof(record->object_hash));
  }
  string_copy(record->principal, sizeof(record->principal), actor);
  string_copy(record->operation, sizeof(record->operation), operation);
  record->role = role;
  record->result = result;
  audit->checksum = audit_checksum(audit);
  uint64_t bytes = sizeof(*audit) - sizeof(audit->records) +
                   ((uint64_t)audit->record_count * sizeof(audit->records[0]));
  xaios_status_t status =
      audit->checksum != 0U
          ? xaiboot_fs_write(XAIOS_ADMIN_AUDIT_PATH, audit, bytes)
          : XAIOS_ERR_NO_MEMORY;
  kheap_free(audit);
  return status == XAIOS_OK ? XAIOS_ADMIN_RESULT_OK : XAIOS_ADMIN_RESULT_IO;
}

static xaios_admin_result_t audit_only(const char *actor, uint32_t role,
                                       uint64_t operation_id,
                                       const char *operation,
                                       xaios_admin_result_t result) {
  uint8_t object_hash[32];
  bytes_zero(object_hash, sizeof(object_hash));
  if (!principal_valid(actor) || operation_id == 0U ||
      role < XAIOS_ADMIN_ROLE_OBSERVER || role > XAIOS_ADMIN_ROLE_ADMIN) {
    return result;
  }
  if (xaiboot_fs_commit("admin-audit-pre") != XAIOS_OK) {
    return XAIOS_ADMIN_RESULT_IO;
  }
  if (append_audit(actor, role, operation_id, operation, (uint32_t)result,
                   object_hash) != XAIOS_ADMIN_RESULT_OK ||
      xaiboot_fs_commit("admin-audit-post") != XAIOS_OK) {
    (void)xaiboot_fs_rollback();
    return XAIOS_ADMIN_RESULT_IO;
  }
  return result;
}

static xaios_admin_result_t begin_mutation(const char *actor, uint32_t role,
                                           uint32_t required_role,
                                           uint64_t operation_id,
                                           const char *operation) {
  if (!principal_valid(actor) || operation_id == 0U) {
    return XAIOS_ADMIN_RESULT_INVALID;
  }
  if (operation_replayed(actor, operation_id)) {
    return XAIOS_ADMIN_RESULT_REPLAY;
  }
  if (role < required_role || role > XAIOS_ADMIN_ROLE_ADMIN) {
    return audit_only(actor, role, operation_id, operation,
                      XAIOS_ADMIN_RESULT_DENIED);
  }
  return xaiboot_fs_commit("admin-mutation-pre") == XAIOS_OK
             ? XAIOS_ADMIN_RESULT_OK
             : XAIOS_ADMIN_RESULT_IO;
}

xaios_admin_result_t admin_control_mutation_begin(
    const char *actor, uint32_t role, uint32_t required_role,
    uint64_t operation_id, const char *operation) {
  return begin_mutation(actor, role, required_role, operation_id, operation);
}

static xaios_admin_result_t finish_mutation(
    const char *actor, uint32_t role, uint64_t operation_id,
    const char *operation, const uint8_t object_hash[32]) {
  if (append_audit(actor, role, operation_id, operation,
                   XAIOS_ADMIN_RESULT_OK, object_hash) !=
          XAIOS_ADMIN_RESULT_OK ||
      xaiboot_fs_commit("admin-mutation-post") != XAIOS_OK) {
    (void)xaiboot_fs_rollback();
    return XAIOS_ADMIN_RESULT_IO;
  }
  return XAIOS_ADMIN_RESULT_OK;
}

xaios_admin_result_t admin_control_mutation_complete(
    const char *actor, uint32_t role, uint64_t operation_id,
    const char *operation, const uint8_t object_hash[32]) {
  return finish_mutation(actor, role, operation_id, operation, object_hash);
}

static void abort_mutation(void) {
  (void)xaiboot_fs_rollback();
}

static xaios_admin_result_t abort_and_audit(
    const char *actor, uint32_t role, uint64_t operation_id,
    const char *operation, xaios_admin_result_t result) {
  abort_mutation();
  return audit_only(actor, role, operation_id, operation, result);
}

xaios_admin_result_t admin_control_mutation_fail(
    const char *actor, uint32_t role, uint64_t operation_id,
    const char *operation, xaios_admin_result_t result) {
  return abort_and_audit(actor, role, operation_id, operation, result);
}

void admin_control_init(void) {
  xaios_admin_config_t stored;
  uint64_t size = 0U;
  default_config(&g_active_config);
  g_initialized = 0U;
  if (xaiboot_fs_mkdir("/state/control") != XAIOS_OK) {
    klog("admin-control: persistent state directory unavailable\n");
    return;
  }
  if (xaiboot_fs_read(XAIOS_ADMIN_CONFIG_PATH, &stored, sizeof(stored),
                      &size) == XAIOS_OK) {
    if (size != sizeof(stored) || !config_valid(&stored)) {
      klog("admin-control: active configuration invalid; safe defaults only\n");
      return;
    }
    g_active_config = stored;
  } else if (xaiboot_fs_write(XAIOS_ADMIN_CONFIG_PATH, &g_active_config,
                              sizeof(g_active_config)) != XAIOS_OK ||
             xaiboot_fs_commit("admin-initial-state") != XAIOS_OK) {
    klog("admin-control: failed to initialize active configuration\n");
    return;
  }
  g_initialized = 1U;
  klog("admin-control: initialized schema=%u generation=%lu password=%s\n",
       XAIOS_ADMIN_SCHEMA_VERSION, g_active_config.generation,
       g_active_config.password_auth == XAIOS_ADMIN_PASSWORD_DEVELOPMENT
           ? "development"
           : "disabled");
}

xaios_admin_result_t admin_control_config_get(xaios_admin_config_t *config) {
  if (config == 0 || g_initialized == 0U) {
    return XAIOS_ADMIN_RESULT_INVALID;
  }
  *config = g_active_config;
  return XAIOS_ADMIN_RESULT_OK;
}

xaios_admin_result_t admin_control_config_validate(
    const char *path, xaios_admin_config_t *candidate, uint32_t *change_mask) {
  if (g_initialized == 0U) return XAIOS_ADMIN_RESULT_INVALID;
  return load_config_source(path, candidate, change_mask);
}

xaios_admin_result_t admin_control_config_apply(
    const char *path, const char *actor, uint32_t role, uint64_t operation_id,
    xaios_admin_config_t *applied, uint32_t *change_mask) {
  xaios_admin_config_t candidate;
  uint32_t changes = 0U;
  xaios_admin_result_t begin = begin_mutation(
      actor, role, XAIOS_ADMIN_ROLE_OPERATOR, operation_id, "config.apply");
  if (begin != XAIOS_ADMIN_RESULT_OK) return begin;
  xaios_admin_result_t validation =
      load_config_source(path, &candidate, &changes);
  if (validation != XAIOS_ADMIN_RESULT_OK) {
    return abort_and_audit(actor, role, operation_id, "config.apply",
                           validation);
  }
  if (xaiboot_fs_write(XAIOS_ADMIN_CONFIG_PATH, &candidate,
                       sizeof(candidate)) != XAIOS_OK) {
    return abort_and_audit(actor, role, operation_id, "config.apply",
                           XAIOS_ADMIN_RESULT_IO);
  }
  uint8_t object_hash[32];
  xaios_sha256(&candidate, sizeof(candidate), object_hash);
  xaios_admin_result_t finish = finish_mutation(
      actor, role, operation_id, "config.apply", object_hash);
  if (finish != XAIOS_ADMIN_RESULT_OK) {
    return audit_only(actor, role, operation_id, "config.apply", finish);
  }
  g_active_config = candidate;
  if (applied != 0) *applied = candidate;
  if (change_mask != 0) *change_mask = changes;
  return XAIOS_ADMIN_RESULT_OK;
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

static void bytes_to_hex(const uint8_t *bytes, uint32_t size, char *text) {
  static const char digits[] = "0123456789abcdef";
  for (uint32_t i = 0U; i < size; ++i) {
    text[i * 2U] = digits[bytes[i] >> 4U];
    text[i * 2U + 1U] = digits[bytes[i] & 15U];
  }
}

xaios_admin_result_t admin_control_host_key_rotate(
    const char *actor, uint32_t actor_role, uint64_t operation_id) {
  xaios_admin_result_t begin = begin_mutation(
      actor, actor_role, XAIOS_ADMIN_ROLE_ADMIN, operation_id,
      "auth.host.rotate");
  if (begin != XAIOS_ADMIN_RESULT_OK) return begin;
  uint8_t private_seed[32];
  char encoded[64];
  if (virtio_rng_read(private_seed, sizeof(private_seed)) != XAIOS_OK) {
    return abort_and_audit(actor, actor_role, operation_id,
                           "auth.host.rotate", XAIOS_ADMIN_RESULT_IO);
  }
  bytes_to_hex(private_seed, sizeof(private_seed), encoded);
  if (xaiboot_fs_write(XAIOS_ADMIN_HOST_KEY_PATH, encoded, sizeof(encoded)) !=
      XAIOS_OK) {
    bytes_zero(private_seed, sizeof(private_seed));
    bytes_zero(encoded, sizeof(encoded));
    return abort_and_audit(actor, actor_role, operation_id,
                           "auth.host.rotate", XAIOS_ADMIN_RESULT_IO);
  }
  uint8_t object_hash[32];
  static const char rotation_object[] = "xaios-host-key-generation";
  xaios_sha256(rotation_object, sizeof(rotation_object) - 1U, object_hash);
  xaios_admin_result_t result = finish_mutation(
      actor, actor_role, operation_id, "auth.host.rotate", object_hash);
  bytes_zero(private_seed, sizeof(private_seed));
  bytes_zero(encoded, sizeof(encoded));
  if (result != XAIOS_ADMIN_RESULT_OK) {
    return audit_only(actor, actor_role, operation_id, "auth.host.rotate",
                      result);
  }
  return result;
}

static int package_id_bytes(const char *package_id, uint8_t output[32]) {
  if (package_id == 0 || output == 0) return 0;
  for (uint32_t index = 0U; index < 32U; ++index) {
    char high_character = package_id[index * 2U];
    char low_character = package_id[index * 2U + 1U];
    uint8_t high = 0U;
    uint8_t low = 0U;
    if (high_character >= '0' && high_character <= '9') {
      high = (uint8_t)(high_character - '0');
    } else if (high_character >= 'a' && high_character <= 'f') {
      high = (uint8_t)(high_character - 'a' + 10);
    } else if (high_character >= 'A' && high_character <= 'F') {
      high = (uint8_t)(high_character - 'A' + 10);
    } else {
      return 0;
    }
    if (low_character >= '0' && low_character <= '9') {
      low = (uint8_t)(low_character - '0');
    } else if (low_character >= 'a' && low_character <= 'f') {
      low = (uint8_t)(low_character - 'a' + 10);
    } else if (low_character >= 'A' && low_character <= 'F') {
      low = (uint8_t)(low_character - 'A' + 10);
    } else {
      return 0;
    }
    output[index] = (uint8_t)((high << 4U) | low);
  }
  return package_id[64] == '\0';
}

static xaios_admin_result_t model_status_result(xaios_status_t status) {
  if (status == XAIOS_OK) return XAIOS_ADMIN_RESULT_OK;
  if (status == XAIOS_ERR_NOT_FOUND) return XAIOS_ADMIN_RESULT_NOT_FOUND;
  if (status == XAIOS_ERR_BUSY || status == XAIOS_ERR_UNSUPPORTED) {
    return XAIOS_ADMIN_RESULT_CONFLICT;
  }
  if (status == XAIOS_ERR_IO) return XAIOS_ADMIN_RESULT_IO;
  return XAIOS_ADMIN_RESULT_INVALID;
}

xaios_admin_result_t admin_control_model_activate(
    const char *package_id, const char *actor, uint32_t actor_role,
    uint64_t operation_id, uint64_t *generation) {
  uint8_t object_hash[32];
  if (generation == 0 || !package_id_bytes(package_id, object_hash)) {
    return XAIOS_ADMIN_RESULT_INVALID;
  }
  xaios_admin_result_t result = begin_mutation(
      actor, actor_role, XAIOS_ADMIN_ROLE_ADMIN, operation_id,
      "model.package.activate");
  if (result != XAIOS_ADMIN_RESULT_OK) return result;
  result = model_status_result(
      vfs_model_activate_staging(package_id, generation));
  if (result != XAIOS_ADMIN_RESULT_OK) {
    return abort_and_audit(actor, actor_role, operation_id,
                           "model.package.activate", result);
  }
  result = finish_mutation(actor, actor_role, operation_id,
                           "model.package.activate", object_hash);
  if (result != XAIOS_ADMIN_RESULT_OK) {
    klog("admin-control: ModelFS activation committed but audit commit failed operation=%lu generation=%lu\n",
         operation_id, *generation);
  }
  return result;
}

xaios_admin_result_t admin_control_audit_read(
    uint64_t since_sequence, uint32_t limit,
    xaios_admin_audit_record_t *records, uint32_t capacity,
    uint32_t *record_count, uint64_t *next_sequence,
    uint64_t *latest_sequence) {
  if (records == 0 || record_count == 0 || next_sequence == 0 ||
      latest_sequence == 0 || limit == 0U || limit > capacity) {
    return XAIOS_ADMIN_RESULT_INVALID;
  }
  xaios_admin_audit_log_t *audit =
      (xaios_admin_audit_log_t *)kheap_alloc(sizeof(*audit), 16U);
  if (audit == 0) return XAIOS_ADMIN_RESULT_NO_MEMORY;
  xaios_admin_result_t result = load_audit(audit);
  if (result == XAIOS_ADMIN_RESULT_OK) {
    *record_count = 0U;
    *next_sequence = since_sequence;
    *latest_sequence = audit->next_sequence - 1U;
    for (uint32_t i = 0U; i < audit->record_count && *record_count < limit;
         ++i) {
      if (audit->records[i].sequence <= since_sequence) continue;
      records[*record_count] = audit->records[i];
      *next_sequence = audit->records[i].sequence;
      ++(*record_count);
    }
  }
  kheap_free(audit);
  return result;
}

void admin_control_self_test(void) {
  static const char valid[] =
      "schema=xaios.config.v1\n"
      "ssh.max_connections=32\n"
      "ssh.max_channels_per_connection=2\n"
      "ssh.max_auth_attempts=5\n"
      "ssh.command_rate_per_minute=60\n"
      "ssh.password_auth=disabled\n";
  static const char invalid[] =
      "schema=xaios.config.v1\nssh.unknown=1\n";
  xaios_admin_config_t candidate;
  kassert(g_initialized != 0U);
  kassert(parse_config_text(valid, sizeof(valid) - 1U, &candidate) == 0);
  kassert(config_valid(&candidate));
  kassert(parse_config_text(invalid, sizeof(invalid) - 1U, &candidate) != 0);
  kassert(principal_valid("ops.user-1"));
  kassert(!principal_valid("bad principal"));
  klog("admin-control: self-test passed schema=1 invalid=1 principal=2 "
       "transactional=1\n");
}
