#include "sshd.h"
#include "ssh_connection.h"
#include "ssh_crypto.h"
#include "ssh_protocol.h"
#include "ssh_channel.h"
#include "ssh_host_key.h"
#include "ssh_utils.h"
#include "tweetnacl_subset.h"
#include <xaios_user.h>
#include <stdarg.h>

#ifndef XAIOS_PASSWORD_AUTH_AVAILABLE
#define XAIOS_PASSWORD_AUTH_AVAILABLE 0
#endif

static sshd_user_t g_users[SSHD_MAX_USERS];
static uint32_t g_user_count = 0;

static sshd_rate_limit_entry_t g_rate_limits[SSHD_RATE_LIMIT_MAX_ENTRIES];
static uint32_t g_rate_limit_count = 0;

static sshd_stats_t g_server_stats;
static xaios_admin_config_user_t g_runtime_config;
static uint32_t g_password_auth_enabled;

static uint64_t fnv1a64_zero_range(const void *data, uint64_t size,
                                   uint64_t zero_offset,
                                   uint64_t zero_size) {
  const uint8_t *bytes = (const uint8_t *)data;
  uint64_t hash = UINT64_C(1469598103934665603);
  for (uint64_t i = 0U; i < size; ++i) {
    uint8_t value = i >= zero_offset && i - zero_offset < zero_size
                        ? 0U
                        : bytes[i];
    hash ^= value;
    hash *= UINT64_C(1099511628211);
  }
  return hash;
}

static int read_exact_file(const char *path, void *buffer, uint64_t size) {
  xaios_mfs_stat_user_t stat;
  if (path == 0 || buffer == 0 || size == 0U ||
      xaios_fs_stat(path, &stat) != 0 || stat.size != size) {
    return -1;
  }
  int fd = xaios_fs_open(path, XAIOS_MFS_OPEN_READ);
  if (fd < 0) return -1;
  int bytes = xaios_fs_read(fd, buffer, size);
  int close_result = xaios_fs_close(fd);
  return bytes == (int)size && close_result == 0 ? 0 : -1;
}

static int config_record_valid(const xaios_admin_config_user_t *config) {
  uint64_t checksum_offset =
      (uint64_t)((const uint8_t *)&config->checksum -
                 (const uint8_t *)config);
  return config->magic == XAIOS_ADMIN_CONFIG_MAGIC &&
         config->version == XAIOS_ADMIN_SCHEMA_VERSION &&
         config->size == sizeof(*config) && config->generation != 0U &&
         config->max_connections >= 1U &&
         config->max_connections <= SSH_MAX_CONNECTIONS &&
         config->max_channels_per_connection >= 1U &&
         config->max_channels_per_connection <= SSH_CHANNELS_PER_CONNECTION &&
         config->max_auth_attempts >= 1U &&
         config->max_auth_attempts <= SSHD_MAX_AUTH_ATTEMPTS &&
         config->command_rate_per_minute >= 1U &&
         config->command_rate_per_minute <= 120U &&
         config->password_auth <= XAIOS_ADMIN_PASSWORD_DEVELOPMENT &&
         (config->password_auth == XAIOS_ADMIN_PASSWORD_DISABLED ||
          XAIOS_PASSWORD_AUTH_AVAILABLE != 0) &&
         config->reserved == 0U &&
         config->checksum ==
             fnv1a64_zero_range(config, sizeof(*config), checksum_offset,
                                sizeof(config->checksum));
}

static int load_runtime_config(void) {
  xaios_admin_config_user_t config;
  if (read_exact_file(XAIOS_ADMIN_CONFIG_PATH, &config, sizeof(config)) != 0 ||
      !config_record_valid(&config)) {
    ssh_mem_zero(&config, sizeof(config));
    return -1;
  }
  g_runtime_config = config;
  g_password_auth_enabled =
      XAIOS_PASSWORD_AUTH_AVAILABLE != 0 &&
      config.password_auth == XAIOS_ADMIN_PASSWORD_DEVELOPMENT;
  return 0;
}

uint32_t sshd_max_channels_per_connection(void) {
  return g_runtime_config.max_channels_per_connection;
}

uint32_t sshd_command_rate_per_minute(void) {
  return g_runtime_config.command_rate_per_minute;
}

static void sha256_update_u32(sha256_ctx_t *context, uint32_t value) {
  uint8_t encoded[4];
  ssh_write_u32_be(encoded, value);
  sha256_update(context, encoded, sizeof(encoded));
}

static void sha256_update_string(sha256_ctx_t *context, const uint8_t *value,
                                 uint32_t value_len) {
  sha256_update_u32(context, value_len);
  sha256_update(context, value, value_len);
}

static void sha256_update_mpint(sha256_ctx_t *context,
                                const uint8_t value[32]) {
  uint32_t first = 0;
  while (first < 32U && value[first] == 0U) ++first;
  uint32_t value_len = 32U - first;
  uint32_t leading_zero = value_len != 0U && (value[first] & 0x80U) != 0U;
  sha256_update_u32(context, value_len + leading_zero);
  if (leading_zero != 0U) {
    static const uint8_t zero = 0;
    sha256_update(context, &zero, 1);
  }
  if (value_len != 0U) sha256_update(context, value + first, value_len);
}

static int g_log_fd = -1;
static uint32_t g_log_bytes = 0;

static int ssh_log_reopen(void) {
  if (g_log_fd >= 0) {
    xaios_fs_close(g_log_fd);
    g_log_fd = -1;
  }
  g_log_fd = xaios_fs_open(
      "/state/sshd.log", XAIOS_MFS_OPEN_WRITE | XAIOS_MFS_OPEN_CREATE |
                             XAIOS_MFS_OPEN_TRUNCATE);
  g_log_bytes = 0;
  return g_log_fd < 0 ? -1 : 0;
}

static void int_to_str(uint64_t val, char *buf, uint32_t buf_size) {
  if (buf_size == 0) return;
  char temp[32];
  uint32_t pos = 0;
  if (val == 0) { temp[pos++] = '0'; }
  else {
    while (val > 0 && pos < 31) {
      temp[pos++] = '0' + (val % 10);
      val /= 10;
    }
  }
  uint32_t len = 0;
  for (int32_t i = (int32_t)(pos - 1); i >= 0 && len < buf_size - 1; i--) {
    buf[len++] = temp[i];
  }
  buf[len] = '\0';
}

static void hex_to_str(uint64_t val, char *buf, uint32_t buf_size) {
  if (buf_size < 3) return;
  const char *hex_chars = "0123456789abcdef";
  uint32_t len = 0;
  for (int i = 60; i >= 0 && len < buf_size - 2; i -= 4) {
    uint8_t digit = (uint8_t)((val >> i) & 0xF);
    if (digit != 0 || len > 0) {
      buf[len++] = hex_chars[digit];
    }
  }
  if (len == 0) buf[len++] = '0';
  buf[len] = '\0';
}

void ssh_log(int level, const char *fmt, ...) {
  const char *prefix;
  switch (level) {
    case SSH_LOG_INFO:  prefix = "[INFO]";  break;
    case SSH_LOG_WARN:  prefix = "[WARN]";  break;
    case SSH_LOG_ERROR: prefix = "[ERROR]"; break;
    default: prefix = "[UNKNOWN]"; break;
  }
  va_list args;
  va_start(args, fmt);
  char buffer[512];
  uint32_t buf_pos = 0;
  for (const char *p = fmt; *p && buf_pos < 511; p++) {
    if (*p == '%' && *(p+1)) {
      p++;
      if (*p == 's') {
        const char *str = va_arg(args, const char*);
        if (str) {
          uint32_t len = ssh_str_len(str);
          if (buf_pos + len < 511) {
            for (uint32_t i = 0; i < len; i++) buffer[buf_pos++] = str[i];
          }
        }
      } else if (*p == 'u' || *p == 'd') {
        uint64_t val = va_arg(args, uint64_t);
        char num_buf[32];
        int_to_str(val, num_buf, 32);
        uint32_t len = ssh_str_len(num_buf);
        if (buf_pos + len < 511) {
          for (uint32_t i = 0; i < len; i++) buffer[buf_pos++] = num_buf[i];
        }
      } else if (*p == 'x' || *p == 'X') {
        uint64_t val = va_arg(args, uint64_t);
        char num_buf[32];
        hex_to_str(val, num_buf, 32);
        uint32_t len = ssh_str_len(num_buf);
        if (buf_pos + len < 511) {
          for (uint32_t i = 0; i < len; i++) buffer[buf_pos++] = num_buf[i];
        }
      } else if (*p == 'p') {
        uint64_t val = (uint64_t)va_arg(args, void*);
        char num_buf[32];
        hex_to_str(val, num_buf, 32);
        uint32_t len = ssh_str_len(num_buf);
        if (buf_pos + len + 2 < 511) {
          buffer[buf_pos++] = '0';
          buffer[buf_pos++] = 'x';
          for (uint32_t i = 0; i < len; i++) buffer[buf_pos++] = num_buf[i];
        }
      } else if (*p == '%') {
        if (buf_pos < 511) buffer[buf_pos++] = '%';
      }
    } else {
      buffer[buf_pos++] = *p;
    }
  }
  buffer[buf_pos] = '\0';
  va_end(args);

  while (buf_pos != 0U && buffer[buf_pos - 1U] == '\n') --buf_pos;
  char line[544];
  uint32_t line_pos = 0;
  uint32_t prefix_len = ssh_str_len(prefix);
  for (uint32_t i = 0; i < prefix_len; ++i) line[line_pos++] = prefix[i];
  line[line_pos++] = ' ';
  for (uint32_t i = 0; i < buf_pos; ++i) line[line_pos++] = buffer[i];
  line[line_pos++] = '\n';

  if (g_log_fd < 0 && ssh_log_reopen() != 0) return;
  if (g_log_bytes + line_pos > SSHD_LOG_ROTATE_BYTES) {
    if (ssh_log_reopen() != 0) return;
    xaios_log("sshd: audit log rotated\n");
  }
  int written = xaios_fs_write(g_log_fd, line, line_pos);
  if (written != (int)line_pos) {
    if (ssh_log_reopen() != 0) return;
    written = xaios_fs_write(g_log_fd, line, line_pos);
    if (written != (int)line_pos) return;
  }
  g_log_bytes += line_pos;
}

static int ip_addr_equal(const xaios_ip_addr_user_t *a,
                         const xaios_ip_addr_user_t *b) {
  if (a->family != b->family) return 0;
  uint32_t len = (a->family == 4) ? 4U : 16U;
  for (uint32_t i = 0; i < len; ++i) {
    if (a->addr[i] != b->addr[i]) return 0;
  }
  return 1;
}

/* ---- Per-connection encryption (replaces globals) ---- */

static int derive_connection_crypto(ssh_connection_crypto_t *c,
                                    const uint8_t *shared_secret,
                                    uint32_t secret_len,
                                    const uint8_t *exchange_hash,
                                    uint32_t hash_len,
                                    const uint8_t session_id[32]) {
  uint8_t derive_buf[128];
  sha256_ctx_t ctx;

  if (c == 0 || shared_secret == 0 || exchange_hash == 0 ||
      session_id == 0 || secret_len != 32U || hash_len != 32U) return -1;
  ssh_mem_zero(c, sizeof(*c));
  sha256_init(&ctx);
  sha256_update_mpint(&ctx, shared_secret);
  sha256_update(&ctx, exchange_hash, hash_len);
  sha256_update(&ctx, (const uint8_t*)"A", 1);
  sha256_update(&ctx, session_id, 32U);
  sha256_final(&ctx, derive_buf);
  ssh_mem_copy(c->decrypt_iv, derive_buf, 16);

  sha256_init(&ctx);
  sha256_update_mpint(&ctx, shared_secret);
  sha256_update(&ctx, exchange_hash, hash_len);
  sha256_update(&ctx, (const uint8_t*)"B", 1);
  sha256_update(&ctx, session_id, 32U);
  sha256_final(&ctx, derive_buf);
  ssh_mem_copy(c->encrypt_iv, derive_buf, 16);

  sha256_init(&ctx);
  sha256_update_mpint(&ctx, shared_secret);
  sha256_update(&ctx, exchange_hash, hash_len);
  sha256_update(&ctx, (const uint8_t*)"C", 1);
  sha256_update(&ctx, session_id, 32U);
  sha256_final(&ctx, derive_buf);
  aes128_init(&c->decrypt_ctx, derive_buf);

  sha256_init(&ctx);
  sha256_update_mpint(&ctx, shared_secret);
  sha256_update(&ctx, exchange_hash, hash_len);
  sha256_update(&ctx, (const uint8_t*)"D", 1);
  sha256_update(&ctx, session_id, 32U);
  sha256_final(&ctx, derive_buf);
  aes128_init(&c->encrypt_ctx, derive_buf);

  sha256_init(&ctx);
  sha256_update_mpint(&ctx, shared_secret);
  sha256_update(&ctx, exchange_hash, hash_len);
  sha256_update(&ctx, (const uint8_t*)"E", 1);
  sha256_update(&ctx, session_id, 32U);
  sha256_final(&ctx, derive_buf);
  ssh_mem_copy(c->decrypt_mac_key, derive_buf, 32);

  sha256_init(&ctx);
  sha256_update_mpint(&ctx, shared_secret);
  sha256_update(&ctx, exchange_hash, hash_len);
  sha256_update(&ctx, (const uint8_t*)"F", 1);
  sha256_update(&ctx, session_id, 32U);
  sha256_final(&ctx, derive_buf);
  ssh_mem_copy(c->encrypt_mac_key, derive_buf, 32);

  c->enabled = 1;
  ssh_mem_zero(derive_buf, sizeof(derive_buf));
  ssh_mem_zero(&ctx, sizeof(ctx));
  return 0;
}

static int conn_init_encryption(ssh_connection_t *conn) {
  if (derive_connection_crypto(&conn->crypto, conn->shared_secret, 32U,
                               conn->exchange_hash, 32U,
                               conn->session_id) != 0) return -1;
  /* Three packets in each direction precede the first encrypted packet. */
  conn->crypto.encrypt_seq = 3U;
  conn->crypto.decrypt_seq = 3U;
  conn->rekey_encrypt_base = conn->crypto.encrypt_seq;
  return 0;
}

static int conn_packet_write_encrypted(ssh_connection_t *conn,
                                        const uint8_t *data, uint32_t len) {
  return ssh_packet_write_encrypted((int)conn->sockfd, data, len);
}

static int conn_packet_read_encrypted(ssh_connection_t *conn,
                                       ssh_packet_t *out_pkt) {
  return ssh_packet_read_encrypted((int)conn->sockfd, out_pkt);
}

/* ---- Timer ---- */
static uint64_t timer_now(void) {
  return xaios_clock_nanos();
}

/* ---- User Database ---- */
#define SSHD_USERS_PATH "/etc/xaios_sshd_users"

static int parse_decimal_u32(const char *text, uint32_t text_len,
                             uint32_t *value) {
  uint32_t result = 0;
  if (text_len == 0U || value == 0) return -1;
  for (uint32_t i = 0; i < text_len; ++i) {
    if (text[i] < '0' || text[i] > '9') return -1;
    uint32_t digit = (uint32_t)(text[i] - '0');
    if (result > (UINT32_MAX - digit) / 10U) return -1;
    result = result * 10U + digit;
  }
  *value = result;
  return 0;
}

static int hex_nibble(char value) {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return 10 + value - 'a';
  if (value >= 'A' && value <= 'F') return 10 + value - 'A';
  return -1;
}

static int parse_hex_bytes(const char *text, uint32_t text_len,
                           uint8_t *output, uint32_t output_capacity,
                           uint32_t *output_len) {
  if (text == 0 || output == 0 || output_len == 0 || text_len == 0U ||
      (text_len & 1U) != 0U || text_len / 2U > output_capacity) {
    return -1;
  }
  for (uint32_t i = 0; i < text_len / 2U; ++i) {
    int high = hex_nibble(text[i * 2U]);
    int low = hex_nibble(text[i * 2U + 1U]);
    if (high < 0 || low < 0) return -1;
    output[i] = (uint8_t)(((uint32_t)high << 4U) | (uint32_t)low);
  }
  *output_len = text_len / 2U;
  return 0;
}

static int parse_user_line(const char *line, uint32_t line_len,
                           sshd_user_t *user) {
  uint32_t separator[4];
  uint32_t separator_count = 0;
  while (line_len > 0U && line[line_len - 1U] == '\r') --line_len;
  if (line_len == 0U || line[0] == '#') return 1;
  for (uint32_t i = 0; i < line_len; ++i) {
    if (line[i] == ':') {
      if (separator_count >= 4U) return -1;
      separator[separator_count++] = i;
    }
  }
  if (separator_count != 4U || separator[0] == 0U ||
      separator[0] >= SSHD_USERNAME_MAX) return -1;
  if (separator[0] != 5U) return -1;
  static const char admin_name[] = "admin";
  for (uint32_t i = 0; i < sizeof(admin_name) - 1U; ++i) {
    if (line[i] != admin_name[i]) return -1;
  }
  static const char scheme[] = "pbkdf2-sha256";
  uint32_t scheme_start = separator[0] + 1U;
  uint32_t scheme_len = separator[1] - scheme_start;
  if (scheme_len != sizeof(scheme) - 1U) return -1;
  for (uint32_t i = 0; i < scheme_len; ++i) {
    if (line[scheme_start + i] != scheme[i]) return -1;
  }
  uint32_t iterations = 0;
  if (parse_decimal_u32(line + separator[1] + 1U,
                        separator[2] - separator[1] - 1U,
                        &iterations) != 0 ||
      iterations < SSHD_PASSWORD_ITERATIONS_MIN ||
      iterations > SSHD_PASSWORD_ITERATIONS_MAX) return -1;
  uint32_t salt_len = 0;
  if (parse_hex_bytes(line + separator[2] + 1U,
                      separator[3] - separator[2] - 1U,
                      user->password_salt, sizeof(user->password_salt),
                      &salt_len) != 0 || salt_len < 16U) return -1;
  uint32_t hash_len = 0;
  if (parse_hex_bytes(line + separator[3] + 1U,
                      line_len - separator[3] - 1U,
                      user->password_hash, sizeof(user->password_hash),
                      &hash_len) != 0 || hash_len != SSHD_PASSWORD_HASH_SIZE) {
    return -1;
  }
  ssh_mem_copy(user->username, admin_name, sizeof(admin_name));
  user->password_salt_len = salt_len;
  user->password_iterations = iterations;
  user->active = 1;
  return 0;
}

static int load_user_database(void) {
  char buffer[4096];
#if XAIOS_PASSWORD_AUTH_AVAILABLE == 0
  ssh_mem_zero(g_users, sizeof(g_users));
  g_user_count = 0U;
  ssh_log(SSH_LOG_INFO, "Password authentication unavailable in this build\n");
  return 0;
#endif
  if (g_password_auth_enabled == 0U) {
    ssh_mem_zero(g_users, sizeof(g_users));
    g_user_count = 0U;
    ssh_log(SSH_LOG_INFO, "Password authentication disabled by configuration\n");
    return 0;
  }
  int result = xaios_read_file(SSHD_USERS_PATH, buffer, sizeof(buffer));
  ssh_mem_zero(g_users, sizeof(g_users));
  g_user_count = 0;
  if (result < 0) {
    ssh_log(SSH_LOG_INFO, "Password authentication disabled\n");
    return 0;
  }
  uint32_t line_start = 0;
  for (uint32_t i = 0; i <= (uint32_t)result; ++i) {
    if (i == (uint32_t)result || buffer[i] == '\n') {
      sshd_user_t parsed;
      ssh_mem_zero(&parsed, sizeof(parsed));
      int line_result = parse_user_line(buffer + line_start, i - line_start,
                                        &parsed);
      if (line_result < 0 ||
          (line_result == 0 && g_user_count != 0U) ||
          (line_result == 0 && g_user_count >= SSHD_MAX_USERS)) {
        ssh_mem_zero(buffer, sizeof(buffer));
        ssh_mem_zero(g_users, sizeof(g_users));
        g_user_count = 0;
        ssh_log(SSH_LOG_ERROR, "Invalid SSH user database\n");
        return -1;
      }
      if (line_result == 0) g_users[g_user_count++] = parsed;
      line_start = i + 1U;
    }
  }
  ssh_mem_zero(buffer, sizeof(buffer));
  if (g_user_count == 0U) return -1;
  ssh_log(SSH_LOG_INFO, "Loaded %u SSH password users\n", g_user_count);
  return 0;
}

static int authenticate_password(const char *username, const char *password) {
  static const uint8_t dummy_salt[16] = {
    0x58,0x41,0x49,0x4f,0x53,0x2d,0x53,0x53,
    0x48,0x2d,0x44,0x55,0x4d,0x4d,0x59,0x31
  };
  static const uint8_t dummy_hash[32] = {0};
  const uint8_t *salt = dummy_salt;
  const uint8_t *expected = dummy_hash;
  uint32_t salt_len = sizeof(dummy_salt);
  uint32_t iterations = SSHD_PASSWORD_ITERATIONS_MIN;
  int found = 0;
  for (uint32_t i = 0; i < g_user_count; ++i) {
    if (!g_users[i].active) continue;
    if (!ssh_str_eq(g_users[i].username, username)) continue;
    salt = g_users[i].password_salt;
    salt_len = g_users[i].password_salt_len;
    expected = g_users[i].password_hash;
    iterations = g_users[i].password_iterations;
    found = 1;
    break;
  }
  uint8_t hash[32];
  if (pbkdf2_hmac_sha256((const uint8_t *)password,
                         ssh_str_len(password), salt, salt_len,
                         iterations, hash) != 0) return -1;
  uint8_t diff = (uint8_t)(found == 0);
  for (uint32_t i = 0; i < sizeof(hash); ++i) diff |= hash[i] ^ expected[i];
  ssh_mem_zero(hash, sizeof(hash));
  return diff == 0U ? 0 : -1;
}

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

static int bytes_equal(const uint8_t *left, const uint8_t *right,
                       uint32_t size) {
  uint8_t difference = 0;
  for (uint32_t i = 0; i < size; ++i) difference |= left[i] ^ right[i];
  return difference == 0U;
}

static int bytes_have_zero(const uint8_t *data, uint32_t size) {
  for (uint32_t i = 0; i < size; ++i) {
    if (data[i] == 0U) return 1;
  }
  return 0;
}

static int valid_client_version(const uint8_t *version, uint32_t length) {
  static const uint8_t prefix[] = "SSH-2.0-";
  if (version == 0 || length < sizeof(prefix) || version[length - 1U] != '\n') {
    return 0;
  }
  uint32_t text_length = length - 1U;
  if (text_length != 0U && version[text_length - 1U] == '\r') --text_length;
  if (text_length < sizeof(prefix) ||
      !bytes_equal(version, prefix, sizeof(prefix) - 1U)) {
    return 0;
  }
  for (uint32_t i = 0; i < text_length; ++i) {
    if (version[i] < 32U || version[i] > 126U) return 0;
  }
  return 1;
}

static int parse_ed25519_key_blob(const uint8_t *blob, uint32_t blob_len,
                                  uint8_t key[32]) {
  static const uint8_t algorithm[] = "ssh-ed25519";
  if (blob == 0 || blob_len != 51U || ssh_read_u32_be(blob) != 11U ||
      !bytes_equal(blob + 4U, algorithm, 11U) ||
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
        bytes_equal((const uint8_t *)line + token_start,
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
      int result = parse_ed25519_key_blob(blob, blob_len, key);
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
          fnv1a64_zero_range(database, sizeof(*database), checksum_offset,
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
        bytes_equal(fingerprint, record->fingerprint, sizeof(fingerprint));
    ssh_mem_zero(fingerprint, sizeof(fingerprint));
    if (terminated == 0U || fingerprint_valid == 0 ||
        record->role < XAIOS_CONTROL_ROLE_OBSERVER ||
        record->role > XAIOS_CONTROL_ROLE_ADMIN || record->reserved != 0U) {
      return 0;
    }
  }
  return 1;
}

static int load_authorized_keys(void) {
  xaios_mfs_stat_user_t stat;
  ssh_mem_zero(g_authorized_keys, sizeof(g_authorized_keys));
  g_authorized_key_count = 0U;
  g_authorized_database_invalid = 0U;
  if (xaios_fs_stat(XAIOS_ADMIN_AUTH_PATH, &stat) == 0) {
    xaios_admin_auth_database_user_t database;
    if (stat.size != sizeof(database) ||
        read_exact_file(XAIOS_ADMIN_AUTH_PATH, &database, sizeof(database)) !=
            0 ||
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

static const authorized_key_t *check_authorized_key(const uint8_t *pubkey) {
  for (uint32_t i = 0; i < g_authorized_key_count; ++i) {
    if (!g_authorized_keys[i].active) continue;
    if (bytes_equal(g_authorized_keys[i].key, pubkey, 32U)) {
      return &g_authorized_keys[i];
    }
  }
  return 0;
}

static int command_starts_with(const char *command, const char *prefix) {
  uint32_t i = 0U;
  if (command == 0 || prefix == 0) return 0;
  while (prefix[i] != '\0') {
    if (command[i] != prefix[i]) return 0;
    ++i;
  }
  return 1;
}

int sshd_reload_control_state(const char *command) {
  if (command_starts_with(command, "xaiosctl config apply ")) {
    if (load_runtime_config() != 0) return -1;
    if (load_user_database() != 0) return -1;
    ssh_log(SSH_LOG_INFO, "Applied SSH runtime configuration generation=%u\n",
            g_runtime_config.generation);
  } else if (command_starts_with(command, "xaiosctl auth key add ") ||
             command_starts_with(command, "xaiosctl auth key remove ")) {
    if (load_authorized_keys() != 0) return -1;
  } else if (command_starts_with(command,
                                 "xaiosctl auth host-key rotate")) {
    if (ssh_host_key_reload() != 0) return -1;
    for (uint32_t i = 0U; i < SSH_MAX_CONNECTIONS; ++i) {
      ssh_connection_t *connection = ssh_conn_by_index(i);
      if (connection != 0) connection->close_requested = 1U;
    }
  }
  return 0;
}

/* ---- Rate Limiting ---- */
static sshd_rate_limit_entry_t *find_rate_limit_entry(
    const xaios_ip_addr_user_t *ip) {
  for (uint32_t i = 0; i < g_rate_limit_count; ++i) {
    if (ip_addr_equal(&g_rate_limits[i].ip_address, ip)) {
      return &g_rate_limits[i];
    }
  }
  return 0;
}

static sshd_rate_limit_entry_t *allocate_rate_limit_entry(
    const xaios_ip_addr_user_t *client_addr, uint64_t now) {
  sshd_rate_limit_entry_t *entry = find_rate_limit_entry(client_addr);
  if (entry != 0) return entry;
  if (g_rate_limit_count < SSHD_RATE_LIMIT_MAX_ENTRIES) {
    entry = &g_rate_limits[g_rate_limit_count++];
  } else {
    uint32_t oldest = 0U;
    for (uint32_t i = 1U; i < g_rate_limit_count; ++i) {
      if (g_rate_limits[i].ban_until <= now &&
          (g_rate_limits[oldest].ban_until > now ||
           g_rate_limits[i].last_attempt_time <
               g_rate_limits[oldest].last_attempt_time)) {
        oldest = i;
      }
    }
    if (g_rate_limits[oldest].ban_until <= now) {
      entry = &g_rate_limits[oldest];
    }
  }
  if (entry != 0) {
    ssh_mem_zero(entry, sizeof(*entry));
    entry->ip_address = *client_addr;
  }
  return entry;
}

static int record_connection_attempt(
    const xaios_ip_addr_user_t *client_addr) {
  uint64_t now = timer_now();
  sshd_rate_limit_entry_t *entry =
      allocate_rate_limit_entry(client_addr, now);
  if (entry == 0) return -1;
  if (entry->connection_window_start == 0U ||
      now - entry->connection_window_start >= SSHD_CONNECTION_RATE_WINDOW) {
    entry->connection_window_start = now;
    entry->connection_count = 0U;
  }
  if (entry->connection_count >= SSHD_CONNECTION_RATE_LIMIT) return -1;
  ++entry->connection_count;
  entry->last_attempt_time = now;
  return 0;
}

static int check_rate_limit(const xaios_ip_addr_user_t *client_addr) {
  sshd_rate_limit_entry_t *entry = find_rate_limit_entry(client_addr);
  if (entry == 0) return 0;
  uint64_t now = timer_now();
  if (entry->ban_until > now) return -1;
  if (entry->ban_until > 0 && entry->ban_until <= now) {
    entry->failure_count = 0;
    entry->ban_until = 0;
  }
  return 0;
}

static void record_auth_failure(const xaios_ip_addr_user_t *client_addr) {
  uint64_t now = timer_now();
  sshd_rate_limit_entry_t *entry =
      allocate_rate_limit_entry(client_addr, now);
  if (entry != 0) {
    entry->last_attempt_time = now;
    entry->failure_count++;
    if (entry->failure_count >= SSHD_RATE_LIMIT_MAX_FAILURES) {
      entry->ban_until = now + SSHD_RATE_LIMIT_BAN_DURATION;
    }
  }
}

static void record_auth_success(const xaios_ip_addr_user_t *client_addr) {
  sshd_rate_limit_entry_t *entry = find_rate_limit_entry(client_addr);
  if (entry) { entry->failure_count = 0; entry->ban_until = 0; }
}

static int send_auth_failure(ssh_connection_t *conn) {
  uint8_t reject[64];
  const char *methods = g_password_auth_enabled == 0U ? "publickey" :
                                                        "publickey,password";
  uint32_t methods_len = ssh_str_len(methods);
  reject[0] = SSH_MSG_USERAUTH_FAILURE;
  ssh_write_u32_be(reject + 1U, methods_len);
  ssh_mem_copy(reject + 5U, methods, methods_len);
  reject[5U + methods_len] = 0U;
  return conn_packet_write_encrypted(conn, reject, 6U + methods_len);
}

/* ---- Build KEXINIT Packet ---- */
static int build_kexinit(uint8_t *buf, uint32_t *out_len) {
  uint32_t pos = 0;
  buf[pos++] = 20;
  if (crypto_random_bytes(buf + pos, 16) != 0) return -1;
  pos += 16;
  const char *kex = "curve25519-sha256";
  uint32_t kex_len = ssh_str_len(kex);
  ssh_write_u32_be(buf + pos, kex_len); pos += 4;
  ssh_mem_copy(buf + pos, kex, kex_len); pos += kex_len;
  const char *hkey = "ssh-ed25519";
  uint32_t hkey_len = ssh_str_len(hkey);
  ssh_write_u32_be(buf + pos, hkey_len); pos += 4;
  ssh_mem_copy(buf + pos, hkey, hkey_len); pos += hkey_len;
  const char *enc = "aes128-ctr";
  uint32_t enc_len = ssh_str_len(enc);
  ssh_write_u32_be(buf + pos, enc_len); pos += 4;
  ssh_mem_copy(buf + pos, enc, enc_len); pos += enc_len;
  ssh_write_u32_be(buf + pos, enc_len); pos += 4;
  ssh_mem_copy(buf + pos, enc, enc_len); pos += enc_len;
  const char *mac = "hmac-sha2-256";
  uint32_t mac_len = ssh_str_len(mac);
  ssh_write_u32_be(buf + pos, mac_len); pos += 4;
  ssh_mem_copy(buf + pos, mac, mac_len); pos += mac_len;
  ssh_write_u32_be(buf + pos, mac_len); pos += 4;
  ssh_mem_copy(buf + pos, mac, mac_len); pos += mac_len;
  const char *comp = "none";
  uint32_t comp_len = ssh_str_len(comp);
  ssh_write_u32_be(buf + pos, comp_len); pos += 4;
  ssh_mem_copy(buf + pos, comp, comp_len); pos += comp_len;
  ssh_write_u32_be(buf + pos, comp_len); pos += 4;
  ssh_mem_copy(buf + pos, comp, comp_len); pos += comp_len;
  ssh_write_u32_be(buf + pos, 0); pos += 4;
  ssh_write_u32_be(buf + pos, 0); pos += 4;
  buf[pos++] = 0;
  ssh_write_u32_be(buf + pos, 0); pos += 4;
  *out_len = pos;
  return 0;
}

static int name_list_contains(const uint8_t *list, uint32_t list_len,
                              const char *required) {
  uint32_t required_len = ssh_str_len(required);
  uint32_t start = 0U;
  for (uint32_t i = 0U; i <= list_len; ++i) {
    if (i == list_len || list[i] == ',') {
      if (i - start == required_len &&
          bytes_equal(list + start, (const uint8_t *)required,
                      required_len)) return 1;
      start = i + 1U;
    }
  }
  return 0;
}

static int consume_required_name_list(const ssh_packet_t *pkt,
                                      uint32_t *offset,
                                      const char *required) {
  if (*offset + 4U > pkt->len) return -1;
  uint32_t length = ssh_read_u32_be(pkt->data + *offset);
  *offset += 4U;
  if (length > pkt->len - *offset ||
      !name_list_contains(pkt->data + *offset, length, required)) return -1;
  *offset += length;
  return 0;
}

static int consume_name_list(const ssh_packet_t *pkt, uint32_t *offset) {
  if (*offset + 4U > pkt->len) return -1;
  uint32_t length = ssh_read_u32_be(pkt->data + *offset);
  *offset += 4U;
  if (length > pkt->len - *offset) return -1;
  *offset += length;
  return 0;
}

static int validate_client_kexinit(const ssh_packet_t *pkt) {
  if (pkt == 0 || pkt->len < 21U || pkt->data[0] != SSH_MSG_KEXINIT) {
    return -1;
  }
  uint32_t offset = 17U;
  if (consume_required_name_list(pkt, &offset, "curve25519-sha256") != 0 ||
      consume_required_name_list(pkt, &offset, "ssh-ed25519") != 0 ||
      consume_required_name_list(pkt, &offset, "aes128-ctr") != 0 ||
      consume_required_name_list(pkt, &offset, "aes128-ctr") != 0 ||
      consume_required_name_list(pkt, &offset, "hmac-sha2-256") != 0 ||
      consume_required_name_list(pkt, &offset, "hmac-sha2-256") != 0 ||
      consume_required_name_list(pkt, &offset, "none") != 0 ||
      consume_required_name_list(pkt, &offset, "none") != 0 ||
      consume_name_list(pkt, &offset) != 0 ||
      consume_name_list(pkt, &offset) != 0 || offset + 5U != pkt->len ||
      pkt->data[offset] != 0U) return -1;
  return 0;
}

static void init_exchange_hash(ssh_connection_t *conn,
                               const ssh_packet_t *client_kexinit) {
  uint32_t client_version_len = conn->version_len;
  while (client_version_len > 0U &&
         (conn->version_buf[client_version_len - 1U] == '\r' ||
          conn->version_buf[client_version_len - 1U] == '\n')) {
    --client_version_len;
  }
  sha256_init(&conn->exchange_hash_ctx);
  sha256_update_string(&conn->exchange_hash_ctx, conn->version_buf,
                       client_version_len);
  static const uint8_t server_version[] = "SSH-2.0-XAIOS_1.0";
  sha256_update_string(&conn->exchange_hash_ctx, server_version,
                       sizeof(server_version) - 1U);
  sha256_update_string(&conn->exchange_hash_ctx, client_kexinit->data,
                       client_kexinit->len);
  sha256_update_string(&conn->exchange_hash_ctx, conn->server_kexinit,
                       conn->server_kexinit_len);
}

static int send_server_kexinit(ssh_connection_t *conn, int encrypted) {
  if (build_kexinit(conn->server_kexinit,
                    &conn->server_kexinit_len) != 0) return -1;
  if (encrypted != 0) {
    return conn_packet_write_encrypted(conn, conn->server_kexinit,
                                       conn->server_kexinit_len);
  }
  return ssh_packet_write((int)conn->sockfd, conn->server_kexinit,
                          conn->server_kexinit_len);
}

static int send_kex_packet(ssh_connection_t *conn, int encrypted,
                           const uint8_t *packet, uint32_t packet_len) {
  if (encrypted != 0) {
    return conn_packet_write_encrypted(conn, packet, packet_len);
  }
  return ssh_packet_write((int)conn->sockfd, packet, packet_len);
}

static int handle_kexdh_init(ssh_connection_t *conn,
                             const ssh_packet_t *pkt, int encrypted) {
  if (pkt == 0 || pkt->len != 37U || pkt->data[0] != SSH_MSG_KEXDH_INIT ||
      ssh_read_string_len(pkt->data + 1U) != 32U) return -1;
  ssh_mem_copy(conn->client_ephemeral_pub, pkt->data + 5U, 32U);
  if (crypto_random_bytes(conn->server_ephemeral_priv, 32U) != 0) return -1;
  xaios_x25519_base(conn->server_ephemeral_pub,
                    conn->server_ephemeral_priv);
  xaios_x25519(conn->shared_secret, conn->server_ephemeral_priv,
               conn->client_ephemeral_pub);
  uint8_t shared_nonzero = 0U;
  for (uint32_t i = 0; i < sizeof(conn->shared_secret); ++i) {
    shared_nonzero |= conn->shared_secret[i];
  }
  if (shared_nonzero == 0U) return -1;

  sha256_ctx_t hash_ctx = conn->exchange_hash_ctx;
  uint8_t host_pub[32];
  if (ssh_host_key_get_public(host_pub) != 0) return -1;
  uint8_t host_key_blob[64];
  uint32_t host_key_blob_pos = 0U;
  ssh_write_u32_be(host_key_blob + host_key_blob_pos, 4U + 11U + 4U + 32U);
  host_key_blob_pos += 4U;
  ssh_write_u32_be(host_key_blob + host_key_blob_pos, 11U);
  host_key_blob_pos += 4U;
  ssh_mem_copy(host_key_blob + host_key_blob_pos, "ssh-ed25519", 11U);
  host_key_blob_pos += 11U;
  ssh_write_u32_be(host_key_blob + host_key_blob_pos, 32U);
  host_key_blob_pos += 4U;
  ssh_mem_copy(host_key_blob + host_key_blob_pos, host_pub, 32U);
  host_key_blob_pos += 32U;
  sha256_update(&hash_ctx, host_key_blob, host_key_blob_pos);
  sha256_update_string(&hash_ctx, conn->client_ephemeral_pub, 32U);
  sha256_update_string(&hash_ctx, conn->server_ephemeral_pub, 32U);
  sha256_update_mpint(&hash_ctx, conn->shared_secret);
  sha256_final(&hash_ctx, conn->exchange_hash);
  if (encrypted == 0) {
    ssh_mem_copy(conn->session_id, conn->exchange_hash,
                 sizeof(conn->session_id));
  }

  uint8_t reply[512];
  uint32_t position = 0U;
  reply[position++] = SSH_MSG_KEXDH_REPLY;
  ssh_write_u32_be(reply + position, host_key_blob_pos - 4U);
  position += 4U;
  ssh_mem_copy(reply + position, host_key_blob + 4U,
               host_key_blob_pos - 4U);
  position += host_key_blob_pos - 4U;
  ssh_write_u32_be(reply + position, 32U);
  position += 4U;
  ssh_mem_copy(reply + position, conn->server_ephemeral_pub, 32U);
  position += 32U;

  uint8_t signature[64];
  uint8_t host_priv[32];
  if (ssh_host_key_get_private(host_priv) != 0) return -1;
  xaios_ed25519_sign(signature, conn->exchange_hash, 32U, host_pub,
                     host_priv);
  ssh_mem_zero(host_priv, sizeof(host_priv));
  ssh_write_u32_be(reply + position, 4U + 11U + 4U + 64U);
  position += 4U;
  ssh_write_u32_be(reply + position, 11U);
  position += 4U;
  ssh_mem_copy(reply + position, "ssh-ed25519", 11U);
  position += 11U;
  ssh_write_u32_be(reply + position, 64U);
  position += 4U;
  ssh_mem_copy(reply + position, signature, sizeof(signature));
  position += sizeof(signature);

  if (send_kex_packet(conn, encrypted, reply, position) != 0) return -1;
  uint8_t newkeys = SSH_MSG_NEWKEYS;
  if (send_kex_packet(conn, encrypted, &newkeys, 1U) != 0) return -1;
  if (encrypted != 0 &&
      derive_connection_crypto(&conn->pending_crypto, conn->shared_secret,
                               32U, conn->exchange_hash, 32U,
                               conn->session_id) != 0) return -1;
  ssh_mem_zero(signature, sizeof(signature));
  ssh_mem_zero(&hash_ctx, sizeof(hash_ctx));
  return 0;
}

static int begin_client_rekey(ssh_connection_t *conn,
                              const ssh_packet_t *client_kexinit,
                              int resume_state, uint64_t now) {
  if (validate_client_kexinit(client_kexinit) != 0 ||
      send_server_kexinit(conn, 1) != 0) return -1;
  init_exchange_hash(conn, client_kexinit);
  conn->rekey_resume_state = resume_state;
  conn->kex_start_time = now;
  conn->state = SSH_STATE_REKEY_DH;
  return 0;
}

static int begin_server_rekey(ssh_connection_t *conn, int resume_state,
                              uint64_t now) {
  if (send_server_kexinit(conn, 1) != 0) return -1;
  conn->rekey_resume_state = resume_state;
  conn->kex_start_time = now;
  conn->state = SSH_STATE_REKEY_KEXINIT;
  return 0;
}

/* ---- Connection State Machine Processor ---- */

/* Process one step for a connection. Returns 0 if connection should remain,
   -1 if closed/done. */
static int process_connection(ssh_connection_t *conn) {
  int sockfd = (int)conn->sockfd;
  ssh_packet_t *pkt = &ssh_conn_scratch()->pkt;
  uint64_t now = timer_now();

  if (conn->state == SSH_STATE_INIT) {
    /* Send server version */
    if (ssh_send_version(sockfd) != 0) {
      ssh_log(SSH_LOG_ERROR, "Failed to send version\n");
      return -1;
    }
    conn->state = SSH_STATE_KEX;
    conn->kex_start_time = now;
    return 0;
  }

  if (conn->state == SSH_STATE_KEX) {
    /* Receive client version */
    if (conn->version_len == 0U ||
        conn->version_buf[conn->version_len - 1U] != '\n') {
      while (conn->version_len < sizeof(conn->version_buf)) {
        u64 n = 0;
        int status = xaios_net_recv(conn->sockfd,
            conn->version_buf + conn->version_len, 1, &n);
        if (status != 0) return -1;
        if (n == 0) return 0;
        conn->version_len += (uint32_t)n;
        if (conn->version_buf[conn->version_len - 1U] == '\n') break;
      }
      if (conn->version_len == sizeof(conn->version_buf) &&
          conn->version_buf[conn->version_len - 1U] != '\n') {
        return -1;
      }
    }
    if (!valid_client_version(conn->version_buf, conn->version_len)) {
      ssh_log(SSH_LOG_WARN, "Rejected invalid SSH client version");
      return -1;
    }

    if (send_server_kexinit(conn, 0) != 0) return -1;
    conn->state = SSH_STATE_KEX_SENT;
    return 0;
  }

  if (conn->state == SSH_STATE_KEX_SENT) {
    /* Receive client KEXINIT */
    int packet_status = ssh_packet_read(sockfd, pkt);
    if (packet_status > 0) return 0;
    if (packet_status < 0) return -1;
    if (validate_client_kexinit(pkt) != 0) return -1;
    init_exchange_hash(conn, pkt);
    conn->state = SSH_STATE_NEWKEYS;
    return 0;
  }

  if (conn->state == SSH_STATE_NEWKEYS) {
    /* KEXDH_INIT */
    int packet_status = ssh_packet_read(sockfd, pkt);
    if (packet_status > 0) return 0;
    if (packet_status < 0) return -1;
    if (handle_kexdh_init(conn, pkt, 0) != 0) return -1;
    conn->state = SSH_STATE_NEWKEYS_SENT;
    return 0;
  }

  if (conn->state == SSH_STATE_NEWKEYS_SENT) {
    /* Receive NEWKEYS */
    int packet_status = ssh_packet_read(sockfd, pkt);
    if (packet_status > 0) return 0;
    if (packet_status < 0) return -1;
    if (pkt->len == 0 || pkt->data[0] != 21) return -1;

    if (conn_init_encryption(conn) != 0) return -1;

    ssh_log(SSH_LOG_INFO, "KEX completed for connection %llx\n", conn->sockfd);
    conn->kex_start_time = now;
    conn->state = SSH_STATE_AUTH;
    return 0;
  }

  if (conn->state == SSH_STATE_REKEY_KEXINIT) {
    int packet_status = conn_packet_read_encrypted(conn, pkt);
    if (packet_status > 0) return 0;
    if (packet_status < 0 || validate_client_kexinit(pkt) != 0) return -1;
    init_exchange_hash(conn, pkt);
    conn->state = SSH_STATE_REKEY_DH;
    return 0;
  }

  if (conn->state == SSH_STATE_REKEY_DH) {
    int packet_status = conn_packet_read_encrypted(conn, pkt);
    if (packet_status > 0) return 0;
    if (packet_status < 0 || handle_kexdh_init(conn, pkt, 1) != 0) return -1;
    conn->state = SSH_STATE_REKEY_NEWKEYS;
    return 0;
  }

  if (conn->state == SSH_STATE_REKEY_NEWKEYS) {
    int packet_status = conn_packet_read_encrypted(conn, pkt);
    if (packet_status > 0) return 0;
    if (packet_status < 0 || pkt->len != 1U ||
        pkt->data[0] != SSH_MSG_NEWKEYS) return -1;
    uint64_t encrypt_seq = conn->crypto.encrypt_seq;
    uint64_t decrypt_seq = conn->crypto.decrypt_seq;
    conn->crypto = conn->pending_crypto;
    conn->crypto.encrypt_seq = encrypt_seq;
    conn->crypto.decrypt_seq = decrypt_seq;
    ssh_mem_zero(&conn->pending_crypto, sizeof(conn->pending_crypto));
    conn->rekey_encrypt_base = encrypt_seq;
    conn->kex_start_time = now;
    conn->state = conn->rekey_resume_state;
    ssh_log(SSH_LOG_INFO, "Rekey completed for connection %llx\n",
            conn->sockfd);
    return 0;
  }

  if (conn->state == SSH_STATE_AUTH) {
    int packet_status = conn_packet_read_encrypted(conn, pkt);
    if (packet_status > 0) return 0;
    if (packet_status < 0) return -1;
    if (pkt->len == 0) return 0;
    uint8_t msg = pkt->data[0];

    if (msg == SSH_MSG_KEXINIT) {
      return begin_client_rekey(conn, pkt, SSH_STATE_AUTH, now);
    }

    if (msg == SSH_MSG_SERVICE_REQUEST) {
      if (pkt->len < 5U) return -1;
      uint32_t requested_len = ssh_read_u32_be(pkt->data + 1U);
      static const char requested_service[] = "ssh-userauth";
      if (requested_len != sizeof(requested_service) - 1U ||
          pkt->len != 5U + requested_len ||
          !bytes_equal(pkt->data + 5U,
                       (const uint8_t *)requested_service, requested_len)) {
        return -1;
      }
      uint8_t sa[32];
      sa[0] = SSH_MSG_SERVICE_ACCEPT;
      const char *svc = requested_service;
      uint32_t svc_len = ssh_str_len(svc);
      ssh_write_u32_be(sa + 1, svc_len);
      ssh_mem_copy(sa + 5, svc, svc_len);
      conn_packet_write_encrypted(conn, sa, 5 + svc_len);
      return 0;
    }

    if (msg == SSH_MSG_USERAUTH_REQUEST) {
      uint32_t offset = 1;
      if (offset + 4U > pkt->len) return 0;
      uint32_t user_len = ssh_read_string_len(pkt->data + offset);
      offset += 4U;
      if (user_len > 64U || offset + user_len > pkt->len ||
          bytes_have_zero(pkt->data + offset, user_len)) return -1;
      char username[65];
      ssh_mem_copy(username, pkt->data + offset, user_len);
      username[user_len] = '\0';
      offset += user_len;

      if (offset + 4U > pkt->len) return 0;
      uint32_t service_len = ssh_read_string_len(pkt->data + offset);
      offset += 4U;
      if (service_len > 64U || offset + service_len > pkt->len ||
          bytes_have_zero(pkt->data + offset, service_len)) return -1;
      char service[65];
      ssh_mem_copy(service, pkt->data + offset, service_len);
      service[service_len] = '\0';
      offset += service_len;
      if (!ssh_str_eq(service, "ssh-connection")) return 0;

      if (offset + 4U > pkt->len) return 0;
      uint32_t method_len = ssh_read_string_len(pkt->data + offset);
      offset += 4U;
      if (method_len > 64U || offset + method_len > pkt->len ||
          bytes_have_zero(pkt->data + offset, method_len)) return -1;
      char method[65];
      ssh_mem_copy(method, pkt->data + offset, method_len);
      method[method_len] = '\0';
      offset += method_len;
      uint32_t auth_data_offset = offset;

      if (check_rate_limit(&conn->client_addr) != 0) {
        if (send_auth_failure(conn) != 0) return -1;
        return 0;
      }

      if (conn->auth_attempts >= g_runtime_config.max_auth_attempts) {
        record_auth_failure(&conn->client_addr);
        if (send_auth_failure(conn) != 0) return -1;
        return 0;
      }

      /* ---- "password" method ---- */
      if (ssh_str_eq(method, "password")) {
        if (g_password_auth_enabled == 0U || g_user_count == 0U) {
          conn->auth_attempts++;
          record_auth_failure(&conn->client_addr);
          if (send_auth_failure(conn) != 0) return -1;
          return 0;
        }
        uint32_t password_offset = auth_data_offset;
        if (password_offset + 5U > pkt->len) return 0;
        if (pkt->data[password_offset] != 0U) return 0;
        password_offset += 1U;
        uint32_t pass_len = ssh_read_string_len(pkt->data + password_offset);
        if (pass_len > 128U || password_offset + 4U + pass_len > pkt->len ||
            bytes_have_zero(pkt->data + password_offset + 4U, pass_len)) {
          return -1;
        }
        char password[129];
        ssh_mem_copy(password, pkt->data + password_offset + 4U, pass_len);
        password[pass_len] = '\0';

        int authenticated = authenticate_password(username, password);
        ssh_mem_zero(password, sizeof(password));
        if (authenticated == 0) {
          uint8_t auth_reply[1] = {SSH_MSG_USERAUTH_SUCCESS};
          if (conn_packet_write_encrypted(conn, auth_reply,
                                          sizeof(auth_reply)) != 0) return -1;
          conn->auth_attempts = 0;
          record_auth_success(&conn->client_addr);
          ssh_log(SSH_LOG_INFO, "Password auth success: '%s'\n", username);
          conn->principal_role = XAIOS_CONTROL_ROLE_ADMIN;
          ssh_mem_copy(conn->principal, "password-admin",
                       sizeof("password-admin"));
          conn->state = SSH_STATE_AUTHENTICATED;
        } else {
          conn->auth_attempts++;
          record_auth_failure(&conn->client_addr);
          if (send_auth_failure(conn) != 0) return -1;
          ssh_log(SSH_LOG_WARN, "Password auth failed: '%s'\n", username);
        }
        return 0;
      }

      /* ---- "publickey" method (RFC 4252 Section 7) ---- */
      if (ssh_str_eq(method, "publickey")) {
        if (!ssh_str_eq(username, "admin")) {
          conn->auth_attempts++;
          record_auth_failure(&conn->client_addr);
          if (send_auth_failure(conn) != 0) return -1;
          return 0;
        }
        offset = auth_data_offset;
        if (offset >= pkt->len) return 0;
        uint8_t has_signature = pkt->data[offset];
        if (has_signature > 1U) return 0;
        offset += 1;

        /* Read public key algorithm */
        if (offset > pkt->len || pkt->len - offset < 4U) return 0;
        uint32_t algo_len = ssh_read_string_len(pkt->data + offset);
        offset += 4;
        if (algo_len > pkt->len - offset) return 0;
        const uint8_t *algorithm = pkt->data + offset;
        if (algo_len != 11U ||
            !bytes_equal(algorithm, (const uint8_t *)"ssh-ed25519", 11U)) {
          return 0;
        }
        offset += algo_len;

        /* Read public key blob */
        if (pkt->len - offset < 4U) return 0;
        uint32_t pubkey_len = ssh_read_string_len(pkt->data + offset);
        offset += 4;
        if (pubkey_len > pkt->len - offset) return 0;
        const uint8_t *pubkey_blob = pkt->data + offset;
        uint8_t client_pubkey[32];
        if (parse_ed25519_key_blob(pubkey_blob, pubkey_len,
                                   client_pubkey) != 0) return 0;
        offset += pubkey_len;
        uint32_t signed_request_len = offset;

        const authorized_key_t *authorized = 0;
        if (load_authorized_keys() == 0) {
          authorized = check_authorized_key(client_pubkey);
        }
        if (authorized == 0) {
          xaios_log("sshd: presented public key was not authorized\n");
          ssh_log(SSH_LOG_WARN, "Public key not authorized\n");
          conn->auth_attempts++;
          record_auth_failure(&conn->client_addr);
          if (send_auth_failure(conn) != 0) return -1;
          return 0;
        }

        if (!has_signature) {
          /* Test request: public key is acceptable */
          uint8_t pk_ok[96];
          pk_ok[0] = SSH_MSG_USERAUTH_PK_OK;
          uint32_t poff = 1;
          ssh_write_u32_be(pk_ok + poff, algo_len); poff += 4;
          ssh_mem_copy(pk_ok + poff, algorithm, algo_len);
          poff += algo_len;
          ssh_write_u32_be(pk_ok + poff, pubkey_len); poff += 4;
          ssh_mem_copy(pk_ok + poff, pubkey_blob, pubkey_len);
          poff += pubkey_len;
          if (conn_packet_write_encrypted(conn, pk_ok, poff) != 0) return -1;
          return 0;
        }

        /* Read signature blob */
        if (pkt->len - offset < 4U) return 0;
        uint32_t sig_len = ssh_read_string_len(pkt->data + offset);
        offset += 4;
        if (sig_len != pkt->len - offset) return 0;
        uint8_t *sig_blob = pkt->data + offset;

        /* Parse signature: string algorithm + string (R,s) */
        if (sig_len < 4U) return 0;
        uint32_t sig_algo_len = ssh_read_string_len(sig_blob);
        if (sig_algo_len != 11U || sig_algo_len > sig_len - 4U ||
            !bytes_equal(sig_blob + 4U,
                         (const uint8_t *)"ssh-ed25519", 11U)) return 0;
        uint32_t sig_data_off = 4U + sig_algo_len;
        if (sig_data_off > sig_len || sig_len - sig_data_off < 4U) return 0;
        uint32_t sig_data_len = ssh_read_string_len(sig_blob + sig_data_off);
        if (sig_data_len != sig_len - sig_data_off - 4U) return 0;
        uint8_t *sig_data = sig_blob + sig_data_off + 4;
        if (sig_data_len != 64) return 0;

        /* RFC 4252 signs string(session_id) followed by the request through
         * the public-key blob, excluding the signature field. */
        uint8_t verify_buf[SSH_PLAINTEXT_PACKET_SIZE + 36U];
        uint32_t vpos = 0;
        ssh_write_u32_be(verify_buf + vpos, 32U);
        vpos += 4U;
        ssh_mem_copy(verify_buf + vpos, conn->session_id, 32U);
        vpos += 32U;
        if (signed_request_len > SSH_PLAINTEXT_PACKET_SIZE) return 0;
        ssh_mem_copy(verify_buf + vpos, pkt->data, signed_request_len);
        vpos += signed_request_len;

        int verify_result = xaios_ed25519_verify(sig_data, verify_buf, vpos,
                                                  client_pubkey);
        if (verify_result == 0) {
          uint8_t auth_reply[1] = {SSH_MSG_USERAUTH_SUCCESS};
          if (conn_packet_write_encrypted(conn, auth_reply,
                                          sizeof(auth_reply)) != 0) return -1;
          conn->auth_attempts = 0;
          record_auth_success(&conn->client_addr);
          conn->principal_role = authorized->role;
          ssh_mem_copy(conn->principal, authorized->principal,
                       sizeof(conn->principal));
          ssh_mem_copy(conn->principal_fingerprint, authorized->fingerprint,
                       sizeof(conn->principal_fingerprint));
          ssh_log(SSH_LOG_INFO, "Public key auth success principal=%s role=%u\n",
                  conn->principal, (uint64_t)conn->principal_role);
          conn->state = SSH_STATE_AUTHENTICATED;
        } else {
          xaios_log("sshd: public key signature verification failed\n");
          conn->auth_attempts++;
          record_auth_failure(&conn->client_addr);
          if (send_auth_failure(conn) != 0) return -1;
          ssh_log(SSH_LOG_WARN, "Public key auth failed (verify)\n");
        }
        return 0;
      }

      /* Unknown auth method */
      if (send_auth_failure(conn) != 0) return -1;
      return 0;
    }

    return 0;
  }

  if (conn->state == SSH_STATE_AUTHENTICATED ||
      conn->state == SSH_STATE_CHANNEL) {
    conn->state = SSH_STATE_CHANNEL;

    uint64_t packets_since_rekey =
        conn->crypto.encrypt_seq - conn->rekey_encrypt_base;
    uint64_t elapsed = now - conn->kex_start_time;
    if (packets_since_rekey >= 1048576U || elapsed >= SSHD_REKEY_INTERVAL) {
      return begin_server_rekey(conn, SSH_STATE_CHANNEL, now);
    }

    /* Check keepalive */
    if (now - conn->last_keepalive > SSHD_KEEPALIVE_INTERVAL) {
      uint8_t keepalive[32];
      keepalive[0] = SSH_MSG_GLOBAL_REQUEST;
      const char *ka_name = "keepalive@xaios.os";
      uint32_t ka_len = ssh_str_len(ka_name);
      ssh_write_u32_be(keepalive + 1, ka_len);
      ssh_mem_copy(keepalive + 5, ka_name, ka_len);
      keepalive[5 + ka_len] = 1;
      conn_packet_write_encrypted(conn, keepalive, 6 + ka_len);
      conn->last_keepalive = now;
      if (now - conn->last_activity > SSHD_TIMEOUT_IDLE) {
        ssh_log(SSH_LOG_WARN, "Idle timeout\n");
        return -1;
      }
    }

    /* Read one packet */
    int packet_status = conn_packet_read_encrypted(conn, pkt);
    if (packet_status > 0) return 0;
    if (packet_status < 0) return -1;
    if (pkt->len == 0) return 0;

    conn->last_activity = now;
    uint8_t msg = pkt->data[0];

    if (msg == SSH_MSG_KEXINIT) {
      return begin_client_rekey(conn, pkt, SSH_STATE_CHANNEL, now);
    }

    if (msg == SSH_MSG_GLOBAL_REQUEST) {
      if (pkt->len < 6U) return -1;
      uint32_t request_len = ssh_read_u32_be(pkt->data + 1U);
      if (request_len > pkt->len - 6U) return -1;
      uint8_t want_reply = pkt->data[5U + request_len];
      if (want_reply != 0U) {
        uint8_t failure = SSH_MSG_REQUEST_FAILURE;
        if (conn_packet_write_encrypted(conn, &failure, 1U) != 0) return -1;
      }
      return 0;
    }

    if (msg >= 90 && msg <= 100) {
      if (ssh_channel_handle_packet(sockfd, pkt) != 0) return -1;
      return 0;
    }

    if (msg == SSH_MSG_DISCONNECT) {
      ssh_log(SSH_LOG_INFO, "Client disconnected\n");
      return -1;
    }

    /* Unknown message */
    return 0;
  }

  return 0;
}

/* ---- Cooperative Polling Main Loop ---- */
int sshd_run(void) {
  if (crypto_random_init() != 0) {
    ssh_log(SSH_LOG_ERROR, "Secure entropy unavailable; refusing SSH startup\n");
    return -1;
  }
  if (ssh_host_key_init() != 0) {
    ssh_log(SSH_LOG_ERROR, "Persistent SSH host key unavailable\n");
    return -1;
  }
  int crypto_status = ssh_crypto_self_test();
  if (crypto_status != 0) {
    ssh_log(SSH_LOG_ERROR, "SSH crypto self-test failed check=%u\n",
            (uint64_t)(uint32_t)(-crypto_status));
    return -1;
  }
  ssh_log(SSH_LOG_INFO, "SSH crypto self-test passed\n");

  if (load_runtime_config() != 0) {
    ssh_log(SSH_LOG_ERROR, "SSH runtime configuration rejected\n");
    return -1;
  }

  if (load_user_database() != 0) {
    ssh_log(SSH_LOG_ERROR, "SSH user database rejected\n");
    return -1;
  }
  (void)load_authorized_keys();
  if (g_authorized_database_invalid != 0U) return -1;

  ssh_mem_zero(&g_server_stats, sizeof(g_server_stats));

  ssh_conn_pool_init();

  u64 listen_fd = 0;
  if (xaios_net_listen(SSHD_PORT, &listen_fd) != 0) {
    ssh_log(SSH_LOG_ERROR, "Failed to listen on port %u\n", SSHD_PORT);
    return -1;
  }
  u64 udp_fd = 0;
  if (xaios_net_bind_udp(SSHD_UDP_ECHO_PORT, &udp_fd) != 0) {
    ssh_log(SSH_LOG_ERROR, "Failed to bind UDP port %u\n",
            SSHD_UDP_ECHO_PORT);
    xaios_net_close(listen_fd);
    return -1;
  }
  ssh_log(SSH_LOG_INFO, "SSH server listening on port %u\n", SSHD_PORT);
  ssh_log(SSH_LOG_INFO, "UDP echo service listening on port %u\n",
          SSHD_UDP_ECHO_PORT);
  ssh_log(SSH_LOG_INFO, "Cooperative polling: max %u concurrent connections\n",
          (uint64_t)SSH_MAX_CONNECTIONS);

  ssh_channel_init();
  xaios_log("sshd: Phase 2 runtime ready\n");

  for (;;) {
    for (uint32_t i = 0; i < 4U; ++i) {
      uint8_t udp_buffer[1400];
      xaios_ip_addr_user_t source_addr;
      u64 bytes_read = 0;
      u64 bytes_written = 0;
      xaios_memzero(&source_addr, sizeof(source_addr));
      if (xaios_net_recvfrom(udp_fd, udp_buffer, sizeof(udp_buffer),
                             &bytes_read, &source_addr) != 0 ||
          bytes_read == 0) {
        break;
      }
      if (xaios_net_send(udp_fd, udp_buffer, bytes_read, &bytes_written) != 0 ||
          bytes_written != bytes_read) {
        ssh_log(SSH_LOG_WARN, "UDP echo send failed\n");
      } else {
        ssh_log(SSH_LOG_INFO, "UDP payload delivered bytes=%u\n", bytes_read);
      }
    }

    /* Try to accept new connections (non-blocking) */
    for (uint32_t i = 0; i < 4; ++i) {
      u64 conn_fd = 0;
      xaios_ip_addr_user_t peer_addr;
      u64 peer_port = 0;
      xaios_memzero(&peer_addr, sizeof(peer_addr));
      if (xaios_net_accept_addr(listen_fd, &conn_fd, &peer_addr, &peer_port) != 0) {
        break;
      }

      if (record_connection_attempt(&peer_addr) != 0) {
        ssh_log(SSH_LOG_WARN, "Connection rate limit reached\n");
        xaios_net_close(conn_fd);
        continue;
      }

      uint32_t active = __atomic_load_n(&g_server_stats.active_connections,
                                         __ATOMIC_ACQUIRE);
      if (active >= g_runtime_config.max_connections) {
        ssh_log(SSH_LOG_WARN, "Max connections reached\n");
        uint32_t rejected = __atomic_add_fetch(
            &g_server_stats.rejected_connections, 1, __ATOMIC_RELEASE);
        if (rejected == 1U) {
          xaios_log("sshd: connection capacity rejection observed\n");
        }
        xaios_net_close(conn_fd);
        continue;
      }

      ssh_connection_t *conn = ssh_conn_alloc();
      if (!conn) {
        xaios_net_close(conn_fd);
        continue;
      }

      conn->sockfd = conn_fd;
      conn->client_addr = peer_addr;
      conn->client_port = (uint16_t)peer_port;
      conn->state = SSH_STATE_INIT;
      conn->last_activity = timer_now();
      conn->last_keepalive = conn->last_activity;
      conn->connect_time = conn->last_activity;
      conn->version_len = 0;
      conn->auth_attempts = 0;

      __atomic_add_fetch(&g_server_stats.total_connections, 1, __ATOMIC_RELEASE);
      __atomic_add_fetch(&g_server_stats.active_connections, 1, __ATOMIC_RELEASE);
      ssh_log(SSH_LOG_INFO, "Accepted connection %llx (total: %u)\n",
              conn_fd, active + 1);
    }

    /* Process each active connection (cooperative time-slicing) */
    for (uint32_t i = 0; i < SSH_MAX_CONNECTIONS; ++i) {
      ssh_connection_t *conn = ssh_conn_by_index(i);
      if (!conn) continue;

      /* Check for timeouts */
      uint64_t now = timer_now();
      if (conn->state == SSH_STATE_INIT || conn->state == SSH_STATE_KEX ||
          conn->state == SSH_STATE_KEX_SENT || conn->state == SSH_STATE_NEWKEYS ||
          conn->state == SSH_STATE_NEWKEYS_SENT ||
          conn->state == SSH_STATE_REKEY_KEXINIT ||
          conn->state == SSH_STATE_REKEY_DH ||
          conn->state == SSH_STATE_REKEY_NEWKEYS) {
        uint64_t exchange_start = conn->state >= SSH_STATE_REKEY_KEXINIT ?
                                      conn->kex_start_time : conn->connect_time;
        if (now - exchange_start > SSHD_TIMEOUT_CONNECT) {
          ssh_log(SSH_LOG_WARN, "Connect timeout\n");
          goto close_conn;
        }
      }
      if (conn->state == SSH_STATE_AUTH) {
        if (now - conn->connect_time > SSHD_TIMEOUT_AUTH) {
          ssh_log(SSH_LOG_WARN, "Auth timeout\n");
          goto close_conn;
        }
      }

      int result = conn->close_requested != 0U ? -1 : process_connection(conn);
      if (result != 0) {
close_conn:
        /* Send disconnect message if encrypted */
        if (conn->state >= SSH_STATE_AUTH) {
          uint8_t disconnect_msg[17];
          ssh_mem_zero(disconnect_msg, sizeof(disconnect_msg));
          disconnect_msg[0] = SSH_MSG_DISCONNECT;
          ssh_write_u32_be(disconnect_msg + 1, SSH_DISCONNECT_BY_APPLICATION);
          ssh_write_u32_be(disconnect_msg + 5, 0);
          ssh_write_u32_be(disconnect_msg + 9, 0);
          conn_packet_write_encrypted(conn, disconnect_msg, 13);
        }

        ssh_channel_close_connection((int)conn->sockfd);
        xaios_net_close(conn->sockfd);
        __atomic_sub_fetch(&g_server_stats.active_connections, 1,
                           __ATOMIC_RELEASE);
        ssh_conn_free(conn);
        ssh_log(SSH_LOG_INFO, "Connection closed\n");
      }
    }
  }

  return 0;
}

int main(void) {
  int status = sshd_run();
  xaios_exit(status == 0 ? 0 : 1);
  return 0;
}
