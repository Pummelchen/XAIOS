/*
 * sshd's credential verification: the password user database, the local console
 * PIN, and the console lockout that paces guesses against both.
 *
 * Split whole out of sshd.c. The state only these functions touch -- the parsed
 * user table, the parsed PIN, the failure count and the lockout clock -- moves
 * with them. sshd.c keeps the console login state machine that calls them
 * (console_submit_auth(), console_auth_failed(), console_auth_succeeded())
 * because it shares the console command buffer and the auth state with
 * console_tick(), which stays whole. See sshd_auth.h for what crosses.
 *
 * Nothing here hands out a pointer into the user table: sshd_auth_account_name()
 * copies into the caller's buffer.
 */

#include "sshd_auth.h"

#include "ssh_crypto.h"
#include "ssh_utils.h"

/* ---- Local Console Lockout ----
   Consecutive failures cost the attacker wall clock time. This matters most
   for the six digit PIN, whose search space is small enough to exhaust in
   seconds against a prompt that answers instantly. */
#define SSHD_CONSOLE_FAILURE_LIMIT 5U
#define SSHD_CONSOLE_LOCKOUT_NS UINT64_C(60000000000)

static uint64_t g_console_lockout_until_ns;
static uint32_t g_console_auth_failures;

int sshd_auth_console_locked_out(void) {
  if (g_console_lockout_until_ns == 0U) return 0;
  if (xaios_clock_nanos() >= g_console_lockout_until_ns) {
    g_console_lockout_until_ns = 0U;
    g_console_auth_failures = 0U;
    return 0;
  }
  return 1;
}

/* The value only, without the expiry check sshd_auth_console_locked_out()
   performs: the caller has just recorded a failure and is asking whether that
   failure tripped the lockout. */
int sshd_auth_console_lockout_active(void) {
  return g_console_lockout_until_ns != 0U;
}

void sshd_auth_console_record_failure(void) {
  if (++g_console_auth_failures >= SSHD_CONSOLE_FAILURE_LIMIT) {
    g_console_lockout_until_ns = xaios_clock_nanos() + SSHD_CONSOLE_LOCKOUT_NS;
  }
}

void sshd_auth_console_clear_failures(void) {
  g_console_auth_failures = 0U;
  g_console_lockout_until_ns = 0U;
}

/* ---- User Database ---- */
#define SSHD_USERS_PATH "/etc/xaios_sshd_users"

static sshd_user_t g_users[SSHD_MAX_USERS];
static uint32_t g_user_count = 0;

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
  /* Any name the grammar allows, not one name. The record used to be required
     to begin "admin", which meant a machine could only ever have the account
     the build shipped -- and once a released image stopped shipping one, no
     account at all. What matters is that the name cannot forge the rest of
     the record or the prompt it is echoed to, so the character class is the
     check: lower-case letters, digits, - and _. */
  for (uint32_t i = 0; i < separator[0]; ++i) {
    char c = line[i];
    int ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' ||
             c == '_';
    if (!ok) return -1;
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
  for (uint32_t i = 0; i < separator[0]; ++i) user->username[i] = line[i];
  user->username[separator[0]] = '\0';
  user->password_salt_len = salt_len;
  user->password_iterations = iterations;
  user->active = 1;
  return 0;
}

int sshd_auth_load_users(uint32_t password_auth_enabled) {
  char buffer[4096];
#if XAIOS_PASSWORD_AUTH_AVAILABLE == 0
  ssh_mem_zero(g_users, sizeof(g_users));
  g_user_count = 0U;
  ssh_log(SSH_LOG_INFO, "Password authentication unavailable in this build\n");
  return 0;
#endif
  if (password_auth_enabled == 0) {
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

uint32_t sshd_auth_user_count(void) { return g_user_count; }

/* Whether this machine has an account by that name. The console and the SSH
   path both used to compare against the literal "admin"; they ask this now, so
   a machine set up with another name can be logged into with it. */
int sshd_auth_user_exists(const char *username) {
  for (uint32_t i = 0U; i < g_user_count; ++i) {
    if (g_users[i].active && ssh_str_eq(g_users[i].username, username)) {
      return 1;
    }
  }
  return 0;
}

/* The name this machine's account goes by: the password database when there
   is one, and "admin" when there is not. A key-only image has no password
   database at all -- authorized keys and nothing else, which is a configured
   machine rather than an unconfigured one -- and its logins have always been
   "admin". Copied out rather than returned as a pointer into the table. */
uint32_t sshd_auth_account_name(char *out, uint32_t capacity) {
  const char *name = "admin";
  for (uint32_t i = 0U; i < g_user_count; ++i) {
    if (g_users[i].active) {
      name = g_users[i].username;
      break;
    }
  }
  uint32_t length = ssh_str_len(name);
  if (out == 0 || capacity == 0U) return length;
  if (length >= capacity) length = capacity - 1U;
  ssh_mem_copy(out, name, length);
  out[length] = '\0';
  return length;
}

int sshd_auth_password_verify(const char *username, const char *password) {
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

/* ---- Local Console PIN ----
   A six digit PIN is a 10^6 search space, so this credential is deliberately
   restricted: it is accepted only on the local console, never over SSH, and
   only when password authentication is already enabled for the image. The
   console prompt is rate limited below, because an unthrottled prompt makes a
   space this small trivially searchable. */
#define SSHD_CONSOLE_PIN_PATH "/etc/xaios_console_pin"
#define SSHD_CONSOLE_PIN_DIGITS 6U

static uint8_t g_console_pin_salt[SSHD_PASSWORD_SALT_MAX];
static uint8_t g_console_pin_hash[32];
static uint32_t g_console_pin_salt_len;
static uint32_t g_console_pin_iterations;
static uint32_t g_console_pin_available;

int sshd_auth_pin_available(void) { return g_console_pin_available != 0U; }

static int parse_console_pin_line(const char *line, uint32_t line_len) {
  uint32_t separator[3];
  uint32_t separator_count = 0U;
  while (line_len > 0U && line[line_len - 1U] == '\r') --line_len;
  if (line_len == 0U || line[0] == '#') return 1;
  for (uint32_t i = 0U; i < line_len; ++i) {
    if (line[i] != ':') continue;
    if (separator_count >= 3U) return -1;
    separator[separator_count++] = i;
  }
  if (separator_count != 3U) return -1;

  static const char scheme[] = "pbkdf2-sha256";
  if (separator[0] != sizeof(scheme) - 1U) return -1;
  for (uint32_t i = 0U; i < sizeof(scheme) - 1U; ++i) {
    if (line[i] != scheme[i]) return -1;
  }

  uint32_t iterations = 0U;
  if (parse_decimal_u32(line + separator[0] + 1U,
                        separator[1] - separator[0] - 1U, &iterations) != 0 ||
      iterations < SSHD_PASSWORD_ITERATIONS_MIN ||
      iterations > SSHD_PASSWORD_ITERATIONS_MAX) {
    return -1;
  }

  uint32_t salt_len = 0U;
  if (parse_hex_bytes(line + separator[1] + 1U,
                      separator[2] - separator[1] - 1U, g_console_pin_salt,
                      sizeof(g_console_pin_salt), &salt_len) != 0 ||
      salt_len == 0U) {
    return -1;
  }
  uint32_t hash_len = 0U;
  if (parse_hex_bytes(line + separator[2] + 1U, line_len - separator[2] - 1U,
                      g_console_pin_hash, sizeof(g_console_pin_hash),
                      &hash_len) != 0 ||
      hash_len != sizeof(g_console_pin_hash)) {
    return -1;
  }
  g_console_pin_salt_len = salt_len;
  g_console_pin_iterations = iterations;
  return 0;
}

int sshd_auth_load_pin(uint32_t password_auth_enabled) {
  char buffer[512];
  ssh_mem_zero(g_console_pin_salt, sizeof(g_console_pin_salt));
  ssh_mem_zero(g_console_pin_hash, sizeof(g_console_pin_hash));
  g_console_pin_salt_len = 0U;
  g_console_pin_iterations = 0U;
  g_console_pin_available = 0U;
  /* The PIN never widens the authentication surface on its own: an image with
     password authentication disabled stays key-only. */
  if (password_auth_enabled == 0) return 0;

  int result = xaios_read_file(SSHD_CONSOLE_PIN_PATH, buffer, sizeof(buffer));
  if (result <= 0) return 0;

  uint32_t line_start = 0U;
  for (uint32_t i = 0U; i <= (uint32_t)result; ++i) {
    if (i != (uint32_t)result && buffer[i] != '\n') continue;
    int parsed = parse_console_pin_line(buffer + line_start, i - line_start);
    if (parsed < 0) {
      ssh_mem_zero(buffer, sizeof(buffer));
      ssh_mem_zero(g_console_pin_salt, sizeof(g_console_pin_salt));
      ssh_mem_zero(g_console_pin_hash, sizeof(g_console_pin_hash));
      g_console_pin_salt_len = 0U;
      g_console_pin_iterations = 0U;
      ssh_log(SSH_LOG_ERROR, "Invalid local console PIN record\n");
      return -1;
    }
    if (parsed == 0) {
      g_console_pin_available = 1U;
      break;
    }
    line_start = i + 1U;
  }
  ssh_mem_zero(buffer, sizeof(buffer));
  if (g_console_pin_available != 0U)
    ssh_log(SSH_LOG_INFO, "Local console PIN authentication enabled\n");
  return 0;
}

int sshd_auth_pin_verify(const char *pin) {
  static const uint8_t dummy_salt[16] = {
    0x58,0x41,0x49,0x4f,0x53,0x2d,0x50,0x49,
    0x4e,0x2d,0x44,0x55,0x4d,0x4d,0x59,0x31
  };
  static const uint8_t dummy_hash[32] = {0};
  const uint8_t *salt = g_console_pin_available != 0U ? g_console_pin_salt
                                                      : dummy_salt;
  const uint8_t *expected = g_console_pin_available != 0U ? g_console_pin_hash
                                                          : dummy_hash;
  uint32_t salt_len = g_console_pin_available != 0U ? g_console_pin_salt_len
                                                    : (uint32_t)sizeof(dummy_salt);
  uint32_t iterations = g_console_pin_available != 0U
                            ? g_console_pin_iterations
                            : SSHD_PASSWORD_ITERATIONS_MIN;
  uint8_t hash[32];
  if (pbkdf2_hmac_sha256((const uint8_t *)pin, ssh_str_len(pin), salt,
                         salt_len, iterations, hash) != 0) {
    return -1;
  }
  /* Fold availability into the accumulator so a missing PIN record cannot
     authenticate regardless of the derived hash, and keep the compare
     constant time. */
  uint8_t diff = (uint8_t)(g_console_pin_available == 0U);
  for (uint32_t i = 0U; i < sizeof(hash); ++i) diff |= hash[i] ^ expected[i];
  ssh_mem_zero(hash, sizeof(hash));
  return diff == 0U ? 0 : -1;
}

int sshd_auth_pin_prefix(const char *text, uint32_t length) {
  if (length == 0U || length > SSHD_CONSOLE_PIN_DIGITS) return 0;
  for (uint32_t i = 0U; i < length; ++i) {
    if (text[i] < '0' || text[i] > '9') return 0;
  }
  return 1;
}

int sshd_auth_pin_matches(const char *text, uint32_t length) {
  return length == SSHD_CONSOLE_PIN_DIGITS &&
         sshd_auth_pin_prefix(text, length);
}
