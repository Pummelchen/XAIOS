#include "sshd.h"
#include "sshd_auth.h"
#include "sshd_audit.h"
#include "sshd_console_screen.h"
#include "sshd_console_programs.h"
#include "ssh_connection.h"
#include "ssh_crypto.h"
#include "ssh_protocol.h"
#include "ssh_channel.h"
#include "ssh_host_key.h"
#include "ssh_mlkem.h"
#include "ssh_utils.h"
#include "tweetnacl_subset.h"
#include "less_pager.h"
#include <xaios_screen.h>
#include "nano_editor.h"
#include "pong_game.h"
#include <xaios_user.h>
#include "sshd_internal.h"
#include "sshd_diagnostics.h"
#include "sshd_console_ui.h"

static sshd_stats_t g_server_stats;
static xaios_admin_config_user_t g_runtime_config;
/* Read by this file's console login state and by sshd_console_ui.c, which
   renders the login screen and decides whether the console opens a shell. */
uint32_t g_password_auth_enabled;

#define SSHD_CONSOLE_COMMAND_MAX UINT32_C(256)

/* The console command line console_tick() edits. The rest of the console state
   is defined here too, because that hub reads and writes it directly every
   pass; sshd_console_ui.c reaches all of it through sshd_console_ui.h. */
static char g_console_command[SSHD_CONSOLE_COMMAND_MAX];
char g_console_output[SSHD_CONSOLE_OUTPUT_MAX];
uint32_t g_console_command_length;
uint32_t g_console_ignore_lf;
uint32_t g_console_ipv4;
uint32_t g_console_ssh_ready;
int32_t g_console_boot_error;
nano_editor_t g_console_nano;
pong_game_t g_console_pong;
less_pager_t g_console_less;
uint32_t g_console_auth_state;

/* Defined below with the console session state they read and write. */
static void console_set_username(const char *username);

/* Running count of closed connections; log_durable_cost() is given it after
   each close and sshd_diagnostics.c prints it in its per-close line. */
static uint32_t g_connection_close_count;

uint64_t sshd_fnv1a64_zero_range(const void *data, uint64_t size,
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

int sshd_read_exact_file(const char *path, void *buffer, uint64_t size) {
  xaios_xbfs_stat_user_t stat;
  if (path == 0 || buffer == 0 || size == 0U ||
      xaios_fs_stat(path, &stat) != 0 || stat.size != size) {
    return -1;
  }
  int fd = xaios_fs_open(path, XAIOS_XBFS_OPEN_READ);
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
             sshd_fnv1a64_zero_range(config, sizeof(*config), checksum_offset,
                                     sizeof(config->checksum));
}

static int load_runtime_config(void) {
  xaios_admin_config_user_t config;
  if (sshd_read_exact_file(XAIOS_ADMIN_CONFIG_PATH, &config,
                           sizeof(config)) != 0 ||
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

/* The active-connection count sshd_diagnostics.c prints in its stall lines.
   A value, not the statistics block: the counters stay here with the accept
   path that updates them. */
uint32_t sshd_active_connections(void) {
  return __atomic_load_n(&g_server_stats.active_connections, __ATOMIC_ACQUIRE);
}

/* The reason the connection currently being serviced is giving up.
 *
 * sshd is one thread and process_connection runs for one connection at a
 * time; the walk reads this immediately after the call that set it, so one
 * slot is the whole requirement. Cleared at the top of every connection's
 * turn, so a reason can never be attributed to the wrong close. */
static const char *g_close_reason;

static int close_because(const char *reason) {
  g_close_reason = reason;
  return -1;
}

/* ---- Timer ---- */
static uint64_t timer_now(void) {
  return xaios_clock_nanos();
}

/* Which background services this machine was told to start.

   One list, one name per line, written by setup. A machine that has never
   been set up has no file and everything starts, which is what every image
   did before this.

   Only the network listener is selectable today. The console is not a service
   in this sense -- it is how a person reaches a machine that has no network,
   and a switch that could turn it off is a switch that can strand a machine
   nobody can reach. */
#define SSHD_SERVICES_PATH "/etc/xaios_services"

static int service_enabled(const char *name) {
  char list[256];
  int length = xaios_read_file(SSHD_SERVICES_PATH, list, sizeof(list) - 1U);
  if (length <= 0) return 1; /* never configured: start everything */
  list[length] = '\0';
  uint32_t start = 0U;
  for (uint32_t i = 0U; i <= (uint32_t)length; ++i) {
    if (i != (uint32_t)length && list[i] != '\n' && list[i] != ',') continue;
    uint32_t end = i;
    while (end > start && (list[end - 1U] == '\r' || list[end - 1U] == ' ')) {
      --end;
    }
    uint32_t j = 0U;
    while (start + j < end && name[j] != '\0' && list[start + j] == name[j]) {
      ++j;
    }
    if (name[j] == '\0' && start + j == end) return 1;
    start = i + 1U;
  }
  return 0;
}

static int verify_ipv4_ready(void) {
  /* The kernel reaches this service only after NIC selection and IPv4 setup.
   * Keep SSH availability independent of a third-party DNS/TCP endpoint. */
  u32 address = xaios_net_local_ipv4();
  return address != 0U && address != UINT32_MAX ? 0 : -1;
}

static void console_execute_command(void) {
  g_console_command[g_console_command_length] = '\0';
  console_write("\n");
  if (g_console_command_length == 0U) {
    console_prompt();
    return;
  }
  char nano_argument[NANO_EDITOR_PATH_MAX];
  if (console_nano_argument(g_console_command, nano_argument,
                            sizeof(nano_argument)) == 0) {
    (void)console_start_nano(g_console_command);
  } else if (ssh_str_eq(g_console_command, "pong")) {
    (void)console_start_pong();
  } else if (g_console_command[0] == 'l' && g_console_command[1] == 'e' &&
             g_console_command[2] == 's' && g_console_command[3] == 's' &&
             (g_console_command[4] == '\0' || g_console_command[4] == ' ')) {
    (void)console_start_less(g_console_command);
  } else if (sshd_console_command_is_xtop(g_console_command)) {
    (void)sshd_console_program_start(g_console_command,
                                     sizeof(g_console_command),
                                     console_username());
  } else if (ssh_str_eq(g_console_command, "clear")) {
    console_write("\x1b[2J\x1b[H");
  } else if (ssh_str_eq(g_console_command, "exit") ||
             ssh_str_eq(g_console_command, "logout") ||
             ssh_str_eq(g_console_command, "quit")) {
    (void)xaios_remote_login_session_close(SSHD_CONSOLE_SESSION_ID);
    console_write("logout\n");
    g_console_auth_state = SSHD_CONSOLE_AUTH_USER;
    g_console_command_length = 0U;
    console_write_login_prompt();
    return;
  } else {
    u64 output_bytes = 0U;
    /* Launch terminal applications with the same options the SSH channel
       gives them, so xtop and friends render identically on both surfaces
       rather than falling back to their plain snapshot form here. */
    (void)ssh_terminal_promote_command(g_console_command,
                                       sizeof(g_console_command),
                                       sshd_console_columns(),
                                       sshd_console_rows());
    xaios_memzero(g_console_output, sizeof(g_console_output));
    int status = xaios_remote_login_session(
        SSHD_CONSOLE_SESSION_ID, console_username(), g_console_command,
        g_console_output,
        sizeof(g_console_output), &output_bytes);
    if (output_bytes != 0U) {
      (void)sshd_console_write_bytes(g_console_output, output_bytes);
      if (g_console_output[output_bytes - 1U] != '\n') console_write("\n");
    }
    if (status < 0 && output_bytes == 0U) {
      console_write("command failed: status=");
      console_write_error(status);
      console_write("\n");
    }
  }
  g_console_command_length = 0U;
  if (g_console_nano.active == 0U && g_console_pong.active == 0U &&
      sshd_console_program_active() == 0 && g_console_less.active == 0U)
    console_prompt();
}

static void console_auth_failed(void) {
  sshd_auth_console_record_failure();
  g_console_auth_state = SSHD_CONSOLE_AUTH_USER;
  if (sshd_auth_console_lockout_active() != 0) {
    console_write(
        "Login incorrect\n"
        "Too many failed attempts. Try again in 60 seconds.\n");
    console_write_login_prompt();
    return;
  }
  console_write("Login incorrect\n");
  console_write_login_prompt();
}

void console_auth_succeeded(void) {
  sshd_auth_console_clear_failures();
  g_console_auth_state = SSHD_CONSOLE_AUTH_SHELL;
  console_write("XAIOS local console session opened\n");
  console_prompt();
}

static void console_submit_auth(void) {
  uint32_t submitted_length = g_console_command_length;
  g_console_command[g_console_command_length] = '\0';
  console_write("\n");
  if (sshd_auth_console_locked_out()) {
    console_write("Locked out. Try again in a moment.\n");
    console_write_login_prompt();
    g_console_auth_state = SSHD_CONSOLE_AUTH_USER;
    xaios_memzero(g_console_command, sizeof(g_console_command));
    g_console_command_length = 0U;
    return;
  }
  if (g_console_auth_state == SSHD_CONSOLE_AUTH_USER) {
    if (sshd_auth_pin_available() != 0U &&
        sshd_auth_pin_matches(g_console_command, submitted_length)) {
      if (sshd_auth_pin_verify(g_console_command) != 0) {
        console_auth_failed();
      } else {
        /* A PIN identifies the machine's account rather than naming one, so
           it logs in as that account. */
        console_set_account_username();
        console_auth_succeeded();
      }
    } else if (!sshd_auth_user_exists(g_console_command)) {
      console_write("Login incorrect\n");
      console_write_login_prompt();
      sshd_auth_console_record_failure();
    } else {
      console_set_username(g_console_command);
      g_console_auth_state = SSHD_CONSOLE_AUTH_PASSWORD;
      console_write("Password: ");
    }
  } else if (g_console_auth_state == SSHD_CONSOLE_AUTH_PASSWORD) {
    if (sshd_auth_password_verify(console_username(), g_console_command) != 0) {
      console_auth_failed();
    } else {
      console_auth_succeeded();
    }
  }
  xaios_memzero(g_console_command, sizeof(g_console_command));
  g_console_command_length = 0U;
}

static void console_tick(void) {
  for (uint32_t count = 0U; count < 32U; ++count) {
    char value = 0;
    int received = xaios_console_read(&value);
    if (received <= 0) return;
    if (g_console_nano.active != 0U) {
      uint32_t frame_size = 0U;
      uint32_t should_exit = 0U;
      if (nano_editor_input(&g_console_nano, (const uint8_t *)&value, 1U,
                            &should_exit) != 0) {
        should_exit = 1U;
      }
      if (should_exit != 0U) {
        g_console_nano.active = 0U;
        console_write(
            "\033[0m\033[?25h\033[?1049l\033[0m\033[?25h\r");
        console_prompt();
      } else if (nano_editor_render(&g_console_nano, g_console_output,
                                    sizeof(g_console_output),
                                    &frame_size) == 0) {
        (void)sshd_console_write_bytes(g_console_output, frame_size);
      }
      continue;
    }
    if (g_console_less.active != 0U) {
      uint32_t frame_size = 0U;
      uint32_t should_exit = 0U;
      if (less_pager_input(&g_console_less, (const uint8_t *)&value, 1U,
                           &should_exit) != 0) {
        should_exit = 1U;
      }
      if (should_exit != 0U) {
        console_finish_less();
      } else if (less_pager_render(&g_console_less, g_console_output,
                                   sizeof(g_console_output),
                                   &frame_size) == 0) {
        (void)sshd_console_write_bytes(g_console_output, frame_size);
      }
      continue;
    }
    if (sshd_console_program_active() != 0) {
      sshd_console_program_input(value);
      continue;
    }
    if (g_console_pong.active != 0U) {
      uint32_t should_exit = 0U;
      uint64_t now_ns = xaios_clock_nanos();
      if (pong_game_input(&g_console_pong, (const uint8_t *)&value, 1U,
                          &should_exit, now_ns) != 0 ||
          should_exit != 0U) {
        console_finish_pong();
      } else if (console_render_pong(now_ns) != 0) {
        console_finish_pong();
      }
      continue;
    }
    if (value == '\n' && g_console_ignore_lf != 0U) {
      g_console_ignore_lf = 0U;
      continue;
    }
    g_console_ignore_lf = 0U;
    if (value == '\r' || value == '\n') {
      g_console_ignore_lf = value == '\r' ? 1U : 0U;
      if (g_console_auth_state == SSHD_CONSOLE_AUTH_SHELL) {
        console_execute_command();
      } else if (g_console_auth_state != SSHD_CONSOLE_AUTH_LOCKED) {
        console_submit_auth();
      }
    } else if (value == '\b' || (uint8_t)value == UINT8_C(0x7f)) {
      if (g_console_command_length != 0U) {
        --g_console_command_length;
        if (g_console_auth_state != SSHD_CONSOLE_AUTH_PASSWORD) {
          console_write("\b \b");
        }
      }
    } else if ((uint8_t)value == UINT8_C(0x03)) {
      g_console_command_length = 0U;
      console_write("^C\n");
      if (g_console_auth_state == SSHD_CONSOLE_AUTH_SHELL) {
        console_prompt();
      } else if (g_console_auth_state == SSHD_CONSOLE_AUTH_USER) {
        console_write_login_prompt();
      } else if (g_console_auth_state == SSHD_CONSOLE_AUTH_PASSWORD) {
        console_write("Password: ");
      }
    } else if ((uint8_t)value == UINT8_C(0x0c)) {
      console_render_boot_status();
    } else if (g_console_auth_state != SSHD_CONSOLE_AUTH_LOCKED &&
               value >= ' ' && value <= '~' &&
               g_console_command_length + 1U < sizeof(g_console_command)) {
      g_console_command[g_console_command_length++] = value;
      if (g_console_auth_state == SSHD_CONSOLE_AUTH_PASSWORD) {
        /* Never echo a password. */
      } else if (g_console_auth_state == SSHD_CONSOLE_AUTH_USER &&
                 sshd_auth_pin_available() != 0U &&
                 sshd_auth_pin_prefix(g_console_command,
                                      g_console_command_length)) {
        /* An all-digit entry at the login prompt may be a PIN, which is a
           secret rather than a user name, so mask it while it is typed. A
           user name that merely starts with digits is masked for those
           leading digits only. */
        static const char masked = '*';
        (void)xaios_console_write(&masked, 1U);
      } else {
        (void)xaios_console_write(&value, 1U);
      }
    }
  }
}

/* The password user database, the password and PIN checks, and the console
   lockout moved to sshd_auth.c; sshd_auth.h declares what crosses. What stays
   here is the console's own session identity, which the console login state
   machine above reads and writes. */

/* The console's own idea of who is at it. Set when a name is accepted at the
   prompt, and when a PIN is -- a PIN identifies the machine's single account
   rather than naming one, so it authenticates as that account. Commands the
   console dispatches run as this user, which is what makes the name mean
   anything past the prompt. */
static char g_console_username[SSHD_USERNAME_MAX];

static void console_set_username(const char *username) {
  uint32_t i = 0U;
  while (username[i] != '\0' && i + 1U < sizeof(g_console_username)) {
    g_console_username[i] = username[i];
    ++i;
  }
  g_console_username[i] = '\0';
}

/* The account a PIN logs in as, or the name the machine's account goes by when
   there is no password database. Copied out of sshd_auth.c rather than held as
   a pointer into its user table. */
void console_set_account_username(void) {
  (void)sshd_auth_account_name(g_console_username, sizeof(g_console_username));
}

/* Who the console is acting as. Falls back to the machine's account so a
   command dispatched before a name was recorded still names someone. The
   account name is filled into this file's own console session buffer, not
   returned from sshd_auth.c as a pointer into its table. */
const char *console_username(void) {
  if (g_console_username[0] == '\0') console_set_account_username();
  return g_console_username;
}

int sshd_bytes_equal(const uint8_t *left, const uint8_t *right,
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
      !sshd_bytes_equal(version, prefix, sizeof(prefix) - 1U)) {
    return 0;
  }
  for (uint32_t i = 0; i < text_length; ++i) {
    if (version[i] < 32U || version[i] > 126U) return 0;
  }
  return 1;
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
    if (sshd_auth_load_users(g_password_auth_enabled) != 0) return -1;
    if (sshd_auth_load_pin(g_password_auth_enabled) != 0) return -1;
    ssh_log(SSH_LOG_INFO, "Applied SSH runtime configuration generation=%u\n",
            g_runtime_config.generation);
  } else if (command_starts_with(command, "xaiosctl auth key add ") ||
             command_starts_with(command, "xaiosctl auth key remove ")) {
    if (sshd_keys_load() != 0) return -1;
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
        if (status != 0) return close_because("peer-gone");
        if (n == 0) return 0;
        conn->version_len += (uint32_t)n;
        if (conn->version_buf[conn->version_len - 1U] == '\n') break;
      }
      if (conn->version_len == sizeof(conn->version_buf) &&
          conn->version_buf[conn->version_len - 1U] != '\n') {
        return close_because("client-version-too-long");
      }
    }
    if (!valid_client_version(conn->version_buf, conn->version_len)) {
      ssh_log(SSH_LOG_WARN, "Rejected invalid SSH client version");
      return close_because("client-version-invalid");
    }

    if (send_server_kexinit(conn, 0) != 0) return -1;
    conn->state = SSH_STATE_KEX_SENT;
    return 0;
  }

  if (conn->state == SSH_STATE_KEX_SENT) {
    /* Receive client KEXINIT */
    int packet_status = ssh_packet_read(sockfd, pkt);
    if (packet_status > 0) return 0;
    if (packet_status < 0) return close_because("packet-read-failed");
    if (validate_client_kexinit(conn, pkt) != 0) return -1;
    init_exchange_hash(conn, pkt);
    conn->state = SSH_STATE_NEWKEYS;
    return 0;
  }

  if (conn->state == SSH_STATE_NEWKEYS) {
    /* KEXDH_INIT */
    int packet_status = ssh_packet_read(sockfd, pkt);
    if (packet_status > 0) return 0;
    if (packet_status < 0) return close_because("packet-read-failed");
    if (handle_kexdh_init(conn, pkt, 0) != 0) return -1;
    conn->state = SSH_STATE_NEWKEYS_SENT;
    return 0;
  }

  if (conn->state == SSH_STATE_NEWKEYS_SENT) {
    /* Receive NEWKEYS */
    int packet_status = ssh_packet_read(sockfd, pkt);
    if (packet_status > 0) return 0;
    if (packet_status < 0) return close_because("packet-read-failed");
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
    if (packet_status < 0 || validate_client_kexinit(conn, pkt) != 0)
      return -1;
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
    if (packet_status < 0) return close_because("packet-read-failed");
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
          !sshd_bytes_equal(pkt->data + 5U,
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
        if (g_password_auth_enabled == 0U || sshd_auth_user_count() == 0U) {
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

        int authenticated = sshd_auth_password_verify(username, password);
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
        /* What authorises a public-key login is the key, checked below
           against the authorized keys; the username is the identity it
           claims. Asking the *password* database whether that name exists
           refuses every key login on a key-only image, where that database is
           empty by design -- which is what this did, and what stopped two
           interoperability gates. */
        char account[SSHD_USERNAME_MAX];
        (void)sshd_auth_account_name(account, sizeof(account));
        if (!sshd_auth_user_exists(username) &&
            !ssh_str_eq(username, account)) {
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
            !sshd_bytes_equal(algorithm, (const uint8_t *)"ssh-ed25519", 11U)) {
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
        if (sshd_keys_blob_parse(pubkey_blob, pubkey_len,
                                 client_pubkey) != 0) return 0;
        offset += pubkey_len;
        uint32_t signed_request_len = offset;

        sshd_keys_entry_t authorized;
        int authorized_found = 0;
        ssh_mem_zero(&authorized, sizeof(authorized));
        if (sshd_keys_load() == 0) {
          authorized_found = sshd_keys_lookup(client_pubkey, &authorized) == 0;
        }
        if (!authorized_found) {
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
            !sshd_bytes_equal(sig_blob + 4U,
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
          conn->principal_role = authorized.role;
          ssh_mem_copy(conn->principal, authorized.principal,
                       sizeof(conn->principal));
          ssh_mem_copy(conn->principal_fingerprint, authorized.fingerprint,
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
        return close_because("idle-timeout");
      }
    }

    /* Read one packet */
    int packet_status = conn_packet_read_encrypted(conn, pkt);
    if (packet_status > 0) return 0;
    if (packet_status < 0) return close_because("packet-read-failed");
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
      return close_because("client-disconnect");
    }

    /* Unknown message */
    return 0;
  }

  return 0;
}

/* ---- Cooperative Polling Main Loop ---- */
int sshd_run(void) {
  u64 listen_fd = 0U;
  u64 udp_fd = 0U;
  int crypto_status;
  int network_status;

  g_console_ipv4 = xaios_net_local_ipv4();
  g_console_ssh_ready = 0U;
  g_console_boot_error = 0;
  network_status = verify_ipv4_ready();
  if (network_status != 0) {
    ssh_log(SSH_LOG_ERROR,
            "IPv4 network readiness check failed; refusing SSH startup status=%u\n",
            (uint64_t)(uint32_t)(-network_status));
    g_console_boot_error = 1000 - network_status;
    goto service_loop;
  }
  console_render_ssh_loading();

  if (crypto_random_init() != 0) {
    ssh_log(SSH_LOG_ERROR, "Secure entropy unavailable; refusing SSH startup\n");
    g_console_boot_error = 2001;
    goto service_loop;
  }
  if (ssh_host_key_init() != 0) {
    ssh_log(SSH_LOG_ERROR, "Persistent SSH host key unavailable\n");
    g_console_boot_error = 2002;
    goto service_loop;
  }
  crypto_status = ssh_crypto_self_test();
  if (crypto_status != 0) {
    ssh_log(SSH_LOG_ERROR, "SSH crypto self-test failed check=%u\n",
            (uint64_t)(uint32_t)(-crypto_status));
    g_console_boot_error = 2100 - crypto_status;
    goto service_loop;
  }
  ssh_log(SSH_LOG_INFO, "SSH crypto self-test passed\n");
  if (ssh_mlkem768_self_test() != 0) {
    ssh_log(SSH_LOG_ERROR, "ML-KEM-768 self-test failed\n");
    g_console_boot_error = 2101;
    goto service_loop;
  }
  ssh_log(SSH_LOG_INFO, "ML-KEM-768 self-test passed\n");

  if (load_runtime_config() != 0) {
    ssh_log(SSH_LOG_ERROR, "SSH runtime configuration rejected\n");
    g_console_boot_error = 2201;
    goto service_loop;
  }

  if (sshd_auth_load_users(g_password_auth_enabled) != 0) {
    ssh_log(SSH_LOG_ERROR, "SSH user database rejected\n");
    g_console_boot_error = 2202;
    goto service_loop;
  }
  if (sshd_auth_load_pin(g_password_auth_enabled) != 0) {
    ssh_log(SSH_LOG_ERROR, "Local console PIN record rejected\n");
    g_console_boot_error = 2203;
    goto service_loop;
  }
  (void)sshd_keys_load();
  if (sshd_keys_database_invalid() != 0) {
    g_console_boot_error = 2203;
    goto service_loop;
  }

  ssh_mem_zero(&g_server_stats, sizeof(g_server_stats));

  ssh_conn_pool_init();

  /* A machine set up without remote access serves its console and nothing
     else. It says so, because "SSH is not running" should never be something
     a person has to discover by trying it. */
  if (!service_enabled("ssh")) {
    ssh_log(SSH_LOG_INFO,
            "Remote access is turned off for this machine; console only\n");
    console_write(
        "Remote access is turned off for this machine.\n"
        "The console below is the only way in.\n");
    goto service_loop;
  }

  if (xaios_net_listen(SSHD_PORT, &listen_fd) != 0) {
    ssh_log(SSH_LOG_ERROR, "Failed to listen on port %u\n", SSHD_PORT);
    g_console_boot_error = 2301;
    goto service_loop;
  }
  if (xaios_net_bind_udp(SSHD_UDP_ECHO_PORT, &udp_fd) != 0) {
    ssh_log(SSH_LOG_ERROR, "Failed to bind UDP port %u\n",
            SSHD_UDP_ECHO_PORT);
    xaios_net_close(listen_fd);
    listen_fd = 0U;
    g_console_boot_error = 2302;
    goto service_loop;
  }
  ssh_log(SSH_LOG_INFO, "SSH server listening on port %u\n", SSHD_PORT);
  ssh_log(SSH_LOG_INFO, "UDP echo service listening on port %u\n",
          SSHD_UDP_ECHO_PORT);
  ssh_log(SSH_LOG_INFO, "Cooperative polling: max %u concurrent connections\n",
          (uint64_t)SSH_MAX_CONNECTIONS);

  ssh_channel_init();
  xaios_log("sshd: Phase 2 runtime ready\n");
  xaios_log("boot-ui: progress=100 loaded=SSH-server loading=complete remaining=0\n");
  g_console_ssh_ready = 1U;

service_loop:
  console_render_boot_status();
  for (;;) {
    uint64_t pass_started = timer_now();
    /* Per pass, so a stall reports what this pass spent on the durable volume
       rather than what every pass has spent since boot. */
    ssh_audit_pass_reset();
    uint64_t now = pass_started;
    console_refresh_boot_ui(now);
    console_service_pong(now);
    sshd_console_program_service();
    console_tick();
    uint64_t after_console = timer_now();
    for (uint32_t i = 0; g_console_ssh_ready != 0U && i < 4U; ++i) {
      uint8_t udp_buffer[1478];
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

    uint64_t after_udp = timer_now();

    /* Try to accept new connections (non-blocking) */
    for (uint32_t i = 0; g_console_ssh_ready != 0U && i < 4U; ++i) {
      u64 conn_fd = 0;
      xaios_ip_addr_user_t peer_addr;
      u64 peer_port = 0;
      xaios_memzero(&peer_addr, sizeof(peer_addr));
      if (xaios_net_accept_addr(listen_fd, &conn_fd, &peer_addr, &peer_port) != 0) {
        break;
      }

      if (record_connection_attempt(&peer_addr) != 0) {
        ssh_log(SSH_LOG_WARN, "Connection rate limit reached\n");
        uint32_t limited = __atomic_add_fetch(
            &g_server_stats.rate_limited_connections, 1, __ATOMIC_RELEASE);
        log_connection_refusal("rate-limit", limited,
                               SSHD_CONNECTION_RATE_LIMIT);
        xaios_net_close(conn_fd);
        continue;
      }

      uint32_t active = __atomic_load_n(&g_server_stats.active_connections,
                                         __ATOMIC_ACQUIRE);
      if (active >= g_runtime_config.max_connections) {
        ssh_log(SSH_LOG_WARN, "Max connections reached\n");
        uint32_t rejected = __atomic_add_fetch(
            &g_server_stats.rejected_connections, 1, __ATOMIC_RELEASE);
        (void)__atomic_add_fetch(&g_server_stats.capacity_refused_connections,
                                 1, __ATOMIC_RELEASE);
        log_connection_refusal("capacity", rejected,
                               g_runtime_config.max_connections);
        xaios_net_close(conn_fd);
        continue;
      }

      ssh_connection_t *conn = ssh_conn_alloc();
      if (!conn) {
        /* The connection table had no free slot while the active count said
           there was room. That disagreement is a defect in itself, so it is
           reported rather than quietly dropped, which is what it used to be. */
        uint32_t exhausted = __atomic_add_fetch(
            &g_server_stats.slot_exhausted_connections, 1, __ATOMIC_RELEASE);
        log_connection_refusal("slot-exhausted", exhausted, active);
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

    uint64_t after_accept = timer_now();

    /* Process each active connection (cooperative time-slicing) */
    for (uint32_t i = 0; i < SSH_MAX_CONNECTIONS; ++i) {
      ssh_connection_t *conn = ssh_conn_by_index(i);
      if (!conn) continue;
      g_close_reason = 0;

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
          g_close_reason = "connect-timeout";
          goto close_conn;
        }
      }
      if (conn->state == SSH_STATE_AUTH) {
        if (now - conn->connect_time > SSHD_TIMEOUT_AUTH) {
          ssh_log(SSH_LOG_WARN, "Auth timeout\n");
          g_close_reason = "auth-timeout";
          goto close_conn;
        }
      }

      int result = conn->close_requested != 0U ? -1 : process_connection(conn);
      if (result != 0) {
close_conn:
        /* Send disconnect message if encrypted -- unless the transport is
           the thing that failed. A connection marked SILENT was closed
           because a transmit was abandoned part way through a packet, so a
           disconnect message would be appended to a truncated one, and the
           socket that would not take those bytes will not take these. It
           would cost another full transmit window with the whole server
           waiting on it: B-40's symptom, produced by B-40's cure. */
        if (conn->state >= SSH_STATE_AUTH &&
            conn->close_requested != SSHD_CLOSE_REQUEST_SILENT) {
          uint8_t disconnect_msg[17];
          ssh_mem_zero(disconnect_msg, sizeof(disconnect_msg));
          disconnect_msg[0] = SSH_MSG_DISCONNECT;
          ssh_write_u32_be(disconnect_msg + 1, SSH_DISCONNECT_BY_APPLICATION);
          ssh_write_u32_be(disconnect_msg + 5, 0);
          ssh_write_u32_be(disconnect_msg + 9, 0);
          conn_packet_write_encrypted(conn, disconnect_msg, 13);
        }

        ssh_channel_close_connection((int)conn->sockfd);
        /* Read before the slot is zeroed: ssh_conn_free wipes the struct, and
           the console line is about the connection, not about the slot. */
        uint64_t closed_sockfd = conn->sockfd;
        uint32_t closed_state = (uint32_t)conn->state;
        uint64_t closed_connect_time = conn->connect_time;
        uint32_t closed_silently =
            conn->close_requested == SSHD_CLOSE_REQUEST_SILENT;
        xaios_net_close(conn->sockfd);
        __atomic_sub_fetch(&g_server_stats.active_connections, 1,
                           __ATOMIC_RELEASE);
        ssh_conn_free(conn);
        ++g_connection_close_count;
        log_connection_close(
            g_close_reason != 0 ? g_close_reason
                                : (closed_silently != 0U ? "transport"
                                                         : "protocol"),
            closed_sockfd, closed_state,
            timer_now() - closed_connect_time, g_connection_close_count);
        ssh_log(SSH_LOG_INFO, "Connection closed\n");
        /* After the audit line above, so the totals include this connection's
           last record rather than all of it but that. The key-loader counters
           live with the cache in sshd_keys.c and are read out here. */
        uint32_t key_load_calls = 0U;
        uint32_t key_load_file_reads = 0U;
        uint64_t key_load_ns = 0U;
        sshd_keys_load_stats(&key_load_calls, &key_load_file_reads,
                             &key_load_ns);
        log_durable_cost(g_connection_close_count, key_load_calls,
                         key_load_file_reads, key_load_ns);
        /* Only when there is enough to be worth the fsync.
         *
         * Flushing at every close made it one fsync per connection, which was
         * already five times better than one per line. But the cost of a flush
         * does not depend on how much is in it -- it is a host fsync either
         * way -- so paying one for forty bytes is the same window as paying
         * one for three kilobytes, and the window is what drops connections.
         *
         * Half the buffer is the threshold rather than "when it is full"
         * because a machine that goes quiet should not sit on records
         * indefinitely: a connection's worth of traffic is enough to cross it,
         * a handful of idle probes is not. Records still reach the file in
         * order and no line is dropped; what changes is how long the last few
         * may wait, and this file is read by no soak and no gate. */
        if (ssh_audit_buffered() >= SSHD_AUDIT_BUFFER_BYTES / 2U) {
          ssh_audit_flush();
        }
      }
    }
    uint64_t after_connections = timer_now();
    if (g_console_ssh_ready != 0U && ssh_channel_tick(timer_now()) != 0) {
      ssh_log(SSH_LOG_WARN, "Interactive channel refresh failed\n");
    }
    report_service_loop_stall(pass_started, after_console, after_udp,
                              after_accept, after_connections, timer_now());
    /* Nothing above blocks, so left to itself this loop spins and keeps a
       whole core at a hundred percent from boot -- which the process
       monitor showed on every machine once it was honest about who was
       running. The kernel wait returns the moment there is console input,
       a packet or connection on a socket sshd owns, or output from a child;
       otherwise after a timeout that only paces the timed housekeeping
       above. A game on the console wants frames, and gets a shorter one. */
    uint64_t wait_requested = g_console_pong.active != 0U
                                  ? UINT64_C(16000000)
                                  : UINT64_C(50000000);
    uint64_t wait_started = timer_now();
    (void)xaios_wait_events(wait_requested);
    report_wait_overrun(wait_requested, wait_started, timer_now());
  }

  return 0;
}

int main(void) {
  int status = sshd_run();
  xaios_exit(status == 0 ? 0 : 1);
  return 0;
}
