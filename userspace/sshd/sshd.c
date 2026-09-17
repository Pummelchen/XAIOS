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
#include "sshd_config.h"
#include "sshd_console_session.h"
#include "sshd_connection_support.h"
#include "sshd_service.h"

xaios_admin_config_user_t g_runtime_config;
/* Read by this file's console login state and by sshd_console_ui.c, which
   renders the login screen and decides whether the console opens a shell. */
uint32_t g_password_auth_enabled;

/* The console command line console_tick() edits. The rest of the console state
   is defined here too, because that hub reads and writes it directly every
   pass; sshd_console_ui.c reaches all of it through sshd_console_ui.h. */
char g_console_command[SSHD_CONSOLE_COMMAND_MAX];
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

void console_auth_succeeded(void) {
  sshd_auth_console_clear_failures();
  g_console_auth_state = SSHD_CONSOLE_AUTH_SHELL;
  console_write("XAIOS local console session opened\n");
  console_prompt();
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

void console_set_username(const char *username) {
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

int main(void) {
  int status = sshd_run();
  xaios_exit(status == 0 ? 0 : 1);
  return 0;
}
