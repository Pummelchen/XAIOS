/*
 * sshd's local console presentation layer.
 *
 * The console's text output, its shell and login prompts, the boot screen it
 * paints, and the pager, editor and game it can run full-screen. sshd.c keeps
 * the console_tick() hub that feeds it and the command dispatcher that starts
 * the programs; the state both sides share stays there with that hub and is
 * declared in sshd_console_ui.h, which this module includes.
 *
 * See sshd_console_ui.h for what crosses back into sshd.c.
 */

#include "sshd_console_ui.h"

#include "sshd.h"
#include "sshd_auth.h"
#include "sshd_console_programs.h"

/* Where the machine's name lives, and the most it can be. */
#define SSHD_HOSTNAME_PATH "/etc/xaios_hostname"
#define SSHD_HOSTNAME_MAX 33U

/* Defined below, after the shell prompt that reads it. */
static uint32_t console_hostname(char *out, uint32_t capacity);

/* The boot screen's blink state, touched only from this module. */
static uint64_t g_console_ui_next_refresh;
static uint32_t g_console_ui_cursor_visible;

void console_write(const char *text) {
  if (text != 0) (void)sshd_console_write_bytes(text, xaios_strlen(text));
}

static void console_write_ipv4(uint32_t address) {
  char line[32];
  u64 offset = 0U;
  xaios_memzero(line, sizeof(line));
  xaios_append_u64(line, sizeof(line), &offset, (address >> 24U) & 0xffU);
  xaios_append_cstr(line, sizeof(line), &offset, ".");
  xaios_append_u64(line, sizeof(line), &offset, (address >> 16U) & 0xffU);
  xaios_append_cstr(line, sizeof(line), &offset, ".");
  xaios_append_u64(line, sizeof(line), &offset, (address >> 8U) & 0xffU);
  xaios_append_cstr(line, sizeof(line), &offset, ".");
  xaios_append_u64(line, sizeof(line), &offset, address & 0xffU);
  console_write(line);
}

/* Render the public IPv6 address in RFC 5952 form, with the longest run of
   zero groups collapsed to "::". Prints nothing when the guest has no public
   IPv6 address, so an IPv4-only network shows an IPv4-only boot screen. */
static void console_write_ipv6(void) {
  uint8_t address[16];
  if (xaios_net_local_ipv6(address) != 1) return;

  uint16_t groups[8];
  for (uint32_t i = 0U; i < 8U; ++i) {
    groups[i] = (uint16_t)(((uint16_t)address[i * 2U] << 8U) |
                           address[i * 2U + 1U]);
  }
  uint32_t best_start = 8U;
  uint32_t best_length = 0U;
  uint32_t run_start = 8U;
  uint32_t run_length = 0U;
  for (uint32_t i = 0U; i < 8U; ++i) {
    if (groups[i] == 0U) {
      if (run_length == 0U) run_start = i;
      ++run_length;
      if (run_length > best_length) {
        best_length = run_length;
        best_start = run_start;
      }
    } else {
      run_length = 0U;
    }
  }
  if (best_length < 2U) best_start = 8U;

  static const char hex[] = "0123456789abcdef";
  /* The marker carries both of its colons, and the group after it therefore
     adds no separator of its own. Splitting the pair across the marker and
     the next group breaks whenever there is no next group: a run reaching
     the last group would render one colon short. */
  uint32_t marker_end = best_start < 8U ? best_start + best_length : 8U;
  char line[48];
  u64 offset = 0U;
  xaios_memzero(line, sizeof(line));
  for (uint32_t i = 0U; i < 8U;) {
    if (i == best_start) {
      xaios_append_cstr(line, sizeof(line), &offset, "::");
      i += best_length;
      continue;
    }
    if (i != 0U && i != marker_end) {
      xaios_append_cstr(line, sizeof(line), &offset, ":");
    }
    uint16_t value = groups[i];
    char digits[4];
    uint32_t count = 0U;
    do {
      digits[count++] = hex[value & 0xfU];
      value = (uint16_t)(value >> 4U);
    } while (value != 0U);
    while (count != 0U) {
      char single[2];
      single[0] = digits[--count];
      single[1] = '\0';
      xaios_append_cstr(line, sizeof(line), &offset, single);
    }
    ++i;
  }
  console_write("\nIPv6: ");
  console_write(line);
}

void console_write_error(int32_t status) {
  char line[32];
  u64 offset = 0U;
  uint64_t magnitude;
  xaios_memzero(line, sizeof(line));
  if (status < 0) {
    xaios_append_cstr(line, sizeof(line), &offset, "-");
    magnitude = (uint64_t)(-(status + 1)) + 1U;
  } else {
    magnitude = (uint64_t)status;
  }
  xaios_append_u64(line, sizeof(line), &offset, magnitude);
  console_write(line);
}

void console_prompt(void) {
  char cwd[256];
  u64 cwd_size = 0U;
  xaios_memzero(cwd, sizeof(cwd));
  if (xaios_remote_login_session(SSHD_CONSOLE_SESSION_ID, console_username(),
                                 "pwd", cwd,
                                 sizeof(cwd), &cwd_size) < 0 ||
      cwd_size == 0U || cwd_size >= sizeof(cwd)) {
    cwd[0] = '/';
    cwd[1] = '\0';
    cwd_size = 1U;
  }
  while (cwd_size != 0U &&
         (cwd[cwd_size - 1U] == '\n' || cwd[cwd_size - 1U] == '\r')) {
    --cwd_size;
  }
  /* Whoever is logged in, on the machine as it is named -- this read
     "admin@xaios" whatever either actually was -- composed into one write so
     a kernel log line cannot land inside it. */
  char who[SSHD_USERNAME_MAX + SSHD_HOSTNAME_MAX + 24U];
  uint32_t used = 0U;
  static const char green[] = "\x1b[1;32m";
  for (uint32_t i = 0U; i < sizeof(green) - 1U; ++i) who[used++] = green[i];
  const char *user = console_username();
  for (uint32_t i = 0U; user[i] != '\0' && used + 1U < sizeof(who); ++i) {
    who[used++] = user[i];
  }
  who[used++] = '@';
  used += console_hostname(who + used, SSHD_HOSTNAME_MAX);
  static const char reset[] = "\x1b[0m:\x1b[1;34m";
  for (uint32_t i = 0U; i < sizeof(reset) - 1U; ++i) who[used++] = reset[i];
  who[used] = '\0';
  console_write(who);
  (void)xaios_console_write(cwd, cwd_size);
  console_write("\x1b[0m$ ");
}

/* Reached from sshd_console_programs.c: the console's text writer and the
   shell prompt. Both stay here with the rest of the console UI the tick loop
   drives; the program-launch module calls them by name rather than being
   handed the console state behind them. */
void sshd_console_text(const char *text) { console_write(text); }

void sshd_console_prompt(void) { console_prompt(); }

/* The login prompt carries the machine's name, so a person in front of a rack
   can tell which machine they are typing at. Setup writes the name; a machine
   nobody has renamed keeps the default, which is what every image did before
   this and what a read of the file failing falls back to. */

/* The machine's name, or "xaios" when it has not been given one.

   Written as its own function because the login prompt and the shell prompt
   both need it, and because the version that did not have one recursed into
   itself on the no-name path -- a machine nobody renamed would have spun
   here forever. */

/* Copy the machine's name out, or "xaios" when it has not been given one. */
static uint32_t console_hostname(char *out, uint32_t capacity) {
  char name[SSHD_HOSTNAME_MAX];
  int length = xaios_read_file(SSHD_HOSTNAME_PATH, name, sizeof(name));
  uint32_t used = 0U;
  if (length > 0) {
    while (used < (uint32_t)length && used < sizeof(name) &&
           name[used] != '\n' && name[used] != '\r' && name[used] > 0x20) {
      ++used;
    }
  }
  if (used == 0U || used >= capacity) {
    static const char fallback[] = "xaios";
    used = 0U;
    while (used < sizeof(fallback) - 1U && used + 1U < capacity) {
      out[used] = fallback[used];
      ++used;
    }
    out[used] = '\0';
    return used;
  }
  for (uint32_t i = 0U; i < used; ++i) out[i] = name[i];
  out[used] = '\0';
  return used;
}

/* One write, not several.

   The kernel logs to the same console, so a prompt assembled from four writes
   can have a log line land in the middle of it -- and a person reading
   "operator@" followed by a filesystem trace has no idea what their machine
   is called. Composing first and writing once makes the prompt atomic as far
   as anything interleaving with it is concerned. */
void console_write_login_prompt(void) {
  char line[SSHD_HOSTNAME_MAX + 16U];
  uint32_t used = console_hostname(line, SSHD_HOSTNAME_MAX);
  static const char suffix[] = " login: ";
  for (uint32_t i = 0U; i < sizeof(suffix) - 1U; ++i) line[used++] = suffix[i];
  line[used] = '\0';
  console_write(line);
}

/* Whether this machine was set up to open a shell without asking.

   Read fresh at each login rather than cached, so logging out of an
   auto-login machine returns to a prompt that reflects the file as it is now.
   Only the exact word enables it: a truncated or unreadable file leaves the
   prompt in place, which is the answer that costs nothing if it is wrong. */
#define SSHD_AUTOLOGIN_PATH "/etc/xaios_autologin"

static int console_autologin_enabled(void) {
  char value[8];
  int length = xaios_read_file(SSHD_AUTOLOGIN_PATH, value, sizeof(value));
  if (length < 3) return 0;
  return value[0] == 'y' && value[1] == 'e' && value[2] == 's';
}

static void console_begin_login(void) {
  g_console_command_length = 0U;
  g_console_ignore_lf = 0U;
  if (sshd_auth_user_count() == 0U || g_password_auth_enabled == 0U) {
    g_console_auth_state = SSHD_CONSOLE_AUTH_LOCKED;
    console_write(
        "Local console locked: password authentication is not configured.\n"
        "Use SSH public-key authentication for administration.\n");
    return;
  }
  /* Asked for during setup, and only ever for this console: an SSH session
     still authenticates. The machine says it is doing this, so a shell that
     appeared without a password is never a mystery. */
  if (console_autologin_enabled()) {
    console_write(
        "Automatic login is enabled on this console.\n"
        "Type \"exit\" to return to a login prompt.\n");
    console_set_account_username();
    console_auth_succeeded();
    return;
  }
  g_console_auth_state = SSHD_CONSOLE_AUTH_USER;
  console_write_login_prompt();
}

int console_nano_argument(const char *command, char *argument,
                          uint32_t capacity) {
  uint32_t i = 0U;
  uint32_t used = 0U;
  while (command[i] == ' ' || command[i] == '\t') ++i;
  if (command[i++] != 'n' || command[i++] != 'a' || command[i++] != 'n' ||
      command[i++] != 'o' ||
      (command[i] != ' ' && command[i] != '\t')) return -1;
  while (command[i] == ' ' || command[i] == '\t') ++i;
  if (command[i] == '\0' || command[i] == '-') return -1;
  while (command[i] != '\0' && command[i] != ' ' && command[i] != '\t') {
    if (used + 1U >= capacity) return -1;
    argument[used++] = command[i++];
  }
  while (command[i] == ' ' || command[i] == '\t') ++i;
  if (command[i] != '\0') return -1;
  argument[used] = '\0';
  return 0;
}

/* Local console pager, driving the same less_pager_t the SSH channel uses so
   paging, searching and quitting behave identically on both surfaces. */
int console_start_less(const char *command) {
  char cwd[LESS_PAGER_PATH_MAX];
  u64 cwd_size = 0U;
  uint32_t frame_size = 0U;
  if (xaios_remote_login_session(SSHD_CONSOLE_SESSION_ID, console_username(),
                                 "pwd", cwd,
                                 sizeof(cwd), &cwd_size) < 0 ||
      cwd_size == 0U || cwd_size >= sizeof(cwd)) {
    return -1;
  }
  while (cwd_size != 0U &&
         (cwd[cwd_size - 1U] == '\n' || cwd[cwd_size - 1U] == '\r')) {
    cwd[--cwd_size] = '\0';
  }
  if (less_pager_open(&g_console_less, command, cwd, sshd_console_columns(),
                      sshd_console_rows()) != 0) {
    console_write(
        "less: usage: less [-N] FILE (regular files up to 128 KiB)\n");
    return -1;
  }
  if (less_pager_render(&g_console_less, g_console_output,
                        sizeof(g_console_output), &frame_size) != 0) {
    less_pager_close(&g_console_less);
    return -1;
  }
  console_write("\033[?1049h\033[?25l");
  (void)sshd_console_write_bytes(g_console_output, frame_size);
  return 0;
}

void console_finish_less(void) {
  less_pager_close(&g_console_less);
  console_write("\033[0m\033[?25h\033[?1049l\033[0m\033[?25h\r");
  console_prompt();
}

int console_start_nano(const char *command) {
  char argument[NANO_EDITOR_PATH_MAX];
  char cwd[NANO_EDITOR_PATH_MAX];
  u64 cwd_size = 0U;
  uint32_t frame_size = 0U;
  if (console_nano_argument(command, argument, sizeof(argument)) != 0 ||
      xaios_remote_login_session(SSHD_CONSOLE_SESSION_ID, console_username(),
                                 "pwd", cwd,
                                 sizeof(cwd), &cwd_size) < 0 ||
      cwd_size == 0U || cwd_size >= sizeof(cwd)) {
    return -1;
  }
  while (cwd_size != 0U &&
         (cwd[cwd_size - 1U] == '\n' || cwd[cwd_size - 1U] == '\r')) {
    cwd[--cwd_size] = '\0';
  }
  if (nano_editor_open(&g_console_nano, argument, cwd, 120U, 40U) != 0) {
    console_write("nano: ");
    console_write(g_console_nano.status);
    console_write("\n");
    return -1;
  }
  if (nano_editor_render(&g_console_nano, g_console_output,
                         sizeof(g_console_output), &frame_size) != 0) {
    g_console_nano.active = 0U;
    return -1;
  }
  console_write("\033[?1049h");
  (void)sshd_console_write_bytes(g_console_output, frame_size);
  return 0;
}

int console_render_pong(uint64_t now_ns) {
  uint32_t frame_size = 0U;
  if (pong_game_render(&g_console_pong, g_console_output,
                       sizeof(g_console_output), &frame_size, now_ns) != 0 ||
      frame_size == 0U)
    return -1;
  return sshd_console_write_bytes(g_console_output, frame_size);
}

static uint32_t console_boot_ui_state(void) {
  if (g_console_auth_state == SSHD_CONSOLE_AUTH_USER)
    return XAIOS_BOOT_UI_CONSOLE_LOGIN;
  if (g_console_auth_state == SSHD_CONSOLE_AUTH_PASSWORD)
    return XAIOS_BOOT_UI_CONSOLE_PASSWORD;
  if (g_console_auth_state == SSHD_CONSOLE_AUTH_SHELL)
    return XAIOS_BOOT_UI_CONSOLE_SHELL;
  return XAIOS_BOOT_UI_CONSOLE_LOCKED;
}

static void console_publish_boot_ui(uint32_t cursor_visible) {
  xaios_boot_ui_control_t control = {
      XAIOS_BOOT_UI_CONTROL_MAGIC, XAIOS_BOOT_UI_CONTROL_VERSION,
      g_console_ssh_ready != 0U ? XAIOS_BOOT_UI_STAGE_SSH_READY
                                : XAIOS_BOOT_UI_STAGE_SSH_FAILED,
      g_console_boot_error, g_console_ipv4, console_boot_ui_state(),
      cursor_visible};
  (void)xaios_console_write((const char *)&control, sizeof(control));
}

void console_refresh_boot_ui(uint64_t now_ns) {
  if (g_console_ssh_ready == 0U && g_console_ui_next_refresh != 0U) return;
  if (now_ns < g_console_ui_next_refresh) return;
  g_console_ui_cursor_visible ^= 1U;
  console_publish_boot_ui(g_console_ui_cursor_visible);
  g_console_ui_next_refresh = now_ns + UINT64_C(500000000);
}

int console_start_pong(void) {
  uint64_t now_ns = xaios_clock_nanos();
  pong_game_start(&g_console_pong, 120U, 40U, now_ns);
  console_write("\033[?1049h\033[?25l");
  if (console_render_pong(now_ns) != 0) {
    g_console_pong.active = 0U;
    console_write("\033[0m\033[?25h\033[?1049l");
    return -1;
  }
  return 0;
}

void console_finish_pong(void) {
  g_console_pong.active = 0U;
  console_write("\033[0m\033[?25h\033[?1049l\033[0m\033[?25h\r");
  console_prompt();
}

void console_service_pong(uint64_t now_ns) {
  if (g_console_pong.active != 0U &&
      pong_game_tick(&g_console_pong, now_ns) != 0 &&
      console_render_pong(now_ns) != 0)
    console_finish_pong();
}

void console_render_boot_status(void) {
  console_write("\x1b[2J\x1b[H\x1b[1;35mXAI\x1b[0m ");
  console_write("\x1b[1;36mOS\x1b[0m\n\n");
  console_write("[########################################] 100%\n\n");
  console_write("Loaded: system services\nLoading: complete\n");
  console_write("Remaining: 0 components\n\nIPv4: ");
  console_write_ipv4(g_console_ipv4);
  console_write_ipv6();
  console_write("\nSSH server: ");
  if (g_console_ssh_ready != 0U) {
    console_write("up and running (tcp/22)\n\n");
  } else {
    console_write("not running error=");
    console_write_error(g_console_boot_error);
    console_write("\n\n");
  }
  console_begin_login();
  g_console_ui_cursor_visible = 1U;
  console_publish_boot_ui(g_console_ui_cursor_visible);
  g_console_ui_next_refresh = xaios_clock_nanos() + UINT64_C(500000000);
}

void console_render_ssh_loading(void) {
  xaios_boot_ui_control_t control = {
      XAIOS_BOOT_UI_CONTROL_MAGIC, XAIOS_BOOT_UI_CONTROL_VERSION,
      XAIOS_BOOT_UI_STAGE_SSH_LOADING, 0, 0U,
      XAIOS_BOOT_UI_CONSOLE_LOCKED, 0U};
  (void)xaios_console_write((const char *)&control, sizeof(control));
  console_write("\x1b[H\x1b[J\x1b[1;35mXAI\x1b[0m ");
  console_write("\x1b[1;36mOS\x1b[0m\n\n");
  console_write("[######################################..] 95%\n\n");
  console_write("Loaded: IPv4 network configuration\nLoading: SSH server\n");
  console_write("Remaining: 1 component\n");
}
