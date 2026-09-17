#include "sshd_console_session.h"
#include "sshd.h"
#include "sshd_auth.h"
#include "sshd_console_programs.h"
#include "sshd_console_screen.h"
#include "sshd_console_ui.h"
#include "ssh_channel.h"
#include "ssh_utils.h"
#include <xaios_user.h>

void console_execute_command(void) {
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

void console_submit_auth(void) {
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
