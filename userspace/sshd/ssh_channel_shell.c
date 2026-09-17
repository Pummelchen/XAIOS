/* The SSH shell's line interpreter and the command/exec path.
 *
 * Split out of `ssh_channel.c` unchanged. The channel table and the request
 * dispatcher stayed there, because both hand out and mutate `ssh_channel_t *`
 * from a file-scope array. Declarations shared with `ssh_channel.c` are in
 * `ssh_channel_shell.h`.
 */

#include "ssh_channel.h"
#include "ssh_channel_shell.h"

#include "ssh_alt_screen.h"
#include "ssh_connection.h"
#include "ssh_protocol.h"
#include "ssh_utils.h"
#include "ssh_client.h"
#include "sshd.h"
#include <xaios_control_client.h>
#include <xaios_user.h>

#define SSH_XTOP_DEFAULT_REFRESH_MS 250U

static int shell_send_output(ssh_channel_t *ch, const uint8_t *data,
                             uint32_t length) {
  uint32_t segment_start = 0U;
  if (ch == 0 || (data == 0 && length != 0U)) return -1;
  for (uint32_t i = 0U; i < length; ++i) {
    if (data[i] != '\n' || (i != 0U && data[i - 1U] == '\r')) continue;
    if (i != segment_start &&
        ssh_channel_send_data((int)ch->owner_sockfd, ch->remote_id,
                              data + segment_start, i - segment_start) != 0) {
      return -1;
    }
    if (ssh_channel_send_data((int)ch->owner_sockfd, ch->remote_id,
                              (const uint8_t *)"\r\n", 2U) != 0) {
      return -1;
    }
    segment_start = i + 1U;
  }
  if (segment_start == length) return 0;
  return ssh_channel_send_data((int)ch->owner_sockfd, ch->remote_id,
                               data + segment_start,
                               length - segment_start);
}

int ssh_shell_token_equal(const char *command, const char *expected) {
  uint32_t index = 0U;
  uint32_t command_len = ssh_str_len(command);
  uint32_t expected_len = ssh_str_len(expected);
  while (command[index] == ' ' || command[index] == '\t' ||
         command[index] == '\r' || command[index] == '\n') {
    ++index;
  }
  if (index > command_len || expected_len > command_len - index) return 0;
  for (uint32_t i = 0U; i < expected_len; ++i) {
    if (command[index + i] != expected[i]) return 0;
  }
  index += expected_len;
  return command[index] == '\0' || command[index] == ' ' ||
         command[index] == '\t' || command[index] == '\r' ||
         command[index] == '\n';
}

static int command_has_option(const char *command, const char *option) {
  uint32_t option_len = ssh_str_len(option);
  for (uint32_t i = 0U; command[i] != '\0';) {
    while (command[i] == ' ' || command[i] == '\t' ||
           command[i] == '\r' || command[i] == '\n') {
      ++i;
    }
    uint32_t start = i;
    while (command[i] != '\0' && command[i] != ' ' &&
           command[i] != '\t' && command[i] != '\r' &&
           command[i] != '\n') {
      ++i;
    }
    if (i - start == option_len &&
        ssh_channel_packet_string_equal((const uint8_t *)command + start,
                                        option_len, option)) {
      return 1;
    }
  }
  return 0;
}

static int append_command_text(char *command, uint32_t capacity,
                               const char *text) {
  uint32_t used = ssh_str_len(command);
  uint32_t length = ssh_str_len(text);
  if (used + length + 1U > capacity) return -1;
  ssh_mem_copy(command + used, text, length + 1U);
  return 0;
}

static int append_command_u32(char *command, uint32_t capacity,
                              uint32_t value) {
  char digits[11];
  uint32_t count = 0U;
  do {
    digits[count++] = (char)('0' + value % 10U);
    value /= 10U;
  } while (value != 0U);
  uint32_t used = ssh_str_len(command);
  if (used + count + 1U > capacity) return -1;
  for (uint32_t i = 0U; i < count; ++i) {
    command[used + i] = digits[count - i - 1U];
  }
  command[used + count] = '\0';
  return 0;
}

/* Shared by the SSH channel and the local console so an application is
   launched with the same options on both, and therefore renders the same.
   The two surfaces still differ in what happens after the first frame: the
   channel keeps an interactive session alive, the console does not yet. */
int ssh_terminal_promote_command(char *command, uint32_t capacity,
                                 uint32_t columns, uint32_t rows) {
  if (command == 0 || ssh_shell_token_equal(command, "xtop") == 0 ||
      command_has_option(command, "--plain") != 0) {
    return 0;
  }
  if (command_has_option(command, "--color") == 0 &&
      append_command_text(command, capacity, " --color") != 0) {
    return -1;
  }
  if (command_has_option(command, "--interactive") == 0 &&
      append_command_text(command, capacity, " --interactive") != 0) {
    return -1;
  }
  if (command_has_option(command, "--columns") == 0 &&
      (append_command_text(command, capacity, " --columns ") != 0 ||
       append_command_u32(command, capacity, columns) != 0)) {
    return -1;
  }
  if (command_has_option(command, "--rows") == 0 &&
      (append_command_text(command, capacity, " --rows ") != 0 ||
       append_command_u32(command, capacity, rows) != 0)) {
    return -1;
  }
  if (command_has_option(command, "--refresh-ms") == 0 &&
      (append_command_text(command, capacity, " --refresh-ms ") != 0 ||
       append_command_u32(command, capacity, SSH_XTOP_DEFAULT_REFRESH_MS) != 0)) {
    return -1;
  }
  return 0;
}

int ssh_shell_prepare_command(const ssh_channel_t *ch, char *command,
                              uint32_t capacity) {
  if (ch == 0 || ch->pty_requested == 0U) return 0;
  return ssh_terminal_promote_command(command, capacity, ch->terminal_columns,
                                      ch->terminal_rows);
}

static int command_rate_allowed(ssh_connection_t *connection) {
  static const u64 window_ns = 60000000000ULL;
  u64 now;
  if (connection == 0) return 0;
  now = xaios_clock_nanos();
  if (connection->command_window_start == 0ULL ||
      now - connection->command_window_start >= window_ns) {
    connection->command_window_start = now;
    connection->command_count = 0U;
  }
  if (connection->command_count >= sshd_command_rate_per_minute()) return 0;
  ++connection->command_count;
  return 1;
}

static int write_command_denial(char *output, u64 output_capacity,
                                u64 *out_size, const char *message) {
  u64 length = xaios_strlen(message);
  if (length + 1ULL > output_capacity) return -1;
  ssh_mem_copy(output, message, (uint32_t)length + 1U);
  *out_size = length;
  return -1;
}

int ssh_shell_execute_admin(int sockfd, const char *command, char *output,
                            u64 output_capacity, u64 *out_size) {
  ssh_connection_t *connection = ssh_conn_find((u64)(uint32_t)sockfd);
  if (connection == 0 || command_rate_allowed(connection) == 0) {
    return write_command_denial(output, output_capacity, out_size,
                                "Command rate limit exceeded\n");
  }
  if (xaios_control_is_command(command)) {
    int result = xaios_control_run_as(
        command, connection->principal_role, connection->principal, output,
        output_capacity, out_size);
    if (result == 0 && sshd_reload_control_state(command) != 0) {
      return write_command_denial(output, output_capacity, out_size,
                                  "Control state reload failed\n");
    }
    return result;
  }
  if (connection->principal_role != XAIOS_CONTROL_ROLE_ADMIN) {
    return write_command_denial(output, output_capacity, out_size,
                                "Permission denied\n");
  }
  int result = xaios_remote_login_session(
      connection->sockfd, "admin", command, output, output_capacity, out_size);
  return result < 0 ? -1 : 0;
}

static int shell_execute_line(ssh_channel_t *ch) {
  char output[8192];
  u64 out_size = 0U;
  ch->shell_line[ch->shell_line_length] = '\0';
  if (ssh_channel_send_data((int)ch->owner_sockfd, ch->remote_id,
                            (const uint8_t *)"\r\n", 2U) != 0) {
    return -1;
  }
  if (ch->shell_line_length == 0U) return shell_send_prompt(ch);
  if (ssh_str_eq(ch->shell_line, "exit") ||
      ssh_str_eq(ch->shell_line, "logout") ||
      ssh_str_eq(ch->shell_line, "quit")) {
    (void)xaios_remote_login_session_close(ch->owner_sockfd);
    ch->shell_active = 0U;
    ch->exit_status = 0U;
    ch->close_after_flush = 1U;
    return flush_channel(ch);
  }
  if (ssh_shell_token_equal(ch->shell_line, "xtop") != 0 &&
      ssh_shell_prepare_command(ch, ch->shell_line,
                                SSH_CHANNEL_SHELL_LINE_SIZE) != 0) {
    ch->shell_line_length = 0U;
    return shell_send_prompt(ch);
  }
  if (ssh_shell_token_equal(ch->shell_line, "nano") != 0 &&
      nano_command_argument(ch->shell_line, output, sizeof(output)) == 0) {
    ch->shell_line_length = 0U;
    return nano_start(ch, ch->shell_line, 1U);
  }
  if (ssh_shell_token_equal(ch->shell_line, "less") != 0) {
    ch->shell_line_length = 0U;
    return less_start(ch, ch->shell_line, 1U);
  }
  if (ssh_shell_token_equal(ch->shell_line, "pong") != 0) {
    ch->shell_line_length = 0U;
    return pong_start(ch, ch->shell_line, 1U);
  }
  {
    int client_result = ssh_client_prepare(ch, ch->shell_line);
    if (client_result != 0) {
      ch->shell_line_length = 0U;
      return client_result < 0 ? shell_send_prompt(ch) : 0;
    }
  }
  int result = ssh_shell_execute_admin((int)ch->owner_sockfd, ch->shell_line,
                                       output, sizeof(output), &out_size);
  if (out_size != 0U &&
      shell_send_output(ch, (const uint8_t *)output,
                        (uint32_t)out_size) != 0) {
    return -1;
  }
  if (result < 0 && out_size == 0U) {
    static const char failed[] = "xaios: command execution failed\r\n";
    if (ssh_channel_send_data((int)ch->owner_sockfd, ch->remote_id,
                              (const uint8_t *)failed,
                              (uint32_t)(sizeof(failed) - 1U)) != 0) {
      return -1;
    }
  }
  ch->shell_line_length = 0U;
  return shell_send_prompt(ch);
}

int ssh_shell_handle_input(ssh_channel_t *ch, const uint8_t *data,
                           uint32_t length) {
  if (ssh_client_is_prompting(ch)) {
    int result = ssh_client_password_input(ch, data, length);
    return result > 0 ? shell_send_prompt(ch) : result;
  }
  if (ssh_client_is_active(ch)) {
    return ssh_client_forward_input(ch, data, length);
  }
  for (uint32_t i = 0U; i < length; ++i) {
    uint8_t value = data[i];
    if (value == '\n' && ch->shell_ignore_lf != 0U) {
      ch->shell_ignore_lf = 0U;
      continue;
    }
    ch->shell_ignore_lf = 0U;
    if (value == '\r' || value == '\n') {
      ch->shell_ignore_lf = value == '\r' ? 1U : 0U;
      if (shell_execute_line(ch) != 0) return -1;
      if (ch->shell_active == 0U) return 0;
      if (ch->nano.active != 0U) {
        return i + 1U < length
                   ? nano_handle_input(ch, data + i + 1U, length - i - 1U)
                   : 0;
      }
      if (ch->less.active != 0U) {
        return i + 1U < length
                   ? less_handle_input(ch, data + i + 1U, length - i - 1U)
                   : 0;
      }
      if (ch->pong.active != 0U) {
        return i + 1U < length
                   ? pong_handle_input(ch, data + i + 1U, length - i - 1U)
                   : 0;
      }
    } else if (value == 8U || value == 127U) {
      if (ch->shell_line_length != 0U) {
        --ch->shell_line_length;
        if (ssh_channel_send_data((int)ch->owner_sockfd, ch->remote_id,
                                  (const uint8_t *)"\b \b", 3U) != 0) {
          return -1;
        }
      }
    } else if (value == 3U) {
      ch->shell_line_length = 0U;
      if (ssh_channel_send_data((int)ch->owner_sockfd, ch->remote_id,
                                (const uint8_t *)"^C\r\n", 4U) != 0 ||
          shell_send_prompt(ch) != 0) {
        return -1;
      }
    } else if (value >= 32U && value <= 126U &&
               ch->shell_line_length + 1U < sizeof(ch->shell_line)) {
      ch->shell_line[ch->shell_line_length++] = (char)value;
      if (ssh_channel_send_data((int)ch->owner_sockfd, ch->remote_id,
                                &value, 1U) != 0) {
        return -1;
      }
    } else if (value >= 32U && value <= 126U) {
      static const char bell[] = "\a";
      if (ssh_channel_send_data((int)ch->owner_sockfd, ch->remote_id,
                                (const uint8_t *)bell, 1U) != 0) {
        return -1;
      }
    }
  }
  return 0;
}
