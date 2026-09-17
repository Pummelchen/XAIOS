/* The channel request path: the PTY and window-change parsers and the
 * CHANNEL_REQUEST dispatcher.
 *
 * Split out of `ssh_channel.c`, which was 1031 lines. The dispatcher looks a
 * channel up in the table -- which moved to `ssh_channel_table.c` -- and
 * mutates the row it finds, so the lookups it needs are declared in the
 * private `ssh_channel_internal.h`. The packet dispatcher stayed in
 * `ssh_channel.c` and calls `ssh_channel_handle_request` for type 98.
 */

#include "ssh_channel.h"
#include "ssh_channel_internal.h"

#include "ssh_alt_screen.h"
#include "ssh_channel_shell.h"
#include "ssh_channel_stream.h"
#include "ssh_connection.h"
#include "ssh_client.h"
#include "ssh_protocol.h"
#include "ssh_utils.h"
#include <xaios_control_client.h>
#include <xaios_user.h>

#define SSH_PTY_DEFAULT_COLUMNS 120U
#define SSH_PTY_DEFAULT_ROWS 40U
#define SSH_PTY_MIN_COLUMNS 40U
#define SSH_PTY_MAX_COLUMNS 240U
#define SSH_PTY_MIN_ROWS 12U
#define SSH_PTY_MAX_ROWS 100U

static uint32_t clamp_terminal_dimension(uint32_t value, uint32_t fallback,
                                         uint32_t minimum,
                                         uint32_t maximum) {
  if (value == 0U) value = fallback;
  if (value < minimum) return minimum;
  if (value > maximum) return maximum;
  return value;
}

static int parse_pty_request(ssh_channel_t *ch, const ssh_packet_t *pkt,
                             uint32_t data_start) {
  uint32_t cursor;
  uint32_t term_len;
  uint32_t modes_len;
  uint32_t columns;
  uint32_t rows;
  if (ch == 0 || pkt == 0 || data_start > pkt->len ||
      pkt->len - data_start < 24U) {
    return -1;
  }
  term_len = ssh_read_u32_be(pkt->data + data_start);
  cursor = data_start + 4U;
  if (term_len >= 64U || term_len > pkt->len - cursor ||
      ssh_channel_packet_has_zero(pkt->data + cursor, term_len)) {
    return -1;
  }
  cursor += term_len;
  if (pkt->len - cursor < 20U) return -1;
  columns = clamp_terminal_dimension(
      ssh_read_u32_be(pkt->data + cursor), SSH_PTY_DEFAULT_COLUMNS,
      SSH_PTY_MIN_COLUMNS, SSH_PTY_MAX_COLUMNS);
  rows = clamp_terminal_dimension(
      ssh_read_u32_be(pkt->data + cursor + 4U), SSH_PTY_DEFAULT_ROWS,
      SSH_PTY_MIN_ROWS, SSH_PTY_MAX_ROWS);
  cursor += 16U;
  modes_len = ssh_read_u32_be(pkt->data + cursor);
  cursor += 4U;
  if (modes_len != pkt->len - cursor) return -1;
  ch->terminal_columns = columns;
  ch->terminal_rows = rows;
  ch->pty_requested = 1U;
  return 0;
}

static int parse_window_change(ssh_channel_t *ch, const ssh_packet_t *pkt,
                               uint32_t data_start) {
  if (ch == 0 || pkt == 0 || ch->pty_requested == 0U ||
      data_start > pkt->len || pkt->len - data_start != 16U) {
    return -1;
  }
  ch->terminal_columns = clamp_terminal_dimension(
      ssh_read_u32_be(pkt->data + data_start), SSH_PTY_DEFAULT_COLUMNS,
      SSH_PTY_MIN_COLUMNS, SSH_PTY_MAX_COLUMNS);
  ch->terminal_rows = clamp_terminal_dimension(
      ssh_read_u32_be(pkt->data + data_start + 4U), SSH_PTY_DEFAULT_ROWS,
      SSH_PTY_MIN_ROWS, SSH_PTY_MAX_ROWS);
  return 0;
}

/* ---- Handle CHANNEL_REQUEST (type 98) ---- */
int ssh_channel_handle_request(int sockfd, const ssh_packet_t *pkt) {
  if (pkt->len < 10) return -1;

  /* Parse: uint32 recipient_channel, string request_type, bool want_reply */
  uint32_t local_id = ssh_read_u32_be(pkt->data + 1);
  ssh_channel_t *ch = ssh_channel_find_local(sockfd, local_id);
  if (!ch) return -1;

  uint32_t type_len = ssh_read_string_len(pkt->data + 5);
  if (type_len > pkt->len - 10U) return -1;
  if (type_len == 0U || type_len >= 64U ||
      ssh_channel_packet_has_zero(pkt->data + 9U, type_len)) return -1;

  char request_type[64];
  ssh_mem_copy(request_type, pkt->data + 9, type_len);
  request_type[type_len] = '\0';

  uint32_t type_end = 9 + type_len;
  uint8_t want_reply = (type_end < pkt->len) ? pkt->data[type_end] : 0;

  uint32_t data_start = type_end + 1;

  if (ssh_str_eq(request_type, "pty-req")) {
    int valid = parse_pty_request(ch, pkt, data_start) == 0;
    if (want_reply) {
      if (ssh_stream_send_reply(sockfd, ch->remote_id, valid) != 0) return -1;
    }
    return valid ? 0 : -1;
  }

  if (ssh_str_eq(request_type, "window-change")) {
    int valid = parse_window_change(ch, pkt, data_start) == 0;
    if (valid && ch->screen != 0) {
      xaios_screen_resize(ch->screen, ch->terminal_rows, ch->terminal_columns);
    }
    if (valid && ch->nano.active != 0U) {
      nano_editor_resize(&ch->nano, ch->terminal_columns, ch->terminal_rows);
      if (nano_render_frame(ch) != 0) return -1;
    }
    if (valid && ch->less.active != 0U) {
      less_pager_resize(&ch->less, ch->terminal_columns, ch->terminal_rows);
      if (less_render_frame(ch) != 0) return -1;
    }
    if (valid && ch->pong.active != 0U) {
      pong_game_resize(&ch->pong, ch->terminal_columns, ch->terminal_rows);
      if (pong_render_frame(ch, xaios_clock_nanos()) != 0) return -1;
    }
    if (want_reply) {
      if (ssh_stream_send_reply(sockfd, ch->remote_id, valid) != 0) return -1;
    }
    return valid ? 0 : -1;
  }

  if (ssh_str_eq(request_type, "env")) {
    /* Accept and ignore */
    if (want_reply) {
      if (ssh_stream_send_reply(sockfd, ch->remote_id, 1) != 0) return -1;
    }
    return 0;
  }

  if (ssh_str_eq(request_type, "auth-agent-req@openssh.com")) {
    ssh_connection_t *connection = ssh_conn_find((u64)(uint32_t)sockfd);
    int valid = data_start == pkt->len && connection != 0 &&
                connection->principal_role == XAIOS_CONTROL_ROLE_ADMIN &&
                ssh_channel_open_agent(ch) == 0;
    if (want_reply && ssh_stream_send_reply(sockfd, ch->remote_id, valid) != 0)
      return -1;
    return valid ? 0 : -1;
  }

  if (ssh_str_eq(request_type, "shell")) {
    int valid = ch->pty_requested != 0U && ch->shell_active == 0U;
    if (want_reply) {
      if (ssh_stream_send_reply(sockfd, ch->remote_id, valid) != 0) return -1;
    }
    if (!valid) return -1;
    ch->shell_active = 1U;
    ch->shell_line_length = 0U;
    ch->shell_ignore_lf = 0U;
    return shell_send_prompt(ch);
  }

  if (ssh_str_eq(request_type, "exec")) {
    /* Parse command string */
    if (data_start > pkt->len || pkt->len - data_start < 4U) {
      if (want_reply && ssh_stream_send_reply(sockfd, ch->remote_id, 0) != 0) {
        return -1;
      }
      return -1;
    }
    uint32_t cmd_len = ssh_read_string_len(pkt->data + data_start);
    if (cmd_len >= 4096U || cmd_len > pkt->len - data_start - 4U ||
        ssh_channel_packet_has_zero(pkt->data + data_start + 4U, cmd_len)) {
      if (want_reply && ssh_stream_send_reply(sockfd, ch->remote_id, 0) != 0) {
        return -1;
      }
      return -1;
    }
    char command[4096];
    char nano_argument[NANO_EDITOR_PATH_MAX];
    ssh_mem_copy(command, pkt->data + data_start + 4, cmd_len);
    command[cmd_len] = '\0';
    int interactive_nano =
        ch->pty_requested != 0U && ssh_shell_token_equal(command, "nano") != 0 &&
        nano_command_argument(command, nano_argument,
                              sizeof(nano_argument)) == 0;
    int interactive_less = ch->pty_requested != 0U &&
                           ssh_shell_token_equal(command, "less") != 0;
    int interactive_pong = ch->pty_requested != 0U &&
                           pong_command_exact(command) != 0;
    if (ssh_shell_prepare_command(ch, command, sizeof(command)) != 0) {
      if (want_reply && ssh_stream_send_reply(sockfd, ch->remote_id, 0) != 0) {
        return -1;
      }
      return -1;
    }

    if (want_reply) {
      if (ssh_stream_send_reply(sockfd, ch->remote_id, 1) != 0) return -1;
    }

    if (interactive_nano != 0) {
      return nano_start(ch, command, 0U);
    }

    if (interactive_less != 0) return less_start(ch, command, 0U);

    if (interactive_pong != 0) return pong_start(ch, command, 0U);

    {
      int client_result = ssh_client_prepare(ch, command);
      if (client_result != 0) return client_result < 0 ? -1 : 0;
    }

    /* Execute command */
    char output[8192];
    u64 out_size = 0;
    int result = ssh_shell_execute_admin(sockfd, command, output, sizeof(output),
                                        &out_size);

    if (result < 0 && out_size == 0U) {
      const char *err = "Command execution failed\n";
      if (ssh_channel_send_data(sockfd, ch->remote_id,
                                (const uint8_t *)err,
                                ssh_str_len(err)) != 0) return -1;
    } else {
      uint32_t olen = (uint32_t)out_size;
      if (olen == 0) { olen = 1; output[0] = '\n'; }
      if (olen > 0) {
        if (ssh_channel_send_data(sockfd, ch->remote_id,
                                  (const uint8_t *)output, olen) != 0) {
          return -1;
        }
      }
    }
    ch->exit_status = result == 0 ? 0U : 1U;
    ch->close_after_flush = 1U;
    return flush_channel(ch);
  }

  if (ssh_str_eq(request_type, "subsystem")) {
    /* Parse subsystem name */
    if (data_start > pkt->len || pkt->len - data_start < 4U) {
      if (want_reply && ssh_stream_send_reply(sockfd, ch->remote_id, 0) != 0) {
        return -1;
      }
      return -1;
    }
    uint32_t name_len = ssh_read_string_len(pkt->data + data_start);
    if (name_len == 0U || name_len >= 64U ||
        name_len > pkt->len - data_start - 4U ||
        ssh_channel_packet_has_zero(pkt->data + data_start + 4U, name_len)) {
      if (want_reply && ssh_stream_send_reply(sockfd, ch->remote_id, 0) != 0) {
        return -1;
      }
      return -1;
    }
    char subsystem[64];
    ssh_mem_copy(subsystem, pkt->data + data_start + 4, name_len);
    subsystem[name_len] = '\0';

    if (ssh_str_eq(subsystem, "sftp")) {
      ssh_connection_t *connection =
          ssh_conn_find((u64)(uint32_t)sockfd);
      if (connection == 0 ||
          connection->principal_role != XAIOS_CONTROL_ROLE_ADMIN) {
        if (want_reply &&
            ssh_stream_send_reply(sockfd, ch->remote_id, 0) != 0) return -1;
        return 0;
      }
      if (want_reply) {
        if (ssh_stream_send_reply(sockfd, ch->remote_id, 1) != 0) return -1;
      }
      ch->is_sftp = 1;
      ch->sftp_rx_used = 0;
      return 0;
    }

    /* Unknown subsystem */
    if (want_reply) {
      if (ssh_stream_send_reply(sockfd, ch->remote_id, 0) != 0) return -1;
    }
    return 0;
  }

  /* Unknown request type */
  if (want_reply) {
    if (ssh_stream_send_reply(sockfd, ch->remote_id, 0) != 0) return -1;
  }
  return 0;
}
