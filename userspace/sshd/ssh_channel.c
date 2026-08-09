#include "ssh_channel.h"
#include "ssh_connection.h"
#include "ssh_protocol.h"
#include "ssh_utils.h"
#include "sftp_server.h"
#include "sshd.h"
#include <xaios_control_client.h>
#include <xaios_user.h>

#define SFTP_REQUEST_READ 5U
#define SFTP_REQUEST_WRITE 6U
#define SSH_PTY_DEFAULT_COLUMNS 120U
#define SSH_PTY_DEFAULT_ROWS 40U
#define SSH_PTY_MIN_COLUMNS 40U
#define SSH_PTY_MAX_COLUMNS 240U
#define SSH_PTY_MIN_ROWS 12U
#define SSH_PTY_MAX_ROWS 100U

static ssh_channel_t g_channels[SSH_CHANNEL_MAX];
static uint32_t g_next_local_id = 1;

void ssh_channel_init(void) {
  for (uint32_t i = 0; i < SSH_CHANNEL_MAX; ++i) {
    g_channels[i].active = 0;
    g_channels[i].owner_sockfd = 0;
    g_channels[i].local_id = 0;
    g_channels[i].remote_id = 0;
    g_channels[i].window_size = 0;
    g_channels[i].remote_window = 0;
    g_channels[i].remote_max_packet = 0;
    g_channels[i].pending_offset = 0;
    g_channels[i].pending_used = 0;
    g_channels[i].close_after_flush = 0;
    g_channels[i].close_sent = 0;
    g_channels[i].exit_status = 0;
    g_channels[i].is_sftp = 0;
    g_channels[i].pty_requested = 0;
    g_channels[i].terminal_columns = 0;
    g_channels[i].terminal_rows = 0;
    g_channels[i].sftp_rx_used = 0;
  }
  g_next_local_id = 1;
}

static ssh_channel_t *alloc_channel(int sockfd) {
  uint32_t owned = 0;
  for (uint32_t i = 0; i < SSH_CHANNEL_MAX; ++i) {
    if (g_channels[i].active &&
        g_channels[i].owner_sockfd == (uint64_t)(uint32_t)sockfd) {
      ++owned;
    }
  }
  if (owned >= sshd_max_channels_per_connection()) return (ssh_channel_t *)0;
  for (uint32_t i = 0; i < SSH_CHANNEL_MAX; ++i) {
    if (!g_channels[i].active) {
      g_channels[i].active = 1;
      g_channels[i].owner_sockfd = (uint64_t)(uint32_t)sockfd;
      g_channels[i].local_id = g_next_local_id++;
      g_channels[i].pending_offset = 0;
      g_channels[i].pending_used = 0;
      g_channels[i].close_after_flush = 0;
      g_channels[i].close_sent = 0;
      g_channels[i].exit_status = 0;
      g_channels[i].is_sftp = 0;
      g_channels[i].pty_requested = 0;
      g_channels[i].terminal_columns = 0;
      g_channels[i].terminal_rows = 0;
      g_channels[i].sftp_rx_used = 0;
      return &g_channels[i];
    }
  }
  return (ssh_channel_t *)0;
}

static ssh_channel_t *find_channel_by_remote(int sockfd, uint32_t remote_id) {
  for (uint32_t i = 0; i < SSH_CHANNEL_MAX; ++i) {
    if (g_channels[i].active &&
        g_channels[i].owner_sockfd == (uint64_t)(uint32_t)sockfd &&
        g_channels[i].remote_id == remote_id) {
      return &g_channels[i];
    }
  }
  return (ssh_channel_t *)0;
}

static ssh_channel_t *find_channel_by_local(int sockfd, uint32_t local_id) {
  for (uint32_t i = 0; i < SSH_CHANNEL_MAX; ++i) {
    if (g_channels[i].active &&
        g_channels[i].owner_sockfd == (uint64_t)(uint32_t)sockfd &&
        g_channels[i].local_id == local_id) {
      return &g_channels[i];
    }
  }
  return (ssh_channel_t *)0;
}

static int packet_string_equal(const uint8_t *value, uint32_t value_len,
                               const char *expected) {
  uint32_t expected_len = ssh_str_len(expected);
  if (value_len != expected_len) return 0;
  for (uint32_t i = 0; i < value_len; ++i) {
    if (value[i] != (uint8_t)expected[i]) return 0;
  }
  return 1;
}

static int packet_has_zero(const uint8_t *value, uint32_t value_len) {
  for (uint32_t i = 0; i < value_len; ++i) {
    if (value[i] == 0U) return 1;
  }
  return 0;
}

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
      packet_has_zero(pkt->data + cursor, term_len)) {
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

static int command_token_equal(const char *command, const char *expected) {
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
        packet_string_equal((const uint8_t *)command + start, option_len,
                            option)) {
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

static int prepare_terminal_command(const ssh_channel_t *ch, char *command,
                                    uint32_t capacity) {
  if (ch == 0 || command == 0 || ch->pty_requested == 0U ||
      command_token_equal(command, "htop") == 0 ||
      command_has_option(command, "--plain") != 0) {
    return 0;
  }
  if (command_has_option(command, "--color") == 0 &&
      append_command_text(command, capacity, " --color") != 0) {
    return -1;
  }
  if (command_has_option(command, "--columns") == 0 &&
      (append_command_text(command, capacity, " --columns ") != 0 ||
       append_command_u32(command, capacity, ch->terminal_columns) != 0)) {
    return -1;
  }
  if (command_has_option(command, "--rows") == 0 &&
      (append_command_text(command, capacity, " --rows ") != 0 ||
       append_command_u32(command, capacity, ch->terminal_rows) != 0)) {
    return -1;
  }
  return 0;
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

static int execute_admin_command(int sockfd, const char *command, char *output,
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
  if (result >= 0) connection->remote_login_session_active = 1U;
  return result < 0 ? -1 : 0;
}

void ssh_channel_close_connection(int sockfd) {
  ssh_connection_t *connection = ssh_conn_find((u64)(uint32_t)sockfd);
  for (uint32_t i = 0; i < SSH_CHANNEL_MAX; ++i) {
    if (g_channels[i].active &&
        g_channels[i].owner_sockfd == (uint64_t)(uint32_t)sockfd) {
      sftp_close_channel(sockfd, g_channels[i].remote_id);
      ssh_mem_zero(&g_channels[i], sizeof(g_channels[i]));
    }
  }
  if (connection != 0 && connection->remote_login_session_active != 0U) {
    (void)xaios_remote_login_session_close(connection->sockfd);
    connection->remote_login_session_active = 0U;
  }
}

/* Send window adjust: type 93, recipient_channel, bytes_to_add */
static int send_window_adjust(int sockfd, uint32_t remote_id, uint32_t bytes) {
  uint8_t adjust[9];
  adjust[0] = SSH_MSG_CHANNEL_WINDOW_ADJUST;
  ssh_write_u32_be(adjust + 1, remote_id);
  ssh_write_u32_be(adjust + 5, bytes);
  return ssh_packet_write_encrypted(sockfd, adjust, sizeof(adjust));
}

/* Send channel success/failure */
static int send_channel_reply(int sockfd, uint32_t remote_id, int success) {
  uint8_t reply[5];
  reply[0] = success ? SSH_MSG_CHANNEL_SUCCESS : SSH_MSG_CHANNEL_FAILURE;
  ssh_write_u32_be(reply + 1, remote_id);
  return ssh_packet_write_encrypted(sockfd, reply, sizeof(reply));
}

/* Send CHANNEL_DATA with output */
static int write_channel_data(int sockfd, uint32_t remote_id,
                              const uint8_t *data, uint32_t len) {
  uint8_t reply[SSH_MAX_PACKET_SIZE];
  if (len > SSH_MAX_PACKET_SIZE - 9U) return -1;
  reply[0] = SSH_MSG_CHANNEL_DATA;
  ssh_write_u32_be(reply + 1, remote_id);
  ssh_write_u32_be(reply + 5, len);
  ssh_mem_copy(reply + 9, data, len);
  return ssh_packet_write_encrypted(sockfd, reply, 9 + len);
}

/* Send CHANNEL_EOF */
static int send_channel_eof(int sockfd, uint32_t remote_id) {
  uint8_t eof_msg[5];
  eof_msg[0] = SSH_MSG_CHANNEL_EOF;
  ssh_write_u32_be(eof_msg + 1, remote_id);
  return ssh_packet_write_encrypted(sockfd, eof_msg, sizeof(eof_msg));
}

static int send_channel_exit_status(int sockfd, uint32_t remote_id,
                                    uint32_t status) {
  uint8_t message[25];
  static const char request[] = "exit-status";
  message[0] = SSH_MSG_CHANNEL_REQUEST;
  ssh_write_u32_be(message + 1U, remote_id);
  ssh_write_u32_be(message + 5U, sizeof(request) - 1U);
  ssh_mem_copy(message + 9U, request, sizeof(request) - 1U);
  message[20] = 0;
  ssh_write_u32_be(message + 21U, status);
  return ssh_packet_write_encrypted(sockfd, message, sizeof(message));
}

static int finish_channel(ssh_channel_t *ch) {
  if (ch->close_sent != 0U) return 0;
  if (send_channel_exit_status((int)ch->owner_sockfd, ch->remote_id,
                               ch->exit_status) != 0 ||
      send_channel_eof((int)ch->owner_sockfd, ch->remote_id) != 0) {
    return -1;
  }
  uint8_t close_msg[5];
  close_msg[0] = SSH_MSG_CHANNEL_CLOSE;
  ssh_write_u32_be(close_msg + 1, ch->remote_id);
  if (ssh_packet_write_encrypted((int)ch->owner_sockfd, close_msg,
                                 sizeof(close_msg)) != 0) return -1;
  sftp_close_channel((int)ch->owner_sockfd, ch->remote_id);
  ch->close_sent = 1U;
  return 0;
}

static int flush_channel(ssh_channel_t *ch) {
  while (ch->pending_used != 0U && ch->remote_window != 0U) {
    uint32_t chunk = ch->pending_used;
    if (chunk > ch->remote_window) chunk = ch->remote_window;
    if (chunk > ch->remote_max_packet) chunk = ch->remote_max_packet;
    if (chunk > SSH_MAX_PACKET_SIZE - 9U) chunk = SSH_MAX_PACKET_SIZE - 9U;
    if (write_channel_data((int)ch->owner_sockfd, ch->remote_id,
                           ch->pending + ch->pending_offset, chunk) != 0) {
      return -1;
    }
    ch->remote_window -= chunk;
    ch->pending_offset += chunk;
    ch->pending_used -= chunk;
  }
  if (ch->pending_used == 0U) {
    ch->pending_offset = 0U;
    if (ch->close_after_flush != 0U) return finish_channel(ch);
  }
  return 0;
}

int ssh_channel_send_data(int sockfd, uint32_t remote_id,
                          const uint8_t *data, uint32_t len) {
  ssh_channel_t *ch = find_channel_by_remote(sockfd, remote_id);
  if (ch == 0 || data == 0 || len == 0U ||
      len > SSH_CHANNEL_PENDING_SIZE - ch->pending_used) return -1;
  if (ch->pending_used != 0U && ch->pending_offset != 0U) {
    for (uint32_t i = 0; i < ch->pending_used; ++i) {
      ch->pending[i] = ch->pending[ch->pending_offset + i];
    }
    ch->pending_offset = 0U;
  }
  ssh_mem_copy(ch->pending + ch->pending_used, data, len);
  ch->pending_used += len;
  return flush_channel(ch);
}

/* ---- Handle CHANNEL_REQUEST (type 98) ---- */
static int handle_channel_request(int sockfd, const ssh_packet_t *pkt) {
  if (pkt->len < 10) return -1;

  /* Parse: uint32 recipient_channel, string request_type, bool want_reply */
  uint32_t local_id = ssh_read_u32_be(pkt->data + 1);
  ssh_channel_t *ch = find_channel_by_local(sockfd, local_id);
  if (!ch) return -1;

  uint32_t type_len = ssh_read_string_len(pkt->data + 5);
  if (type_len > pkt->len - 10U) return -1;
  if (type_len == 0U || type_len >= 64U ||
      packet_has_zero(pkt->data + 9U, type_len)) return -1;

  char request_type[64];
  ssh_mem_copy(request_type, pkt->data + 9, type_len);
  request_type[type_len] = '\0';

  uint32_t type_end = 9 + type_len;
  uint8_t want_reply = (type_end < pkt->len) ? pkt->data[type_end] : 0;

  uint32_t data_start = type_end + 1;

  if (ssh_str_eq(request_type, "pty-req")) {
    int valid = parse_pty_request(ch, pkt, data_start) == 0;
    if (want_reply) {
      if (send_channel_reply(sockfd, ch->remote_id, valid) != 0) return -1;
    }
    return valid ? 0 : -1;
  }

  if (ssh_str_eq(request_type, "window-change")) {
    int valid = parse_window_change(ch, pkt, data_start) == 0;
    if (want_reply) {
      if (send_channel_reply(sockfd, ch->remote_id, valid) != 0) return -1;
    }
    return valid ? 0 : -1;
  }

  if (ssh_str_eq(request_type, "env")) {
    /* Accept and ignore */
    if (want_reply) {
      if (send_channel_reply(sockfd, ch->remote_id, 1) != 0) return -1;
    }
    return 0;
  }

  if (ssh_str_eq(request_type, "shell")) {
    if (want_reply) {
      if (send_channel_reply(sockfd, ch->remote_id, 1) != 0) return -1;
    }
    return 0;
  }

  if (ssh_str_eq(request_type, "exec")) {
    /* Parse command string */
    if (data_start > pkt->len || pkt->len - data_start < 4U) {
      if (want_reply && send_channel_reply(sockfd, ch->remote_id, 0) != 0) {
        return -1;
      }
      return -1;
    }
    uint32_t cmd_len = ssh_read_string_len(pkt->data + data_start);
    if (cmd_len >= 4096U || cmd_len > pkt->len - data_start - 4U ||
        packet_has_zero(pkt->data + data_start + 4U, cmd_len)) {
      if (want_reply && send_channel_reply(sockfd, ch->remote_id, 0) != 0) {
        return -1;
      }
      return -1;
    }
    char command[4096];
    ssh_mem_copy(command, pkt->data + data_start + 4, cmd_len);
    command[cmd_len] = '\0';
    if (prepare_terminal_command(ch, command, sizeof(command)) != 0) {
      if (want_reply && send_channel_reply(sockfd, ch->remote_id, 0) != 0) {
        return -1;
      }
      return -1;
    }

    if (want_reply) {
      if (send_channel_reply(sockfd, ch->remote_id, 1) != 0) return -1;
    }

    /* Execute command */
    char output[8192];
    u64 out_size = 0;
    int result = execute_admin_command(sockfd, command, output, sizeof(output),
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
      if (want_reply && send_channel_reply(sockfd, ch->remote_id, 0) != 0) {
        return -1;
      }
      return -1;
    }
    uint32_t name_len = ssh_read_string_len(pkt->data + data_start);
    if (name_len == 0U || name_len >= 64U ||
        name_len > pkt->len - data_start - 4U ||
        packet_has_zero(pkt->data + data_start + 4U, name_len)) {
      if (want_reply && send_channel_reply(sockfd, ch->remote_id, 0) != 0) {
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
            send_channel_reply(sockfd, ch->remote_id, 0) != 0) return -1;
        return 0;
      }
      if (want_reply) {
        if (send_channel_reply(sockfd, ch->remote_id, 1) != 0) return -1;
      }
      ch->is_sftp = 1;
      ch->sftp_rx_used = 0;
      return 0;
    }

    /* Unknown subsystem */
    if (want_reply) {
      if (send_channel_reply(sockfd, ch->remote_id, 0) != 0) return -1;
    }
    return 0;
  }

  /* Unknown request type */
  if (want_reply) {
    if (send_channel_reply(sockfd, ch->remote_id, 0) != 0) return -1;
  }
  return 0;
}

int ssh_channel_handle_packet(int sockfd, const ssh_packet_t *pkt) {
  if (pkt->len == 0) return -1;
  uint8_t msg_type = pkt->data[0];

  if (msg_type == SSH_MSG_CHANNEL_OPEN) {
    if (pkt->len < 17) return -1;
    uint32_t type_len = ssh_read_string_len(pkt->data + 1);
    if (type_len > pkt->len - 17U) return -1;
    uint32_t off = 5U + type_len;
    if (off + 12U > pkt->len) return -1;
    uint32_t remote_id = ssh_read_u32_be(pkt->data + off);
    if (!packet_string_equal(pkt->data + 5U, type_len, "session")) {
      uint8_t failure[17];
      failure[0] = SSH_MSG_CHANNEL_OPEN_FAILURE;
      ssh_write_u32_be(failure + 1U, remote_id);
      ssh_write_u32_be(failure + 5U, 1U);
      ssh_write_u32_be(failure + 9U, 0U);
      ssh_write_u32_be(failure + 13U, 0U);
      return ssh_packet_write_encrypted(sockfd, failure, sizeof(failure));
    }
    ssh_channel_t *ch = alloc_channel(sockfd);
    if (!ch) {
      uint8_t failure[17];
      failure[0] = SSH_MSG_CHANNEL_OPEN_FAILURE;
      ssh_write_u32_be(failure + 1U, remote_id);
      ssh_write_u32_be(failure + 5U, 4U);
      ssh_write_u32_be(failure + 9U, 0U);
      ssh_write_u32_be(failure + 13U, 0U);
      return ssh_packet_write_encrypted(sockfd, failure, sizeof(failure));
    }
    ch->remote_id = remote_id;
    ch->window_size = SSH_CHANNEL_INITIAL_WINDOW;
    ch->remote_window = ssh_read_u32_be(pkt->data + off + 4U);
    ch->remote_max_packet = ssh_read_u32_be(pkt->data + off + 8U);
    if (ch->remote_max_packet == 0U) {
      ch->active = 0U;
      return -1;
    }
    /* Send CHANNEL_OPEN_CONFIRMATION */
    uint8_t reply[32];
    reply[0] = SSH_MSG_CHANNEL_OPEN_CONFIRM;
    ssh_write_u32_be(reply + 1, ch->remote_id);
    ssh_write_u32_be(reply + 5, ch->local_id);
    ssh_write_u32_be(reply + 9, SSH_CHANNEL_INITIAL_WINDOW);
    ssh_write_u32_be(reply + 13, SSH_CHANNEL_MAX_PACKET);
    return ssh_packet_write_encrypted(sockfd, reply, 17);
  }

  if (msg_type == SSH_MSG_CHANNEL_DATA) {
    if (pkt->len < 9) return -1;
    uint32_t local_id = ssh_read_u32_be(pkt->data + 1);
    uint32_t data_len = ssh_read_string_len(pkt->data + 5);
    if (data_len > pkt->len - 9U || data_len == 0) return -1;

    /* Find channel for window management */
    ssh_channel_t *ch = find_channel_by_local(sockfd, local_id);
    if (!ch) return -1;
    if (data_len > ch->window_size || data_len > SSH_CHANNEL_MAX_PACKET) {
      return -1;
    }
    ch->window_size -= data_len;
    if (ch->window_size <= SSH_CHANNEL_INITIAL_WINDOW / 2U) {
      uint32_t added = SSH_CHANNEL_INITIAL_WINDOW - ch->window_size;
      if (send_window_adjust(sockfd, ch->remote_id, added) != 0) return -1;
      ch->window_size += added;
    }

    if (ch->is_sftp != 0U) {
      if (data_len > SSH_CHANNEL_SFTP_BUFFER_SIZE - ch->sftp_rx_used) {
        xaios_log("sshd: SFTP channel receive buffer exceeded\n");
        return -1;
      }
      ssh_mem_copy(ch->sftp_rx + ch->sftp_rx_used, pkt->data + 9, data_len);
      ch->sftp_rx_used += data_len;

      while (ch->sftp_rx_used >= 4U) {
        uint32_t sftp_len = ssh_read_u32_be(ch->sftp_rx);
        if (sftp_len == 0U ||
            sftp_len > SSH_CHANNEL_SFTP_REQUEST_MAX - 4U) {
          xaios_log("sshd: rejected invalid SFTP packet length\n");
          return -1;
        }
        if (ch->sftp_rx_used < sftp_len + 4U) break;
        if (sftp_handle_message(sockfd, ch->remote_id,
                                ch->sftp_rx + 4U, sftp_len) != 0) {
          xaios_log("sshd: SFTP request handler failed\n");
          return -1;
        }
        uint32_t consumed = sftp_len + 4U;
        uint32_t remaining = ch->sftp_rx_used - consumed;
        for (uint32_t i = 0; i < remaining; ++i) {
          ch->sftp_rx[i] = ch->sftp_rx[consumed + i];
        }
        ch->sftp_rx_used = remaining;
      }
      return 0;
    }

    /* Execute command via remote_login */
    char command[4096];
    if (data_len >= sizeof(command) ||
        packet_has_zero(pkt->data + 9U, data_len)) return -1;
    ssh_mem_copy(command, pkt->data + 9, data_len);
    command[data_len] = '\0';
    if (prepare_terminal_command(ch, command, sizeof(command)) != 0) return -1;

    char output[8192];
    u64 out_size = 0;
    int result = execute_admin_command(sockfd, command, output, sizeof(output),
                                       &out_size);

    if (result < 0 && out_size == 0U) {
      const char *error_msg = "Command execution failed\n";
      uint32_t error_len = ssh_str_len(error_msg);
      return ssh_channel_send_data(sockfd, ch->remote_id,
                                   (const uint8_t *)error_msg, error_len);
    }

    uint32_t output_len = (uint32_t)out_size;
    if (output_len == 0) {
      output_len = 1;
      output[0] = '\n';
      output[1] = '\0';
    }

    return ssh_channel_send_data(sockfd, ch->remote_id,
                                 (const uint8_t *)output, output_len);
  }

  if (msg_type == SSH_MSG_CHANNEL_REQUEST) {
    return handle_channel_request(sockfd, pkt);
  }

  if (msg_type == SSH_MSG_CHANNEL_EOF) {
    if (pkt->len < 5U) return -1;
    ssh_channel_t *ch = find_channel_by_local(
        sockfd, ssh_read_u32_be(pkt->data + 1U));
    if (ch == 0 || ch->close_sent != 0U) return 0;
    if (ch->is_sftp != 0U) {
      ch->exit_status = 0U;
      ch->close_after_flush = 1U;
      return flush_channel(ch);
    }
    return 0;
  }

  if (msg_type == SSH_MSG_CHANNEL_CLOSE) {
    if (pkt->len >= 5) {
      uint32_t local_id = ssh_read_u32_be(pkt->data + 1);
      ssh_channel_t *ch = find_channel_by_local(sockfd, local_id);
      if (ch) {
        sftp_close_channel(sockfd, ch->remote_id);
        if (ch->close_sent == 0U) {
          uint8_t close_msg[5];
          close_msg[0] = SSH_MSG_CHANNEL_CLOSE;
          ssh_write_u32_be(close_msg + 1, ch->remote_id);
          if (ssh_packet_write_encrypted(sockfd, close_msg,
                                         sizeof(close_msg)) != 0) return -1;
        }
        ssh_mem_zero(ch, sizeof(*ch));
      }
    }
    return 0;
  }

  if (msg_type == SSH_MSG_CHANNEL_WINDOW_ADJUST) {
    if (pkt->len >= 9) {
      uint32_t local_id = ssh_read_u32_be(pkt->data + 1);
      uint32_t bytes_to_add = ssh_read_u32_be(pkt->data + 5);
      ssh_channel_t *ch = find_channel_by_local(sockfd, local_id);
      if (ch) {
        if (UINT32_MAX - ch->remote_window < bytes_to_add) return -1;
        ch->remote_window += bytes_to_add;
        return flush_channel(ch);
      }
    }
    return 0;
  }

  if (msg_type == SSH_MSG_CHANNEL_SUCCESS || msg_type == SSH_MSG_CHANNEL_FAILURE) {
    /* Responses to our requests — accept and ignore */
    return 0;
  }

  return 0; /* ignore unknown channel messages */
}
