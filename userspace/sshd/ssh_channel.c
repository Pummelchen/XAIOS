#include "ssh_channel.h"
#include "ssh_alt_screen.h"
#include "ssh_channel_shell.h"
#include "ssh_channel_stream.h"
#include "ssh_connection.h"
#include "ssh_protocol.h"
#include "ssh_utils.h"
#include "sftp_server.h"
#include "ssh_client.h"
#include "nano_editor.h"
#include "pong_game.h"
#include "sshd.h"
#include <xaios_control_client.h>
#include <xaios_user.h>
#include <xaios_screen.h>

#define SFTP_REQUEST_READ 5U
#define SFTP_REQUEST_WRITE 6U
#define SSH_PTY_DEFAULT_COLUMNS 120U
#define SSH_PTY_DEFAULT_ROWS 40U
#define SSH_PTY_MIN_COLUMNS 40U
#define SSH_PTY_MAX_COLUMNS 240U
#define SSH_PTY_MIN_ROWS 12U
#define SSH_PTY_MAX_ROWS 100U

enum {
  SSH_XTOP_SORT_CPU = 0U,
  SSH_XTOP_SORT_MEMORY,
  SSH_XTOP_SORT_TIME,
  SSH_XTOP_SORT_PID,
  SSH_XTOP_SORT_STATE,
  SSH_XTOP_SORT_SYSCALLS,
  SSH_XTOP_SORT_COMMAND,
  SSH_XTOP_SORT_PARENT
};

static ssh_channel_t g_channels[SSH_CHANNEL_MAX];
static uint32_t g_next_local_id = 1;
static uint8_t g_forward_buffer[SSH_CHANNEL_MAX_PACKET];

static ssh_channel_t *alloc_channel(int sockfd);

static ssh_channel_t *find_agent_channel(const ssh_channel_t *session) {
  if (session == 0) return 0;
  for (uint32_t i = 0U; i < SSH_CHANNEL_MAX; ++i) {
    if (g_channels[i].active != 0U && g_channels[i].is_agent != 0U &&
        g_channels[i].owner_sockfd == session->owner_sockfd &&
        g_channels[i].agent_session_local_id == session->local_id) {
      return &g_channels[i];
    }
  }
  return 0;
}

static int open_agent_channel(ssh_channel_t *session) {
  static const char type[] = "auth-agent@openssh.com";
  uint8_t packet[64];
  uint32_t position = 0U;
  if (session == 0 || session->agent_forwarding != 0U ||
      find_agent_channel(session) != 0) return -1;
  ssh_channel_t *agent = alloc_channel((int)session->owner_sockfd);
  if (agent == 0) return -1;
  agent->is_agent = 1U;
  agent->agent_open_pending = 1U;
  agent->agent_session_local_id = session->local_id;
  agent->window_size = SSH_CHANNEL_INITIAL_WINDOW;
  packet[position++] = SSH_MSG_CHANNEL_OPEN;
  ssh_write_u32_be(packet + position, (uint32_t)(sizeof(type) - 1U));
  position += 4U;
  ssh_mem_copy(packet + position, type, (uint32_t)(sizeof(type) - 1U));
  position += (uint32_t)(sizeof(type) - 1U);
  ssh_write_u32_be(packet + position, agent->local_id);
  position += 4U;
  ssh_write_u32_be(packet + position, SSH_CHANNEL_INITIAL_WINDOW);
  position += 4U;
  ssh_write_u32_be(packet + position, SSH_CHANNEL_MAX_PACKET);
  position += 4U;
  if (ssh_packet_write_encrypted((int)session->owner_sockfd, packet,
                                 position) != 0) {
    ssh_mem_zero(agent, sizeof(*agent));
    return -1;
  }
  session->agent_forwarding = 1U;
  session->agent_open_pending = 1U;
  return 0;
}

int nano_command_argument(const char *command, char *argument,
                                 uint32_t capacity) {
  uint32_t i = 0U;
  uint32_t used = 0U;
  while (command[i] == ' ' || command[i] == '\t') ++i;
  while (command[i] != '\0' && command[i] != ' ' && command[i] != '\t') ++i;
  while (command[i] == ' ' || command[i] == '\t') ++i;
  if (command[i] == '\0' || command[i] == '-') return -1;
  while (command[i] != '\0' && command[i] != ' ' && command[i] != '\t' &&
         command[i] != '\r' && command[i] != '\n') {
    if (used + 1U >= capacity) return -1;
    argument[used++] = command[i++];
  }
  while (command[i] == ' ' || command[i] == '\t' || command[i] == '\r' ||
         command[i] == '\n') ++i;
  if (command[i] != '\0') return -1;
  argument[used] = '\0';
  return 0;
}

void ssh_channel_init(void) {
  ssh_stream_screen_reset();
  ssh_mem_zero(g_channels, sizeof(g_channels));
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
      ssh_mem_zero(&g_channels[i], sizeof(g_channels[i]));
      g_channels[i].active = 1;
      g_channels[i].owner_sockfd = (uint64_t)(uint32_t)sockfd;
      g_channels[i].local_id = g_next_local_id++;
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

int ssh_channel_packet_string_equal(const uint8_t *value, uint32_t value_len,
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

static int parse_forward_ipv4(const char *text,
                              xaios_ip_addr_user_t *address) {
  uint32_t part = 0U, value = 0U, digits = 0U;
  xaios_memzero(address, sizeof(*address));
  for (uint32_t i = 0U;; ++i) {
    char character = text[i];
    if (character >= '0' && character <= '9') {
      value = value * 10U + (uint32_t)(character - '0');
      if (value > 255U || ++digits > 3U) return -1;
    } else if (character == '.' || character == '\0') {
      if (digits == 0U || part >= 4U) return -1;
      address->addr[part++] = (uint8_t)value;
      value = 0U;
      digits = 0U;
      if (character == '\0') break;
    } else {
      return -1;
    }
  }
  if (part != 4U) return -1;
  address->family = 4U;
  return 0;
}

static int connect_forward_target(const uint8_t *host, uint32_t host_length,
                                  uint32_t port, u64 *socket) {
  char name[128];
  xaios_ip_addr_user_t address;
  if (host_length == 0U || host_length >= sizeof(name) || port == 0U ||
      port > 65535U || packet_has_zero(host, host_length)) return -1;
  ssh_mem_copy(name, host, host_length);
  name[host_length] = '\0';
  if (parse_forward_ipv4(name, &address) != 0) {
    int status = xaios_net_resolve_address(name, 4U, &address);
    if (status != 0) status = xaios_net_resolve_address(name, 6U, &address);
    if (status != 0) return -1;
  }
  return xaios_net_connect(&address, port, socket);
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

int pong_command_exact(const char *command) {
  uint32_t index = 0U;
  static const char name[] = "pong";
  while (command[index] == ' ' || command[index] == '\t' ||
         command[index] == '\r' || command[index] == '\n') ++index;
  for (uint32_t i = 0U; i < sizeof(name) - 1U; ++i)
    if (command[index++] != name[i]) return 0;
  while (command[index] == ' ' || command[index] == '\t' ||
         command[index] == '\r' || command[index] == '\n') ++index;
  return command[index] == '\0';
}

void ssh_channel_close_connection(int sockfd) {
  for (uint32_t i = 0; i < SSH_CHANNEL_MAX; ++i) {
    if (g_channels[i].active &&
        g_channels[i].owner_sockfd == (uint64_t)(uint32_t)sockfd) {
      sftp_close_channel(sockfd, g_channels[i].remote_id);
      ssh_client_close(&g_channels[i]);
      if (g_channels[i].forward_fd != 0U)
        (void)xaios_net_close(g_channels[i].forward_fd);
      if (g_channels[i].less.active != 0U)
        less_pager_close(&g_channels[i].less);
      ssh_stream_screen_release(&g_channels[i]);
      ssh_mem_zero(&g_channels[i], sizeof(g_channels[i]));
    }
  }
  /* Unconditionally, and this is B-25.
   *
   * The kernel allocates a session context on the first call that names a
   * session id, because the context holds the working directory and that has
   * to survive between commands. sshd used to close it only when a flag said
   * a session had been opened, and the flag was set in exactly one place --
   * after a command had *succeeded*. Every other way of reaching the kernel
   * with this id allocated a context and set nothing: a command that failed,
   * and, more often, an interactive shell, whose prompt asks the kernel for
   * the working directory before the user has typed anything. Those contexts
   * were never freed. The connection went away; the context stayed, for the
   * life of the machine.
   *
   * There are sixty-four of them. After sixty-four such connections every
   * later session is refused before remote_login_execute runs, so the guest
   * boots perfectly, keeps answering SFTP -- which does not take this path --
   * and answers "Command execution failed" to every command, with nothing in
   * the console to say why. That is B-25's signature exactly, and its
   * intermittency is just how long a machine takes to reach sixty-four.
   *
   * Closing is idempotent: a session the kernel never opened answers
   * NOT_FOUND and we ignore it. So the flag is gone rather than corrected --
   * it was a record of one caller's belief about a table it did not own, and
   * the next caller added would have got it wrong the same way. */
  (void)xaios_remote_login_session_close((u64)(uint32_t)sockfd);
}

int ssh_channel_send_data(int sockfd, uint32_t remote_id,
                          const uint8_t *data, uint32_t len) {
  ssh_channel_t *ch = find_channel_by_remote(sockfd, remote_id);
  if (ch == 0 || data == 0 || len == 0U) return -1;
  return ssh_stream_write(ch, data, len);
}

int ssh_channel_agent_send(const ssh_channel_t *session, const uint8_t *data,
                           uint32_t len) {
  ssh_channel_t *agent = find_agent_channel(session);
  if (agent == 0 || agent->agent_open_pending != 0U ||
      agent->remote_max_packet == 0U) return -1;
  return ssh_channel_send_data((int)agent->owner_sockfd, agent->remote_id,
                               data, len);
}

/* What one channel's turn came to.
 *
 * The two failures are told apart because they need different endings. A
 * channel whose own I/O failed -- a forwarded connection whose far end went
 * away is the everyday case -- leaves the session it belongs to perfectly
 * healthy, so the peer is told the channel is closing and everything else on
 * that connection carries on. A failure to *write* means the connection's
 * byte stream is the thing that broke: a packet went out half-written, so
 * what follows it is not a packet boundary, and the socket that would not
 * take those bytes will not take a courtesy close either. There the whole
 * connection goes, silently. */
#define SSH_CHANNEL_TICK_OK 0
#define SSH_CHANNEL_TICK_CHANNEL_FAILED 1
#define SSH_CHANNEL_TICK_TRANSPORT_FAILED 2

static int channel_tick_one(ssh_channel_t *ch, uint64_t now_ns) {
  if (ch->active != 0U && ch->screen != 0 && ch->pending_used == 0U &&
      ch->screen->incomplete != 0U && ssh_stream_screen_flush(ch) != 0)
    return SSH_CHANNEL_TICK_TRANSPORT_FAILED;
  if (ch->active != 0U && ch->is_forward != 0U &&
      ch->pending_used == 0U && ch->remote_window != 0U) {
    u64 received = 0U;
    uint32_t capacity = sizeof(g_forward_buffer);
    if (capacity > ch->remote_window) capacity = ch->remote_window;
    if (capacity > ch->remote_max_packet) capacity = ch->remote_max_packet;
    if (xaios_net_recv(ch->forward_fd, g_forward_buffer, capacity,
                       &received) != 0 || received > capacity)
      return SSH_CHANNEL_TICK_CHANNEL_FAILED;
    if (received != 0U &&
        ssh_channel_send_data((int)ch->owner_sockfd, ch->remote_id,
                              g_forward_buffer, (uint32_t)received) != 0)
      return SSH_CHANNEL_TICK_TRANSPORT_FAILED;
  }
  if (ch->active != 0U && ssh_client_is_active(ch)) {
    int client_result = ssh_client_tick(ch, now_ns);
    if (client_result < 0) return SSH_CHANNEL_TICK_CHANNEL_FAILED;
    if (client_result > 0 && ch->shell_active != 0U &&
        shell_send_prompt(ch) != 0)
      return SSH_CHANNEL_TICK_TRANSPORT_FAILED;
    if (client_result > 0 && ch->shell_active == 0U) {
      ch->close_after_flush = 1U;
      if (flush_channel(ch) != 0) return SSH_CHANNEL_TICK_TRANSPORT_FAILED;
    }
  }
  if (ch->active != 0U && ch->pong.active != 0U &&
      ch->pending_used == 0U && pong_game_tick(&ch->pong, now_ns) != 0 &&
      pong_render_frame(ch, now_ns) != 0) {
    ch->exit_status = 1U;
    if (pong_finish(ch, 1U) != 0) return SSH_CHANNEL_TICK_TRANSPORT_FAILED;
  }
  return SSH_CHANNEL_TICK_OK;
}

/* Give up on one channel, and say so on the console.
 *
 * ssh_channel_close_connection does this for every channel a connection owns
 * when the connection goes; this is the same teardown for one of them, with
 * the session-context close left out because the session belongs to the
 * connection and not to the channel. */
static void channel_abandon(ssh_channel_t *ch, int transport_failed) {
  int sockfd = (int)ch->owner_sockfd;
  uint32_t remote_id = ch->remote_id;
  uint32_t local_id = ch->local_id;

  if (transport_failed == 0 && ch->close_sent == 0U) {
    uint8_t close_msg[5];
    (void)ssh_stream_send_eof(sockfd, remote_id);
    close_msg[0] = SSH_MSG_CHANNEL_CLOSE;
    ssh_write_u32_be(close_msg + 1, remote_id);
    (void)ssh_packet_write_encrypted(sockfd, close_msg, sizeof(close_msg));
  }
  sftp_close_channel(sockfd, remote_id);
  ssh_client_close(ch);
  if (ch->forward_fd != 0U) (void)xaios_net_close(ch->forward_fd);
  if (ch->less.active != 0U) less_pager_close(&ch->less);
  ssh_stream_screen_release(ch);
  ssh_mem_zero(ch, sizeof(*ch));

  if (transport_failed != 0) {
    ssh_connection_t *connection = ssh_conn_find((u64)(uint32_t)sockfd);
    if (connection != 0)
      connection->close_requested = SSHD_CLOSE_REQUEST_SILENT;
  }

  /* On the console rather than through ssh_log, which writes to the audit
     file on the durable volume: this is the line that says why a session's
     channel went away, and a console is the only thing a soak captures. */
  char line[160];
  u64 offset = 0;
  xaios_memzero(line, sizeof(line));
  xaios_append_cstr(line, sizeof(line), &offset,
                    "sshd: channel closed after tick failure local=");
  xaios_append_u64(line, sizeof(line), &offset, local_id);
  xaios_append_cstr(line, sizeof(line), &offset, " reason=");
  xaios_append_cstr(line, sizeof(line), &offset,
                    transport_failed != 0 ? "transport" : "channel");
  xaios_append_cstr(line, sizeof(line), &offset, "\n");
  xaios_log(line);
}

/* Every channel gets its turn, whatever the one before it did. This is B-41.
 *
 * The loop used to return the moment a channel failed, which did two things
 * at once and neither of them on purpose. The channel that failed was left
 * active, so the next tick reached it again, failed again, and returned
 * again -- for as long as the connection lived. And every channel after it in
 * the table never ran at all: a forward's data is pumped here and nowhere
 * else, so a second session's forward simply stopped moving, with one warning
 * line per tick in a log nobody was reading to say so.
 *
 * A channel that cannot be serviced is therefore closed here rather than
 * carried, and the loop goes on to the next one. The return value still says
 * whether anything failed, because the caller's warning is worth keeping;
 * what it no longer means is that the remaining channels were skipped. */
int ssh_channel_tick(uint64_t now_ns) {
  int failed = 0;
  for (uint32_t i = 0U; i < SSH_CHANNEL_MAX; ++i) {
    ssh_channel_t *ch = &g_channels[i];
    if (ch->active == 0U) continue;
    int outcome = channel_tick_one(ch, now_ns);
    if (outcome == SSH_CHANNEL_TICK_OK) continue;
    channel_abandon(ch, outcome == SSH_CHANNEL_TICK_TRANSPORT_FAILED);
    failed = 1;
  }
  return failed != 0 ? -1 : 0;
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
                open_agent_channel(ch) == 0;
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
        packet_has_zero(pkt->data + data_start + 4U, cmd_len)) {
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
        packet_has_zero(pkt->data + data_start + 4U, name_len)) {
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

int ssh_channel_handle_packet(int sockfd, const ssh_packet_t *pkt) {
  if (pkt->len == 0) return -1;
  uint8_t msg_type = pkt->data[0];

  if (msg_type == SSH_MSG_CHANNEL_OPEN_CONFIRM) {
    if (pkt->len < 17U) return -1;
    uint32_t local_id = ssh_read_u32_be(pkt->data + 1U);
    ssh_channel_t *agent = find_channel_by_local(sockfd, local_id);
    if (agent == 0 || agent->is_agent == 0U ||
        agent->agent_open_pending == 0U) return -1;
    agent->remote_id = ssh_read_u32_be(pkt->data + 5U);
    agent->remote_window = ssh_read_u32_be(pkt->data + 9U);
    agent->remote_max_packet = ssh_read_u32_be(pkt->data + 13U);
    if (agent->remote_max_packet == 0U) return -1;
    agent->agent_open_pending = 0U;
    ssh_channel_t *session = find_channel_by_local(
        sockfd, agent->agent_session_local_id);
    if (session == 0) return -1;
    session->agent_open_pending = 0U;
    return ssh_client_agent_ready(session);
  }

  if (msg_type == SSH_MSG_CHANNEL_OPEN_FAILURE) {
    if (pkt->len < 9U) return -1;
    ssh_channel_t *agent = find_channel_by_local(
        sockfd, ssh_read_u32_be(pkt->data + 1U));
    if (agent == 0 || agent->is_agent == 0U) return 0;
    ssh_channel_t *session = find_channel_by_local(
        sockfd, agent->agent_session_local_id);
    if (session != 0) {
      session->agent_forwarding = 0U;
      session->agent_open_pending = 0U;
    }
    ssh_mem_zero(agent, sizeof(*agent));
    return 0;
  }

  if (msg_type == SSH_MSG_CHANNEL_OPEN) {
    if (pkt->len < 17) return -1;
    uint32_t type_len = ssh_read_string_len(pkt->data + 1);
    if (type_len > pkt->len - 17U) return -1;
    uint32_t off = 5U + type_len;
    if (off + 12U > pkt->len) return -1;
    uint32_t remote_id = ssh_read_u32_be(pkt->data + off);
    uint32_t is_session =
        ssh_channel_packet_string_equal(pkt->data + 5U, type_len, "session");
    uint32_t is_forward =
        ssh_channel_packet_string_equal(pkt->data + 5U, type_len, "direct-tcpip");
    if (is_session == 0U && is_forward == 0U) {
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
    if (is_forward != 0U) {
      ssh_connection_t *connection = ssh_conn_find((u64)(uint32_t)sockfd);
      uint32_t cursor = off + 12U;
      if (connection == 0 ||
          connection->principal_role != XAIOS_CONTROL_ROLE_ADMIN ||
          pkt->len - cursor < 4U) {
        ch->active = 0U;
        return -1;
      }
      uint32_t host_length = ssh_read_u32_be(pkt->data + cursor);
      cursor += 4U;
      if (host_length > pkt->len - cursor ||
          pkt->len - cursor - host_length < 8U) {
        ch->active = 0U;
        return -1;
      }
      const uint8_t *host = pkt->data + cursor;
      cursor += host_length;
      uint32_t port = ssh_read_u32_be(pkt->data + cursor);
      cursor += 4U;
      uint32_t origin_length = ssh_read_u32_be(pkt->data + cursor);
      cursor += 4U;
      if (origin_length > pkt->len - cursor ||
          pkt->len - cursor - origin_length != 4U ||
          packet_has_zero(pkt->data + cursor, origin_length) ||
          connect_forward_target(host, host_length, port,
                                 &ch->forward_fd) != 0) {
        uint8_t failure[17];
        failure[0] = SSH_MSG_CHANNEL_OPEN_FAILURE;
        ssh_write_u32_be(failure + 1U, remote_id);
        ssh_write_u32_be(failure + 5U, 2U);
        ssh_write_u32_be(failure + 9U, 0U);
        ssh_write_u32_be(failure + 13U, 0U);
        ssh_stream_screen_release(ch);
        ssh_mem_zero(ch, sizeof(*ch));
        return ssh_packet_write_encrypted(sockfd, failure, sizeof(failure));
      }
      ch->is_forward = 1U;
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
      if (ssh_stream_send_window_adjust(sockfd, ch->remote_id, added) != 0) return -1;
      ch->window_size += added;
    }

    if (ch->is_forward != 0U) {
      uint32_t offset = 0U;
      while (offset < data_len) {
        u64 sent = 0U;
        if (xaios_net_send(ch->forward_fd, pkt->data + 9U + offset,
                           data_len - offset, &sent) != 0 || sent == 0U ||
            sent > data_len - offset) return -1;
        offset += (uint32_t)sent;
      }
      return 0;
    }

    if (ch->is_agent != 0U) {
      ssh_channel_t *session = find_channel_by_local(
          sockfd, ch->agent_session_local_id);
      if (session == 0 ||
          ssh_client_agent_response(session, pkt->data + 9U, data_len) != 0)
        return -1;
      return 0;
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

    if (ch->nano.active != 0U) {
      return nano_handle_input(ch, pkt->data + 9U, data_len);
    }

    if (ch->less.active != 0U) {
      return less_handle_input(ch, pkt->data + 9U, data_len);
    }

    if (ch->pong.active != 0U) {
      return pong_handle_input(ch, pkt->data + 9U, data_len);
    }

    if (ssh_client_is_prompting(ch)) {
      int result = ssh_client_password_input(ch, pkt->data + 9U, data_len);
      return result > 0 ? shell_send_prompt(ch) : result;
    }

    if (ssh_client_is_active(ch)) {
      return ssh_client_forward_input(ch, pkt->data + 9U, data_len);
    }

    if (ch->shell_active != 0U) {
      return ssh_shell_handle_input(ch, pkt->data + 9U, data_len);
    }

    /* Execute command via remote_login */
    char command[4096];
    if (data_len >= sizeof(command) ||
        packet_has_zero(pkt->data + 9U, data_len)) return -1;
    ssh_mem_copy(command, pkt->data + 9, data_len);
    command[data_len] = '\0';
    if (ssh_shell_prepare_command(ch, command, sizeof(command)) != 0) return -1;

    char output[8192];
    u64 out_size = 0;
    int result = ssh_shell_execute_admin(sockfd, command, output, sizeof(output),
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
    if (ch->is_forward != 0U) {
      if (ch->forward_fd != 0U) (void)xaios_net_close(ch->forward_fd);
      ch->forward_fd = 0U;
      ch->exit_status = 0U;
      ch->close_after_flush = 1U;
      return flush_channel(ch);
    }
    if (ch->is_sftp != 0U) {
      ch->exit_status = 0U;
      ch->close_after_flush = 1U;
      return flush_channel(ch);
    }
    if (ch->nano.active != 0U) return nano_finish(ch, 0U);
    if (ch->less.active != 0U) return less_finish(ch, 0U);
    if (ch->pong.active != 0U) return pong_finish(ch, 0U);
    if (ssh_client_is_prompting(ch) || ssh_client_is_active(ch)) return 0;
    if (ch->shell_active != 0U) {
      (void)xaios_remote_login_session_close(ch->owner_sockfd);
      ch->shell_active = 0U;
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
        if (ch->forward_fd != 0U) (void)xaios_net_close(ch->forward_fd);
        sftp_close_channel(sockfd, ch->remote_id);
        ssh_client_close(ch);
        if (ch->is_agent != 0U) {
          ssh_channel_t *session = find_channel_by_local(
              sockfd, ch->agent_session_local_id);
          if (session != 0) {
            session->agent_forwarding = 0U;
            session->agent_open_pending = 0U;
          }
        } else {
          ssh_channel_t *agent = find_agent_channel(ch);
          if (agent != 0) {
            if (agent->close_sent == 0U && agent->remote_max_packet != 0U) {
              uint8_t close_agent[5];
              close_agent[0] = SSH_MSG_CHANNEL_CLOSE;
              ssh_write_u32_be(close_agent + 1U, agent->remote_id);
              (void)ssh_packet_write_encrypted(sockfd, close_agent,
                                               sizeof(close_agent));
            }
            ssh_mem_zero(agent, sizeof(*agent));
          }
        }
        if (ch->close_sent == 0U) {
          uint8_t close_msg[5];
          close_msg[0] = SSH_MSG_CHANNEL_CLOSE;
          ssh_write_u32_be(close_msg + 1, ch->remote_id);
          if (ssh_packet_write_encrypted(sockfd, close_msg,
                                         sizeof(close_msg)) != 0) return -1;
        }
        ssh_stream_screen_release(ch);
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
