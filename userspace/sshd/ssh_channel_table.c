/* The SSH channel table: its rows, the id counter, and the lifetime work
 * that walks them.
 *
 * Split out of `ssh_channel.c`, which was 1031 lines. The table state and the
 * lookups that hand out a row pointer move as a unit, so every reader of the
 * table stays in this translation unit or reaches it through the private
 * `ssh_channel_internal.h`. The request dispatcher moved to
 * `ssh_channel_request.c`; the packet dispatcher stayed in `ssh_channel.c`,
 * which imports the three lookups it needs.
 *
 * sshd runs this table from one cooperative loop with no lock, so no row
 * pointer crosses a critical section.
 */

#include "ssh_channel.h"
#include "ssh_channel_internal.h"

#include "ssh_alt_screen.h"
#include "ssh_channel_stream.h"
#include "ssh_connection.h"
#include "ssh_protocol.h"
#include "ssh_utils.h"
#include "sftp_server.h"
#include "ssh_client.h"
#include "sshd.h"
#include <xaios_user.h>

static ssh_channel_t g_channels[SSH_CHANNEL_MAX];
static uint32_t g_next_local_id = 1;
static uint8_t g_forward_buffer[SSH_CHANNEL_MAX_PACKET];

ssh_channel_t *ssh_channel_find_agent(const ssh_channel_t *session) {
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

int ssh_channel_open_agent(ssh_channel_t *session) {
  static const char type[] = "auth-agent@openssh.com";
  uint8_t packet[64];
  uint32_t position = 0U;
  if (session == 0 || session->agent_forwarding != 0U ||
      ssh_channel_find_agent(session) != 0) return -1;
  ssh_channel_t *agent = ssh_channel_alloc((int)session->owner_sockfd);
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

void ssh_channel_init(void) {
  ssh_stream_screen_reset();
  ssh_mem_zero(g_channels, sizeof(g_channels));
  g_next_local_id = 1;
}

ssh_channel_t *ssh_channel_alloc(int sockfd) {
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

ssh_channel_t *ssh_channel_find_local(int sockfd, uint32_t local_id) {
  for (uint32_t i = 0; i < SSH_CHANNEL_MAX; ++i) {
    if (g_channels[i].active &&
        g_channels[i].owner_sockfd == (uint64_t)(uint32_t)sockfd &&
        g_channels[i].local_id == local_id) {
      return &g_channels[i];
    }
  }
  return (ssh_channel_t *)0;
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
  ssh_channel_t *agent = ssh_channel_find_agent(session);
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
