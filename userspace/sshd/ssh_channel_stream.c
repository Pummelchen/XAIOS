/* The outbound half of a channel: wire framing, the output queue, and the
 * alternate-screen session filter.
 *
 * Split out of `ssh_channel.c` unchanged. The screen pool -- four screens and
 * their cell storage -- moved with the filter that fills them. Declarations
 * shared with `ssh_channel.c` are in `ssh_channel_stream.h`.
 */

#include "ssh_channel.h"
#include "ssh_channel_stream.h"

#include "ssh_protocol.h"
#include "ssh_utils.h"
#include "sftp_server.h"
#include <xaios_screen.h>

#define SSH_SCREEN_POOL 4U
static uint32_t g_screen_used[SSH_SCREEN_POOL];

/* Send window adjust: type 93, recipient_channel, bytes_to_add */
int ssh_stream_send_window_adjust(int sockfd, uint32_t remote_id,
                                  uint32_t bytes) {
  uint8_t adjust[9];
  adjust[0] = SSH_MSG_CHANNEL_WINDOW_ADJUST;
  ssh_write_u32_be(adjust + 1, remote_id);
  ssh_write_u32_be(adjust + 5, bytes);
  return ssh_packet_write_encrypted(sockfd, adjust, sizeof(adjust));
}

/* Send channel success/failure */
int ssh_stream_send_reply(int sockfd, uint32_t remote_id, int success) {
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
int ssh_stream_send_eof(int sockfd, uint32_t remote_id) {
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
      ssh_stream_send_eof((int)ch->owner_sockfd, ch->remote_id) != 0) {
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

int flush_channel(ssh_channel_t *ch) {
  while (ch->pending_used != 0U && ch->remote_window != 0U) {
    uint32_t chunk = ch->pending_used;
    if (chunk > ch->remote_window) chunk = ch->remote_window;
    if (chunk > ch->remote_max_packet) chunk = ch->remote_max_packet;
    if (chunk > SSH_CHANNEL_MAX_PACKET) chunk = SSH_CHANNEL_MAX_PACKET;
    if (chunk > SSH_WIRE_MAX_CHUNK) chunk = SSH_WIRE_MAX_CHUNK;
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

/* The session filter of the screen framework: a program that enters the
   alternate screen is run through a screen the session holds, and only
   the cells that changed reach the client -- whether the program writes
   whole frames or knows the framework. Four screens are kept; a fifth
   full-screen session at once passes through as before. */
static xaios_screen_cell_t g_screen_cells[SSH_SCREEN_POOL][2][XAIOS_SCREEN_MAX_CELLS];
static xaios_screen_t g_screens[SSH_SCREEN_POOL];
static char g_screen_out[SSH_CHANNEL_PENDING_SIZE];
static uint8_t g_screen_in[SSH_CHANNEL_PENDING_SIZE + 8U];
static const uint8_t k_alternate_enter[8] = {0x1b, '[', '?', '1', '0', '4', '9', 'h'};
static const uint8_t k_alternate_leave[8] = {0x1b, '[', '?', '1', '0', '4', '9', 'l'};

void ssh_stream_screen_reset(void) {
  for (uint32_t i = 0U; i < SSH_SCREEN_POOL; ++i) g_screen_used[i] = 0U;
}

void ssh_stream_screen_release(ssh_channel_t *ch) {
  if (ch->screen == 0) return;
  g_screen_used[ch->screen_slot] = 0U;
  ch->screen = 0;
  ch->screen_slot = 0U;
  ch->screen_carry_used = 0U;
}

static void screen_acquire(ssh_channel_t *ch) {
  if (ch->screen != 0) return;
  for (uint32_t i = 0U; i < SSH_SCREEN_POOL; ++i) {
    if (g_screen_used[i] != 0U) continue;
    g_screen_used[i] = 1U;
    ch->screen = &g_screens[i];
    ch->screen_slot = i;
    ch->screen_carry_used = 0U;
    xaios_screen_init(ch->screen, g_screen_cells[i][0], g_screen_cells[i][1],
                      XAIOS_SCREEN_MAX_CELLS,
                      ch->terminal_rows != 0U ? ch->terminal_rows : 24U,
                      ch->terminal_columns != 0U ? ch->terminal_columns : 80U);
    return;
  }
}

static int queue_raw(ssh_channel_t *ch, const uint8_t *data, uint32_t len) {
  if (len == 0U) return 0;
  if (len > SSH_CHANNEL_PENDING_SIZE - ch->pending_used) return -1;
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

/* Present into the room the pending buffer has; what does not fit now is
   presented from the tick once the buffer drains. */
int ssh_stream_screen_flush(ssh_channel_t *ch) {
  for (;;) {
    uint32_t room = SSH_CHANNEL_PENDING_SIZE - ch->pending_used;
    if (room < 64U) return 0;
    if (room > sizeof(g_screen_out)) room = sizeof(g_screen_out);
    uint64_t n = xaios_screen_present(ch->screen, g_screen_out, room);
    if (n == 0U) return 0;
    if (queue_raw(ch, (const uint8_t *)g_screen_out, (uint32_t)n) != 0) return -1;
    if (ch->screen->incomplete == 0U) return 0;
  }
}

static int64_t find_bytes(const uint8_t *data, uint32_t len,
                          const uint8_t *needle, uint32_t n) {
  for (uint32_t i = 0U; i + n <= len; ++i) {
    uint32_t k = 0U;
    while (k < n && data[i + k] == needle[k]) ++k;
    if (k == n) return (int64_t)i;
  }
  return -1;
}

/* Bytes at the end that begin an escape sequence the paint cannot finish
   are kept for the next write, so a leave sequence split across two
   writes is still seen. */
static uint32_t trailing_partial_escape(const uint8_t *data, uint32_t len) {
  uint32_t back = len < 8U ? len : 8U;
  for (uint32_t i = 0U; i < back; ++i) {
    uint32_t at = len - 1U - i;
    if (data[at] == 0x1bU) {
      /* Complete if a final byte (0x40..0x7e) follows ESC [ ... */
      if (at + 1U < len && data[at + 1U] == '[') {
        for (uint32_t j = at + 2U; j < len; ++j) {
          if (data[j] >= 0x40U && data[j] <= 0x7eU) return 0U;
        }
        return len - at;
      }
      return at + 1U == len ? 1U : 0U;
    }
  }
  return 0U;
}

/* Whether this channel's outgoing bytes are a terminal's output.
 *
 * The screen framework's session filter reads every byte a channel sends,
 * looking for the sequence a program uses to enter the alternate screen; from
 * then on it paints the bytes into a screen and sends changed cells instead of
 * the bytes themselves. That is right for a terminal and wrong for everything
 * else, and this is B-38.
 *
 * Three kinds of channel carry bytes that are not a terminal's output at all:
 * the SFTP subsystem carries file contents, a direct-tcpip forward carries
 * whatever the forwarded connection carries, and an agent channel carries the
 * agent protocol. All three are arbitrary binary, so all three can contain
 * those eight bytes -- and file contents are the case that needs no
 * coincidence at all, because any file that holds captured terminal output
 * holds them on purpose. When one does, the filter eats the payload. The
 * client receives a byte stream that is no longer the file: SFTP's
 * length-prefixed framing then either desynchronises into a bogus length
 * ("Received message too long") or, if the mangled stream happens to promise
 * more bytes than follow, leaves the client waiting for a response the server
 * has already decided it sent.
 *
 * A client waiting on that response sends nothing more, so the server sees an
 * authenticated connection that has gone quiet: no error, nothing to close,
 * and the session sits in the table until the 300-second idle timeout reaps
 * it. That is the observation this was filed as -- a session accepted and
 * authenticated with no matching close, while the machine went on serving
 * everyone else.
 *
 * Gated on what the channel is rather than on the bytes, because no byte test
 * can work: the payload is arbitrary, so any sequence the filter reacts to can
 * occur in it.
 */
static int channel_carries_terminal_output(const ssh_channel_t *ch) {
  return ch->is_sftp == 0U && ch->is_forward == 0U && ch->is_agent == 0U;
}

int ssh_stream_write(ssh_channel_t *ch, const uint8_t *data, uint32_t len) {
  if (channel_carries_terminal_output(ch) == 0) {
    return queue_raw(ch, data, len);
  }
  while (len != 0U) {
    if (ch->screen == 0) {
      int64_t at = find_bytes(data, len, k_alternate_enter, 8U);
      if (at < 0) return queue_raw(ch, data, len);
      uint32_t head = (uint32_t)at + 8U;
      if (queue_raw(ch, data, head) != 0) return -1;
      data += head;
      len -= head;
      screen_acquire(ch);
      if (ch->screen == 0) return queue_raw(ch, data, len);
      continue;
    }
    /* Carried bytes first, then this write. */
    uint32_t total = ch->screen_carry_used + len;
    if (total > sizeof(g_screen_in)) return -1;
    for (uint32_t i = 0U; i < ch->screen_carry_used; ++i) g_screen_in[i] = ch->screen_carry[i];
    ssh_mem_copy(g_screen_in + ch->screen_carry_used, data, len);
    ch->screen_carry_used = 0U;
    data = g_screen_in;
    len = total;
    int64_t at = find_bytes(data, len, k_alternate_leave, 8U);
    if (at < 0) {
      uint32_t keep = trailing_partial_escape(data, len);
      xaios_screen_paint(ch->screen, (const char *)data, len - keep);
      for (uint32_t i = 0U; i < keep; ++i) ch->screen_carry[i] = data[len - keep + i];
      ch->screen_carry_used = keep;
      return ssh_stream_screen_flush(ch);
    }
    xaios_screen_paint(ch->screen, (const char *)data, (uint32_t)at);
    if (ssh_stream_screen_flush(ch) != 0) return -1;
    ssh_stream_screen_release(ch);
    if (queue_raw(ch, data + at, 8U) != 0) return -1;
    data += (uint32_t)at + 8U;
    len -= (uint32_t)at + 8U;
  }
  return 0;
}
