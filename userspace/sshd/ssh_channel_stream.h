#ifndef XAIOS_SSH_CHANNEL_STREAM_H
#define XAIOS_SSH_CHANNEL_STREAM_H

/* The outbound half of a channel, split out of `ssh_channel.c`.
 *
 * The SSH wire messages a channel emits, the pending output queue that feeds
 * them, and the alternate-screen session filter -- the four screens and their
 * cell storage -- all moved together. Every function here takes a channel the
 * caller has already found in `ssh_channel.c`'s table. The table itself stayed
 * behind: its lookup helpers hand out `ssh_channel_t *` into a file-scope
 * array, and publishing one of those across a translation unit would let
 * another file mutate this module's state through a pointer this header never
 * describes.
 *
 * `flush_channel` is also defined in `ssh_channel_stream.c` but is declared in
 * `ssh_alt_screen.h`, which already owned its declaration; its name is
 * unchanged so that module needs no edit.
 *
 * Private to those two translation units.
 */

#include "ssh_channel.h"

/* Wire messages. */
int ssh_stream_send_window_adjust(int sockfd, uint32_t remote_id,
                                  uint32_t bytes);
int ssh_stream_send_reply(int sockfd, uint32_t remote_id, int success);
int ssh_stream_send_eof(int sockfd, uint32_t remote_id);

/* Zero the screen pool. Called from the channel initialiser, which owns the
   reset point; there is no accessor returning the pool. */
void ssh_stream_screen_reset(void);

/* Give back the screen a channel holds, if it holds one. */
void ssh_stream_screen_release(ssh_channel_t *ch);

/* Present whatever the channel's screen still owes the client. */
int ssh_stream_screen_flush(ssh_channel_t *ch);

/* Queue, and as window and packet sizes allow send, outbound channel bytes --
 * through the alternate-screen filter when the channel carries a terminal's
 * output, raw otherwise. */
int ssh_stream_write(ssh_channel_t *ch, const uint8_t *data, uint32_t len);

#endif
