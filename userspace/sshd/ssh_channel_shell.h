#ifndef XAIOS_SSH_CHANNEL_SHELL_H
#define XAIOS_SSH_CHANNEL_SHELL_H

#include <xaios/types.h>
#include <xaios_user.h>

/* The interactive shell line and the command/exec path, split out of
 * `ssh_channel.c`.
 *
 * The channel table stayed behind, so these take a channel the caller has
 * already found, or the socket a command is to run on. That is also why the
 * request dispatcher stayed: it looks a channel up in the table and mutates it.
 *
 * `ssh_terminal_promote_command` is defined here too, but its declaration stays
 * in the public `ssh_channel.h` because the local console calls it as well.
 * `nano_command_argument` and `pong_command_exact` also stayed in
 * `ssh_channel.c` (declared in `ssh_alt_screen.h`); this module calls them.
 *
 * Private to those two translation units.
 */

#include "ssh_channel.h"

/* The shell line interpreter, called with a channel's typed input once the
   full-screen programs have declined it. */
int ssh_shell_handle_input(ssh_channel_t *ch, const uint8_t *data,
                           uint32_t length);

/* Whether the first whitespace-delimited token of `command` is exactly
   `expected`. */
int ssh_shell_token_equal(const char *command, const char *expected);

/* Apply the terminal-application option promotion to a channel's command when
   the channel has a PTY. */
int ssh_shell_prepare_command(const ssh_channel_t *ch, char *command,
                              uint32_t capacity);

/* Run an administrative or control command on behalf of a connection. */
int ssh_shell_execute_admin(int sockfd, const char *command, char *output,
                            u64 output_capacity, u64 *out_size);

/* Defined in `ssh_channel.c` and used on both sides: the request dispatcher
   there and the option scanner here compare a length-prefixed wire string to a
   C literal, and one definition serves both. */
int ssh_channel_packet_string_equal(const uint8_t *value, uint32_t value_len,
                                    const char *expected);

#endif
