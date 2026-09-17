#ifndef XAIOS_SSH_ALT_SCREEN_H
#define XAIOS_SSH_ALT_SCREEN_H

/* The full-screen programs the SSH shell hosts: nano, less and pong.
 *
 * These thirteen functions moved out of `ssh_channel.c` into
 * `ssh_alt_screen.c` unchanged. They all take the channel pointer, and the
 * only file-scope object they reached -- `g_nano_frame`, the shared render
 * buffer -- moved with them. `ssh_channel.c` still calls them from the shell
 * line dispatcher, the tick path and the input path, so they are declared
 * here; `flush_channel`, `nano_command_argument` and `pong_command_exact`
 * stayed behind and are declared here for the same reason.
 *
 * Private to those two translation units.
 */

#include "ssh_channel.h"

int shell_send_prompt(ssh_channel_t *ch);

int nano_start(ssh_channel_t *ch, const char *command,
               uint32_t return_to_shell);
int nano_handle_input(ssh_channel_t *ch, const uint8_t *data, uint32_t length);
int nano_finish(ssh_channel_t *ch, uint32_t status);
int nano_render_frame(ssh_channel_t *ch);

int less_start(ssh_channel_t *ch, const char *command,
               uint32_t return_to_shell);
int less_handle_input(ssh_channel_t *ch, const uint8_t *data, uint32_t length);
int less_finish(ssh_channel_t *ch, uint32_t status);
int less_render_frame(ssh_channel_t *ch);

int pong_start(ssh_channel_t *ch, const char *command,
               uint32_t return_to_shell);
int pong_handle_input(ssh_channel_t *ch, const uint8_t *data, uint32_t length);
int pong_finish(ssh_channel_t *ch, uint32_t status);
int pong_render_frame(ssh_channel_t *ch, uint64_t now_ns);

/* Still in ssh_channel.c; the programs above call them. */
int nano_command_argument(const char *command, char *argument,
                          uint32_t capacity);
int pong_command_exact(const char *command);
int flush_channel(ssh_channel_t *ch);

#endif
