/* The SSH shell's alternate-screen programs: nano, less and pong.
 *
 * Split out of `ssh_channel.c` unchanged. `g_nano_frame`, the one file-scope
 * object this block reached, moved with it. The three helpers it calls that
 * stayed behind are declared in `ssh_alt_screen.h`.
 */

#include "ssh_channel.h"
#include "ssh_alt_screen.h"

#include "ssh_utils.h"
#include <xaios_user.h>

/* The shared render buffer: each program renders a whole frame into here
 * before it goes out on the channel. */
static char g_nano_frame[SSH_CHANNEL_PENDING_SIZE];

int shell_send_prompt(ssh_channel_t *ch) {
  char cwd[256];
  char prompt[320];
  u64 cwd_size = 0U;
  uint32_t used = 0U;
  static const char prefix[] = "\033[1;32madmin@xaios\033[0m:\033[1;34m";
  static const char suffix[] = "\033[0m$ ";
  if (ch == 0 || ch->shell_active == 0U) return -1;
  if (xaios_remote_login_session(ch->owner_sockfd, "admin", "pwd", cwd,
                                 sizeof(cwd), &cwd_size) < 0 ||
      cwd_size == 0U || cwd_size >= sizeof(cwd)) {
    cwd[0] = '/';
    cwd[1] = '\0';
    cwd_size = 1U;
  }
  while (cwd_size != 0U &&
         (cwd[cwd_size - 1U] == '\n' || cwd[cwd_size - 1U] == '\r')) {
    --cwd_size;
  }
  if (sizeof(prefix) - 1U + cwd_size + sizeof(suffix) - 1U >
      sizeof(prompt)) {
    return -1;
  }
  ssh_mem_copy(prompt + used, prefix, sizeof(prefix) - 1U);
  used += sizeof(prefix) - 1U;
  ssh_mem_copy(prompt + used, cwd, (uint32_t)cwd_size);
  used += (uint32_t)cwd_size;
  ssh_mem_copy(prompt + used, suffix, sizeof(suffix) - 1U);
  used += sizeof(suffix) - 1U;
  return ssh_channel_send_data((int)ch->owner_sockfd, ch->remote_id,
                               (const uint8_t *)prompt, used);
}


int nano_render_frame(ssh_channel_t *ch) {
  uint32_t frame_size = 0U;
  if (nano_editor_render(&ch->nano, g_nano_frame, sizeof(g_nano_frame),
                         &frame_size) != 0 ||
      frame_size == 0U) {
    return -1;
  }
  return ssh_channel_send_data((int)ch->owner_sockfd, ch->remote_id,
                               (const uint8_t *)g_nano_frame, frame_size);
}

int nano_finish(ssh_channel_t *ch, uint32_t status) {
  static const char restore[] =
      "\033[0m\033[?25h\033[?1049l\033[0m\033[?25h\r";
  ch->nano.active = 0U;
  ch->exit_status = status;
  if (ssh_channel_send_data((int)ch->owner_sockfd, ch->remote_id,
                            (const uint8_t *)restore,
                            (uint32_t)(sizeof(restore) - 1U)) != 0) {
    return -1;
  }
  if (ch->interactive_returns_to_shell != 0U && ch->shell_active != 0U) {
    ch->interactive_returns_to_shell = 0U;
    return shell_send_prompt(ch);
  }
  ch->close_after_flush = 1U;
  return flush_channel(ch);
}

int nano_start(ssh_channel_t *ch, const char *command,
                      uint32_t return_to_shell) {
  char argument[NANO_EDITOR_PATH_MAX];
  char cwd[NANO_EDITOR_PATH_MAX];
  u64 cwd_size = 0U;
  static const char enter[] = "\033[?1049h";
  if (nano_command_argument(command, argument, sizeof(argument)) != 0) {
    static const char usage[] = "nano: usage: nano FILE\r\n";
    if (ssh_channel_send_data((int)ch->owner_sockfd, ch->remote_id,
                              (const uint8_t *)usage,
                              (uint32_t)(sizeof(usage) - 1U)) != 0) {
      return -1;
    }
    return return_to_shell != 0U ? shell_send_prompt(ch) : nano_finish(ch, 1U);
  }
  if (xaios_remote_login_session(ch->owner_sockfd, "admin", "pwd", cwd,
                                 sizeof(cwd), &cwd_size) < 0 ||
      cwd_size == 0U || cwd_size >= sizeof(cwd)) {
    return -1;
  }
  while (cwd_size != 0U &&
         (cwd[cwd_size - 1U] == '\n' || cwd[cwd_size - 1U] == '\r')) {
    cwd[--cwd_size] = '\0';
  }
  if (nano_editor_open(&ch->nano, argument, cwd, ch->terminal_columns,
                       ch->terminal_rows) != 0) {
    char error[160];
    uint32_t used = 0U;
    static const char prefix[] = "nano: ";
    ssh_mem_copy(error + used, prefix, sizeof(prefix) - 1U);
    used += sizeof(prefix) - 1U;
    uint32_t status_length = ssh_str_len(ch->nano.status);
    if (status_length > sizeof(error) - used - 2U) {
      status_length = sizeof(error) - used - 2U;
    }
    ssh_mem_copy(error + used, ch->nano.status, status_length);
    used += status_length;
    error[used++] = '\r';
    error[used++] = '\n';
    if (ssh_channel_send_data((int)ch->owner_sockfd, ch->remote_id,
                              (const uint8_t *)error, used) != 0) {
      return -1;
    }
    if (return_to_shell != 0U) return shell_send_prompt(ch);
    ch->exit_status = 1U;
    ch->close_after_flush = 1U;
    return flush_channel(ch);
  }
  ch->interactive_returns_to_shell = return_to_shell;
  if (ssh_channel_send_data((int)ch->owner_sockfd, ch->remote_id,
                            (const uint8_t *)enter,
                            (uint32_t)(sizeof(enter) - 1U)) != 0) {
    return -1;
  }
  return nano_render_frame(ch);
}

int nano_handle_input(ssh_channel_t *ch, const uint8_t *data,
                             uint32_t length) {
  uint32_t should_exit = 0U;
  if (nano_editor_input(&ch->nano, data, length, &should_exit) != 0) return -1;
  if (should_exit != 0U) return nano_finish(ch, 0U);
  return nano_render_frame(ch);
}

int less_render_frame(ssh_channel_t *ch) {
  uint32_t frame_size = 0U;
  if (less_pager_render(&ch->less, g_nano_frame, sizeof(g_nano_frame),
                        &frame_size) != 0 || frame_size == 0U) return -1;
  return ssh_channel_send_data((int)ch->owner_sockfd, ch->remote_id,
                               (const uint8_t *)g_nano_frame, frame_size);
}

int less_finish(ssh_channel_t *ch, uint32_t status) {
  static const char restore[] =
      "\033[0m\033[?25h\033[?1049l\033[0m\033[?25h\r";
  less_pager_close(&ch->less);
  ch->exit_status = status;
  if (ssh_channel_send_data((int)ch->owner_sockfd, ch->remote_id,
                            (const uint8_t *)restore,
                            (uint32_t)(sizeof(restore) - 1U)) != 0) return -1;
  if (ch->interactive_returns_to_shell != 0U && ch->shell_active != 0U) {
    ch->interactive_returns_to_shell = 0U;
    return shell_send_prompt(ch);
  }
  ch->close_after_flush = 1U;
  return flush_channel(ch);
}

int less_start(ssh_channel_t *ch, const char *command,
                      uint32_t return_to_shell) {
  char cwd[LESS_PAGER_PATH_MAX];
  u64 cwd_size = 0U;
  static const char enter[] = "\033[?1049h\033[?25l";
  if (xaios_remote_login_session(ch->owner_sockfd, "admin", "pwd", cwd,
                                 sizeof(cwd), &cwd_size) < 0 ||
      cwd_size == 0U || cwd_size >= sizeof(cwd)) return -1;
  while (cwd_size != 0U &&
         (cwd[cwd_size - 1U] == '\n' || cwd[cwd_size - 1U] == '\r'))
    cwd[--cwd_size] = '\0';
  if (less_pager_open(&ch->less, command, cwd, ch->terminal_columns,
                      ch->terminal_rows) != 0) {
    static const char error[] =
        "less: usage: less [-N] FILE (regular files up to 128 KiB)\r\n";
    if (ssh_channel_send_data((int)ch->owner_sockfd, ch->remote_id,
                              (const uint8_t *)error,
                              (uint32_t)(sizeof(error) - 1U)) != 0) return -1;
    if (return_to_shell != 0U) return shell_send_prompt(ch);
    ch->exit_status = 1U;
    ch->close_after_flush = 1U;
    return flush_channel(ch);
  }
  ch->interactive_returns_to_shell = return_to_shell;
  if (ssh_channel_send_data((int)ch->owner_sockfd, ch->remote_id,
                            (const uint8_t *)enter,
                            (uint32_t)(sizeof(enter) - 1U)) != 0)
    return -1;
  return less_render_frame(ch);
}

int less_handle_input(ssh_channel_t *ch, const uint8_t *data,
                             uint32_t length) {
  uint32_t should_exit = 0U;
  if (less_pager_input(&ch->less, data, length, &should_exit) != 0) return -1;
  if (should_exit != 0U) return less_finish(ch, 0U);
  return less_render_frame(ch);
}

int pong_render_frame(ssh_channel_t *ch, uint64_t now_ns) {
  uint32_t frame_size = 0U;
  if (pong_game_render(&ch->pong, g_nano_frame, sizeof(g_nano_frame),
                       &frame_size, now_ns) != 0 || frame_size == 0U)
    return -1;
  return ssh_channel_send_data((int)ch->owner_sockfd, ch->remote_id,
                               (const uint8_t *)g_nano_frame, frame_size);
}

int pong_finish(ssh_channel_t *ch, uint32_t status) {
  static const char restore[] =
      "\033[0m\033[?25h\033[?1049l\033[0m\033[?25h\r";
  ch->pong.active = 0U;
  ch->exit_status = status;
  if (ssh_channel_send_data((int)ch->owner_sockfd, ch->remote_id,
                            (const uint8_t *)restore,
                            (uint32_t)(sizeof(restore) - 1U)) != 0)
    return -1;
  if (ch->interactive_returns_to_shell != 0U && ch->shell_active != 0U) {
    ch->interactive_returns_to_shell = 0U;
    return shell_send_prompt(ch);
  }
  ch->close_after_flush = 1U;
  return flush_channel(ch);
}

int pong_start(ssh_channel_t *ch, const char *command,
                      uint32_t return_to_shell) {
  static const char enter[] = "\033[?1049h\033[?25l";
  if (pong_command_exact(command) == 0) {
    static const char usage[] = "pong: usage: pong\r\n";
    if (ssh_channel_send_data((int)ch->owner_sockfd, ch->remote_id,
                              (const uint8_t *)usage,
                              (uint32_t)(sizeof(usage) - 1U)) != 0)
      return -1;
    if (return_to_shell != 0U) return shell_send_prompt(ch);
    ch->exit_status = 1U;
    ch->close_after_flush = 1U;
    return flush_channel(ch);
  }
  uint64_t now_ns = xaios_clock_nanos();
  pong_game_start(&ch->pong, ch->terminal_columns, ch->terminal_rows, now_ns);
  ch->interactive_returns_to_shell = return_to_shell;
  if (ssh_channel_send_data((int)ch->owner_sockfd, ch->remote_id,
                            (const uint8_t *)enter,
                            (uint32_t)(sizeof(enter) - 1U)) != 0)
    return -1;
  return pong_render_frame(ch, now_ns);
}

int pong_handle_input(ssh_channel_t *ch, const uint8_t *data,
                             uint32_t length) {
  uint32_t should_exit = 0U;
  uint64_t now_ns = xaios_clock_nanos();
  if (pong_game_input(&ch->pong, data, length, &should_exit, now_ns) != 0)
    return -1;
  if (should_exit != 0U) return pong_finish(ch, 0U);
  return ch->pending_used == 0U ? pong_render_frame(ch, now_ns) : 0;
}
