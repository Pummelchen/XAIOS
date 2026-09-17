/*
 * sshd's console program launcher.
 *
 * The local console runs xtop the way an SSH session does: as one child
 * process streaming frames over a child channel, driven by the keys typed
 * here. This module owns that child -- its handle, its receive buffer and its
 * framing -- so the start, input, service and release paths can be read in one
 * file. sshd.c keeps the console_tick() loop that feeds it and the command
 * dispatcher that calls into it.
 *
 * See sshd_console_programs.h for what crosses back into sshd.c.
 */

#include "sshd_console_programs.h"

#include "ssh_channel.h"
#include "ssh_child_ipc.h"
#include "sshd_console_screen.h"

/* The local console runs xtop the way an SSH session does: as one child
   process streaming frames over a child channel, driven by the keys typed
   here. The two surfaces therefore run the same program the same way, and
   there is no second copy of its behaviour to drift. */
static u64 g_console_child;
static uint8_t g_console_child_rx[SSH_CHILD_IPC_HEADER_SIZE +
                                  SSH_CHILD_IPC_PAYLOAD_MAX];
static uint32_t g_console_child_used;

/* "xtop" with or without options, but not "xtop --plain": that form asks for
   the snapshot output on purpose, on either surface. */
int sshd_console_command_is_xtop(const char *command) {
  static const char name[] = "xtop";
  uint32_t i = 0U;
  if (command == 0) return 0;
  for (; i < sizeof(name) - 1U; ++i) {
    if (command[i] != name[i]) return 0;
  }
  if (command[i] != '\0' && command[i] != ' ') return 0;
  for (uint32_t j = i; command[j] != '\0'; ++j) {
    if (command[j] == '-' && command[j + 1U] == '-' &&
        command[j + 2U] == 'p' && command[j + 3U] == 'l' &&
        command[j + 4U] == 'a' && command[j + 5U] == 'i' &&
        command[j + 6U] == 'n') {
      return 0;
    }
  }
  return 1;
}

int sshd_console_program_active(void) { return g_console_child != 0U; }

static void console_child_release(int cancel) {
  if (g_console_child == 0U) return;
  if (cancel != 0) (void)xaios_remote_login_child_cancel(g_console_child);
  (void)xaios_remote_login_child_release(g_console_child);
  g_console_child = 0U;
  g_console_child_used = 0U;
}

int sshd_console_program_start(char *command, uint32_t capacity,
                               const char *username) {
  char cwd[256];
  u64 cwd_size = 0U;
  (void)ssh_terminal_promote_command(command, capacity, sshd_console_columns(),
                                     sshd_console_rows());
  if (xaios_remote_login_session(SSHD_CONSOLE_SESSION_ID, username, "pwd", cwd,
                                 sizeof(cwd), &cwd_size) != 0 ||
      cwd_size == 0U || cwd_size >= sizeof(cwd)) {
    cwd[0] = '/';
    cwd[1] = '\0';
    cwd_size = 1U;
  }
  while (cwd_size != 0U &&
         (cwd[cwd_size - 1U] == '\n' || cwd[cwd_size - 1U] == '\r')) {
    cwd[--cwd_size] = '\0';
  }
  if (xaios_remote_login_child_open(SSHD_CONSOLE_SESSION_ID, command, cwd,
                                    &g_console_child) != 0) {
    g_console_child = 0U;
    sshd_console_text("xtop: launch failed\n");
    return -1;
  }
  g_console_child_used = 0U;
  return 0;
}

void sshd_console_program_input(char value) {
  uint8_t frame[SSH_CHILD_IPC_HEADER_SIZE + 1U];
  ssh_child_ipc_header(frame, SSH_CHILD_IPC_INPUT, 1U);
  frame[SSH_CHILD_IPC_HEADER_SIZE] = (uint8_t)value;
  (void)xaios_remote_login_child_write(g_console_child, frame, sizeof(frame));
}

static void console_child_finish(int cancel) {
  console_child_release(cancel);
  sshd_console_prompt();
}

void sshd_console_program_service(void) {
  if (g_console_child == 0U) return;
  for (uint32_t iteration = 0U; iteration < 8U; ++iteration) {
    u64 size = 0U;
    if (g_console_child_used == sizeof(g_console_child_rx) ||
        xaios_remote_login_child_read(
            g_console_child, g_console_child_rx + g_console_child_used,
            sizeof(g_console_child_rx) - g_console_child_used, &size) != 0 ||
        size > sizeof(g_console_child_rx) - g_console_child_used) {
      console_child_finish(1);
      return;
    }
    if (size == 0U) break;
    g_console_child_used += (uint32_t)size;
    while (g_console_child_used >= SSH_CHILD_IPC_HEADER_SIZE) {
      if (ssh_child_ipc_read_u32(g_console_child_rx) != SSH_CHILD_IPC_MAGIC) {
        console_child_finish(1);
        return;
      }
      uint32_t type = ssh_child_ipc_read_u32(g_console_child_rx + 4U);
      uint32_t length = ssh_child_ipc_read_u32(g_console_child_rx + 8U);
      if (length > SSH_CHILD_IPC_PAYLOAD_MAX) {
        console_child_finish(1);
        return;
      }
      uint32_t frame_length = SSH_CHILD_IPC_HEADER_SIZE + length;
      if (g_console_child_used < frame_length) break;
      if (type == SSH_CHILD_IPC_OUTPUT) {
        (void)sshd_console_write_bytes(
            (const char *)g_console_child_rx + SSH_CHILD_IPC_HEADER_SIZE,
            length);
      }
      uint32_t remaining = g_console_child_used - frame_length;
      for (uint32_t i = 0U; i < remaining; ++i) {
        g_console_child_rx[i] = g_console_child_rx[frame_length + i];
      }
      g_console_child_used = remaining;
    }
  }
  u64 status = 0U;
  if (xaios_remote_login_child_status(g_console_child, &status) != 0 ||
      (u32)status != 1U) {
    console_child_finish(0);
  }
}
