#ifndef XAIOS_TERMINAL_APP_BRIDGE_H
#define XAIOS_TERMINAL_APP_BRIDGE_H

#include <xaios_user.h>

#define XAIOS_TERMINAL_COMMAND_BYTES 4096U
#define XAIOS_TERMINAL_OUTPUT_BYTES 8192U

static int terminal_append(char *output, u64 capacity, u64 *used,
                           char value) {
  if (*used + 1U >= capacity) return -1;
  output[(*used)++] = value;
  output[*used] = '\0';
  return 0;
}

static int terminal_append_text(char *output, u64 capacity, u64 *used,
                                const char *text) {
  if (text == 0) return -1;
  for (u64 index = 0U; text[index] != '\0'; ++index) {
    if (terminal_append(output, capacity, used, text[index]) != 0) return -1;
  }
  return 0;
}

static int terminal_app_main(const char *core_command, int argc, char **argv) {
  static char command[XAIOS_TERMINAL_COMMAND_BYTES];
  static char output[XAIOS_TERMINAL_OUTPUT_BYTES];
  u64 command_size = 0U;
  u64 output_size = 0U;
  int status;

  command[0] = '\0';
  if (terminal_append_text(command, sizeof(command), &command_size,
                           core_command) != 0) {
    return 2;
  }
  if (argc > 2) return 2;
  if (argc == 2) {
    if (terminal_append(command, sizeof(command), &command_size, ' ') != 0 ||
        terminal_append_text(command, sizeof(command), &command_size,
                             argv[1]) != 0) {
      static const char error[] = "application: arguments exceed limit\n";
      (void)xaios_console_write(error, sizeof(error) - 1U);
      return 2;
    }
  }
  status = xaios_remote_login("admin", command, output, sizeof(output),
                              &output_size);
  if (output_size > sizeof(output)) output_size = sizeof(output);
  if (output_size != 0U) {
    (void)xaios_console_write(output, output_size);
  }
  return status < 0 ? 1 : 0;
}

#endif
