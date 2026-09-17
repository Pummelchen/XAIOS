#include <xaios/assert.h>
#include <xaios/app_store.h>
#include <xaios/crc32.h>
#include <xaios/initramfs.h>
#include <xaios/inflate.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/klog_ring.h>
#include <xaios/xaiboot_fs.h>
#include <xaios/operations.h>
#include <xaios/pmm.h>
#include <xaios/remote_login.h>
#include <xaios/scheduler.h>
#include <xaios/security.h>
#include <xaios/smp.h>
#include <xaios/status.h>
#include <xaios/timer.h>
#include <xaios/types.h>
#include <xaios/user.h>
#include <xaios/vfs.h>

#include "remote_login_internal.h"
#include "remote_login_session_internal.h"
#include "remote_login_archive_internal.h"
#include "remote_login_meta_internal.h"
#include "remote_login_parse_internal.h"

/*
 * Picard — “They invade our space and we fall back. They assimilate entire
 * worlds, and we fall back. Not again!”
 */

#ifndef XAIOS_REMOTE_LOGIN_LIST_BYTES
#define XAIOS_REMOTE_LOGIN_LIST_BYTES XAIOS_XBFS_MAX_LIST_BYTES
#endif

#ifndef XAIOS_BOOT_TEST_APPS
#define XAIOS_BOOT_TEST_APPS 0
#endif

#if XAIOS_BOOT_TEST_APPS
/* remote_login_handle_cpio writes this header and the archive module reads it, so it has
   one home here and an extern declaration in the private header. */
const char g_remote_login_archive_magic[] = "XAIOSARCHIVE\n";
#endif

void remote_login_log_failure(const char *operation, const char *reason,
                                   xaios_status_t status) {
  if (operation == 0) {
    return;
  }
  klog("remote-login: operation=%s failed reason=%s rc=%d\n", operation,
       reason == 0 ? "unknown" : reason, status);
}

#if XAIOS_BOOT_TEST_APPS
xaios_status_t remote_login_buffer_append_char(char *buffer, uint64_t capacity,
                                       uint64_t *offset, char value) {
  if (buffer == 0 || offset == 0 || capacity == 0U) {
    return XAIOS_ERR_INVALID;
  }
  if (*offset + 1U >= capacity) {
    return XAIOS_ERR_NO_MEMORY;
  }
  buffer[*offset] = value;
  ++(*offset);
  buffer[*offset] = '\0';
  return XAIOS_OK;
}

xaios_status_t remote_login_buffer_append_text(char *buffer, uint64_t capacity,
                                       uint64_t *offset, const char *text) {
  if (buffer == 0 || text == 0 || offset == 0 || capacity == 0U) {
    return XAIOS_ERR_INVALID;
  }
  for (uint64_t i = 0; text[i] != '\0'; ++i) {
    if (remote_login_buffer_append_char(buffer, capacity, offset, text[i]) != XAIOS_OK) {
      return XAIOS_ERR_NO_MEMORY;
    }
  }
  return XAIOS_OK;
}

xaios_status_t write_buffer_to_path(const char *path, const char *data,
                                    uint64_t data_size) {
  int64_t fd = -1;
  if (path == 0 || data == 0) {
    return XAIOS_ERR_INVALID;
  }
  fd = xaiboot_fs_open(path,
                       XAIOS_XBFS_OPEN_WRITE | XAIOS_XBFS_OPEN_CREATE |
                           XAIOS_XBFS_OPEN_TRUNCATE);
  if (fd < 0) {
    return XAIOS_ERR_INVALID;
  }
  if (data_size != 0U) {
    int64_t written = xaiboot_fs_write_fd((uint32_t)fd, data, data_size);
    if (written < 0 || ((uint64_t)written) != data_size) {
      (void)xaiboot_fs_close((uint32_t)fd);
      return XAIOS_ERR_INVALID;
    }
  }
  if (xaiboot_fs_close((uint32_t)fd) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  return XAIOS_OK;
}

xaios_status_t read_file_buffer(const char *path, char *buffer,
                                uint64_t buffer_capacity,
                                uint64_t *out_size) {
  if (path == 0 || buffer == 0 || out_size == 0 || buffer_capacity == 0U) {
    return XAIOS_ERR_INVALID;
  }
  xaios_status_t status = xaiboot_fs_read(path, buffer, buffer_capacity, out_size);
  if (status != XAIOS_OK) {
    return status;
  }
  return XAIOS_OK;
}

int string_starts_with(const char *text, const char *prefix) {
  if (text == 0 || prefix == 0) {
    return 0;
  }
  uint64_t i = 0;
  for (;;) {
    if (prefix[i] == '\0') {
      return 1;
    }
    if (text[i] != prefix[i] || text[i] == '\0') {
      return 0;
    }
    ++i;
  }
}

static int glob_match(const char *text, const char *pattern) {
  if (pattern == 0 || text == 0) {
    return 0;
  }

  if (pattern[0] == '\0') {
    return text[0] == '\0';
  }
  if (pattern[0] == '*') {
    while (pattern[0] == '*') {
      ++pattern;
    }
    if (pattern[0] == '\0') {
      return 1;
    }
    while (text[0] != '\0') {
      if (glob_match(text, pattern) != 0) {
        return 1;
      }
      ++text;
    }
    return 0;
  }
  if (pattern[0] == '?') {
    return text[0] != '\0' && glob_match(text + 1U, pattern + 1U);
  }
  if (pattern[0] == '\\' && pattern[1] != '\0') {
    return text[0] == pattern[1] && glob_match(text + 1U, pattern + 2U);
  }
  return text[0] == pattern[0] && glob_match(text + 1U, pattern + 1U);
}

int find_match(const char *name, const char *pattern) {
  if (pattern == 0 || pattern[0] == '\0') {
    return 1;
  }
  int has_wildcard = 0;
  for (uint64_t i = 0; pattern[i] != '\0'; ++i) {
    if (pattern[i] == '*' || pattern[i] == '?') {
      has_wildcard = 1;
      break;
    }
  }
  return has_wildcard != 0 ? glob_match(name, pattern)
                           : (string_equal(name, pattern) == 1U);
}

uint64_t parse_decimal_uint(const char *text, uint64_t *value) {
  uint64_t cursor = 0;
  uint64_t parsed = 0;
  if (text == 0 || value == 0 || text[0] == '\0') {
    return 0;
  }
  while (text[cursor] != '\0') {
    char digit = text[cursor];
    if (digit < '0' || digit > '9') {
      return 0;
    }
    parsed = (parsed * 10U) + (uint64_t)(digit - '0');
    ++cursor;
  }
  *value = parsed;
  return cursor;
}

xaios_status_t read_file_lines(const char *path, char *buffer,
                                    uint64_t buffer_capacity, uint64_t *size) {
  if (path == 0 || buffer == 0 || size == 0 || buffer_capacity == 0U) {
    return XAIOS_ERR_INVALID;
  }
  if (xaiboot_fs_read(path, buffer, buffer_capacity, size) != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  return XAIOS_OK;
}
#endif

xaios_status_t remote_login_exec(const char *command, char *output,
                                      uint64_t output_capacity,
                                      uint64_t *output_bytes) {
  char cmd[32];
  char args[XAIOS_REMOTE_LOGIN_LIST_BYTES];
  char arg1[XAIOS_XBFS_PATH_MAX];
  char arg2[XAIOS_XBFS_PATH_MAX];
  char payload[XAIOS_REMOTE_LOGIN_LIST_BYTES];
  uint64_t index = 0;
  uint64_t arg_index = 0;

  if (token_next(command, &index, cmd, sizeof(cmd)) != XAIOS_OK) {
    remote_login_log_failure("parse", "missing-command", XAIOS_ERR_INVALID);
    return XAIOS_ERR_INVALID;
  }
  remote_login_remainder(command, index, args, sizeof(args));
  arg1[0] = '\0';
  arg2[0] = '\0';
  payload[0] = '\0';
  (void)token_next(args, &arg_index, arg1, sizeof(arg1));

  if (string_equal(cmd, "help") == 1U) {
    output_append(
        output, output_capacity, output_bytes,
        "XAIOS shell: pwd ls l la ll cd mkdir touch cp grep find head tail echo "
        "tar zip unzip cpio cat less mv rm rmdir stat df du ps write sed nano xtop pong "
        "ssh scp status sysinfo "
        "shutdown reboot power service kill ifconfig route arp ndp netstat "
        "ping nslookup date ntp limits recovery update config support "
        "hello helloworldc99 systest smptest nettest lstm-xor mltest "
        "posix-shell agenttest xapt "
        "xaiosctl exit "
        "quit logout help\n");
    return XAIOS_OK;
  }
  if (operations_is_command(command) != 0U) {
    return operations_execute(command, output, output_capacity, output_bytes);
  }
  if (string_equal(cmd, "status") == 1U) {
    output_append(output, output_capacity, output_bytes,
                  "status: legacy command; use xaiosctl status for measured "
                  "state\n");
    return XAIOS_OK;
  }
  if (string_equal(cmd, "sysinfo") == 1U) {
#if XAIOS_BOOT_TEST_APPS
    output_append(output, output_capacity, output_bytes,
                  "sysinfo: legacy command; use xaiosctl hardware for "
                  "discovered state\n");
    return XAIOS_OK;
#else
    return remote_login_app_run(remote_login_app_find(cmd), args, output,
                             output_capacity, output_bytes);
#endif
  }
#if !XAIOS_BOOT_TEST_APPS
  {
    const remote_login_app_definition_t *app = remote_login_app_find(cmd);
    if (app != 0) {
      return remote_login_app_run(app, args, output, output_capacity,
                               output_bytes);
    }
  }
#endif
  if (string_equal(cmd, "pwd") == 1U) {
    return remote_login_handle_pwd(output, output_capacity, output_bytes);
  }
  if (string_equal(cmd, "cd") == 1U) {
    if (has_more_args(args, arg_index) != 0) {
      return command_fail(output, output_capacity, output_bytes,
                          "cd: too many arguments");
    }
    return remote_login_handle_cd(arg1, output, output_capacity, output_bytes);
  }
#if XAIOS_BOOT_TEST_APPS
  if (string_equal(cmd, "ls") == 1U) {
    return handle_ls(args, output, output_capacity, output_bytes);
  }
  if (string_equal(cmd, "l") == 1U || string_equal(cmd, "ll") == 1U ||
      string_equal(cmd, "la") == 1U) {
    /* The alias has to carry its argument. This branch used to pass the flags
       alone -- so "l /" listed the working directory rather than the root, and
       "ll /tmp" quietly ignored /tmp. The other branch of this #if built the
       argument string properly, which is how the two configurations came to
       disagree about what the same command does. */
    char alias_args[XAIOS_XBFS_PATH_MAX];
    const char *flags = string_equal(cmd, "ll") == 1U ? "-l" : "-la";
    uint64_t used = cstr_len(flags);
    if (used + (args[0] != '\0' ? cstr_len(args) + 2U : 1U) >
        sizeof(alias_args)) {
      return command_fail(output, output_capacity, output_bytes,
                          "ls: arguments exceed limit");
    }
    (void)copy_cstr(alias_args, sizeof(alias_args), flags);
    if (args[0] != '\0') {
      alias_args[used++] = ' ';
      (void)copy_cstr(alias_args + used, sizeof(alias_args) - used, args);
    }
    return handle_ls(alias_args, output, output_capacity, output_bytes);
  }
#else
  if (string_equal(cmd, "l") == 1U || string_equal(cmd, "ll") == 1U ||
      string_equal(cmd, "la") == 1U) {
    char alias_args[XAIOS_XBFS_PATH_MAX];
    const char *flags = string_equal(cmd, "ll") == 1U ? "-l" : "-la";
    uint64_t used = cstr_len(flags);
    if (used + (args[0] != '\0' ? cstr_len(args) + 2U : 1U) >
        sizeof(alias_args)) {
      return command_fail(output, output_capacity, output_bytes,
                          "ls: arguments exceed limit");
    }
    (void)copy_cstr(alias_args, sizeof(alias_args), flags);
    if (args[0] != '\0') {
      alias_args[used++] = ' ';
      (void)copy_cstr(alias_args + used, sizeof(alias_args) - used, args);
    }
    return remote_login_app_run(remote_login_app_find("ls"), alias_args, output,
                             output_capacity, output_bytes);
  }
#endif
  if (string_equal(cmd, "exit") == 1U) {
    return XAIOS_OK;
  }
  if (string_equal(cmd, "quit") == 1U) {
    return XAIOS_OK;
  }
  if (string_equal(cmd, "logout") == 1U) {
    return XAIOS_OK;
  }
#if XAIOS_BOOT_TEST_APPS
  if (string_equal(cmd, "cp") == 1U) {
    return remote_login_copy_cp(args, output, output_capacity, output_bytes);
  }
  if (string_equal(cmd, "grep") == 1U) {
    return handle_grep(args, output, output_capacity, output_bytes);
  }
  if (string_equal(cmd, "find") == 1U) {
    return handle_find_cmd(args, output, output_capacity, output_bytes);
  }
  if (string_equal(cmd, "head") == 1U) {
    return handle_head_tail(args, 1, output, output_capacity, output_bytes);
  }
  if (string_equal(cmd, "tail") == 1U) {
    return handle_head_tail(args, 0, output, output_capacity, output_bytes);
  }
#endif
  if (string_equal(cmd, "echo") == 1U) {
    if (args[0] == '\0') {
      output_append_char(output, output_capacity, output_bytes, '\n');
      return XAIOS_OK;
    }
    output_append(output, output_capacity, output_bytes, args);
    output_append_char(output, output_capacity, output_bytes, '\n');
    return XAIOS_OK;
  }
#if XAIOS_BOOT_TEST_APPS
  if (string_equal(cmd, "cpio") == 1U) {
    return remote_login_handle_cpio(args, output, output_capacity, output_bytes);
  }
  if (string_equal(cmd, "tar") == 1U) {
    return remote_login_handle_tar(args, output, output_capacity, output_bytes);
  }
  if (string_equal(cmd, "zip") == 1U) {
    return remote_login_handle_zip(args, output, output_capacity, output_bytes);
  }
  if (string_equal(cmd, "unzip") == 1U) {
    return remote_login_handle_unzip(args, output, output_capacity, output_bytes);
  }
  if (string_equal(cmd, "mkdir") == 1U) {
    return handle_mkdir(args, output, output_capacity, output_bytes);
  }
  if (string_equal(cmd, "touch") == 1U) {
    if (has_more_args(args, arg_index) != 0) {
      return command_fail(output, output_capacity, output_bytes,
                          "touch: too many arguments");
    }
    return handle_touch(arg1, output, output_capacity, output_bytes);
  }
  if (string_equal(cmd, "cat") == 1U) {
    return remote_login_handle_cat(args, output, output_capacity, output_bytes);
  }
  if (string_equal(cmd, "less") == 1U) {
    return remote_login_handle_less(args, output, output_capacity, output_bytes);
  }
  if (string_equal(cmd, "mv") == 1U) {
    return remote_login_copy_mv(args, output, output_capacity, output_bytes);
  }
  if (string_equal(cmd, "rm") == 1U) {
    return remote_login_copy_rm(args, output, output_capacity, output_bytes);
  }
  if (string_equal(cmd, "rmdir") == 1U) {
    return remote_login_copy_rmdir(args, output, output_capacity, output_bytes);
  }
  if (string_equal(cmd, "stat") == 1U) {
    if (has_more_args(args, arg_index) != 0) {
      return command_fail(output, output_capacity, output_bytes,
                          "stat: too many arguments");
    }
    return handle_stat(arg1, output, output_capacity, output_bytes);
  }
  if (string_equal(cmd, "write") == 1U) {
    uint64_t payload_index = 0;
    if (token_next(args, &payload_index, arg1, sizeof(arg1)) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "write: missing path");
    }
    remote_login_remainder(args, payload_index, payload, sizeof(payload));
    return handle_write(arg1, payload[0] == '\0' ? 0 : payload, output,
                        output_capacity, output_bytes);
  }
  if (string_equal(cmd, "sed") == 1U) {
    return handle_sed(args, output, output_capacity, output_bytes);
  }
  if (string_equal(cmd, "ps") == 1U) {
    return handle_ps(args, output, output_capacity, output_bytes);
  }
  if (string_equal(cmd, "df") == 1U) {
    return handle_df(args, output, output_capacity, output_bytes);
  }
  if (string_equal(cmd, "du") == 1U) {
    return handle_du(args, output, output_capacity, output_bytes);
  }
#endif

#if !XAIOS_BOOT_TEST_APPS
  {
    xaios_app_image_t image;
    if (app_store_load(cmd, &image) == XAIOS_OK) {
      remote_login_app_definition_t app = {
          cmd, image.path, image.capabilities, 0U, 0U, 1U};
      xaios_status_t status = remote_login_app_run_file(
          &app, &image.file, args, output, output_capacity, output_bytes);
      app_store_release(&image);
      return status;
    }
  }
#endif

  klog("remote-login: command rejected reason=not-allowlisted\n");
  output_append(output, output_capacity, output_bytes, "xaios: ");
  output_append(output, output_capacity, output_bytes, cmd);
  output_append(output, output_capacity, output_bytes, ": command not found\n");
  return XAIOS_ERR_INVALID;
}
