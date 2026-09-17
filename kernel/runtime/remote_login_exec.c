/*
 * Paging and command execution for the remote-login shell: the `less` handler,
 * and the redirect/pipe driver that parses a command line and hands each stage
 * to remote_login.c's dispatcher.
 *
 * Split out of remote_login.c, which keeps the dispatcher itself
 * (remote_login_exec) because the shell help catalog tests/repository/
 * check-user-docs.py reads lives in it. The dispatcher calls the pager across
 * the translation-unit boundary and the driver calls the dispatcher, so both
 * names cross and lose `static`.
 *
 * `less` came from a boot-test-only arm of remote_login.c and keeps that guard;
 * the redirect/pipe driver had no guard there and has none here.
 */

#include "remote_login_internal.h"

#include <xaios/status.h>
#include <xaios/types.h>
#include <xaios/xaiboot_fs.h>

/* The only user is the redirect/pipe driver below, so it moved with it rather
   than becoming a shell-wide symbol. */
static uint64_t find_unquoted_char(const char *text, uint64_t start,
                                   char target) {
  if (text == 0) return UINT64_MAX;
  int in_single = 0;
  int in_double = 0;
  for (uint64_t i = start; text[i] != '\0'; ++i) {
    char c = text[i];
    if (c == '\'' && in_double == 0) {
      in_single = in_single ? 0 : 1;
    } else if (c == '"' && in_single == 0) {
      in_double = in_double ? 0 : 1;
    } else if (c == target && in_single == 0 && in_double == 0) {
      return i;
    }
  }
  return UINT64_MAX;
}

#if XAIOS_BOOT_TEST_APPS
xaios_status_t remote_login_handle_less(const char *args, char *output,
                                uint64_t output_capacity,
                                uint64_t *output_bytes) {
  uint64_t index = 0U;
  char token[XAIOS_XBFS_PATH_MAX];
  char files[XAIOS_REMOTE_LOGIN_LIST_BYTES];
  uint64_t files_used = 0U;
  int number_lines = 0;
  uint32_t file_count = 0U;
  files[0] = '\0';
  while (token_next(args, &index, token, sizeof(token)) == XAIOS_OK) {
    if (string_equal(token, "-N")) {
      number_lines = 1;
    } else if (token[0] == '-') {
      return command_fail(output, output_capacity, output_bytes,
                          "less: unsupported option");
    } else {
      if (file_count != 0U &&
          remote_login_buffer_append_char(files, sizeof(files), &files_used, ' ') != XAIOS_OK) {
        return XAIOS_ERR_NO_MEMORY;
      }
      if (remote_login_buffer_append_text(files, sizeof(files), &files_used, token) != XAIOS_OK) {
        return XAIOS_ERR_NO_MEMORY;
      }
      ++file_count;
    }
  }
  if (file_count == 0U) {
    return command_fail(output, output_capacity, output_bytes,
                        "less: missing file operand");
  }
  char cat_args[XAIOS_REMOTE_LOGIN_LIST_BYTES];
  uint64_t cat_used = 0U;
  cat_args[0] = '\0';
  if (number_lines != 0) {
    (void)remote_login_buffer_append_text(cat_args, sizeof(cat_args), &cat_used, "-n ");
  }
  (void)remote_login_buffer_append_text(cat_args, sizeof(cat_args), &cat_used, files);
  return remote_login_handle_cat(cat_args, output, output_capacity, output_bytes);
}
#endif

xaios_status_t remote_login_exec_pipeline(const char *command,
                                                char *output,
                                                uint64_t output_capacity,
                                                uint64_t *output_bytes) {
  uint64_t redirect_pos = find_unquoted_char(command, 0, '>');
  if (redirect_pos != UINT64_MAX) {
    char lhs[XAIOS_REMOTE_LOGIN_LIST_BYTES];
    char rhs[XAIOS_XBFS_PATH_MAX];
    if (redirect_pos == 0U || redirect_pos >= sizeof(lhs)) {
      return command_fail(output, output_capacity, output_bytes,
                          "redirect: command too long");
    }
    uint64_t lhs_end = redirect_pos;
    while (lhs_end > 0U && (command[lhs_end - 1U] == ' ' ||
                            command[lhs_end - 1U] == '\t')) {
      --lhs_end;
    }
    for (uint64_t i = 0; i < lhs_end; ++i) {
      lhs[i] = command[i];
    }
    lhs[lhs_end] = '\0';
    uint64_t rhs_start = redirect_pos + 1U;
    while (command[rhs_start] == ' ' || command[rhs_start] == '\t') {
      ++rhs_start;
    }
    uint64_t rhs_idx = 0;
    while (command[rhs_start] != '\0' && command[rhs_start] != ' ' &&
           command[rhs_start] != '\t' && rhs_idx + 1U < sizeof(rhs)) {
      rhs[rhs_idx++] = command[rhs_start++];
    }
    rhs[rhs_idx] = '\0';
    char lhs_output[XAIOS_XBFS_MAX_FILE_BYTES];
    uint64_t lhs_bytes = 0;
    lhs_output[0] = '\0';
    xaios_status_t rc =
        remote_login_exec(lhs, lhs_output, sizeof(lhs_output), &lhs_bytes);
    if (rc != XAIOS_OK) {
      return rc;
    }
    char resolved[XAIOS_XBFS_PATH_MAX];
    if (remote_path_resolve(remote_login_cwd(), rhs, resolved,
                            sizeof(resolved)) != XAIOS_OK ||
        remote_ensure_parent(resolved) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "redirect: invalid path");
    }
    if (xaiboot_fs_write(resolved, lhs_output, lhs_bytes) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "redirect: write failed");
    }
    output[0] = '\0';
    *output_bytes = 0;
    return XAIOS_OK;
  }
  uint64_t pipe_pos = find_unquoted_char(command, 0, '|');
  if (pipe_pos != UINT64_MAX) {
    char lhs[XAIOS_REMOTE_LOGIN_LIST_BYTES];
    char rhs[XAIOS_REMOTE_LOGIN_LIST_BYTES];
    if (pipe_pos == 0U || pipe_pos >= sizeof(lhs)) {
      return command_fail(output, output_capacity, output_bytes,
                          "pipe: command too long");
    }
    uint64_t lhs_end = pipe_pos;
    while (lhs_end > 0U && (command[lhs_end - 1U] == ' ' ||
                            command[lhs_end - 1U] == '\t')) {
      --lhs_end;
    }
    for (uint64_t i = 0; i < lhs_end; ++i) {
      lhs[i] = command[i];
    }
    lhs[lhs_end] = '\0';
    uint64_t rhs_start = pipe_pos + 1U;
    while (command[rhs_start] == ' ' || command[rhs_start] == '\t') {
      ++rhs_start;
    }
    uint64_t rhs_idx = 0;
    while (command[rhs_start] != '\0' && rhs_idx + 1U < sizeof(rhs)) {
      rhs[rhs_idx++] = command[rhs_start++];
    }
    rhs[rhs_idx] = '\0';
    char lhs_output[XAIOS_XBFS_MAX_FILE_BYTES];
    uint64_t lhs_bytes = 0;
    lhs_output[0] = '\0';
    xaios_status_t rc =
        remote_login_exec(lhs, lhs_output, sizeof(lhs_output), &lhs_bytes);
    if (rc != XAIOS_OK) {
      return rc;
    }
    if (xaiboot_fs_write("/tmp/_pipe_stage", lhs_output, lhs_bytes) !=
        XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "pipe: temp write failed");
    }
    char rhs_with_input[XAIOS_REMOTE_LOGIN_LIST_BYTES];
    uint64_t rhs_len = cstr_len(rhs);
    const char *tmp_path = "/tmp/_pipe_stage";
    uint64_t tmp_len = cstr_len(tmp_path);
    if (rhs_len + 1U + tmp_len + 1U >= sizeof(rhs_with_input)) {
      return command_fail(output, output_capacity, output_bytes,
                          "pipe: command too long");
    }
    for (uint64_t i = 0; i < rhs_len; ++i) {
      rhs_with_input[i] = rhs[i];
    }
    rhs_with_input[rhs_len] = ' ';
    for (uint64_t i = 0; i < tmp_len; ++i) {
      rhs_with_input[rhs_len + 1U + i] = tmp_path[i];
    }
    rhs_with_input[rhs_len + 1U + tmp_len] = '\0';
    return remote_login_exec(rhs_with_input, output, output_capacity,
                             output_bytes);
  }
  return remote_login_exec(command, output, output_capacity, output_bytes);
}
