/*
 * Text tools for the remote-login shell: grep with the pattern matchers only
 * it uses, head/tail, and sed.
 *
 * Split out of remote_login.c, which keeps the command dispatch and the
 * session state these entry points read through remote_login_cwd(). The body
 * is compiled only when XAIOS_BOOT_TEST_APPS is on, exactly as it was inside
 * remote_login.c; in the shipped configuration none of these commands is
 * registered and none of this exists.
 */

#include "remote_login_internal.h"

#include <xaios/kheap.h>
#include <xaios/status.h>
#include <xaios/types.h>
#include <xaios/xaiboot_fs.h>

#if XAIOS_BOOT_TEST_APPS

static char ascii_fold(char value) {
  return value >= 'A' && value <= 'Z' ? (char)(value + ('a' - 'A')) : value;
}

static int span_contains(const char *text, uint64_t text_len,
                         const char *pattern, int ignore_case) {
  uint64_t pattern_len = cstr_len(pattern);
  if (pattern_len == 0U) return 1;
  if (pattern_len > text_len) return 0;
  for (uint64_t start = 0U; start + pattern_len <= text_len; ++start) {
    uint64_t matched = 0U;
    while (matched < pattern_len) {
      char left = text[start + matched];
      char right = pattern[matched];
      if (ignore_case != 0) {
        left = ascii_fold(left);
        right = ascii_fold(right);
      }
      if (left != right) break;
      ++matched;
    }
    if (matched == pattern_len) return 1;
  }
  return 0;
}

static int grep_atom_matches(const char *pattern, uint64_t *atom_len, char value,
                             int ignore_case) {
  char expected = pattern[0];
  *atom_len = 1U;
  if (expected == '\\' && pattern[1] != '\0') {
    expected = pattern[1];
    *atom_len = 2U;
  }
  if (expected == '.') return 1;
  if (ignore_case != 0) {
    expected = ascii_fold(expected);
    value = ascii_fold(value);
  }
  return expected == value;
}

static int grep_regex_here(const char *pattern, const char *text,
                           uint64_t text_len, int ignore_case) {
  if (pattern[0] == '\0') return 1;
  if (pattern[0] == '$' && pattern[1] == '\0') return text_len == 0U;
  uint64_t atom_len = 0U;
  (void)grep_atom_matches(pattern, &atom_len, '\0', ignore_case);
  if (pattern[atom_len] == '*') {
    uint64_t used = 0U;
    for (;;) {
      if (grep_regex_here(pattern + atom_len + 1U, text + used,
                          text_len - used, ignore_case)) {
        return 1;
      }
      if (used >= text_len ||
          !grep_atom_matches(pattern, &atom_len, text[used], ignore_case)) {
        return 0;
      }
      ++used;
    }
  }
  if (text_len != 0U &&
      grep_atom_matches(pattern, &atom_len, text[0], ignore_case)) {
    return grep_regex_here(pattern + atom_len, text + 1U, text_len - 1U,
                           ignore_case);
  }
  return 0;
}

static int grep_regex_matches(const char *pattern, const char *text,
                              uint64_t text_len, int ignore_case) {
  if (pattern[0] == '^') {
    return grep_regex_here(pattern + 1U, text, text_len, ignore_case);
  }
  for (uint64_t start = 0U; start <= text_len; ++start) {
    if (grep_regex_here(pattern, text + start, text_len - start, ignore_case)) {
      return 1;
    }
  }
  return 0;
}

xaios_status_t handle_grep(const char *args, char *output,
                                uint64_t output_capacity,
                                uint64_t *output_bytes) {
  char pattern[XAIOS_XBFS_PATH_MAX];
  char files[16][XAIOS_XBFS_PATH_MAX];
  uint32_t file_count = 0U;
  uint64_t index = 0U;
  int ignore_case = 0;
  int line_numbers = 0;
  int invert = 0;
  int count_only = 0;
  int fixed = 0;
  int show_filename = 0;
  int hide_filename = 0;
  int end_options = 0;
  char token[XAIOS_XBFS_PATH_MAX];
  pattern[0] = '\0';
  while (token_next(args, &index, token, sizeof(token)) == XAIOS_OK) {
    if (end_options == 0 && string_equal(token, "--")) {
      end_options = 1;
      continue;
    }
    if (pattern[0] == '\0' && end_options == 0 && token[0] == '-') {
      for (uint64_t flag = 1U; token[flag] != '\0'; ++flag) {
        if (token[flag] == 'i') ignore_case = 1;
        else if (token[flag] == 'n') line_numbers = 1;
        else if (token[flag] == 'v') invert = 1;
        else if (token[flag] == 'c') count_only = 1;
        else if (token[flag] == 'F') fixed = 1;
        else if (token[flag] == 'H') show_filename = 1;
        else if (token[flag] == 'h') hide_filename = 1;
        else {
          return command_fail(output, output_capacity, output_bytes,
                              "grep: unsupported option");
        }
      }
      continue;
    }
    if (pattern[0] == '\0') {
      if (copy_cstr(pattern, sizeof(pattern), token) != XAIOS_OK) {
        return command_fail(output, output_capacity, output_bytes,
                            "grep: pattern too long");
      }
    } else if (file_count < 16U &&
               copy_cstr(files[file_count], sizeof(files[0]), token) == XAIOS_OK) {
      ++file_count;
    } else {
      return command_fail(output, output_capacity, output_bytes,
                          "grep: too many files");
    }
  }
  if (pattern[0] == '\0') {
    return command_fail(output, output_capacity, output_bytes,
                        "grep: missing pattern");
  }
  if (file_count == 0U) {
    return command_fail(output, output_capacity, output_bytes,
                        "grep: missing file");
  }

  uint64_t total_matches = 0U;
  for (uint32_t file = 0U; file < file_count; ++file) {
    char resolved[XAIOS_XBFS_PATH_MAX];
    char *data = (char *)kheap_alloc(XAIOS_XBFS_MAX_FILE_BYTES_V5 + 1U, 16U);
    uint64_t data_size = 0U;
    if (data == 0 ||
        remote_path_resolve(remote_login_cwd(), files[file], resolved,
                            sizeof(resolved)) != XAIOS_OK ||
        xaiboot_fs_read(resolved, data, XAIOS_XBFS_MAX_FILE_BYTES_V5,
                        &data_size) != XAIOS_OK) {
      kheap_free(data);
      return command_fail(output, output_capacity, output_bytes,
                          "grep: cannot read file");
    }
    uint64_t file_matches = 0U;
    uint64_t line_start = 0U;
    uint64_t line_number = 1U;
    while (line_start <= data_size) {
      uint64_t line_end = line_start;
      while (line_end < data_size && data[line_end] != '\n') ++line_end;
      uint64_t line_len = line_end - line_start;
      int matched = fixed != 0
                        ? span_contains(data + line_start, line_len, pattern,
                                        ignore_case)
                        : grep_regex_matches(pattern, data + line_start,
                                             line_len, ignore_case);
      if (invert != 0) matched = !matched;
      if (matched != 0) {
        ++file_matches;
        ++total_matches;
        if (count_only == 0) {
          if ((file_count > 1U || show_filename != 0) && hide_filename == 0) {
            output_append(output, output_capacity, output_bytes, files[file]);
            output_append(output, output_capacity, output_bytes, ":");
          }
          if (line_numbers != 0) {
            output_append_u64(output, output_capacity, output_bytes, line_number);
            output_append(output, output_capacity, output_bytes, ":");
          }
          for (uint64_t byte = line_start; byte < line_end; ++byte) {
            if (output_append_char(output, output_capacity, output_bytes,
                                   data[byte]) != XAIOS_OK) {
              kheap_free(data);
              return XAIOS_ERR_NO_MEMORY;
            }
          }
          if (output_append_char(output, output_capacity, output_bytes, '\n') !=
              XAIOS_OK) {
            kheap_free(data);
            return XAIOS_ERR_NO_MEMORY;
          }
        }
      }
      if (line_end >= data_size) break;
      line_start = line_end + 1U;
      ++line_number;
    }
    if (count_only != 0) {
      if ((file_count > 1U || show_filename != 0) && hide_filename == 0) {
        output_append(output, output_capacity, output_bytes, files[file]);
        output_append(output, output_capacity, output_bytes, ":");
      }
      output_append_u64(output, output_capacity, output_bytes, file_matches);
      output_append(output, output_capacity, output_bytes, "\n");
    }
    kheap_free(data);
  }
  return total_matches == 0U ? XAIOS_ERR_NOT_FOUND : XAIOS_OK;
}

xaios_status_t handle_head_tail(const char *args, int is_head, char *output,
                                     uint64_t output_capacity,
                                     uint64_t *output_bytes) {
  uint64_t arg_index = 0;
  char token[XAIOS_XBFS_PATH_MAX];
  char path_arg[XAIOS_XBFS_PATH_MAX];
  uint64_t lines = 10U;
  char resolved[XAIOS_XBFS_PATH_MAX];
  char data[XAIOS_XBFS_MAX_FILE_BYTES];
  uint64_t data_size = 0;

  if (token_next(args, &arg_index, token, sizeof(token)) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes, "head/tail: missing path");
  }
  if (string_equal(token, "-n") == 1U) {
    uint64_t parsed = 0;
    if (token_next(args, &arg_index, token, sizeof(token)) != XAIOS_OK ||
        parse_decimal_uint(token, &parsed) == 0U || parsed == 0U) {
      return command_fail(output, output_capacity, output_bytes,
                          "head/tail: invalid -n argument");
    }
    lines = parsed;
    if (token_next(args, &arg_index, path_arg, sizeof(path_arg)) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "head/tail: missing path");
    }
  } else if (string_starts_with(token, "-n") == 1U && token[2] != '\0') {
    uint64_t parsed = 0;
    if (parse_decimal_uint(token + 2U, &parsed) == 0U || parsed == 0U) {
      return command_fail(output, output_capacity, output_bytes,
                          "head/tail: invalid -n argument");
    }
    lines = parsed;
    if (token_next(args, &arg_index, path_arg, sizeof(path_arg)) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "head/tail: missing path");
    }
  } else {
    if (copy_cstr(path_arg, sizeof(path_arg), token) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "head/tail: invalid path");
    }
    if (has_more_args(args, arg_index) != 0) {
      return command_fail(output, output_capacity, output_bytes,
                          "head/tail: too many arguments");
    }
  }

  if (has_more_args(args, arg_index) != 0) {
    return command_fail(output, output_capacity, output_bytes,
                        "head/tail: too many arguments");
  }

  if (remote_path_resolve(remote_login_cwd(), path_arg, resolved,
                         sizeof(resolved)) != XAIOS_OK ||
      read_file_lines(resolved, data, sizeof(data), &data_size) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes, "head/tail: cannot open");
  }
  if (data_size >= sizeof(data)) {
    return command_fail(output, output_capacity, output_bytes,
                        "head/tail: file too large");
  }
  data[data_size] = '\0';

  if (is_head == 1) {
    if (data_size == 0U) {
      return XAIOS_OK;
    }
    uint64_t line_count = 0;
    for (uint64_t i = 0; i < data_size; ++i) {
      if (data[i] == '\n') {
        ++line_count;
      }
      if (line_count >= lines && data[i] == '\n') {
        if (output_append_char(output, output_capacity, output_bytes, '\n') !=
            XAIOS_OK) {
          return command_fail(output, output_capacity, output_bytes,
                             "head/tail: output too large");
        }
        break;
      }
      if (output_append_char(output, output_capacity, output_bytes, data[i]) !=
          XAIOS_OK) {
        return command_fail(output, output_capacity, output_bytes,
                            "head/tail: output too large");
      }
    }
    return XAIOS_OK;
  }

  uint64_t lines_seen = 0U;
  uint64_t start = data_size;
  if (data_size == 0U) {
    return XAIOS_OK;
  }
  for (uint64_t i = data_size; i > 0U; --i) {
    if (data[i - 1U] != '\n') {
      continue;
    }
    ++lines_seen;
    if (lines_seen >= lines) {
      start = i;
      break;
    }
  }
  if (lines_seen < lines) {
    start = 0U;
  }
  for (uint64_t i = start; i < data_size; ++i) {
    if (output_append_char(output, output_capacity, output_bytes, data[i]) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "head/tail: output too large");
    }
  }
  return XAIOS_OK;
}

xaios_status_t handle_sed(const char *args, char *output,
                               uint64_t output_capacity,
                               uint64_t *output_bytes) {
  char expr[XAIOS_XBFS_PATH_MAX];
  char path_arg[XAIOS_XBFS_PATH_MAX];
  uint64_t arg_index = 0;
  char resolved[XAIOS_XBFS_PATH_MAX];
  char data[XAIOS_XBFS_MAX_FILE_BYTES];
  uint64_t data_size = 0;
  char result[XAIOS_XBFS_MAX_FILE_BYTES];
  uint64_t result_len = 0;

  if (token_next(args, &arg_index, expr, sizeof(expr)) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "sed: missing expression");
  }
  if (token_next(args, &arg_index, path_arg, sizeof(path_arg)) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "sed: missing file");
  }
  uint64_t expr_len = cstr_len(expr);
  if (expr_len >= 2U &&
      ((expr[0] == '\'' && expr[expr_len - 1U] == '\'') ||
       (expr[0] == '"' && expr[expr_len - 1U] == '"'))) {
    for (uint64_t i = 1U; i + 1U < expr_len; ++i) {
      expr[i - 1U] = expr[i];
    }
    expr_len -= 2U;
    expr[expr_len] = '\0';
  }
  if (expr[0] != 's' || expr[1] != '/') {
    return command_fail(output, output_capacity, output_bytes,
                        "sed: only s/// supported");
  }
  uint64_t slash2 = 0;
  uint64_t slash3 = 0;
  for (uint64_t i = 2; i < expr_len; ++i) {
    if (expr[i] == '/') {
      if (slash2 == 0) {
        slash2 = i;
      } else {
        slash3 = i;
        break;
      }
    }
  }
  if (slash2 == 0) {
    return command_fail(output, output_capacity, output_bytes,
                        "sed: malformed expression");
  }
  char old_pat[128];
  char new_pat[128];
  uint64_t old_len = slash2 - 2U;
  uint64_t new_len =
      (slash3 == 0) ? (expr_len - slash2 - 1U) : (slash3 - slash2 - 1U);
  if (old_len >= sizeof(old_pat) || new_len >= sizeof(new_pat)) {
    return command_fail(output, output_capacity, output_bytes,
                        "sed: pattern too long");
  }
  for (uint64_t i = 0; i < old_len; ++i) {
    old_pat[i] = expr[2U + i];
  }
  old_pat[old_len] = '\0';
  for (uint64_t i = 0; i < new_len; ++i) {
    new_pat[i] = expr[slash2 + 1U + i];
  }
  new_pat[new_len] = '\0';
  int global = 0;
  if (slash3 != 0 && slash3 + 1U < expr_len && expr[slash3 + 1U] == 'g') {
    global = 1;
  }
  if (remote_path_resolve(remote_login_cwd(), path_arg, resolved,
                          sizeof(resolved)) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "sed: cannot open file");
  }
  if (xaiboot_fs_read(resolved, data, sizeof(data), &data_size) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "sed: read error");
  }
  if (data_size >= sizeof(data)) {
    return command_fail(output, output_capacity, output_bytes,
                        "sed: file too large");
  }
  data[data_size] = '\0';
  uint64_t line_start = 0;
  while (line_start <= data_size) {
    uint64_t line_end = line_start;
    while (line_end < data_size && data[line_end] != '\n') {
      ++line_end;
    }
    uint64_t line_len = line_end - line_start;
    uint64_t src = 0;
    while (src <= line_len) {
      int match = 1;
      if (old_len == 0) {
        match = 0;
      }
      for (uint64_t k = 0; match != 0 && k < old_len; ++k) {
        if (src + k >= line_len ||
            data[line_start + src + k] != old_pat[k]) {
          match = 0;
        }
      }
      if (match != 0) {
        for (uint64_t k = 0; k < new_len && result_len + 1U < sizeof(result);
             ++k) {
          result[result_len++] = new_pat[k];
        }
        src += old_len;
        if (global == 0) {
          while (src < line_len && result_len + 1U < sizeof(result)) {
            result[result_len++] = data[line_start + src];
            ++src;
          }
          break;
        }
      } else {
        if (src < line_len && result_len + 1U < sizeof(result)) {
          result[result_len++] = data[line_start + src];
        }
        ++src;
      }
    }
    if (result_len + 1U < sizeof(result)) {
      result[result_len++] = '\n';
    }
    if (line_end >= data_size) {
      break;
    }
    line_start = line_end + 1U;
  }
  result[result_len] = '\0';
  if (xaiboot_fs_write(resolved, result, result_len) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "sed: write error");
  }
  output_append(output, output_capacity, output_bytes, result);
  return XAIOS_OK;
}

#endif /* XAIOS_BOOT_TEST_APPS */
