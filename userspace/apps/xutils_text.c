/*
 * Text applets (cat/head/tail/less/grep/find/write/sed) with the argument
 * tokenizer and the glob matcher they share, split out of xutils.c.
 *
 * xutils.c is compiled once per applet name with -DXAIOS_UTILITY_NAME; this
 * file is compiled with the same flags and linked beside xutils.c,
 * xutils_archive.c and xutils_file.c into every utility ELF.  It reads the
 * shared declarations from xutils_applets.h and the per-process scratch
 * arena and output helpers from xutils_archive.h, all of which stay
 * single-instanced in xutils.c.
 */
#include "xutils_applets.h"

static u64 skip_space(const char *text, u64 cursor) {
  while (text != 0 && (text[cursor] == ' ' || text[cursor] == '\t' ||
                       text[cursor] == '\r' || text[cursor] == '\n')) ++cursor;
  return cursor;
}

int xutils_next_token(const char *text, u64 *cursor, char *token, u64 capacity) {
  u64 used = 0U;
  char quote = '\0';
  u64 at = skip_space(text, *cursor);
  if (text == 0 || text[at] == '\0' || capacity == 0U) return -1;
  while (text[at] != '\0') {
    char value = text[at];
    if (quote == '\0' && (value == ' ' || value == '\t' || value == '\r' ||
                          value == '\n')) break;
    if (value == '\\' && quote != '\'' && text[at + 1U] != '\0') {
      value = text[++at];
    } else if ((value == '\'' || value == '"') &&
               (quote == '\0' || quote == value)) {
      quote = quote == '\0' ? value : '\0';
      ++at;
      continue;
    }
    if (used + 1U >= capacity) return -1;
    token[used++] = value;
    ++at;
  }
  if (quote != '\0') return -1;
  token[used] = '\0';
  *cursor = skip_space(text, at);
  return 0;
}

static int parse_u64(const char *text, u64 *value) {
  u64 result = 0U;
  if (text == 0 || text[0] == '\0') return -1;
  for (u64 i = 0U; text[i] != '\0'; ++i) {
    if (text[i] < '0' || text[i] > '9') return -1;
    u64 digit = (u64)(text[i] - '0');
    if (result > (~0ULL - digit) / 10U) return -1;
    result = result * 10U + digit;
  }
  *value = result;
  return 0;
}

static int glob_match(const char *text, const char *pattern) {
  if (*pattern == '\0') return *text == '\0';
  if (*pattern == '*') {
    while (*pattern == '*') ++pattern;
    if (*pattern == '\0') return 1;
    while (*text != '\0') if (glob_match(text++, pattern)) return 1;
    return 0;
  }
  if (*pattern == '?') return *text != '\0' && glob_match(text + 1U, pattern + 1U);
  return *text == *pattern && glob_match(text + 1U, pattern + 1U);
}

static int print_file(const char *path_arg, int number_lines, int head,
                      u64 line_limit) {
  char path[PATH_MAX];
  u64 size = 0U;
  if (xutils_resolve_path(path_arg, path) != 0 ||
      xutils_read_file(path, xutils_scratch, sizeof(xutils_scratch), &size) != 0) return -1;
  u64 start = 0U;
  u64 end = size;
  if (head != 0) {
    u64 lines = 0U;
    end = 0U;
    while (end < size && lines < line_limit)
      if (xutils_scratch[end++] == '\n') ++lines;
  } else if (head == 0 && line_limit != ~0ULL) {
    u64 lines = 0U;
    start = size;
    while (start > 0U && lines <= line_limit) {
      --start;
      if (xutils_scratch[start] == '\n' && start + 1U < size && ++lines == line_limit) {
        ++start;
        break;
      }
    }
  }
  u64 line = 1U;
  if (!number_lines) return xutils_append_bytes(xutils_scratch + start, end - start);
  u64 cursor = start;
  while (cursor < end) {
    (void)xutils_append_u64(line++); (void)xutils_append("\t");
    while (cursor < end) {
      char value = (char)xutils_scratch[cursor++];
      (void)xutils_append_char(value);
      if (value == '\n') break;
    }
  }
  return 0;
}

int xutils_cmd_cat_like(const char *args, int mode) {
  u64 cursor = 0U;
  char token[PATH_MAX];
  int numbered = 0;
  u64 lines = mode == 0 ? ~0ULL : 10U;
  int count = 0;
  while (xutils_next_token(args, &cursor, token, sizeof(token)) == 0) {
    if (xutils_equal(token, "-n") || xutils_equal(token, "-N")) {
      if (mode == 0) numbered = 1;
      else {
        if (xutils_next_token(args, &cursor, token, sizeof(token)) != 0 ||
            parse_u64(token, &lines) != 0) return xutils_fail("invalid line count");
      }
      continue;
    }
    if (print_file(token, numbered, mode == 1 ? 1 : mode == 2 ? 0 : -1,
                   lines) != 0) return xutils_fail("cannot read file");
    ++count;
  }
  return count ? 0 : xutils_fail("missing file operand");
}

static int fold(char value) {
  return value >= 'A' && value <= 'Z' ? value + ('a' - 'A') : value;
}

static int span_contains(const unsigned char *line, u64 line_size,
                         const char *pattern, int insensitive) {
  u64 pattern_size = xutils_length(pattern);
  if (pattern_size == 0U) return 1;
  for (u64 i = 0U; i + pattern_size <= line_size; ++i) {
    u64 j = 0U;
    while (j < pattern_size) {
      int lhs = line[i + j];
      int rhs = pattern[j];
      if (insensitive) { lhs = fold((char)lhs); rhs = fold((char)rhs); }
      if (lhs != rhs) break;
      ++j;
    }
    if (j == pattern_size) return 1;
  }
  return 0;
}

static int grep_atom_matches(const char *pattern, u64 *atom_size, char value,
                             int insensitive) {
  char expected = pattern[0];
  *atom_size = 1U;
  if (expected == '\\' && pattern[1] != '\0') {
    expected = pattern[1];
    *atom_size = 2U;
  }
  if (expected == '.') return 1;
  if (insensitive) {
    expected = (char)fold(expected);
    value = (char)fold(value);
  }
  return expected == value;
}

static int grep_regex_here(const char *pattern, const unsigned char *text,
                           u64 text_size, int insensitive) {
  if (pattern[0] == '\0') return 1;
  if (pattern[0] == '$' && pattern[1] == '\0') return text_size == 0U;
  u64 atom_size = 0U;
  (void)grep_atom_matches(pattern, &atom_size, '\0', insensitive);
  if (pattern[atom_size] == '*') {
    u64 used = 0U;
    for (;;) {
      if (grep_regex_here(pattern + atom_size + 1U, text + used,
                          text_size - used, insensitive))
        return 1;
      if (used >= text_size ||
          !grep_atom_matches(pattern, &atom_size, (char)text[used],
                             insensitive))
        return 0;
      ++used;
    }
  }
  if (text_size != 0U &&
      grep_atom_matches(pattern, &atom_size, (char)text[0], insensitive))
    return grep_regex_here(pattern + atom_size, text + 1U, text_size - 1U,
                           insensitive);
  return 0;
}

static int grep_regex_matches(const char *pattern, const unsigned char *text,
                              u64 text_size, int insensitive) {
  if (pattern[0] == '^')
    return grep_regex_here(pattern + 1U, text, text_size, insensitive);
  for (u64 start = 0U; start <= text_size; ++start)
    if (grep_regex_here(pattern, text + start, text_size - start, insensitive))
      return 1;
  return 0;
}

static int grep_file(const char *path_arg, const char *pattern, int insensitive,
                     int invert, int numbered, int count_only, int show_name,
                     int fixed, u64 *match_count) {
  char path[PATH_MAX];
  u64 size = 0U;
  if (xutils_resolve_path(path_arg, path) != 0 ||
      xutils_read_file(path, xutils_scratch, sizeof(xutils_scratch), &size) != 0) return -1;
  u64 cursor = 0U;
  u64 line_number = 1U;
  u64 matches = 0U;
  while (cursor < size) {
    u64 start = cursor;
    while (cursor < size && xutils_scratch[cursor] != '\n') ++cursor;
    int match = fixed
                    ? span_contains(xutils_scratch + start, cursor - start, pattern,
                                    insensitive)
                    : grep_regex_matches(pattern, xutils_scratch + start,
                                         cursor - start, insensitive);
    if (invert) match = !match;
    if (match) {
      ++matches;
      if (!count_only) {
        if (show_name) { (void)xutils_append(path_arg); (void)xutils_append(":"); }
        if (numbered) { (void)xutils_append_u64(line_number); (void)xutils_append(":"); }
        (void)xutils_append_bytes(xutils_scratch + start, cursor - start); (void)xutils_append("\n");
      }
    }
    if (cursor < size) ++cursor;
    ++line_number;
  }
  if (count_only) {
    if (show_name) { (void)xutils_append(path_arg); (void)xutils_append(":"); }
    (void)xutils_append_u64(matches); (void)xutils_append("\n");
  }
  *match_count = matches;
  return 0;
}

int xutils_cmd_grep(const char *args) {
  u64 cursor = 0U;
  char token[PATH_MAX];
  char pattern[PATH_MAX] = "";
  char files[16][PATH_MAX];
  u32 file_count = 0U;
  int insensitive = 0, invert = 0, numbered = 0, count_only = 0, fixed = 0;
  int force_name = 0, hide_name = 0;
  while (xutils_next_token(args, &cursor, token, sizeof(token)) == 0) {
    if (pattern[0] == '\0' && token[0] == '-') {
      for (u64 i = 1U; token[i] != '\0'; ++i) {
        if (token[i] == 'i') insensitive = 1;
        else if (token[i] == 'v') invert = 1;
        else if (token[i] == 'n') numbered = 1;
        else if (token[i] == 'c') count_only = 1;
        else if (token[i] == 'H') force_name = 1;
        else if (token[i] == 'h') hide_name = 1;
        else if (token[i] == 'F') fixed = 1;
        else return xutils_fail("unsupported option");
      }
    } else if (pattern[0] == '\0') xutils_copy(pattern, token, sizeof(pattern));
    else if (file_count < 16U) xutils_copy(files[file_count++], token, PATH_MAX);
    else return xutils_fail("too many files");
  }
  if (pattern[0] == '\0') return xutils_fail("missing pattern");
  u64 total_matches = 0U;
  if (file_count == 0U) {
    u64 matches = 0U;
    if (grep_file("/tmp/_pipe_stage", pattern, insensitive, invert, numbered,
                  count_only, 0, fixed, &matches) != 0)
      return xutils_fail("cannot read input");
    total_matches += matches;
  } else for (u32 i = 0U; i < file_count; ++i) {
    u64 matches = 0U;
    if (grep_file(files[i], pattern, insensitive, invert, numbered, count_only,
                  !hide_name && (force_name || file_count > 1U), fixed,
                  &matches) != 0)
      return xutils_fail("cannot read file");
    total_matches += matches;
  }
  return total_matches == 0U ? 1 : 0;
}

static int find_walk(const char *path, const char *display,
                     const char *pattern) {
  char name[PATH_MAX];
  if (xutils_basename_of(path, name) != 0) xutils_copy(name, path, sizeof(name));
  if (pattern == 0 || glob_match(name, pattern)) {
    (void)xutils_append(display); (void)xutils_append("\n");
  }
  xaios_xbfs_stat_user_t stat;
  if (xaios_fs_stat(path, &stat) != 0 || stat.type != XAIOS_FS_TYPE_DIRECTORY)
    return 0;
  char listing[LIST_MAX];
  u64 size = 0U;
  if (xutils_list_dir(path, listing, &size) != 0) return -1;
  u64 cursor = 0U;
  int next;
  while ((next = xutils_each_listing(listing, size, &cursor, name)) > 0) {
    char child[PATH_MAX];
    char child_display[PATH_MAX];
    if (xutils_join_path(path, name, child) != 0 ||
        xutils_join_path(display, name, child_display) != 0 ||
        find_walk(child, child_display, pattern) != 0) return -1;
  }
  return next < 0 ? -1 : 0;
}

int xutils_cmd_find(const char *args) {
  u64 cursor = 0U;
  char path_arg[PATH_MAX] = ".";
  char token[PATH_MAX];
  char pattern[PATH_MAX] = "";
  if (xutils_next_token(args, &cursor, token, sizeof(token)) == 0) {
    if (!xutils_equal(token, "-name")) xutils_copy(path_arg, token, sizeof(path_arg));
    else if (xutils_next_token(args, &cursor, pattern, sizeof(pattern)) != 0)
      return xutils_fail("missing pattern");
  }
  if (xutils_next_token(args, &cursor, token, sizeof(token)) == 0) {
    if (!xutils_equal(token, "-name") ||
        xutils_next_token(args, &cursor, pattern, sizeof(pattern)) != 0)
      return xutils_fail("unsupported expression");
  }
  char path[PATH_MAX];
  if (xutils_resolve_path(path_arg, path) != 0 ||
      find_walk(path, path_arg, pattern[0] == '\0' ? 0 : pattern) != 0)
    return xutils_fail("cannot inspect path");
  return 0;
}

int xutils_cmd_write(const char *args) {
  u64 cursor = 0U;
  char path_arg[PATH_MAX];
  if (xutils_next_token(args, &cursor, path_arg, sizeof(path_arg)) != 0)
    return xutils_fail("missing path");
  char path[PATH_MAX];
  if (xutils_resolve_path(path_arg, path) != 0 || xutils_ensure_parents(path) != 0)
    return xutils_fail("invalid path");
  const char *payload = args + cursor;
  return xutils_write_file(path, payload, xutils_length(payload)) == 0 ? 0 : xutils_fail("write failed");
}

int xutils_cmd_sed(const char *args) {
  u64 cursor = 0U;
  char expression[PATH_MAX];
  char path_arg[PATH_MAX];
  if (xutils_next_token(args, &cursor, expression, sizeof(expression)) != 0 ||
      xutils_next_token(args, &cursor, path_arg, sizeof(path_arg)) != 0)
    return xutils_fail("usage: sed 's/OLD/NEW/[g]' FILE");
  u64 expr_size = xutils_length(expression);
  if (expr_size < 5U || expression[0] != 's') return xutils_fail("unsupported expression");
  char delimiter = expression[1];
  u64 first = 2U;
  u64 middle = first;
  while (middle < expr_size && expression[middle] != delimiter) ++middle;
  u64 last = middle + 1U;
  while (last < expr_size && expression[last] != delimiter) ++last;
  if (middle == first || last >= expr_size) return xutils_fail("invalid expression");
  char old_text[PATH_MAX];
  char new_text[PATH_MAX];
  u64 old_size = middle - first;
  u64 new_size = last - middle - 1U;
  if (old_size + 1U > sizeof(old_text) || new_size + 1U > sizeof(new_text))
    return xutils_fail("expression too long");
  for (u64 i = 0U; i < old_size; ++i) old_text[i] = expression[first + i];
  old_text[old_size] = '\0';
  for (u64 i = 0U; i < new_size; ++i) new_text[i] = expression[middle + 1U + i];
  new_text[new_size] = '\0';
  int global = expression[last + 1U] == 'g';
  char path[PATH_MAX];
  u64 size = 0U;
  if (xutils_resolve_path(path_arg, path) != 0 ||
      xutils_read_file(path, xutils_scratch, sizeof(xutils_scratch), &size) != 0) return xutils_fail("cannot read file");
  u64 out = 0U;
  int replaced_on_line = 0;
  for (u64 i = 0U; i < size;) {
    int match = (!replaced_on_line || global) && i + old_size <= size;
    for (u64 j = 0U; match && j < old_size; ++j)
      if (xutils_scratch[i + j] != (unsigned char)old_text[j]) match = 0;
    if (match) {
      if (out + new_size > sizeof(xutils_aux)) return xutils_fail("result too large");
      for (u64 j = 0U; j < new_size; ++j) xutils_aux[out++] = (unsigned char)new_text[j];
      i += old_size;
      replaced_on_line = 1;
    } else {
      if (out == sizeof(xutils_aux)) return xutils_fail("result too large");
      xutils_aux[out++] = xutils_scratch[i];
      if (xutils_scratch[i++] == '\n') replaced_on_line = 0;
    }
  }
  if (xutils_write_file(path, xutils_aux, out) != 0 || xutils_append_bytes(xutils_aux, out) != 0)
    return xutils_fail("write error");
  return 0;
}
