#include <xaios_user.h>

#ifndef XAIOS_UTILITY_NAME
#define XAIOS_UTILITY_NAME "xutils"
#endif

#define PATH_MAX 256U
#define FILE_MAX 131072U
#define LIST_MAX 16384U
#define OUTPUT_MAX 32768U
#define ENTRY_MAX 128U
#define USTAR_BLOCK 512U

extern int xaios_inflate_raw(const unsigned char *input, u64 input_size,
                             unsigned char *output, u64 output_capacity,
                             u64 *output_size);

typedef struct archive_entry {
  char name[PATH_MAX];
  u32 crc;
  u32 size;
  u32 offset;
  u32 method;
  u32 directory;
} archive_entry_t;

static char g_output[OUTPUT_MAX];
static unsigned char g_data[FILE_MAX];
static unsigned char g_aux[FILE_MAX];
static archive_entry_t g_entries[ENTRY_MAX];
static u64 g_used;
static const char *g_cwd;

static u64 length(const char *text) {
  u64 result = 0U;
  while (text != 0 && text[result] != '\0') ++result;
  return result;
}

static int equal(const char *lhs, const char *rhs) {
  if (lhs == 0 || rhs == 0) return 0;
  while (*lhs != '\0' && *lhs == *rhs) {
    ++lhs;
    ++rhs;
  }
  return *lhs == *rhs;
}

static int starts(const char *text, const char *prefix) {
  if (text == 0 || prefix == 0) return 0;
  while (*prefix != '\0') if (*text++ != *prefix++) return 0;
  return 1;
}

static void copy(char *dst, const char *src, u64 capacity) {
  u64 i = 0U;
  if (capacity == 0U) return;
  while (src != 0 && src[i] != '\0' && i + 1U < capacity) {
    dst[i] = src[i];
    ++i;
  }
  dst[i] = '\0';
}

static int append_bytes(const void *data, u64 size) {
  const char *bytes = (const char *)data;
  if (size > sizeof(g_output) - g_used - 1U) return -1;
  for (u64 i = 0U; i < size; ++i) g_output[g_used++] = bytes[i];
  g_output[g_used] = '\0';
  return 0;
}

static int append(const char *text) { return append_bytes(text, length(text)); }

static int append_char(char value) { return append_bytes(&value, 1U); }

static int append_u64(u64 value) {
  char digits[24];
  u32 count = 0U;
  do {
    digits[count++] = (char)('0' + value % 10U);
    value /= 10U;
  } while (value != 0U);
  while (count != 0U) if (append_char(digits[--count]) != 0) return -1;
  return 0;
}

static int flush_output(void) {
  u64 offset = 0U;
  while (offset < g_used) {
    u64 chunk = g_used - offset;
    if (chunk > 4096U) chunk = 4096U;
    if (xaios_console_write(g_output + offset, chunk) != (int)chunk) return -1;
    offset += chunk;
  }
  return 0;
}

static int fail(const char *message) {
  g_used = 0U;
  g_output[0] = '\0';
  (void)append(XAIOS_UTILITY_NAME);
  (void)append(": ");
  (void)append(message);
  (void)append("\n");
  (void)flush_output();
  return 1;
}

static u64 skip_space(const char *text, u64 cursor) {
  while (text != 0 && (text[cursor] == ' ' || text[cursor] == '\t' ||
                       text[cursor] == '\r' || text[cursor] == '\n')) ++cursor;
  return cursor;
}

static int next_token(const char *text, u64 *cursor, char *token, u64 capacity) {
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

static int sensitive(const char *path) {
  return equal(path, "/state/xaios_host_key") ||
         equal(path, "/etc/xaios_sshd_users") ||
         equal(path, "/etc/xaios_authorized_keys") ||
         starts(path, "/state/control/") || equal(path, "/state/control");
}

static int resolve_path(const char *input, char *output) {
  char source[PATH_MAX];
  u64 source_used = 0U;
  u64 input_at = 0U;
  if (input == 0 || input[0] == '\0') input = ".";
  if (input[0] == '/') {
    if (length(input) + 1U > sizeof(source)) return -1;
    copy(source, input, sizeof(source));
  } else {
    copy(source, g_cwd, sizeof(source));
    source_used = length(source);
    if (source_used > 1U && source[source_used - 1U] != '/')
      source[source_used++] = '/';
    if (length(input) + source_used + 1U > sizeof(source)) return -1;
    copy(source + source_used, input, sizeof(source) - source_used);
  }
  output[0] = '/';
  output[1] = '\0';
  u64 out = 1U;
  while (source[input_at] != '\0') {
    while (source[input_at] == '/') ++input_at;
    if (source[input_at] == '\0') break;
    u64 start = input_at;
    while (source[input_at] != '\0' && source[input_at] != '/') ++input_at;
    u64 span = input_at - start;
    if (span == 1U && source[start] == '.') continue;
    if (span == 2U && source[start] == '.' && source[start + 1U] == '.') {
      if (out > 1U) {
        --out;
        while (out > 1U && output[out - 1U] != '/') --out;
        if (out > 1U) --out;
        output[out] = '\0';
      }
      continue;
    }
    if (out > 1U) output[out++] = '/';
    if (out + span + 1U > PATH_MAX) return -1;
    for (u64 i = 0U; i < span; ++i) output[out++] = source[start + i];
    output[out] = '\0';
  }
  return sensitive(output) ? -1 : 0;
}

static int join_path(const char *base, const char *name, char *output) {
  u64 base_size = length(base);
  u64 name_size = length(name);
  if (base_size + name_size + 2U > PATH_MAX) return -1;
  copy(output, base, PATH_MAX);
  if (base_size != 1U) output[base_size++] = '/';
  copy(output + base_size, name, PATH_MAX - base_size);
  return 0;
}

static int basename_of(const char *path, char *name) {
  u64 end = length(path);
  while (end > 1U && path[end - 1U] == '/') --end;
  u64 start = end;
  while (start > 0U && path[start - 1U] != '/') --start;
  if (end == start || end - start + 1U > PATH_MAX) return -1;
  for (u64 i = start; i < end; ++i) name[i - start] = path[i];
  name[end - start] = '\0';
  return 0;
}

static int read_file(const char *path, unsigned char *buffer, u64 capacity,
                     u64 *size) {
  xaios_mfs_stat_user_t stat;
  if (xaios_fs_stat(path, &stat) != 0 || stat.type != XAIOS_FS_TYPE_FILE ||
      stat.size > capacity)
    return -1;
  int fd = xaios_fs_open(path, XAIOS_MFS_OPEN_READ);
  if (fd < 0) return -1;
  u64 used = 0U;
  while (used < capacity) {
    u64 chunk = capacity - used;
    if (chunk > 65536U) chunk = 65536U;
    int got = xaios_fs_read(fd, buffer + used, chunk);
    if (got < 0) { (void)xaios_fs_close(fd); return -1; }
    if (got == 0) break;
    used += (u64)(u32)got;
  }
  if (xaios_fs_close(fd) != 0) return -1;
  *size = used;
  return used == stat.size ? 0 : -1;
}

static int write_file(const char *path, const void *buffer, u64 size) {
  int fd = xaios_fs_open(path, XAIOS_MFS_OPEN_WRITE | XAIOS_MFS_OPEN_CREATE |
                                   XAIOS_MFS_OPEN_TRUNCATE);
  if (fd < 0) return -1;
  u64 done = 0U;
  while (done < size) {
    u64 chunk = size - done;
    if (chunk > 65536U) chunk = 65536U;
    int wrote = xaios_fs_write(fd, (const unsigned char *)buffer + done, chunk);
    if (wrote <= 0) { (void)xaios_fs_close(fd); return -1; }
    done += (u64)(u32)wrote;
  }
  if (xaios_fs_fsync(fd) != 0 || xaios_fs_close(fd) != 0) return -1;
  return 0;
}

static int list_dir(const char *path, char *listing, u64 *size) {
  return xaios_fs_list(path, listing, LIST_MAX, size) < 0 ? -1 : 0;
}

static int ensure_parents(const char *path) {
  char current[PATH_MAX];
  copy(current, path, sizeof(current));
  for (u64 i = 1U; current[i] != '\0'; ++i) {
    if (current[i] == '/') {
      current[i] = '\0';
      if (xaios_fs_mkdir(current) != 0) {
        xaios_mfs_stat_user_t stat;
        if (xaios_fs_stat(current, &stat) != 0 ||
            stat.type != XAIOS_FS_TYPE_DIRECTORY) return -1;
      }
      current[i] = '/';
    }
  }
  return 0;
}

static int each_listing(const char *listing, u64 size, u64 *cursor,
                        char *name) {
  if (*cursor >= size) return 0;
  u64 start = *cursor;
  while (*cursor < size && listing[*cursor] != '\n') ++(*cursor);
  u64 span = *cursor - start;
  if (*cursor < size) ++(*cursor);
  if (span == 0U || span + 1U > PATH_MAX) return -1;
  for (u64 i = 0U; i < span; ++i) name[i] = listing[start + i];
  name[span] = '\0';
  return 1;
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

static int remove_tree(const char *path) {
  xaios_mfs_stat_user_t stat;
  if (xaios_fs_stat(path, &stat) != 0) return -1;
  if (stat.type == XAIOS_FS_TYPE_FILE) return xaios_fs_delete(path);
  char listing[LIST_MAX];
  u64 size = 0U;
  if (list_dir(path, listing, &size) != 0) return -1;
  u64 cursor = 0U;
  char name[PATH_MAX];
  int next;
  while ((next = each_listing(listing, size, &cursor, name)) > 0) {
    char child[PATH_MAX];
    if (join_path(path, name, child) != 0 || remove_tree(child) != 0) return -1;
  }
  return next < 0 ? -1 : xaios_fs_delete(path);
}

static int copy_tree(const char *source, const char *destination, int recursive) {
  xaios_mfs_stat_user_t stat;
  if (xaios_fs_stat(source, &stat) != 0) return -1;
  if (stat.type == XAIOS_FS_TYPE_FILE) {
    u64 size = 0U;
    if (read_file(source, g_data, sizeof(g_data), &size) != 0 ||
        ensure_parents(destination) != 0) return -1;
    return write_file(destination, g_data, size);
  }
  if (!recursive || stat.type != XAIOS_FS_TYPE_DIRECTORY) return -1;
  if (xaios_fs_mkdir(destination) != 0) {
    xaios_mfs_stat_user_t dst;
    if (xaios_fs_stat(destination, &dst) != 0 ||
        dst.type != XAIOS_FS_TYPE_DIRECTORY) return -1;
  }
  char listing[LIST_MAX];
  u64 size = 0U;
  if (list_dir(source, listing, &size) != 0) return -1;
  u64 cursor = 0U;
  char name[PATH_MAX];
  int next;
  while ((next = each_listing(listing, size, &cursor, name)) > 0) {
    char child_source[PATH_MAX];
    char child_destination[PATH_MAX];
    if (join_path(source, name, child_source) != 0 ||
        join_path(destination, name, child_destination) != 0 ||
        copy_tree(child_source, child_destination, 1) != 0) return -1;
  }
  return next < 0 ? -1 : 0;
}

static int cmd_ls(const char *args) {
  int show_all = 0;
  int long_form = 0;
  char operand[PATH_MAX] = ".";
  char token[PATH_MAX];
  u64 cursor = 0U;
  int operands = 0;
  while (next_token(args, &cursor, token, sizeof(token)) == 0) {
    if (token[0] == '-') {
      for (u64 i = 1U; token[i] != '\0'; ++i) {
        if (token[i] == 'a') show_all = 1;
        else if (token[i] == 'l') long_form = 1;
        else return fail("invalid option");
      }
    } else {
      if (operands++) return fail("too many arguments");
      copy(operand, token, sizeof(operand));
    }
  }
  char path[PATH_MAX];
  if (resolve_path(operand, path) != 0) return fail("invalid path");
  xaios_mfs_stat_user_t stat;
  if (xaios_fs_stat(path, &stat) == 0 && stat.type == XAIOS_FS_TYPE_FILE) {
    if (long_form) { (void)append("- "); (void)append_u64(stat.size); (void)append(" "); }
    (void)append(operand); (void)append("\n");
    return 0;
  }
  char listing[LIST_MAX];
  u64 size = 0U;
  if (list_dir(path, listing, &size) != 0) return fail("not found");
  cursor = 0U;
  char name[PATH_MAX];
  int next;
  while ((next = each_listing(listing, size, &cursor, name)) > 0) {
    if (!show_all && name[0] == '.') continue;
    char child[PATH_MAX];
    if (join_path(path, name, child) != 0 || xaios_fs_stat(child, &stat) != 0)
      continue;
    if (long_form) {
      (void)append(stat.type == XAIOS_FS_TYPE_DIRECTORY ? "d " : "- ");
      (void)append_u64(stat.size); (void)append(" ");
    }
    (void)append(name); (void)append("\n");
  }
  return next < 0 ? fail("directory listing failed") : 0;
}

static int cmd_mkdir(const char *args) {
  u64 cursor = 0U;
  char token[PATH_MAX];
  int parents = 0;
  int made = 0;
  while (next_token(args, &cursor, token, sizeof(token)) == 0) {
    if (equal(token, "-p")) { parents = 1; continue; }
    if (token[0] == '-') return fail("invalid option");
    char path[PATH_MAX];
    if (resolve_path(token, path) != 0 ||
        (parents && ensure_parents(path) != 0) || xaios_fs_mkdir(path) != 0) {
      xaios_mfs_stat_user_t stat;
      if (!parents || xaios_fs_stat(path, &stat) != 0 ||
          stat.type != XAIOS_FS_TYPE_DIRECTORY) return fail("cannot create directory");
    }
    made = 1;
  }
  return made ? 0 : fail("missing operand");
}

static int cmd_touch(const char *args) {
  u64 cursor = 0U;
  char token[PATH_MAX];
  int count = 0;
  while (next_token(args, &cursor, token, sizeof(token)) == 0) {
    char path[PATH_MAX];
    if (resolve_path(token, path) != 0 || ensure_parents(path) != 0 ||
        write_file(path, "", 0U) != 0) return fail("cannot touch file");
    ++count;
  }
  return count ? 0 : fail("missing file operand");
}

static int cmd_cp(const char *args) {
  char operands[16][PATH_MAX];
  u32 count = 0U;
  int recursive = 0;
  u64 cursor = 0U;
  char token[PATH_MAX];
  while (next_token(args, &cursor, token, sizeof(token)) == 0) {
    if (equal(token, "-R") || equal(token, "-r")) { recursive = 1; continue; }
    if (token[0] == '-') return fail("unsupported option");
    if (count == 16U) return fail("too many operands");
    copy(operands[count++], token, PATH_MAX);
  }
  if (count < 2U) return fail("missing file operand");
  char destination[PATH_MAX];
  if (resolve_path(operands[count - 1U], destination) != 0)
    return fail("invalid destination");
  xaios_mfs_stat_user_t dst_stat;
  int dst_dir = xaios_fs_stat(destination, &dst_stat) == 0 &&
                dst_stat.type == XAIOS_FS_TYPE_DIRECTORY;
  if (count > 2U && !dst_dir) return fail("destination is not a directory");
  for (u32 i = 0U; i + 1U < count; ++i) {
    char source[PATH_MAX];
    char target[PATH_MAX];
    if (resolve_path(operands[i], source) != 0) return fail("invalid source");
    copy(target, destination, sizeof(target));
    if (dst_dir) {
      char name[PATH_MAX];
      if (basename_of(source, name) != 0 || join_path(destination, name, target) != 0)
        return fail("invalid destination");
    }
    if (copy_tree(source, target, recursive) != 0) return fail("copy failed");
  }
  return 0;
}

static int cmd_mv(const char *args) {
  u64 cursor = 0U;
  char source_arg[PATH_MAX];
  char destination_arg[PATH_MAX];
  char extra[2];
  if (next_token(args, &cursor, source_arg, sizeof(source_arg)) != 0 ||
      next_token(args, &cursor, destination_arg, sizeof(destination_arg)) != 0 ||
      next_token(args, &cursor, extra, sizeof(extra)) == 0)
    return fail("usage: mv SOURCE DEST");
  char source[PATH_MAX];
  char destination[PATH_MAX];
  if (resolve_path(source_arg, source) != 0 ||
      resolve_path(destination_arg, destination) != 0 ||
      ensure_parents(destination) != 0) return fail("invalid path");
  xaios_mfs_stat_user_t stat;
  if (xaios_fs_stat(destination, &stat) == 0 &&
      stat.type == XAIOS_FS_TYPE_DIRECTORY) {
    char name[PATH_MAX];
    char nested[PATH_MAX];
    if (basename_of(source, name) != 0 || join_path(destination, name, nested) != 0)
      return fail("invalid destination");
    copy(destination, nested, sizeof(destination));
  }
  return xaios_fs_rename(source, destination) == 0 ? 0 : fail("rename failed");
}

static int cmd_rm(const char *args, int directories_only) {
  u64 cursor = 0U;
  char token[PATH_MAX];
  int recursive = 0;
  int force = 0;
  int count = 0;
  while (next_token(args, &cursor, token, sizeof(token)) == 0) {
    if (!directories_only && token[0] == '-') {
      for (u64 i = 1U; token[i] != '\0'; ++i) {
        if (token[i] == 'r' || token[i] == 'R') recursive = 1;
        else if (token[i] == 'f') force = 1;
        else return fail("unsupported option");
      }
      continue;
    }
    char path[PATH_MAX];
    xaios_mfs_stat_user_t stat;
    if (resolve_path(token, path) != 0 || equal(path, "/")) return fail("invalid path");
    if (xaios_fs_stat(path, &stat) != 0) {
      if (!force) return fail("not found");
    } else if ((directories_only && stat.type != XAIOS_FS_TYPE_DIRECTORY) ||
               (stat.type == XAIOS_FS_TYPE_DIRECTORY && !recursive && !directories_only)) {
      return fail("is a directory");
    } else if ((recursive ? remove_tree(path) : xaios_fs_delete(path)) != 0) {
      return fail(directories_only ? "directory not empty" : "remove failed");
    }
    ++count;
  }
  return count ? 0 : fail("missing operand");
}

static int cmd_stat(const char *args) {
  u64 cursor = 0U;
  char token[PATH_MAX];
  if (next_token(args, &cursor, token, sizeof(token)) != 0)
    return fail("missing operand");
  do {
    char path[PATH_MAX];
    xaios_mfs_stat_user_t stat;
    if (resolve_path(token, path) != 0 || xaios_fs_stat(path, &stat) != 0)
      return fail("not found");
    (void)append("File: "); (void)append(path);
    (void)append("\nType: ");
    (void)append(stat.type == XAIOS_FS_TYPE_DIRECTORY ? "directory" : "file");
    (void)append("\nSize: "); (void)append_u64(stat.size);
    (void)append("\nBlocks: "); (void)append_u64(stat.block_count);
    (void)append("\nGeneration: "); (void)append_u64(stat.generation);
    (void)append("\nHash: "); (void)append_u64(stat.content_hash);
    (void)append("\n");
  } while (next_token(args, &cursor, token, sizeof(token)) == 0);
  return 0;
}

static int print_file(const char *path_arg, int number_lines, int head,
                      u64 line_limit) {
  char path[PATH_MAX];
  u64 size = 0U;
  if (resolve_path(path_arg, path) != 0 ||
      read_file(path, g_data, sizeof(g_data), &size) != 0) return -1;
  u64 start = 0U;
  u64 end = size;
  if (head != 0) {
    u64 lines = 0U;
    end = 0U;
    while (end < size && lines < line_limit)
      if (g_data[end++] == '\n') ++lines;
  } else if (head == 0 && line_limit != ~0ULL) {
    u64 lines = 0U;
    start = size;
    while (start > 0U && lines <= line_limit) {
      --start;
      if (g_data[start] == '\n' && start + 1U < size && ++lines == line_limit) {
        ++start;
        break;
      }
    }
  }
  u64 line = 1U;
  if (!number_lines) return append_bytes(g_data + start, end - start);
  u64 cursor = start;
  while (cursor < end) {
    (void)append_u64(line++); (void)append("\t");
    while (cursor < end) {
      char value = (char)g_data[cursor++];
      (void)append_char(value);
      if (value == '\n') break;
    }
  }
  return 0;
}

static int cmd_cat_like(const char *args, int mode) {
  u64 cursor = 0U;
  char token[PATH_MAX];
  int numbered = 0;
  u64 lines = mode == 0 ? ~0ULL : 10U;
  int count = 0;
  while (next_token(args, &cursor, token, sizeof(token)) == 0) {
    if (equal(token, "-n") || equal(token, "-N")) {
      if (mode == 0) numbered = 1;
      else {
        if (next_token(args, &cursor, token, sizeof(token)) != 0 ||
            parse_u64(token, &lines) != 0) return fail("invalid line count");
      }
      continue;
    }
    if (print_file(token, numbered, mode == 1 ? 1 : mode == 2 ? 0 : -1,
                   lines) != 0) return fail("cannot read file");
    ++count;
  }
  return count ? 0 : fail("missing file operand");
}

static int fold(char value) {
  return value >= 'A' && value <= 'Z' ? value + ('a' - 'A') : value;
}

static int span_contains(const unsigned char *line, u64 line_size,
                         const char *pattern, int insensitive) {
  u64 pattern_size = length(pattern);
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
  if (resolve_path(path_arg, path) != 0 ||
      read_file(path, g_data, sizeof(g_data), &size) != 0) return -1;
  u64 cursor = 0U;
  u64 line_number = 1U;
  u64 matches = 0U;
  while (cursor < size) {
    u64 start = cursor;
    while (cursor < size && g_data[cursor] != '\n') ++cursor;
    int match = fixed
                    ? span_contains(g_data + start, cursor - start, pattern,
                                    insensitive)
                    : grep_regex_matches(pattern, g_data + start,
                                         cursor - start, insensitive);
    if (invert) match = !match;
    if (match) {
      ++matches;
      if (!count_only) {
        if (show_name) { (void)append(path_arg); (void)append(":"); }
        if (numbered) { (void)append_u64(line_number); (void)append(":"); }
        (void)append_bytes(g_data + start, cursor - start); (void)append("\n");
      }
    }
    if (cursor < size) ++cursor;
    ++line_number;
  }
  if (count_only) {
    if (show_name) { (void)append(path_arg); (void)append(":"); }
    (void)append_u64(matches); (void)append("\n");
  }
  *match_count = matches;
  return 0;
}

static int cmd_grep(const char *args) {
  u64 cursor = 0U;
  char token[PATH_MAX];
  char pattern[PATH_MAX] = "";
  char files[16][PATH_MAX];
  u32 file_count = 0U;
  int insensitive = 0, invert = 0, numbered = 0, count_only = 0, fixed = 0;
  int force_name = 0, hide_name = 0;
  while (next_token(args, &cursor, token, sizeof(token)) == 0) {
    if (pattern[0] == '\0' && token[0] == '-') {
      for (u64 i = 1U; token[i] != '\0'; ++i) {
        if (token[i] == 'i') insensitive = 1;
        else if (token[i] == 'v') invert = 1;
        else if (token[i] == 'n') numbered = 1;
        else if (token[i] == 'c') count_only = 1;
        else if (token[i] == 'H') force_name = 1;
        else if (token[i] == 'h') hide_name = 1;
        else if (token[i] == 'F') fixed = 1;
        else return fail("unsupported option");
      }
    } else if (pattern[0] == '\0') copy(pattern, token, sizeof(pattern));
    else if (file_count < 16U) copy(files[file_count++], token, PATH_MAX);
    else return fail("too many files");
  }
  if (pattern[0] == '\0') return fail("missing pattern");
  u64 total_matches = 0U;
  if (file_count == 0U) {
    u64 matches = 0U;
    if (grep_file("/tmp/_pipe_stage", pattern, insensitive, invert, numbered,
                  count_only, 0, fixed, &matches) != 0)
      return fail("cannot read input");
    total_matches += matches;
  } else for (u32 i = 0U; i < file_count; ++i) {
    u64 matches = 0U;
    if (grep_file(files[i], pattern, insensitive, invert, numbered, count_only,
                  !hide_name && (force_name || file_count > 1U), fixed,
                  &matches) != 0)
      return fail("cannot read file");
    total_matches += matches;
  }
  return total_matches == 0U ? 1 : 0;
}

static int find_walk(const char *path, const char *display,
                     const char *pattern) {
  char name[PATH_MAX];
  if (basename_of(path, name) != 0) copy(name, path, sizeof(name));
  if (pattern == 0 || glob_match(name, pattern)) {
    (void)append(display); (void)append("\n");
  }
  xaios_mfs_stat_user_t stat;
  if (xaios_fs_stat(path, &stat) != 0 || stat.type != XAIOS_FS_TYPE_DIRECTORY)
    return 0;
  char listing[LIST_MAX];
  u64 size = 0U;
  if (list_dir(path, listing, &size) != 0) return -1;
  u64 cursor = 0U;
  int next;
  while ((next = each_listing(listing, size, &cursor, name)) > 0) {
    char child[PATH_MAX];
    char child_display[PATH_MAX];
    if (join_path(path, name, child) != 0 ||
        join_path(display, name, child_display) != 0 ||
        find_walk(child, child_display, pattern) != 0) return -1;
  }
  return next < 0 ? -1 : 0;
}

static int cmd_find(const char *args) {
  u64 cursor = 0U;
  char path_arg[PATH_MAX] = ".";
  char token[PATH_MAX];
  char pattern[PATH_MAX] = "";
  if (next_token(args, &cursor, token, sizeof(token)) == 0) {
    if (!equal(token, "-name")) copy(path_arg, token, sizeof(path_arg));
    else if (next_token(args, &cursor, pattern, sizeof(pattern)) != 0)
      return fail("missing pattern");
  }
  if (next_token(args, &cursor, token, sizeof(token)) == 0) {
    if (!equal(token, "-name") ||
        next_token(args, &cursor, pattern, sizeof(pattern)) != 0)
      return fail("unsupported expression");
  }
  char path[PATH_MAX];
  if (resolve_path(path_arg, path) != 0 ||
      find_walk(path, path_arg, pattern[0] == '\0' ? 0 : pattern) != 0)
    return fail("cannot inspect path");
  return 0;
}

static int cmd_write(const char *args) {
  u64 cursor = 0U;
  char path_arg[PATH_MAX];
  if (next_token(args, &cursor, path_arg, sizeof(path_arg)) != 0)
    return fail("missing path");
  char path[PATH_MAX];
  if (resolve_path(path_arg, path) != 0 || ensure_parents(path) != 0)
    return fail("invalid path");
  const char *payload = args + cursor;
  return write_file(path, payload, length(payload)) == 0 ? 0 : fail("write failed");
}

static int cmd_sed(const char *args) {
  u64 cursor = 0U;
  char expression[PATH_MAX];
  char path_arg[PATH_MAX];
  if (next_token(args, &cursor, expression, sizeof(expression)) != 0 ||
      next_token(args, &cursor, path_arg, sizeof(path_arg)) != 0)
    return fail("usage: sed 's/OLD/NEW/[g]' FILE");
  u64 expr_size = length(expression);
  if (expr_size < 5U || expression[0] != 's') return fail("unsupported expression");
  char delimiter = expression[1];
  u64 first = 2U;
  u64 middle = first;
  while (middle < expr_size && expression[middle] != delimiter) ++middle;
  u64 last = middle + 1U;
  while (last < expr_size && expression[last] != delimiter) ++last;
  if (middle == first || last >= expr_size) return fail("invalid expression");
  char old_text[PATH_MAX];
  char new_text[PATH_MAX];
  u64 old_size = middle - first;
  u64 new_size = last - middle - 1U;
  if (old_size + 1U > sizeof(old_text) || new_size + 1U > sizeof(new_text))
    return fail("expression too long");
  for (u64 i = 0U; i < old_size; ++i) old_text[i] = expression[first + i];
  old_text[old_size] = '\0';
  for (u64 i = 0U; i < new_size; ++i) new_text[i] = expression[middle + 1U + i];
  new_text[new_size] = '\0';
  int global = expression[last + 1U] == 'g';
  char path[PATH_MAX];
  u64 size = 0U;
  if (resolve_path(path_arg, path) != 0 ||
      read_file(path, g_data, sizeof(g_data), &size) != 0) return fail("cannot read file");
  u64 out = 0U;
  int replaced_on_line = 0;
  for (u64 i = 0U; i < size;) {
    int match = (!replaced_on_line || global) && i + old_size <= size;
    for (u64 j = 0U; match && j < old_size; ++j)
      if (g_data[i + j] != (unsigned char)old_text[j]) match = 0;
    if (match) {
      if (out + new_size > sizeof(g_aux)) return fail("result too large");
      for (u64 j = 0U; j < new_size; ++j) g_aux[out++] = (unsigned char)new_text[j];
      i += old_size;
      replaced_on_line = 1;
    } else {
      if (out == sizeof(g_aux)) return fail("result too large");
      g_aux[out++] = g_data[i];
      if (g_data[i++] == '\n') replaced_on_line = 0;
    }
  }
  if (write_file(path, g_aux, out) != 0 || append_bytes(g_aux, out) != 0)
    return fail("write error");
  return 0;
}

static u32 crc32(const void *data, u64 size) {
  const unsigned char *bytes = (const unsigned char *)data;
  u32 crc = 0xffffffffU;
  for (u64 i = 0U; i < size; ++i) {
    crc ^= bytes[i];
    for (u32 bit = 0U; bit < 8U; ++bit)
      crc = (crc >> 1U) ^ (0xedb88320U & (u32)(0U - (crc & 1U)));
  }
  return crc ^ 0xffffffffU;
}

static void put_le16(unsigned char *p, u32 value) {
  p[0] = (unsigned char)value; p[1] = (unsigned char)(value >> 8U);
}
static void put_le32(unsigned char *p, u32 value) {
  p[0] = (unsigned char)value; p[1] = (unsigned char)(value >> 8U);
  p[2] = (unsigned char)(value >> 16U); p[3] = (unsigned char)(value >> 24U);
}
static u32 get_le16(const unsigned char *p) { return (u32)p[0] | (u32)p[1] << 8U; }
static u32 get_le32(const unsigned char *p) {
  return (u32)p[0] | (u32)p[1] << 8U | (u32)p[2] << 16U | (u32)p[3] << 24U;
}

static int archive_safe(const char *name) {
  if (name == 0 || name[0] == '\0' || name[0] == '/' || name[0] == '\\')
    return 0;
  for (u64 i = 0U; name[i] != '\0'; ++i) {
    if (name[i] == '\\' || name[i] == ':') return 0;
    if ((i == 0U || name[i - 1U] == '/') && name[i] == '.' &&
        name[i + 1U] == '.' && (name[i + 2U] == '/' || name[i + 2U] == '\0'))
      return 0;
  }
  return 1;
}

static int octal_put(char *field, u64 width, u64 value) {
  for (u64 i = 0U; i < width; ++i) field[i] = '0';
  field[width - 1U] = '\0';
  u64 cursor = width - 1U;
  do {
    if (cursor == 0U) return -1;
    field[--cursor] = (char)('0' + (value & 7U));
    value >>= 3U;
  } while (value != 0U);
  return 0;
}

static int octal_get(const char *field, u64 width, u64 *value) {
  u64 result = 0U;
  for (u64 i = 0U; i < width; ++i) {
    if (field[i] == '\0' || field[i] == ' ') break;
    if (field[i] < '0' || field[i] > '7') return -1;
    result = result * 8U + (u64)(field[i] - '0');
  }
  *value = result;
  return 0;
}

static int tar_add(const char *source, const char *name, u64 *used) {
  xaios_mfs_stat_user_t stat;
  if (xaios_fs_stat(source, &stat) != 0 || length(name) > 99U ||
      *used + USTAR_BLOCK > sizeof(g_data)) return -1;
  unsigned char *header = g_data + *used;
  xaios_memzero(header, USTAR_BLOCK);
  copy((char *)header, name, 100U);
  (void)octal_put((char *)header + 100U, 8U, stat.type == XAIOS_FS_TYPE_DIRECTORY ? 0755U : 0644U);
  (void)octal_put((char *)header + 108U, 8U, 0U);
  (void)octal_put((char *)header + 116U, 8U, 0U);
  (void)octal_put((char *)header + 124U, 12U, stat.type == XAIOS_FS_TYPE_FILE ? stat.size : 0U);
  (void)octal_put((char *)header + 136U, 12U, 0U);
  for (u64 i = 148U; i < 156U; ++i) header[i] = ' ';
  header[156] = stat.type == XAIOS_FS_TYPE_DIRECTORY ? '5' : '0';
  copy((char *)header + 257U, "ustar", 6U);
  copy((char *)header + 263U, "00", 3U);
  u64 sum = 0U;
  for (u64 i = 0U; i < USTAR_BLOCK; ++i) sum += header[i];
  (void)octal_put((char *)header + 148U, 8U, sum);
  *used += USTAR_BLOCK;
  if (stat.type == XAIOS_FS_TYPE_FILE) {
    u64 got = 0U;
    if (read_file(source, g_data + *used, sizeof(g_data) - *used, &got) != 0 ||
        got != stat.size) return -1;
    *used += (got + USTAR_BLOCK - 1U) & ~(USTAR_BLOCK - 1U);
    return *used <= sizeof(g_data) ? 0 : -1;
  }
  char listing[LIST_MAX];
  u64 listing_size = 0U;
  if (list_dir(source, listing, &listing_size) != 0) return -1;
  u64 cursor = 0U;
  char child_name[PATH_MAX];
  int next;
  while ((next = each_listing(listing, listing_size, &cursor, child_name)) > 0) {
    char child_source[PATH_MAX];
    char child_archive[PATH_MAX];
    if (join_path(source, child_name, child_source) != 0 ||
        join_path(name, child_name, child_archive) != 0 ||
        tar_add(child_source, child_archive, used) != 0) return -1;
  }
  return next < 0 ? -1 : 0;
}

static int tar_header_path(const unsigned char *header, char *path) {
  u64 name_size = 0U;
  u64 prefix_size = 0U;
  while (name_size < 100U && header[name_size] != 0U) ++name_size;
  while (prefix_size < 155U && header[345U + prefix_size] != 0U) ++prefix_size;
  if (name_size == 0U || prefix_size + (prefix_size != 0U ? 1U : 0U) +
                              name_size + 1U > PATH_MAX)
    return -1;
  u64 used = 0U;
  for (u64 i = 0U; i < prefix_size; ++i) path[used++] = (char)header[345U + i];
  if (prefix_size != 0U) path[used++] = '/';
  for (u64 i = 0U; i < name_size; ++i) path[used++] = (char)header[i];
  path[used] = '\0';
  return 0;
}

static int pax_path(const unsigned char *data, u64 size, char *path) {
  u64 cursor = 0U;
  while (cursor < size) {
    u64 record_start = cursor;
    u64 record_size = 0U;
    u64 digits = 0U;
    while (cursor < size && data[cursor] >= '0' && data[cursor] <= '9') {
      if (record_size > (~0ULL - 9U) / 10U) return -1;
      record_size = record_size * 10U + (u64)(data[cursor++] - '0');
      ++digits;
    }
    if (digits == 0U || cursor >= size || data[cursor] != ' ' ||
        record_size <= cursor - record_start + 1U ||
        record_size > size - record_start)
      return -1;
    u64 value_start = ++cursor;
    u64 record_end = record_start + record_size;
    if (record_end == 0U || data[record_end - 1U] != '\n') return -1;
    if (record_end - 1U - value_start >= 5U &&
        data[value_start] == 'p' && data[value_start + 1U] == 'a' &&
        data[value_start + 2U] == 't' && data[value_start + 3U] == 'h' &&
        data[value_start + 4U] == '=') {
      u64 path_size = record_end - 1U - value_start - 5U;
      if (path_size == 0U || path_size + 1U > PATH_MAX) return -1;
      for (u64 i = 0U; i < path_size; ++i)
        path[i] = (char)data[value_start + 5U + i];
      path[path_size] = '\0';
    }
    cursor = record_end;
  }
  return 0;
}

static int gzip_decode(const unsigned char *input, u64 input_size,
                       unsigned char *output, u64 output_capacity,
                       u64 *output_size) {
  if (input_size < 18U || input[0] != 0x1fU || input[1] != 0x8bU ||
      input[2] != 8U || (input[3] & 0xe0U) != 0U)
    return -1;
  u32 flags = input[3];
  u64 cursor = 10U;
  if ((flags & 4U) != 0U) {
    if (input_size - cursor < 2U) return -1;
    u64 extra = get_le16(input + cursor);
    cursor += 2U;
    if (extra > input_size - cursor) return -1;
    cursor += extra;
  }
  if ((flags & 8U) != 0U) {
    while (cursor < input_size && input[cursor] != 0U) ++cursor;
    if (cursor >= input_size) return -1;
    ++cursor;
  }
  if ((flags & 16U) != 0U) {
    while (cursor < input_size && input[cursor] != 0U) ++cursor;
    if (cursor >= input_size) return -1;
    ++cursor;
  }
  if ((flags & 2U) != 0U) {
    if (input_size - cursor < 2U ||
        (crc32(input, cursor) & 0xffffU) != get_le16(input + cursor))
      return -1;
    cursor += 2U;
  }
  if (cursor > input_size - 8U) return -1;
  u32 expected_crc = get_le32(input + input_size - 8U);
  u32 expected_size = get_le32(input + input_size - 4U);
  if (expected_size > output_capacity ||
      xaios_inflate_raw(input + cursor, input_size - cursor - 8U, output,
                        output_capacity, output_size) != 0 ||
      *output_size != expected_size || crc32(output, *output_size) != expected_crc)
    return -1;
  return 0;
}

static int cmd_tar(const char *args) {
  u64 cursor = 0U;
  char mode[16];
  char archive_arg[PATH_MAX];
  if (next_token(args, &cursor, mode, sizeof(mode)) != 0 ||
      next_token(args, &cursor, archive_arg, sizeof(archive_arg)) != 0)
    return fail("usage: tar -cf|-tf|-xf ARCHIVE [PATH...]");
  int create = starts(mode, "-c");
  int list = starts(mode, "-t");
  int extract = starts(mode, "-x");
  int verbose = mode[length(mode) - 1U] == 'v' || mode[2] == 'v';
  if (!create && !list && !extract) return fail("unsupported mode");
  char archive_path[PATH_MAX];
  if (resolve_path(archive_arg, archive_path) != 0) return fail("invalid archive");
  if (create) {
    u64 used = 0U;
    char source_arg[PATH_MAX];
    int count = 0;
    while (next_token(args, &cursor, source_arg, sizeof(source_arg)) == 0) {
      char source[PATH_MAX];
      char name[PATH_MAX];
      if (resolve_path(source_arg, source) != 0 || basename_of(source, name) != 0 ||
          tar_add(source, name, &used) != 0) return fail("cannot create archive");
      if (verbose) { (void)append(name); (void)append("\n"); }
      ++count;
    }
    if (!count || used + 1024U > sizeof(g_data)) return fail("missing files");
    xaios_memzero(g_data + used, 1024U); used += 1024U;
    return write_file(archive_path, g_data, used) == 0 ? 0 : fail("write failed");
  }
  u64 size = 0U;
  if (read_file(archive_path, g_data, sizeof(g_data), &size) != 0)
    return fail("cannot read archive");
  if (size >= 2U && g_data[0] == 0x1fU && g_data[1] == 0x8bU) {
    u64 decoded_size = 0U;
    if (gzip_decode(g_data, size, g_aux, sizeof(g_aux), &decoded_size) != 0)
      return fail("invalid gzip archive");
    xaios_memcpy(g_data, g_aux, decoded_size);
    size = decoded_size;
  }
  char destination[PATH_MAX];
  copy(destination, g_cwd, sizeof(destination));
  char token[PATH_MAX];
  while (next_token(args, &cursor, token, sizeof(token)) == 0) {
    if (equal(token, "-C") && next_token(args, &cursor, token, sizeof(token)) == 0) {
      if (resolve_path(token, destination) != 0) return fail("invalid destination");
    } else return fail("unsupported option");
  }
  char extended_path[PATH_MAX];
  extended_path[0] = '\0';
  int saw_entry = 0;
  int saw_terminator = 0;
  for (u64 at = 0U; at + USTAR_BLOCK <= size;) {
    int zero = 1;
    for (u64 i = 0U; i < USTAR_BLOCK; ++i) if (g_data[at + i] != 0U) zero = 0;
    if (zero) {
      saw_terminator = 1;
      break;
    }
    saw_entry = 1;
    const unsigned char *header = g_data + at;
    u64 file_size = 0U;
    u64 stored_checksum = 0U;
    if (octal_get((const char *)header + 124U, 12U, &file_size) != 0 ||
        octal_get((const char *)header + 148U, 8U, &stored_checksum) != 0 ||
        file_size > size - at - USTAR_BLOCK) return fail("invalid archive");
    u64 checksum = 0U;
    for (u64 i = 0U; i < USTAR_BLOCK; ++i)
      checksum += i >= 148U && i < 156U ? (u64)' ' : header[i];
    if (checksum != stored_checksum || file_size > ~0ULL - (USTAR_BLOCK - 1U))
      return fail("invalid archive");
    u64 padded = (file_size + USTAR_BLOCK - 1U) & ~(USTAR_BLOCK - 1U);
    if (padded > size - at - USTAR_BLOCK) return fail("invalid archive");
    char type = header[156U] == 0U ? '0' : (char)header[156U];
    const unsigned char *payload = header + USTAR_BLOCK;
    if (type == 'x' || type == 'g') {
      if (type == 'x' && pax_path(payload, file_size, extended_path) != 0)
        return fail("invalid PAX header");
      at += USTAR_BLOCK + padded;
      continue;
    }
    if (type == 'L') {
      u64 path_size = 0U;
      while (path_size < file_size && payload[path_size] != 0U &&
             payload[path_size] != '\n')
        ++path_size;
      if (path_size == 0U || path_size + 1U > sizeof(extended_path))
        return fail("invalid GNU long name");
      for (u64 i = 0U; i < path_size; ++i)
        extended_path[i] = (char)payload[i];
      extended_path[path_size] = '\0';
      at += USTAR_BLOCK + padded;
      continue;
    }
    char name[PATH_MAX];
    if (extended_path[0] != '\0') {
      copy(name, extended_path, sizeof(name));
      extended_path[0] = '\0';
    } else if (tar_header_path(header, name) != 0) {
      return fail("invalid archive path");
    }
    if (!archive_safe(name)) return fail("unsafe path");
    if (list) { (void)append(name); (void)append("\n"); }
    if (extract) {
      char target[PATH_MAX];
      if (join_path(destination, name, target) != 0 || ensure_parents(target) != 0)
        return fail("unsafe path");
      if (type == '5') {
        if (xaios_fs_mkdir(target) != 0) {
          xaios_mfs_stat_user_t stat;
          if (xaios_fs_stat(target, &stat) != 0) return fail("mkdir failed");
        }
      } else if (type == '0') {
        if (write_file(target, payload, file_size) != 0)
          return fail("extract failed");
      } else return fail("unsupported entry type");
    }
    at += USTAR_BLOCK + padded;
  }
  return saw_entry && saw_terminator ? 0 : fail("invalid archive");
}

static void hex8(char *dst, u32 value) {
  static const char digits[] = "0123456789abcdef";
  for (u32 i = 0U; i < 8U; ++i) dst[i] = digits[(value >> (28U - i * 4U)) & 15U];
}
static int from_hex8(const unsigned char *src, u32 *value) {
  u32 result = 0U;
  for (u32 i = 0U; i < 8U; ++i) {
    unsigned char c = src[i];
    u32 digit = c >= '0' && c <= '9' ? c - '0' :
                c >= 'a' && c <= 'f' ? c - 'a' + 10U :
                c >= 'A' && c <= 'F' ? c - 'A' + 10U : 16U;
    if (digit == 16U) return -1;
    result = result * 16U + digit;
  }
  *value = result;
  return 0;
}

static int cpio_add(const char *source, const char *name, u64 *used, u32 *ino) {
  xaios_mfs_stat_user_t stat;
  if (xaios_fs_stat(source, &stat) != 0 || !archive_safe(name)) return -1;
  u32 namesize = (u32)length(name) + 1U;
  u32 filesize = stat.type == XAIOS_FS_TYPE_FILE ? (u32)stat.size : 0U;
  u64 header_end = *used + 110U + namesize;
  u64 data_at = (header_end + 3U) & ~3ULL;
  u64 end = (data_at + filesize + 3U) & ~3ULL;
  if (end > sizeof(g_data)) return -1;
  unsigned char *header = g_data + *used;
  xaios_memzero(header, end - *used);
  copy((char *)header, "070701", 7U);
  hex8((char *)header + 6U, (*ino)++);
  hex8((char *)header + 14U, stat.type == XAIOS_FS_TYPE_DIRECTORY ? 0040755U : 0100644U);
  hex8((char *)header + 22U, 0U); hex8((char *)header + 30U, 0U);
  hex8((char *)header + 38U, 1U); hex8((char *)header + 46U, 0U);
  hex8((char *)header + 54U, filesize);
  for (u32 off = 62U; off <= 94U; off += 8U) hex8((char *)header + off, 0U);
  hex8((char *)header + 94U, namesize); hex8((char *)header + 102U, 0U);
  copy((char *)header + 110U, name, namesize);
  if (filesize != 0U) {
    u64 got = 0U;
    if (read_file(source, g_data + data_at, filesize, &got) != 0 || got != filesize)
      return -1;
  }
  *used = end;
  if (stat.type == XAIOS_FS_TYPE_DIRECTORY) {
    char listing[LIST_MAX]; u64 listing_size = 0U;
    if (list_dir(source, listing, &listing_size) != 0) return -1;
    u64 cursor = 0U; char child_name[PATH_MAX]; int next;
    while ((next = each_listing(listing, listing_size, &cursor, child_name)) > 0) {
      char child_source[PATH_MAX], child_archive[PATH_MAX];
      if (join_path(source, child_name, child_source) != 0 ||
          join_path(name, child_name, child_archive) != 0 ||
          cpio_add(child_source, child_archive, used, ino) != 0) return -1;
    }
    if (next < 0) return -1;
  }
  return 0;
}

static int cmd_cpio(const char *args) {
  u64 cursor = 0U; char token[PATH_MAX];
  int create = 0, list = 0, extract = 0;
  char archive_arg[PATH_MAX] = "";
  char destination_arg[PATH_MAX] = "";
  char sources[16][PATH_MAX]; u32 source_count = 0U;
  while (next_token(args, &cursor, token, sizeof(token)) == 0) {
    if (equal(token, "-o")) create = 1;
    else if (equal(token, "-it") || equal(token, "-t")) list = 1;
    else if (equal(token, "-i")) extract = 1;
    else if (equal(token, "-O") || equal(token, "-I")) {
      if (next_token(args, &cursor, archive_arg, sizeof(archive_arg)) != 0)
        return fail("missing archive");
    } else if (equal(token, "-D")) {
      if (next_token(args, &cursor, destination_arg,
                     sizeof(destination_arg)) != 0)
        return fail("missing destination");
    } else if (token[0] == '-') return fail("unsupported option");
    else if (source_count < 16U) copy(sources[source_count++], token, PATH_MAX);
    else return fail("too many files");
  }
  if (archive_arg[0] == '\0' || (!create && !list && !extract))
    return fail("usage: cpio -o -O ARCHIVE FILE... | -it|-i -I ARCHIVE");
  char archive_path[PATH_MAX];
  if (resolve_path(archive_arg, archive_path) != 0) return fail("invalid archive");
  if (create) {
    u64 used = 0U; u32 ino = 1U;
    for (u32 i = 0U; i < source_count; ++i) {
      char source[PATH_MAX], name[PATH_MAX];
      if (resolve_path(sources[i], source) != 0 || basename_of(source, name) != 0 ||
          cpio_add(source, name, &used, &ino) != 0) return fail("create failed");
    }
    char trailer[] = "TRAILER!!!";
    if (used + 124U > sizeof(g_data)) return fail("archive too large");
    unsigned char *h = g_data + used; xaios_memzero(h, 124U);
    copy((char *)h, "070701", 7U);
    hex8((char *)h + 6U, ino); hex8((char *)h + 14U, 0U);
    for (u32 off = 22U; off <= 86U; off += 8U) hex8((char *)h + off, 0U);
    hex8((char *)h + 94U, 11U); hex8((char *)h + 102U, 0U);
    copy((char *)h + 110U, trailer, sizeof(trailer)); used += 124U;
    return write_file(archive_path, g_data, used) == 0 ? 0 : fail("write failed");
  }
  u64 size = 0U;
  if (read_file(archive_path, g_data, sizeof(g_data), &size) != 0)
    return fail("cannot read archive");
  char destination[PATH_MAX];
  if (destination_arg[0] == '\0') copy(destination, g_cwd, sizeof(destination));
  else if (resolve_path(destination_arg, destination) != 0)
    return fail("invalid destination");
  int found_trailer = 0;
  for (u64 at = 0U; at + 110U <= size;) {
    if (!starts((char *)g_data + at, "070701")) return fail("invalid archive");
    u32 file_size, name_size, mode;
    if (from_hex8(g_data + at + 54U, &file_size) != 0 ||
        from_hex8(g_data + at + 94U, &name_size) != 0 ||
        from_hex8(g_data + at + 14U, &mode) != 0 || name_size == 0U ||
        name_size >= PATH_MAX || name_size > size - at - 110U ||
        g_data[at + 110U + name_size - 1U] != 0U)
      return fail("invalid archive");
    char name[PATH_MAX];
    for (u32 i = 0U; i < name_size; ++i)
      name[i] = (char)g_data[at + 110U + i];
    name[name_size - 1U] = '\0';
    u64 data_at = (at + 110U + name_size + 3U) & ~3ULL;
    if (data_at > size || file_size > size - data_at)
      return fail("invalid archive");
    if (equal(name, "TRAILER!!!")) {
      found_trailer = 1;
      break;
    }
    if (!archive_safe(name)) return fail("unsafe path");
    if (list) { (void)append(name); (void)append("\n"); }
    if (extract) {
      char target[PATH_MAX];
      if (join_path(destination, name, target) != 0 || ensure_parents(target) != 0)
        return fail("unsafe path");
      if ((mode & 0170000U) == 0040000U) {
        if (xaios_fs_mkdir(target) != 0) {
          xaios_mfs_stat_user_t stat;
          if (xaios_fs_stat(target, &stat) != 0) return fail("mkdir failed");
        }
      } else if ((mode & 0170000U) == 0100000U) {
        if (write_file(target, g_data + data_at, file_size) != 0)
          return fail("extract failed");
      } else return fail("unsupported entry type");
    }
    at = (data_at + file_size + 3U) & ~3ULL;
  }
  return found_trailer ? 0 : fail("invalid archive");
}

static int zip_add(const char *source, const char *name, int recursive,
                   u64 *used, u32 *count) {
  xaios_mfs_stat_user_t stat;
  if (*count >= ENTRY_MAX || xaios_fs_stat(source, &stat) != 0) return -1;
  int directory = stat.type == XAIOS_FS_TYPE_DIRECTORY;
  if (directory && !recursive) return -1;
  char entry_name[PATH_MAX]; copy(entry_name, name, sizeof(entry_name));
  u64 name_size = length(entry_name);
  if (directory && entry_name[name_size - 1U] != '/') {
    if (name_size + 2U > sizeof(entry_name)) return -1;
    entry_name[name_size++] = '/'; entry_name[name_size] = '\0';
  }
  u64 file_size = directory ? 0U : stat.size;
  if (*used + 30U + name_size + file_size > sizeof(g_data)) return -1;
  unsigned char *header = g_data + *used;
  xaios_memzero(header, 30U);
  put_le32(header, 0x04034b50U); put_le16(header + 4U, 20U);
  u64 data_at = *used + 30U + name_size;
  if (!directory) {
    u64 got = 0U;
    if (read_file(source, g_data + data_at, file_size, &got) != 0 || got != file_size)
      return -1;
  }
  u32 crc = crc32(g_data + data_at, file_size);
  put_le32(header + 14U, crc); put_le32(header + 18U, (u32)file_size);
  put_le32(header + 22U, (u32)file_size); put_le16(header + 26U, (u32)name_size);
  for (u64 i = 0U; i < name_size; ++i) header[30U + i] = (unsigned char)entry_name[i];
  archive_entry_t *entry = &g_entries[(*count)++];
  copy(entry->name, entry_name, sizeof(entry->name)); entry->crc = crc;
  entry->size = (u32)file_size; entry->offset = (u32)*used; entry->directory = directory;
  *used = data_at + file_size;
  if (directory) {
    char listing[LIST_MAX]; u64 listing_size = 0U;
    if (list_dir(source, listing, &listing_size) != 0) return -1;
    u64 cursor = 0U; char child_name[PATH_MAX]; int next;
    while ((next = each_listing(listing, listing_size, &cursor, child_name)) > 0) {
      char child_source[PATH_MAX], child_archive[PATH_MAX];
      if (join_path(source, child_name, child_source) != 0 ||
          join_path(entry_name, child_name, child_archive) != 0 ||
          zip_add(child_source, child_archive, 1, used, count) != 0) return -1;
    }
    if (next < 0) return -1;
  }
  return 0;
}

static int cmd_zip(const char *args) {
  u64 cursor = 0U; char token[PATH_MAX]; int recursive = 0;
  if (next_token(args, &cursor, token, sizeof(token)) != 0) return fail("missing archive");
  if (equal(token, "-r")) { recursive = 1; if (next_token(args, &cursor, token, sizeof(token)) != 0) return fail("missing archive"); }
  char archive_path[PATH_MAX];
  if (resolve_path(token, archive_path) != 0) return fail("invalid archive");
  u64 used = 0U; u32 count = 0U; int sources = 0;
  while (next_token(args, &cursor, token, sizeof(token)) == 0) {
    char source[PATH_MAX], name[PATH_MAX];
    if (resolve_path(token, source) != 0 || basename_of(source, name) != 0 ||
        zip_add(source, name, recursive, &used, &count) != 0)
      return fail("cannot add path");
    ++sources;
  }
  if (!sources) return fail("missing files");
  u64 central = used;
  for (u32 i = 0U; i < count; ++i) {
    archive_entry_t *entry = &g_entries[i]; u64 name_size = length(entry->name);
    if (used + 46U + name_size > sizeof(g_data)) return fail("archive too large");
    unsigned char *h = g_data + used; xaios_memzero(h, 46U);
    put_le32(h, 0x02014b50U); put_le16(h + 4U, 0x0314U); put_le16(h + 6U, 20U);
    put_le32(h + 16U, entry->crc); put_le32(h + 20U, entry->size);
    put_le32(h + 24U, entry->size); put_le16(h + 28U, (u32)name_size);
    put_le32(h + 38U, entry->directory ? 0x10U : 0U); put_le32(h + 42U, entry->offset);
    for (u64 j = 0U; j < name_size; ++j) h[46U + j] = (unsigned char)entry->name[j];
    used += 46U + name_size;
  }
  if (used + 22U > sizeof(g_data)) return fail("archive too large");
  unsigned char *end = g_data + used; xaios_memzero(end, 22U);
  put_le32(end, 0x06054b50U); put_le16(end + 8U, count); put_le16(end + 10U, count);
  put_le32(end + 12U, (u32)(used - central)); put_le32(end + 16U, (u32)central);
  used += 22U;
  return write_file(archive_path, g_data, used) == 0 ? 0 : fail("write failed");
}

static int cmd_unzip(const char *args) {
  u64 cursor = 0U; char token[PATH_MAX]; int list = 0;
  if (next_token(args, &cursor, token, sizeof(token)) != 0) return fail("missing archive");
  if (equal(token, "-l")) { list = 1; if (next_token(args, &cursor, token, sizeof(token)) != 0) return fail("missing archive"); }
  char archive_path[PATH_MAX];
  if (resolve_path(token, archive_path) != 0) return fail("invalid archive");
  char destination[PATH_MAX]; copy(destination, g_cwd, sizeof(destination));
  while (next_token(args, &cursor, token, sizeof(token)) == 0) {
    if (!equal(token, "-d") || next_token(args, &cursor, token, sizeof(token)) != 0 ||
        resolve_path(token, destination) != 0) return fail("unsupported option");
  }
  u64 size = 0U;
  if (read_file(archive_path, g_data, sizeof(g_data), &size) != 0)
    return fail("cannot read archive");
  u64 at = 0U;
  u32 entries = 0U;
  while (at + 30U <= size && get_le32(g_data + at) == 0x04034b50U) {
    u32 flags = get_le16(g_data + at + 6U); u32 method = get_le16(g_data + at + 8U);
    u32 crc = get_le32(g_data + at + 14U); u32 packed = get_le32(g_data + at + 18U);
    u32 unpacked = get_le32(g_data + at + 22U); u32 name_size = get_le16(g_data + at + 26U);
    u32 extra_size = get_le16(g_data + at + 28U);
    if ((u64)name_size + (u64)extra_size > size - at - 30U)
      return fail("unsupported or corrupt archive");
    u64 data_at = at + 30U + name_size + extra_size;
    if ((flags & 9U) != 0U || name_size == 0U || name_size >= PATH_MAX ||
        packed > size - data_at || (method != 0U && method != 8U))
      return fail("unsupported or corrupt archive");
    char name[PATH_MAX];
    for (u32 i = 0U; i < name_size; ++i) name[i] = (char)g_data[at + 30U + i];
    name[name_size] = '\0';
    if (!archive_safe(name)) return fail("unsafe path");
    if (list) { (void)append_u64(unpacked); (void)append(" "); (void)append(name); (void)append("\n"); }
    else {
      char target[PATH_MAX];
      if (join_path(destination, name, target) != 0 || ensure_parents(target) != 0)
        return fail("unsafe path");
      if (name[name_size - 1U] == '/') {
        if (xaios_fs_mkdir(target) != 0) {
          xaios_mfs_stat_user_t stat; if (xaios_fs_stat(target, &stat) != 0) return fail("mkdir failed");
        }
      } else {
        const unsigned char *payload = g_data + data_at; u64 output_size = packed;
        if (method == 8U) {
          if (xaios_inflate_raw(payload, packed, g_aux, sizeof(g_aux), &output_size) != 0 ||
              output_size != unpacked) return fail("deflate failed");
          payload = g_aux;
        }
        if (output_size != unpacked || crc32(payload, output_size) != crc ||
            write_file(target, payload, output_size) != 0) return fail("extract failed");
      }
    }
    at = data_at + packed;
    ++entries;
  }
  if (entries == 0U || at + 4U > size ||
      (get_le32(g_data + at) != 0x02014b50U &&
       get_le32(g_data + at) != 0x06054b50U))
    return fail("unsupported or corrupt archive");
  return 0;
}

static int runtime_query(xaios_control_runtime_snapshot_payload_user_t *snapshot,
                         u32 process_start) {
  struct {
    xaios_control_request_header_user_t header;
    xaios_control_runtime_snapshot_request_user_t payload;
  } request;
  union { u64 align; unsigned char bytes[XAIOS_CONTROL_MAX_RESPONSE_BYTES]; } response;
  u64 response_size = 0U;
  xaios_memzero(&request, sizeof(request));
  request.header.magic = XAIOS_CONTROL_MAGIC; request.header.version = XAIOS_CONTROL_VERSION;
  request.header.header_size = (u16)sizeof(request.header);
  request.header.operation = XAIOS_CONTROL_OP_RUNTIME_SNAPSHOT;
  request.header.payload_type = XAIOS_CONTROL_PAYLOAD_RUNTIME_SNAPSHOT_REQUEST;
  request.header.request_id = 1U; request.header.principal_role = XAIOS_CONTROL_ROLE_OBSERVER;
  request.header.payload_length = sizeof(request.payload);
  request.payload.process_start = process_start;
  request.payload.process_limit = XAIOS_CONTROL_RUNTIME_PROCESS_MAX;
  if (xaios_control_query(&request, sizeof(request), response.bytes,
                          sizeof(response.bytes), &response_size) != 0 ||
      response_size < sizeof(xaios_control_response_header_user_t)) return -1;
  xaios_control_response_header_user_t *header = (xaios_control_response_header_user_t *)response.bytes;
  if (header->magic != XAIOS_CONTROL_MAGIC ||
      header->version != XAIOS_CONTROL_VERSION ||
      header->header_size != sizeof(*header) ||
      header->operation != XAIOS_CONTROL_OP_RUNTIME_SNAPSHOT ||
      header->flags != 0U || header->request_id != 1U ||
      response_size != sizeof(*header) + header->payload_length ||
      header->status != XAIOS_CONTROL_STATUS_OK ||
      header->payload_type != XAIOS_CONTROL_PAYLOAD_RUNTIME_SNAPSHOT ||
      header->payload_length != sizeof(*snapshot)) return -1;
  xaios_memcpy(snapshot, response.bytes + sizeof(*header), sizeof(*snapshot));
  if (snapshot->process_count > XAIOS_CONTROL_RUNTIME_PROCESS_MAX ||
      snapshot->process_start != process_start ||
      snapshot->process_capacity < snapshot->process_count)
    return -1;
  return 0;
}

static const char *state_name(u32 state) {
  if (state == XAIOS_RUNTIME_PROCESS_LOADED) return "loaded";
  if (state == XAIOS_RUNTIME_PROCESS_RUNNABLE) return "runnable";
  if (state == XAIOS_RUNTIME_PROCESS_RUNNING) return "running";
  if (state == XAIOS_RUNTIME_PROCESS_WAITING) return "waiting";
  if (state == XAIOS_RUNTIME_PROCESS_EXITED) return "exited";
  if (state == XAIOS_RUNTIME_PROCESS_FAILED) return "failed";
  return "unknown";
}

static int cmd_ps(const char *args) {
  int show_all = length(args) != 0U;
  (void)append(show_all ? "USER PID PPID STAT CPU TIME RSS COMMAND\n" :
                          "PID STAT TIME COMMAND\n");
  u32 cursor = 0U;
  for (;;) {
    xaios_control_runtime_snapshot_payload_user_t snapshot;
    if (runtime_query(&snapshot, cursor) != 0) return fail("snapshot unavailable");
    for (u32 i = 0U; i < snapshot.process_count; ++i) {
      xaios_control_runtime_process_record_user_t *p = &snapshot.processes[i];
      int active = p->state >= XAIOS_RUNTIME_PROCESS_LOADED &&
                   p->state <= XAIOS_RUNTIME_PROCESS_WAITING;
      if (!show_all && !active) continue;
      if (show_all) (void)append("admin ");
      (void)append_u64(p->pid); (void)append(" ");
      if (show_all) { (void)append_u64(p->parent_pid); (void)append(" "); }
      (void)append(state_name(p->state)); (void)append(" ");
      if (show_all) { if (p->cpu_id == 0xffffffffU) (void)append("- "); else { (void)append_u64(p->cpu_id); (void)append(" "); } }
      (void)append_u64(p->runtime_ns / 1000000U); (void)append(" ");
      if (show_all) { (void)append_u64(p->resident_pages * 4U); (void)append(" "); }
      (void)append(p->name); (void)append("\n");
    }
    if (snapshot.process_next == 0xffffffffU) break;
    if (snapshot.process_next <= cursor) return fail("invalid snapshot cursor");
    cursor = snapshot.process_next;
  }
  return 0;
}

static int filesystem_query(unsigned char *response, u64 *response_size) {
  xaios_control_request_header_user_t request;
  xaios_memzero(&request, sizeof(request));
  request.magic = XAIOS_CONTROL_MAGIC; request.version = XAIOS_CONTROL_VERSION;
  request.header_size = (u16)sizeof(request); request.operation = XAIOS_CONTROL_OP_STORAGE_FILESYSTEM_LIST;
  request.request_id = 2U; request.principal_role = XAIOS_CONTROL_ROLE_OBSERVER;
  return xaios_control_query(&request, sizeof(request), response,
                             XAIOS_CONTROL_MAX_RESPONSE_BYTES, response_size);
}

static int fixed_string_valid(const char *text, u64 capacity) {
  for (u64 i = 0U; i < capacity; ++i)
    if (text[i] == '\0') return 1;
  return 0;
}

static u64 percent_ceil(u64 used, u64 total) {
  if (total == 0U || used == 0U) return 0U;
  if (used >= total) return 100U;
  u64 percent = 0U;
  u64 accumulator = 0U;
  for (u32 step = 0U; step < 100U; ++step) {
    if (accumulator >= total - used) {
      accumulator -= total - used;
      ++percent;
    } else {
      accumulator += used;
    }
  }
  return percent + (accumulator != 0U ? 1U : 0U);
}

static int cmd_df(const char *args) {
  u64 cursor = 0U;
  char token[PATH_MAX];
  if (next_token(args, &cursor, token, sizeof(token)) == 0 &&
      (!equal(token, "-h") ||
       next_token(args, &cursor, token, sizeof(token)) == 0))
    return fail("unsupported option");
  union { u64 align; unsigned char bytes[XAIOS_CONTROL_MAX_RESPONSE_BYTES]; } response;
  u64 response_size = 0U;
  if (filesystem_query(response.bytes, &response_size) != 0 ||
      response_size < sizeof(xaios_control_response_header_user_t))
    return fail("filesystem data unavailable");
  xaios_control_response_header_user_t *header = (xaios_control_response_header_user_t *)response.bytes;
  if (header->magic != XAIOS_CONTROL_MAGIC ||
      header->version != XAIOS_CONTROL_VERSION ||
      header->header_size != sizeof(*header) ||
      header->operation != XAIOS_CONTROL_OP_STORAGE_FILESYSTEM_LIST ||
      header->flags != 0U || header->request_id != 2U ||
      response_size != sizeof(*header) + header->payload_length ||
      header->status != XAIOS_CONTROL_STATUS_OK ||
      header->payload_type != XAIOS_CONTROL_PAYLOAD_STORAGE_FILESYSTEMS ||
      header->payload_length < sizeof(xaios_control_storage_filesystems_payload_user_t))
    return fail("filesystem data unavailable");
  xaios_control_storage_filesystems_payload_user_t *meta =
      (xaios_control_storage_filesystems_payload_user_t *)(response.bytes + sizeof(*header));
  u64 records_size = header->payload_length - sizeof(*meta);
  if (meta->record_count > XAIOS_CONTROL_STORAGE_MAX_FILESYSTEMS ||
      meta->total_count < meta->record_count || meta->truncated > 1U ||
      meta->reserved != 0U ||
      records_size != (u64)meta->record_count *
                          sizeof(xaios_control_storage_filesystem_record_user_t))
    return fail("filesystem data unavailable");
  xaios_control_storage_filesystem_record_user_t *records =
      (xaios_control_storage_filesystem_record_user_t *)(meta + 1);
  (void)append("Filesystem Size Used Avail Capacity Mounted on\n");
  for (u32 i = 0U; i < meta->record_count; ++i) {
    xaios_control_storage_filesystem_record_user_t *r = &records[i];
    if (!fixed_string_valid(r->filesystem, sizeof(r->filesystem)) ||
        !fixed_string_valid(r->mount_path, sizeof(r->mount_path)) ||
        r->allocated_bytes > r->total_bytes || r->free_bytes > r->total_bytes ||
        r->mounted > 1U || r->read_only > 1U || r->staging_writable > 1U)
      return fail("filesystem data unavailable");
    (void)append(r->filesystem); (void)append(" ");
    (void)append_u64(r->total_bytes / 1024U); (void)append("K ");
    (void)append_u64(r->allocated_bytes / 1024U); (void)append("K ");
    (void)append_u64(r->free_bytes / 1024U); (void)append("K ");
    (void)append_u64(percent_ceil(r->allocated_bytes, r->total_bytes));
    (void)append("% "); (void)append(r->mount_path); (void)append("\n");
  }
  return 0;
}

static int du_walk(const char *path, int human, int summary, u64 *total) {
  xaios_mfs_stat_user_t stat;
  if (xaios_fs_stat(path, &stat) != 0) return -1;
  if (stat.type == XAIOS_FS_TYPE_FILE) { *total = (u64)stat.block_count * 512U; return 0; }
  char listing[LIST_MAX]; u64 size = 0U;
  if (list_dir(path, listing, &size) != 0) return -1;
  u64 cursor = 0U; char name[PATH_MAX]; int next; u64 sum = 0U;
  while ((next = each_listing(listing, size, &cursor, name)) > 0) {
    char child[PATH_MAX]; u64 child_size = 0U;
    if (join_path(path, name, child) != 0 || du_walk(child, human, summary, &child_size) != 0)
      return -1;
    sum += child_size;
  }
  if (next < 0) return -1;
  *total = sum;
  if (!summary) { (void)append_u64(human ? (sum + 1023U) / 1024U : (sum + 511U) / 512U); (void)append(human ? "K\t" : "\t"); (void)append(path); (void)append("\n"); }
  return 0;
}

static int cmd_du(const char *args) {
  u64 cursor = 0U; char token[PATH_MAX]; int human = 0, summary = 0, paths = 0;
  while (next_token(args, &cursor, token, sizeof(token)) == 0) {
    if (token[0] == '-') {
      for (u64 i = 1U; token[i] != '\0'; ++i) {
        if (token[i] == 'h') human = 1; else if (token[i] == 's') summary = 1;
        else if (token[i] != 'k' && token[i] != 'a') return fail("unsupported option");
      }
      continue;
    }
    char path[PATH_MAX]; u64 total = 0U;
    if (resolve_path(token, path) != 0 || du_walk(path, human, summary, &total) != 0)
      return fail("cannot inspect path");
    if (summary) { (void)append_u64(human ? (total + 1023U) / 1024U : (total + 511U) / 512U); (void)append(human ? "K\t" : "\t"); (void)append(path); (void)append("\n"); }
    ++paths;
  }
  if (!paths) { u64 total = 0U; if (du_walk(g_cwd, human, summary, &total) != 0) return fail("cannot inspect current directory"); if (summary) { (void)append_u64((total + 511U) / 512U); (void)append("\t"); (void)append(g_cwd); (void)append("\n"); } }
  return 0;
}

int main(int argc, char **argv) {
  const char *args = argc > 2 ? argv[2] : "";
  if (argc < 2 || argv == 0 || argv[1] == 0 || argv[1][0] != '/') return fail("missing session context");
  g_cwd = argv[1]; g_used = 0U; g_output[0] = '\0';
  int result;
  if (equal(XAIOS_UTILITY_NAME, "ls")) result = cmd_ls(args);
  else if (equal(XAIOS_UTILITY_NAME, "mkdir")) result = cmd_mkdir(args);
  else if (equal(XAIOS_UTILITY_NAME, "touch")) result = cmd_touch(args);
  else if (equal(XAIOS_UTILITY_NAME, "cp")) result = cmd_cp(args);
  else if (equal(XAIOS_UTILITY_NAME, "mv")) result = cmd_mv(args);
  else if (equal(XAIOS_UTILITY_NAME, "rm")) result = cmd_rm(args, 0);
  else if (equal(XAIOS_UTILITY_NAME, "rmdir")) result = cmd_rm(args, 1);
  else if (equal(XAIOS_UTILITY_NAME, "stat")) result = cmd_stat(args);
  else if (equal(XAIOS_UTILITY_NAME, "cat")) result = cmd_cat_like(args, 0);
  else if (equal(XAIOS_UTILITY_NAME, "head")) result = cmd_cat_like(args, 1);
  else if (equal(XAIOS_UTILITY_NAME, "tail")) result = cmd_cat_like(args, 2);
  else if (equal(XAIOS_UTILITY_NAME, "less")) result = cmd_cat_like(args, 0);
  else if (equal(XAIOS_UTILITY_NAME, "grep")) result = cmd_grep(args);
  else if (equal(XAIOS_UTILITY_NAME, "find")) result = cmd_find(args);
  else if (equal(XAIOS_UTILITY_NAME, "write")) result = cmd_write(args);
  else if (equal(XAIOS_UTILITY_NAME, "sed")) result = cmd_sed(args);
  else if (equal(XAIOS_UTILITY_NAME, "tar")) result = cmd_tar(args);
  else if (equal(XAIOS_UTILITY_NAME, "cpio")) result = cmd_cpio(args);
  else if (equal(XAIOS_UTILITY_NAME, "zip")) result = cmd_zip(args);
  else if (equal(XAIOS_UTILITY_NAME, "unzip")) result = cmd_unzip(args);
  else if (equal(XAIOS_UTILITY_NAME, "ps")) result = cmd_ps(args);
  else if (equal(XAIOS_UTILITY_NAME, "df")) result = cmd_df(args);
  else if (equal(XAIOS_UTILITY_NAME, "du")) result = cmd_du(args);
  else result = fail("unsupported utility image");
  if (result == 0 && flush_output() != 0) return 1;
  return result;
}
