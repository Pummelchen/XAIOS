#include <xaios_user.h>

#define NANO_PATH_MAX 256U
#define NANO_BUFFER_SIZE 32768U
#define NANO_OUTPUT_SIZE 32768U

static char g_data[NANO_BUFFER_SIZE];
static char g_edited[NANO_BUFFER_SIZE];
static char g_output[NANO_OUTPUT_SIZE];

static u64 text_length(const char *text) {
  u64 length = 0U;
  while (text != 0 && text[length] != '\0') ++length;
  return length;
}

static int text_equal(const char *lhs, const char *rhs) {
  if (lhs == 0 || rhs == 0) return 0;
  while (*lhs != '\0' && *lhs == *rhs) {
    ++lhs;
    ++rhs;
  }
  return *lhs == *rhs;
}

static u64 skip_space(const char *text, u64 index) {
  while (text[index] == ' ' || text[index] == '\t' ||
         text[index] == '\r' || text[index] == '\n')
    ++index;
  return index;
}

static int next_token(const char *text, u64 *index, char *token,
                      u64 capacity) {
  u64 used = 0U;
  u64 cursor;
  char quote = '\0';
  if (text == 0 || index == 0 || token == 0 || capacity == 0U) return -1;
  cursor = skip_space(text, *index);
  if (text[cursor] == '\0') return -1;
  if (text[cursor] == '\'' || text[cursor] == '"') quote = text[cursor++];
  while (text[cursor] != '\0') {
    if (quote != '\0') {
      if (text[cursor] == quote) {
        ++cursor;
        break;
      }
    } else if (text[cursor] == ' ' || text[cursor] == '\t' ||
               text[cursor] == '\r' || text[cursor] == '\n') {
      break;
    }
    if (used + 1U >= capacity) return -1;
    token[used++] = text[cursor++];
  }
  token[used] = '\0';
  *index = skip_space(text, cursor);
  return 0;
}

static int append_char(char *output, u64 capacity, u64 *used, char value) {
  if (*used + 1U >= capacity) return -1;
  output[(*used)++] = value;
  output[*used] = '\0';
  return 0;
}

static int append_bytes(char *output, u64 capacity, u64 *used,
                        const char *data, u64 size) {
  for (u64 i = 0U; i < size; ++i)
    if (append_char(output, capacity, used, data[i]) != 0) return -1;
  return 0;
}

static int append_text(char *output, u64 capacity, u64 *used,
                       const char *text) {
  return append_bytes(output, capacity, used, text, text_length(text));
}

static int append_u64(char *output, u64 capacity, u64 *used, u64 value) {
  char digits[24];
  u32 count = 0U;
  do {
    digits[count++] = (char)('0' + value % 10U);
    value /= 10U;
  } while (value != 0U);
  while (count != 0U)
    if (append_char(output, capacity, used, digits[--count]) != 0) return -1;
  return 0;
}

static int append_decoded(char *output, u64 capacity, u64 *used,
                          const char *text) {
  for (u64 i = 0U; text[i] != '\0'; ++i) {
    char value = text[i];
    if (value == '\\' && text[i + 1U] != '\0') {
      char escaped = text[++i];
      if (escaped == 'n') value = '\n';
      else if (escaped == 'r') value = '\r';
      else if (escaped == 't') value = '\t';
      else if (escaped == '\\') value = '\\';
      else {
        if (append_char(output, capacity, used, '\\') != 0) return -1;
        value = escaped;
      }
    }
    if (append_char(output, capacity, used, value) != 0) return -1;
  }
  return 0;
}

static int parse_line(const char *text, u64 *line) {
  u64 value = 0U;
  if (text == 0 || text[0] < '0' || text[0] > '9') return -1;
  for (u64 i = 0U; text[i] != '\0'; ++i) {
    if (text[i] < '0' || text[i] > '9') return -1;
    u64 digit = (u64)(text[i] - '0');
    if (value > (~0ULL - digit) / 10U) return -1;
    value = value * 10U + digit;
  }
  if (value == 0U) return -1;
  *line = value;
  return 0;
}

static int normalize_path(const char *input, char *output, u64 capacity) {
  u64 input_cursor = 1U;
  u64 output_size = 1U;
  if (input == 0 || output == 0 || capacity < 2U || input[0] != '/') return -1;
  output[0] = '/';
  output[1] = '\0';
  while (input[input_cursor] != '\0') {
    while (input[input_cursor] == '/') ++input_cursor;
    if (input[input_cursor] == '\0') break;
    u64 start = input_cursor;
    while (input[input_cursor] != '\0' && input[input_cursor] != '/')
      ++input_cursor;
    u64 size = input_cursor - start;
    if (size == 1U && input[start] == '.') continue;
    if (size == 2U && input[start] == '.' && input[start + 1U] == '.') {
      if (output_size > 1U) {
        --output_size;
        while (output_size > 1U && output[output_size - 1U] != '/')
          --output_size;
        if (output_size > 1U) --output_size;
        output[output_size] = '\0';
      }
      continue;
    }
    if (output_size > 1U) {
      if (output_size + 1U >= capacity) return -1;
      output[output_size++] = '/';
    }
    if (size == 0U || size + 1U > capacity - output_size) return -1;
    xaios_memcpy(output + output_size, input + start, size);
    output_size += size;
    output[output_size] = '\0';
  }
  return 0;
}

static int resolve_path(const char *path, char *resolved, u64 capacity) {
  char combined[NANO_PATH_MAX];
  if (path[0] == '/') return normalize_path(path, resolved, capacity);
  char cwd[NANO_PATH_MAX];
  u64 cwd_size = 0U;
  if (xaios_remote_login("admin", "pwd", cwd, sizeof(cwd), &cwd_size) != 0 ||
      cwd_size == 0U)
    return -1;
  while (cwd_size != 0U &&
         (cwd[cwd_size - 1U] == '\n' || cwd[cwd_size - 1U] == '\r'))
    --cwd_size;
  u64 path_size = text_length(path);
  u64 separator = cwd_size == 1U && cwd[0] == '/' ? 0U : 1U;
  if (cwd_size + separator + path_size + 1U > sizeof(combined)) return -1;
  xaios_memcpy(combined, cwd, cwd_size);
  u64 used = cwd_size;
  if (separator != 0U) combined[used++] = '/';
  xaios_memcpy(combined + used, path, path_size + 1U);
  return normalize_path(combined, resolved, capacity);
}

static int path_protected(const char *path) {
  static const char control[] = "/state/control";
  static const char host_key[] = "/state/xaios_host_key";
  static const char users[] = "/etc/xaios_sshd_users";
  static const char keys[] = "/etc/xaios_authorized_keys";
  if (text_equal(path, host_key) || text_equal(path, users) ||
      text_equal(path, keys))
    return 1;
  for (u64 i = 0U; i < sizeof(control) - 1U; ++i)
    if (path[i] != control[i]) return 0;
  return path[sizeof(control) - 1U] == '\0' ||
         path[sizeof(control) - 1U] == '/';
}

static int read_file(const char *path, u64 *size, int *exists) {
  xaios_mfs_stat_user_t stat;
  *size = 0U;
  *exists = xaios_fs_stat(path, &stat) == 0;
  if (!*exists) return 0;
  if (stat.type != XAIOS_FS_TYPE_FILE || stat.size >= sizeof(g_data)) return -1;
  int fd = xaios_fs_open(path, XAIOS_MFS_OPEN_READ);
  if (fd < 0) return -1;
  while (*size < stat.size) {
    int bytes = xaios_fs_read(fd, g_data + *size, stat.size - *size);
    if (bytes <= 0) {
      (void)xaios_fs_close(fd);
      return -1;
    }
    *size += (u64)bytes;
  }
  if (xaios_fs_close(fd) != 0) return -1;
  g_data[*size] = '\0';
  return 0;
}

static int write_file(const char *path, const char *data, u64 size) {
  int fd = xaios_fs_open(path, XAIOS_MFS_OPEN_WRITE | XAIOS_MFS_OPEN_CREATE |
                                   XAIOS_MFS_OPEN_TRUNCATE);
  if (fd < 0) return -1;
  u64 written = 0U;
  while (written < size) {
    int bytes = xaios_fs_write(fd, data + written, size - written);
    if (bytes <= 0) {
      (void)xaios_fs_close(fd);
      return -1;
    }
    written += (u64)bytes;
  }
  return xaios_fs_fsync(fd) == 0 && xaios_fs_close(fd) == 0 ? 0 : -1;
}

static int find_line(const char *data, u64 size, u64 requested, u64 *start,
                     u64 *end, u64 *next) {
  u64 current = 1U;
  u64 line_start = 0U;
  for (;;) {
    if (current == requested) {
      u64 line_end = line_start;
      while (line_end < size && data[line_end] != '\n') ++line_end;
      *start = line_start;
      *end = line_end;
      *next = line_end < size ? line_end + 1U : line_end;
      return 0;
    }
    while (line_start < size && data[line_start] != '\n') ++line_start;
    if (line_start >= size) return -1;
    ++line_start;
    ++current;
  }
}

static int fail(const char *message) {
  (void)xaios_console_write(message, text_length(message));
  (void)xaios_console_write("\n", 1U);
  return 1;
}

int main(int argc, char **argv) {
  char path[NANO_PATH_MAX];
  char resolved[NANO_PATH_MAX];
  char action[24];
  char line_token[24];
  const char *args = argc == 2 ? argv[1] : "";
  u64 index = 0U;
  u64 data_size = 0U;
  u64 edited_size = 0U;
  u64 output_size = 0U;
  u64 line = 0U;
  u64 line_start = 0U;
  u64 line_end = 0U;
  u64 line_next = 0U;
  int exists = 0;
  if (argc > 2 || next_token(args, &index, path, sizeof(path)) != 0 ||
      text_equal(path, "--help")) {
    static const char usage[] =
        "nano PATH [--number|--write TEXT|--append TEXT|--insert LINE TEXT|"
        "--replace LINE TEXT|--delete LINE]\n"
        "TEXT escapes: \\n \\r \\t \\\\\n";
    (void)xaios_console_write(usage, sizeof(usage) - 1U);
    return argc > 2 ? 2 : 0;
  }
  if (resolve_path(path, resolved, sizeof(resolved)) != 0)
    return fail("nano: invalid path");
  if (path_protected(resolved)) return fail("nano: protected path");
  if (read_file(resolved, &data_size, &exists) != 0)
    return fail("nano: file exceeds editor capacity");

  if (next_token(args, &index, action, sizeof(action)) != 0) {
    append_text(g_output, sizeof(g_output), &output_size, "nano: ");
    append_text(g_output, sizeof(g_output), &output_size, resolved);
    append_text(g_output, sizeof(g_output), &output_size,
                exists ? "\n" : " [ New File ]\n");
    append_bytes(g_output, sizeof(g_output), &output_size, g_data, data_size);
    if (data_size != 0U && g_data[data_size - 1U] != '\n')
      append_char(g_output, sizeof(g_output), &output_size, '\n');
    (void)xaios_console_write(g_output, output_size);
    return 0;
  }

  if (text_equal(action, "--number")) {
    if (args[skip_space(args, index)] != '\0')
      return fail("nano: too many arguments");
    u64 start = 0U;
    u64 number = 1U;
    if (data_size == 0U) {
      append_text(g_output, sizeof(g_output), &output_size, "1  \n");
    } else while (start < data_size) {
      u64 end = start;
      while (end < data_size && g_data[end] != '\n') ++end;
      append_u64(g_output, sizeof(g_output), &output_size, number++);
      append_text(g_output, sizeof(g_output), &output_size, "  ");
      append_bytes(g_output, sizeof(g_output), &output_size, g_data + start,
                   end - start);
      append_char(g_output, sizeof(g_output), &output_size, '\n');
      start = end < data_size ? end + 1U : end;
    }
    (void)xaios_console_write(g_output, output_size);
    return 0;
  }

  if (text_equal(action, "--write")) {
    if (append_decoded(g_edited, sizeof(g_edited), &edited_size,
                       args + skip_space(args, index)) != 0)
      return fail("nano: text exceeds editor capacity");
  } else if (text_equal(action, "--append")) {
    if (append_bytes(g_edited, sizeof(g_edited), &edited_size, g_data,
                     data_size) != 0 ||
        append_decoded(g_edited, sizeof(g_edited), &edited_size,
                       args + skip_space(args, index)) != 0)
      return fail("nano: text exceeds editor capacity");
  } else if (text_equal(action, "--insert") ||
             text_equal(action, "--replace") ||
             text_equal(action, "--delete")) {
    if (next_token(args, &index, line_token, sizeof(line_token)) != 0 ||
        parse_line(line_token, &line) != 0 ||
        find_line(g_data, data_size, line, &line_start, &line_end,
                  &line_next) != 0)
      return fail("nano: invalid line number");
    if (text_equal(action, "--delete")) {
      if (args[skip_space(args, index)] != '\0')
        return fail("nano: delete takes only a line number");
      if (append_bytes(g_edited, sizeof(g_edited), &edited_size, g_data,
                       line_start) != 0 ||
          append_bytes(g_edited, sizeof(g_edited), &edited_size,
                       g_data + line_next, data_size - line_next) != 0)
        return fail("nano: edit exceeds editor capacity");
    } else {
      const char *text = args + skip_space(args, index);
      u64 suffix = text_equal(action, "--insert") ? line_start : line_next;
      if (text[0] == '\0') return fail("nano: missing text");
      if (append_bytes(g_edited, sizeof(g_edited), &edited_size, g_data,
                       line_start) != 0 ||
          append_decoded(g_edited, sizeof(g_edited), &edited_size, text) != 0 ||
          append_char(g_edited, sizeof(g_edited), &edited_size, '\n') != 0 ||
          append_bytes(g_edited, sizeof(g_edited), &edited_size,
                       g_data + suffix, data_size - suffix) != 0)
        return fail("nano: edit exceeds editor capacity");
      (void)line_end;
    }
  } else {
    return fail("nano: unsupported option; use nano --help");
  }

  if (write_file(resolved, g_edited, edited_size) != 0)
    return fail("nano: save failed");
  append_text(g_output, sizeof(g_output), &output_size, "nano: saved ");
  append_text(g_output, sizeof(g_output), &output_size, resolved);
  append_text(g_output, sizeof(g_output), &output_size, " bytes=");
  append_u64(g_output, sizeof(g_output), &output_size, edited_size);
  append_char(g_output, sizeof(g_output), &output_size, '\n');
  (void)xaios_console_write(g_output, output_size);
  return 0;
}
