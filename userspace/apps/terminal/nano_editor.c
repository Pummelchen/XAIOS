#include "nano_editor.h"
#include <xaios_user.h>

static void app_mem_copy(void *destination, const void *source,
                         uint64_t size) {
  uint8_t *output = (uint8_t *)destination;
  const uint8_t *input = (const uint8_t *)source;
  for (uint64_t i = 0U; i < size; ++i) output[i] = input[i];
}

static void app_mem_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0U; i < size; ++i) bytes[i] = 0U;
}

static uint32_t app_text_length(const char *text) {
  uint32_t size = 0U;
  while (text[size] != '\0') ++size;
  return size;
}

static int app_text_equal(const char *lhs, const char *rhs) {
  if (lhs == 0 || rhs == 0) return 0;
  while (*lhs != '\0' && *lhs == *rhs) {
    ++lhs;
    ++rhs;
  }
  return *lhs == *rhs;
}

static void copy_text(char *destination, uint32_t capacity,
                      const char *source) {
  uint32_t i = 0U;
  if (capacity == 0U) return;
  while (i + 1U < capacity && source[i] != '\0') {
    destination[i] = source[i];
    ++i;
  }
  destination[i] = '\0';
}

static int append_bytes(char *output, uint32_t capacity, uint32_t *used,
                        const void *value, uint32_t length) {
  if (output == 0 || used == 0 || value == 0 || *used > capacity ||
      length > capacity - *used) {
    return -1;
  }
  app_mem_copy(output + *used, value, length);
  *used += length;
  return 0;
}

static int append_text(char *output, uint32_t capacity, uint32_t *used,
                       const char *value) {
  return append_bytes(output, capacity, used, value, app_text_length(value));
}

static int append_text_clipped(char *output, uint32_t capacity,
                               uint32_t *used, const char *value,
                               uint32_t columns) {
  uint32_t length = app_text_length(value);
  if (length > columns) length = columns;
  return append_bytes(output, capacity, used, value, length);
}

static int append_u32(char *output, uint32_t capacity, uint32_t *used,
                      uint32_t value) {
  char digits[10];
  uint32_t count = 0U;
  do {
    digits[count++] = (char)('0' + value % 10U);
    value /= 10U;
  } while (value != 0U);
  if (count > capacity - *used) return -1;
  while (count != 0U) output[(*used)++] = digits[--count];
  return 0;
}

static int protected_path(const char *path) {
  static const char control[] = "/state/control";
  static const char host_key[] = "/state/xaios_host_key";
  static const char users[] = "/etc/xaios_sshd_users";
  static const char keys[] = "/etc/xaios_authorized_keys";
  if (app_text_equal(path, host_key) || app_text_equal(path, users) ||
      app_text_equal(path, keys)) {
    return 1;
  }
  uint32_t control_length = sizeof(control) - 1U;
  for (uint32_t i = 0U; i < control_length; ++i) {
    if (path[i] != control[i]) return 0;
  }
  return path[control_length] == '\0' || path[control_length] == '/';
}

static int resolve_path(const char *cwd, const char *argument, char *output) {
  char combined[NANO_EDITOR_PATH_MAX];
  uint32_t combined_length = 0U;
  uint32_t output_length = 1U;
  if (cwd == 0 || argument == 0 || argument[0] == '\0') return -1;
  combined[0] = '\0';
  if (argument[0] != '/') {
    uint32_t cwd_length = app_text_length(cwd);
    if (cwd_length == 0U || cwd_length >= sizeof(combined)) return -1;
    app_mem_copy(combined, cwd, cwd_length);
    combined_length = cwd_length;
    if (combined_length > 1U && combined[combined_length - 1U] != '/') {
      combined[combined_length++] = '/';
    }
  }
  uint32_t argument_length = app_text_length(argument);
  if (argument_length >= sizeof(combined) - combined_length) return -1;
  app_mem_copy(combined + combined_length, argument, argument_length + 1U);
  if (combined[0] != '/') return -1;
  output[0] = '/';
  output[1] = '\0';
  for (uint32_t i = 1U; combined[i] != '\0';) {
    while (combined[i] == '/') ++i;
    if (combined[i] == '\0') break;
    uint32_t start = i;
    while (combined[i] != '\0' && combined[i] != '/') ++i;
    uint32_t length = i - start;
    if (length == 1U && combined[start] == '.') continue;
    if (length == 2U && combined[start] == '.' && combined[start + 1U] == '.') {
      if (output_length > 1U) {
        --output_length;
        while (output_length > 1U && output[output_length - 1U] != '/') {
          --output_length;
        }
        if (output_length > 1U) --output_length;
        output[output_length] = '\0';
      }
      continue;
    }
    if (output_length > 1U) {
      if (output_length + 1U >= NANO_EDITOR_PATH_MAX) return -1;
      output[output_length++] = '/';
    }
    if (length == 0U || length >= NANO_EDITOR_PATH_MAX - output_length) {
      return -1;
    }
    app_mem_copy(output + output_length, combined + start, length);
    output_length += length;
    output[output_length] = '\0';
  }
  return protected_path(output) ? -1 : 0;
}

static int editor_save(nano_editor_t *editor) {
  int fd = xaios_fs_open(editor->path,
                         XAIOS_XBFS_OPEN_WRITE | XAIOS_XBFS_OPEN_CREATE |
                             XAIOS_XBFS_OPEN_TRUNCATE);
  if (fd < 0) {
    copy_text(editor->status, sizeof(editor->status), "Error writing file");
    return -1;
  }
  uint32_t written = 0U;
  while (written < editor->length) {
    int result = xaios_fs_write(fd, editor->data + written,
                                editor->length - written);
    if (result <= 0 || (uint32_t)result > editor->length - written) {
      (void)xaios_fs_close(fd);
      copy_text(editor->status, sizeof(editor->status), "Error writing file");
      return -1;
    }
    written += (uint32_t)result;
  }
  if (xaios_fs_close(fd) != 0) {
    copy_text(editor->status, sizeof(editor->status), "Error closing file");
    return -1;
  }
  editor->dirty = 0U;
  copy_text(editor->status, sizeof(editor->status), "Wrote file");
  return 0;
}

static void cursor_line_column(const nano_editor_t *editor, uint32_t *line,
                               uint32_t *column) {
  *line = 0U;
  *column = 0U;
  for (uint32_t i = 0U; i < editor->cursor; ++i) {
    if (editor->data[i] == '\n') {
      ++(*line);
      *column = 0U;
    } else {
      ++(*column);
    }
  }
}

static uint32_t line_start(const nano_editor_t *editor, uint32_t line) {
  uint32_t current = 0U;
  for (uint32_t i = 0U; i < editor->length; ++i) {
    if (current == line) return i;
    if (editor->data[i] == '\n') ++current;
  }
  return editor->length;
}

static void move_vertical(nano_editor_t *editor, int direction) {
  uint32_t line;
  uint32_t column;
  cursor_line_column(editor, &line, &column);
  if (direction < 0 && line == 0U) return;
  if (direction > 0) {
    uint32_t next = line_start(editor, line + 1U);
    if (next == editor->length &&
        (editor->length == 0U || editor->data[editor->length - 1U] != '\n')) {
      return;
    }
    ++line;
  } else {
    --line;
  }
  uint32_t start = line_start(editor, line);
  uint32_t end = start;
  while (end < editor->length && editor->data[end] != '\n') ++end;
  editor->cursor = start + (column < end - start ? column : end - start);
}

int nano_editor_open(nano_editor_t *editor, const char *argument,
                     const char *cwd, uint32_t columns, uint32_t rows) {
  if (editor == 0) return -1;
  app_mem_zero(editor, sizeof(*editor));
  if (resolve_path(cwd, argument, editor->path) != 0) {
    copy_text(editor->status, sizeof(editor->status),
              "Invalid or protected path");
    return -1;
  }
  xaios_xbfs_stat_user_t stat;
  if (xaios_fs_stat(editor->path, &stat) == 0) {
    if (stat.type != XAIOS_FS_TYPE_FILE ||
        stat.size >= NANO_EDITOR_BUFFER_SIZE) {
      copy_text(editor->status, sizeof(editor->status),
                "File is not editable or exceeds 32 KiB");
      return -1;
    }
    int fd = xaios_fs_open(editor->path, XAIOS_XBFS_OPEN_READ);
    if (fd < 0) return -1;
    while (editor->length < stat.size) {
      int result = xaios_fs_read(fd, editor->data + editor->length,
                                 stat.size - editor->length);
      if (result <= 0) {
        (void)xaios_fs_close(fd);
        return -1;
      }
      editor->length += (uint32_t)result;
    }
    if (xaios_fs_close(fd) != 0) return -1;
  }
  editor->columns = columns < 20U ? 20U : columns;
  editor->rows = rows < 6U ? 6U : rows;
  editor->active = 1U;
  copy_text(editor->status, sizeof(editor->status), "File loaded");
  return 0;
}

int nano_editor_render(nano_editor_t *editor, char *output,
                       uint32_t output_capacity, uint32_t *output_size) {
  static const char title[] = "  XAIOS nano  ";
  static const char footer[] =
      "^O Write Out  ^X Exit  ^A Home  ^E End  Arrows Move";
  uint32_t used = 0U;
  uint32_t cursor_line;
  uint32_t cursor_column;
  uint32_t body_rows = editor->rows > 4U ? editor->rows - 4U : 1U;
  cursor_line_column(editor, &cursor_line, &cursor_column);
  if (cursor_line < editor->viewport_line) editor->viewport_line = cursor_line;
  if (cursor_line >= editor->viewport_line + body_rows) {
    editor->viewport_line = cursor_line - body_rows + 1U;
  }
  if (cursor_column < editor->viewport_column) {
    editor->viewport_column = cursor_column;
  } else if (cursor_column >= editor->viewport_column + editor->columns) {
    editor->viewport_column = cursor_column - editor->columns + 1U;
  }
  if (append_text(output, output_capacity, &used,
                  "\033[?25l\033[2J\033[H\033[44;97m") != 0 ||
      append_text_clipped(output, output_capacity, &used, title,
                          editor->columns) != 0 ||
      append_text_clipped(
          output, output_capacity, &used, editor->path,
          editor->columns > sizeof(title) - 1U
              ? editor->columns - (uint32_t)(sizeof(title) - 1U)
              : 0U) != 0 ||
      append_text(output, output_capacity, &used, "\033[K\033[0m\r\n") != 0) {
    return -1;
  }
  uint32_t position = line_start(editor, editor->viewport_line);
  for (uint32_t row = 0U; row < body_rows; ++row) {
    uint32_t column = 0U;
    while (position < editor->length && editor->data[position] != '\n') {
      uint8_t value = editor->data[position++];
      if (column >= editor->viewport_column &&
          column - editor->viewport_column < editor->columns &&
          value >= 32U && value != 127U &&
          append_bytes(output, output_capacity, &used, &value, 1U) != 0) {
        return -1;
      }
      ++column;
    }
    if (position < editor->length && editor->data[position] == '\n') ++position;
    if (append_text(output, output_capacity, &used, "\033[K\r\n") != 0) {
      return -1;
    }
  }
  if (append_text(output, output_capacity, &used, "\033[7m ") != 0 ||
      append_text_clipped(output, output_capacity, &used,
                          editor->confirm_exit != 0U
                              ? "Save modified buffer?  Y Yes  N No  ^C Cancel"
                              : editor->status,
                          editor->columns - 1U) != 0 ||
      append_text(output, output_capacity, &used, "\033[K\033[0m\r\n") != 0 ||
      append_text_clipped(output, output_capacity, &used, footer,
                          editor->columns) != 0 ||
      append_text(output, output_capacity, &used, "\033[K") != 0 ||
      append_text(output, output_capacity, &used, "\033[") != 0 ||
      append_u32(output, output_capacity, &used,
                 2U + cursor_line - editor->viewport_line) != 0 ||
      append_text(output, output_capacity, &used, ";") != 0 ||
      append_u32(output, output_capacity, &used,
                 cursor_column - editor->viewport_column + 1U) != 0 ||
      append_text(output, output_capacity, &used, "H\033[?25h") != 0) {
    return -1;
  }
  *output_size = used;
  return 0;
}

int nano_editor_input(nano_editor_t *editor, const uint8_t *input,
                      uint32_t input_size, uint32_t *should_exit) {
  *should_exit = 0U;
  for (uint32_t i = 0U; i < input_size; ++i) {
    uint8_t value = input[i];
    if (value == '\n' && editor->ignore_lf != 0U) {
      editor->ignore_lf = 0U;
      continue;
    }
    editor->ignore_lf = 0U;
    if (editor->confirm_exit != 0U) {
      if (value == 'y' || value == 'Y') {
        if (editor_save(editor) == 0) {
          *should_exit = 1U;
        } else {
          editor->confirm_exit = 0U;
        }
      } else if (value == 'n' || value == 'N') {
        *should_exit = 1U;
      } else if (value == 3U || value == 27U) {
        editor->confirm_exit = 0U;
        copy_text(editor->status, sizeof(editor->status), "Exit cancelled");
      }
      continue;
    }
    if (editor->escape_state == 1U) {
      editor->escape_state = value == '[' ? 2U : 0U;
      continue;
    }
    if (editor->escape_state == 2U) {
      if (value == '3') {
        editor->escape_state = 3U;
        continue;
      }
      editor->escape_state = 0U;
      if (value == 'A') move_vertical(editor, -1);
      else if (value == 'B') move_vertical(editor, 1);
      else if (value == 'C' && editor->cursor < editor->length) ++editor->cursor;
      else if (value == 'D' && editor->cursor != 0U) --editor->cursor;
      else if (value == 'H') {
        while (editor->cursor != 0U &&
               editor->data[editor->cursor - 1U] != '\n') --editor->cursor;
      } else if (value == 'F') {
        while (editor->cursor < editor->length &&
               editor->data[editor->cursor] != '\n') ++editor->cursor;
      }
      continue;
    }
    if (editor->escape_state == 3U) {
      editor->escape_state = 0U;
      if (value == '~' && editor->cursor < editor->length) {
        for (uint32_t j = editor->cursor + 1U; j < editor->length; ++j) {
          editor->data[j - 1U] = editor->data[j];
        }
        --editor->length;
        editor->dirty = 1U;
        copy_text(editor->status, sizeof(editor->status), "Modified");
      }
      continue;
    }
    if (value == 27U) {
      editor->escape_state = 1U;
    } else if (value == 15U) {
      (void)editor_save(editor);
    } else if (value == 24U) {
      if (editor->dirty != 0U) editor->confirm_exit = 1U;
      else *should_exit = 1U;
    } else if (value == 1U) {
      while (editor->cursor != 0U && editor->data[editor->cursor - 1U] != '\n')
        --editor->cursor;
    } else if (value == 5U) {
      while (editor->cursor < editor->length &&
             editor->data[editor->cursor] != '\n') ++editor->cursor;
    } else if (value == 8U || value == 127U) {
      if (editor->cursor != 0U) {
        for (uint32_t j = editor->cursor; j < editor->length; ++j) {
          editor->data[j - 1U] = editor->data[j];
        }
        --editor->cursor;
        --editor->length;
        editor->dirty = 1U;
      }
    } else if (value == 4U) {
      if (editor->cursor < editor->length) {
        for (uint32_t j = editor->cursor + 1U; j < editor->length; ++j) {
          editor->data[j - 1U] = editor->data[j];
        }
        --editor->length;
        editor->dirty = 1U;
      }
    } else if ((value == '\r' || value == '\n' ||
                (value >= 32U && value <= 126U)) &&
               editor->length + 1U < NANO_EDITOR_BUFFER_SIZE) {
      if (value == '\r') {
        value = '\n';
        editor->ignore_lf = 1U;
      }
      for (uint32_t j = editor->length; j > editor->cursor; --j) {
        editor->data[j] = editor->data[j - 1U];
      }
      editor->data[editor->cursor++] = value;
      ++editor->length;
      editor->dirty = 1U;
      copy_text(editor->status, sizeof(editor->status), "Modified");
    } else if (editor->length + 1U >= NANO_EDITOR_BUFFER_SIZE) {
      copy_text(editor->status, sizeof(editor->status), "Buffer full (32 KiB)");
    }
  }
  return 0;
}

void nano_editor_resize(nano_editor_t *editor, uint32_t columns,
                        uint32_t rows) {
  if (editor == 0) return;
  editor->columns = columns < 20U ? 20U : columns;
  editor->rows = rows < 6U ? 6U : rows;
}
