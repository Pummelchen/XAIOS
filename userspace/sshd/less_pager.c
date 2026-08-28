#include "less_pager.h"

#include "ssh_utils.h"
#include <xaios_user.h>

#define LESS_PAGER_FILE_MAX UINT32_C(131072)

static uint8_t g_less_file[LESS_PAGER_FILE_MAX];

static int append_bytes(char *output, uint32_t capacity, uint32_t *used,
                        const void *data, uint32_t length) {
  if (*used > capacity || length > capacity - *used) return -1;
  ssh_mem_copy(output + *used, data, length);
  *used += length;
  return 0;
}

static int append_text(char *output, uint32_t capacity, uint32_t *used,
                       const char *text) {
  return append_bytes(output, capacity, used, text, ssh_str_len(text));
}

static int append_u32(char *output, uint32_t capacity, uint32_t *used,
                      uint32_t value) {
  char digits[10];
  uint32_t count = 0U;
  do {
    digits[count++] = (char)('0' + value % 10U);
    value /= 10U;
  } while (value != 0U);
  while (count != 0U)
    if (append_bytes(output, capacity, used, &digits[--count], 1U) != 0)
      return -1;
  return 0;
}

static int protected_path(const char *path) {
  static const char control[] = "/state/control";
  if (ssh_str_eq(path, "/state/xaios_host_key") ||
      ssh_str_eq(path, "/etc/xaios_sshd_users") ||
      ssh_str_eq(path, "/etc/xaios_authorized_keys") ||
      ssh_str_eq(path, "/etc/xaios_ssh_client_identity")) return 1;
  for (uint32_t i = 0U; i < sizeof(control) - 1U; ++i)
    if (path[i] != control[i]) return 0;
  return path[sizeof(control) - 1U] == '\0' ||
         path[sizeof(control) - 1U] == '/';
}

static int resolve_path(const char *cwd, const char *argument, char *output) {
  char combined[LESS_PAGER_PATH_MAX];
  uint32_t used = 0U;
  if (cwd == 0 || argument == 0 || argument[0] == '\0') return -1;
  if (argument[0] != '/') {
    uint32_t cwd_length = ssh_str_len(cwd);
    if (cwd_length == 0U || cwd_length >= sizeof(combined)) return -1;
    ssh_mem_copy(combined, cwd, cwd_length);
    used = cwd_length;
    if (used > 1U && combined[used - 1U] != '/') combined[used++] = '/';
  }
  uint32_t argument_length = ssh_str_len(argument);
  if (argument_length + used >= sizeof(combined)) return -1;
  ssh_mem_copy(combined + used, argument, argument_length + 1U);
  if (combined[0] != '/') return -1;
  uint32_t output_length = 1U;
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
      while (output_length > 1U && output[output_length - 1U] != '/')
        --output_length;
      if (output_length > 1U) --output_length;
      output[output_length] = '\0';
      continue;
    }
    if (output_length > 1U) {
      if (output_length + 1U >= LESS_PAGER_PATH_MAX) return -1;
      output[output_length++] = '/';
    }
    if (length == 0U || length >= LESS_PAGER_PATH_MAX - output_length) return -1;
    ssh_mem_copy(output + output_length, combined + start, length);
    output_length += length;
    output[output_length] = '\0';
  }
  return protected_path(output) ? -1 : 0;
}

static int next_token(const char *command, uint32_t *position, char *output,
                      uint32_t capacity) {
  uint32_t used = 0U;
  while (command[*position] == ' ' || command[*position] == '\t') ++*position;
  if (command[*position] == '\0') return -1;
  while (command[*position] != '\0' && command[*position] != ' ' &&
         command[*position] != '\t') {
    if (used + 1U >= capacity) return -1;
    output[used++] = command[(*position)++];
  }
  output[used] = '\0';
  return 0;
}

static int load_file(less_pager_t *pager, uint32_t *length) {
  if (pager->size > sizeof(g_less_file) || xaios_fs_seek(pager->fd, 0U) != 0)
    return -1;
  uint32_t used = 0U;
  while ((uint64_t)used < pager->size) {
    uint32_t remaining = (uint32_t)(pager->size - used);
    uint32_t request = remaining > 16384U ? 16384U : remaining;
    int result = xaios_fs_read(pager->fd, g_less_file + used, request);
    if (result <= 0 || (uint32_t)result > pager->size - used) return -1;
    used += (uint32_t)result;
  }
  *length = used;
  return 0;
}

static uint32_t count_lines(uint32_t length) {
  if (length == 0U) return 0U;
  uint32_t lines = 1U;
  for (uint32_t i = 0U; i < length; ++i)
    if (g_less_file[i] == '\n' && i + 1U < length) ++lines;
  return lines;
}

static uint32_t line_offset(uint32_t length, uint32_t wanted) {
  if (wanted == 0U) return 0U;
  uint32_t line = 0U;
  for (uint32_t i = 0U; i < length; ++i) {
    if (g_less_file[i] == '\n' && ++line == wanted) return i + 1U;
  }
  return length;
}

static uint32_t page_rows(const less_pager_t *pager) {
  return pager->rows > 2U ? pager->rows - 1U : 1U;
}

int less_pager_open(less_pager_t *pager, const char *command, const char *cwd,
                    uint32_t columns, uint32_t rows) {
  char token[LESS_PAGER_PATH_MAX];
  char argument[LESS_PAGER_PATH_MAX];
  uint32_t position = 0U;
  ssh_mem_zero(pager, sizeof(*pager));
  pager->fd = -1;
  if (next_token(command, &position, token, sizeof(token)) != 0 ||
      !ssh_str_eq(token, "less")) return -1;
  if (next_token(command, &position, token, sizeof(token)) != 0) return -1;
  if (ssh_str_eq(token, "-N")) {
    pager->number_lines = 1U;
    if (next_token(command, &position, token, sizeof(token)) != 0) return -1;
  }
  uint32_t token_length = ssh_str_len(token);
  ssh_mem_copy(argument, token, token_length + 1U);
  if (next_token(command, &position, token, sizeof(token)) == 0 ||
      resolve_path(cwd, argument, pager->path) != 0) return -1;
  xaios_xbfs_stat_user_t stat;
  if (xaios_fs_stat(pager->path, &stat) != 0 ||
      stat.type != XAIOS_FS_TYPE_FILE || stat.size > LESS_PAGER_FILE_MAX)
    return -1;
  pager->fd = xaios_fs_open(pager->path, XAIOS_XBFS_OPEN_READ);
  if (pager->fd < 0) return -1;
  pager->size = stat.size;
  pager->columns = columns == 0U ? 80U : columns;
  pager->rows = rows == 0U ? 24U : rows;
  pager->active = 1U;
  return 0;
}

int less_pager_render(less_pager_t *pager, char *output,
                      uint32_t output_capacity, uint32_t *output_size) {
  uint32_t length = 0U;
  uint32_t used = 0U;
  if (pager == 0 || pager->active == 0U ||
      load_file(pager, &length) != 0) return -1;
  pager->total_lines = count_lines(length);
  if (pager->total_lines != 0U && pager->top_line >= pager->total_lines)
    pager->top_line = pager->total_lines - 1U;
  if (append_text(output, output_capacity, &used, "\033[2J\033[H") != 0)
    return -1;
  uint32_t position = line_offset(length, pager->top_line);
  uint32_t rows = page_rows(pager);
  for (uint32_t row = 0U; row < rows; ++row) {
    if (position >= length) {
      if (append_text(output, output_capacity, &used, "~\033[K\r\n") != 0)
        return -1;
      continue;
    }
    if (pager->number_lines != 0U) {
      if (append_u32(output, output_capacity, &used,
                     pager->top_line + row + 1U) != 0 ||
          append_text(output, output_capacity, &used, " ") != 0) return -1;
    }
    uint32_t columns = pager->columns > 1U ? pager->columns - 1U : 1U;
    uint32_t shown = 0U;
    while (position < length && g_less_file[position] != '\n') {
      uint8_t value = g_less_file[position++];
      if (value == '\r') continue;
      if (shown < columns) {
        char printable = value >= 32U && value != 127U ? (char)value : '?';
        if (append_bytes(output, output_capacity, &used, &printable, 1U) != 0)
          return -1;
        ++shown;
      }
    }
    if (position < length && g_less_file[position] == '\n') ++position;
    if (append_text(output, output_capacity, &used, "\033[K\r\n") != 0)
      return -1;
  }
  if (append_text(output, output_capacity, &used, "\033[7m") != 0 ||
      append_text(output, output_capacity, &used, pager->path) != 0)
    return -1;
  if (pager->search_mode != 0U) {
    if (append_text(output, output_capacity, &used, " / ") != 0 ||
        append_bytes(output, output_capacity, &used, pager->query,
                     pager->query_length) != 0) return -1;
  } else {
    uint32_t percent = pager->total_lines == 0U
                           ? 100U
                           : ((pager->top_line + rows) * 100U) /
                                 pager->total_lines;
    if (percent > 100U) percent = 100U;
    if (append_text(output, output_capacity, &used, "  ") != 0 ||
        append_u32(output, output_capacity, &used, percent) != 0 ||
        append_text(output, output_capacity, &used, "%") != 0) return -1;
  }
  if (append_text(output, output_capacity, &used, "\033[0m\033[K") != 0)
    return -1;
  *output_size = used;
  return 0;
}

static int line_contains(uint32_t start, uint32_t end, const char *query,
                         uint32_t query_length) {
  if (query_length == 0U || end - start < query_length) return 0;
  for (uint32_t at = start; at + query_length <= end; ++at) {
    uint32_t matched = 0U;
    while (matched < query_length &&
           g_less_file[at + matched] == (uint8_t)query[matched]) ++matched;
    if (matched == query_length) return 1;
  }
  return 0;
}

static void search_forward(less_pager_t *pager) {
  uint32_t length = 0U;
  if (load_file(pager, &length) != 0 || pager->query_length == 0U) return;
  uint32_t line = pager->top_line + 1U;
  uint32_t position = line_offset(length, line);
  while (position < length) {
    uint32_t end = position;
    while (end < length && g_less_file[end] != '\n') ++end;
    if (line_contains(position, end, pager->query, pager->query_length)) {
      pager->top_line = line;
      return;
    }
    position = end < length ? end + 1U : end;
    ++line;
  }
}

int less_pager_input(less_pager_t *pager, const uint8_t *input,
                     uint32_t input_size, uint32_t *should_exit) {
  *should_exit = 0U;
  for (uint32_t i = 0U; i < input_size; ++i) {
    uint8_t key = input[i];
    if (pager->search_mode != 0U) {
      if (key == 27U) {
        pager->search_mode = 0U;
      } else if (key == '\r' || key == '\n') {
        pager->search_mode = 0U;
        search_forward(pager);
      } else if (key == 8U || key == 127U) {
        if (pager->query_length != 0U)
          pager->query[--pager->query_length] = '\0';
      } else if (key >= 32U && key <= 126U &&
                 pager->query_length + 1U < sizeof(pager->query)) {
        pager->query[pager->query_length++] = (char)key;
        pager->query[pager->query_length] = '\0';
      }
      continue;
    }
    if (pager->escape_state == 1U) {
      pager->escape_state = key == '[' ? 2U : 0U;
      continue;
    }
    if (pager->escape_state == 2U) {
      if (key == 'A' && pager->top_line != 0U) --pager->top_line;
      else if (key == 'B') ++pager->top_line;
      else if (key == '5') pager->top_line =
          pager->top_line > page_rows(pager) ?
              pager->top_line - page_rows(pager) : 0U;
      else if (key == '6') pager->top_line += page_rows(pager);
      pager->escape_state = 0U;
      continue;
    }
    if (key == 27U) pager->escape_state = 1U;
    else if (key == 'q' || key == 3U) *should_exit = 1U;
    else if (key == 'j' || key == '\r' || key == '\n') ++pager->top_line;
    else if (key == 'k' && pager->top_line != 0U) --pager->top_line;
    else if (key == ' ' || key == 'f') pager->top_line += page_rows(pager);
    else if (key == 'b') pager->top_line =
        pager->top_line > page_rows(pager) ?
            pager->top_line - page_rows(pager) : 0U;
    else if (key == 'g') pager->top_line = 0U;
    else if (key == 'G') pager->top_line = pager->total_lines > page_rows(pager)
        ? pager->total_lines - page_rows(pager) : 0U;
    else if (key == '/') {
      pager->search_mode = 1U;
      pager->query_length = 0U;
      pager->query[0] = '\0';
    } else if (key == 'n') search_forward(pager);
  }
  return 0;
}

void less_pager_resize(less_pager_t *pager, uint32_t columns, uint32_t rows) {
  pager->columns = columns == 0U ? 80U : columns;
  pager->rows = rows == 0U ? 24U : rows;
}

void less_pager_close(less_pager_t *pager) {
  if (pager == 0) return;
  if (pager->fd >= 0) (void)xaios_fs_close(pager->fd);
  ssh_mem_zero(pager, sizeof(*pager));
  pager->fd = -1;
}
