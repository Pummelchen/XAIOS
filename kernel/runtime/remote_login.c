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
#include "remote_login_archive_internal.h"

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
#ifndef XAIOS_FAILURE_TEST_APP
#define XAIOS_FAILURE_TEST_APP 0
#endif

static uint64_t g_remote_login_sessions;
static uint64_t g_remote_login_commands;
static uint64_t g_remote_login_denials;
#define XAIOS_REMOTE_LOGIN_MAX_SESSIONS 64U
typedef struct remote_login_context {
  uint64_t session_id;
  char cwd[XAIOS_XBFS_PATH_MAX];
  uint32_t active;
  /* When this context was last named, on a counter that only goes up. It
     exists so a full table can give up its oldest entry instead of refusing
     everything -- see remote_login_context_get. */
  uint64_t last_used;
} remote_login_context_t;
static uint64_t g_remote_login_context_clock;
static uint64_t g_remote_login_context_evictions;
static remote_login_context_t
    g_remote_login_contexts[XAIOS_REMOTE_LOGIN_MAX_SESSIONS];
static char g_remote_login_default_cwd[XAIOS_XBFS_PATH_MAX] = "/";
static char *g_remote_login_cwd = g_remote_login_default_cwd;

const char *remote_login_cwd(void) { return g_remote_login_cwd; }

#if XAIOS_BOOT_TEST_APPS
/* remote_login_handle_cpio writes this header and the archive module reads it, so it has
   one home here and an extern declaration in the private header. */
const char g_remote_login_archive_magic[] = "XAIOSARCHIVE\n";
#endif

#if XAIOS_BOOT_TEST_APPS
static uint64_t u64_digits(uint64_t value) {
  uint64_t digits = 1U;
  while (value >= 10U) {
    value /= 10U;
    ++digits;
  }
  return digits;
}
#endif

uint64_t cstr_len(const char *text) {
  uint64_t len = 0;
  if (text == 0) {
    return 0;
  }
  while (text[len] != '\0') {
    ++len;
  }
  return len;
}

int string_equal(const char *lhs, const char *rhs) {
  if (lhs == 0 || rhs == 0) {
    return 0;
  }
  for (uint64_t i = 0;; ++i) {
    if (lhs[i] != rhs[i]) {
      return 0;
    }
    if (lhs[i] == '\0') {
      return 1;
    }
  }
}

void output_append(char *output, uint64_t capacity, uint64_t *offset,
                   const char *text) {
  if (output == 0 || offset == 0 || text == 0 || capacity == 0) {
    return;
  }
  for (uint64_t i = 0; text[i] != '\0' && *offset + 1U < capacity; ++i) {
    output[*offset] = text[i];
    ++(*offset);
  }
  output[*offset] = '\0';
}

xaios_status_t copy_cstr_range(char *dst, uint64_t dst_capacity,
                               const char *src, uint64_t src_len) {
  if (dst == 0 || src == 0 || dst_capacity == 0U) {
    return XAIOS_ERR_INVALID;
  }
  if (src_len + 1U > dst_capacity) {
    return XAIOS_ERR_NO_MEMORY;
  }
  for (uint64_t i = 0; i < src_len; ++i) {
    dst[i] = src[i];
  }
  dst[src_len] = '\0';
  return XAIOS_OK;
}

xaios_status_t copy_cstr(char *dst, uint64_t dst_capacity, const char *src) {
  if (src == 0) {
    if (dst_capacity > 0U) {
      dst[0] = '\0';
    }
    return XAIOS_ERR_INVALID;
  }
  return copy_cstr_range(dst, dst_capacity, src, cstr_len(src));
}

void output_append_u64(char *output, uint64_t capacity, uint64_t *offset,
                             uint64_t value) {
  char digits[24];
  uint64_t count = 0;
  if (value == 0U) {
    output_append(output, capacity, offset, "0");
    return;
  }
  while (value != 0U && count < sizeof(digits)) {
    digits[count] = (char)('0' + (value % 10U));
    value /= 10U;
    ++count;
  }
  while (count != 0U) {
    char one[2];
    --count;
    one[0] = digits[count];
    one[1] = '\0';
    output_append(output, capacity, offset, one);
  }
}

static uint64_t skip_ws(const char *text, uint64_t index) {
  if (text == 0) {
    return 0;
  }
  while (text[index] == ' ' || text[index] == '\t' || text[index] == '\n' ||
         text[index] == '\r') {
    ++index;
  }
  return index;
}

xaios_status_t token_next(const char *text, uint64_t *index, char *token,
                               uint64_t capacity) {
  if (text == 0 || index == 0 || token == 0 || capacity == 0) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t i = skip_ws(text, *index);
  if (text[i] == '\0') {
    token[0] = '\0';
    *index = i;
    return XAIOS_ERR_NOT_FOUND;
  }
  uint64_t length = 0U;
  char quote = '\0';
  while (text[i] != '\0') {
    char value = text[i];
    if (quote == '\0' &&
        (value == ' ' || value == '\t' || value == '\n' || value == '\r')) {
      break;
    }
    if (value == '\\' && quote != '\'') {
      if (text[i + 1U] == '\0') {
        token[0] = '\0';
        *index = i;
        return XAIOS_ERR_INVALID;
      }
      value = text[++i];
    } else if ((value == '\'' || value == '"') &&
               (quote == '\0' || quote == value)) {
      quote = quote == '\0' ? value : '\0';
      ++i;
      continue;
    }
    if (length + 1U >= capacity) {
      token[0] = '\0';
      *index = i;
      return XAIOS_ERR_NO_MEMORY;
    }
    token[length++] = value;
    ++i;
  }
  if (quote != '\0') {
    token[0] = '\0';
    *index = i;
    return XAIOS_ERR_INVALID;
  }
  token[length] = '\0';
  *index = i;
  return XAIOS_OK;
}

xaios_status_t remote_ensure_parent(const char *path) {
  uint64_t len = cstr_len(path);
  if (len == 0U) {
    return XAIOS_ERR_INVALID;
  }
  if (len == 1U && path[0] == '/') {
    return XAIOS_OK;
  }
  if (path[len - 1U] == '/') {
    return XAIOS_ERR_INVALID;
  }
  uint64_t parent_len = len - 1U;
  while (parent_len > 0U && path[parent_len] != '/') {
    --parent_len;
  }
  char parent[XAIOS_XBFS_PATH_MAX];
  xaios_xbfs_stat_t parent_stat;
  if (parent_len == 0U) {
    if (copy_cstr(parent, sizeof(parent), "/") != XAIOS_OK) {
      return XAIOS_ERR_INVALID;
    }
  } else if (parent_len == 1U) {
    if (copy_cstr(parent, sizeof(parent), "/") != XAIOS_OK) {
      return XAIOS_ERR_INVALID;
    }
  } else {
    if (copy_cstr_range(parent, sizeof(parent), path, parent_len) != XAIOS_OK) {
      return XAIOS_ERR_INVALID;
    }
  }
  return xaiboot_fs_stat(parent, &parent_stat) == XAIOS_OK &&
                     parent_stat.type == 1U
             ? XAIOS_OK
             : XAIOS_ERR_INVALID;
}

xaios_status_t command_fail(char *output, uint64_t output_capacity,
                                 uint64_t *output_bytes,
                                 const char *message) {
  output_append(output, output_capacity, output_bytes, message);
  output_append(output, output_capacity, output_bytes, "\n");
  return XAIOS_ERR_INVALID;
}

xaios_status_t output_append_char(char *output, uint64_t capacity,
                                  uint64_t *offset, char value) {
  if (output == 0 || offset == 0 || capacity == 0U) {
    return XAIOS_ERR_INVALID;
  }
  if (*offset + 1U >= capacity) {
    return XAIOS_ERR_NO_MEMORY;
  }
  output[*offset] = value;
  ++(*offset);
  output[*offset] = '\0';
  return XAIOS_OK;
}

static void copy_remainder(const char *text, uint64_t index, char *out,
                          uint64_t out_capacity) {
  uint64_t i = 0;
  if (out == 0 || out_capacity == 0U) {
    return;
  }
  if (text == 0) {
    out[0] = '\0';
    return;
  }
  index = skip_ws(text, index);
  while (text[index] != '\0' && i + 1U < out_capacity) {
    out[i] = text[index];
    ++i;
    ++index;
  }
  out[i] = '\0';
}

void remote_login_log_failure(const char *operation, const char *reason,
                                   xaios_status_t status) {
  if (operation == 0) {
    return;
  }
  klog("remote-login: operation=%s failed reason=%s rc=%d\n", operation,
       reason == 0 ? "unknown" : reason, status);
}

int has_more_args(const char *text, uint64_t index) {
  return text != 0 && text[skip_ws(text, index)] != '\0';
}

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
static xaios_status_t buffer_append_char(char *buffer, uint64_t capacity,
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

static xaios_status_t buffer_append_u64(char *buffer, uint64_t capacity,
                                      uint64_t *offset, uint64_t value) {
  char digits[24];
  uint64_t count = 0;
  if (value == 0U) {
    return buffer_append_char(buffer, capacity, offset, '0');
  }
  while (value != 0U && count < sizeof(digits)) {
    digits[count] = (char)('0' + (value % 10U));
    value /= 10U;
    ++count;
  }
  while (count != 0U) {
    char c = digits[count - 1U];
    --count;
    if (buffer_append_char(buffer, capacity, offset, c) != XAIOS_OK) {
      return XAIOS_ERR_NO_MEMORY;
    }
  }
  return XAIOS_OK;
}

xaios_status_t remote_login_buffer_append_text(char *buffer, uint64_t capacity,
                                       uint64_t *offset, const char *text) {
  if (buffer == 0 || text == 0 || offset == 0 || capacity == 0U) {
    return XAIOS_ERR_INVALID;
  }
  for (uint64_t i = 0; text[i] != '\0'; ++i) {
    if (buffer_append_char(buffer, capacity, offset, text[i]) != XAIOS_OK) {
      return XAIOS_ERR_NO_MEMORY;
    }
  }
  return XAIOS_OK;
}

static xaios_status_t parse_u64_token(const char *text, uint64_t *value,
                                    uint64_t *consumed) {
  if (text == 0 || value == 0 || consumed == 0 || text[0] == '\0') {
    return XAIOS_ERR_INVALID;
  }
  if (text[0] < '0' || text[0] > '9') {
    return XAIOS_ERR_INVALID;
  }
  *value = 0;
  *consumed = 0;
  for (uint64_t i = 0; text[i] != '\0'; ++i) {
    char ch = text[i];
    uint64_t digit;
    if (ch < '0' || ch > '9') {
      *consumed = i;
      return XAIOS_OK;
    }
    digit = (uint64_t)(ch - '0');
    if (*value > (UINT64_MAX - digit) / 10U) {
      return XAIOS_ERR_INVALID;
    }
    *value = (*value * 10U) + digit;
    *consumed = i + 1U;
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

xaios_status_t archive_append_entry(char *archive, uint64_t archive_capacity,
                                    uint64_t *archive_size,
                                    char kind, const char *path,
                                    const char *data,
                                    uint64_t data_size) {
  uint64_t path_len;
  uint64_t required = 0U;
  if (archive == 0 || archive_size == 0 || path == 0 ||
      (data_size > 0U && data == 0)) {
    return XAIOS_ERR_INVALID;
  }
  path_len = cstr_len(path);
  if (path_len == 0U || path_len >= XAIOS_XBFS_PATH_MAX) {
    return XAIOS_ERR_INVALID;
  }
  if (kind != 'F' && kind != 'D') {
    return XAIOS_ERR_INVALID;
  }
  required = 1U + 1U + u64_digits(path_len) + 1U + u64_digits(data_size) +
             1U + path_len + 1U + data_size + 1U;
  if (*archive_size + required >= archive_capacity) {
    return XAIOS_ERR_NO_MEMORY;
  }
  if (path == 0 || path_len == 0U) {
    return XAIOS_ERR_INVALID;
  }
  archive[*archive_size] = kind;
  ++(*archive_size);
  archive[*archive_size] = ' ';
  ++(*archive_size);
  if (buffer_append_u64(archive, archive_capacity, archive_size, path_len) !=
      XAIOS_OK) {
    return XAIOS_ERR_NO_MEMORY;
  }
  if (buffer_append_char(archive, archive_capacity, archive_size, ' ') != XAIOS_OK) {
    return XAIOS_ERR_NO_MEMORY;
  }
  if (buffer_append_u64(archive, archive_capacity, archive_size, data_size) !=
      XAIOS_OK) {
    return XAIOS_ERR_NO_MEMORY;
  }
  if (buffer_append_char(archive, archive_capacity, archive_size, ' ') != XAIOS_OK) {
    return XAIOS_ERR_NO_MEMORY;
  }
  if (remote_login_buffer_append_text(archive, archive_capacity, archive_size, path) != XAIOS_OK) {
    return XAIOS_ERR_NO_MEMORY;
  }
  if (buffer_append_char(archive, archive_capacity, archive_size, '\n') != XAIOS_OK) {
    return XAIOS_ERR_NO_MEMORY;
  }
  for (uint64_t i = 0; i < data_size; ++i) {
    if (buffer_append_char(archive, archive_capacity, archive_size, data[i]) != XAIOS_OK) {
      return XAIOS_ERR_NO_MEMORY;
    }
  }
  archive[*archive_size] = '\n';
  ++(*archive_size);
  return XAIOS_OK;
}

xaios_status_t archive_parse_entry(const char *line, uint64_t line_size,
                                   char *kind, uint64_t *data_size,
                                   uint64_t *path_len, char *path,
                                   uint64_t path_capacity) {
  uint64_t idx;
  uint64_t consumed = 0U;
  if (line == 0 || kind == 0 || data_size == 0 || path_len == 0 ||
      path == 0 || path_capacity == 0U || line_size == 0U) {
    return XAIOS_ERR_INVALID;
  }
  if (line[0] != 'F' && line[0] != 'D') {
    return XAIOS_ERR_INVALID;
  }
  if (line[1] != ' ') {
    return XAIOS_ERR_INVALID;
  }
  idx = 2U;
  if (parse_u64_token(line + idx, path_len, &consumed) != XAIOS_OK ||
      consumed == 0U || line[idx + consumed] != ' ') {
    return XAIOS_ERR_INVALID;
  }
  idx += consumed + 1U;
  if (parse_u64_token(line + idx, data_size, &consumed) != XAIOS_OK ||
      consumed == 0U || line[idx + consumed] != ' ') {
    return XAIOS_ERR_INVALID;
  }
  idx += consumed + 1U;
  if (*path_len == 0U || *path_len >= path_capacity ||
      idx + *path_len != line_size) {
    return XAIOS_ERR_INVALID;
  }
  if (copy_cstr_range(path, path_capacity, line + idx, *path_len) != XAIOS_OK) {
    return XAIOS_ERR_NO_MEMORY;
  }
  *kind = line[0];
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

xaios_status_t path_join(char *out, uint64_t out_capacity, const char *base,
                         const char *name) {
  if (out == 0 || out_capacity == 0U || base == 0 || name == 0) {
    return XAIOS_ERR_INVALID;
  }
  if (string_equal(name, ".") == 1U || string_equal(name, "..") == 1U) {
    return copy_cstr(out, out_capacity, name);
  }
  uint64_t base_len = cstr_len(base);
  uint64_t name_len = cstr_len(name);
  if (base_len == 0U || name_len == 0U ||
      (base_len + name_len + 1U) > out_capacity ||
      (base_len + name_len + 2U) > out_capacity) {
    return XAIOS_ERR_NO_MEMORY;
  }
  if (string_equal(base, "/") == 1U) {
    out[0] = '/';
    (void)copy_cstr_range(out + 1U, out_capacity - 1U, name, name_len);
    return XAIOS_OK;
  }
  out[0] = '\0';
  if (copy_cstr_range(out, out_capacity, base, base_len) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  if (out[base_len - 1U] != '/') {
    if (base_len + 1U >= out_capacity) {
      return XAIOS_ERR_NO_MEMORY;
    }
    out[base_len] = '/';
    ++base_len;
  }
  if (base_len + name_len + 1U > out_capacity) {
    return XAIOS_ERR_NO_MEMORY;
  }
  for (uint64_t i = 0; i < name_len; ++i) {
    out[base_len + i] = name[i];
  }
  out[base_len + name_len] = '\0';
  return XAIOS_OK;
}

static int path_is_same_or_child(const char *parent, const char *path) {
  uint64_t parent_len = cstr_len(parent);
  if (parent_len == 0U || path == 0) return 0;
  for (uint64_t i = 0U; i < parent_len; ++i) {
    if (parent[i] != path[i]) return 0;
  }
  return path[parent_len] == '\0' || path[parent_len] == '/';
}

static xaios_status_t copy_file_path(const char *src, const char *dst) {
  char buffer[512];
  int64_t src_fd = xaiboot_fs_open(src, XAIOS_XBFS_OPEN_READ);
  if (src_fd < 0) return XAIOS_ERR_NOT_FOUND;
  int64_t dst_fd = xaiboot_fs_open(
      dst, XAIOS_XBFS_OPEN_WRITE | XAIOS_XBFS_OPEN_CREATE |
               XAIOS_XBFS_OPEN_TRUNCATE);
  if (dst_fd < 0) {
    (void)xaiboot_fs_close((uint32_t)src_fd);
    return XAIOS_ERR_INVALID;
  }
  xaios_status_t status = XAIOS_OK;
  for (;;) {
    int64_t got = xaiboot_fs_read_fd((uint32_t)src_fd, buffer, sizeof(buffer));
    if (got < 0) {
      status = XAIOS_ERR_IO;
      break;
    }
    if (got == 0) break;
    int64_t written =
        xaiboot_fs_write_fd((uint32_t)dst_fd, buffer, (uint64_t)got);
    if (written != got) {
      status = XAIOS_ERR_IO;
      break;
    }
  }
  if (xaiboot_fs_close((uint32_t)src_fd) != XAIOS_OK) status = XAIOS_ERR_IO;
  if (xaiboot_fs_close((uint32_t)dst_fd) != XAIOS_OK) status = XAIOS_ERR_IO;
  return status;
}

static xaios_status_t copy_path_recursive(const char *src, const char *dst,
                                         int recursive) {
  xaios_xbfs_stat_t src_stat;
  xaios_xbfs_stat_t dst_stat;
  if (xaiboot_fs_stat(src, &src_stat) != XAIOS_OK) return XAIOS_ERR_NOT_FOUND;
  if (src_stat.type == 2U) {
    if (remote_ensure_parent(dst) != XAIOS_OK) return XAIOS_ERR_INVALID;
    return copy_file_path(src, dst);
  }
  if (src_stat.type != 1U || recursive == 0) return XAIOS_ERR_INVALID;
  if (path_is_same_or_child(src, dst) != 0) return XAIOS_ERR_INVALID;
  if (xaiboot_fs_stat(dst, &dst_stat) != XAIOS_OK) {
    if (remote_ensure_parent(dst) != XAIOS_OK ||
        xaiboot_fs_mkdir(dst) != XAIOS_OK) {
      return XAIOS_ERR_INVALID;
    }
  } else if (dst_stat.type != 1U) {
    return XAIOS_ERR_INVALID;
  }

  char listing[XAIOS_XBFS_MAX_LIST_BYTES];
  uint64_t listing_size = 0U;
  if (xaiboot_fs_list(src, listing, sizeof(listing), &listing_size) != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  uint64_t line_start = 0U;
  while (line_start < listing_size) {
    uint64_t line_end = line_start;
    while (line_end < listing_size && listing[line_end] != '\n') ++line_end;
    if (line_end > line_start) {
      char name[XAIOS_XBFS_PATH_MAX];
      char child_src[XAIOS_XBFS_PATH_MAX];
      char child_dst[XAIOS_XBFS_PATH_MAX];
      if (copy_cstr_range(name, sizeof(name), listing + line_start,
                          line_end - line_start) != XAIOS_OK ||
          path_join(child_src, sizeof(child_src), src, name) != XAIOS_OK ||
          path_join(child_dst, sizeof(child_dst), dst, name) != XAIOS_OK ||
          copy_path_recursive(child_src, child_dst, recursive) != XAIOS_OK) {
        return XAIOS_ERR_IO;
      }
    }
    line_start = line_end + 1U;
  }
  return XAIOS_OK;
}

static xaios_status_t handle_cp(const char *args, char *output,
                              uint64_t output_capacity, uint64_t *output_bytes) {
  char operands[17][XAIOS_XBFS_PATH_MAX];
  uint32_t operand_count = 0U;
  uint64_t index = 0U;
  int recursive = 0;
  int end_options = 0;
  char token[XAIOS_XBFS_PATH_MAX];
  while (token_next(args, &index, token, sizeof(token)) == XAIOS_OK) {
    if (end_options == 0 && string_equal(token, "--")) {
      end_options = 1;
    } else if (end_options == 0 &&
               (string_equal(token, "-R") || string_equal(token, "-r"))) {
      recursive = 1;
    } else if (end_options == 0 && token[0] == '-') {
      return command_fail(output, output_capacity, output_bytes,
                          "cp: unsupported option");
    } else if (operand_count >= 17U ||
               copy_cstr(operands[operand_count], sizeof(operands[0]), token) !=
                   XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "cp: too many operands");
    } else {
      ++operand_count;
    }
  }
  if (operand_count < 2U) {
    return command_fail(output, output_capacity, output_bytes,
                        "cp: missing file operand");
  }

  char destination[XAIOS_XBFS_PATH_MAX];
  if (remote_path_resolve(g_remote_login_cwd, operands[operand_count - 1U],
                          destination, sizeof(destination)) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "cp: invalid destination");
  }
  xaios_xbfs_stat_t destination_stat;
  int destination_is_dir =
      xaiboot_fs_stat(destination, &destination_stat) == XAIOS_OK &&
      destination_stat.type == 1U;
  if (operand_count > 2U && destination_is_dir == 0) {
    return command_fail(output, output_capacity, output_bytes,
                        "cp: destination is not a directory");
  }
  for (uint32_t operand = 0U; operand + 1U < operand_count; ++operand) {
    char source[XAIOS_XBFS_PATH_MAX];
    char target[XAIOS_XBFS_PATH_MAX];
    if (remote_path_resolve(g_remote_login_cwd, operands[operand], source,
                            sizeof(source)) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "cp: invalid source");
    }
    if (destination_is_dir != 0) {
      char basename[XAIOS_XBFS_PATH_MAX];
      if (remote_login_path_basename(source, basename, sizeof(basename)) != XAIOS_OK ||
          path_join(target, sizeof(target), destination, basename) != XAIOS_OK) {
        return command_fail(output, output_capacity, output_bytes,
                            "cp: destination path too long");
      }
    } else if (copy_cstr(target, sizeof(target), destination) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "cp: invalid destination");
    }
    if (copy_path_recursive(source, target, recursive) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "cp: copy failed");
    }
  }
  output[0] = '\0';
  return XAIOS_OK;
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

static xaios_status_t handle_pwd(char *output, uint64_t output_capacity,
                               uint64_t *output_bytes) {
  output_append(output, output_capacity, output_bytes, g_remote_login_cwd);
  output_append(output, output_capacity, output_bytes, "\n");
  return XAIOS_OK;
}

static xaios_status_t handle_cd(const char *arg, char *output,
                              uint64_t output_capacity,
                              uint64_t *output_bytes) {
  const char *target = (arg == 0 || arg[0] == '\0') ? "/" : arg;
  char resolved[XAIOS_XBFS_PATH_MAX];
  xaios_xbfs_stat_t stat;
  if (remote_path_resolve(g_remote_login_cwd, target, resolved,
                         sizeof(resolved)) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes, "cd: invalid path");
  }
  if (string_equal(resolved, "/") == 1U) {
    if (copy_cstr(g_remote_login_cwd, XAIOS_XBFS_PATH_MAX, resolved) !=
        XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "cd: path too long");
    }
    output_append(output, output_capacity, output_bytes, resolved);
    output_append(output, output_capacity, output_bytes, "\n");
    return XAIOS_OK;
  }
  if ((xaiboot_fs_stat(resolved, &stat) != XAIOS_OK || stat.type != 1U) &&
      initramfs_directory_exists(resolved) == 0) {
    return command_fail(output, output_capacity, output_bytes,
                        "cd: not a directory");
  }
  if (copy_cstr(g_remote_login_cwd, XAIOS_XBFS_PATH_MAX, resolved) !=
      XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "cd: path too long");
  }
  output_append(output, output_capacity, output_bytes, resolved);
  output_append(output, output_capacity, output_bytes, "\n");
  return XAIOS_OK;
}

#if XAIOS_BOOT_TEST_APPS
static xaios_status_t handle_stat(const char *arg, char *output,
                                uint64_t output_capacity,
                                uint64_t *output_bytes) {
  char resolved[XAIOS_XBFS_PATH_MAX];
  xaios_xbfs_stat_t stat;
  if (arg == 0 || arg[0] == '\0') {
    return command_fail(output, output_capacity, output_bytes, "stat: missing path");
  }
  if (remote_path_resolve(g_remote_login_cwd, arg, resolved, sizeof(resolved)) !=
          XAIOS_OK ||
      xaiboot_fs_stat(resolved, &stat) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes, "stat: no such file");
  }
  output_append(output, output_capacity, output_bytes, "path=");
  output_append(output, output_capacity, output_bytes, resolved);
  output_append(output, output_capacity, output_bytes, "\n");
  output_append(output, output_capacity, output_bytes, "type=");
  output_append(output, output_capacity, output_bytes,
                stat.type == 1U ? "dir\n" : "file\n");
  output_append(output, output_capacity, output_bytes, "size=");
  output_append_u64(output, output_capacity, output_bytes, stat.size);
  output_append(output, output_capacity, output_bytes, "\n");
  output_append(output, output_capacity, output_bytes, "block_count=");
  output_append_u64(output, output_capacity, output_bytes, stat.block_count);
  output_append(output, output_capacity, output_bytes, "\n");
  output_append(output, output_capacity, output_bytes, "generation=");
  output_append_u64(output, output_capacity, output_bytes, stat.generation);
  output_append(output, output_capacity, output_bytes, "\n");
  output_append(output, output_capacity, output_bytes, "content_hash=");
  output_append_u64(output, output_capacity, output_bytes, stat.content_hash);
  output_append(output, output_capacity, output_bytes, "\n");
  return XAIOS_OK;
}

xaios_status_t mkdir_resolved(const char *path, int parents) {
  xaios_xbfs_stat_t stat;
  if (xaiboot_fs_stat(path, &stat) == XAIOS_OK) {
    return parents != 0 && stat.type == 1U ? XAIOS_OK : XAIOS_ERR_BUSY;
  }
  if (parents == 0) {
    return remote_ensure_parent(path) == XAIOS_OK ? xaiboot_fs_mkdir(path)
                                                  : XAIOS_ERR_NOT_FOUND;
  }
  char current[XAIOS_XBFS_PATH_MAX];
  uint64_t used = 1U;
  current[0] = '/';
  current[1] = '\0';
  for (uint64_t i = 1U;; ++i) {
    if (path[i] != '/' && path[i] != '\0') continue;
    uint64_t component_start = i;
    while (component_start > 0U && path[component_start - 1U] != '/') {
      --component_start;
    }
    uint64_t component_len = i - component_start;
    if (component_len != 0U) {
      if (used > 1U) current[used++] = '/';
      if (used + component_len >= sizeof(current)) return XAIOS_ERR_NO_MEMORY;
      for (uint64_t j = 0U; j < component_len; ++j) {
        current[used++] = path[component_start + j];
      }
      current[used] = '\0';
      if (xaiboot_fs_stat(current, &stat) == XAIOS_OK) {
        if (stat.type != 1U) return XAIOS_ERR_INVALID;
      } else if (xaiboot_fs_mkdir(current) != XAIOS_OK) {
        return XAIOS_ERR_IO;
      }
    }
    if (path[i] == '\0') break;
  }
  return XAIOS_OK;
}

static xaios_status_t handle_mkdir(const char *args, char *output,
                                 uint64_t output_capacity,
                                 uint64_t *output_bytes) {
  uint64_t index = 0U;
  uint32_t paths = 0U;
  int parents = 0;
  int end_options = 0;
  char token[XAIOS_XBFS_PATH_MAX];
  while (token_next(args, &index, token, sizeof(token)) == XAIOS_OK) {
    if (end_options == 0 && string_equal(token, "--")) {
      end_options = 1;
      continue;
    }
    if (end_options == 0 && string_equal(token, "-p")) {
      parents = 1;
      continue;
    }
    if (end_options == 0 && token[0] == '-') {
      return command_fail(output, output_capacity, output_bytes,
                          "mkdir: unsupported option");
    }
    char resolved[XAIOS_XBFS_PATH_MAX];
    if (remote_path_resolve(g_remote_login_cwd, token, resolved,
                            sizeof(resolved)) != XAIOS_OK ||
        mkdir_resolved(resolved, parents) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "mkdir: cannot create directory");
    }
    ++paths;
  }
  if (paths == 0U) {
    return command_fail(output, output_capacity, output_bytes,
                        "mkdir: missing operand");
  }
  output[0] = '\0';
  return XAIOS_OK;
}

static xaios_status_t handle_touch(const char *arg, char *output,
                                 uint64_t output_capacity, uint64_t *output_bytes) {
  char resolved[XAIOS_XBFS_PATH_MAX];
  int64_t fd = -1;
  if (arg == 0 || arg[0] == '\0') {
    return command_fail(output, output_capacity, output_bytes,
                       "touch: missing path");
  }
  if (remote_path_resolve(g_remote_login_cwd, arg, resolved, sizeof(resolved)) !=
          XAIOS_OK ||
      remote_ensure_parent(resolved) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "touch: failed");
  }
  fd = xaiboot_fs_open(resolved,
                       XAIOS_XBFS_OPEN_WRITE | XAIOS_XBFS_OPEN_CREATE |
                           XAIOS_XBFS_OPEN_TRUNCATE);
  if (fd < 0) {
    return command_fail(output, output_capacity, output_bytes,
                        "touch: failed");
  }
  if (xaiboot_fs_close((uint32_t)fd) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "touch: close failed");
  }
  output[0] = '\0';
  return XAIOS_OK;
}

static xaios_status_t cat_file(const char *resolved, int number_lines,
                              uint64_t *line_number, int *line_start,
                              char *output, uint64_t output_capacity,
                              uint64_t *output_bytes) {
  int64_t fd = xaiboot_fs_open(resolved, XAIOS_XBFS_OPEN_READ);
  if (fd < 0) return XAIOS_ERR_NOT_FOUND;
  char buffer[512];
  xaios_status_t status = XAIOS_OK;
  for (;;) {
    int64_t got = xaiboot_fs_read_fd((uint32_t)fd, buffer, sizeof(buffer));
    if (got < 0) {
      status = XAIOS_ERR_IO;
      break;
    }
    if (got == 0) break;
    for (int64_t i = 0; i < got; ++i) {
      if (number_lines != 0 && *line_start != 0) {
        output_append_u64(output, output_capacity, output_bytes, *line_number);
        output_append(output, output_capacity, output_bytes, "\t");
        ++(*line_number);
        *line_start = 0;
      }
      if (output_append_char(output, output_capacity, output_bytes,
                             buffer[(uint64_t)i]) != XAIOS_OK) {
        status = XAIOS_ERR_NO_MEMORY;
        break;
      }
      if (buffer[(uint64_t)i] == '\n') *line_start = 1;
    }
    if (status != XAIOS_OK) break;
  }
  if (xaiboot_fs_close((uint32_t)fd) != XAIOS_OK) status = XAIOS_ERR_IO;
  return status;
}

static xaios_status_t handle_cat(const char *args, char *output,
                               uint64_t output_capacity,
                               uint64_t *output_bytes) {
  uint64_t index = 0U;
  uint64_t line_number = 1U;
  uint32_t files = 0U;
  int number_lines = 0;
  int line_start = 1;
  int end_options = 0;
  char token[XAIOS_XBFS_PATH_MAX];
  while (token_next(args, &index, token, sizeof(token)) == XAIOS_OK) {
    if (end_options == 0 && string_equal(token, "--")) {
      end_options = 1;
      continue;
    }
    if (end_options == 0 && string_equal(token, "-n")) {
      number_lines = 1;
      continue;
    }
    if (end_options == 0 && token[0] == '-') {
      return command_fail(output, output_capacity, output_bytes,
                          "cat: unsupported option");
    }
    char resolved[XAIOS_XBFS_PATH_MAX];
    if (remote_path_resolve(g_remote_login_cwd, token, resolved,
                            sizeof(resolved)) != XAIOS_OK ||
        cat_file(resolved, number_lines, &line_number, &line_start, output,
                 output_capacity, output_bytes) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "cat: cannot read file");
    }
    ++files;
  }
  if (files == 0U) {
    return command_fail(output, output_capacity, output_bytes,
                        "cat: missing file operand");
  }
  return XAIOS_OK;
}

static xaios_status_t handle_write(const char *path_arg, const char *payload,
                                 char *output, uint64_t output_capacity,
                                 uint64_t *output_bytes) {
  char resolved[XAIOS_XBFS_PATH_MAX];
  uint64_t payload_len = payload == 0 ? 0U : cstr_len(payload);
  int64_t fd = -1;

  if (path_arg == 0 || path_arg[0] == '\0') {
    return command_fail(output, output_capacity, output_bytes,
                        "write: missing path");
  }
  if (remote_path_resolve(g_remote_login_cwd, path_arg, resolved,
                         sizeof(resolved)) != XAIOS_OK ||
      remote_ensure_parent(resolved) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "write: invalid path");
  }
  fd = xaiboot_fs_open(resolved, XAIOS_XBFS_OPEN_WRITE | XAIOS_XBFS_OPEN_CREATE |
                                  XAIOS_XBFS_OPEN_TRUNCATE);
  if (fd < 0) {
    return command_fail(output, output_capacity, output_bytes,
                        "write: failed to open");
  }
  if (payload_len != 0U) {
    int64_t written = xaiboot_fs_write_fd((uint32_t)fd, payload, payload_len);
    if (written < 0 || ((uint64_t)written) != payload_len) {
      (void)xaiboot_fs_close((uint32_t)fd);
      return command_fail(output, output_capacity, output_bytes,
                          "write: write failed");
    }
  }
  if (xaiboot_fs_close((uint32_t)fd) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "write: close failed");
  }
  output[0] = '\0';
  return XAIOS_OK;
}

xaios_status_t remote_login_path_basename(const char *path, char *basename,
                                  uint64_t basename_capacity) {
  uint64_t len = 0;
  if (path == 0 || basename == 0 || basename_capacity == 0U) {
    return XAIOS_ERR_INVALID;
  }
  len = cstr_len(path);
  if (len == 0U || (len == 1U && path[0] == '/')) {
    return XAIOS_ERR_INVALID;
  }
  while (len > 0U && path[len - 1U] == '/') {
    --len;
  }
  if (len == 0U) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t start = len;
  while (start > 0U && path[start - 1U] != '/') {
    --start;
  }
  return copy_cstr_range(basename, basename_capacity, path + start, len - start);
}

xaios_status_t ustar_parse_octal(const char *field, uint64_t width,
                                 uint64_t *value) {
  uint64_t result = 0U;
  uint64_t digits = 0U;
  if (field == 0 || value == 0) return XAIOS_ERR_INVALID;
  for (uint64_t i = 0U; i < width; ++i) {
    char c = field[i];
    if ((c == ' ' || c == '\0') && digits == 0U) continue;
    if (c == ' ' || c == '\0') break;
    if (c < '0' || c > '7' || result > (UINT64_MAX >> 3U))
      return XAIOS_ERR_INVALID;
    result = (result << 3U) | (uint64_t)(c - '0');
    ++digits;
  }
  *value = result;
  return XAIOS_OK;
}

int ustar_block_is_zero(const char *block) {
  for (uint64_t i = 0U; i < XAIOS_USTAR_BLOCK_SIZE; ++i)
    if (block[i] != '\0') return 0;
  return 1;
}

xaios_status_t ustar_header_path(const char *header, char *path,
                                 uint64_t capacity) {
  uint64_t name_len = 0U;
  uint64_t prefix_len = 0U;
  while (name_len < 100U && header[name_len] != '\0') ++name_len;
  while (prefix_len < 155U && header[345U + prefix_len] != '\0') ++prefix_len;
  if (name_len == 0U || prefix_len + (prefix_len != 0U ? 1U : 0U) + name_len +
                              1U > capacity)
    return XAIOS_ERR_INVALID;
  uint64_t used = 0U;
  for (uint64_t i = 0U; i < prefix_len; ++i) path[used++] = header[345U + i];
  if (prefix_len != 0U) path[used++] = '/';
  for (uint64_t i = 0U; i < name_len; ++i) path[used++] = header[i];
  path[used] = '\0';
  return XAIOS_OK;
}

int archive_path_is_safe(const char *path) {
  if (path == 0 || path[0] == '\0' || path[0] == '/' || path[0] == '\\')
    return 0;
  uint64_t component = 0U;
  for (uint64_t i = 0U;; ++i) {
    char c = path[i];
    if (c == '\\' || c == ':') return 0;
    if (c == '/' || c == '\0') {
      if (component == 2U && path[i - 2U] == '.' && path[i - 1U] == '.')
        return 0;
      component = 0U;
      if (c == '\0') break;
    } else {
      ++component;
    }
  }
  return 1;
}

xaios_status_t pax_extract_path(const char *data, uint64_t size,
                                char *path, uint64_t capacity) {
  uint64_t cursor = 0U;
  while (cursor < size) {
    uint64_t record_start = cursor;
    uint64_t record_size = 0U;
    uint64_t digits = 0U;
    while (cursor < size && data[cursor] >= '0' && data[cursor] <= '9') {
      if (record_size > (UINT64_MAX - 9U) / 10U) return XAIOS_ERR_INVALID;
      record_size = record_size * 10U + (uint64_t)(data[cursor] - '0');
      ++cursor;
      ++digits;
    }
    if (digits == 0U || cursor >= size || data[cursor] != ' ' ||
        record_size <= cursor - record_start + 1U ||
        record_size > size - record_start)
      return XAIOS_ERR_INVALID;
    uint64_t value_start = ++cursor;
    uint64_t record_end = record_start + record_size;
    if (record_end == 0U || data[record_end - 1U] != '\n')
      return XAIOS_ERR_INVALID;
    static const char key[] = "path=";
    int is_path = record_end - 1U - value_start >= sizeof(key) - 1U;
    for (uint64_t i = 0U; is_path != 0 && i < sizeof(key) - 1U; ++i)
      if (data[value_start + i] != key[i]) is_path = 0;
    if (is_path != 0) {
      uint64_t path_size = record_end - 1U - value_start - (sizeof(key) - 1U);
      if (path_size == 0U || path_size + 1U > capacity)
        return XAIOS_ERR_INVALID;
      for (uint64_t i = 0U; i < path_size; ++i)
        path[i] = data[value_start + sizeof(key) - 1U + i];
      path[path_size] = '\0';
    }
    cursor = record_end;
  }
  return XAIOS_OK;
}

static uint32_t gzip_read_le32(const uint8_t *data) {
  return (uint32_t)data[0] | ((uint32_t)data[1] << 8U) |
         ((uint32_t)data[2] << 16U) | ((uint32_t)data[3] << 24U);
}

xaios_status_t gzip_decode(const uint8_t *input, uint64_t input_size,
                           uint8_t *output, uint64_t output_capacity,
                           uint64_t *output_size) {
  if (input == 0 || output == 0 || output_size == 0 || input_size < 18U ||
      input[0] != UINT8_C(0x1f) || input[1] != UINT8_C(0x8b) ||
      input[2] != 8U || (input[3] & UINT8_C(0xe0)) != 0U)
    return XAIOS_ERR_INVALID;
  uint8_t flags = input[3];
  uint64_t cursor = 10U;
  if ((flags & 4U) != 0U) {
    if (input_size - cursor < 2U) return XAIOS_ERR_INVALID;
    uint64_t extra = (uint64_t)input[cursor] |
                     ((uint64_t)input[cursor + 1U] << 8U);
    cursor += 2U;
    if (extra > input_size - cursor) return XAIOS_ERR_INVALID;
    cursor += extra;
  }
  if ((flags & 8U) != 0U) {
    while (cursor < input_size && input[cursor] != 0U) ++cursor;
    if (cursor >= input_size) return XAIOS_ERR_INVALID;
    ++cursor;
  }
  if ((flags & 16U) != 0U) {
    while (cursor < input_size && input[cursor] != 0U) ++cursor;
    if (cursor >= input_size) return XAIOS_ERR_INVALID;
    ++cursor;
  }
  if ((flags & 2U) != 0U) {
    if (input_size - cursor < 2U) return XAIOS_ERR_INVALID;
    uint32_t expected_header_crc = (uint32_t)input[cursor] |
                                   ((uint32_t)input[cursor + 1U] << 8U);
    if ((xaios_crc32(input, cursor) & UINT32_C(0xffff)) !=
        expected_header_crc)
      return XAIOS_ERR_INVALID;
    cursor += 2U;
  }
  if (cursor > input_size - 8U) return XAIOS_ERR_INVALID;
  uint32_t expected_crc = gzip_read_le32(input + input_size - 8U);
  uint32_t expected_size = gzip_read_le32(input + input_size - 4U);
  if (expected_size > output_capacity ||
      xaios_inflate_raw(input + cursor, input_size - cursor - 8U, output,
                        output_capacity, output_size) != XAIOS_OK ||
      *output_size != expected_size ||
      xaios_crc32(output, *output_size) != expected_crc)
    return XAIOS_ERR_INVALID;
  return XAIOS_OK;
}

uint16_t remote_login_read_le16(const uint8_t *data) {
  return (uint16_t)((uint16_t)data[0] | ((uint16_t)data[1] << 8U));
}

uint32_t remote_login_read_le32(const uint8_t *data) {
  return (uint32_t)data[0] | ((uint32_t)data[1] << 8U) |
         ((uint32_t)data[2] << 16U) | ((uint32_t)data[3] << 24U);
}

void remote_login_write_le16(uint8_t *data, uint16_t value) {
  data[0] = (uint8_t)value;
  data[1] = (uint8_t)(value >> 8U);
}

void remote_login_write_le32(uint8_t *data, uint32_t value) {
  data[0] = (uint8_t)value;
  data[1] = (uint8_t)(value >> 8U);
  data[2] = (uint8_t)(value >> 16U);
  data[3] = (uint8_t)(value >> 24U);
}

xaios_status_t remote_login_zip_finish(uint8_t *archive, uint64_t capacity,
                                uint64_t *archive_size,
                                const xaios_zip_entry_t *entries,
                                uint32_t entry_count) {
  uint64_t central_offset = *archive_size;
  for (uint32_t i = 0U; i < entry_count; ++i) {
    uint64_t name_len = cstr_len(entries[i].name);
    if (capacity - *archive_size < 46U + name_len) return XAIOS_ERR_NO_MEMORY;
    uint8_t *header = archive + *archive_size;
    remote_login_bytes_zero(header, 46U);
    remote_login_write_le32(header, UINT32_C(0x02014b50));
    remote_login_write_le16(header + 4U, UINT16_C(0x031e));
    remote_login_write_le16(header + 6U, 20U);
    remote_login_write_le32(header + 16U, entries[i].crc32);
    remote_login_write_le32(header + 20U, entries[i].size);
    remote_login_write_le32(header + 24U, entries[i].size);
    remote_login_write_le16(header + 28U, (uint16_t)name_len);
    remote_login_write_le32(header + 38U,
               entries[i].directory != 0U ? UINT32_C(0040755) << 16U
                                          : UINT32_C(0100644) << 16U);
    remote_login_write_le32(header + 42U, entries[i].local_offset);
    for (uint64_t j = 0U; j < name_len; ++j) header[46U + j] = entries[i].name[j];
    *archive_size += 46U + name_len;
  }
  uint64_t central_size = *archive_size - central_offset;
  if (entry_count > UINT16_MAX || central_offset > UINT32_MAX ||
      central_size > UINT32_MAX || capacity - *archive_size < 22U)
    return XAIOS_ERR_NO_MEMORY;
  uint8_t *end = archive + *archive_size;
  remote_login_bytes_zero(end, 22U);
  remote_login_write_le32(end, UINT32_C(0x06054b50));
  remote_login_write_le16(end + 8U, (uint16_t)entry_count);
  remote_login_write_le16(end + 10U, (uint16_t)entry_count);
  remote_login_write_le32(end + 12U, (uint32_t)central_size);
  remote_login_write_le32(end + 16U, (uint32_t)central_offset);
  *archive_size += 22U;
  return XAIOS_OK;
}

static xaios_status_t move_path(const char *src, const char *dst) {
  char resolved_src[XAIOS_XBFS_PATH_MAX];
  char resolved_dst[XAIOS_XBFS_PATH_MAX];
  if (src == 0 || dst == 0 || src[0] == '\0' || dst[0] == '\0')
    return XAIOS_ERR_INVALID;
  if (remote_path_resolve(g_remote_login_cwd, src, resolved_src,
                         sizeof(resolved_src)) != XAIOS_OK ||
      remote_path_resolve(g_remote_login_cwd, dst, resolved_dst,
                         sizeof(resolved_dst)) != XAIOS_OK)
    return XAIOS_ERR_INVALID;
  xaios_xbfs_stat_t destination;
  if (xaiboot_fs_stat(resolved_dst, &destination) == XAIOS_OK &&
      destination.type == 1U) {
    char basename[XAIOS_XBFS_PATH_MAX];
    char target[XAIOS_XBFS_PATH_MAX];
    if (remote_login_path_basename(resolved_src, basename, sizeof(basename)) != XAIOS_OK ||
        path_join(target, sizeof(target), resolved_dst, basename) != XAIOS_OK ||
        copy_cstr(resolved_dst, sizeof(resolved_dst), target) != XAIOS_OK)
      return XAIOS_ERR_INVALID;
  }
  if (path_is_same_or_child(resolved_src, resolved_dst) != 0 ||
      remote_ensure_parent(resolved_dst) != XAIOS_OK)
    return XAIOS_ERR_INVALID;
  return xaiboot_fs_rename(resolved_src, resolved_dst);
}

static xaios_status_t handle_mv(const char *args, char *output,
                              uint64_t output_capacity,
                              uint64_t *output_bytes) {
  char operands[17][XAIOS_XBFS_PATH_MAX];
  uint32_t count = 0U;
  uint64_t index = 0U;
  int end_options = 0;
  char token[XAIOS_XBFS_PATH_MAX];
  while (token_next(args, &index, token, sizeof(token)) == XAIOS_OK) {
    if (end_options == 0 && string_equal(token, "--")) {
      end_options = 1;
      continue;
    }
    if (end_options == 0 && token[0] == '-')
      return command_fail(output, output_capacity, output_bytes,
                          "mv: unsupported option");
    if (count >= 17U ||
        copy_cstr(operands[count], sizeof(operands[0]), token) != XAIOS_OK)
      return command_fail(output, output_capacity, output_bytes,
                          "mv: too many operands");
    ++count;
  }
  if (count < 2U)
    return command_fail(output, output_capacity, output_bytes,
                        "mv: missing operand");
  if (count > 2U) {
    char destination[XAIOS_XBFS_PATH_MAX];
    xaios_xbfs_stat_t stat;
    if (remote_path_resolve(g_remote_login_cwd, operands[count - 1U],
                            destination, sizeof(destination)) != XAIOS_OK ||
        xaiboot_fs_stat(destination, &stat) != XAIOS_OK || stat.type != 1U)
      return command_fail(output, output_capacity, output_bytes,
                          "mv: destination is not a directory");
  }
  for (uint32_t i = 0U; i + 1U < count; ++i) {
    if (move_path(operands[i], operands[count - 1U]) != XAIOS_OK)
      return command_fail(output, output_capacity, output_bytes, "mv: failed");
  }
  output[0] = '\0';
  return XAIOS_OK;
}

static xaios_status_t handle_rm_path(const char *arg, int recursive, int force) {
  char resolved[XAIOS_XBFS_PATH_MAX];
  xaios_xbfs_stat_t stat;
  if (arg == 0 || arg[0] == '\0' ||
      remote_path_resolve(g_remote_login_cwd, arg, resolved, sizeof(resolved)) !=
          XAIOS_OK || string_equal(resolved, "/")) {
    return XAIOS_ERR_INVALID;
  }
  if (xaiboot_fs_stat(resolved, &stat) != XAIOS_OK) {
    return force != 0 ? XAIOS_OK : XAIOS_ERR_NOT_FOUND;
  }
  if (stat.type == 1U && recursive == 0) return XAIOS_ERR_INVALID;
  if ((recursive != 0 ? xaiboot_fs_delete_tree(resolved)
                      : xaiboot_fs_delete(resolved)) != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  return XAIOS_OK;
}

static xaios_status_t handle_rm(const char *args, char *output,
                              uint64_t output_capacity,
                              uint64_t *output_bytes) {
  uint64_t index = 0U;
  uint32_t paths = 0U;
  int recursive = 0;
  int force = 0;
  int end_options = 0;
  char token[XAIOS_XBFS_PATH_MAX];
  while (token_next(args, &index, token, sizeof(token)) == XAIOS_OK) {
    if (end_options == 0 && string_equal(token, "--")) {
      end_options = 1;
      continue;
    }
    if (end_options == 0 && token[0] == '-') {
      for (uint64_t flag = 1U; token[flag] != '\0'; ++flag) {
        if (token[flag] == 'r' || token[flag] == 'R') recursive = 1;
        else if (token[flag] == 'f') force = 1;
        else {
          return command_fail(output, output_capacity, output_bytes,
                              "rm: unsupported option");
        }
      }
      continue;
    }
    if (handle_rm_path(token, recursive, force) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "rm: cannot remove path");
    }
    ++paths;
  }
  if (paths == 0U && force == 0) {
    return command_fail(output, output_capacity, output_bytes,
                        "rm: missing operand");
  }
  output[0] = '\0';
  return XAIOS_OK;
}

static xaios_status_t handle_rmdir(const char *args, char *output,
                                  uint64_t output_capacity,
                                  uint64_t *output_bytes) {
  uint64_t index = 0U;
  uint32_t paths = 0U;
  char token[XAIOS_XBFS_PATH_MAX];
  while (token_next(args, &index, token, sizeof(token)) == XAIOS_OK) {
    char resolved[XAIOS_XBFS_PATH_MAX];
    xaios_xbfs_stat_t stat;
    if (token[0] == '-' ||
        remote_path_resolve(g_remote_login_cwd, token, resolved,
                            sizeof(resolved)) != XAIOS_OK ||
        string_equal(resolved, "/") == 1U ||
        xaiboot_fs_stat(resolved, &stat) != XAIOS_OK || stat.type != 1U ||
        xaiboot_fs_delete(resolved) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "rmdir: cannot remove directory");
    }
    ++paths;
  }
  if (paths == 0U) {
    return command_fail(output, output_capacity, output_bytes,
                        "rmdir: missing operand");
  }
  output[0] = '\0';
  return XAIOS_OK;
}

static xaios_status_t handle_less(const char *args, char *output,
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
          buffer_append_char(files, sizeof(files), &files_used, ' ') != XAIOS_OK) {
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
  return handle_cat(cat_args, output, output_capacity, output_bytes);
}
#endif

#if !XAIOS_BOOT_TEST_APPS
typedef struct remote_app_definition {
  const char *command;
  const char *path;
  uint64_t capabilities;
  uint8_t raw_arguments;
  uint8_t pass_cwd;
  uint8_t report_completion;
} remote_app_definition_t;

#define REMOTE_APP(command_, path_, capabilities_)                            \
  {command_, path_, capabilities_, 0U, 0U, 1U}
#define REMOTE_TERMINAL_APP(command_, path_, capabilities_)                   \
  {command_, path_, capabilities_, 1U, 0U, 1U}
#define REMOTE_UTILITY_APP(command_, capabilities_)                           \
  {command_, "/bin/" command_, capabilities_, 1U, 1U, 0U}

static const remote_app_definition_t g_remote_apps[] = {
    REMOTE_APP("hello", "/bin/hello", XAIOS_CAP_LOG | XAIOS_CAP_EXIT),
    REMOTE_APP("helloworldc99", "/bin/helloworldc99",
               XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT),
    /* XAIOS_CAP_NET is what authorizes net_resolve. Without it xapt can open
       sockets but cannot turn a name into an address, so a configured host
       works only as a literal and every hostname fails identically whether or
       not it is DNSSEC-signed. */
    REMOTE_APP("xapt", "/bin/xapt",
     XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT | XAIOS_CAP_TIME |
         XAIOS_CAP_FS_READ | XAIOS_CAP_FS_WRITE |
         XAIOS_CAP_NET | XAIOS_CAP_NET_SOCKET |
         XAIOS_CAP_RANDOM |
         XAIOS_CAP_CONTROL_QUERY | XAIOS_CAP_CONTROL_ADMIN |
         XAIOS_CAP_UPDATE | XAIOS_CAP_ADMIN),
    REMOTE_TERMINAL_APP("nano", "/bin/nano",
     XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT | XAIOS_CAP_FS_READ |
         XAIOS_CAP_FS_WRITE | XAIOS_CAP_REMOTE_LOGIN),
    REMOTE_TERMINAL_APP("xtop", "/bin/xtop",
                        XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                            XAIOS_CAP_CONTROL_QUERY),
    REMOTE_TERMINAL_APP("pong", "/bin/pong",
                        XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT),
    /* Operator control surface. Arguments are forwarded verbatim to the
       control protocol, which authorizes them under the observer role. */
    {"xaiosctl", "/bin/xaiosctl",
     XAIOS_CAP_CONSOLE | XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_TIME |
         XAIOS_CAP_CONTROL_QUERY | XAIOS_CAP_STORAGE_READ,
     1U, 0U, 0U},
    REMOTE_APP("sysinfo", "/bin/sysinfo",
               XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_TIME),
    REMOTE_APP("systest", "/bin/systest",
     XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_FS_READ |
         XAIOS_CAP_FS_WRITE),
    REMOTE_APP("smptest", "/bin/smptest",
     XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_OSCTL | XAIOS_CAP_SMP |
         XAIOS_CAP_THREADS),
    REMOTE_APP("nettest", "/bin/nettest",
     XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_OSCTL | XAIOS_CAP_NET |
         XAIOS_CAP_TIME),
    REMOTE_APP("sshtest", "/bin/sshtest",
               XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_REMOTE_LOGIN),
    REMOTE_APP("lstm-xor", "/bin/lstm-xor",
               XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_CPU_AI |
                   XAIOS_CAP_ML),
    REMOTE_APP("mltest", "/bin/mltest",
               XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_CPU_AI |
                   XAIOS_CAP_ML),
    REMOTE_APP("posix-shell", "/bin/posix-shell",
               XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_REMOTE_LOGIN),
    REMOTE_APP("agenttest", "/bin/agenttest",
     XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_AGENT | XAIOS_CAP_CPU_AI |
         XAIOS_CAP_ML),
    REMOTE_UTILITY_APP("ls", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                XAIOS_CAP_FS_READ),
    REMOTE_UTILITY_APP("mkdir", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                   XAIOS_CAP_FS_READ | XAIOS_CAP_FS_WRITE),
    REMOTE_UTILITY_APP("touch", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                   XAIOS_CAP_FS_READ | XAIOS_CAP_FS_WRITE),
    REMOTE_UTILITY_APP("cp", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                XAIOS_CAP_FS_READ | XAIOS_CAP_FS_WRITE),
    REMOTE_UTILITY_APP("mv", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                XAIOS_CAP_FS_READ | XAIOS_CAP_FS_WRITE),
    REMOTE_UTILITY_APP("rm", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                XAIOS_CAP_FS_READ | XAIOS_CAP_FS_WRITE),
    REMOTE_UTILITY_APP("rmdir", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                   XAIOS_CAP_FS_READ | XAIOS_CAP_FS_WRITE),
    REMOTE_UTILITY_APP("stat", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                  XAIOS_CAP_FS_READ),
    REMOTE_UTILITY_APP("cat", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                 XAIOS_CAP_FS_READ),
    REMOTE_UTILITY_APP("head", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                  XAIOS_CAP_FS_READ),
    REMOTE_UTILITY_APP("tail", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                  XAIOS_CAP_FS_READ),
    REMOTE_UTILITY_APP("less", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                  XAIOS_CAP_FS_READ),
    REMOTE_UTILITY_APP("grep", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                  XAIOS_CAP_FS_READ),
    REMOTE_UTILITY_APP("find", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                  XAIOS_CAP_FS_READ),
    REMOTE_UTILITY_APP("sed", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                 XAIOS_CAP_FS_READ | XAIOS_CAP_FS_WRITE),
    REMOTE_UTILITY_APP("write", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                   XAIOS_CAP_FS_READ | XAIOS_CAP_FS_WRITE),
    REMOTE_UTILITY_APP("tar", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                 XAIOS_CAP_FS_READ | XAIOS_CAP_FS_WRITE),
    REMOTE_UTILITY_APP("cpio", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                  XAIOS_CAP_FS_READ | XAIOS_CAP_FS_WRITE),
    REMOTE_UTILITY_APP("zip", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                 XAIOS_CAP_FS_READ | XAIOS_CAP_FS_WRITE),
    REMOTE_UTILITY_APP("unzip", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                   XAIOS_CAP_FS_READ | XAIOS_CAP_FS_WRITE),
    REMOTE_UTILITY_APP("ps", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                XAIOS_CAP_CONTROL_QUERY),
    REMOTE_UTILITY_APP("df", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                XAIOS_CAP_CONTROL_QUERY |
                                XAIOS_CAP_STORAGE_READ),
    REMOTE_UTILITY_APP("du", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                XAIOS_CAP_FS_READ),
#if XAIOS_FAILURE_TEST_APP
    REMOTE_APP("app-fail", "/bin/app-fail", XAIOS_CAP_LOG | XAIOS_CAP_EXIT),
    REMOTE_APP("app-crash", "/bin/app-crash",
               XAIOS_CAP_LOG | XAIOS_CAP_EXIT),
#endif
};

static const remote_app_definition_t *remote_app_find(const char *command) {
  for (uint32_t i = 0U;
       i < sizeof(g_remote_apps) / sizeof(g_remote_apps[0]); ++i) {
    if (string_equal(command, g_remote_apps[i].command) != 0) {
      return &g_remote_apps[i];
    }
  }
  return 0;
}

static int line_has_prefix(const char *line, uint32_t length,
                           const char *prefix) {
  uint32_t i = 0U;
  if (line == 0 || prefix == 0) return 0;
  while (prefix[i] != '\0') {
    if (i >= length || line[i] != prefix[i]) return 0;
    ++i;
  }
  return 1;
}

static void append_app_log_lines(char *output, uint64_t output_capacity,
                                 uint64_t *output_bytes, const char *log,
                                 uint32_t log_bytes, const char *path) {
  uint32_t line_start = 0U;
  for (uint32_t i = 0U; i <= log_bytes; ++i) {
    if (i != log_bytes && log[i] != '\n') continue;
    uint32_t line_bytes = i - line_start;
    if (line_has_prefix(&log[line_start], line_bytes, path) != 0) {
      for (uint32_t j = line_start; j < i; ++j) {
        (void)output_append_char(output, output_capacity, output_bytes, log[j]);
      }
      (void)output_append_char(output, output_capacity, output_bytes, '\n');
    }
    line_start = i + 1U;
  }
}

/* The most console output one application run hands back. */
#define REMOTE_APP_CONSOLE_CAPTURE_MAX UINT64_C(65536)

static xaios_status_t handle_remote_app_file(
    const remote_app_definition_t *app, const xaios_initramfs_file_t *file,
    const char *args, char *output,
    uint64_t output_capacity, uint64_t *output_bytes) {
  const char *argv[XAIOS_USER_ARG_MAX];
  char argument_storage[XAIOS_USER_ARG_MAX - 1U][XAIOS_XBFS_PATH_MAX];
  uint32_t argc = 1U;
  uint64_t argument_cursor = 0U;
  uint64_t argument_bytes = 0U;
  char *log;
  char *console;
  uint64_t cursor;
  uint64_t start_cursor = 0U;
  uint64_t next_cursor = 0U;
  uint64_t latest_cursor = 0U;
  uint32_t log_bytes;
  uint64_t console_bytes;
  uint64_t console_capacity;
  int exit_code = 0;
  xaios_status_t status;

  if (app == 0 || file == 0 || args == 0 || file->executable == 0U) {
    return command_fail(output, output_capacity, output_bytes,
                        "application: executable unavailable");
  }
  argv[0] = app->command;
  if (app->pass_cwd != 0U) argv[argc++] = g_remote_login_cwd;
  if (app->raw_arguments != 0U && args[0] != '\0') {
    if (cstr_len(args) + 1U > XAIOS_USER_ARG_BYTES_MAX) {
      return command_fail(output, output_capacity, output_bytes,
                          "application: argument data exceeds limit");
    }
    argv[argc++] = args;
  } else {
    while (has_more_args(args, argument_cursor) != 0) {
      uint64_t before = argument_cursor;
      if (argc >= XAIOS_USER_ARG_MAX ||
          token_next(args, &argument_cursor, argument_storage[argc - 1U],
                     sizeof(argument_storage[0])) != XAIOS_OK) {
        return command_fail(output, output_capacity, output_bytes,
                            "application: too many or oversized arguments");
      }
      argument_bytes += argument_cursor - before;
      if (argument_bytes > XAIOS_USER_ARG_BYTES_MAX) {
        return command_fail(output, output_capacity, output_bytes,
                            "application: argument data exceeds limit");
      }
      argv[argc] = argument_storage[argc - 1U];
      ++argc;
    }
  }

  log = (char *)kheap_alloc(XAIOS_KLOG_FLUSH_MAX, 16U);
  if (log == 0) {
    return command_fail(output, output_capacity, output_bytes,
                        "application: output buffer unavailable");
  }
  /* Capture as much as the caller can take back, rather than a fixed eight
     kilobytes: a screen-sized frame from a terminal application is larger
     than that, and a capture that stops early hands back a torn frame. The
     ceiling keeps one command from asking for the whole heap. */
  console_capacity = output_capacity;
  if (console_capacity > REMOTE_APP_CONSOLE_CAPTURE_MAX) {
    console_capacity = REMOTE_APP_CONSOLE_CAPTURE_MAX;
  }
  if (console_capacity < XAIOS_KLOG_FLUSH_MAX) {
    console_capacity = XAIOS_KLOG_FLUSH_MAX;
  }
  console = (char *)kheap_alloc(console_capacity, 16U);
  if (console == 0) {
    kheap_free(log);
    return command_fail(output, output_capacity, output_bytes,
                        "application: output buffer unavailable");
  }
  cursor = klog_ring_total_written();
  if (klog_console_capture_begin(console, console_capacity) == 0) {
    kheap_free(console);
    kheap_free(log);
    return command_fail(output, output_capacity, output_bytes,
                        "application: output capture unavailable");
  }
  status = user_process_run_transient_args(file, app->capabilities, argc, argv,
                                           &exit_code);
  console_bytes = klog_console_capture_end();
  log_bytes = klog_ring_snapshot(log, XAIOS_KLOG_FLUSH_MAX, cursor,
                                 &start_cursor, &next_cursor, &latest_cursor);
  if (status == XAIOS_OK) {
    for (uint64_t i = 0U; i < console_bytes; ++i) {
      (void)output_append_char(output, output_capacity, output_bytes, console[i]);
    }
    append_app_log_lines(output, output_capacity, output_bytes, log, log_bytes,
                         app->path);
  }
  kheap_free(console);
  kheap_free(log);

  if (status == XAIOS_ERR_BUSY) {
    return command_fail(output, output_capacity, output_bytes,
                        "application: another transient command is running");
  }
  if (status != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "application: launch failed");
  }
  if (exit_code != 0) {
    output_append(output, output_capacity, output_bytes, app->command);
    output_append(output, output_capacity, output_bytes, ": exit status ");
    output_append_u64(output, output_capacity, output_bytes,
                      (uint64_t)(uint32_t)exit_code);
    output_append(output, output_capacity, output_bytes, "\n");
    return XAIOS_ERR_INVALID;
  }
  if (app->report_completion != 0U) {
    output_append(output, output_capacity, output_bytes, app->command);
    output_append(output, output_capacity, output_bytes, ": complete\n");
  }
  return XAIOS_OK;
}

static xaios_status_t handle_remote_app(
    const remote_app_definition_t *app, const char *args, char *output,
    uint64_t output_capacity, uint64_t *output_bytes) {
  const xaios_initramfs_file_t *file = 0;
  if (app == 0 || initramfs_lookup(app->path, &file) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "application: executable unavailable");
  }
  return handle_remote_app_file(app, file, args, output, output_capacity,
                                output_bytes);
}
#endif

static xaios_status_t parse_and_execute(const char *command, char *output,
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
  copy_remainder(command, index, args, sizeof(args));
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
    return handle_remote_app(remote_app_find(cmd), args, output,
                             output_capacity, output_bytes);
#endif
  }
#if !XAIOS_BOOT_TEST_APPS
  {
    const remote_app_definition_t *app = remote_app_find(cmd);
    if (app != 0) {
      return handle_remote_app(app, args, output, output_capacity,
                               output_bytes);
    }
  }
#endif
  if (string_equal(cmd, "pwd") == 1U) {
    return handle_pwd(output, output_capacity, output_bytes);
  }
  if (string_equal(cmd, "cd") == 1U) {
    if (has_more_args(args, arg_index) != 0) {
      return command_fail(output, output_capacity, output_bytes,
                          "cd: too many arguments");
    }
    return handle_cd(arg1, output, output_capacity, output_bytes);
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
    return handle_remote_app(remote_app_find("ls"), alias_args, output,
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
    return handle_cp(args, output, output_capacity, output_bytes);
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
    return handle_cat(args, output, output_capacity, output_bytes);
  }
  if (string_equal(cmd, "less") == 1U) {
    return handle_less(args, output, output_capacity, output_bytes);
  }
  if (string_equal(cmd, "mv") == 1U) {
    return handle_mv(args, output, output_capacity, output_bytes);
  }
  if (string_equal(cmd, "rm") == 1U) {
    return handle_rm(args, output, output_capacity, output_bytes);
  }
  if (string_equal(cmd, "rmdir") == 1U) {
    return handle_rmdir(args, output, output_capacity, output_bytes);
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
    copy_remainder(args, payload_index, payload, sizeof(payload));
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
      remote_app_definition_t app = {
          cmd, image.path, image.capabilities, 0U, 0U, 1U};
      xaios_status_t status = handle_remote_app_file(
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

static xaios_status_t parse_and_execute_pipeline(const char *command,
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
        parse_and_execute(lhs, lhs_output, sizeof(lhs_output), &lhs_bytes);
    if (rc != XAIOS_OK) {
      return rc;
    }
    char resolved[XAIOS_XBFS_PATH_MAX];
    if (remote_path_resolve(g_remote_login_cwd, rhs, resolved,
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
        parse_and_execute(lhs, lhs_output, sizeof(lhs_output), &lhs_bytes);
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
    return parse_and_execute(rhs_with_input, output, output_capacity,
                             output_bytes);
  }
  return parse_and_execute(command, output, output_capacity, output_bytes);
}

/* The name of the account this machine has.

   This used to be the literal "admin", which was true of every image because
   every image packaged the same credential. A machine that makes its own
   account during setup can be called something else, and refusing that name
   would let a person log in at the console and then have every command they
   typed denied.

   Read from the account file sshd authenticates against, so the two cannot
   disagree about who exists, and cached after the first read: it changes only
   when a machine is set up, which happens before anything dispatches a
   command. Falls back to "admin", the account every packaged image has. */
#define REMOTE_LOGIN_ACCOUNT_MAX 64U

static char g_local_account[REMOTE_LOGIN_ACCOUNT_MAX];
static uint32_t g_local_account_loaded;

static int local_account_is(const char *user) {
  if (g_local_account_loaded == 0U) {
    char record[256];
    uint64_t read_bytes = 0U;
    uint64_t used = 0U;
    if (xaiboot_fs_read("/etc/xaios_sshd_users", record, sizeof(record) - 1U,
                        &read_bytes) == XAIOS_OK && read_bytes != 0U) {
      record[read_bytes] = '\0';
      /* Comment lines are not the account. Take the first record's name,
         which is the text before its first colon. */
      uint64_t start = 0U;
      while (start < read_bytes) {
        uint64_t end = start;
        while (end < read_bytes && record[end] != '\n') ++end;
        if (record[start] != '#' && end > start) {
          for (uint64_t i = start; i < end; ++i) {
            if (record[i] == ':') break;
            if (used + 1U >= sizeof(g_local_account)) { used = 0U; break; }
            g_local_account[used++] = record[i];
          }
          if (used != 0U) break;
        }
        start = end + 1U;
      }
    }
    if (used == 0U) {
      static const char fallback[] = "admin";
      for (used = 0U; used < sizeof(fallback) - 1U; ++used) {
        g_local_account[used] = fallback[used];
      }
    }
    g_local_account[used] = '\0';
    g_local_account_loaded = 1U;
  }
  return string_equal(user, g_local_account);
}

/* Forget the cached name.

   The cache is filled by the first command dispatched, and boot self-tests
   dispatch several before setup has run -- so without this the machine
   remembers "admin" from its own self-test and then denies every command the
   person who just set it up types. Called when an account is installed. */
void remote_login_forget_account(void) { g_local_account_loaded = 0U; }

xaios_status_t remote_login_execute(const char *user, const char *command,
                                  char *output, uint64_t output_capacity,
                                  uint64_t *output_bytes) {
  if (user == 0 || command == 0 || output == 0 || output_bytes == 0 ||
      output_capacity < 2U) {
    ++g_remote_login_denials;
    return XAIOS_ERR_INVALID;
  }
  if (!local_account_is(user)) {
    ++g_remote_login_denials;
    klog("remote-login: denied reason=unknown-user\n");
    return XAIOS_ERR_INVALID;
  }
  if (security_reject_credential_material(command) != XAIOS_OK) {
    ++g_remote_login_denials;
    klog("remote-login: denied user=%s reason=secret-material\n", user);
    return XAIOS_ERR_INVALID;
  }
  if (operations_rescue_mode() != 0U &&
      operations_command_allowed_in_rescue(command) == 0U) {
    ++g_remote_login_denials;
    output[0] = '\0';
    *output_bytes = 0U;
    output_append(output, output_capacity, output_bytes,
                  "xaios: rescue mode permits diagnostics and filesystem "
                  "repair commands only\n");
    return XAIOS_ERR_INVALID;
  }

  uint64_t offset = 0;
  output[0] = '\0';
  ++g_remote_login_sessions;
  ++g_remote_login_commands;
  klog("remote-login: ssh-compatible session opened user=%s\n", user);
  klog("remote-login: command dispatch started\n");

  if (parse_and_execute_pipeline(command, output, output_capacity, &offset) !=
      XAIOS_OK) {
    *output_bytes = offset;
    klog("remote-login: command dispatch failed offset=%lu\n", offset);
    ++g_remote_login_denials;
    return XAIOS_ERR_INVALID;
  }

  *output_bytes = offset;
  klog("remote-login: session complete authenticated=1 commands=1 bytes=%lu\n",
       offset);
  return XAIOS_OK;
}

static remote_login_context_t *remote_login_context_find(uint64_t session_id) {
  for (uint32_t i = 0U; i < XAIOS_REMOTE_LOGIN_MAX_SESSIONS; ++i) {
    if (g_remote_login_contexts[i].active != 0U &&
        g_remote_login_contexts[i].session_id == session_id) {
      g_remote_login_contexts[i].last_used = ++g_remote_login_context_clock;
      return &g_remote_login_contexts[i];
    }
  }
  return 0;
}

static remote_login_context_t *remote_login_context_get(uint64_t session_id) {
  remote_login_context_t *context = remote_login_context_find(session_id);
  if (context != 0) return context;
  remote_login_context_t *oldest = &g_remote_login_contexts[0];
  for (uint32_t i = 0U; i < XAIOS_REMOTE_LOGIN_MAX_SESSIONS; ++i) {
    if (g_remote_login_contexts[i].active == 0U) {
      context = &g_remote_login_contexts[i];
      break;
    }
    if (g_remote_login_contexts[i].last_used < oldest->last_used) {
      oldest = &g_remote_login_contexts[i];
    }
  }
  if (context == 0) {
    /* The table is full, and the oldest entry gives way rather than the new
       session being refused.
       Refusing was the old behaviour and it is what made B-25 unrecoverable.
       A context here is a cache of one thing -- a session's working directory
       -- and losing one costs a shell its cwd, which resets to /. Refusing
       one costs the machine every command, for as long as it stays up, with
       SFTP still answering so it does not even look broken. Between a
       forgotten directory and a machine that will not take a command, the
       directory is the cheaper thing to lose.
       This is a backstop, not the fix: sshd closes what it opens now, so a
       table that fills means something is leaking again. Hence the log --
       the original defect's whole difficulty was that it was silent. */
    context = oldest;
    ++g_remote_login_context_evictions;
    klog("remote-login: session table full at %u; evicting session=%lu to "
         "admit session=%lu (evictions=%lu)\n",
         XAIOS_REMOTE_LOGIN_MAX_SESSIONS, context->session_id, session_id,
         g_remote_login_context_evictions);
  }
  context->session_id = session_id;
  context->active = 1U;
  context->last_used = ++g_remote_login_context_clock;
  context->cwd[0] = '/';
  context->cwd[1] = '\0';
  return context;
}

uint64_t remote_login_open_session_count(void) {
  uint64_t open = 0U;
  for (uint32_t i = 0U; i < XAIOS_REMOTE_LOGIN_MAX_SESSIONS; ++i) {
    if (g_remote_login_contexts[i].active != 0U) ++open;
  }
  return open;
}

uint64_t remote_login_session_eviction_count(void) {
  return g_remote_login_context_evictions;
}

xaios_status_t remote_login_execute_session(
    uint64_t session_id, const char *user, const char *command, char *output,
    uint64_t output_capacity, uint64_t *output_bytes) {
  if (session_id == 0U) return XAIOS_ERR_INVALID;
  remote_login_context_t *context = remote_login_context_get(session_id);
  if (context == 0) return XAIOS_ERR_NO_MEMORY;
  char *previous_cwd = g_remote_login_cwd;
  g_remote_login_cwd = context->cwd;
  xaios_status_t status = remote_login_execute(
      user, command, output, output_capacity, output_bytes);
  g_remote_login_cwd = previous_cwd;
  return status;
}

xaios_status_t remote_login_close_session(uint64_t session_id) {
  remote_login_context_t *context = remote_login_context_find(session_id);
  if (session_id == 0U || context == 0) return XAIOS_ERR_NOT_FOUND;
  for (uint64_t i = 0U; i < sizeof(*context); ++i) {
    ((uint8_t *)context)[i] = 0U;
  }
  return XAIOS_OK;
}

uint64_t remote_login_session_count(void) {
  return g_remote_login_sessions;
}

uint64_t remote_login_command_count(void) {
  return g_remote_login_commands;
}

uint64_t remote_login_denial_count(void) {
  return g_remote_login_denials;
}

void remote_login_self_test(void) {
  char output[192];
  uint64_t out = 0;
  uint64_t saved_sessions = g_remote_login_sessions;
  uint64_t saved_commands = g_remote_login_commands;
  uint64_t saved_denials = g_remote_login_denials;
  g_remote_login_sessions = 0U;
  g_remote_login_commands = 0U;
  g_remote_login_denials = 0U;
  for (uint32_t i = 0U; i < XAIOS_REMOTE_LOGIN_MAX_SESSIONS; ++i) {
    g_remote_login_contexts[i].active = 0U;
  }

  kassert(remote_login_execute("admin", "shell", output, sizeof(output),
                               &out) == XAIOS_ERR_INVALID);
  remote_login_context_t *first = remote_login_context_get(101U);
  kassert(first != 0);
  kassert(copy_cstr(first->cwd, sizeof(first->cwd), "/state") == XAIOS_OK);
  kassert(remote_login_execute_session(101U, "admin", "pwd", output,
                                       sizeof(output), &out) == XAIOS_OK);
  kassert(out >= 7U && output[0] == '/' && output[1] == 's');
  kassert(remote_login_execute_session(202U, "admin", "pwd", output,
                                       sizeof(output), &out) == XAIOS_OK);
  kassert(out == 2U && output[0] == '/' && output[1] == '\n');
  kassert(remote_login_close_session(101U) == XAIOS_OK);
  kassert(remote_login_close_session(202U) == XAIOS_OK);
  kassert(remote_login_close_session(202U) == XAIOS_ERR_NOT_FOUND);
  klog("remote-login: isolated session cwd self-test passed\n");

  /* What a full table does, which is B-25's other half.
     Before, the sixty-fifth session was refused and so was every session
     after it, for the life of the machine -- a guest that booted perfectly
     and answered "Command execution failed" to everything. Now the table
     gives up its least recently used entry, so a leak degrades to a lost
     working directory instead of a machine that will not take a command.
     Filled the long way round, through the same entry point sshd uses, so
     this tests the path rather than the table. */
  uint64_t evictions_before = remote_login_session_eviction_count();
  for (uint64_t id = 1000U;
       id < 1000U + (uint64_t)XAIOS_REMOTE_LOGIN_MAX_SESSIONS; ++id) {
    kassert(remote_login_execute_session(id, "admin", "pwd", output,
                                         sizeof(output), &out) == XAIOS_OK);
  }
  kassert(remote_login_open_session_count() ==
          (uint64_t)XAIOS_REMOTE_LOGIN_MAX_SESSIONS);
  kassert(remote_login_session_eviction_count() == evictions_before);
  /* The sixty-fifth. It must be served, not refused. */
  kassert(remote_login_execute_session(2000U, "admin", "pwd", output,
                                       sizeof(output), &out) == XAIOS_OK);
  kassert(remote_login_session_eviction_count() == evictions_before + 1U);
  /* And the one evicted is the oldest -- 1000, which nothing has named since
     it was created -- rather than one still in use. */
  kassert(remote_login_close_session(1000U) == XAIOS_ERR_NOT_FOUND);
  kassert(remote_login_close_session(2000U) == XAIOS_OK);
  for (uint64_t id = 1001U;
       id < 1000U + (uint64_t)XAIOS_REMOTE_LOGIN_MAX_SESSIONS; ++id) {
    kassert(remote_login_close_session(id) == XAIOS_OK);
  }
  kassert(remote_login_open_session_count() == 0U);
  klog("remote-login: a full session table evicts its oldest entry rather "
       "than refusing every session after it\n");
  kassert(remote_login_execute("admin", "cat /state/xaios_host_key", output,
                               sizeof(output), &out) == XAIOS_ERR_INVALID);
  kassert(remote_login_execute("admin", "cat /state/control/config.bin", output,
                               sizeof(output), &out) == XAIOS_ERR_INVALID);
  klog("remote-login: sensitive administrative paths denied\n");
  kassert(remote_login_execute("admin", "shell", output, sizeof(output),
                               &out) == XAIOS_ERR_INVALID);
  klog("remote-login: self-test passed sessions=%lu commands=%lu denials=%lu\n",
       remote_login_session_count(), remote_login_command_count(),
       remote_login_denial_count());
  g_remote_login_sessions = saved_sessions;
  g_remote_login_commands = saved_commands;
  g_remote_login_denials = saved_denials;
}
