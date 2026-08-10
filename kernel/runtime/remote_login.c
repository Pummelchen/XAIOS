#include <xaios/assert.h>
#include <xaios/crc32.h>
#include <xaios/initramfs.h>
#include <xaios/inflate.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/klog_ring.h>
#include <xaios/mutable_fs.h>
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

#ifndef XAIOS_REMOTE_LOGIN_LIST_BYTES
#define XAIOS_REMOTE_LOGIN_LIST_BYTES XAIOS_MFS_MAX_LIST_BYTES
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
#define XAIOS_REMOTE_LOGIN_MAX_SESSIONS 16U
typedef struct remote_login_context {
  uint64_t session_id;
  char cwd[XAIOS_MFS_PATH_MAX];
  uint32_t active;
} remote_login_context_t;
static remote_login_context_t
    g_remote_login_contexts[XAIOS_REMOTE_LOGIN_MAX_SESSIONS];
static char g_remote_login_default_cwd[XAIOS_MFS_PATH_MAX] = "/";
static char *g_remote_login_cwd = g_remote_login_default_cwd;
static const char g_remote_login_archive_magic[] = "XAIOSARCHIVE\n";
static xaios_status_t path_join(char *out, uint64_t out_capacity, const char *base,
                              const char *name);
static xaios_status_t path_basename(const char *path, char *basename,
                                  uint64_t basename_capacity);

static uint64_t u64_digits(uint64_t value) {
  uint64_t digits = 1U;
  while (value >= 10U) {
    value /= 10U;
    ++digits;
  }
  return digits;
}

static uint64_t cstr_len(const char *text) {
  uint64_t len = 0;
  if (text == 0) {
    return 0;
  }
  while (text[len] != '\0') {
    ++len;
  }
  return len;
}

static int string_equal(const char *lhs, const char *rhs) {
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

static void output_append(char *output, uint64_t capacity, uint64_t *offset,
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

static xaios_status_t copy_cstr_range(char *dst, uint64_t dst_capacity,
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

static xaios_status_t copy_cstr(char *dst, uint64_t dst_capacity, const char *src) {
  if (src == 0) {
    if (dst_capacity > 0U) {
      dst[0] = '\0';
    }
    return XAIOS_ERR_INVALID;
  }
  return copy_cstr_range(dst, dst_capacity, src, cstr_len(src));
}

static void output_append_u64(char *output, uint64_t capacity, uint64_t *offset,
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

static xaios_status_t token_next(const char *text, uint64_t *index, char *token,
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

static int remote_path_is_sensitive(const char *path) {
  static const char control_prefix[] = "/state/control";
  static const char host_key[] = "/state/xaios_host_key";
  static const char password_users[] = "/etc/xaios_sshd_users";
  static const char authorized_keys[] = "/etc/xaios_authorized_keys";
  uint64_t control_length = sizeof(control_prefix) - 1U;
  if (path == 0) return 1;
  if (string_equal(path, host_key) || string_equal(path, password_users) ||
      string_equal(path, authorized_keys)) {
    return 1;
  }
  for (uint64_t i = 0U; i < control_length; ++i) {
    if (path[i] != control_prefix[i]) return 0;
  }
  return path[control_length] == '\0' || path[control_length] == '/';
}

static xaios_status_t remote_path_resolve(const char *cwd, const char *path,
                                        char *resolved,
                                        uint64_t resolved_capacity) {
  char source[XAIOS_MFS_PATH_MAX];
  uint64_t source_len = 0;
  uint64_t idx = 0;
  uint64_t resolved_len = 1;
  if (cwd == 0 || path == 0 || resolved == 0 ||
      resolved_capacity < 2U) {
    return XAIOS_ERR_INVALID;
  }

  if (path[0] == '/') {
    if (cstr_len(path) >= XAIOS_MFS_PATH_MAX) {
      return XAIOS_ERR_NO_MEMORY;
    }
    if (copy_cstr(source, sizeof(source), path) != XAIOS_OK) {
      return XAIOS_ERR_INVALID;
    }
    source_len = cstr_len(path);
  } else {
    uint64_t cwd_len = cstr_len(cwd);
    if (cwd_len == 0U || cstr_len(cwd) >= XAIOS_MFS_PATH_MAX) {
      return XAIOS_ERR_INVALID;
    }
    if (copy_cstr(source, sizeof(source), cwd) != XAIOS_OK) {
      return XAIOS_ERR_INVALID;
    }
    source_len = cstr_len(source);
    if (source_len != 1U && source[source_len - 1U] != '/') {
      source[source_len] = '/';
      ++source_len;
      source[source_len] = '\0';
    }
    if (source_len + cstr_len(path) >= XAIOS_MFS_PATH_MAX) {
      return XAIOS_ERR_NO_MEMORY;
    }
    for (uint64_t i = 0; path[i] != '\0'; ++i) {
      source[source_len] = path[i];
      ++source_len;
    }
    source[source_len] = '\0';
  }

  if (source[0] != '/' || source_len == 0U) {
    return XAIOS_ERR_INVALID;
  }

  resolved[0] = '/';
  resolved[1] = '\0';
  while (idx < source_len) {
    while (idx < source_len && source[idx] == '/') {
      ++idx;
    }
    if (idx >= source_len) {
      break;
    }
    uint64_t seg_start = idx;
    while (idx < source_len && source[idx] != '/') {
      ++idx;
    }
    uint64_t seg_len = idx - seg_start;
    if (seg_len == 1U && source[seg_start] == '.') {
      continue;
    }
    if (seg_len == 2U && source[seg_start] == '.' &&
        source[seg_start + 1U] == '.') {
      while (resolved_len > 1U) {
        --resolved_len;
        if (resolved[resolved_len] == '/') {
          break;
        }
      }
      continue;
    }
    if (seg_len == 0U) {
      continue;
    }
    if (resolved_len > 1U) {
      if (resolved_len + 1U >= resolved_capacity) {
        return XAIOS_ERR_NO_MEMORY;
      }
      resolved[resolved_len] = '/';
      ++resolved_len;
    }
    if (resolved_len + seg_len >= resolved_capacity) {
      return XAIOS_ERR_NO_MEMORY;
    }
    for (uint64_t i = 0; i < seg_len; ++i) {
      resolved[resolved_len] = source[seg_start + i];
      ++resolved_len;
    }
  }
  if (resolved_len == 0U) {
    resolved_len = 1U;
  }
  resolved[resolved_len] = '\0';
  if (remote_path_is_sensitive(resolved)) {
    return XAIOS_ERR_INVALID;
  }
  return XAIOS_OK;
}

static xaios_status_t remote_ensure_parent(const char *path) {
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
  char parent[XAIOS_MFS_PATH_MAX];
  xaios_mfs_stat_t parent_stat;
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
  return mutable_fs_stat(parent, &parent_stat) == XAIOS_OK &&
                     parent_stat.type == 1U
             ? XAIOS_OK
             : XAIOS_ERR_INVALID;
}

static xaios_status_t command_fail(char *output, uint64_t output_capacity,
                                 uint64_t *output_bytes,
                                 const char *message) {
  output_append(output, output_capacity, output_bytes, message);
  output_append(output, output_capacity, output_bytes, "\n");
  return XAIOS_ERR_INVALID;
}

static xaios_status_t output_append_char(char *output, uint64_t capacity,
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

static void remote_login_log_failure(const char *operation, const char *reason,
                                   xaios_status_t status) {
  if (operation == 0) {
    return;
  }
  klog("remote-login: operation=%s failed reason=%s rc=%lu\n", operation,
       reason == 0 ? "unknown" : reason, status);
}

static int has_more_args(const char *text, uint64_t index) {
  char token[2];
  return token_next(text, &index, token, sizeof(token)) == XAIOS_OK;
}

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

static xaios_status_t buffer_append_text(char *buffer, uint64_t capacity,
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

static xaios_status_t write_buffer_to_path(const char *path, const char *data,
                                         uint64_t data_size) {
  int64_t fd = -1;
  if (path == 0 || data == 0) {
    return XAIOS_ERR_INVALID;
  }
  fd = mutable_fs_open(path,
                       XAIOS_MFS_OPEN_WRITE | XAIOS_MFS_OPEN_CREATE |
                           XAIOS_MFS_OPEN_TRUNCATE);
  if (fd < 0) {
    return XAIOS_ERR_INVALID;
  }
  if (data_size != 0U) {
    int64_t written = mutable_fs_write_fd((uint32_t)fd, data, data_size);
    if (written < 0 || ((uint64_t)written) != data_size) {
      (void)mutable_fs_close((uint32_t)fd);
      return XAIOS_ERR_INVALID;
    }
  }
  if (mutable_fs_close((uint32_t)fd) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  return XAIOS_OK;
}

static xaios_status_t read_file_buffer(const char *path, char *buffer,
                                     uint64_t buffer_capacity,
                                     uint64_t *out_size) {
  if (path == 0 || buffer == 0 || out_size == 0 || buffer_capacity == 0U) {
    return XAIOS_ERR_INVALID;
  }
  xaios_status_t status = mutable_fs_read(path, buffer, buffer_capacity, out_size);
  if (status != XAIOS_OK) {
    return status;
  }
  return XAIOS_OK;
}

static xaios_status_t archive_append_entry(char *archive, uint64_t archive_capacity,
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
  if (path_len == 0U || path_len >= XAIOS_MFS_PATH_MAX) {
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
  if (buffer_append_text(archive, archive_capacity, archive_size, path) != XAIOS_OK) {
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

static xaios_status_t archive_parse_entry(const char *line, uint64_t line_size,
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

static xaios_status_t archive_build_from_path(const char *source,
                                            const char *archive_path,
                                            char *archive,
                                            uint64_t archive_capacity,
                                            uint64_t *archive_size) {
  xaios_mfs_stat_t source_stat;
  if (source == 0 || archive == 0 || archive_size == 0) {
    return XAIOS_ERR_INVALID;
  }
  if (mutable_fs_stat(source, &source_stat) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  if (source_stat.type == 1U) {
    uint64_t archive_entry_name_len = cstr_len(archive_path);
    if (archive_entry_name_len == 0U) {
      return XAIOS_ERR_INVALID;
    }
    if (archive_append_entry(archive, archive_capacity, archive_size, 'D',
                            archive_path, "", 0U) != XAIOS_OK) {
      return XAIOS_ERR_NO_MEMORY;
    }
    char listing[XAIOS_REMOTE_LOGIN_LIST_BYTES];
    uint64_t listing_size = 0;
    if (mutable_fs_list(source, listing, sizeof(listing), &listing_size) != XAIOS_OK) {
      return XAIOS_ERR_INVALID;
    }
    uint64_t line_start = 0;
    while (line_start < listing_size) {
      uint64_t line_end = line_start;
      while (line_end < listing_size && listing[line_end] != '\n') {
        ++line_end;
      }
      uint64_t child_name_len = line_end - line_start;
      if (child_name_len != 0U) {
        char child_name[XAIOS_MFS_PATH_MAX];
        char child_source[XAIOS_MFS_PATH_MAX];
        char child_archive_path[XAIOS_MFS_PATH_MAX];
        if (copy_cstr_range(child_name, sizeof(child_name), listing + line_start,
                            child_name_len) != XAIOS_OK) {
          return XAIOS_ERR_NO_MEMORY;
        }
        if (path_join(child_source, sizeof(child_source), source, child_name) != XAIOS_OK) {
          return XAIOS_ERR_NO_MEMORY;
        }
        if (path_join(child_archive_path, sizeof(child_archive_path),
                      archive_path, child_name) != XAIOS_OK) {
          return XAIOS_ERR_NO_MEMORY;
        }
        if (archive_build_from_path(child_source, child_archive_path, archive,
                                   archive_capacity, archive_size) != XAIOS_OK) {
          return XAIOS_ERR_INVALID;
        }
      }
      line_start = line_end + 1U;
    }
    return XAIOS_OK;
  }
  if (source_stat.type == 2U) {
    char data[XAIOS_MFS_MAX_FILE_BYTES];
    uint64_t data_size = 0;
    if (read_file_buffer(source, data, sizeof(data), &data_size) != XAIOS_OK) {
      return XAIOS_ERR_INVALID;
    }
    if (archive_append_entry(archive, archive_capacity, archive_size, 'F',
                            archive_path, data, data_size) != XAIOS_OK) {
      return XAIOS_ERR_NO_MEMORY;
    }
    return XAIOS_OK;
  }
  return XAIOS_ERR_INVALID;
}

static xaios_status_t archive_extract_to(const char *archive_path,
                                       const char *extract_base) {
  char archive[XAIOS_MFS_MAX_FILE_BYTES];
  char path[XAIOS_MFS_PATH_MAX];
  char resolved_path[XAIOS_MFS_PATH_MAX];
  char entry_path[XAIOS_MFS_PATH_MAX];
  uint64_t archive_size = 0;
  uint64_t cursor = 0;
  uint64_t magic_len = cstr_len(g_remote_login_archive_magic);
  if (archive_path == 0 || extract_base == 0) {
    return XAIOS_ERR_INVALID;
  }
  if (read_file_buffer(archive_path, archive, sizeof(archive), &archive_size) !=
          XAIOS_OK ||
      archive_size <= magic_len ||
      copy_cstr(path, sizeof(path), g_remote_login_archive_magic) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  if (archive_size < magic_len + 1U) {
    return XAIOS_ERR_INVALID;
  }
  for (uint64_t i = 0; i < magic_len; ++i) {
    if (archive[i] != g_remote_login_archive_magic[i]) {
      return XAIOS_ERR_INVALID;
    }
  }
  cursor = magic_len;
  while (cursor < archive_size) {
    if (archive[cursor] == '\r' || archive[cursor] == '\n' ||
        archive[cursor] == '\0') {
      ++cursor;
      if (cursor >= archive_size) {
        return XAIOS_OK;
      }
      continue;
    }
    uint64_t line_start = cursor;
    while (cursor < archive_size && archive[cursor] != '\n') {
      ++cursor;
    }
    if (cursor >= archive_size) {
      return XAIOS_ERR_INVALID;
    }
    uint64_t line_size = cursor - line_start;
    if (line_size == 0U) {
      ++cursor;
      continue;
    }
    char line[XAIOS_MFS_MAX_FILE_BYTES];
    if (line_size >= sizeof(line)) {
      return XAIOS_ERR_NO_MEMORY;
    }
    if (copy_cstr_range(line, sizeof(line), archive + line_start, line_size) !=
        XAIOS_OK) {
      return XAIOS_ERR_NO_MEMORY;
    }
    line[line_size] = '\0';
    ++cursor;

    char kind = 0;
    uint64_t data_size = 0;
    uint64_t entry_path_len = 0;
    if (archive_parse_entry(line, line_size, &kind, &data_size, &entry_path_len,
                            entry_path, sizeof(entry_path)) != XAIOS_OK) {
      return XAIOS_ERR_INVALID;
    }
    if (entry_path_len + 1U >= sizeof(entry_path)) {
      return XAIOS_ERR_NO_MEMORY;
    }
    if (entry_path[0] == '/') {
      return XAIOS_ERR_INVALID;
    }
    if (path_join(resolved_path, sizeof(resolved_path), extract_base,
                  entry_path) != XAIOS_OK) {
      return XAIOS_ERR_NO_MEMORY;
    }
    if (kind == 'D') {
      if (remote_path_resolve(g_remote_login_cwd, resolved_path, path,
                             sizeof(path)) != XAIOS_OK ||
          remote_ensure_parent(path) != XAIOS_OK ||
          mutable_fs_mkdir(path) != XAIOS_OK) {
        return XAIOS_ERR_INVALID;
      }
      continue;
    }
    if (kind != 'F') {
      return XAIOS_ERR_INVALID;
    }
    if (cursor + data_size > archive_size) {
      return XAIOS_ERR_INVALID;
    }
    if (remote_path_resolve(g_remote_login_cwd, resolved_path, path,
                           sizeof(path)) != XAIOS_OK ||
        remote_ensure_parent(path) != XAIOS_OK ||
        write_buffer_to_path(path, archive + cursor, data_size) != XAIOS_OK) {
      return XAIOS_ERR_INVALID;
    }
    cursor += data_size;
  }
  return XAIOS_OK;
}

static xaios_status_t archive_list(const char *archive_path, char *output,
                                 uint64_t output_capacity,
                                 uint64_t *output_bytes) {
  char archive[XAIOS_MFS_MAX_FILE_BYTES];
  uint64_t archive_size = 0;
  uint64_t cursor = 0;
  uint64_t magic_len = cstr_len(g_remote_login_archive_magic);
  char path[XAIOS_MFS_PATH_MAX];
  if (archive_path == 0 || read_file_buffer(archive_path, archive,
                                            sizeof(archive), &archive_size) !=
                                         XAIOS_OK ||
      archive_size <= magic_len) {
    klog("remote-login: archive-list file read failed path=%s size=%lu magic_len=%lu\n",
         archive_path == 0 ? "(null)" : archive_path, archive_size, magic_len);
    return XAIOS_ERR_INVALID;
  }
  for (uint64_t i = 0; i < magic_len; ++i) {
    if (archive[i] != g_remote_login_archive_magic[i]) {
      klog("remote-login: archive-list bad magic at offset=%lu byte=%u expected=%u\n", i,
           (uint8_t)archive[i], (uint8_t)g_remote_login_archive_magic[i]);
      return XAIOS_ERR_INVALID;
    }
  }
  cursor = magic_len;
  while (cursor < archive_size) {
    while (cursor < archive_size &&
           (archive[cursor] == '\r' || archive[cursor] == '\n' ||
            archive[cursor] == '\0')) {
      ++cursor;
      if (cursor >= archive_size) {
        return XAIOS_OK;
      }
    }
    uint64_t line_start = cursor;
    while (cursor < archive_size && archive[cursor] != '\n') {
      ++cursor;
    }
    if (line_start >= archive_size || cursor > archive_size) {
      klog("remote-login: archive-list bad line bounds line_start=%lu cursor=%lu size=%lu\n",
           line_start, cursor, archive_size);
      return XAIOS_ERR_INVALID;
    }
    uint64_t line_size = cursor - line_start;
    if (line_size == 0U) {
      ++cursor;
      continue;
    }
    char line[XAIOS_MFS_MAX_FILE_BYTES];
    if (line_size >= sizeof(line)) {
      klog("remote-login: archive-list line too long=%lu\n", line_size);
      return XAIOS_ERR_NO_MEMORY;
    }
    if (copy_cstr_range(line, sizeof(line), archive + line_start, line_size) !=
        XAIOS_OK) {
      klog("remote-login: archive-list failed to copy header line_size=%lu\n", line_size);
      return XAIOS_ERR_NO_MEMORY;
    }
    line[line_size] = '\0';
    if (cursor < archive_size) {
      ++cursor;
    }
    char kind = 0;
    uint64_t data_size = 0;
    uint64_t entry_path_len = 0;
    if (archive_parse_entry(line, line_size, &kind, &data_size, &entry_path_len,
                            path, sizeof(path)) != XAIOS_OK) {
      klog("remote-login: archive-list parse failed header='%s' line_size=%lu magic_len=%lu\n",
           line, line_size, magic_len);
      return XAIOS_ERR_INVALID;
    }
    output_append(output, output_capacity, output_bytes, path);
    if (kind == 'D' &&
        output_append_char(output, output_capacity, output_bytes, '/') != XAIOS_OK) {
      return XAIOS_ERR_NO_MEMORY;
    }
    if (output_append_char(output, output_capacity, output_bytes, '\n') != XAIOS_OK) {
      return XAIOS_ERR_NO_MEMORY;
    }
    if (kind == 'D') {
      continue;
    }
    if (cursor + data_size > archive_size) {
      klog("remote-login: archive-list invalid data_size=%lu cursor=%lu archive_size=%lu\n",
           data_size, cursor, archive_size);
      return XAIOS_ERR_INVALID;
    }
    cursor += data_size;
  }
  return XAIOS_OK;
}

static int string_starts_with(const char *text, const char *prefix) {
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

static int contains_substring(const char *text, const char *needle) {
  uint64_t needle_len = cstr_len(needle);
  if (needle == 0 || needle_len == 0U) {
    return 0;
  }
  for (uint64_t i = 0; text[i] != '\0'; ++i) {
    uint64_t j = 0;
    for (;;) {
      if (needle[j] == '\0') {
        return 1;
      }
      if (text[i + j] != needle[j]) {
        break;
      }
      ++j;
    }
    if (text[i + j] == '\0' && needle[j] != '\0') {
      return 0;
    }
  }
  return 0;
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

static int find_match(const char *name, const char *pattern) {
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

static int is_hidden_name(const char *name) {
  return name != 0 && name[0] == '.';
}

static uint64_t parse_decimal_uint(const char *text, uint64_t *value) {
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

static xaios_status_t path_join(char *out, uint64_t out_capacity, const char *base,
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

static xaios_status_t append_ls_entry(char *output, uint64_t output_capacity,
                                    uint64_t *output_bytes, const char *name,
                                    uint64_t size, uint64_t type,
                                    int long_form) {
  if (long_form) {
    char type_char = type == 1U ? 'd' : '-';
    output_append_char(output, output_capacity, output_bytes, type_char);
    output_append(output, output_capacity, output_bytes, " ");
    output_append_u64(output, output_capacity, output_bytes, size);
    output_append(output, output_capacity, output_bytes, " ");
  }
  output_append(output, output_capacity, output_bytes, name);
  return output_append_char(output, output_capacity, output_bytes, '\n');
}

static xaios_status_t handle_ls(const char *args, char *output,
                               uint64_t output_capacity,
                               uint64_t *output_bytes) {
  uint64_t arg_index = 0;
  char token[32];
  char explicit_path[XAIOS_MFS_PATH_MAX];
  int show_all = 0;
  int long_form = 0;
  int end_of_options = 0;
  explicit_path[0] = '\0';

  while (token_next(args, &arg_index, token, sizeof(token)) == XAIOS_OK) {
    if (end_of_options == 0 && string_equal(token, "--") == 1U) {
      end_of_options = 1;
      continue;
    }

    if (token[0] == '-' && end_of_options == 0) {
      if (string_equal(token, "-a") == 1U) {
        show_all = 1;
      } else if (string_equal(token, "-l") == 1U) {
        long_form = 1;
      } else if (string_equal(token, "-la") == 1U ||
                 string_equal(token, "-al") == 1U) {
        show_all = 1;
        long_form = 1;
      } else {
        return command_fail(output, output_capacity, output_bytes,
                           "ls: invalid option");
      }
      continue;
    }

    if (explicit_path[0] != '\0') {
      return command_fail(output, output_capacity, output_bytes,
                          "ls: too many arguments");
    }
    if (copy_cstr(explicit_path, sizeof(explicit_path), token) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes, "ls: invalid path");
    }
  }

  char target[XAIOS_MFS_PATH_MAX];
  if (explicit_path[0] == '\0') {
    if (copy_cstr(target, sizeof(target), g_remote_login_cwd) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "ls: invalid path");
    }
  } else if (copy_cstr(target, sizeof(target), explicit_path) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "ls: invalid path");
  }

  char resolved[XAIOS_MFS_PATH_MAX];
  char listing[XAIOS_REMOTE_LOGIN_LIST_BYTES];
  uint64_t listing_size = 0;
  if (remote_path_resolve(g_remote_login_cwd, target, resolved,
                         sizeof(resolved)) != XAIOS_OK) {
    remote_login_log_failure("ls", "invalid-path", XAIOS_ERR_INVALID);
    return command_fail(output, output_capacity, output_bytes, "ls: invalid path");
  }
  xaios_mfs_stat_t target_stat;
  if (mutable_fs_stat(resolved, &target_stat) == XAIOS_OK &&
      target_stat.type == 2U) {
    return append_ls_entry(output, output_capacity, output_bytes,
                           explicit_path[0] == '\0' ? resolved : explicit_path,
                           target_stat.size, target_stat.type, long_form);
  }
  xaios_status_t list_status = mutable_fs_list(resolved, listing,
                                              sizeof(listing),
                                              &listing_size);
  if ((list_status != XAIOS_OK &&
       (list_status != XAIOS_ERR_NO_MEMORY || listing_size == 0U)) ||
      listing_size > sizeof(listing)) {
    klog(
        "remote-login: ls path=%s list_status=%lu listing_size=%lu capacity=%lu\n",
        resolved, list_status, listing_size, (uint64_t)sizeof(listing));
    remote_login_log_failure("ls", "list-failed", list_status);
    return command_fail(output, output_capacity, output_bytes, "ls: not found");
  }

  uint64_t line_start = 0;
  while (line_start < listing_size) {
    uint64_t line_end = line_start;
    while (line_end < listing_size && listing[line_end] != '\n') {
      ++line_end;
    }
    uint64_t name_len = line_end - line_start;
    if (name_len == 0U) {
      line_start = line_end + 1U;
      continue;
    }
    if (name_len + 1U >= XAIOS_MFS_PATH_MAX) {
      return command_fail(output, output_capacity, output_bytes,
                          "ls: path too long");
    }
    char name[XAIOS_MFS_PATH_MAX];
    if (copy_cstr_range(name, sizeof(name), listing + line_start, name_len) !=
        XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes, "ls: not found");
    }
    if (!show_all && is_hidden_name(name) != 0) {
      line_start = line_end + 1U;
      continue;
    }
    char child[XAIOS_MFS_PATH_MAX];
    if (path_join(child, sizeof(child), resolved, name) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes, "ls: not found");
    }
    xaios_mfs_stat_t child_stat;
    if (mutable_fs_stat(child, &child_stat) != XAIOS_OK) {
      line_start = line_end + 1U;
      continue;
    }
    if (append_ls_entry(output, output_capacity, output_bytes, name,
                        child_stat.size, child_stat.type, long_form) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes, "ls: output too large");
    }
    line_start = line_end + 1U;
  }
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
  int64_t src_fd = mutable_fs_open(src, XAIOS_MFS_OPEN_READ);
  if (src_fd < 0) return XAIOS_ERR_NOT_FOUND;
  int64_t dst_fd = mutable_fs_open(
      dst, XAIOS_MFS_OPEN_WRITE | XAIOS_MFS_OPEN_CREATE |
               XAIOS_MFS_OPEN_TRUNCATE);
  if (dst_fd < 0) {
    (void)mutable_fs_close((uint32_t)src_fd);
    return XAIOS_ERR_INVALID;
  }
  xaios_status_t status = XAIOS_OK;
  for (;;) {
    int64_t got = mutable_fs_read_fd((uint32_t)src_fd, buffer, sizeof(buffer));
    if (got < 0) {
      status = XAIOS_ERR_IO;
      break;
    }
    if (got == 0) break;
    int64_t written =
        mutable_fs_write_fd((uint32_t)dst_fd, buffer, (uint64_t)got);
    if (written != got) {
      status = XAIOS_ERR_IO;
      break;
    }
  }
  if (mutable_fs_close((uint32_t)src_fd) != XAIOS_OK) status = XAIOS_ERR_IO;
  if (mutable_fs_close((uint32_t)dst_fd) != XAIOS_OK) status = XAIOS_ERR_IO;
  return status;
}

static xaios_status_t copy_path_recursive(const char *src, const char *dst,
                                         int recursive) {
  xaios_mfs_stat_t src_stat;
  xaios_mfs_stat_t dst_stat;
  if (mutable_fs_stat(src, &src_stat) != XAIOS_OK) return XAIOS_ERR_NOT_FOUND;
  if (src_stat.type == 2U) {
    if (remote_ensure_parent(dst) != XAIOS_OK) return XAIOS_ERR_INVALID;
    return copy_file_path(src, dst);
  }
  if (src_stat.type != 1U || recursive == 0) return XAIOS_ERR_INVALID;
  if (path_is_same_or_child(src, dst) != 0) return XAIOS_ERR_INVALID;
  if (mutable_fs_stat(dst, &dst_stat) != XAIOS_OK) {
    if (remote_ensure_parent(dst) != XAIOS_OK ||
        mutable_fs_mkdir(dst) != XAIOS_OK) {
      return XAIOS_ERR_INVALID;
    }
  } else if (dst_stat.type != 1U) {
    return XAIOS_ERR_INVALID;
  }

  char listing[XAIOS_MFS_MAX_LIST_BYTES];
  uint64_t listing_size = 0U;
  if (mutable_fs_list(src, listing, sizeof(listing), &listing_size) != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  uint64_t line_start = 0U;
  while (line_start < listing_size) {
    uint64_t line_end = line_start;
    while (line_end < listing_size && listing[line_end] != '\n') ++line_end;
    if (line_end > line_start) {
      char name[XAIOS_MFS_PATH_MAX];
      char child_src[XAIOS_MFS_PATH_MAX];
      char child_dst[XAIOS_MFS_PATH_MAX];
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
  char operands[17][XAIOS_MFS_PATH_MAX];
  uint32_t operand_count = 0U;
  uint64_t index = 0U;
  int recursive = 0;
  int end_options = 0;
  char token[XAIOS_MFS_PATH_MAX];
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

  char destination[XAIOS_MFS_PATH_MAX];
  if (remote_path_resolve(g_remote_login_cwd, operands[operand_count - 1U],
                          destination, sizeof(destination)) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "cp: invalid destination");
  }
  xaios_mfs_stat_t destination_stat;
  int destination_is_dir =
      mutable_fs_stat(destination, &destination_stat) == XAIOS_OK &&
      destination_stat.type == 1U;
  if (operand_count > 2U && destination_is_dir == 0) {
    return command_fail(output, output_capacity, output_bytes,
                        "cp: destination is not a directory");
  }
  for (uint32_t operand = 0U; operand + 1U < operand_count; ++operand) {
    char source[XAIOS_MFS_PATH_MAX];
    char target[XAIOS_MFS_PATH_MAX];
    if (remote_path_resolve(g_remote_login_cwd, operands[operand], source,
                            sizeof(source)) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "cp: invalid source");
    }
    if (destination_is_dir != 0) {
      char basename[XAIOS_MFS_PATH_MAX];
      if (path_basename(source, basename, sizeof(basename)) != XAIOS_OK ||
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

static xaios_status_t handle_grep(const char *args, char *output,
                                uint64_t output_capacity,
                                uint64_t *output_bytes) {
  char pattern[XAIOS_MFS_PATH_MAX];
  char files[16][XAIOS_MFS_PATH_MAX];
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
  char token[XAIOS_MFS_PATH_MAX];
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
    char resolved[XAIOS_MFS_PATH_MAX];
    char *data = (char *)kheap_alloc(XAIOS_MFS_MAX_FILE_BYTES_V4 + 1U, 16U);
    uint64_t data_size = 0U;
    if (data == 0 ||
        remote_path_resolve(g_remote_login_cwd, files[file], resolved,
                            sizeof(resolved)) != XAIOS_OK ||
        mutable_fs_read(resolved, data, XAIOS_MFS_MAX_FILE_BYTES_V4,
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

static xaios_status_t handle_find_recursive(const char *path, const char *pattern,
                                          char *output,
                                          uint64_t output_capacity,
                                          uint64_t *output_bytes,
                                          int print_entry_path) {
  xaios_mfs_stat_t start_stat;
  char listing[XAIOS_REMOTE_LOGIN_LIST_BYTES];
  uint64_t listing_size = 0;
  if (mutable_fs_stat(path, &start_stat) != XAIOS_OK || start_stat.type != 1U) {
    return XAIOS_ERR_NOT_FOUND;
  }
  if (pattern == 0 || pattern[0] == '\0') {
    if (print_entry_path != 0) {
      output_append(output, output_capacity, output_bytes, path);
      if (output_append_char(output, output_capacity, output_bytes, '\n') !=
          XAIOS_OK) {
        return XAIOS_ERR_NO_MEMORY;
      }
    }
  } else {
    const char *name = path;
    uint64_t path_len = cstr_len(path);
    for (uint64_t i = 0; i + 1U < path_len; ++i) {
      if (path[path_len - i - 1U] == '/') {
        name = &path[path_len - i];
        break;
      }
    }
    if (find_match(name, pattern) != 0) {
      if (print_entry_path != 0) {
        output_append(output, output_capacity, output_bytes, path);
        if (output_append_char(output, output_capacity, output_bytes, '\n') !=
            XAIOS_OK) {
          return XAIOS_ERR_NO_MEMORY;
        }
      }
    }
  }
  if (mutable_fs_list(path, listing, sizeof(listing), &listing_size) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t line_start = 0;
  while (line_start < listing_size) {
    uint64_t line_end = line_start;
    while (line_end < listing_size && listing[line_end] != '\n') {
      ++line_end;
    }
    char name[XAIOS_MFS_PATH_MAX];
    uint64_t name_len = line_end - line_start;
    if (name_len >= sizeof(name)) {
      name_len = sizeof(name) - 1U;
    }
    for (uint64_t i = 0; i < name_len; ++i) {
      name[i] = listing[line_start + i];
    }
    name[name_len] = '\0';
    if (name_len == 0U) {
      line_start = line_end + 1U;
      continue;
    }
    char child[XAIOS_MFS_PATH_MAX];
    if (path_join(child, sizeof(child), path, name) != XAIOS_OK) {
      return XAIOS_ERR_NO_MEMORY;
    }
    xaios_mfs_stat_t child_stat;
    if (mutable_fs_stat(child, &child_stat) != XAIOS_OK) {
      line_start = line_end + 1U;
      continue;
    }
    if (pattern == 0 || pattern[0] == '\0' || find_match(name, pattern) != 0) {
      output_append(output, output_capacity, output_bytes, child);
      if (output_append_char(output, output_capacity, output_bytes, '\n') !=
          XAIOS_OK) {
        return XAIOS_ERR_NO_MEMORY;
      }
    }
    if (child_stat.type == 1U) {
      xaios_status_t child_status =
          handle_find_recursive(child, pattern, output, output_capacity, output_bytes,
                               0);
      if (child_status != XAIOS_OK && child_status != XAIOS_ERR_NOT_FOUND) {
        return child_status;
      }
    }
    line_start = line_end + 1U;
  }
  return XAIOS_OK;
}

static xaios_status_t handle_find(const char *path, const char *pattern, char *output,
                                uint64_t output_capacity,
                                uint64_t *output_bytes) {
  return handle_find_recursive(path, pattern, output, output_capacity, output_bytes,
                              1);
}

static xaios_status_t handle_find_cmd(const char *args, char *output,
                                    uint64_t output_capacity,
                                    uint64_t *output_bytes) {
  uint64_t arg_index = 0;
  char path_arg[XAIOS_MFS_PATH_MAX];
  char resolved[XAIOS_MFS_PATH_MAX];
  char token[XAIOS_MFS_PATH_MAX];
  char pattern[XAIOS_MFS_PATH_MAX];
  char explicit_path[XAIOS_MFS_PATH_MAX];
  int path_was_given = 0;
  int has_name_filter = 0;
  explicit_path[0] = '\0';
  pattern[0] = '\0';

  if (token_next(args, &arg_index, path_arg, sizeof(path_arg)) == XAIOS_OK) {
    path_was_given = 1;
    if (path_arg[0] == '-') {
      if (copy_cstr(explicit_path, sizeof(explicit_path), ".") != XAIOS_OK) {
        return command_fail(output, output_capacity, output_bytes, "find: invalid path");
      }
    } else {
      if (copy_cstr(explicit_path, sizeof(explicit_path), path_arg) != XAIOS_OK) {
        return command_fail(output, output_capacity, output_bytes, "find: invalid path");
      }
    }
  } else {
    (void)copy_cstr(explicit_path, sizeof(explicit_path), ".");
  }

  while (token_next(args, &arg_index, token, sizeof(token)) == XAIOS_OK) {
    if (string_equal(token, "-name") == 1U) {
      has_name_filter = 1;
      if (token_next(args, &arg_index, pattern, sizeof(pattern)) != XAIOS_OK) {
        return command_fail(output, output_capacity, output_bytes,
                            "find: missing -name argument");
      }
      continue;
    }
    if (token[0] == '-') {
      return command_fail(output, output_capacity, output_bytes,
                          "find: unsupported option");
    } else {
      return command_fail(output, output_capacity, output_bytes,
                          path_was_given == 0 ? "find: invalid path"
                                              : "find: too many path arguments");
    }
  }
  if (has_name_filter == 0) {
    pattern[0] = '\0';
  }

  if (remote_path_resolve(g_remote_login_cwd, explicit_path, resolved,
                         sizeof(resolved)) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes, "find: invalid path");
  }
  if (handle_find(resolved, pattern, output, output_capacity, output_bytes) !=
      XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "find: cannot list");
  }
  return XAIOS_OK;
}

static xaios_status_t read_file_lines(const char *path, char *buffer,
                                    uint64_t buffer_capacity, uint64_t *size) {
  if (path == 0 || buffer == 0 || size == 0 || buffer_capacity == 0U) {
    return XAIOS_ERR_INVALID;
  }
  if (mutable_fs_read(path, buffer, buffer_capacity, size) != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  return XAIOS_OK;
}

static xaios_status_t handle_head_tail(const char *args, int is_head, char *output,
                                     uint64_t output_capacity,
                                     uint64_t *output_bytes) {
  uint64_t arg_index = 0;
  char token[XAIOS_MFS_PATH_MAX];
  char path_arg[XAIOS_MFS_PATH_MAX];
  uint64_t lines = 10U;
  char resolved[XAIOS_MFS_PATH_MAX];
  char data[XAIOS_MFS_MAX_FILE_BYTES];
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

  if (remote_path_resolve(g_remote_login_cwd, path_arg, resolved,
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
  char resolved[XAIOS_MFS_PATH_MAX];
  xaios_mfs_stat_t stat;
  if (remote_path_resolve(g_remote_login_cwd, target, resolved,
                         sizeof(resolved)) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes, "cd: invalid path");
  }
  if (string_equal(resolved, "/") == 1U) {
    if (copy_cstr(g_remote_login_cwd, XAIOS_MFS_PATH_MAX, resolved) !=
        XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "cd: path too long");
    }
    output_append(output, output_capacity, output_bytes, resolved);
    output_append(output, output_capacity, output_bytes, "\n");
    return XAIOS_OK;
  }
  if (mutable_fs_stat(resolved, &stat) != XAIOS_OK || stat.type != 1U) {
    return command_fail(output, output_capacity, output_bytes,
                        "cd: not a directory");
  }
  if (copy_cstr(g_remote_login_cwd, XAIOS_MFS_PATH_MAX, resolved) !=
      XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "cd: path too long");
  }
  output_append(output, output_capacity, output_bytes, resolved);
  output_append(output, output_capacity, output_bytes, "\n");
  return XAIOS_OK;
}

static xaios_status_t handle_stat(const char *arg, char *output,
                                uint64_t output_capacity,
                                uint64_t *output_bytes) {
  char resolved[XAIOS_MFS_PATH_MAX];
  xaios_mfs_stat_t stat;
  if (arg == 0 || arg[0] == '\0') {
    return command_fail(output, output_capacity, output_bytes, "stat: missing path");
  }
  if (remote_path_resolve(g_remote_login_cwd, arg, resolved, sizeof(resolved)) !=
          XAIOS_OK ||
      mutable_fs_stat(resolved, &stat) != XAIOS_OK) {
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

static xaios_status_t mkdir_resolved(const char *path, int parents) {
  xaios_mfs_stat_t stat;
  if (mutable_fs_stat(path, &stat) == XAIOS_OK) {
    return parents != 0 && stat.type == 1U ? XAIOS_OK : XAIOS_ERR_BUSY;
  }
  if (parents == 0) {
    return remote_ensure_parent(path) == XAIOS_OK ? mutable_fs_mkdir(path)
                                                  : XAIOS_ERR_NOT_FOUND;
  }
  char current[XAIOS_MFS_PATH_MAX];
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
      if (mutable_fs_stat(current, &stat) == XAIOS_OK) {
        if (stat.type != 1U) return XAIOS_ERR_INVALID;
      } else if (mutable_fs_mkdir(current) != XAIOS_OK) {
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
  char token[XAIOS_MFS_PATH_MAX];
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
    char resolved[XAIOS_MFS_PATH_MAX];
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
  char resolved[XAIOS_MFS_PATH_MAX];
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
  fd = mutable_fs_open(resolved,
                       XAIOS_MFS_OPEN_WRITE | XAIOS_MFS_OPEN_CREATE |
                           XAIOS_MFS_OPEN_TRUNCATE);
  if (fd < 0) {
    return command_fail(output, output_capacity, output_bytes,
                        "touch: failed");
  }
  if (mutable_fs_close((uint32_t)fd) != XAIOS_OK) {
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
  int64_t fd = mutable_fs_open(resolved, XAIOS_MFS_OPEN_READ);
  if (fd < 0) return XAIOS_ERR_NOT_FOUND;
  char buffer[512];
  xaios_status_t status = XAIOS_OK;
  for (;;) {
    int64_t got = mutable_fs_read_fd((uint32_t)fd, buffer, sizeof(buffer));
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
  if (mutable_fs_close((uint32_t)fd) != XAIOS_OK) status = XAIOS_ERR_IO;
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
  char token[XAIOS_MFS_PATH_MAX];
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
    char resolved[XAIOS_MFS_PATH_MAX];
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
  char resolved[XAIOS_MFS_PATH_MAX];
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
  fd = mutable_fs_open(resolved, XAIOS_MFS_OPEN_WRITE | XAIOS_MFS_OPEN_CREATE |
                                  XAIOS_MFS_OPEN_TRUNCATE);
  if (fd < 0) {
    return command_fail(output, output_capacity, output_bytes,
                        "write: failed to open");
  }
  if (payload_len != 0U) {
    int64_t written = mutable_fs_write_fd((uint32_t)fd, payload, payload_len);
    if (written < 0 || ((uint64_t)written) != payload_len) {
      (void)mutable_fs_close((uint32_t)fd);
      return command_fail(output, output_capacity, output_bytes,
                          "write: write failed");
    }
  }
  if (mutable_fs_close((uint32_t)fd) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "write: close failed");
  }
  output[0] = '\0';
  return XAIOS_OK;
}

static xaios_status_t path_basename(const char *path, char *basename,
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

#define XAIOS_USTAR_BLOCK_SIZE UINT64_C(512)

static void bytes_zero(void *data, uint64_t size) {
  uint8_t *bytes = (uint8_t *)data;
  for (uint64_t i = 0U; i < size; ++i) bytes[i] = 0U;
}

static xaios_status_t ustar_put_octal(char *field, uint64_t width,
                                    uint64_t value) {
  if (field == 0 || width < 2U) return XAIOS_ERR_INVALID;
  for (uint64_t i = 0U; i + 1U < width; ++i) field[i] = '0';
  field[width - 1U] = '\0';
  uint64_t cursor = width - 1U;
  do {
    if (cursor == 0U) return XAIOS_ERR_INVALID;
    field[--cursor] = (char)('0' + (value & 7U));
    value >>= 3U;
  } while (value != 0U);
  return XAIOS_OK;
}

static xaios_status_t ustar_parse_octal(const char *field, uint64_t width,
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

static xaios_status_t ustar_set_path(char *header, const char *path) {
  uint64_t length = cstr_len(path);
  if (header == 0 || path == 0 || length == 0U || length > 255U)
    return XAIOS_ERR_INVALID;
  if (length <= 100U) {
    for (uint64_t i = 0U; i < length; ++i) header[i] = path[i];
    return XAIOS_OK;
  }
  uint64_t split = length;
  while (split > 0U) {
    --split;
    if (path[split] == '/' && split <= 155U && length - split - 1U <= 100U) {
      for (uint64_t i = 0U; i < split; ++i) header[345U + i] = path[i];
      for (uint64_t i = 0U; i < length - split - 1U; ++i)
        header[i] = path[split + 1U + i];
      return XAIOS_OK;
    }
  }
  return XAIOS_ERR_INVALID;
}

static xaios_status_t ustar_append_header(char *archive, uint64_t capacity,
                                         uint64_t *size, const char *path,
                                         uint64_t data_size, char type) {
  if (archive == 0 || size == 0 || *size > capacity ||
      capacity - *size < XAIOS_USTAR_BLOCK_SIZE)
    return XAIOS_ERR_NO_MEMORY;
  char *header = archive + *size;
  bytes_zero(header, XAIOS_USTAR_BLOCK_SIZE);
  if (ustar_set_path(header, path) != XAIOS_OK ||
      ustar_put_octal(header + 100U, 8U, type == '5' ? 0755U : 0644U) !=
          XAIOS_OK ||
      ustar_put_octal(header + 108U, 8U, 0U) != XAIOS_OK ||
      ustar_put_octal(header + 116U, 8U, 0U) != XAIOS_OK ||
      ustar_put_octal(header + 124U, 12U, data_size) != XAIOS_OK ||
      ustar_put_octal(header + 136U, 12U, 0U) != XAIOS_OK)
    return XAIOS_ERR_INVALID;
  for (uint64_t i = 148U; i < 156U; ++i) header[i] = ' ';
  header[156U] = type;
  header[257U] = 'u'; header[258U] = 's'; header[259U] = 't';
  header[260U] = 'a'; header[261U] = 'r';
  header[263U] = '0'; header[264U] = '0';
  (void)copy_cstr(header + 265U, 32U, "admin");
  (void)copy_cstr(header + 297U, 32U, "admin");
  uint64_t checksum = 0U;
  for (uint64_t i = 0U; i < XAIOS_USTAR_BLOCK_SIZE; ++i)
    checksum += (uint8_t)header[i];
  if (ustar_put_octal(header + 148U, 7U, checksum) != XAIOS_OK)
    return XAIOS_ERR_INVALID;
  header[154U] = '\0';
  header[155U] = ' ';
  *size += XAIOS_USTAR_BLOCK_SIZE;
  return XAIOS_OK;
}

static xaios_status_t ustar_build_path(const char *source, const char *name,
                                      char *archive, uint64_t capacity,
                                      uint64_t *archive_size) {
  xaios_mfs_stat_t stat;
  if (mutable_fs_stat(source, &stat) != XAIOS_OK) return XAIOS_ERR_NOT_FOUND;
  if (stat.type == 1U) {
    if (ustar_append_header(archive, capacity, archive_size, name, 0U, '5') !=
        XAIOS_OK)
      return XAIOS_ERR_NO_MEMORY;
    char listing[XAIOS_REMOTE_LOGIN_LIST_BYTES];
    uint64_t listing_size = 0U;
    if (mutable_fs_list(source, listing, sizeof(listing), &listing_size) !=
        XAIOS_OK)
      return XAIOS_ERR_IO;
    for (uint64_t start = 0U; start < listing_size;) {
      uint64_t end = start;
      while (end < listing_size && listing[end] != '\n') ++end;
      if (end != start) {
        char child[XAIOS_MFS_PATH_MAX];
        char child_source[XAIOS_MFS_PATH_MAX];
        char child_name[XAIOS_MFS_PATH_MAX];
        if (copy_cstr_range(child, sizeof(child), listing + start, end - start) !=
                XAIOS_OK ||
            path_join(child_source, sizeof(child_source), source, child) !=
                XAIOS_OK ||
            path_join(child_name, sizeof(child_name), name, child) != XAIOS_OK ||
            ustar_build_path(child_source, child_name, archive, capacity,
                             archive_size) != XAIOS_OK)
          return XAIOS_ERR_INVALID;
      }
      start = end + 1U;
    }
    return XAIOS_OK;
  }
  if (stat.type != 2U || stat.size > XAIOS_MFS_MAX_FILE_BYTES_V4)
    return XAIOS_ERR_INVALID;
  if (stat.size > UINT64_MAX - 511U) return XAIOS_ERR_INVALID;
  uint64_t padded = (stat.size + 511U) & ~UINT64_C(511);
  if (capacity - *archive_size < XAIOS_USTAR_BLOCK_SIZE + padded ||
      ustar_append_header(archive, capacity, archive_size, name, stat.size,
                          '0') != XAIOS_OK)
    return XAIOS_ERR_NO_MEMORY;
  uint64_t read_size = 0U;
  if (mutable_fs_read(source, archive + *archive_size, stat.size, &read_size) !=
          XAIOS_OK ||
      read_size != stat.size)
    return XAIOS_ERR_IO;
  bytes_zero(archive + *archive_size + stat.size, padded - stat.size);
  *archive_size += padded;
  return XAIOS_OK;
}

static int ustar_block_is_zero(const char *block) {
  for (uint64_t i = 0U; i < XAIOS_USTAR_BLOCK_SIZE; ++i)
    if (block[i] != '\0') return 0;
  return 1;
}

static xaios_status_t ustar_header_path(const char *header, char *path,
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

static int archive_path_is_safe(const char *path) {
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

static xaios_status_t pax_extract_path(const char *data, uint64_t size,
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

static xaios_status_t gzip_decode(const uint8_t *input, uint64_t input_size,
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

static xaios_status_t ustar_walk(const char *archive_path,
                                const char *destination, int extract,
                                char *output, uint64_t output_capacity,
                                uint64_t *output_bytes) {
  char *archive = (char *)kheap_alloc(XAIOS_MFS_MAX_FILE_BYTES_V4, 16U);
  char *decoded = 0;
  uint64_t archive_size = 0U;
  xaios_status_t status = XAIOS_ERR_INVALID;
  if (archive == 0) return XAIOS_ERR_NO_MEMORY;
  if (mutable_fs_read(archive_path, archive, XAIOS_MFS_MAX_FILE_BYTES_V4,
                      &archive_size) != XAIOS_OK)
    goto done;
  if (archive_size >= 2U && (uint8_t)archive[0] == UINT8_C(0x1f) &&
      (uint8_t)archive[1] == UINT8_C(0x8b)) {
    uint64_t decoded_size = 0U;
    decoded = (char *)kheap_alloc(XAIOS_MFS_MAX_FILE_BYTES_V4, 16U);
    if (decoded == 0 ||
        gzip_decode((const uint8_t *)archive, archive_size, (uint8_t *)decoded,
                    XAIOS_MFS_MAX_FILE_BYTES_V4, &decoded_size) != XAIOS_OK)
      goto done;
    kheap_free(archive);
    archive = decoded;
    decoded = 0;
    archive_size = decoded_size;
  }
  char extended_path[XAIOS_MFS_PATH_MAX];
  extended_path[0] = '\0';
  for (uint64_t cursor = 0U; cursor + XAIOS_USTAR_BLOCK_SIZE <= archive_size;) {
    const char *header = archive + cursor;
    if (ustar_block_is_zero(header) != 0) {
      status = XAIOS_OK;
      goto done;
    }
    uint64_t stored_checksum = 0U;
    uint64_t size = 0U;
    if (ustar_parse_octal(header + 148U, 8U, &stored_checksum) != XAIOS_OK ||
        ustar_parse_octal(header + 124U, 12U, &size) != XAIOS_OK)
      goto done;
    uint64_t checksum = 0U;
    for (uint64_t i = 0U; i < XAIOS_USTAR_BLOCK_SIZE; ++i)
      checksum += (i >= 148U && i < 156U) ? (uint8_t)' ' : (uint8_t)header[i];
    if (checksum != stored_checksum) goto done;
    if (size > UINT64_MAX - 511U) goto done;
    uint64_t padded = (size + 511U) & ~UINT64_C(511);
    if (padded > archive_size - cursor - 512U)
      goto done;
    char type = header[156U] == '\0' ? '0' : header[156U];
    const char *payload = archive + cursor + XAIOS_USTAR_BLOCK_SIZE;
    if (type == 'x' || type == 'g') {
      if (type == 'x' &&
          pax_extract_path(payload, size, extended_path,
                           sizeof(extended_path)) != XAIOS_OK)
        goto done;
      cursor += XAIOS_USTAR_BLOCK_SIZE + padded;
      continue;
    }
    if (type == 'L') {
      uint64_t path_size = 0U;
      while (path_size < size && payload[path_size] != '\0' &&
             payload[path_size] != '\n') ++path_size;
      if (path_size == 0U || path_size + 1U > sizeof(extended_path)) goto done;
      for (uint64_t i = 0U; i < path_size; ++i)
        extended_path[i] = payload[i];
      extended_path[path_size] = '\0';
      cursor += XAIOS_USTAR_BLOCK_SIZE + padded;
      continue;
    }
    char name[XAIOS_MFS_PATH_MAX];
    if (extended_path[0] != '\0') {
      if (copy_cstr(name, sizeof(name), extended_path) != XAIOS_OK) goto done;
      extended_path[0] = '\0';
    } else if (ustar_header_path(header, name, sizeof(name)) != XAIOS_OK) {
      goto done;
    }
    if (archive_path_is_safe(name) == 0) goto done;
    if (type == '0' || type == '5') {
      if (output != 0) {
        output_append(output, output_capacity, output_bytes, name);
        if (type == '5' && name[cstr_len(name) - 1U] != '/')
          output_append_char(output, output_capacity, output_bytes, '/');
        output_append_char(output, output_capacity, output_bytes, '\n');
      }
      if (extract != 0) {
        char target[XAIOS_MFS_PATH_MAX];
        if (path_join(target, sizeof(target), destination, name) != XAIOS_OK)
          goto done;
        if (type == '5') {
          if (mkdir_resolved(target, 1) != XAIOS_OK) goto done;
        } else {
          if (remote_ensure_parent(target) != XAIOS_OK ||
              write_buffer_to_path(target, archive + cursor + 512U, size) !=
                  XAIOS_OK)
            goto done;
        }
      }
    } else {
      goto done;
    }
    cursor += XAIOS_USTAR_BLOCK_SIZE + padded;
  }
done:
  kheap_free(decoded);
  kheap_free(archive);
  return status;
}

static xaios_status_t handle_tar(const char *args, char *output,
                               uint64_t output_capacity,
                               uint64_t *output_bytes) {
  uint64_t arg_index = 0U;
  char mode[32];
  char token[XAIOS_MFS_PATH_MAX];
  char archive_token[XAIOS_MFS_PATH_MAX];
  char archive_path[XAIOS_MFS_PATH_MAX];
  char destination_path[XAIOS_MFS_PATH_MAX];
  int operation = 0;
  int has_file = 0;
  int verbose = 0;
  int gzip = 0;

  if (token_next(args, &arg_index, mode, sizeof(mode)) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                       "tar: missing options");
  }
  uint64_t option_start = mode[0] == '-' ? 1U : 0U;
  for (uint64_t i = option_start; mode[i] != '\0'; ++i) {
    if (mode[i] == 'c' || mode[i] == 'x' || mode[i] == 't') {
      if (operation != 0) return command_fail(output, output_capacity,
                                               output_bytes,
                                               "tar: conflicting operation");
      operation = mode[i];
    } else if (mode[i] == 'f') {
      has_file = 1;
    } else if (mode[i] == 'v') {
      verbose = 1;
    } else if (mode[i] == 'z') {
      gzip = 1;
    } else {
      return command_fail(output, output_capacity, output_bytes,
                          "tar: unsupported option");
    }
  }
  if (operation == 0)
    return command_fail(output, output_capacity, output_bytes,
                        "tar: missing operation");
  if (operation == 'c' && gzip != 0)
    return command_fail(output, output_capacity, output_bytes,
                        "tar: gzip creation is not supported; use zip -r");
  if (has_file == 0) {
    if (token_next(args, &arg_index, token, sizeof(token)) != XAIOS_OK ||
        string_equal(token, "-f") == 0)
      return command_fail(output, output_capacity, output_bytes,
                          "tar: archive must be specified with -f");
  }
  if (token_next(args, &arg_index, archive_token, sizeof(archive_token)) !=
      XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "tar: missing archive");
  }
  if (remote_path_resolve(g_remote_login_cwd, archive_token, archive_path,
                          sizeof(archive_path)) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "tar: cannot resolve archive");
  }

  if (operation == 't') {
    if (token_next(args, &arg_index, token, sizeof(token)) == XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "tar: too many arguments");
    }
    if (ustar_walk(archive_path, g_remote_login_cwd, 0, output,
                   output_capacity, output_bytes) !=
        XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "tar: cannot list archive");
    }
    return XAIOS_OK;
  }

  if (operation == 'x') {
    int saw_destination = 0;
    while (token_next(args, &arg_index, token, sizeof(token)) == XAIOS_OK) {
      if (string_equal(token, "-C") == 1U) {
        if (saw_destination != 0U) {
          return command_fail(output, output_capacity, output_bytes,
                              "tar: duplicate destination");
        }
        if (token_next(args, &arg_index, token, sizeof(token)) != XAIOS_OK) {
          return command_fail(output, output_capacity, output_bytes,
                              "tar: missing destination");
        }
        if (copy_cstr(destination_path, sizeof(destination_path), token) != XAIOS_OK) {
          return XAIOS_ERR_NO_MEMORY;
        }
        saw_destination = 1;
        continue;
      }
      return command_fail(output, output_capacity, output_bytes,
                         "tar: unsupported option");
    }
    if (saw_destination == 0U) {
      if (copy_cstr(destination_path, sizeof(destination_path),
                   g_remote_login_cwd) != XAIOS_OK) {
        return command_fail(output, output_capacity, output_bytes,
                            "tar: destination state error");
      }
    }
    if (remote_path_resolve(g_remote_login_cwd, destination_path,
                            destination_path, sizeof(destination_path)) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "tar: invalid destination");
    }
    xaios_mfs_stat_t destination_stat;
    if (mutable_fs_stat(destination_path, &destination_stat) != XAIOS_OK ||
        destination_stat.type != 1U ||
        ustar_walk(archive_path, destination_path, 1,
                   verbose != 0 ? output : 0, output_capacity,
                   output_bytes) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                         "tar: extract failed");
    }
    output[0] = '\0';
    return XAIOS_OK;
  }

  char *archive = (char *)kheap_alloc(XAIOS_MFS_MAX_FILE_BYTES_V4, 16U);
  if (archive == 0)
    return command_fail(output, output_capacity, output_bytes,
                        "tar: memory unavailable");
  uint64_t archive_size = 0U;
  uint32_t sources = 0U;
  xaios_status_t status = XAIOS_OK;
  while (token_next(args, &arg_index, token, sizeof(token)) == XAIOS_OK) {
    char source_path[XAIOS_MFS_PATH_MAX];
    char source_name[XAIOS_MFS_PATH_MAX];
    if (remote_path_resolve(g_remote_login_cwd, token, source_path,
                            sizeof(source_path)) != XAIOS_OK ||
        path_basename(source_path, source_name, sizeof(source_name)) !=
            XAIOS_OK ||
        ustar_build_path(source_path, source_name, archive,
                         XAIOS_MFS_MAX_FILE_BYTES_V4 - 1024U,
                         &archive_size) != XAIOS_OK) {
      status = XAIOS_ERR_INVALID;
      break;
    }
    if (verbose != 0) {
      output_append(output, output_capacity, output_bytes, source_name);
      output_append_char(output, output_capacity, output_bytes, '\n');
    }
    ++sources;
  }
  if (status == XAIOS_OK && sources != 0U) {
    bytes_zero(archive + archive_size, 1024U);
    archive_size += 1024U;
    status = write_buffer_to_path(archive_path, archive, archive_size);
  }
  kheap_free(archive);
  if (sources == 0U)
    return command_fail(output, output_capacity, output_bytes,
                        "tar: missing files");
  if (status != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "tar: cannot create archive");
  }
  return XAIOS_OK;
}

#define XAIOS_ZIP_MAX_ENTRIES 128U

typedef struct xaios_zip_entry {
  char name[XAIOS_MFS_PATH_MAX];
  uint32_t crc32;
  uint32_t size;
  uint32_t local_offset;
  uint8_t directory;
} xaios_zip_entry_t;

static uint16_t read_le16(const uint8_t *data) {
  return (uint16_t)((uint16_t)data[0] | ((uint16_t)data[1] << 8U));
}

static uint32_t read_le32(const uint8_t *data) {
  return (uint32_t)data[0] | ((uint32_t)data[1] << 8U) |
         ((uint32_t)data[2] << 16U) | ((uint32_t)data[3] << 24U);
}

static void write_le16(uint8_t *data, uint16_t value) {
  data[0] = (uint8_t)value;
  data[1] = (uint8_t)(value >> 8U);
}

static void write_le32(uint8_t *data, uint32_t value) {
  data[0] = (uint8_t)value;
  data[1] = (uint8_t)(value >> 8U);
  data[2] = (uint8_t)(value >> 16U);
  data[3] = (uint8_t)(value >> 24U);
}

static xaios_status_t zip_append_path(
    const char *source, const char *name, int recursive, uint8_t *archive,
    uint64_t capacity, uint64_t *archive_size, xaios_zip_entry_t *entries,
    uint32_t *entry_count) {
  xaios_mfs_stat_t stat;
  if (*entry_count >= XAIOS_ZIP_MAX_ENTRIES ||
      mutable_fs_stat(source, &stat) != XAIOS_OK)
    return XAIOS_ERR_INVALID;
  uint64_t name_len = cstr_len(name);
  if (name_len == 0U || name_len > UINT16_MAX) return XAIOS_ERR_INVALID;
  if (stat.type == 1U && recursive == 0) return XAIOS_ERR_INVALID;

  char entry_name[XAIOS_MFS_PATH_MAX];
  if (copy_cstr(entry_name, sizeof(entry_name), name) != XAIOS_OK)
    return XAIOS_ERR_INVALID;
  if (stat.type == 1U && entry_name[name_len - 1U] != '/') {
    if (name_len + 2U > sizeof(entry_name)) return XAIOS_ERR_INVALID;
    entry_name[name_len++] = '/';
    entry_name[name_len] = '\0';
  }
  uint64_t data_size = stat.type == 2U ? stat.size : 0U;
  if (data_size > UINT32_MAX ||
      capacity - *archive_size < 30U + name_len + data_size)
    return XAIOS_ERR_NO_MEMORY;
  xaios_zip_entry_t *entry = &entries[*entry_count];
  bytes_zero(entry, sizeof(*entry));
  if (copy_cstr(entry->name, sizeof(entry->name), entry_name) != XAIOS_OK)
    return XAIOS_ERR_INVALID;
  entry->size = (uint32_t)data_size;
  entry->local_offset = (uint32_t)*archive_size;
  entry->directory = stat.type == 1U ? 1U : 0U;

  uint8_t *header = archive + *archive_size;
  bytes_zero(header, 30U);
  write_le32(header, UINT32_C(0x04034b50));
  write_le16(header + 4U, 20U);
  write_le16(header + 8U, 0U);
  write_le16(header + 26U, (uint16_t)name_len);
  for (uint64_t i = 0U; i < name_len; ++i) header[30U + i] = entry_name[i];
  *archive_size += 30U + name_len;
  if (data_size != 0U) {
    uint64_t got = 0U;
    if (mutable_fs_read(source, archive + *archive_size, data_size, &got) !=
            XAIOS_OK ||
        got != data_size)
      return XAIOS_ERR_IO;
    entry->crc32 = xaios_crc32(archive + *archive_size, data_size);
    *archive_size += data_size;
  }
  write_le32(header + 14U, entry->crc32);
  write_le32(header + 18U, entry->size);
  write_le32(header + 22U, entry->size);
  ++(*entry_count);

  if (stat.type != 1U) return XAIOS_OK;
  char listing[XAIOS_REMOTE_LOGIN_LIST_BYTES];
  uint64_t listing_size = 0U;
  if (mutable_fs_list(source, listing, sizeof(listing), &listing_size) !=
      XAIOS_OK)
    return XAIOS_ERR_IO;
  for (uint64_t start = 0U; start < listing_size;) {
    uint64_t end = start;
    while (end < listing_size && listing[end] != '\n') ++end;
    if (end != start) {
      char child[XAIOS_MFS_PATH_MAX];
      char child_source[XAIOS_MFS_PATH_MAX];
      char child_name[XAIOS_MFS_PATH_MAX];
      if (copy_cstr_range(child, sizeof(child), listing + start, end - start) !=
              XAIOS_OK ||
          path_join(child_source, sizeof(child_source), source, child) !=
              XAIOS_OK ||
          path_join(child_name, sizeof(child_name), name, child) != XAIOS_OK ||
          zip_append_path(child_source, child_name, recursive, archive,
                          capacity, archive_size, entries, entry_count) !=
              XAIOS_OK)
        return XAIOS_ERR_INVALID;
    }
    start = end + 1U;
  }
  return XAIOS_OK;
}

static xaios_status_t zip_finish(uint8_t *archive, uint64_t capacity,
                                uint64_t *archive_size,
                                const xaios_zip_entry_t *entries,
                                uint32_t entry_count) {
  uint64_t central_offset = *archive_size;
  for (uint32_t i = 0U; i < entry_count; ++i) {
    uint64_t name_len = cstr_len(entries[i].name);
    if (capacity - *archive_size < 46U + name_len) return XAIOS_ERR_NO_MEMORY;
    uint8_t *header = archive + *archive_size;
    bytes_zero(header, 46U);
    write_le32(header, UINT32_C(0x02014b50));
    write_le16(header + 4U, UINT16_C(0x031e));
    write_le16(header + 6U, 20U);
    write_le32(header + 16U, entries[i].crc32);
    write_le32(header + 20U, entries[i].size);
    write_le32(header + 24U, entries[i].size);
    write_le16(header + 28U, (uint16_t)name_len);
    write_le32(header + 38U,
               entries[i].directory != 0U ? UINT32_C(0040755) << 16U
                                          : UINT32_C(0100644) << 16U);
    write_le32(header + 42U, entries[i].local_offset);
    for (uint64_t j = 0U; j < name_len; ++j) header[46U + j] = entries[i].name[j];
    *archive_size += 46U + name_len;
  }
  uint64_t central_size = *archive_size - central_offset;
  if (entry_count > UINT16_MAX || central_offset > UINT32_MAX ||
      central_size > UINT32_MAX || capacity - *archive_size < 22U)
    return XAIOS_ERR_NO_MEMORY;
  uint8_t *end = archive + *archive_size;
  bytes_zero(end, 22U);
  write_le32(end, UINT32_C(0x06054b50));
  write_le16(end + 8U, (uint16_t)entry_count);
  write_le16(end + 10U, (uint16_t)entry_count);
  write_le32(end + 12U, (uint32_t)central_size);
  write_le32(end + 16U, (uint32_t)central_offset);
  *archive_size += 22U;
  return XAIOS_OK;
}

static xaios_status_t handle_zip(const char *args, char *output,
                                uint64_t output_capacity,
                                uint64_t *output_bytes) {
  uint64_t index = 0U;
  int recursive = 0;
  char token[XAIOS_MFS_PATH_MAX];
  char archive_token[XAIOS_MFS_PATH_MAX];
  if (token_next(args, &index, token, sizeof(token)) != XAIOS_OK)
    return command_fail(output, output_capacity, output_bytes,
                        "zip: missing archive");
  if (string_equal(token, "-r")) {
    recursive = 1;
    if (token_next(args, &index, archive_token, sizeof(archive_token)) !=
        XAIOS_OK)
      return command_fail(output, output_capacity, output_bytes,
                          "zip: missing archive");
  } else if (copy_cstr(archive_token, sizeof(archive_token), token) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "zip: invalid archive");
  }
  char archive_path[XAIOS_MFS_PATH_MAX];
  if (remote_path_resolve(g_remote_login_cwd, archive_token, archive_path,
                          sizeof(archive_path)) != XAIOS_OK)
    return command_fail(output, output_capacity, output_bytes,
                        "zip: invalid archive");
  uint8_t *archive = (uint8_t *)kheap_alloc(XAIOS_MFS_MAX_FILE_BYTES_V4, 16U);
  xaios_zip_entry_t *entries = (xaios_zip_entry_t *)kheap_calloc(
      sizeof(xaios_zip_entry_t) * XAIOS_ZIP_MAX_ENTRIES, 16U);
  if (archive == 0 || entries == 0) {
    kheap_free(archive);
    kheap_free(entries);
    return command_fail(output, output_capacity, output_bytes,
                        "zip: memory unavailable");
  }
  uint64_t archive_size = 0U;
  uint32_t entry_count = 0U;
  xaios_status_t status = XAIOS_OK;
  while (token_next(args, &index, token, sizeof(token)) == XAIOS_OK) {
    char source[XAIOS_MFS_PATH_MAX];
    char name[XAIOS_MFS_PATH_MAX];
    if (remote_path_resolve(g_remote_login_cwd, token, source,
                            sizeof(source)) != XAIOS_OK ||
        path_basename(source, name, sizeof(name)) != XAIOS_OK ||
        zip_append_path(source, name, recursive, archive,
                        XAIOS_MFS_MAX_FILE_BYTES_V4, &archive_size, entries,
                        &entry_count) != XAIOS_OK) {
      status = XAIOS_ERR_INVALID;
      break;
    }
    output_append(output, output_capacity, output_bytes, "  adding: ");
    output_append(output, output_capacity, output_bytes, name);
    output_append_char(output, output_capacity, output_bytes, '\n');
  }
  if (entry_count == 0U) status = XAIOS_ERR_INVALID;
  if (status == XAIOS_OK)
    status = zip_finish(archive, XAIOS_MFS_MAX_FILE_BYTES_V4, &archive_size,
                        entries, entry_count);
  if (status == XAIOS_OK)
    status = write_buffer_to_path(archive_path, (const char *)archive,
                                  archive_size);
  kheap_free(entries);
  kheap_free(archive);
  if (status != XAIOS_OK)
    return command_fail(output, output_capacity, output_bytes,
                        "zip: cannot create archive");
  return XAIOS_OK;
}

static xaios_status_t unzip_archive(const char *archive_path,
                                    const char *destination, int list_only,
                                    char *output, uint64_t output_capacity,
                                    uint64_t *output_bytes) {
  uint8_t *archive = (uint8_t *)kheap_alloc(XAIOS_MFS_MAX_FILE_BYTES_V4, 16U);
  uint64_t archive_size = 0U;
  xaios_status_t status = XAIOS_ERR_INVALID;
  if (archive == 0) return XAIOS_ERR_NO_MEMORY;
  if (mutable_fs_read(archive_path, archive, XAIOS_MFS_MAX_FILE_BYTES_V4,
                      &archive_size) != XAIOS_OK ||
      archive_size < 22U)
    goto done;
  uint64_t end_offset = archive_size - 22U;
  uint64_t search_floor = archive_size > 65557U ? archive_size - 65557U : 0U;
  while (read_le32(archive + end_offset) != UINT32_C(0x06054b50)) {
    if (end_offset == search_floor) goto done;
    --end_offset;
  }
  uint16_t entries = read_le16(archive + end_offset + 10U);
  uint32_t central_size = read_le32(archive + end_offset + 12U);
  uint32_t central_offset = read_le32(archive + end_offset + 16U);
  if (read_le16(archive + end_offset + 4U) != 0U ||
      read_le16(archive + end_offset + 6U) != 0U ||
      entries != read_le16(archive + end_offset + 8U) ||
      (uint64_t)central_offset + central_size > end_offset)
    goto done;
  uint64_t cursor = central_offset;
  for (uint16_t entry_index = 0U; entry_index < entries; ++entry_index) {
    if (cursor + 46U > archive_size ||
        read_le32(archive + cursor) != UINT32_C(0x02014b50))
      goto done;
    uint16_t flags = read_le16(archive + cursor + 8U);
    uint16_t method = read_le16(archive + cursor + 10U);
    uint32_t crc = read_le32(archive + cursor + 16U);
    uint32_t compressed = read_le32(archive + cursor + 20U);
    uint32_t uncompressed = read_le32(archive + cursor + 24U);
    uint16_t name_len = read_le16(archive + cursor + 28U);
    uint16_t extra_len = read_le16(archive + cursor + 30U);
    uint16_t comment_len = read_le16(archive + cursor + 32U);
    uint32_t local_offset = read_le32(archive + cursor + 42U);
    uint64_t next = cursor + 46U + name_len + extra_len + comment_len;
    if (name_len == 0U || name_len >= XAIOS_MFS_PATH_MAX ||
        next > archive_size || (flags & 1U) != 0U ||
        (method != 0U && method != 8U))
      goto done;
    char name[XAIOS_MFS_PATH_MAX];
    if (copy_cstr_range(name, sizeof(name),
                        (const char *)archive + cursor + 46U, name_len) !=
            XAIOS_OK ||
        archive_path_is_safe(name) == 0)
      goto done;
    output_append(output, output_capacity, output_bytes, name);
    output_append_char(output, output_capacity, output_bytes, '\n');
    int directory = name[name_len - 1U] == '/';
    if (list_only == 0) {
      char target[XAIOS_MFS_PATH_MAX];
      if (path_join(target, sizeof(target), destination, name) != XAIOS_OK)
        goto done;
      if (directory != 0) {
        if (mkdir_resolved(target, 1) != XAIOS_OK) goto done;
      } else {
        if ((uint64_t)local_offset + 30U > archive_size ||
            read_le32(archive + local_offset) != UINT32_C(0x04034b50))
          goto done;
        uint16_t local_name = read_le16(archive + local_offset + 26U);
        uint16_t local_extra = read_le16(archive + local_offset + 28U);
        uint64_t data_offset = (uint64_t)local_offset + 30U + local_name +
                               local_extra;
        if (data_offset > archive_size || compressed > archive_size - data_offset ||
            uncompressed > XAIOS_MFS_MAX_FILE_BYTES_V4)
          goto done;
        uint8_t *decoded = archive + data_offset;
        uint8_t *allocated = 0;
        uint64_t decoded_size = compressed;
        if (method == 8U) {
          allocated = (uint8_t *)kheap_alloc(uncompressed == 0U ? 1U : uncompressed,
                                             16U);
          if (allocated == 0 ||
              xaios_inflate_raw(archive + data_offset, compressed, allocated,
                                uncompressed, &decoded_size) != XAIOS_OK) {
            kheap_free(allocated);
            goto done;
          }
          decoded = allocated;
        }
        if (decoded_size != uncompressed ||
            xaios_crc32(decoded, decoded_size) != crc ||
            remote_ensure_parent(target) != XAIOS_OK ||
            write_buffer_to_path(target, (const char *)decoded, decoded_size) !=
                XAIOS_OK) {
          kheap_free(allocated);
          goto done;
        }
        kheap_free(allocated);
      }
    }
    cursor = next;
  }
  status = XAIOS_OK;
done:
  kheap_free(archive);
  return status;
}

static xaios_status_t handle_unzip(const char *args, char *output,
                                  uint64_t output_capacity,
                                  uint64_t *output_bytes) {
  uint64_t index = 0U;
  int list_only = 0;
  char token[XAIOS_MFS_PATH_MAX];
  char archive_token[XAIOS_MFS_PATH_MAX];
  if (token_next(args, &index, token, sizeof(token)) != XAIOS_OK)
    return command_fail(output, output_capacity, output_bytes,
                        "unzip: missing archive");
  if (string_equal(token, "-l")) {
    list_only = 1;
    if (token_next(args, &index, archive_token, sizeof(archive_token)) !=
        XAIOS_OK)
      return command_fail(output, output_capacity, output_bytes,
                          "unzip: missing archive");
  } else if (copy_cstr(archive_token, sizeof(archive_token), token) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "unzip: invalid archive");
  }
  char destination[XAIOS_MFS_PATH_MAX];
  if (copy_cstr(destination, sizeof(destination), g_remote_login_cwd) != XAIOS_OK)
    return XAIOS_ERR_INVALID;
  if (token_next(args, &index, token, sizeof(token)) == XAIOS_OK) {
    if (list_only != 0 || string_equal(token, "-d") == 0 ||
        token_next(args, &index, token, sizeof(token)) != XAIOS_OK ||
        remote_path_resolve(g_remote_login_cwd, token, destination,
                            sizeof(destination)) != XAIOS_OK ||
        has_more_args(args, index) != 0)
      return command_fail(output, output_capacity, output_bytes,
                          "unzip: invalid destination");
  }
  char archive_path[XAIOS_MFS_PATH_MAX];
  xaios_mfs_stat_t stat;
  if (remote_path_resolve(g_remote_login_cwd, archive_token, archive_path,
                          sizeof(archive_path)) != XAIOS_OK ||
      (list_only == 0 &&
       (mutable_fs_stat(destination, &stat) != XAIOS_OK || stat.type != 1U)) ||
      unzip_archive(archive_path, destination, list_only, output,
                    output_capacity, output_bytes) != XAIOS_OK)
    return command_fail(output, output_capacity, output_bytes,
                        "unzip: invalid or unsupported archive");
  return XAIOS_OK;
}

static xaios_status_t handle_cpio(const char *args, char *output,
                                uint64_t output_capacity,
                                uint64_t *output_bytes) {
  uint64_t arg_index = 0;
  char mode[32];
  char token[XAIOS_MFS_PATH_MAX];
  char archive_token[XAIOS_MFS_PATH_MAX];
  char archive_path[XAIOS_MFS_PATH_MAX];
  char source_token[XAIOS_MFS_PATH_MAX];
  char source_path[XAIOS_MFS_PATH_MAX];
  char source_archive_name[XAIOS_MFS_PATH_MAX];
  char archive[XAIOS_MFS_MAX_FILE_BYTES];
  uint64_t archive_size = 0;
  uint64_t source_count = 0;
  int can_create = 0;
  int can_extract = 0;
  int can_list = 0;
  int has_archive = 0;

  if (token_next(args, &arg_index, mode, sizeof(mode)) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                       "cpio: missing options");
  }
  if (mode[0] != '-') {
    return command_fail(output, output_capacity, output_bytes,
                        "cpio: unsupported option");
  }
  for (uint64_t i = 1U; mode[i] != '\0'; ++i) {
    if (mode[i] == 'o') {
      can_create = 1;
      continue;
    }
    if (mode[i] == 'i') {
      can_extract = 1;
      continue;
    }
    if (mode[i] == 't') {
      can_list = 1;
      continue;
    }
    return command_fail(output, output_capacity, output_bytes,
                        "cpio: unsupported option");
  }
  if ((can_create + can_extract + can_list) != 1) {
    return command_fail(output, output_capacity, output_bytes,
                        "cpio: unsupported option");
  }

  if (can_create != 0U) {
    if (buffer_append_text(archive, sizeof(archive), &archive_size,
                          g_remote_login_archive_magic) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "cpio: archive too large");
    }
    if (token_next(args, &arg_index, token, sizeof(token)) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "cpio: missing source");
    }
    while (1) {
      if (string_equal(token, "-O") == 1U) {
        if (token_next(args, &arg_index, archive_token, sizeof(archive_token)) !=
            XAIOS_OK) {
          return command_fail(output, output_capacity, output_bytes,
                              "cpio: missing archive");
        }
        if (copy_cstr(archive_path, sizeof(archive_path), archive_token) != XAIOS_OK) {
          return command_fail(output, output_capacity, output_bytes,
                              "cpio: invalid archive");
        }
        if (remote_path_resolve(g_remote_login_cwd, archive_path, archive_path,
                                sizeof(archive_path)) != XAIOS_OK) {
          return command_fail(output, output_capacity, output_bytes,
                              "cpio: invalid archive");
        }
        has_archive = 1;
      } else if (token[0] == '-') {
        return command_fail(output, output_capacity, output_bytes,
                            "cpio: unsupported option");
      } else {
        if (copy_cstr(source_token, sizeof(source_token), token) != XAIOS_OK) {
          return command_fail(output, output_capacity, output_bytes,
                              "cpio: invalid source");
        }
        if (remote_path_resolve(g_remote_login_cwd, source_token, source_path,
                                sizeof(source_path)) != XAIOS_OK) {
          return command_fail(output, output_capacity, output_bytes,
                              "cpio: invalid source");
        }
        if (path_basename(source_path, source_archive_name,
                          sizeof(source_archive_name)) != XAIOS_OK) {
          return command_fail(output, output_capacity, output_bytes,
                              "cpio: invalid source");
        }
        if (archive_build_from_path(source_path, source_archive_name, archive,
                                   sizeof(archive), &archive_size) != XAIOS_OK) {
          return command_fail(output, output_capacity, output_bytes,
                              "cpio: cannot add source");
        }
        ++source_count;
      }
      if (token_next(args, &arg_index, token, sizeof(token)) != XAIOS_OK) {
        break;
      }
    }
    if (has_archive == 0U) {
      return command_fail(output, output_capacity, output_bytes,
                          "cpio: missing archive");
    }
    if (source_count == 0U) {
      return command_fail(output, output_capacity, output_bytes,
                          "cpio: missing source");
    }
    if (write_buffer_to_path(archive_path, archive, archive_size) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "cpio: cannot write archive");
    }
    output[0] = '\0';
    return XAIOS_OK;
  }

  if (token_next(args, &arg_index, token, sizeof(token)) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "cpio: missing archive");
  }
  if (string_equal(token, "-I") != 1U) {
    return command_fail(output, output_capacity, output_bytes,
                        "cpio: expected -I");
  }
  if (token_next(args, &arg_index, archive_token, sizeof(archive_token)) !=
      XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "cpio: missing archive");
  }
  if (copy_cstr(archive_path, sizeof(archive_path), archive_token) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes, "cpio: invalid archive");
  }
  if (remote_path_resolve(g_remote_login_cwd, archive_path, archive_path,
                          sizeof(archive_path)) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "cpio: invalid archive");
  }
  if (has_archive == 0U) {
    has_archive = 1;
  }
  if (token_next(args, &arg_index, token, sizeof(token)) == XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "cpio: too many arguments");
  }
  if (can_list != 0) {
    if (archive_list(archive_path, output, output_capacity, output_bytes) !=
        XAIOS_OK)
      return command_fail(output, output_capacity, output_bytes,
                          "cpio: list failed");
    return XAIOS_OK;
  }
  if (archive_extract_to(archive_path, g_remote_login_cwd) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "cpio: extract failed");
  }
  output[0] = '\0';
  return XAIOS_OK;
}

static xaios_status_t move_path(const char *src, const char *dst) {
  char resolved_src[XAIOS_MFS_PATH_MAX];
  char resolved_dst[XAIOS_MFS_PATH_MAX];
  if (src == 0 || dst == 0 || src[0] == '\0' || dst[0] == '\0')
    return XAIOS_ERR_INVALID;
  if (remote_path_resolve(g_remote_login_cwd, src, resolved_src,
                         sizeof(resolved_src)) != XAIOS_OK ||
      remote_path_resolve(g_remote_login_cwd, dst, resolved_dst,
                         sizeof(resolved_dst)) != XAIOS_OK)
    return XAIOS_ERR_INVALID;
  xaios_mfs_stat_t destination;
  if (mutable_fs_stat(resolved_dst, &destination) == XAIOS_OK &&
      destination.type == 1U) {
    char basename[XAIOS_MFS_PATH_MAX];
    char target[XAIOS_MFS_PATH_MAX];
    if (path_basename(resolved_src, basename, sizeof(basename)) != XAIOS_OK ||
        path_join(target, sizeof(target), resolved_dst, basename) != XAIOS_OK ||
        copy_cstr(resolved_dst, sizeof(resolved_dst), target) != XAIOS_OK)
      return XAIOS_ERR_INVALID;
  }
  if (path_is_same_or_child(resolved_src, resolved_dst) != 0 ||
      remote_ensure_parent(resolved_dst) != XAIOS_OK)
    return XAIOS_ERR_INVALID;
  return mutable_fs_rename(resolved_src, resolved_dst);
}

static xaios_status_t handle_mv(const char *args, char *output,
                              uint64_t output_capacity,
                              uint64_t *output_bytes) {
  char operands[17][XAIOS_MFS_PATH_MAX];
  uint32_t count = 0U;
  uint64_t index = 0U;
  int end_options = 0;
  char token[XAIOS_MFS_PATH_MAX];
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
    char destination[XAIOS_MFS_PATH_MAX];
    xaios_mfs_stat_t stat;
    if (remote_path_resolve(g_remote_login_cwd, operands[count - 1U],
                            destination, sizeof(destination)) != XAIOS_OK ||
        mutable_fs_stat(destination, &stat) != XAIOS_OK || stat.type != 1U)
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
  char resolved[XAIOS_MFS_PATH_MAX];
  xaios_mfs_stat_t stat;
  if (arg == 0 || arg[0] == '\0' ||
      remote_path_resolve(g_remote_login_cwd, arg, resolved, sizeof(resolved)) !=
          XAIOS_OK || string_equal(resolved, "/")) {
    return XAIOS_ERR_INVALID;
  }
  if (mutable_fs_stat(resolved, &stat) != XAIOS_OK) {
    return force != 0 ? XAIOS_OK : XAIOS_ERR_NOT_FOUND;
  }
  if (stat.type == 1U && recursive == 0) return XAIOS_ERR_INVALID;
  if ((recursive != 0 ? mutable_fs_delete_tree(resolved)
                      : mutable_fs_delete(resolved)) != XAIOS_OK) {
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
  char token[XAIOS_MFS_PATH_MAX];
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
  char token[XAIOS_MFS_PATH_MAX];
  while (token_next(args, &index, token, sizeof(token)) == XAIOS_OK) {
    char resolved[XAIOS_MFS_PATH_MAX];
    xaios_mfs_stat_t stat;
    if (token[0] == '-' ||
        remote_path_resolve(g_remote_login_cwd, token, resolved,
                            sizeof(resolved)) != XAIOS_OK ||
        string_equal(resolved, "/") == 1U ||
        mutable_fs_stat(resolved, &stat) != XAIOS_OK || stat.type != 1U ||
        mutable_fs_delete(resolved) != XAIOS_OK) {
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

static uint64_t find_unquoted_char(const char *text, uint64_t start,
                                   char target) {
  if (text == 0) {
    return UINT64_MAX;
  }
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

static xaios_status_t handle_sed(const char *args, char *output,
                               uint64_t output_capacity,
                               uint64_t *output_bytes) {
  char expr[XAIOS_MFS_PATH_MAX];
  char path_arg[XAIOS_MFS_PATH_MAX];
  uint64_t arg_index = 0;
  char resolved[XAIOS_MFS_PATH_MAX];
  char data[XAIOS_MFS_MAX_FILE_BYTES];
  uint64_t data_size = 0;
  char result[XAIOS_MFS_MAX_FILE_BYTES];
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
  if (remote_path_resolve(g_remote_login_cwd, path_arg, resolved,
                          sizeof(resolved)) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "sed: cannot open file");
  }
  if (mutable_fs_read(resolved, data, sizeof(data), &data_size) != XAIOS_OK) {
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
  if (mutable_fs_write(resolved, result, result_len) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "sed: write error");
  }
  output_append(output, output_capacity, output_bytes, result);
  return XAIOS_OK;
}

static xaios_status_t nano_append_bytes(char *buffer, uint64_t capacity,
                                       uint64_t *offset, const char *data,
                                       uint64_t size) {
  if (buffer == 0 || offset == 0 || (data == 0 && size != 0U)) {
    return XAIOS_ERR_INVALID;
  }
  for (uint64_t i = 0; i < size; ++i) {
    if (buffer_append_char(buffer, capacity, offset, data[i]) != XAIOS_OK) {
      return XAIOS_ERR_NO_MEMORY;
    }
  }
  return XAIOS_OK;
}

static xaios_status_t nano_append_decoded(char *buffer, uint64_t capacity,
                                         uint64_t *offset,
                                         const char *text) {
  if (buffer == 0 || offset == 0 || text == 0) {
    return XAIOS_ERR_INVALID;
  }
  for (uint64_t i = 0; text[i] != '\0'; ++i) {
    char value = text[i];
    if (value == '\\' && text[i + 1U] != '\0') {
      char escaped = text[i + 1U];
      if (escaped == 'n') {
        value = '\n';
        ++i;
      } else if (escaped == 'r') {
        value = '\r';
        ++i;
      } else if (escaped == 't') {
        value = '\t';
        ++i;
      } else if (escaped == '\\') {
        value = '\\';
        ++i;
      }
    }
    if (buffer_append_char(buffer, capacity, offset, value) != XAIOS_OK) {
      return XAIOS_ERR_NO_MEMORY;
    }
  }
  return XAIOS_OK;
}

static xaios_status_t nano_find_line(const char *data, uint64_t size,
                                    uint64_t requested, uint64_t *start,
                                    uint64_t *end, uint64_t *next) {
  uint64_t current = 1U;
  uint64_t line_start = 0U;
  if (data == 0 || requested == 0U || start == 0 || end == 0 || next == 0) {
    return XAIOS_ERR_INVALID;
  }
  for (;;) {
    if (current == requested) {
      uint64_t line_end = line_start;
      while (line_end < size && data[line_end] != '\n') {
        ++line_end;
      }
      *start = line_start;
      *end = line_end;
      *next = line_end < size ? line_end + 1U : line_end;
      return XAIOS_OK;
    }
    while (line_start < size && data[line_start] != '\n') {
      ++line_start;
    }
    if (line_start >= size) {
      return XAIOS_ERR_NOT_FOUND;
    }
    ++line_start;
    ++current;
  }
}

static xaios_status_t nano_render_numbered(const char *data, uint64_t size,
                                          char *output,
                                          uint64_t output_capacity,
                                          uint64_t *output_bytes) {
  uint64_t line = 1U;
  uint64_t start = 0U;
  if (size == 0U) {
    output_append(output, output_capacity, output_bytes, "1  \n");
    return XAIOS_OK;
  }
  while (start < size) {
    uint64_t end = start;
    while (end < size && data[end] != '\n') {
      ++end;
    }
    output_append_u64(output, output_capacity, output_bytes, line);
    output_append(output, output_capacity, output_bytes, "  ");
    for (uint64_t i = start; i < end; ++i) {
      if (output_append_char(output, output_capacity, output_bytes, data[i]) !=
          XAIOS_OK) {
        return XAIOS_ERR_NO_MEMORY;
      }
    }
    if (output_append_char(output, output_capacity, output_bytes, '\n') !=
        XAIOS_OK) {
      return XAIOS_ERR_NO_MEMORY;
    }
    start = end < size ? end + 1U : end;
    ++line;
  }
  return XAIOS_OK;
}

static xaios_status_t handle_nano(const char *args, char *output,
                                 uint64_t output_capacity,
                                 uint64_t *output_bytes) {
  char path_arg[XAIOS_MFS_PATH_MAX];
  char action[24];
  char line_token[24];
  char resolved[XAIOS_MFS_PATH_MAX];
  char data[XAIOS_MFS_MAX_FILE_BYTES];
  char edited[XAIOS_MFS_MAX_FILE_BYTES];
  uint64_t data_size = 0U;
  uint64_t edited_size = 0U;
  uint64_t index = 0U;
  uint64_t line = 0U;
  uint64_t consumed = 0U;
  uint64_t line_start = 0U;
  uint64_t line_end = 0U;
  uint64_t line_next = 0U;
  xaios_mfs_stat_t stat;

  if (token_next(args, &index, path_arg, sizeof(path_arg)) != XAIOS_OK ||
      string_equal(path_arg, "--help") == 1U) {
    output_append(
        output, output_capacity, output_bytes,
        "nano PATH [--number|--write TEXT|--append TEXT|--insert LINE TEXT|"
        "--replace LINE TEXT|--delete LINE]\n"
        "TEXT escapes: \\n \\r \\t \\\\\n");
    return XAIOS_OK;
  }
  if (remote_path_resolve(g_remote_login_cwd, path_arg, resolved,
                          sizeof(resolved)) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "nano: invalid path");
  }

  xaios_status_t stat_status = mutable_fs_stat(resolved, &stat);
  if (stat_status == XAIOS_OK && stat.type != 2U) {
    return command_fail(output, output_capacity, output_bytes,
                        "nano: path is not a file");
  }
  if (stat_status == XAIOS_OK) {
    if (stat.size >= sizeof(data) ||
        mutable_fs_read(resolved, data, sizeof(data), &data_size) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "nano: file exceeds editor capacity");
    }
  } else {
    data_size = 0U;
  }
  data[data_size] = '\0';

  if (token_next(args, &index, action, sizeof(action)) != XAIOS_OK) {
    output_append(output, output_capacity, output_bytes, "nano: ");
    output_append(output, output_capacity, output_bytes, resolved);
    output_append(output, output_capacity, output_bytes,
                  stat_status == XAIOS_OK ? "\n" : " [ New File ]\n");
    if (nano_append_bytes(output, output_capacity, output_bytes, data,
                          data_size) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "nano: output buffer too small");
    }
    if (data_size != 0U && data[data_size - 1U] != '\n') {
      (void)output_append_char(output, output_capacity, output_bytes, '\n');
    }
    return XAIOS_OK;
  }

  if (string_equal(action, "--number") == 1U) {
    if (has_more_args(args, index) != 0) {
      return command_fail(output, output_capacity, output_bytes,
                          "nano: too many arguments");
    }
    return nano_render_numbered(data, data_size, output, output_capacity,
                                output_bytes);
  }
  if (remote_ensure_parent(resolved) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "nano: parent directory not found");
  }

  if (string_equal(action, "--write") == 1U) {
    const char *text = args + skip_ws(args, index);
    if (nano_append_decoded(edited, sizeof(edited), &edited_size, text) !=
        XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "nano: text exceeds editor capacity");
    }
  } else if (string_equal(action, "--append") == 1U) {
    const char *text = args + skip_ws(args, index);
    if (nano_append_bytes(edited, sizeof(edited), &edited_size, data,
                          data_size) != XAIOS_OK ||
        nano_append_decoded(edited, sizeof(edited), &edited_size, text) !=
            XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "nano: text exceeds editor capacity");
    }
  } else if (string_equal(action, "--insert") == 1U ||
             string_equal(action, "--replace") == 1U ||
             string_equal(action, "--delete") == 1U) {
    if (token_next(args, &index, line_token, sizeof(line_token)) != XAIOS_OK ||
        parse_u64_token(line_token, &line, &consumed) != XAIOS_OK ||
        consumed != cstr_len(line_token) || line == 0U ||
        nano_find_line(data, data_size, line, &line_start, &line_end,
                       &line_next) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "nano: invalid line number");
    }
    if (string_equal(action, "--delete") == 1U) {
      if (has_more_args(args, index) != 0) {
        return command_fail(output, output_capacity, output_bytes,
                            "nano: delete takes only a line number");
      }
      if (nano_append_bytes(edited, sizeof(edited), &edited_size, data,
                            line_start) != XAIOS_OK ||
          nano_append_bytes(edited, sizeof(edited), &edited_size,
                            data + line_next, data_size - line_next) !=
              XAIOS_OK) {
        return command_fail(output, output_capacity, output_bytes,
                            "nano: edit exceeds editor capacity");
      }
    } else {
      const char *text = args + skip_ws(args, index);
      uint64_t suffix = string_equal(action, "--insert") == 1U
                            ? line_start
                            : line_next;
      if (text[0] == '\0') {
        return command_fail(output, output_capacity, output_bytes,
                            "nano: missing text");
      }
      if (nano_append_bytes(edited, sizeof(edited), &edited_size, data,
                            line_start) != XAIOS_OK ||
          nano_append_decoded(edited, sizeof(edited), &edited_size, text) !=
              XAIOS_OK ||
          output_append_char(edited, sizeof(edited), &edited_size, '\n') !=
              XAIOS_OK ||
          nano_append_bytes(edited, sizeof(edited), &edited_size, data + suffix,
                            data_size - suffix) != XAIOS_OK) {
        return command_fail(output, output_capacity, output_bytes,
                            "nano: edit exceeds editor capacity");
      }
      (void)line_end;
    }
  } else {
    return command_fail(output, output_capacity, output_bytes,
                        "nano: unsupported option; use nano --help");
  }

  if (mutable_fs_write(resolved, edited, edited_size) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "nano: save failed");
  }
  output_append(output, output_capacity, output_bytes, "nano: saved ");
  output_append(output, output_capacity, output_bytes, resolved);
  output_append(output, output_capacity, output_bytes, " bytes=");
  output_append_u64(output, output_capacity, output_bytes, edited_size);
  output_append(output, output_capacity, output_bytes, "\n");
  return XAIOS_OK;
}

static const char *htop_state_name(xaios_user_process_state_t state) {
  switch (state) {
  case XAIOS_USER_PROCESS_LOADED:
    return "loaded";
  case XAIOS_USER_PROCESS_RUNNABLE:
    return "runnable";
  case XAIOS_USER_PROCESS_RUNNING:
    return "running";
  case XAIOS_USER_PROCESS_WAITING:
    return "waiting";
  case XAIOS_USER_PROCESS_EXITED:
    return "exited";
  case XAIOS_USER_PROCESS_FAILED:
    return "failed";
  default:
    return "unknown";
  }
}

static int htop_state_active(xaios_user_process_state_t state) {
  return state == XAIOS_USER_PROCESS_LOADED ||
         state == XAIOS_USER_PROCESS_RUNNABLE ||
         state == XAIOS_USER_PROCESS_RUNNING ||
         state == XAIOS_USER_PROCESS_WAITING;
}

typedef struct htop_process_row {
  uint32_t pid;
  uint32_t parent_pid;
  uint32_t cpu_id;
  xaios_user_process_state_t state;
  uint64_t cpu_tenths;
  uint64_t memory_tenths;
  uint64_t runtime_ns;
  uint64_t resident_pages;
  uint64_t syscall_count;
  uint32_t tree_depth;
  const char *name;
} htop_process_row_t;

typedef enum htop_sort_key {
  HTOP_SORT_CPU = 0,
  HTOP_SORT_MEMORY,
  HTOP_SORT_TIME,
  HTOP_SORT_PID,
  HTOP_SORT_STATE,
  HTOP_SORT_SYSCALLS,
  HTOP_SORT_COMMAND,
  HTOP_SORT_PARENT
} htop_sort_key_t;

static const char *htop_sort_name(htop_sort_key_t key) {
  switch (key) {
  case HTOP_SORT_MEMORY:
    return "mem";
  case HTOP_SORT_TIME:
    return "time";
  case HTOP_SORT_PID:
    return "pid";
  case HTOP_SORT_STATE:
    return "state";
  case HTOP_SORT_SYSCALLS:
    return "syscalls";
  case HTOP_SORT_COMMAND:
    return "command";
  case HTOP_SORT_PARENT:
    return "parent";
  default:
    return "cpu";
  }
}

static int htop_name_compare(const char *lhs, const char *rhs) {
  uint32_t index = 0U;
  while (lhs[index] != '\0' && rhs[index] != '\0' &&
         lhs[index] == rhs[index]) {
    ++index;
  }
  return (int)(uint8_t)lhs[index] - (int)(uint8_t)rhs[index];
}

static uint64_t htop_ratio_tenths(uint64_t numerator,
                                  uint64_t denominator) {
  if (denominator == 0U || numerator == 0U) {
    return 0U;
  }
  if (numerator > UINT64_MAX / UINT64_C(1000)) {
    numerator /= UINT64_C(1000);
    denominator /= UINT64_C(1000);
    if (denominator == 0U) {
      return UINT64_C(1000);
    }
  }
  return (numerator * UINT64_C(1000)) / denominator;
}

static uint64_t htop_capacity_tenths(uint64_t numerator,
                                     uint64_t denominator) {
  uint64_t tenths = htop_ratio_tenths(numerator, denominator);
  return tenths > UINT64_C(1000) ? UINT64_C(1000) : tenths;
}

static void htop_append_percent(char *output, uint64_t output_capacity,
                                uint64_t *output_bytes, uint64_t tenths) {
  output_append_u64(output, output_capacity, output_bytes, tenths / 10U);
  output_append(output, output_capacity, output_bytes, ".");
  output_append_u64(output, output_capacity, output_bytes, tenths % 10U);
  output_append(output, output_capacity, output_bytes, "%");
}

static void htop_append_repeat(char *output, uint64_t output_capacity,
                               uint64_t *output_bytes, char value,
                               uint32_t count) {
  for (uint32_t i = 0U; i < count; ++i) {
    if (output_append_char(output, output_capacity, output_bytes, value) !=
        XAIOS_OK) {
      return;
    }
  }
}

static void htop_append_u64_width(char *output, uint64_t output_capacity,
                                  uint64_t *output_bytes, uint64_t value,
                                  uint32_t width) {
  uint64_t digits = u64_digits(value);
  if (digits < width) {
    htop_append_repeat(output, output_capacity, output_bytes, ' ',
                       width - (uint32_t)digits);
  }
  output_append_u64(output, output_capacity, output_bytes, value);
}

static void htop_append_percent_width(char *output, uint64_t output_capacity,
                                      uint64_t *output_bytes,
                                      uint64_t tenths) {
  uint64_t whole = tenths / 10U;
  uint64_t digits = u64_digits(whole);
  if (digits < 3U) {
    htop_append_repeat(output, output_capacity, output_bytes, ' ',
                       3U - (uint32_t)digits);
  }
  output_append_u64(output, output_capacity, output_bytes, whole);
  output_append(output, output_capacity, output_bytes, ".");
  output_append_u64(output, output_capacity, output_bytes, tenths % 10U);
  output_append(output, output_capacity, output_bytes, "%");
}

static void htop_append_bounded(char *output, uint64_t output_capacity,
                                uint64_t *output_bytes, const char *text,
                                uint32_t width) {
  uint32_t used = 0U;
  while (text[used] != '\0' && used < width) {
    if (output_append_char(output, output_capacity, output_bytes, text[used]) !=
        XAIOS_OK) {
      return;
    }
    ++used;
  }
}

static void htop_append_ansi_line(char *output, uint64_t output_capacity,
                                  uint64_t *output_bytes, const char *style,
                                  const char *text, uint32_t columns) {
  uint32_t visible = (uint32_t)cstr_len(text);
  if (visible > columns) visible = columns;
  output_append(output, output_capacity, output_bytes, style);
  htop_append_bounded(output, output_capacity, output_bytes, text, columns);
  if (visible < columns) {
    htop_append_repeat(output, output_capacity, output_bytes, ' ',
                       columns - visible);
  }
  output_append(output, output_capacity, output_bytes, "\033[0m\r\n");
}

static const char *htop_meter_color(uint64_t tenths) {
  if (tenths >= 850U) return "\033[31m";
  if (tenths >= 600U) return "\033[33m";
  return "\033[32m";
}

static void htop_append_meter(char *output, uint64_t output_capacity,
                              uint64_t *output_bytes, const char *label,
                              uint32_t label_columns, uint64_t tenths,
                              uint32_t bar_width, uint32_t cell_width) {
  uint32_t label_width = (uint32_t)cstr_len(label);
  uint32_t visible = label_columns + bar_width + 8U;
  uint64_t filled64 = (tenths * bar_width + 999U) / 1000U;
  uint32_t filled = filled64 > bar_width ? bar_width : (uint32_t)filled64;
  output_append(output, output_capacity, output_bytes, "\033[36m");
  if (label_width < label_columns) {
    htop_append_repeat(output, output_capacity, output_bytes, ' ',
                       label_columns - label_width);
  }
  output_append(output, output_capacity, output_bytes, label);
  output_append(output, output_capacity, output_bytes, "\033[32m[");
  output_append(output, output_capacity, output_bytes,
                htop_meter_color(tenths));
  htop_append_repeat(output, output_capacity, output_bytes, '|', filled);
  output_append(output, output_capacity, output_bytes, "\033[90m");
  htop_append_repeat(output, output_capacity, output_bytes, ' ',
                     bar_width - filled);
  output_append(output, output_capacity, output_bytes, "\033[32m");
  htop_append_percent_width(output, output_capacity, output_bytes, tenths);
  output_append(output, output_capacity, output_bytes, "]\033[0m");
  if (visible < cell_width) {
    htop_append_repeat(output, output_capacity, output_bytes, ' ',
                       cell_width - visible);
  }
}

static void htop_append_footer_segment(char *output, uint64_t output_capacity,
                                       uint64_t *output_bytes,
                                       uint32_t *visible, const char *key,
                                       const char *label) {
  output_append(output, output_capacity, output_bytes, "\033[30;46m");
  output_append(output, output_capacity, output_bytes, key);
  output_append(output, output_capacity, output_bytes, "\033[42;30m");
  output_append(output, output_capacity, output_bytes, label);
  output_append_char(output, output_capacity, output_bytes, ' ');
  *visible += (uint32_t)cstr_len(key) + (uint32_t)cstr_len(label) + 1U;
}

static void htop_append_footer(char *output, uint64_t output_capacity,
                               uint64_t *output_bytes, uint32_t columns,
                               int interactive) {
  uint32_t visible = 0U;
  output_append(output, output_capacity, output_bytes, "\033[42;30m");
  if (interactive != 0) {
    htop_append_footer_segment(output, output_capacity, output_bytes, &visible,
                               "F1", "Help");
    htop_append_footer_segment(output, output_capacity, output_bytes, &visible,
                               "F3", "Search");
    htop_append_footer_segment(output, output_capacity, output_bytes, &visible,
                               "F4", "Filter");
    htop_append_footer_segment(output, output_capacity, output_bytes, &visible,
                               "F5", "Tree");
    if (columns >= 80U) {
      htop_append_footer_segment(output, output_capacity, output_bytes,
                                 &visible, "F6", "Sort");
      htop_append_footer_segment(output, output_capacity, output_bytes,
                                 &visible, "I", "Reverse");
      htop_append_footer_segment(output, output_capacity, output_bytes,
                                 &visible, "[/]", "CPUs");
    }
    htop_append_footer_segment(output, output_capacity, output_bytes, &visible,
                               "F10", "Quit");
  } else {
    const char *text = columns < 60U
                           ? " --active --all --sort KEY --plain"
                           : " --active  --all  --sort KEY  --filter TEXT  --cpu-start N  --plain";
    output_append(output, output_capacity, output_bytes, text);
    visible = (uint32_t)cstr_len(text);
  }
  if (visible < columns) {
    htop_append_repeat(output, output_capacity, output_bytes, ' ',
                       columns - visible);
  }
  output_append(output, output_capacity, output_bytes, "\033[0m\r\n");
}

static char htop_state_character(xaios_user_process_state_t state) {
  switch (state) {
  case XAIOS_USER_PROCESS_RUNNING:
    return 'R';
  case XAIOS_USER_PROCESS_RUNNABLE:
    return 'R';
  case XAIOS_USER_PROCESS_WAITING:
    return 'S';
  case XAIOS_USER_PROCESS_EXITED:
    return 'Z';
  case XAIOS_USER_PROCESS_FAILED:
    return 'F';
  case XAIOS_USER_PROCESS_LOADED:
    return 'L';
  default:
    return '?';
  }
}

static void htop_append_runtime(char *output, uint64_t output_capacity,
                                uint64_t *output_bytes, uint64_t runtime_ns) {
  uint64_t seconds = runtime_ns / UINT64_C(1000000000);
  uint64_t hours = seconds / 3600U;
  uint64_t minutes = (seconds / 60U) % 60U;
  seconds %= 60U;
  htop_append_u64_width(output, output_capacity, output_bytes, hours, 2U);
  output_append(output, output_capacity, output_bytes, ":");
  if (minutes < 10U) output_append(output, output_capacity, output_bytes, "0");
  output_append_u64(output, output_capacity, output_bytes, minutes);
  output_append(output, output_capacity, output_bytes, ":");
  if (seconds < 10U) output_append(output, output_capacity, output_bytes, "0");
  output_append_u64(output, output_capacity, output_bytes, seconds);
}

static uint32_t htop_append_uptime(char *output, uint64_t output_capacity,
                                   uint64_t *output_bytes, uint64_t now_ns) {
  uint64_t seconds = now_ns / UINT64_C(1000000000);
  uint64_t days = seconds / 86400U;
  uint64_t hours = (seconds / 3600U) % 24U;
  uint64_t minutes = (seconds / 60U) % 60U;
  seconds %= 60U;
  output_append_u64(output, output_capacity, output_bytes, days);
  output_append(output, output_capacity, output_bytes, " days, ");
  if (hours < 10U) output_append(output, output_capacity, output_bytes, "0");
  output_append_u64(output, output_capacity, output_bytes, hours);
  output_append(output, output_capacity, output_bytes, ":");
  if (minutes < 10U) output_append(output, output_capacity, output_bytes, "0");
  output_append_u64(output, output_capacity, output_bytes, minutes);
  output_append(output, output_capacity, output_bytes, ":");
  if (seconds < 10U) output_append(output, output_capacity, output_bytes, "0");
  output_append_u64(output, output_capacity, output_bytes, seconds);
  return (uint32_t)u64_digits(days) + 15U;
}

static void htop_append_hundredths(char *output, uint64_t output_capacity,
                                   uint64_t *output_bytes, uint32_t value) {
  output_append_u64(output, output_capacity, output_bytes, value / 100U);
  output_append(output, output_capacity, output_bytes, ".");
  if (value % 100U < 10U) {
    output_append(output, output_capacity, output_bytes, "0");
  }
  output_append_u64(output, output_capacity, output_bytes, value % 100U);
}

static uint32_t htop_cpu_max_columns(uint32_t terminal_columns,
                                     uint32_t label_columns) {
  if (label_columns < 5U) label_columns = 5U;
  uint32_t cells = terminal_columns / (label_columns + 9U);
  if (cells >= 16U) return 16U;
  if (cells >= 8U) return 8U;
  if (cells >= 4U) return 4U;
  if (cells >= 2U) return 2U;
  return 1U;
}

static uint32_t htop_cpu_grid_columns(uint32_t cpu_count,
                                      uint32_t terminal_columns,
                                      uint32_t label_columns) {
  uint32_t requested = 1U;
  if (cpu_count > 64U) requested = 16U;
  else if (cpu_count > 32U) requested = 8U;
  else if (cpu_count > 16U) requested = 4U;
  else if (cpu_count > 8U) requested = 2U;
  uint32_t maximum = htop_cpu_max_columns(terminal_columns, label_columns);
  return requested < maximum ? requested : maximum;
}

static uint32_t htop_cpu_grid_rows(uint32_t cpu_count,
                                   uint32_t grid_columns) {
  if (cpu_count == 0U) return 0U;
  return (cpu_count + grid_columns - 1U) / grid_columns;
}

static uint32_t htop_cpu_page_capacity(uint32_t terminal_columns,
                                       uint32_t terminal_rows,
                                       uint32_t label_columns) {
  uint32_t rows = terminal_rows > 10U ? terminal_rows - 10U : 1U;
  if (rows > 8U) rows = 8U;
  uint32_t columns = htop_cpu_max_columns(terminal_columns, label_columns);
  return rows > UINT32_MAX / columns ? UINT32_MAX : rows * columns;
}

static void htop_append_info_cell(
    char *output, uint64_t output_capacity, uint64_t *output_bytes,
    uint32_t row, uint32_t width, uint32_t active_tasks,
    uint32_t failed_tasks, uint32_t cpu_total,
    const uint32_t load_average[3], uint64_t now_ns) {
  uint32_t visible = 0U;
  if (row == 0U) {
    output_append(output, output_capacity, output_bytes,
                  "\033[36mTasks: \033[32m");
    output_append_u64(output, output_capacity, output_bytes, active_tasks);
    visible = 7U + (uint32_t)u64_digits(active_tasks);
    if (width >= 40U) {
      output_append(output, output_capacity, output_bytes,
                    "\033[36m active, \033[31m");
      output_append_u64(output, output_capacity, output_bytes, failed_tasks);
      output_append(output, output_capacity, output_bytes,
                    "\033[36m failed; CPUs: \033[32m");
      output_append_u64(output, output_capacity, output_bytes, cpu_total);
      visible += 24U + (uint32_t)u64_digits(failed_tasks) +
                 (uint32_t)u64_digits(cpu_total);
    } else {
      output_append(output, output_capacity, output_bytes,
                    "\033[36m  Fail: \033[31m");
      output_append_u64(output, output_capacity, output_bytes, failed_tasks);
      visible += 8U + (uint32_t)u64_digits(failed_tasks);
    }
  } else if (row == 1U) {
    const char *caption = width >= 32U ? "Load average: " : "Load: ";
    output_append(output, output_capacity, output_bytes, "\033[36m");
    output_append(output, output_capacity, output_bytes, caption);
    output_append(output, output_capacity, output_bytes, "\033[32m");
    visible = (uint32_t)cstr_len(caption);
    uint32_t values = width >= 24U ? 3U : 2U;
    for (uint32_t i = 0U; i < values; ++i) {
      if (i != 0U) {
        output_append(output, output_capacity, output_bytes, " ");
        ++visible;
      }
      htop_append_hundredths(output, output_capacity, output_bytes,
                             load_average[i]);
      visible += (uint32_t)u64_digits(load_average[i] / 100U) + 3U;
    }
  } else {
    uint64_t seconds = now_ns / UINT64_C(1000000000);
    if (width >= 24U) {
      output_append(output, output_capacity, output_bytes,
                    "\033[36mUptime: \033[32m");
      visible = 8U + htop_append_uptime(output, output_capacity, output_bytes,
                                        now_ns);
    } else {
      uint64_t days = seconds / 86400U;
      uint64_t hours = (seconds / 3600U) % 24U;
      uint64_t minutes = (seconds / 60U) % 60U;
      seconds %= 60U;
      output_append(output, output_capacity, output_bytes,
                    "\033[36mUptime: \033[32m");
      output_append_u64(output, output_capacity, output_bytes, days);
      output_append(output, output_capacity, output_bytes, "d ");
      if (hours < 10U) output_append(output, output_capacity, output_bytes, "0");
      output_append_u64(output, output_capacity, output_bytes, hours);
      output_append(output, output_capacity, output_bytes, ":");
      if (minutes < 10U) output_append(output, output_capacity, output_bytes, "0");
      output_append_u64(output, output_capacity, output_bytes, minutes);
      output_append(output, output_capacity, output_bytes, ":");
      if (seconds < 10U) output_append(output, output_capacity, output_bytes, "0");
      output_append_u64(output, output_capacity, output_bytes, seconds);
      visible = 18U + (uint32_t)u64_digits(days);
    }
  }
  output_append(output, output_capacity, output_bytes, "\033[0m");
  if (visible < width) {
    htop_append_repeat(output, output_capacity, output_bytes, ' ',
                       width - visible);
  }
}

static void htop_append_system_meter_cell(
    char *output, uint64_t output_capacity, uint64_t *output_bytes,
    const char *label, uint32_t label_columns, uint64_t tenths,
    uint32_t cell_width, uint64_t used_mebibytes,
    uint64_t managed_mebibytes) {
  uint32_t value_width = string_equal(label, "Mem") == 1
                             ? (uint32_t)u64_digits(used_mebibytes) +
                                   (uint32_t)u64_digits(managed_mebibytes) + 3U
                             : 5U;
  uint32_t suffix_width = value_width > 5U ? value_width + 1U : 6U;
  if (suffix_width < 14U) suffix_width = 14U;
  uint32_t minimum_meter_columns = label_columns + 9U;
  if (cell_width <= minimum_meter_columns ||
      suffix_width > cell_width - minimum_meter_columns) {
    suffix_width = 0U;
  }
  uint32_t meter_columns = cell_width - suffix_width;
  uint32_t meter_overhead = label_columns + 8U;
  uint32_t bar_width = meter_columns > meter_overhead
                           ? meter_columns - meter_overhead
                           : 1U;
  htop_append_meter(output, output_capacity, output_bytes, label,
                    label_columns, tenths, bar_width, meter_columns);
  if (suffix_width == 0U) return;
  output_append(output, output_capacity, output_bytes,
                string_equal(label, "Mem") == 1 ? "\033[33m" : "\033[36m");
  htop_append_repeat(output, output_capacity, output_bytes, ' ',
                     suffix_width - value_width);
  if (string_equal(label, "Mem") == 1) {
    output_append_u64(output, output_capacity, output_bytes, used_mebibytes);
    output_append(output, output_capacity, output_bytes, "M/");
    output_append_u64(output, output_capacity, output_bytes,
                      managed_mebibytes);
    output_append(output, output_capacity, output_bytes, "M");
  } else {
    output_append(output, output_capacity, output_bytes, "0K/0K");
  }
  output_append(output, output_capacity, output_bytes, "\033[0m");
}

static const char *htop_cpu_role_name(uint32_t cpu_id) {
  const xaios_cpu_state_t *state = smp_cpu_state(cpu_id);
  if (state == 0 || state->online == 0U) {
    return "offline";
  }
  switch (state->role) {
  case XAIOS_CPU_ROLE_HOUSEKEEPING:
    return "housekeeping";
  case XAIOS_CPU_ROLE_SCHEDULING:
    return "scheduling";
  case XAIOS_CPU_ROLE_AI_HOT:
    return "ai-hot";
  default:
    return "offline";
  }
}

static int htop_row_precedes(const htop_process_row_t *lhs,
                             const htop_process_row_t *rhs,
                             htop_sort_key_t key, int reverse) {
  int precedes = 0;
  int differs = 1;
  switch (key) {
  case HTOP_SORT_MEMORY:
    precedes = lhs->resident_pages > rhs->resident_pages;
    differs = lhs->resident_pages != rhs->resident_pages;
    break;
  case HTOP_SORT_TIME:
    precedes = lhs->runtime_ns > rhs->runtime_ns;
    differs = lhs->runtime_ns != rhs->runtime_ns;
    break;
  case HTOP_SORT_PID:
    precedes = lhs->pid < rhs->pid;
    differs = lhs->pid != rhs->pid;
    break;
  case HTOP_SORT_STATE:
    precedes = lhs->state < rhs->state;
    differs = lhs->state != rhs->state;
    break;
  case HTOP_SORT_SYSCALLS:
    precedes = lhs->syscall_count > rhs->syscall_count;
    differs = lhs->syscall_count != rhs->syscall_count;
    break;
  case HTOP_SORT_COMMAND: {
    int comparison = htop_name_compare(lhs->name, rhs->name);
    precedes = comparison < 0;
    differs = comparison != 0;
    break;
  }
  case HTOP_SORT_PARENT:
    if (lhs->parent_pid != rhs->parent_pid) {
      precedes = lhs->parent_pid < rhs->parent_pid;
    } else {
      precedes = lhs->pid < rhs->pid;
    }
    differs = lhs->parent_pid != rhs->parent_pid || lhs->pid != rhs->pid;
    break;
  default:
    precedes = lhs->cpu_tenths > rhs->cpu_tenths;
    differs = lhs->cpu_tenths != rhs->cpu_tenths;
    break;
  }
  if (differs == 0) return lhs->pid < rhs->pid;
  return reverse != 0 ? !precedes : precedes;
}

static void htop_sort_rows(htop_process_row_t *rows, uint32_t count,
                           htop_sort_key_t key, int reverse) {
  for (uint32_t i = 1U; i < count; ++i) {
    htop_process_row_t value = rows[i];
    uint32_t position = i;
    while (position > 0U &&
           htop_row_precedes(&value, &rows[position - 1U], key, reverse)) {
      rows[position] = rows[position - 1U];
      --position;
    }
    rows[position] = value;
  }
}

static int htop_tree_parent_present(const htop_process_row_t *rows,
                                    uint32_t count, uint32_t parent_pid) {
  if (parent_pid == 0U) return 0;
  for (uint32_t i = 0U; i < count; ++i) {
    if (rows[i].pid == parent_pid) return 1;
  }
  return 0;
}

static int htop_arrange_tree(htop_process_row_t *rows, uint32_t count) {
  htop_process_row_t *ordered;
  uint32_t *stack_index;
  uint32_t *stack_depth;
  uint8_t *emitted;
  uint32_t output_count = 0U;
  if (count == 0U) return 0;
  ordered = (htop_process_row_t *)kheap_calloc(
      (uint64_t)count * sizeof(*ordered), 16U);
  stack_index = (uint32_t *)kheap_calloc(
      (uint64_t)count * sizeof(*stack_index), 16U);
  stack_depth = (uint32_t *)kheap_calloc(
      (uint64_t)count * sizeof(*stack_depth), 16U);
  emitted = (uint8_t *)kheap_calloc(count, 16U);
  if (ordered == 0 || stack_index == 0 || stack_depth == 0 || emitted == 0) {
    kheap_free(ordered);
    kheap_free(stack_index);
    kheap_free(stack_depth);
    kheap_free(emitted);
    return -1;
  }

  for (uint32_t root_pass = 0U; root_pass < 2U; ++root_pass) {
    for (uint32_t root = 0U; root < count; ++root) {
      int natural_root = rows[root].parent_pid == 0U ||
                         htop_tree_parent_present(rows, count,
                                                  rows[root].parent_pid) == 0;
      if (emitted[root] != 0U ||
          (root_pass == 0U && natural_root == 0) ||
          (root_pass != 0U && natural_root != 0)) {
        continue;
      }
      uint32_t stack_count = 0U;
      stack_index[stack_count] = root;
      stack_depth[stack_count++] = 0U;
      while (stack_count != 0U) {
        --stack_count;
        uint32_t index = stack_index[stack_count];
        uint32_t depth = stack_depth[stack_count];
        if (emitted[index] != 0U) continue;
        emitted[index] = 1U;
        ordered[output_count] = rows[index];
        ordered[output_count++].tree_depth = depth;
        for (uint32_t child = count; child != 0U; --child) {
          uint32_t child_index = child - 1U;
          if (emitted[child_index] == 0U &&
              rows[child_index].parent_pid == rows[index].pid &&
              stack_count < count) {
            stack_index[stack_count] = child_index;
            stack_depth[stack_count++] =
                depth == UINT32_MAX ? UINT32_MAX : depth + 1U;
          }
        }
      }
    }
  }
  for (uint32_t i = 0U; i < output_count; ++i) rows[i] = ordered[i];
  kheap_free(ordered);
  kheap_free(stack_index);
  kheap_free(stack_depth);
  kheap_free(emitted);
  return output_count == count ? 0 : -1;
}

static uint32_t htop_render_color(
    char *output, uint64_t output_capacity, uint64_t *output_bytes,
    uint32_t columns, uint32_t terminal_rows, uint32_t cpu_start,
    uint32_t cpu_shown, uint32_t cpu_total, const uint64_t *before_cpu,
    uint64_t after_ns, uint64_t elapsed_ns, uint64_t managed_pages,
    uint64_t free_pages, uint32_t active_tasks, uint32_t failed_tasks,
    const htop_process_row_t *process_rows, uint32_t process_count,
    uint32_t process_start, uint32_t selected, htop_sort_key_t sort_key,
    int reverse, int interactive, const char *filter) {
  uint32_t process_shown = 0U;
  uint32_t label_columns = 3U;
  if (cpu_total != 0U && u64_digits((uint64_t)cpu_total - 1U) > label_columns) {
    label_columns = (uint32_t)u64_digits((uint64_t)cpu_total - 1U);
  }
  uint32_t grid_columns =
      htop_cpu_grid_columns(cpu_shown, columns, label_columns);
  uint32_t cpu_line_count = htop_cpu_grid_rows(cpu_shown, grid_columns);
  uint32_t header_lines = grid_columns == 1U
                              ? cpu_line_count + 2U
                              : cpu_line_count + 3U;
  if (header_lines < 3U) header_lines = 3U;
  uint32_t fixed_lines = 6U;
  uint32_t process_budget = terminal_rows > header_lines + fixed_lines
                                ? terminal_rows - header_lines - fixed_lines
                                : 1U;
  uint32_t left_width = columns / 2U;
  uint32_t right_width = columns - left_width;
  uint64_t used_pages = managed_pages >= free_pages
                            ? managed_pages - free_pages
                            : 0U;
  uint64_t memory_tenths = htop_capacity_tenths(used_pages, managed_pages);
  uint64_t used_mebibytes = used_pages / 256U;
  uint64_t managed_mebibytes = managed_pages / 256U;
  uint32_t load_average[3];
  scheduler_load_average_hundredths(load_average);

  output_append(output, output_capacity, output_bytes,
                interactive != 0 ? "\033[2J\033[H\033[?25l"
                                 : "\033[2J\033[H\033[?25h");
  htop_append_ansi_line(output, output_capacity, output_bytes,
                        "\033[44;97m",
                        " XAIOS htop | sampled kernel process monitor",
                        columns);

  for (uint32_t line = 0U; line < header_lines; ++line) {
    if (grid_columns > 1U && line < cpu_line_count) {
      uint32_t base_width = columns / grid_columns;
      for (uint32_t column = 0U; column < grid_columns; ++column) {
        uint32_t cell_width = column + 1U == grid_columns
                                  ? columns - base_width * column
                                  : base_width;
        uint32_t offset = column * cpu_line_count + line;
        if (offset >= cpu_shown) {
          htop_append_repeat(output, output_capacity, output_bytes, ' ',
                             cell_width);
          continue;
        }
        xaios_cpu_usage_snapshot_t usage;
        uint64_t tenths = 0U;
        if (user_cpu_usage_snapshot(cpu_start + offset, after_ns, &usage) ==
            XAIOS_OK) {
          uint64_t delta = usage.busy_ns >= before_cpu[offset]
                               ? usage.busy_ns - before_cpu[offset]
                               : 0U;
          tenths = htop_capacity_tenths(delta, elapsed_ns);
        }
        char label[12];
        uint64_t label_bytes = 0U;
        label[0] = '\0';
        htop_append_u64_width(label, sizeof(label), &label_bytes,
                              cpu_start + offset, label_columns);
        uint32_t bar_width = cell_width > label_columns + 8U
                                 ? cell_width - label_columns - 8U
                                 : 1U;
        htop_append_meter(output, output_capacity, output_bytes, label,
                          label_columns, tenths, bar_width, cell_width);
      }
      output_append(output, output_capacity, output_bytes, "\r\n");
      continue;
    }

    uint32_t system_row = line >= cpu_line_count
                              ? line - cpu_line_count
                              : UINT32_MAX;
    if (grid_columns == 1U && line < cpu_line_count) {
      uint32_t offset = line;
      xaios_cpu_usage_snapshot_t usage;
      uint64_t tenths = 0U;
      if (user_cpu_usage_snapshot(cpu_start + offset, after_ns, &usage) ==
          XAIOS_OK) {
        uint64_t delta = usage.busy_ns >= before_cpu[offset]
                             ? usage.busy_ns - before_cpu[offset]
                             : 0U;
        tenths = htop_capacity_tenths(delta, elapsed_ns);
      }
      char label[12];
      uint64_t label_bytes = 0U;
      label[0] = '\0';
      htop_append_u64_width(label, sizeof(label), &label_bytes,
                            cpu_start + offset, label_columns);
      uint32_t bar_width = left_width > label_columns + 8U
                               ? left_width - label_columns - 8U
                               : 1U;
      htop_append_meter(output, output_capacity, output_bytes, label,
                        label_columns, tenths, bar_width, left_width);
    } else if (system_row == 0U) {
      htop_append_system_meter_cell(
          output, output_capacity, output_bytes, "Mem", label_columns,
          memory_tenths, left_width, used_mebibytes, managed_mebibytes);
    } else if (system_row == 1U) {
      htop_append_system_meter_cell(
          output, output_capacity, output_bytes, "Swp", label_columns, 0U,
          left_width, used_mebibytes, managed_mebibytes);
    } else {
      htop_append_repeat(output, output_capacity, output_bytes, ' ', left_width);
    }

    uint32_t info_row = grid_columns == 1U ? line : system_row;
    if (info_row < 3U) {
      htop_append_info_cell(output, output_capacity, output_bytes, info_row,
                            right_width, active_tasks, failed_tasks, cpu_total,
                            load_average, after_ns);
    } else {
      htop_append_repeat(output, output_capacity, output_bytes, ' ', right_width);
    }
    output_append(output, output_capacity, output_bytes, "\r\n");
  }

  output_append(output, output_capacity, output_bytes,
                "\033[36mView: \033[32m");
  output_append(output, output_capacity, output_bytes,
                interactive != 0 ? "live" : "snapshot");
  output_append(output, output_capacity, output_bytes,
                "\033[36m  Sort: \033[32m");
  output_append(output, output_capacity, output_bytes, htop_sort_name(sort_key));
  if (reverse != 0) {
    output_append(output, output_capacity, output_bytes, " ascending");
  }
  if (filter[0] != '\0') {
    output_append(output, output_capacity, output_bytes,
                  "\033[36m  Filter: \033[33m");
    htop_append_bounded(output, output_capacity, output_bytes, filter,
                        columns > 40U ? columns - 40U : 1U);
  }
  if (cpu_start != 0U || cpu_start + cpu_shown < cpu_total) {
    output_append(output, output_capacity, output_bytes,
                  "\033[36m  CPU page: \033[32m");
    output_append_u64(output, output_capacity, output_bytes, cpu_start);
    output_append(output, output_capacity, output_bytes, "-");
    output_append_u64(output, output_capacity, output_bytes,
                      cpu_shown == 0U ? cpu_start
                                      : cpu_start + cpu_shown - 1U);
    output_append(output, output_capacity, output_bytes, "/");
    output_append_u64(output, output_capacity, output_bytes, cpu_total);
  }
  output_append(output, output_capacity, output_bytes, "\033[0m\r\n\r\n");

  htop_append_ansi_line(output, output_capacity, output_bytes,
                        "\033[44;97m", "[Main]", columns);
  htop_append_ansi_line(output, output_capacity, output_bytes,
                        "\033[42;30m",
                        columns < 60U
                            ? " PID S   CPU%   MEM% COMMAND"
                            : (columns < 100U
                                   ? "  PID  PPID S   CPU%   MEM%    TIME+ RES_KIB CPU COMMAND"
                                   : "  PID  PPID S   CPU%   MEM%    TIME+ RES_KIB CPU  SYSCALLS COMMAND"),
                        columns);

  for (uint32_t i = process_start;
       i < process_count && process_shown < process_budget;
       ++i) {
    uint64_t row_and_footer = ((uint64_t)columns + 64U) * 2U;
    if (*output_bytes >= output_capacity ||
        row_and_footer >= output_capacity - *output_bytes) {
      break;
    }
    const htop_process_row_t *row = &process_rows[i];
    if (i == selected) output_append(output, output_capacity, output_bytes,
                                    "\033[46;30m");
    else output_append(output, output_capacity, output_bytes, "\033[36m");
    uint32_t fixed_visible;
    if (columns < 60U) {
      htop_append_u64_width(output, output_capacity, output_bytes, row->pid,
                            4U);
      output_append(output, output_capacity, output_bytes, " ");
      output_append_char(output, output_capacity, output_bytes,
                         htop_state_character(row->state));
      output_append(output, output_capacity, output_bytes, " ");
      htop_append_percent_width(output, output_capacity, output_bytes,
                                row->cpu_tenths);
      output_append(output, output_capacity, output_bytes, " ");
      htop_append_percent_width(output, output_capacity, output_bytes,
                                row->memory_tenths);
      output_append(output, output_capacity, output_bytes, " ");
      fixed_visible = 21U;
    } else {
      htop_append_u64_width(output, output_capacity, output_bytes, row->pid,
                            5U);
      output_append(output, output_capacity, output_bytes, " ");
      htop_append_u64_width(output, output_capacity, output_bytes,
                            row->parent_pid, 5U);
      output_append(output, output_capacity, output_bytes, " ");
      output_append_char(output, output_capacity, output_bytes,
                         htop_state_character(row->state));
      output_append(output, output_capacity, output_bytes, " ");
      htop_append_percent_width(output, output_capacity, output_bytes,
                                row->cpu_tenths);
      output_append(output, output_capacity, output_bytes, " ");
      htop_append_percent_width(output, output_capacity, output_bytes,
                                row->memory_tenths);
      output_append(output, output_capacity, output_bytes, " ");
      htop_append_runtime(output, output_capacity, output_bytes,
                          row->runtime_ns);
      output_append(output, output_capacity, output_bytes, " ");
      htop_append_u64_width(output, output_capacity, output_bytes,
                            row->resident_pages * 4U, 7U);
      output_append(output, output_capacity, output_bytes, " ");
      if (row->cpu_id == UINT32_MAX) {
        output_append(output, output_capacity, output_bytes, "  -");
      } else {
        htop_append_u64_width(output, output_capacity, output_bytes,
                              row->cpu_id, 3U);
      }
      output_append(output, output_capacity, output_bytes, " ");
      fixed_visible = 49U;
      if (columns >= 100U) {
        htop_append_u64_width(output, output_capacity, output_bytes,
                              row->syscall_count, 9U);
        output_append(output, output_capacity, output_bytes, " ");
        fixed_visible += 10U;
      }
    }
    uint32_t command_width = columns > fixed_visible
                                 ? columns - fixed_visible
                                 : 0U;
    uint32_t prefix_length = 0U;
    if (sort_key == HTOP_SORT_PARENT && row->tree_depth != 0U) {
      uint32_t indent = row->tree_depth > 8U ? 14U
                                             : (row->tree_depth - 1U) * 2U;
      prefix_length = indent + 3U;
      if (prefix_length <= command_width) {
        htop_append_repeat(output, output_capacity, output_bytes, ' ', indent);
      } else {
        prefix_length = 0U;
      }
    }
    if (prefix_length != 0U && command_width >= prefix_length) {
      output_append(output, output_capacity, output_bytes, "|- ");
    }
    uint32_t name_width = command_width > prefix_length
                              ? command_width - prefix_length : 0U;
    htop_append_bounded(output, output_capacity, output_bytes, row->name,
                        name_width);
    uint32_t command_length = (uint32_t)cstr_len(row->name);
    if (command_length < name_width) {
      htop_append_repeat(output, output_capacity, output_bytes, ' ',
                         name_width - command_length);
    }
    output_append(output, output_capacity, output_bytes, "\033[0m\r\n");
    ++process_shown;
  }

  if (interactive != 0) {
    htop_append_footer(output, output_capacity, output_bytes, columns, 1);
    output_append(output, output_capacity, output_bytes, "\033[0m\033[?25l");
  } else {
    htop_append_footer(output, output_capacity, output_bytes, columns, 0);
    output_append(output, output_capacity, output_bytes, "\033[0m\033[?25h");
  }
  return process_shown;
}

static xaios_status_t htop_parse_u32_option(const char *args, uint64_t *index,
                                            uint32_t *value) {
  char token[24];
  uint64_t parsed = 0U;
  uint64_t consumed = 0U;
  if (token_next(args, index, token, sizeof(token)) != XAIOS_OK ||
      parse_u64_token(token, &parsed, &consumed) != XAIOS_OK ||
      consumed != cstr_len(token) || parsed > UINT32_MAX) {
    return XAIOS_ERR_INVALID;
  }
  *value = (uint32_t)parsed;
  return XAIOS_OK;
}

static xaios_status_t htop_parse_sort_option(const char *args, uint64_t *index,
                                             htop_sort_key_t *key) {
  char value[24];
  if (token_next(args, index, value, sizeof(value)) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  if (string_equal(value, "cpu") == 1U) *key = HTOP_SORT_CPU;
  else if (string_equal(value, "mem") == 1U) *key = HTOP_SORT_MEMORY;
  else if (string_equal(value, "time") == 1U) *key = HTOP_SORT_TIME;
  else if (string_equal(value, "pid") == 1U) *key = HTOP_SORT_PID;
  else if (string_equal(value, "state") == 1U) *key = HTOP_SORT_STATE;
  else if (string_equal(value, "syscalls") == 1U) *key = HTOP_SORT_SYSCALLS;
  else if (string_equal(value, "command") == 1U) *key = HTOP_SORT_COMMAND;
  else if (string_equal(value, "parent") == 1U) *key = HTOP_SORT_PARENT;
  else return XAIOS_ERR_INVALID;
  return XAIOS_OK;
}

static void htop_sample_wait(uint64_t deadline_ns) {
  user_process_idle_until(deadline_ns);
}

static xaios_status_t handle_htop(const char *args, char *output,
                                 uint64_t output_capacity,
                                 uint64_t *output_bytes) {
  char option[24];
  uint64_t index = 0U;
  int show_all = 1;
  int show_cpus = 1;
  int color_output = 0;
  int reverse = 0;
  int interactive = 0;
  char filter[32];
  htop_sort_key_t sort_key = HTOP_SORT_CPU;
  uint32_t cpu_start = 0U;
  uint32_t cpu_requested = UINT32_MAX;
  uint32_t process_start = 0U;
  uint32_t selected = 0U;
  uint32_t sample_ms = 250U;
  uint32_t terminal_columns = 120U;
  uint32_t terminal_rows = 40U;
  uint32_t cpu_total;
  uint32_t cpu_shown = 0U;
  uint32_t process_count = 0U;
  uint32_t process_shown = 0U;
  uint32_t process_total = 0U;
  uint64_t before_ns;
  uint64_t after_ns;
  uint64_t elapsed_ns;
  uint64_t before_busy_total;
  uint64_t after_busy_total;
  uint64_t total_pages;
  uint64_t managed_pages;
  uint64_t free_pages;
  uint64_t *before_runtime = 0;
  uint64_t *before_cpu = 0;
  htop_process_row_t *rows = 0;
  xaios_user_process_t process;
  filter[0] = '\0';
  while (token_next(args, &index, option, sizeof(option)) == XAIOS_OK) {
    if (string_equal(option, "--all") == 1U) {
      show_all = 1;
    } else if (string_equal(option, "--active") == 1U) {
      show_all = 0;
    } else if (string_equal(option, "--no-cpus") == 1U) {
      show_cpus = 0;
    } else if (string_equal(option, "--color") == 1U) {
      color_output = 1;
    } else if (string_equal(option, "--plain") == 1U) {
      color_output = 0;
    } else if (string_equal(option, "--interactive") == 1U) {
      interactive = 1;
      color_output = 1;
    } else if (string_equal(option, "--reverse") == 1U) {
      reverse = 1;
    } else if (string_equal(option, "--tree") == 1U) {
      sort_key = HTOP_SORT_PARENT;
    } else if (string_equal(option, "--sort") == 1U) {
      if (htop_parse_sort_option(args, &index, &sort_key) != XAIOS_OK) {
        return command_fail(output, output_capacity, output_bytes,
                            "htop: invalid --sort key");
      }
    } else if (string_equal(option, "--filter") == 1U) {
      if (token_next(args, &index, filter, sizeof(filter)) != XAIOS_OK) {
        return command_fail(output, output_capacity, output_bytes,
                            "htop: invalid --filter");
      }
    } else if (string_equal(option, "--process-start") == 1U) {
      if (htop_parse_u32_option(args, &index, &process_start) != XAIOS_OK) {
        return command_fail(output, output_capacity, output_bytes,
                            "htop: invalid --process-start");
      }
    } else if (string_equal(option, "--selected") == 1U) {
      if (htop_parse_u32_option(args, &index, &selected) != XAIOS_OK) {
        return command_fail(output, output_capacity, output_bytes,
                            "htop: invalid --selected");
      }
    } else if (string_equal(option, "--columns") == 1U) {
      if (htop_parse_u32_option(args, &index, &terminal_columns) != XAIOS_OK ||
          terminal_columns < 40U || terminal_columns > 240U) {
        return command_fail(output, output_capacity, output_bytes,
                            "htop: --columns must be 40..240");
      }
    } else if (string_equal(option, "--rows") == 1U) {
      if (htop_parse_u32_option(args, &index, &terminal_rows) != XAIOS_OK ||
          terminal_rows < 12U || terminal_rows > 100U) {
        return command_fail(output, output_capacity, output_bytes,
                            "htop: --rows must be 12..100");
      }
    } else if (string_equal(option, "--cpu-start") == 1U) {
      if (htop_parse_u32_option(args, &index, &cpu_start) != XAIOS_OK) {
        return command_fail(output, output_capacity, output_bytes,
                            "htop: invalid --cpu-start");
      }
    } else if (string_equal(option, "--cpu-count") == 1U) {
      if (htop_parse_u32_option(args, &index, &cpu_requested) != XAIOS_OK ||
          cpu_requested == 0U) {
        return command_fail(output, output_capacity, output_bytes,
                            "htop: invalid --cpu-count");
      }
    } else if (string_equal(option, "--sample-ms") == 1U) {
      if (htop_parse_u32_option(args, &index, &sample_ms) != XAIOS_OK ||
          sample_ms == 0U || sample_ms > 1000U) {
        return command_fail(output, output_capacity, output_bytes,
                            "htop: --sample-ms must be 1..1000");
      }
    } else if (string_equal(option, "--help") == 1U) {
      output_append(
          output, output_capacity, output_bytes,
          "htop [--active|--all] [--sample-ms 1..1000] [--cpu-start N] "
          "[--cpu-count N] [--no-cpus] [--color|--plain] "
          "[--columns 40..240] [--rows 12..100] "
          "[--sort cpu|mem|time|pid|state|syscalls|command|parent] "
          "[--reverse] [--tree] [--filter TEXT] [--process-start N] "
          "[--selected N]\n");
      return XAIOS_OK;
    } else {
      return command_fail(output, output_capacity, output_bytes,
                          "htop: unsupported option; use htop --help");
    }
  }

  cpu_total = user_cpu_usage_count();
  if (cpu_start > cpu_total) {
    cpu_start = cpu_total;
  }
  uint32_t cpu_available = cpu_total - cpu_start;
  uint32_t cpu_page_budget = output_capacity > 1024U
                                 ? (uint32_t)((output_capacity - 1024U) / 72U)
                                 : 0U;
  if (cpu_page_budget == 0U && show_cpus != 0 && cpu_available != 0U) {
    cpu_page_budget = 1U;
  }
  cpu_shown = cpu_available;
  if (cpu_shown > cpu_requested) {
    cpu_shown = cpu_requested;
  }
  if (cpu_shown > cpu_page_budget) {
    cpu_shown = cpu_page_budget;
  }
  if (color_output != 0) {
    uint32_t label_columns = 3U;
    if (cpu_total != 0U &&
        u64_digits((uint64_t)cpu_total - 1U) > label_columns) {
      label_columns = (uint32_t)u64_digits((uint64_t)cpu_total - 1U);
    }
    uint32_t visual_budget = htop_cpu_page_capacity(
        terminal_columns, terminal_rows, label_columns);
    if (cpu_shown > visual_budget) cpu_shown = visual_budget;
  }
  if (show_cpus == 0) {
    cpu_shown = 0U;
  }

  before_runtime = (uint64_t *)kheap_calloc(
      (uint64_t)XAIOS_MAX_USER_PROCESSES * sizeof(uint64_t), 16U);
  rows = (htop_process_row_t *)kheap_calloc(
      (uint64_t)XAIOS_MAX_USER_PROCESSES * sizeof(htop_process_row_t), 16U);
  if (cpu_shown != 0U) {
    before_cpu = (uint64_t *)kheap_calloc(
        (uint64_t)cpu_shown * sizeof(uint64_t), 16U);
  }
  if (before_runtime == 0 || rows == 0 ||
      (cpu_shown != 0U && before_cpu == 0)) {
    kheap_free(before_runtime);
    kheap_free(before_cpu);
    kheap_free(rows);
    return command_fail(output, output_capacity, output_bytes,
                        "htop: accounting allocation failed");
  }

  before_ns = timer_now_ns();
  before_busy_total = user_cpu_busy_total(before_ns);
  for (uint32_t pid = 1U; pid <= XAIOS_MAX_USER_PROCESSES; ++pid) {
    if (user_process_snapshot_at(pid, before_ns, &process) == XAIOS_OK) {
      before_runtime[pid - 1U] = process.runtime_ns;
    }
  }
  for (uint32_t offset = 0U; offset < cpu_shown; ++offset) {
    xaios_cpu_usage_snapshot_t usage;
    if (user_cpu_usage_snapshot(cpu_start + offset, before_ns, &usage) ==
        XAIOS_OK) {
      before_cpu[offset] = usage.busy_ns;
    }
  }

  uint64_t sample_ns = (uint64_t)sample_ms * UINT64_C(1000000);
  uint64_t deadline_ns = before_ns + sample_ns;
  if (deadline_ns < before_ns) {
    deadline_ns = UINT64_MAX;
  }
  htop_sample_wait(deadline_ns);
  after_ns = timer_now_ns();
  elapsed_ns = after_ns > before_ns ? after_ns - before_ns : 1U;
  after_busy_total = user_cpu_busy_total(after_ns);
  total_pages = pmm_total_pages();
  managed_pages = pmm_managed_pages();
  free_pages = pmm_free_pages();

  for (uint32_t pid = 1U; pid <= XAIOS_MAX_USER_PROCESSES; ++pid) {
    if (user_process_snapshot_at(pid, after_ns, &process) != XAIOS_OK ||
        (show_all == 0 && htop_state_active(process.state) == 0) ||
        (filter[0] != '\0' &&
         contains_substring(process.name == 0 ? "(unknown)" : process.name,
                            filter) == 0)) {
      continue;
    }
    htop_process_row_t *row = &rows[process_count++];
    uint64_t delta = process.runtime_ns >= before_runtime[pid - 1U]
                         ? process.runtime_ns - before_runtime[pid - 1U]
                         : 0U;
    row->pid = process.pid;
    row->parent_pid = process.parent_pid;
    row->cpu_id = process.running_cpu_id;
    row->state = process.state;
    row->cpu_tenths = htop_ratio_tenths(delta, elapsed_ns);
    row->memory_tenths = htop_ratio_tenths(process.resident_pages, total_pages);
    row->runtime_ns = process.runtime_ns;
    row->resident_pages = process.resident_pages;
    row->syscall_count = process.syscall_count;
    row->name = process.name == 0 ? "(unknown)" : process.name;
  }
  process_total = process_count;
  if (sort_key == HTOP_SORT_PARENT) {
    htop_sort_rows(rows, process_count, HTOP_SORT_PID, reverse);
    if (htop_arrange_tree(rows, process_count) != 0) {
      htop_sort_rows(rows, process_count, HTOP_SORT_PARENT, reverse);
    }
  } else {
    htop_sort_rows(rows, process_count, sort_key, reverse);
  }
  if (process_start > process_count) process_start = process_count;
  if (process_count == 0U) selected = 0U;
  else if (selected >= process_count) selected = process_count - 1U;

  if (color_output != 0) {
    process_shown = htop_render_color(
        output, output_capacity, output_bytes, terminal_columns, terminal_rows,
        cpu_start, cpu_shown, cpu_total, before_cpu, after_ns, elapsed_ns,
        managed_pages, free_pages, user_process_active_count(),
        user_process_current_failed_count(), rows, process_count, process_start,
        selected, sort_key, reverse, interactive, filter);
    (void)process_shown;
    kheap_free(before_runtime);
    kheap_free(before_cpu);
    kheap_free(rows);
    return XAIOS_OK;
  }

  output_append(output, output_capacity, output_bytes, "XAIOS htop sample_ms=");
  output_append_u64(output, output_capacity, output_bytes, sample_ms);
  output_append(output, output_capacity, output_bytes, " cpus=");
  output_append_u64(output, output_capacity, output_bytes, cpu_total);
  output_append(output, output_capacity, output_bytes, " tasks_active=");
  output_append_u64(output, output_capacity, output_bytes,
                    user_process_active_count());
  output_append(output, output_capacity, output_bytes, " failed=");
  output_append_u64(output, output_capacity, output_bytes,
                    user_process_current_failed_count());
  output_append(output, output_capacity, output_bytes, " sort=");
  output_append(output, output_capacity, output_bytes, htop_sort_name(sort_key));
  output_append(output, output_capacity, output_bytes, " reverse=");
  output_append_u64(output, output_capacity, output_bytes,
                    reverse != 0 ? 1U : 0U);
  if (filter[0] != '\0') {
    output_append(output, output_capacity, output_bytes, " filter=");
    output_append(output, output_capacity, output_bytes, filter);
  }
  output_append(output, output_capacity, output_bytes, "\nCPU all=");
  uint64_t busy_delta = after_busy_total >= before_busy_total
                            ? after_busy_total - before_busy_total
                            : 0U;
  uint64_t cpu_capacity = (uint64_t)(cpu_total == 0U ? 1U : cpu_total);
  uint64_t capacity_ns = elapsed_ns > UINT64_MAX / cpu_capacity
                             ? UINT64_MAX
                             : elapsed_ns * cpu_capacity;
  htop_append_percent(output, output_capacity, output_bytes,
                      htop_capacity_tenths(busy_delta, capacity_ns));
  output_append(output, output_capacity, output_bytes, " MEM managed=");
  uint64_t used_pages = managed_pages >= free_pages
                            ? managed_pages - free_pages
                            : 0U;
  htop_append_percent(output, output_capacity, output_bytes,
                      htop_capacity_tenths(used_pages, managed_pages));
  output_append(output, output_capacity, output_bytes, " pages=");
  output_append_u64(output, output_capacity, output_bytes, used_pages);
  output_append(output, output_capacity, output_bytes, "/");
  output_append_u64(output, output_capacity, output_bytes, managed_pages);
  output_append(output, output_capacity, output_bytes, " physical_pages=");
  output_append_u64(output, output_capacity, output_bytes, total_pages);
  output_append(output, output_capacity, output_bytes, "\n");

  if (show_cpus != 0) {
    output_append(output, output_capacity, output_bytes,
                  "CPU CPU% BUSY_MS IDLE_MS ACTIVE ROLE\n");
    for (uint32_t offset = 0U; offset < cpu_shown; ++offset) {
      xaios_cpu_usage_snapshot_t usage;
      if (user_cpu_usage_snapshot(cpu_start + offset, after_ns, &usage) !=
          XAIOS_OK) {
        continue;
      }
      uint64_t cpu_delta = usage.busy_ns >= before_cpu[offset]
                               ? usage.busy_ns - before_cpu[offset]
                               : 0U;
      output_append_u64(output, output_capacity, output_bytes, usage.cpu_id);
      output_append(output, output_capacity, output_bytes, " ");
      htop_append_percent(output, output_capacity, output_bytes,
                          htop_capacity_tenths(cpu_delta, elapsed_ns));
      output_append(output, output_capacity, output_bytes, " ");
      output_append_u64(output, output_capacity, output_bytes,
                        usage.busy_ns / UINT64_C(1000000));
      output_append(output, output_capacity, output_bytes, " ");
      uint64_t idle_ns = usage.elapsed_ns >= usage.busy_ns
                             ? usage.elapsed_ns - usage.busy_ns
                             : 0U;
      output_append_u64(output, output_capacity, output_bytes,
                        idle_ns / UINT64_C(1000000));
      output_append(output, output_capacity, output_bytes, " ");
      output_append_u64(output, output_capacity, output_bytes, usage.active_pid);
      output_append(output, output_capacity, output_bytes, " ");
      output_append(output, output_capacity, output_bytes,
                    htop_cpu_role_name(usage.cpu_id));
      output_append(output, output_capacity, output_bytes, "\n");
    }
    output_append(output, output_capacity, output_bytes, "cpu_shown=");
    output_append_u64(output, output_capacity, output_bytes, cpu_shown);
    output_append(output, output_capacity, output_bytes, " cpu_total=");
    output_append_u64(output, output_capacity, output_bytes, cpu_total);
    if (cpu_start + cpu_shown < cpu_total) {
      output_append(output, output_capacity, output_bytes, " next_cpu_start=");
      output_append_u64(output, output_capacity, output_bytes,
                        cpu_start + cpu_shown);
    }
    output_append(output, output_capacity, output_bytes, "\n");
  }

  output_append(output, output_capacity, output_bytes,
                "PID PPID S CPU% MEM% TIME_MS RES_KIB CPU SYSCALLS COMMAND\n");
  for (uint32_t i = process_start; i < process_count; ++i) {
    if (*output_bytes + 160U >= output_capacity) {
      break;
    }
    const htop_process_row_t *row = &rows[i];
    output_append_u64(output, output_capacity, output_bytes, row->pid);
    output_append(output, output_capacity, output_bytes, " ");
    output_append_u64(output, output_capacity, output_bytes, row->parent_pid);
    output_append(output, output_capacity, output_bytes, " ");
    output_append(output, output_capacity, output_bytes,
                  htop_state_name(row->state));
    output_append(output, output_capacity, output_bytes, " ");
    htop_append_percent(output, output_capacity, output_bytes, row->cpu_tenths);
    output_append(output, output_capacity, output_bytes, " ");
    htop_append_percent(output, output_capacity, output_bytes,
                        row->memory_tenths);
    output_append(output, output_capacity, output_bytes, " ");
    output_append_u64(output, output_capacity, output_bytes,
                      row->runtime_ns / UINT64_C(1000000));
    output_append(output, output_capacity, output_bytes, " ");
    output_append_u64(output, output_capacity, output_bytes,
                      row->resident_pages * 4U);
    output_append(output, output_capacity, output_bytes, " ");
    if (row->cpu_id == UINT32_MAX) {
      output_append(output, output_capacity, output_bytes, "-");
    } else {
      output_append_u64(output, output_capacity, output_bytes, row->cpu_id);
    }
    output_append(output, output_capacity, output_bytes, " ");
    output_append_u64(output, output_capacity, output_bytes, row->syscall_count);
    output_append(output, output_capacity, output_bytes, " ");
    output_append(output, output_capacity, output_bytes, row->name);
    output_append(output, output_capacity, output_bytes, "\n");
    ++process_shown;
  }
  output_append(output, output_capacity, output_bytes, "process_shown=");
  output_append_u64(output, output_capacity, output_bytes, process_shown);
  output_append(output, output_capacity, output_bytes, " process_total=");
  output_append_u64(output, output_capacity, output_bytes, process_total);
  output_append(output, output_capacity, output_bytes, " process_start=");
  output_append_u64(output, output_capacity, output_bytes, process_start);
  if (process_start + process_shown < process_total) {
    output_append(output, output_capacity, output_bytes, " truncated=1");
  }
  output_append(output, output_capacity, output_bytes, "\n");

  kheap_free(before_runtime);
  kheap_free(before_cpu);
  kheap_free(rows);
  return XAIOS_OK;
}

static xaios_status_t handle_ps(const char *args, char *output,
                              uint64_t output_capacity,
                              uint64_t *output_bytes) {
  uint64_t index = 0U;
  int show_all = 0;
  int long_format = 0;
  char token[32];
  while (token_next(args, &index, token, sizeof(token)) == XAIOS_OK) {
    if (string_equal(token, "aux") || string_equal(token, "-aux") ||
        string_equal(token, "-A") || string_equal(token, "-a") ||
        string_equal(token, "-ax")) {
      show_all = 1;
      long_format = 1;
    } else if (string_equal(token, "-l")) {
      long_format = 1;
    } else {
      return command_fail(output, output_capacity, output_bytes,
                          "ps: unsupported option");
    }
  }
  output_append(output, output_capacity, output_bytes,
                long_format != 0
                    ? "USER PID PPID STAT CPU TIME RSS COMMAND\n"
                    : "PID STAT TIME COMMAND\n");
  uint64_t now_ns = timer_now_ns();
  for (uint32_t pid = 1U; pid <= XAIOS_MAX_USER_PROCESSES; ++pid) {
    xaios_user_process_t process;
    if (user_process_snapshot_at(pid, now_ns, &process) != XAIOS_OK ||
        (show_all == 0 && htop_state_active(process.state) == 0)) {
      continue;
    }
    if (long_format != 0) {
      output_append(output, output_capacity, output_bytes, "admin ");
    }
    output_append_u64(output, output_capacity, output_bytes, process.pid);
    output_append(output, output_capacity, output_bytes, " ");
    if (long_format != 0) {
      output_append_u64(output, output_capacity, output_bytes,
                        process.parent_pid);
      output_append(output, output_capacity, output_bytes, " ");
    }
    output_append(output, output_capacity, output_bytes,
                  htop_state_name(process.state));
    output_append(output, output_capacity, output_bytes, " ");
    if (long_format != 0) {
      if (process.running_cpu_id == UINT32_MAX) {
        output_append(output, output_capacity, output_bytes, "- ");
      } else {
        output_append_u64(output, output_capacity, output_bytes,
                          process.running_cpu_id);
        output_append(output, output_capacity, output_bytes, " ");
      }
    }
    output_append_u64(output, output_capacity, output_bytes,
                      process.runtime_ns / UINT64_C(1000000));
    if (long_format != 0) {
      output_append(output, output_capacity, output_bytes, " ");
      output_append_u64(output, output_capacity, output_bytes,
                        process.resident_pages * 4U);
    }
    output_append(output, output_capacity, output_bytes, " ");
    output_append(output, output_capacity, output_bytes,
                  process.name == 0 ? "(unknown)" : process.name);
    output_append(output, output_capacity, output_bytes, "\n");
  }
  return XAIOS_OK;
}

static void append_size_human(char *output, uint64_t output_capacity,
                              uint64_t *output_bytes, uint64_t bytes) {
  static const char *units[] = {"B", "K", "M", "G", "T"};
  uint32_t unit = 0U;
  uint64_t tenths = bytes * 10U;
  while (tenths >= 10240U && unit + 1U < 5U) {
    tenths = (tenths + 512U) / 1024U;
    ++unit;
  }
  output_append_u64(output, output_capacity, output_bytes, tenths / 10U);
  if (unit != 0U && tenths % 10U != 0U) {
    output_append(output, output_capacity, output_bytes, ".");
    output_append_u64(output, output_capacity, output_bytes, tenths % 10U);
  }
  output_append(output, output_capacity, output_bytes, units[unit]);
}

static xaios_status_t handle_df(const char *args, char *output,
                              uint64_t output_capacity,
                              uint64_t *output_bytes) {
  uint64_t index = 0U;
  uint64_t block_size = 512U;
  int human = 0;
  uint32_t paths = 0U;
  char path[XAIOS_MFS_PATH_MAX];
  output_append(output, output_capacity, output_bytes,
                "Filesystem  Size Used Avail Capacity Mounted on\n");
  while (token_next(args, &index, path, sizeof(path)) == XAIOS_OK) {
    if (string_equal(path, "-h")) {
      human = 1;
      continue;
    }
    if (string_equal(path, "-k") || string_equal(path, "-P")) {
      block_size = string_equal(path, "-k") ? 1024U : 512U;
      continue;
    }
    char resolved[XAIOS_MFS_PATH_MAX];
    xaios_vfs_statfs_t statfs;
    if (remote_path_resolve(g_remote_login_cwd, path, resolved,
                            sizeof(resolved)) != XAIOS_OK ||
        vfs_statfs(resolved, &statfs) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "df: cannot inspect filesystem");
    }
    output_append(output, output_capacity, output_bytes,
                  resolved[0] == '/' && resolved[1] == 'm' ? "modelfs     "
                                                           : "mutablefs   ");
    uint64_t values[3] = {statfs.total_bytes, statfs.allocated_bytes,
                          statfs.free_bytes};
    for (uint32_t value = 0U; value < 3U; ++value) {
      if (human != 0) append_size_human(output, output_capacity, output_bytes,
                                        values[value]);
      else output_append_u64(output, output_capacity, output_bytes,
                             (values[value] + block_size - 1U) / block_size);
      output_append(output, output_capacity, output_bytes, " ");
    }
    uint64_t capacity = statfs.total_bytes == 0U
                            ? 0U
                            : (statfs.allocated_bytes * 100U +
                               statfs.total_bytes - 1U) /
                                  statfs.total_bytes;
    output_append_u64(output, output_capacity, output_bytes, capacity);
    output_append(output, output_capacity, output_bytes, "% ");
    output_append(output, output_capacity, output_bytes,
                  resolved[0] == '/' && resolved[1] == 'm' ? "/models" : "/");
    output_append(output, output_capacity, output_bytes, "\n");
    ++paths;
  }
  if (paths == 0U) {
    xaios_vfs_statfs_t root;
    if (vfs_statfs("/", &root) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "df: root filesystem unavailable");
    }
    output_append(output, output_capacity, output_bytes, "mutablefs   ");
    uint64_t values[3] = {root.total_bytes, root.allocated_bytes,
                          root.free_bytes};
    for (uint32_t value = 0U; value < 3U; ++value) {
      if (human != 0) append_size_human(output, output_capacity, output_bytes,
                                        values[value]);
      else output_append_u64(output, output_capacity, output_bytes,
                             (values[value] + block_size - 1U) / block_size);
      output_append(output, output_capacity, output_bytes, " ");
    }
    output_append_u64(output, output_capacity, output_bytes,
                      root.total_bytes == 0U
                          ? 0U
                          : (root.allocated_bytes * 100U + root.total_bytes - 1U) /
                                root.total_bytes);
    output_append(output, output_capacity, output_bytes, "% /\n");
  }
  return XAIOS_OK;
}

static xaios_status_t du_path(const char *path, int print_files,
                             int summary, int human, char *output,
                             uint64_t output_capacity, uint64_t *output_bytes,
                             uint64_t *total_bytes) {
  xaios_mfs_stat_t stat;
  if (mutable_fs_stat(path, &stat) != XAIOS_OK) return XAIOS_ERR_NOT_FOUND;
  if (stat.type == 2U) {
    *total_bytes = (uint64_t)stat.block_count * 512U;
    if (print_files != 0 && summary == 0) {
      if (human != 0) append_size_human(output, output_capacity, output_bytes,
                                        *total_bytes);
      else output_append_u64(output, output_capacity, output_bytes,
                             (*total_bytes + 511U) / 512U);
      output_append(output, output_capacity, output_bytes, "\t");
      output_append(output, output_capacity, output_bytes, path);
      output_append(output, output_capacity, output_bytes, "\n");
    }
    return XAIOS_OK;
  }
  if (stat.type != 1U) return XAIOS_ERR_INVALID;
  char listing[XAIOS_MFS_MAX_LIST_BYTES];
  uint64_t listing_size = 0U;
  uint64_t total = 0U;
  if (mutable_fs_list(path, listing, sizeof(listing), &listing_size) != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  uint64_t line_start = 0U;
  while (line_start < listing_size) {
    uint64_t line_end = line_start;
    while (line_end < listing_size && listing[line_end] != '\n') ++line_end;
    if (line_end > line_start) {
      char name[XAIOS_MFS_PATH_MAX];
      char child[XAIOS_MFS_PATH_MAX];
      uint64_t child_bytes = 0U;
      if (copy_cstr_range(name, sizeof(name), listing + line_start,
                          line_end - line_start) != XAIOS_OK ||
          path_join(child, sizeof(child), path, name) != XAIOS_OK ||
          du_path(child, print_files, summary, human, output, output_capacity,
                  output_bytes, &child_bytes) != XAIOS_OK ||
          UINT64_MAX - total < child_bytes) {
        return XAIOS_ERR_IO;
      }
      total += child_bytes;
    }
    line_start = line_end + 1U;
  }
  *total_bytes = total;
  if (summary == 0) {
    if (human != 0) append_size_human(output, output_capacity, output_bytes, total);
    else output_append_u64(output, output_capacity, output_bytes,
                           (total + 511U) / 512U);
    output_append(output, output_capacity, output_bytes, "\t");
    output_append(output, output_capacity, output_bytes, path);
    output_append(output, output_capacity, output_bytes, "\n");
  }
  return XAIOS_OK;
}

static xaios_status_t handle_du(const char *args, char *output,
                              uint64_t output_capacity,
                              uint64_t *output_bytes) {
  uint64_t index = 0U;
  uint32_t paths = 0U;
  int print_files = 0;
  int summary = 0;
  int human = 0;
  char token[XAIOS_MFS_PATH_MAX];
  while (token_next(args, &index, token, sizeof(token)) == XAIOS_OK) {
    if (token[0] == '-') {
      for (uint64_t flag = 1U; token[flag] != '\0'; ++flag) {
        if (token[flag] == 'a') print_files = 1;
        else if (token[flag] == 's') summary = 1;
        else if (token[flag] == 'h') human = 1;
        else if (token[flag] != 'k') {
          return command_fail(output, output_capacity, output_bytes,
                              "du: unsupported option");
        }
      }
      continue;
    }
    char resolved[XAIOS_MFS_PATH_MAX];
    uint64_t total = 0U;
    if (remote_path_resolve(g_remote_login_cwd, token, resolved,
                            sizeof(resolved)) != XAIOS_OK ||
        du_path(resolved, print_files, summary, human, output, output_capacity,
                output_bytes, &total) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "du: cannot inspect path");
    }
    if (summary != 0) {
      if (human != 0) append_size_human(output, output_capacity, output_bytes,
                                        total);
      else output_append_u64(output, output_capacity, output_bytes,
                             (total + 511U) / 512U);
      output_append(output, output_capacity, output_bytes, "\t");
      output_append(output, output_capacity, output_bytes, resolved);
      output_append(output, output_capacity, output_bytes, "\n");
    }
    ++paths;
  }
  if (paths == 0U) {
    uint64_t total = 0U;
    if (du_path(g_remote_login_cwd, print_files, summary, human, output,
                output_capacity, output_bytes, &total) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "du: cannot inspect current directory");
    }
    if (summary != 0) {
      if (human != 0) append_size_human(output, output_capacity, output_bytes,
                                        total);
      else output_append_u64(output, output_capacity, output_bytes,
                             (total + 511U) / 512U);
      output_append(output, output_capacity, output_bytes, "\t");
      output_append(output, output_capacity, output_bytes, g_remote_login_cwd);
      output_append(output, output_capacity, output_bytes, "\n");
    }
  }
  return XAIOS_OK;
}

static xaios_status_t handle_less(const char *args, char *output,
                                uint64_t output_capacity,
                                uint64_t *output_bytes) {
  uint64_t index = 0U;
  char token[XAIOS_MFS_PATH_MAX];
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
      if (buffer_append_text(files, sizeof(files), &files_used, token) != XAIOS_OK) {
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
    (void)buffer_append_text(cat_args, sizeof(cat_args), &cat_used, "-n ");
  }
  (void)buffer_append_text(cat_args, sizeof(cat_args), &cat_used, files);
  return handle_cat(cat_args, output, output_capacity, output_bytes);
}

#if !XAIOS_BOOT_TEST_APPS
typedef struct remote_app_definition {
  const char *command;
  const char *path;
  uint64_t capabilities;
} remote_app_definition_t;

static const remote_app_definition_t g_remote_apps[] = {
    {"hello", "/bin/hello", XAIOS_CAP_LOG | XAIOS_CAP_EXIT},
    {"sysinfo", "/bin/sysinfo",
     XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_TIME},
    {"systest", "/bin/systest",
     XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_FS_READ |
         XAIOS_CAP_FS_WRITE},
    {"smptest", "/bin/smptest",
     XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_OSCTL | XAIOS_CAP_SMP |
         XAIOS_CAP_THREADS},
    {"nettest", "/bin/nettest",
     XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_OSCTL | XAIOS_CAP_NET |
         XAIOS_CAP_TIME},
    {"lstm-xor", "/bin/lstm-xor",
     XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_CPU_AI | XAIOS_CAP_ML},
    {"mltest", "/bin/mltest",
     XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_CPU_AI | XAIOS_CAP_ML},
    {"posix-shell", "/bin/posix-shell",
     XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_REMOTE_LOGIN},
    {"agenttest", "/bin/agenttest",
     XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_AGENT | XAIOS_CAP_CPU_AI |
         XAIOS_CAP_ML},
#if XAIOS_FAILURE_TEST_APP
    {"app-fail", "/bin/app-fail", XAIOS_CAP_LOG | XAIOS_CAP_EXIT},
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

static xaios_status_t handle_remote_app(
    const remote_app_definition_t *app, const char *args, char *output,
    uint64_t output_capacity, uint64_t *output_bytes) {
  const xaios_initramfs_file_t *file = 0;
  char *log;
  uint64_t cursor;
  uint64_t start_cursor = 0U;
  uint64_t next_cursor = 0U;
  uint64_t latest_cursor = 0U;
  uint32_t log_bytes;
  int exit_code = 0;
  xaios_status_t status;

  if (app == 0 || args == 0 || args[skip_ws(args, 0U)] != '\0') {
    return command_fail(output, output_capacity, output_bytes,
                        "application: arguments are not supported");
  }
  if (initramfs_lookup(app->path, &file) != XAIOS_OK || file == 0 ||
      file->executable == 0U) {
    return command_fail(output, output_capacity, output_bytes,
                        "application: executable unavailable");
  }

  log = (char *)kheap_alloc(XAIOS_KLOG_FLUSH_MAX, 16U);
  if (log == 0) {
    return command_fail(output, output_capacity, output_bytes,
                        "application: output buffer unavailable");
  }
  cursor = klog_ring_total_written();
  status = user_process_run_transient(file, app->capabilities, &exit_code);
  log_bytes = klog_ring_snapshot(log, XAIOS_KLOG_FLUSH_MAX, cursor,
                                 &start_cursor, &next_cursor, &latest_cursor);
  if (status == XAIOS_OK) {
    append_app_log_lines(output, output_capacity, output_bytes, log, log_bytes,
                         app->path);
  }
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
  output_append(output, output_capacity, output_bytes, app->command);
  output_append(output, output_capacity, output_bytes, ": complete\n");
  return XAIOS_OK;
}
#endif

static xaios_status_t parse_and_execute(const char *command, char *output,
                                      uint64_t output_capacity,
                                      uint64_t *output_bytes) {
  char cmd[32];
  char args[XAIOS_REMOTE_LOGIN_LIST_BYTES];
  char arg1[XAIOS_MFS_PATH_MAX];
  char arg2[XAIOS_MFS_PATH_MAX];
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
        "tar zip unzip cpio cat less mv rm rmdir stat df du ps write sed nano htop pong "
        "ssh scp status sysinfo "
        "hello systest smptest nettest lstm-xor mltest posix-shell agenttest "
        "xaiosctl exit "
        "quit logout help\n");
    return XAIOS_OK;
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
  if (string_equal(cmd, "ls") == 1U) {
    return handle_ls(args, output, output_capacity, output_bytes);
  }
  if (string_equal(cmd, "l") == 1U) {
    return handle_ls("-la", output, output_capacity, output_bytes);
  }
  if (string_equal(cmd, "ll") == 1U) {
    return handle_ls("-l", output, output_capacity, output_bytes);
  }
  if (string_equal(cmd, "la") == 1U) {
    return handle_ls("-la", output, output_capacity, output_bytes);
  }
  if (string_equal(cmd, "exit") == 1U) {
    return XAIOS_OK;
  }
  if (string_equal(cmd, "quit") == 1U) {
    return XAIOS_OK;
  }
  if (string_equal(cmd, "logout") == 1U) {
    return XAIOS_OK;
  }
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
  if (string_equal(cmd, "echo") == 1U) {
    if (args[0] == '\0') {
      output_append_char(output, output_capacity, output_bytes, '\n');
      return XAIOS_OK;
    }
    output_append(output, output_capacity, output_bytes, args);
    output_append_char(output, output_capacity, output_bytes, '\n');
    return XAIOS_OK;
  }
  if (string_equal(cmd, "cpio") == 1U) {
    return handle_cpio(args, output, output_capacity, output_bytes);
  }
  if (string_equal(cmd, "tar") == 1U) {
    return handle_tar(args, output, output_capacity, output_bytes);
  }
  if (string_equal(cmd, "zip") == 1U) {
    return handle_zip(args, output, output_capacity, output_bytes);
  }
  if (string_equal(cmd, "unzip") == 1U) {
    return handle_unzip(args, output, output_capacity, output_bytes);
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
  if (string_equal(cmd, "nano") == 1U) {
    return handle_nano(args, output, output_capacity, output_bytes);
  }
  if (string_equal(cmd, "htop") == 1U) {
    return handle_htop(args, output, output_capacity, output_bytes);
  }
  if (string_equal(cmd, "pong") == 1U) {
    if (args[0] != '\0')
      return command_fail(output, output_capacity, output_bytes,
                          "pong: usage: pong");
    return command_fail(output, output_capacity, output_bytes,
                        "pong: interactive terminal required");
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
    char rhs[XAIOS_MFS_PATH_MAX];
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
    char lhs_output[XAIOS_MFS_MAX_FILE_BYTES];
    uint64_t lhs_bytes = 0;
    lhs_output[0] = '\0';
    xaios_status_t rc =
        parse_and_execute(lhs, lhs_output, sizeof(lhs_output), &lhs_bytes);
    if (rc != XAIOS_OK) {
      return rc;
    }
    char resolved[XAIOS_MFS_PATH_MAX];
    if (remote_path_resolve(g_remote_login_cwd, rhs, resolved,
                            sizeof(resolved)) != XAIOS_OK ||
        remote_ensure_parent(resolved) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "redirect: invalid path");
    }
    if (mutable_fs_write(resolved, lhs_output, lhs_bytes) != XAIOS_OK) {
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
    char lhs_output[XAIOS_MFS_MAX_FILE_BYTES];
    uint64_t lhs_bytes = 0;
    lhs_output[0] = '\0';
    xaios_status_t rc =
        parse_and_execute(lhs, lhs_output, sizeof(lhs_output), &lhs_bytes);
    if (rc != XAIOS_OK) {
      return rc;
    }
    if (mutable_fs_write("/tmp/_pipe_stage", lhs_output, lhs_bytes) !=
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

xaios_status_t remote_login_execute(const char *user, const char *command,
                                  char *output, uint64_t output_capacity,
                                  uint64_t *output_bytes) {
  if (user == 0 || command == 0 || output == 0 || output_bytes == 0 ||
      output_capacity < 2U) {
    ++g_remote_login_denials;
    return XAIOS_ERR_INVALID;
  }
  if (!string_equal(user, "admin")) {
    ++g_remote_login_denials;
    klog("remote-login: denied reason=unknown-user\n");
    return XAIOS_ERR_INVALID;
  }
  if (security_reject_credential_material(command) != XAIOS_OK) {
    ++g_remote_login_denials;
    klog("remote-login: denied user=%s reason=secret-material\n", user);
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
      return &g_remote_login_contexts[i];
    }
  }
  return 0;
}

static remote_login_context_t *remote_login_context_get(uint64_t session_id) {
  remote_login_context_t *context = remote_login_context_find(session_id);
  if (context != 0) return context;
  for (uint32_t i = 0U; i < XAIOS_REMOTE_LOGIN_MAX_SESSIONS; ++i) {
    if (g_remote_login_contexts[i].active == 0U) {
      context = &g_remote_login_contexts[i];
      context->session_id = session_id;
      context->active = 1U;
      context->cwd[0] = '/';
      context->cwd[1] = '\0';
      return context;
    }
  }
  return 0;
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
  kassert(htop_cpu_grid_columns(8U, 120U, 3U) == 1U);
  kassert(htop_cpu_grid_columns(9U, 120U, 3U) == 2U);
  kassert(htop_cpu_grid_columns(16U, 120U, 3U) == 2U);
  kassert(htop_cpu_grid_columns(17U, 120U, 3U) == 4U);
  kassert(htop_cpu_grid_columns(33U, 120U, 3U) == 8U);
  kassert(htop_cpu_grid_columns(65U, 240U, 3U) == 16U);
  kassert(htop_cpu_grid_columns(65U, 120U, 3U) == 8U);
  kassert(htop_cpu_grid_rows(16U, 2U) == 8U);
  kassert(htop_cpu_grid_rows(32U, 4U) == 8U);
  kassert(htop_cpu_page_capacity(120U, 40U, 3U) == 64U);
  kassert(htop_cpu_page_capacity(80U, 40U, 3U) == 32U);
  kassert(htop_cpu_page_capacity(40U, 12U, 3U) == 4U);
  klog("remote-login: adaptive htop CPU grid self-test passed\n");
  for (uint32_t i = 0U; i < XAIOS_REMOTE_LOGIN_MAX_SESSIONS; ++i) {
    g_remote_login_contexts[i].active = 0U;
  }

  kassert(remote_login_execute("admin", "shell", output, sizeof(output),
                               &out) == XAIOS_ERR_INVALID);
  out = 0U;
  output[0] = '\0';
  kassert(parse_and_execute("pong", output, sizeof(output),
                            &out) == XAIOS_ERR_INVALID);
  kassert(contains_substring(output,
                            "pong: interactive terminal required") == 1);
  klog("remote-login: Pong requires an interactive terminal\n");
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
