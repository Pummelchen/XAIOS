/*
 * Boot-test archive format primitives: the XAIOSARCHIVE entry encoding, the
 * ustar header accessors and the raw-DEFLATE gzip decoder, the zip
 * little-endian codecs and central-directory writer, and the `cat` handler the
 * pager falls back to.
 *
 * Every piece came from a `#if XAIOS_BOOT_TEST_APPS` arm of remote_login.c and
 * keeps that guard, so in the shipped configuration this translation unit is
 * empty. remote_login_buffer_append_char and remote_login_buffer_append_text
 * stay in remote_login.c with the other guarded shell primitives -- the text
 * module and the redirect driver name them too -- and archive_append_entry
 * calls them across the translation-unit boundary through
 * remote_login_internal.h. u64_digits, buffer_append_u64, parse_u64_token,
 * gzip_read_le32 and cat_file have no caller outside this file and stay
 * `static`.
 */

#include "remote_login_internal.h"
#include "remote_login_archive_internal.h"

#include <xaios/crc32.h>
#include <xaios/inflate.h>
#include <xaios/status.h>
#include <xaios/types.h>
#include <xaios/xaiboot_fs.h>

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

#if XAIOS_BOOT_TEST_APPS
static xaios_status_t buffer_append_u64(char *buffer, uint64_t capacity,
                                      uint64_t *offset, uint64_t value) {
  char digits[24];
  uint64_t count = 0;
  if (value == 0U) {
    return remote_login_buffer_append_char(buffer, capacity, offset, '0');
  }
  while (value != 0U && count < sizeof(digits)) {
    digits[count] = (char)('0' + (value % 10U));
    value /= 10U;
    ++count;
  }
  while (count != 0U) {
    char c = digits[count - 1U];
    --count;
    if (remote_login_buffer_append_char(buffer, capacity, offset, c) != XAIOS_OK) {
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
  if (remote_login_buffer_append_char(archive, archive_capacity, archive_size, ' ') != XAIOS_OK) {
    return XAIOS_ERR_NO_MEMORY;
  }
  if (buffer_append_u64(archive, archive_capacity, archive_size, data_size) !=
      XAIOS_OK) {
    return XAIOS_ERR_NO_MEMORY;
  }
  if (remote_login_buffer_append_char(archive, archive_capacity, archive_size, ' ') != XAIOS_OK) {
    return XAIOS_ERR_NO_MEMORY;
  }
  if (remote_login_buffer_append_text(archive, archive_capacity, archive_size, path) != XAIOS_OK) {
    return XAIOS_ERR_NO_MEMORY;
  }
  if (remote_login_buffer_append_char(archive, archive_capacity, archive_size, '\n') != XAIOS_OK) {
    return XAIOS_ERR_NO_MEMORY;
  }
  for (uint64_t i = 0; i < data_size; ++i) {
    if (remote_login_buffer_append_char(archive, archive_capacity, archive_size, data[i]) != XAIOS_OK) {
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
#endif

#if XAIOS_BOOT_TEST_APPS
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

xaios_status_t remote_login_handle_cat(const char *args, char *output,
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
    if (remote_path_resolve(remote_login_cwd(), token, resolved,
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

#endif
