#include <xaios_user.h>

#include "xapt_internal.h"

/* The repository index: the lexical helpers the records are read with, the
   per-line parsers for the two record kinds a catalog carries, and the lookups
   the commands in xapt.c ask for. The record shapes themselves are in
   xapt_internal.h, shared with the HTTP module that only moves bytes. */

static int hex_digit(char value) {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  if (value >= 'A' && value <= 'F') return value - 'A' + 10;
  return -1;
}

static int parse_hash(const char *text, unsigned char hash[32]) {
  for (u32 i = 0U; i < 32U; ++i) {
    int high = hex_digit(text[i * 2U]);
    int low = hex_digit(text[i * 2U + 1U]);
    if (high < 0 || low < 0) return -1;
    hash[i] = (unsigned char)((high << 4) | low);
  }
  return 0;
}

const char *xapt_architecture(void) {
#if defined(__aarch64__)
  return "aarch64";
#elif defined(__x86_64__)
  return "x86_64";
#elif defined(__riscv)
  return "riscv64";
#else
  return "unknown";
#endif
}

int xapt_text_equal(const char *left, const char *right) {
  u64 i = 0U;
  if (left == 0 || right == 0) return 0;
  while (left[i] != '\0' && left[i] == right[i]) ++i;
  return left[i] == right[i];
}

int xapt_text_starts(const char *text, const char *prefix) {
  u64 i = 0U;
  while (prefix[i] != '\0') {
    if (text[i] != prefix[i]) return 0;
    ++i;
  }
  return 1;
}

int xapt_copy_text(char *output, u64 capacity, const char *input,
                   u64 length) {
  if (length >= capacity) return -1;
  for (u64 i = 0U; i < length; ++i) output[i] = input[i];
  output[length] = '\0';
  return 0;
}

int xapt_parse_u64(const char *text, u64 length, u64 *value) {
  u64 result = 0U;
  if (length == 0U) return -1;
  for (u64 i = 0U; i < length; ++i) {
    u64 digit;
    if (text[i] < '0' || text[i] > '9') return -1;
    digit = (u64)(text[i] - '0');
    if (result > (~0ULL - digit) / 10U) return -1;
    result = result * 10U + digit;
  }
  *value = result;
  return 0;
}

int xapt_path_valid(const char *path) {
  if (path == 0 || path[0] != '/') return 0;
  for (u64 i = 0U; path[i] != '\0'; ++i) {
    if (path[i] == '\\' || path[i] == '\r' || path[i] == '\n' ||
        (path[i] == '.' && path[i + 1U] == '.' &&
         (i == 0U || path[i - 1U] == '/') &&
         (path[i + 2U] == '/' || path[i + 2U] == '\0'))) {
      return 0;
    }
  }
  return 1;
}

static int read_file_bounded(const char *path, char *buffer, u64 capacity) {
  u64 used = 0U;
  int fd;
  if (capacity < 2U) return -1;
  fd = xaios_fs_open(path, XAIOS_XBFS_OPEN_READ);
  if (fd < 0) return -1;
  while (used + 1U < capacity) {
    u64 available = capacity - used - 1U;
    u64 amount = available < XAPT_BUFFER_BYTES ? available : XAPT_BUFFER_BYTES;
    int bytes = xaios_fs_read(fd, buffer + used, amount);
    if (bytes < 0) {
      (void)xaios_fs_close(fd);
      return -1;
    }
    if (bytes == 0) break;
    used += (u64)bytes;
  }
  if (xaios_fs_close(fd) != 0 || used + 1U == capacity) return -1;
  buffer[used] = '\0';
  return (int)used;
}

int xapt_read_catalog(void) {
  int bytes = read_file_bounded(XAPT_CATALOG_PATH, xapt_catalog,
                                sizeof(xapt_catalog));
  return bytes > 0 && xapt_text_starts(xapt_catalog, "XAIOS-CATALOG-V1\n")
             ? bytes
             : -1;
}

static int split_fields(const char *line, u64 length, char *fields[],
                        u64 capacities[], u32 count) {
  u64 start = 0U;
  for (u32 field = 0U; field < count; ++field) {
    u64 end = start;
    while (end < length && line[end] != '|') ++end;
    if (xapt_copy_text(fields[field], capacities[field], line + start,
                       end - start) != 0)
      return -1;
    if (field + 1U < count) {
      if (end == length) return -1;
      start = end + 1U;
    } else if (end != length) {
      return -1;
    }
  }
  return 0;
}

int xapt_parse_app_line(const char *line, u64 length,
                        xapt_app_record_t *record) {
  char *fields[] = {record->name, record->version, record->architecture,
                    record->minimum_os, record->manifest_path,
                    record->binary_path, record->description};
  u64 capacities[] = {sizeof(record->name), sizeof(record->version),
                      sizeof(record->architecture), sizeof(record->minimum_os),
                      sizeof(record->manifest_path), sizeof(record->binary_path),
                      sizeof(record->description)};
  xaios_memzero(record, sizeof(*record));
  return length > 4U && line[0] == 'a' && line[1] == 'p' && line[2] == 'p' &&
                 line[3] == '=' &&
                 split_fields(line + 4U, length - 4U, fields, capacities, 7U) ==
                     0 &&
                 xapt_text_equal(record->architecture, xapt_architecture()) &&
                 xapt_path_valid(record->manifest_path) &&
                 xapt_path_valid(record->binary_path)
             ? 0
             : -1;
}

static int parse_os_line(const char *line, u64 length,
                         xapt_os_record_t *record) {
  char generation[16];
  char size[24];
  char hash[65];
  char *fields[] = {record->version, generation, record->architecture, size,
                    hash, record->signature, record->image_path};
  u64 capacities[] = {sizeof(record->version), sizeof(generation),
                      sizeof(record->architecture), sizeof(size), sizeof(hash),
                      sizeof(record->signature), sizeof(record->image_path)};
  u64 parsed_generation = 0U;
  xaios_memzero(record, sizeof(*record));
  if (length <= 3U || line[0] != 'o' || line[1] != 's' || line[2] != '=' ||
      split_fields(line + 3U, length - 3U, fields, capacities, 7U) != 0 ||
      xapt_parse_u64(generation, xaios_strlen(generation), &parsed_generation) !=
          0 ||
      parsed_generation == 0U || parsed_generation > 0xffffffffULL ||
      xapt_parse_u64(size, xaios_strlen(size), &record->size) != 0 ||
      xaios_strlen(hash) != 64U || parse_hash(hash, record->hash) != 0 ||
      !xapt_text_equal(record->architecture, xapt_architecture()) ||
      !xapt_path_valid(record->image_path)) {
    return -1;
  }
  record->generation = (u32)parsed_generation;
  return 0;
}

int xapt_find_app(const char *name, xapt_app_record_t *record) {
  int bytes = xapt_read_catalog();
  if (bytes < 0) return -1;
  u64 cursor = 0U;
  while (cursor < (u64)bytes) {
    u64 start = cursor;
    while (cursor < (u64)bytes && xapt_catalog[cursor] != '\n') ++cursor;
    if (xapt_parse_app_line(xapt_catalog + start, cursor - start, record) == 0 &&
        xapt_text_equal(record->name, name))
      return 0;
    ++cursor;
  }
  return -1;
}

int xapt_find_os(xapt_os_record_t *record) {
  int bytes = xapt_read_catalog();
  if (bytes < 0) return -1;
  u64 cursor = 0U;
  while (cursor < (u64)bytes) {
    u64 start = cursor;
    while (cursor < (u64)bytes && xapt_catalog[cursor] != '\n') ++cursor;
    if (parse_os_line(xapt_catalog + start, cursor - start, record) == 0)
      return 0;
    ++cursor;
  }
  return -1;
}

int xapt_installed_version(const char *name, char version[24]) {
  char path[96];
  u64 used = 0U;
  xaios_memzero(path, sizeof(path));
  xaios_append_cstr(path, sizeof(path), &used, "/apps/");
  xaios_append_cstr(path, sizeof(path), &used, name);
  xaios_append_cstr(path, sizeof(path), &used, "/current.manifest");
  int bytes = xaios_read_file(path, xapt_buffer, sizeof(xapt_buffer));
  if (bytes <= 0) return -1;
  for (u64 i = 0U; i + 8U < (u64)bytes; ++i) {
    if ((i == 0U || xapt_buffer[i - 1U] == '\n') &&
        xapt_text_starts(xapt_buffer + i, "version=")) {
      u64 end = i + 8U;
      while (end < (u64)bytes && xapt_buffer[end] != '\n') ++end;
      return xapt_copy_text(version, 24U, xapt_buffer + i + 8U, end - i - 8U);
    }
  }
  return -1;
}

int xapt_version_compare(const char *left, const char *right) {
  u64 li = 0U;
  u64 ri = 0U;
  for (u32 part = 0U; part < 3U; ++part) {
    u64 lv = 0U;
    u64 rv = 0U;
    while (left[li] >= '0' && left[li] <= '9')
      lv = lv * 10U + (u64)(left[li++] - '0');
    while (right[ri] >= '0' && right[ri] <= '9')
      rv = rv * 10U + (u64)(right[ri++] - '0');
    if (lv != rv) return lv > rv ? 1 : -1;
    if (part < 2U) {
      if (left[li++] != '.' || right[ri++] != '.') return 0;
    }
  }
  return 0;
}
