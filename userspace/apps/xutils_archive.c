/*
 * Archive and compression applets for the multi-call xutils binary.
 *
 * This file is compiled once per applet name beside xutils.c and linked into
 * every utility ELF, so it must be built with the same flags and the same
 * -DXAIOS_UTILITY_NAME as xutils.c.  It holds the ustar/tar implementation,
 * the gzip decoder it uses, and the zip/unzip pair, together with the crc32
 * and little-endian primitives they share.
 *
 * cpio deliberately stays in xutils.c: moving it here as well would push this
 * file past the 500-line limit.  The interface it shares back, and the
 * declarations of everything xutils.c lends this module, are in
 * xutils_archive.h.
 */
#include "xutils_archive.h"

typedef struct archive_entry {
  char name[PATH_MAX];
  u32 crc;
  u32 size;
  u32 offset;
  u32 method;
  u32 directory;
} archive_entry_t;

static archive_entry_t g_entries[ENTRY_MAX];

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

int xutils_archive_safe(const char *name) {
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
  xaios_xbfs_stat_user_t stat;
  if (xaios_fs_stat(source, &stat) != 0 || xutils_length(name) > 99U ||
      *used + USTAR_BLOCK > sizeof(xutils_scratch)) return -1;
  unsigned char *header = xutils_scratch + *used;
  xaios_memzero(header, USTAR_BLOCK);
  xutils_copy((char *)header, name, 100U);
  (void)octal_put((char *)header + 100U, 8U, stat.type == XAIOS_FS_TYPE_DIRECTORY ? 0755U : 0644U);
  (void)octal_put((char *)header + 108U, 8U, 0U);
  (void)octal_put((char *)header + 116U, 8U, 0U);
  (void)octal_put((char *)header + 124U, 12U, stat.type == XAIOS_FS_TYPE_FILE ? stat.size : 0U);
  (void)octal_put((char *)header + 136U, 12U, 0U);
  for (u64 i = 148U; i < 156U; ++i) header[i] = ' ';
  header[156] = stat.type == XAIOS_FS_TYPE_DIRECTORY ? '5' : '0';
  xutils_copy((char *)header + 257U, "ustar", 6U);
  xutils_copy((char *)header + 263U, "00", 3U);
  u64 sum = 0U;
  for (u64 i = 0U; i < USTAR_BLOCK; ++i) sum += header[i];
  (void)octal_put((char *)header + 148U, 8U, sum);
  *used += USTAR_BLOCK;
  if (stat.type == XAIOS_FS_TYPE_FILE) {
    u64 got = 0U;
    if (xutils_read_file(source, xutils_scratch + *used, sizeof(xutils_scratch) - *used, &got) != 0 ||
        got != stat.size) return -1;
    *used += (got + USTAR_BLOCK - 1U) & ~(USTAR_BLOCK - 1U);
    return *used <= sizeof(xutils_scratch) ? 0 : -1;
  }
  char listing[LIST_MAX];
  u64 listing_size = 0U;
  if (xutils_list_dir(source, listing, &listing_size) != 0) return -1;
  u64 cursor = 0U;
  char child_name[PATH_MAX];
  int next;
  while ((next = xutils_each_listing(listing, listing_size, &cursor, child_name)) > 0) {
    char child_source[PATH_MAX];
    char child_archive[PATH_MAX];
    if (xutils_join_path(source, child_name, child_source) != 0 ||
        xutils_join_path(name, child_name, child_archive) != 0 ||
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

int xutils_cmd_tar(const char *args) {
  u64 cursor = 0U;
  char mode[16];
  char archive_arg[PATH_MAX];
  if (xutils_next_token(args, &cursor, mode, sizeof(mode)) != 0 ||
      xutils_next_token(args, &cursor, archive_arg, sizeof(archive_arg)) != 0)
    return xutils_fail("usage: tar -cf|-tf|-xf ARCHIVE [PATH...]");
  int create = xutils_starts(mode, "-c");
  int list = xutils_starts(mode, "-t");
  int extract = xutils_starts(mode, "-x");
  int verbose = mode[xutils_length(mode) - 1U] == 'v' || mode[2] == 'v';
  if (!create && !list && !extract) return xutils_fail("unsupported mode");
  char archive_path[PATH_MAX];
  if (xutils_resolve_path(archive_arg, archive_path) != 0) return xutils_fail("invalid archive");
  if (create) {
    u64 used = 0U;
    char source_arg[PATH_MAX];
    int count = 0;
    while (xutils_next_token(args, &cursor, source_arg, sizeof(source_arg)) == 0) {
      char source[PATH_MAX];
      char name[PATH_MAX];
      if (xutils_resolve_path(source_arg, source) != 0 || xutils_basename_of(source, name) != 0 ||
          tar_add(source, name, &used) != 0) return xutils_fail("cannot create archive");
      if (verbose) { (void)xutils_append(name); (void)xutils_append("\n"); }
      ++count;
    }
    if (!count || used + 1024U > sizeof(xutils_scratch)) return xutils_fail("missing files");
    xaios_memzero(xutils_scratch + used, 1024U); used += 1024U;
    return xutils_write_file(archive_path, xutils_scratch, used) == 0 ? 0 : xutils_fail("write failed");
  }
  u64 size = 0U;
  if (xutils_read_file(archive_path, xutils_scratch, sizeof(xutils_scratch), &size) != 0)
    return xutils_fail("cannot read archive");
  if (size >= 2U && xutils_scratch[0] == 0x1fU && xutils_scratch[1] == 0x8bU) {
    u64 decoded_size = 0U;
    if (gzip_decode(xutils_scratch, size, xutils_aux, sizeof(xutils_aux), &decoded_size) != 0)
      return xutils_fail("invalid gzip archive");
    xaios_memcpy(xutils_scratch, xutils_aux, decoded_size);
    size = decoded_size;
  }
  char destination[PATH_MAX];
  xutils_copy(destination, xutils_cwd, sizeof(destination));
  char token[PATH_MAX];
  while (xutils_next_token(args, &cursor, token, sizeof(token)) == 0) {
    if (xutils_equal(token, "-C") && xutils_next_token(args, &cursor, token, sizeof(token)) == 0) {
      if (xutils_resolve_path(token, destination) != 0) return xutils_fail("invalid destination");
    } else return xutils_fail("unsupported option");
  }
  char extended_path[PATH_MAX];
  extended_path[0] = '\0';
  int saw_entry = 0;
  int saw_terminator = 0;
  for (u64 at = 0U; at + USTAR_BLOCK <= size;) {
    int zero = 1;
    for (u64 i = 0U; i < USTAR_BLOCK; ++i) if (xutils_scratch[at + i] != 0U) zero = 0;
    if (zero) {
      saw_terminator = 1;
      break;
    }
    saw_entry = 1;
    const unsigned char *header = xutils_scratch + at;
    u64 file_size = 0U;
    u64 stored_checksum = 0U;
    if (octal_get((const char *)header + 124U, 12U, &file_size) != 0 ||
        octal_get((const char *)header + 148U, 8U, &stored_checksum) != 0 ||
        file_size > size - at - USTAR_BLOCK) return xutils_fail("invalid archive");
    u64 checksum = 0U;
    for (u64 i = 0U; i < USTAR_BLOCK; ++i)
      checksum += i >= 148U && i < 156U ? (u64)' ' : header[i];
    if (checksum != stored_checksum || file_size > ~0ULL - (USTAR_BLOCK - 1U))
      return xutils_fail("invalid archive");
    u64 padded = (file_size + USTAR_BLOCK - 1U) & ~(USTAR_BLOCK - 1U);
    if (padded > size - at - USTAR_BLOCK) return xutils_fail("invalid archive");
    char type = header[156U] == 0U ? '0' : (char)header[156U];
    const unsigned char *payload = header + USTAR_BLOCK;
    if (type == 'x' || type == 'g') {
      if (type == 'x' && pax_path(payload, file_size, extended_path) != 0)
        return xutils_fail("invalid PAX header");
      at += USTAR_BLOCK + padded;
      continue;
    }
    if (type == 'L') {
      u64 path_size = 0U;
      while (path_size < file_size && payload[path_size] != 0U &&
             payload[path_size] != '\n')
        ++path_size;
      if (path_size == 0U || path_size + 1U > sizeof(extended_path))
        return xutils_fail("invalid GNU long name");
      for (u64 i = 0U; i < path_size; ++i)
        extended_path[i] = (char)payload[i];
      extended_path[path_size] = '\0';
      at += USTAR_BLOCK + padded;
      continue;
    }
    char name[PATH_MAX];
    if (extended_path[0] != '\0') {
      xutils_copy(name, extended_path, sizeof(name));
      extended_path[0] = '\0';
    } else if (tar_header_path(header, name) != 0) {
      return xutils_fail("invalid archive path");
    }
    if (!xutils_archive_safe(name)) return xutils_fail("unsafe path");
    if (list) { (void)xutils_append(name); (void)xutils_append("\n"); }
    if (extract) {
      char target[PATH_MAX];
      if (xutils_join_path(destination, name, target) != 0 || xutils_ensure_parents(target) != 0)
        return xutils_fail("unsafe path");
      if (type == '5') {
        if (xaios_fs_mkdir(target) != 0) {
          xaios_xbfs_stat_user_t stat;
          if (xaios_fs_stat(target, &stat) != 0) return xutils_fail("mkdir failed");
        }
      } else if (type == '0') {
        if (xutils_write_file(target, payload, file_size) != 0)
          return xutils_fail("extract failed");
      } else return xutils_fail("unsupported entry type");
    }
    at += USTAR_BLOCK + padded;
  }
  return saw_entry && saw_terminator ? 0 : xutils_fail("invalid archive");
}

static int zip_add(const char *source, const char *name, int recursive,
                   u64 *used, u32 *count) {
  xaios_xbfs_stat_user_t stat;
  if (*count >= ENTRY_MAX || xaios_fs_stat(source, &stat) != 0) return -1;
  int directory = stat.type == XAIOS_FS_TYPE_DIRECTORY;
  if (directory && !recursive) return -1;
  char entry_name[PATH_MAX]; xutils_copy(entry_name, name, sizeof(entry_name));
  u64 name_size = xutils_length(entry_name);
  if (directory && entry_name[name_size - 1U] != '/') {
    if (name_size + 2U > sizeof(entry_name)) return -1;
    entry_name[name_size++] = '/'; entry_name[name_size] = '\0';
  }
  u64 file_size = directory ? 0U : stat.size;
  if (*used + 30U + name_size + file_size > sizeof(xutils_scratch)) return -1;
  unsigned char *header = xutils_scratch + *used;
  xaios_memzero(header, 30U);
  put_le32(header, 0x04034b50U); put_le16(header + 4U, 20U);
  u64 data_at = *used + 30U + name_size;
  if (!directory) {
    u64 got = 0U;
    if (xutils_read_file(source, xutils_scratch + data_at, file_size, &got) != 0 || got != file_size)
      return -1;
  }
  u32 crc = crc32(xutils_scratch + data_at, file_size);
  put_le32(header + 14U, crc); put_le32(header + 18U, (u32)file_size);
  put_le32(header + 22U, (u32)file_size); put_le16(header + 26U, (u32)name_size);
  for (u64 i = 0U; i < name_size; ++i) header[30U + i] = (unsigned char)entry_name[i];
  archive_entry_t *entry = &g_entries[(*count)++];
  xutils_copy(entry->name, entry_name, sizeof(entry->name)); entry->crc = crc;
  entry->size = (u32)file_size; entry->offset = (u32)*used; entry->directory = directory;
  *used = data_at + file_size;
  if (directory) {
    char listing[LIST_MAX]; u64 listing_size = 0U;
    if (xutils_list_dir(source, listing, &listing_size) != 0) return -1;
    u64 cursor = 0U; char child_name[PATH_MAX]; int next;
    while ((next = xutils_each_listing(listing, listing_size, &cursor, child_name)) > 0) {
      char child_source[PATH_MAX], child_archive[PATH_MAX];
      if (xutils_join_path(source, child_name, child_source) != 0 ||
          xutils_join_path(entry_name, child_name, child_archive) != 0 ||
          zip_add(child_source, child_archive, 1, used, count) != 0) return -1;
    }
    if (next < 0) return -1;
  }
  return 0;
}

int xutils_cmd_zip(const char *args) {
  u64 cursor = 0U; char token[PATH_MAX]; int recursive = 0;
  if (xutils_next_token(args, &cursor, token, sizeof(token)) != 0) return xutils_fail("missing archive");
  if (xutils_equal(token, "-r")) { recursive = 1; if (xutils_next_token(args, &cursor, token, sizeof(token)) != 0) return xutils_fail("missing archive"); }
  char archive_path[PATH_MAX];
  if (xutils_resolve_path(token, archive_path) != 0) return xutils_fail("invalid archive");
  u64 used = 0U; u32 count = 0U; int sources = 0;
  while (xutils_next_token(args, &cursor, token, sizeof(token)) == 0) {
    char source[PATH_MAX], name[PATH_MAX];
    if (xutils_resolve_path(token, source) != 0 || xutils_basename_of(source, name) != 0 ||
        zip_add(source, name, recursive, &used, &count) != 0)
      return xutils_fail("cannot add path");
    ++sources;
  }
  if (!sources) return xutils_fail("missing files");
  u64 central = used;
  for (u32 i = 0U; i < count; ++i) {
    archive_entry_t *entry = &g_entries[i]; u64 name_size = xutils_length(entry->name);
    if (used + 46U + name_size > sizeof(xutils_scratch)) return xutils_fail("archive too large");
    unsigned char *h = xutils_scratch + used; xaios_memzero(h, 46U);
    put_le32(h, 0x02014b50U); put_le16(h + 4U, 0x0314U); put_le16(h + 6U, 20U);
    put_le32(h + 16U, entry->crc); put_le32(h + 20U, entry->size);
    put_le32(h + 24U, entry->size); put_le16(h + 28U, (u32)name_size);
    put_le32(h + 38U, entry->directory ? 0x10U : 0U); put_le32(h + 42U, entry->offset);
    for (u64 j = 0U; j < name_size; ++j) h[46U + j] = (unsigned char)entry->name[j];
    used += 46U + name_size;
  }
  if (used + 22U > sizeof(xutils_scratch)) return xutils_fail("archive too large");
  unsigned char *end = xutils_scratch + used; xaios_memzero(end, 22U);
  put_le32(end, 0x06054b50U); put_le16(end + 8U, count); put_le16(end + 10U, count);
  put_le32(end + 12U, (u32)(used - central)); put_le32(end + 16U, (u32)central);
  used += 22U;
  return xutils_write_file(archive_path, xutils_scratch, used) == 0 ? 0 : xutils_fail("write failed");
}

int xutils_cmd_unzip(const char *args) {
  u64 cursor = 0U; char token[PATH_MAX]; int list = 0;
  if (xutils_next_token(args, &cursor, token, sizeof(token)) != 0) return xutils_fail("missing archive");
  if (xutils_equal(token, "-l")) { list = 1; if (xutils_next_token(args, &cursor, token, sizeof(token)) != 0) return xutils_fail("missing archive"); }
  char archive_path[PATH_MAX];
  if (xutils_resolve_path(token, archive_path) != 0) return xutils_fail("invalid archive");
  char destination[PATH_MAX]; xutils_copy(destination, xutils_cwd, sizeof(destination));
  while (xutils_next_token(args, &cursor, token, sizeof(token)) == 0) {
    if (!xutils_equal(token, "-d") || xutils_next_token(args, &cursor, token, sizeof(token)) != 0 ||
        xutils_resolve_path(token, destination) != 0) return xutils_fail("unsupported option");
  }
  u64 size = 0U;
  if (xutils_read_file(archive_path, xutils_scratch, sizeof(xutils_scratch), &size) != 0)
    return xutils_fail("cannot read archive");
  u64 at = 0U;
  u32 entries = 0U;
  while (at + 30U <= size && get_le32(xutils_scratch + at) == 0x04034b50U) {
    u32 flags = get_le16(xutils_scratch + at + 6U); u32 method = get_le16(xutils_scratch + at + 8U);
    u32 crc = get_le32(xutils_scratch + at + 14U); u32 packed = get_le32(xutils_scratch + at + 18U);
    u32 unpacked = get_le32(xutils_scratch + at + 22U); u32 name_size = get_le16(xutils_scratch + at + 26U);
    u32 extra_size = get_le16(xutils_scratch + at + 28U);
    if ((u64)name_size + (u64)extra_size > size - at - 30U)
      return xutils_fail("unsupported or corrupt archive");
    u64 data_at = at + 30U + name_size + extra_size;
    if ((flags & 9U) != 0U || name_size == 0U || name_size >= PATH_MAX ||
        packed > size - data_at || (method != 0U && method != 8U))
      return xutils_fail("unsupported or corrupt archive");
    char name[PATH_MAX];
    for (u32 i = 0U; i < name_size; ++i) name[i] = (char)xutils_scratch[at + 30U + i];
    name[name_size] = '\0';
    if (!xutils_archive_safe(name)) return xutils_fail("unsafe path");
    if (list) { (void)xutils_append_u64(unpacked); (void)xutils_append(" "); (void)xutils_append(name); (void)xutils_append("\n"); }
    else {
      char target[PATH_MAX];
      if (xutils_join_path(destination, name, target) != 0 || xutils_ensure_parents(target) != 0)
        return xutils_fail("unsafe path");
      if (name[name_size - 1U] == '/') {
        if (xaios_fs_mkdir(target) != 0) {
          xaios_xbfs_stat_user_t stat; if (xaios_fs_stat(target, &stat) != 0) return xutils_fail("mkdir failed");
        }
      } else {
        const unsigned char *payload = xutils_scratch + data_at; u64 output_size = packed;
        if (method == 8U) {
          if (xaios_inflate_raw(payload, packed, xutils_aux, sizeof(xutils_aux), &output_size) != 0 ||
              output_size != unpacked) return xutils_fail("deflate failed");
          payload = xutils_aux;
        }
        if (output_size != unpacked || crc32(payload, output_size) != crc ||
            xutils_write_file(target, payload, output_size) != 0) return xutils_fail("extract failed");
      }
    }
    at = data_at + packed;
    ++entries;
  }
  if (entries == 0U || at + 4U > size ||
      (get_le32(xutils_scratch + at) != 0x02014b50U &&
       get_le32(xutils_scratch + at) != 0x06054b50U))
    return xutils_fail("unsupported or corrupt archive");
  return 0;
}
