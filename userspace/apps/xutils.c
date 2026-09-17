#include <xaios_user.h>

#ifndef XAIOS_UTILITY_NAME
#define XAIOS_UTILITY_NAME "xutils"
#endif

#include "xutils_archive.h"
#include "xutils_applets.h"

static char g_output[OUTPUT_MAX];
unsigned char xutils_scratch[FILE_MAX];
unsigned char xutils_aux[FILE_MAX];
static u64 g_used;
const char *xutils_cwd;

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

/* Bridges to the helpers the applet modules share.  The output buffer and the
 * per-process state stay single-instanced here; xutils_archive.c,
 * xutils_file.c and xutils_text.c call these rather than carrying a copy. */
int xutils_append(const char *text) { return append(text); }
int xutils_append_u64(u64 value) { return append_u64(value); }
int xutils_append_bytes(const void *data, u64 size) { return append_bytes(data, size); }
int xutils_append_char(char value) { return append_char(value); }
int xutils_fail(const char *message) { return fail(message); }
u64 xutils_length(const char *text) { return length(text); }
int xutils_equal(const char *lhs, const char *rhs) { return equal(lhs, rhs); }
int xutils_starts(const char *text, const char *prefix) {
  return starts(text, prefix);
}
void xutils_copy(char *dst, const char *src, u64 capacity) {
  copy(dst, src, capacity);
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
  xaios_xbfs_stat_user_t stat;
  if (xaios_fs_stat(source, &stat) != 0 || !xutils_archive_safe(name)) return -1;
  u32 namesize = (u32)xutils_length(name) + 1U;
  u32 filesize = stat.type == XAIOS_FS_TYPE_FILE ? (u32)stat.size : 0U;
  u64 header_end = *used + 110U + namesize;
  u64 data_at = (header_end + 3U) & ~3ULL;
  u64 end = (data_at + filesize + 3U) & ~3ULL;
  if (end > sizeof(xutils_scratch)) return -1;
  unsigned char *header = xutils_scratch + *used;
  xaios_memzero(header, end - *used);
  xutils_copy((char *)header, "070701", 7U);
  hex8((char *)header + 6U, (*ino)++);
  hex8((char *)header + 14U, stat.type == XAIOS_FS_TYPE_DIRECTORY ? 0040755U : 0100644U);
  hex8((char *)header + 22U, 0U); hex8((char *)header + 30U, 0U);
  hex8((char *)header + 38U, 1U); hex8((char *)header + 46U, 0U);
  hex8((char *)header + 54U, filesize);
  for (u32 off = 62U; off <= 94U; off += 8U) hex8((char *)header + off, 0U);
  hex8((char *)header + 94U, namesize); hex8((char *)header + 102U, 0U);
  xutils_copy((char *)header + 110U, name, namesize);
  if (filesize != 0U) {
    u64 got = 0U;
    if (xutils_read_file(source, xutils_scratch + data_at, filesize, &got) != 0 || got != filesize)
      return -1;
  }
  *used = end;
  if (stat.type == XAIOS_FS_TYPE_DIRECTORY) {
    char listing[LIST_MAX]; u64 listing_size = 0U;
    if (xutils_list_dir(source, listing, &listing_size) != 0) return -1;
    u64 cursor = 0U; char child_name[PATH_MAX]; int next;
    while ((next = xutils_each_listing(listing, listing_size, &cursor, child_name)) > 0) {
      char child_source[PATH_MAX], child_archive[PATH_MAX];
      if (xutils_join_path(source, child_name, child_source) != 0 ||
          xutils_join_path(name, child_name, child_archive) != 0 ||
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
  while (xutils_next_token(args, &cursor, token, sizeof(token)) == 0) {
    if (xutils_equal(token, "-o")) create = 1;
    else if (xutils_equal(token, "-it") || xutils_equal(token, "-t")) list = 1;
    else if (xutils_equal(token, "-i")) extract = 1;
    else if (xutils_equal(token, "-O") || xutils_equal(token, "-I")) {
      if (xutils_next_token(args, &cursor, archive_arg, sizeof(archive_arg)) != 0)
        return xutils_fail("missing archive");
    } else if (xutils_equal(token, "-D")) {
      if (xutils_next_token(args, &cursor, destination_arg,
                     sizeof(destination_arg)) != 0)
        return xutils_fail("missing destination");
    } else if (token[0] == '-') return xutils_fail("unsupported option");
    else if (source_count < 16U) xutils_copy(sources[source_count++], token, PATH_MAX);
    else return xutils_fail("too many files");
  }
  if (archive_arg[0] == '\0' || (!create && !list && !extract))
    return xutils_fail("usage: cpio -o -O ARCHIVE FILE... | -it|-i -I ARCHIVE");
  char archive_path[PATH_MAX];
  if (xutils_resolve_path(archive_arg, archive_path) != 0) return xutils_fail("invalid archive");
  if (create) {
    u64 used = 0U; u32 ino = 1U;
    for (u32 i = 0U; i < source_count; ++i) {
      char source[PATH_MAX], name[PATH_MAX];
      if (xutils_resolve_path(sources[i], source) != 0 || xutils_basename_of(source, name) != 0 ||
          cpio_add(source, name, &used, &ino) != 0) return xutils_fail("create failed");
    }
    char trailer[] = "TRAILER!!!";
    if (used + 124U > sizeof(xutils_scratch)) return xutils_fail("archive too large");
    unsigned char *h = xutils_scratch + used; xaios_memzero(h, 124U);
    xutils_copy((char *)h, "070701", 7U);
    hex8((char *)h + 6U, ino); hex8((char *)h + 14U, 0U);
    for (u32 off = 22U; off <= 86U; off += 8U) hex8((char *)h + off, 0U);
    hex8((char *)h + 94U, 11U); hex8((char *)h + 102U, 0U);
    xutils_copy((char *)h + 110U, trailer, sizeof(trailer)); used += 124U;
    return xutils_write_file(archive_path, xutils_scratch, used) == 0 ? 0 : xutils_fail("write failed");
  }
  u64 size = 0U;
  if (xutils_read_file(archive_path, xutils_scratch, sizeof(xutils_scratch), &size) != 0)
    return xutils_fail("cannot read archive");
  char destination[PATH_MAX];
  if (destination_arg[0] == '\0') xutils_copy(destination, xutils_cwd, sizeof(destination));
  else if (xutils_resolve_path(destination_arg, destination) != 0)
    return xutils_fail("invalid destination");
  int found_trailer = 0;
  for (u64 at = 0U; at + 110U <= size;) {
    if (!xutils_starts((char *)xutils_scratch + at, "070701")) return xutils_fail("invalid archive");
    u32 file_size, name_size, mode;
    if (from_hex8(xutils_scratch + at + 54U, &file_size) != 0 ||
        from_hex8(xutils_scratch + at + 94U, &name_size) != 0 ||
        from_hex8(xutils_scratch + at + 14U, &mode) != 0 || name_size == 0U ||
        name_size >= PATH_MAX || name_size > size - at - 110U ||
        xutils_scratch[at + 110U + name_size - 1U] != 0U)
      return xutils_fail("invalid archive");
    char name[PATH_MAX];
    for (u32 i = 0U; i < name_size; ++i)
      name[i] = (char)xutils_scratch[at + 110U + i];
    name[name_size - 1U] = '\0';
    u64 data_at = (at + 110U + name_size + 3U) & ~3ULL;
    if (data_at > size || file_size > size - data_at)
      return xutils_fail("invalid archive");
    if (xutils_equal(name, "TRAILER!!!")) {
      found_trailer = 1;
      break;
    }
    if (!xutils_archive_safe(name)) return xutils_fail("unsafe path");
    if (list) { (void)xutils_append(name); (void)xutils_append("\n"); }
    if (extract) {
      char target[PATH_MAX];
      if (xutils_join_path(destination, name, target) != 0 || xutils_ensure_parents(target) != 0)
        return xutils_fail("unsafe path");
      if ((mode & 0170000U) == 0040000U) {
        if (xaios_fs_mkdir(target) != 0) {
          xaios_xbfs_stat_user_t stat;
          if (xaios_fs_stat(target, &stat) != 0) return xutils_fail("mkdir failed");
        }
      } else if ((mode & 0170000U) == 0100000U) {
        if (xutils_write_file(target, xutils_scratch + data_at, file_size) != 0)
          return xutils_fail("extract failed");
      } else return xutils_fail("unsupported entry type");
    }
    at = (data_at + file_size + 3U) & ~3ULL;
  }
  return found_trailer ? 0 : xutils_fail("invalid archive");
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
  int show_all = xutils_length(args) != 0U;
  (void)xutils_append(show_all ? "USER PID PPID STAT CPU TIME RSS COMMAND\n" :
                          "PID STAT TIME COMMAND\n");
  u32 cursor = 0U;
  for (;;) {
    xaios_control_runtime_snapshot_payload_user_t snapshot;
    if (runtime_query(&snapshot, cursor) != 0) return xutils_fail("snapshot unavailable");
    for (u32 i = 0U; i < snapshot.process_count; ++i) {
      xaios_control_runtime_process_record_user_t *p = &snapshot.processes[i];
      int active = p->state >= XAIOS_RUNTIME_PROCESS_LOADED &&
                   p->state <= XAIOS_RUNTIME_PROCESS_WAITING;
      if (!show_all && !active) continue;
      if (show_all) (void)xutils_append("admin ");
      (void)xutils_append_u64(p->pid); (void)xutils_append(" ");
      if (show_all) { (void)xutils_append_u64(p->parent_pid); (void)xutils_append(" "); }
      (void)xutils_append(state_name(p->state)); (void)xutils_append(" ");
      if (show_all) { if (p->cpu_id == 0xffffffffU) (void)xutils_append("- "); else { (void)xutils_append_u64(p->cpu_id); (void)xutils_append(" "); } }
      (void)xutils_append_u64(p->runtime_ns / 1000000U); (void)xutils_append(" ");
      if (show_all) { (void)xutils_append_u64(p->resident_pages * 4U); (void)xutils_append(" "); }
      (void)xutils_append(p->name); (void)xutils_append("\n");
    }
    if (snapshot.process_next == 0xffffffffU) break;
    if (snapshot.process_next <= cursor) return xutils_fail("invalid snapshot cursor");
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
  if (xutils_next_token(args, &cursor, token, sizeof(token)) == 0 &&
      (!xutils_equal(token, "-h") ||
       xutils_next_token(args, &cursor, token, sizeof(token)) == 0))
    return xutils_fail("unsupported option");
  union { u64 align; unsigned char bytes[XAIOS_CONTROL_MAX_RESPONSE_BYTES]; } response;
  u64 response_size = 0U;
  if (filesystem_query(response.bytes, &response_size) != 0 ||
      response_size < sizeof(xaios_control_response_header_user_t))
    return xutils_fail("filesystem data unavailable");
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
    return xutils_fail("filesystem data unavailable");
  xaios_control_storage_filesystems_payload_user_t *meta =
      (xaios_control_storage_filesystems_payload_user_t *)(response.bytes + sizeof(*header));
  u64 records_size = header->payload_length - sizeof(*meta);
  if (meta->record_count > XAIOS_CONTROL_STORAGE_MAX_FILESYSTEMS ||
      meta->total_count < meta->record_count || meta->truncated > 1U ||
      meta->reserved != 0U ||
      records_size != (u64)meta->record_count *
                          sizeof(xaios_control_storage_filesystem_record_user_t))
    return xutils_fail("filesystem data unavailable");
  xaios_control_storage_filesystem_record_user_t *records =
      (xaios_control_storage_filesystem_record_user_t *)(meta + 1);
  (void)xutils_append("Filesystem Size Used Avail Capacity Mounted on\n");
  for (u32 i = 0U; i < meta->record_count; ++i) {
    xaios_control_storage_filesystem_record_user_t *r = &records[i];
    if (!fixed_string_valid(r->filesystem, sizeof(r->filesystem)) ||
        !fixed_string_valid(r->mount_path, sizeof(r->mount_path)) ||
        r->allocated_bytes > r->total_bytes || r->free_bytes > r->total_bytes ||
        r->mounted > 1U || r->read_only > 1U || r->staging_writable > 1U)
      return xutils_fail("filesystem data unavailable");
    (void)xutils_append(r->filesystem); (void)xutils_append(" ");
    (void)xutils_append_u64(r->total_bytes / 1024U); (void)xutils_append("K ");
    (void)xutils_append_u64(r->allocated_bytes / 1024U); (void)xutils_append("K ");
    (void)xutils_append_u64(r->free_bytes / 1024U); (void)xutils_append("K ");
    (void)xutils_append_u64(percent_ceil(r->allocated_bytes, r->total_bytes));
    (void)xutils_append("% "); (void)xutils_append(r->mount_path); (void)xutils_append("\n");
  }
  return 0;
}

static int du_walk(const char *path, int human, int summary, u64 *total) {
  xaios_xbfs_stat_user_t stat;
  if (xaios_fs_stat(path, &stat) != 0) return -1;
  if (stat.type == XAIOS_FS_TYPE_FILE) { *total = (u64)stat.block_count * 512U; return 0; }
  char listing[LIST_MAX]; u64 size = 0U;
  if (xutils_list_dir(path, listing, &size) != 0) return -1;
  u64 cursor = 0U; char name[PATH_MAX]; int next; u64 sum = 0U;
  while ((next = xutils_each_listing(listing, size, &cursor, name)) > 0) {
    char child[PATH_MAX]; u64 child_size = 0U;
    if (xutils_join_path(path, name, child) != 0 || du_walk(child, human, summary, &child_size) != 0)
      return -1;
    sum += child_size;
  }
  if (next < 0) return -1;
  *total = sum;
  if (!summary) { (void)xutils_append_u64(human ? (sum + 1023U) / 1024U : (sum + 511U) / 512U); (void)xutils_append(human ? "K\t" : "\t"); (void)xutils_append(path); (void)xutils_append("\n"); }
  return 0;
}

static int cmd_du(const char *args) {
  u64 cursor = 0U; char token[PATH_MAX]; int human = 0, summary = 0, paths = 0;
  while (xutils_next_token(args, &cursor, token, sizeof(token)) == 0) {
    if (token[0] == '-') {
      for (u64 i = 1U; token[i] != '\0'; ++i) {
        if (token[i] == 'h') human = 1; else if (token[i] == 's') summary = 1;
        else if (token[i] != 'k' && token[i] != 'a') return xutils_fail("unsupported option");
      }
      continue;
    }
    char path[PATH_MAX]; u64 total = 0U;
    if (xutils_resolve_path(token, path) != 0 || du_walk(path, human, summary, &total) != 0)
      return xutils_fail("cannot inspect path");
    if (summary) { (void)xutils_append_u64(human ? (total + 1023U) / 1024U : (total + 511U) / 512U); (void)xutils_append(human ? "K\t" : "\t"); (void)xutils_append(path); (void)xutils_append("\n"); }
    ++paths;
  }
  if (!paths) { u64 total = 0U; if (du_walk(xutils_cwd, human, summary, &total) != 0) return xutils_fail("cannot inspect current directory"); if (summary) { (void)xutils_append_u64((total + 511U) / 512U); (void)xutils_append("\t"); (void)xutils_append(xutils_cwd); (void)xutils_append("\n"); } }
  return 0;
}

int main(int argc, char **argv) {
  const char *args = argc > 2 ? argv[2] : "";
  if (argc < 2 || argv == 0 || argv[1] == 0 || argv[1][0] != '/') return xutils_fail("missing session context");
  xutils_cwd = argv[1]; g_used = 0U; g_output[0] = '\0';
  int result;
  if (xutils_equal(XAIOS_UTILITY_NAME, "ls")) result = xutils_cmd_ls(args);
  else if (xutils_equal(XAIOS_UTILITY_NAME, "mkdir")) result = xutils_cmd_mkdir(args);
  else if (xutils_equal(XAIOS_UTILITY_NAME, "touch")) result = xutils_cmd_touch(args);
  else if (xutils_equal(XAIOS_UTILITY_NAME, "cp")) result = xutils_cmd_cp(args);
  else if (xutils_equal(XAIOS_UTILITY_NAME, "mv")) result = xutils_cmd_mv(args);
  else if (xutils_equal(XAIOS_UTILITY_NAME, "rm")) result = xutils_cmd_rm(args, 0);
  else if (xutils_equal(XAIOS_UTILITY_NAME, "rmdir")) result = xutils_cmd_rm(args, 1);
  else if (xutils_equal(XAIOS_UTILITY_NAME, "stat")) result = xutils_cmd_stat(args);
  else if (xutils_equal(XAIOS_UTILITY_NAME, "cat")) result = xutils_cmd_cat_like(args, 0);
  else if (xutils_equal(XAIOS_UTILITY_NAME, "head")) result = xutils_cmd_cat_like(args, 1);
  else if (xutils_equal(XAIOS_UTILITY_NAME, "tail")) result = xutils_cmd_cat_like(args, 2);
  else if (xutils_equal(XAIOS_UTILITY_NAME, "less")) result = xutils_cmd_cat_like(args, 0);
  else if (xutils_equal(XAIOS_UTILITY_NAME, "grep")) result = xutils_cmd_grep(args);
  else if (xutils_equal(XAIOS_UTILITY_NAME, "find")) result = xutils_cmd_find(args);
  else if (xutils_equal(XAIOS_UTILITY_NAME, "write")) result = xutils_cmd_write(args);
  else if (xutils_equal(XAIOS_UTILITY_NAME, "sed")) result = xutils_cmd_sed(args);
  else if (xutils_equal(XAIOS_UTILITY_NAME, "tar")) result = xutils_cmd_tar(args);
  else if (xutils_equal(XAIOS_UTILITY_NAME, "cpio")) result = cmd_cpio(args);
  else if (xutils_equal(XAIOS_UTILITY_NAME, "zip")) result = xutils_cmd_zip(args);
  else if (xutils_equal(XAIOS_UTILITY_NAME, "unzip")) result = xutils_cmd_unzip(args);
  else if (xutils_equal(XAIOS_UTILITY_NAME, "ps")) result = cmd_ps(args);
  else if (xutils_equal(XAIOS_UTILITY_NAME, "df")) result = cmd_df(args);
  else if (xutils_equal(XAIOS_UTILITY_NAME, "du")) result = cmd_du(args);
  else result = xutils_fail("unsupported utility image");
  if (result == 0 && flush_output() != 0) return 1;
  return result;
}
