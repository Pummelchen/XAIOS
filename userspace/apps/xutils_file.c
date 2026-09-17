/*
 * File applets (ls/mkdir/touch/cp/mv/rm/rmdir/stat) and the path and
 * file-I/O helpers they own, split out of xutils.c.
 *
 * xutils.c is compiled once per applet name with -DXAIOS_UTILITY_NAME; this
 * file is compiled with the same flags and linked beside xutils.c,
 * xutils_archive.c and xutils_text.c into every utility ELF.  It reads the
 * shared declarations from xutils_applets.h and the per-process scratch
 * arena, working directory and output helpers from xutils_archive.h, all of
 * which stay single-instanced in xutils.c.
 */
#include "xutils_applets.h"

static int sensitive(const char *path) {
  return xutils_equal(path, "/state/xaios_host_key") ||
         xutils_equal(path, "/etc/xaios_sshd_users") ||
         xutils_equal(path, "/etc/xaios_authorized_keys") ||
         xutils_equal(path, "/etc/xaios_ssh_client_identity") ||
         xutils_starts(path, "/state/control/") || xutils_equal(path, "/state/control");
}

int xutils_resolve_path(const char *input, char *output) {
  char source[PATH_MAX];
  u64 source_used = 0U;
  u64 input_at = 0U;
  if (input == 0 || input[0] == '\0') input = ".";
  if (input[0] == '/') {
    if (xutils_length(input) + 1U > sizeof(source)) return -1;
    xutils_copy(source, input, sizeof(source));
  } else {
    xutils_copy(source, xutils_cwd, sizeof(source));
    source_used = xutils_length(source);
    if (source_used > 1U && source[source_used - 1U] != '/')
      source[source_used++] = '/';
    if (xutils_length(input) + source_used + 1U > sizeof(source)) return -1;
    xutils_copy(source + source_used, input, sizeof(source) - source_used);
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

int xutils_join_path(const char *base, const char *name, char *output) {
  u64 base_size = xutils_length(base);
  u64 name_size = xutils_length(name);
  if (base_size + name_size + 2U > PATH_MAX) return -1;
  xutils_copy(output, base, PATH_MAX);
  if (base_size != 1U) output[base_size++] = '/';
  xutils_copy(output + base_size, name, PATH_MAX - base_size);
  return 0;
}

int xutils_basename_of(const char *path, char *name) {
  u64 end = xutils_length(path);
  while (end > 1U && path[end - 1U] == '/') --end;
  u64 start = end;
  while (start > 0U && path[start - 1U] != '/') --start;
  if (end == start || end - start + 1U > PATH_MAX) return -1;
  for (u64 i = start; i < end; ++i) name[i - start] = path[i];
  name[end - start] = '\0';
  return 0;
}

int xutils_read_file(const char *path, unsigned char *buffer, u64 capacity,
                     u64 *size) {
  xaios_xbfs_stat_user_t stat;
  if (xaios_fs_stat(path, &stat) != 0 || stat.type != XAIOS_FS_TYPE_FILE ||
      stat.size > capacity)
    return -1;
  int fd = xaios_fs_open(path, XAIOS_XBFS_OPEN_READ);
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

int xutils_write_file(const char *path, const void *buffer, u64 size) {
  int fd = xaios_fs_open(path, XAIOS_XBFS_OPEN_WRITE | XAIOS_XBFS_OPEN_CREATE |
                                   XAIOS_XBFS_OPEN_TRUNCATE);
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

int xutils_list_dir(const char *path, char *listing, u64 *size) {
  return xaios_fs_list(path, listing, LIST_MAX, size) < 0 ? -1 : 0;
}

int xutils_ensure_parents(const char *path) {
  char current[PATH_MAX];
  xutils_copy(current, path, sizeof(current));
  for (u64 i = 1U; current[i] != '\0'; ++i) {
    if (current[i] == '/') {
      current[i] = '\0';
      if (xaios_fs_mkdir(current) != 0) {
        xaios_xbfs_stat_user_t stat;
        if (xaios_fs_stat(current, &stat) != 0 ||
            stat.type != XAIOS_FS_TYPE_DIRECTORY) return -1;
      }
      current[i] = '/';
    }
  }
  return 0;
}

int xutils_each_listing(const char *listing, u64 size, u64 *cursor,
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

static int remove_tree(const char *path) {
  xaios_xbfs_stat_user_t stat;
  if (xaios_fs_stat(path, &stat) != 0) return -1;
  if (stat.type == XAIOS_FS_TYPE_FILE) return xaios_fs_delete(path);
  char listing[LIST_MAX];
  u64 size = 0U;
  if (xutils_list_dir(path, listing, &size) != 0) return -1;
  u64 cursor = 0U;
  char name[PATH_MAX];
  int next;
  while ((next = xutils_each_listing(listing, size, &cursor, name)) > 0) {
    char child[PATH_MAX];
    if (xutils_join_path(path, name, child) != 0 || remove_tree(child) != 0) return -1;
  }
  return next < 0 ? -1 : xaios_fs_delete(path);
}

static int copy_tree(const char *source, const char *destination, int recursive) {
  xaios_xbfs_stat_user_t stat;
  if (xaios_fs_stat(source, &stat) != 0) return -1;
  if (stat.type == XAIOS_FS_TYPE_FILE) {
    u64 size = 0U;
    if (xutils_read_file(source, xutils_scratch, sizeof(xutils_scratch), &size) != 0 ||
        xutils_ensure_parents(destination) != 0) return -1;
    return xutils_write_file(destination, xutils_scratch, size);
  }
  if (!recursive || stat.type != XAIOS_FS_TYPE_DIRECTORY) return -1;
  if (xaios_fs_mkdir(destination) != 0) {
    xaios_xbfs_stat_user_t dst;
    if (xaios_fs_stat(destination, &dst) != 0 ||
        dst.type != XAIOS_FS_TYPE_DIRECTORY) return -1;
  }
  char listing[LIST_MAX];
  u64 size = 0U;
  if (xutils_list_dir(source, listing, &size) != 0) return -1;
  u64 cursor = 0U;
  char name[PATH_MAX];
  int next;
  while ((next = xutils_each_listing(listing, size, &cursor, name)) > 0) {
    char child_source[PATH_MAX];
    char child_destination[PATH_MAX];
    if (xutils_join_path(source, name, child_source) != 0 ||
        xutils_join_path(destination, name, child_destination) != 0 ||
        copy_tree(child_source, child_destination, 1) != 0) return -1;
  }
  return next < 0 ? -1 : 0;
}

int xutils_cmd_ls(const char *args) {
  int show_all = 0;
  int long_form = 0;
  char operand[PATH_MAX] = ".";
  char token[PATH_MAX];
  u64 cursor = 0U;
  int operands = 0;
  while (xutils_next_token(args, &cursor, token, sizeof(token)) == 0) {
    if (token[0] == '-') {
      for (u64 i = 1U; token[i] != '\0'; ++i) {
        if (token[i] == 'a') show_all = 1;
        else if (token[i] == 'l') long_form = 1;
        else return xutils_fail("invalid option");
      }
    } else {
      if (operands++) return xutils_fail("too many arguments");
      xutils_copy(operand, token, sizeof(operand));
    }
  }
  char path[PATH_MAX];
  if (xutils_resolve_path(operand, path) != 0) return xutils_fail("invalid path");
  xaios_xbfs_stat_user_t stat;
  if (xaios_fs_stat(path, &stat) == 0 && stat.type == XAIOS_FS_TYPE_FILE) {
    if (long_form) { (void)xutils_append("- "); (void)xutils_append_u64(stat.size); (void)xutils_append(" "); }
    (void)xutils_append(operand); (void)xutils_append("\n");
    return 0;
  }
  char listing[LIST_MAX];
  u64 size = 0U;
  if (xutils_list_dir(path, listing, &size) != 0) return xutils_fail("not found");
  cursor = 0U;
  char name[PATH_MAX];
  int next;
  while ((next = xutils_each_listing(listing, size, &cursor, name)) > 0) {
    if (!show_all && name[0] == '.') continue;
    char child[PATH_MAX];
    if (xutils_join_path(path, name, child) != 0 || xaios_fs_stat(child, &stat) != 0)
      continue;
    if (long_form) {
      (void)xutils_append(stat.type == XAIOS_FS_TYPE_DIRECTORY ? "d " : "- ");
      (void)xutils_append_u64(stat.size); (void)xutils_append(" ");
    }
    (void)xutils_append(name); (void)xutils_append("\n");
  }
  return next < 0 ? xutils_fail("directory listing failed") : 0;
}

int xutils_cmd_mkdir(const char *args) {
  u64 cursor = 0U;
  char token[PATH_MAX];
  int parents = 0;
  int made = 0;
  while (xutils_next_token(args, &cursor, token, sizeof(token)) == 0) {
    if (xutils_equal(token, "-p")) { parents = 1; continue; }
    if (token[0] == '-') return xutils_fail("invalid option");
    char path[PATH_MAX];
    if (xutils_resolve_path(token, path) != 0 ||
        (parents && xutils_ensure_parents(path) != 0) || xaios_fs_mkdir(path) != 0) {
      xaios_xbfs_stat_user_t stat;
      if (!parents || xaios_fs_stat(path, &stat) != 0 ||
          stat.type != XAIOS_FS_TYPE_DIRECTORY) return xutils_fail("cannot create directory");
    }
    made = 1;
  }
  return made ? 0 : xutils_fail("missing operand");
}

int xutils_cmd_touch(const char *args) {
  u64 cursor = 0U;
  char token[PATH_MAX];
  int count = 0;
  while (xutils_next_token(args, &cursor, token, sizeof(token)) == 0) {
    char path[PATH_MAX];
    if (xutils_resolve_path(token, path) != 0 || xutils_ensure_parents(path) != 0 ||
        xutils_write_file(path, "", 0U) != 0) return xutils_fail("cannot touch file");
    ++count;
  }
  return count ? 0 : xutils_fail("missing file operand");
}

int xutils_cmd_cp(const char *args) {
  char operands[16][PATH_MAX];
  u32 count = 0U;
  int recursive = 0;
  u64 cursor = 0U;
  char token[PATH_MAX];
  while (xutils_next_token(args, &cursor, token, sizeof(token)) == 0) {
    if (xutils_equal(token, "-R") || xutils_equal(token, "-r")) { recursive = 1; continue; }
    if (token[0] == '-') return xutils_fail("unsupported option");
    if (count == 16U) return xutils_fail("too many operands");
    xutils_copy(operands[count++], token, PATH_MAX);
  }
  if (count < 2U) return xutils_fail("missing file operand");
  char destination[PATH_MAX];
  if (xutils_resolve_path(operands[count - 1U], destination) != 0)
    return xutils_fail("invalid destination");
  xaios_xbfs_stat_user_t dst_stat;
  int dst_dir = xaios_fs_stat(destination, &dst_stat) == 0 &&
                dst_stat.type == XAIOS_FS_TYPE_DIRECTORY;
  if (count > 2U && !dst_dir) return xutils_fail("destination is not a directory");
  for (u32 i = 0U; i + 1U < count; ++i) {
    char source[PATH_MAX];
    char target[PATH_MAX];
    if (xutils_resolve_path(operands[i], source) != 0) return xutils_fail("invalid source");
    xutils_copy(target, destination, sizeof(target));
    if (dst_dir) {
      char name[PATH_MAX];
      if (xutils_basename_of(source, name) != 0 || xutils_join_path(destination, name, target) != 0)
        return xutils_fail("invalid destination");
    }
    if (copy_tree(source, target, recursive) != 0) return xutils_fail("copy failed");
  }
  return 0;
}

int xutils_cmd_mv(const char *args) {
  u64 cursor = 0U;
  char source_arg[PATH_MAX];
  char destination_arg[PATH_MAX];
  char extra[2];
  if (xutils_next_token(args, &cursor, source_arg, sizeof(source_arg)) != 0 ||
      xutils_next_token(args, &cursor, destination_arg, sizeof(destination_arg)) != 0 ||
      xutils_next_token(args, &cursor, extra, sizeof(extra)) == 0)
    return xutils_fail("usage: mv SOURCE DEST");
  char source[PATH_MAX];
  char destination[PATH_MAX];
  if (xutils_resolve_path(source_arg, source) != 0 ||
      xutils_resolve_path(destination_arg, destination) != 0 ||
      xutils_ensure_parents(destination) != 0) return xutils_fail("invalid path");
  xaios_xbfs_stat_user_t stat;
  if (xaios_fs_stat(destination, &stat) == 0 &&
      stat.type == XAIOS_FS_TYPE_DIRECTORY) {
    char name[PATH_MAX];
    char nested[PATH_MAX];
    if (xutils_basename_of(source, name) != 0 || xutils_join_path(destination, name, nested) != 0)
      return xutils_fail("invalid destination");
    xutils_copy(destination, nested, sizeof(destination));
  }
  return xaios_fs_rename(source, destination) == 0 ? 0 : xutils_fail("rename failed");
}

int xutils_cmd_rm(const char *args, int directories_only) {
  u64 cursor = 0U;
  char token[PATH_MAX];
  int recursive = 0;
  int force = 0;
  int count = 0;
  while (xutils_next_token(args, &cursor, token, sizeof(token)) == 0) {
    if (!directories_only && token[0] == '-') {
      for (u64 i = 1U; token[i] != '\0'; ++i) {
        if (token[i] == 'r' || token[i] == 'R') recursive = 1;
        else if (token[i] == 'f') force = 1;
        else return xutils_fail("unsupported option");
      }
      continue;
    }
    char path[PATH_MAX];
    xaios_xbfs_stat_user_t stat;
    if (xutils_resolve_path(token, path) != 0 || xutils_equal(path, "/")) return xutils_fail("invalid path");
    if (xaios_fs_stat(path, &stat) != 0) {
      if (!force) return xutils_fail("not found");
    } else if ((directories_only && stat.type != XAIOS_FS_TYPE_DIRECTORY) ||
               (stat.type == XAIOS_FS_TYPE_DIRECTORY && !recursive && !directories_only)) {
      return xutils_fail("is a directory");
    } else if ((recursive ? remove_tree(path) : xaios_fs_delete(path)) != 0) {
      return xutils_fail(directories_only ? "directory not empty" : "remove failed");
    }
    ++count;
  }
  return count ? 0 : xutils_fail("missing operand");
}

int xutils_cmd_stat(const char *args) {
  u64 cursor = 0U;
  char token[PATH_MAX];
  if (xutils_next_token(args, &cursor, token, sizeof(token)) != 0)
    return xutils_fail("missing operand");
  do {
    char path[PATH_MAX];
    xaios_xbfs_stat_user_t stat;
    if (xutils_resolve_path(token, path) != 0 || xaios_fs_stat(path, &stat) != 0)
      return xutils_fail("not found");
    (void)xutils_append("File: "); (void)xutils_append(path);
    (void)xutils_append("\nType: ");
    (void)xutils_append(stat.type == XAIOS_FS_TYPE_DIRECTORY ? "directory" : "file");
    (void)xutils_append("\nSize: "); (void)xutils_append_u64(stat.size);
    (void)xutils_append("\nBlocks: "); (void)xutils_append_u64(stat.block_count);
    (void)xutils_append("\nGeneration: "); (void)xutils_append_u64(stat.generation);
    (void)xutils_append("\nHash: "); (void)xutils_append_u64(stat.content_hash);
    (void)xutils_append("\n");
  } while (xutils_next_token(args, &cursor, token, sizeof(token)) == 0);
  return 0;
}
