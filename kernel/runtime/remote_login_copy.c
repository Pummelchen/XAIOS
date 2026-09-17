/*
 * The file-copy command group -- cp, mv, rm and rmdir -- split out of
 * remote_login.c. Every handler here came from a boot-test-only arm of that
 * file, so the whole translation unit carries the same guard: in the shipped
 * configuration none of this is compiled.
 */

#include <xaios/status.h>
#include <xaios/types.h>
#include <xaios/xaiboot_fs.h>

#include "remote_login_archive_internal.h"
#include "remote_login_internal.h"

#if XAIOS_BOOT_TEST_APPS

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

xaios_status_t remote_login_copy_cp(const char *args, char *output,
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
  if (remote_path_resolve(remote_login_cwd(), operands[operand_count - 1U],
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
    if (remote_path_resolve(remote_login_cwd(), operands[operand], source,
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

static xaios_status_t move_path(const char *src, const char *dst) {
  char resolved_src[XAIOS_XBFS_PATH_MAX];
  char resolved_dst[XAIOS_XBFS_PATH_MAX];
  if (src == 0 || dst == 0 || src[0] == '\0' || dst[0] == '\0')
    return XAIOS_ERR_INVALID;
  if (remote_path_resolve(remote_login_cwd(), src, resolved_src,
                         sizeof(resolved_src)) != XAIOS_OK ||
      remote_path_resolve(remote_login_cwd(), dst, resolved_dst,
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

xaios_status_t remote_login_copy_mv(const char *args, char *output,
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
    if (remote_path_resolve(remote_login_cwd(), operands[count - 1U],
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
      remote_path_resolve(remote_login_cwd(), arg, resolved, sizeof(resolved)) !=
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

xaios_status_t remote_login_copy_rm(const char *args, char *output,
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

xaios_status_t remote_login_copy_rmdir(const char *args, char *output,
                                  uint64_t output_capacity,
                                  uint64_t *output_bytes) {
  uint64_t index = 0U;
  uint32_t paths = 0U;
  char token[XAIOS_XBFS_PATH_MAX];
  while (token_next(args, &index, token, sizeof(token)) == XAIOS_OK) {
    char resolved[XAIOS_XBFS_PATH_MAX];
    xaios_xbfs_stat_t stat;
    if (token[0] == '-' ||
        remote_path_resolve(remote_login_cwd(), token, resolved,
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

#endif /* XAIOS_BOOT_TEST_APPS */
