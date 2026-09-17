/*
 * The remote-login shell's stat, mkdir, touch and write handlers.
 *
 * Split out of remote_login.c's boot-test arm. The dispatcher
 * (remote_login_exec) stays in remote_login.c because the shell help catalog
 * tests/repository/check-user-docs.py reads lives in its body; these handlers
 * move out and are named across the translation-unit boundary. They keep the
 * XAIOS_BOOT_TEST_APPS guard they were written under, so a guard-off build
 * compiles exactly what it did. mkdir_resolved, which the archive modules
 * already called across a boundary, moves with the mkdir handler that uses it
 * and stays public in every configuration that compiles it.
 *
 * The session cwd is read through remote_login_cwd() rather than the variable,
 * which stays private to remote_login.c.
 */

#include "remote_login_internal.h"
#include "remote_login_meta_internal.h"

#include <xaios/status.h>
#include <xaios/types.h>
#include <xaios/xaiboot_fs.h>

#if XAIOS_BOOT_TEST_APPS

xaios_status_t handle_stat(const char *arg, char *output,
                                uint64_t output_capacity,
                                uint64_t *output_bytes) {
  char resolved[XAIOS_XBFS_PATH_MAX];
  xaios_xbfs_stat_t stat;
  if (arg == 0 || arg[0] == '\0') {
    return command_fail(output, output_capacity, output_bytes, "stat: missing path");
  }
  if (remote_path_resolve(remote_login_cwd(), arg, resolved, sizeof(resolved)) !=
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

xaios_status_t handle_mkdir(const char *args, char *output,
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
    if (remote_path_resolve(remote_login_cwd(), token, resolved,
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

xaios_status_t handle_touch(const char *arg, char *output,
                                 uint64_t output_capacity, uint64_t *output_bytes) {
  char resolved[XAIOS_XBFS_PATH_MAX];
  int64_t fd = -1;
  if (arg == 0 || arg[0] == '\0') {
    return command_fail(output, output_capacity, output_bytes,
                       "touch: missing path");
  }
  if (remote_path_resolve(remote_login_cwd(), arg, resolved, sizeof(resolved)) !=
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

xaios_status_t handle_write(const char *path_arg, const char *payload,
                                 char *output, uint64_t output_capacity,
                                 uint64_t *output_bytes) {
  char resolved[XAIOS_XBFS_PATH_MAX];
  uint64_t payload_len = payload == 0 ? 0U : cstr_len(payload);
  int64_t fd = -1;

  if (path_arg == 0 || path_arg[0] == '\0') {
    return command_fail(output, output_capacity, output_bytes,
                        "write: missing path");
  }
  if (remote_path_resolve(remote_login_cwd(), path_arg, resolved,
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

#endif /* XAIOS_BOOT_TEST_APPS */
