/*
 * Navigation and listing for the remote-login shell: the path resolver every
 * command shares, plus ls and find with the directory helpers only they use.
 *
 * Split out of remote_login.c, which keeps the command dispatch and the
 * session state these entry points read through remote_login_cwd().
 * remote_path_resolve is compiled in every configuration -- the shipped shell
 * resolves paths too -- so it sits outside the boot-test guard that the ls and
 * find commands were, and still are, compiled under.
 */

#include "remote_login_internal.h"

#include <xaios/initramfs.h>
#include <xaios/klog.h>
#include <xaios/status.h>
#include <xaios/types.h>
#include <xaios/xaiboot_fs.h>

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

xaios_status_t remote_path_resolve(const char *cwd, const char *path,
                                   char *resolved,
                                   uint64_t resolved_capacity) {
  char source[XAIOS_XBFS_PATH_MAX];
  uint64_t source_len = 0;
  uint64_t idx = 0;
  uint64_t resolved_len = 1;
  if (cwd == 0 || path == 0 || resolved == 0 ||
      resolved_capacity < 2U) {
    return XAIOS_ERR_INVALID;
  }

  if (path[0] == '/') {
    if (cstr_len(path) >= XAIOS_XBFS_PATH_MAX) {
      return XAIOS_ERR_NO_MEMORY;
    }
    if (copy_cstr(source, sizeof(source), path) != XAIOS_OK) {
      return XAIOS_ERR_INVALID;
    }
    source_len = cstr_len(path);
  } else {
    uint64_t cwd_len = cstr_len(cwd);
    if (cwd_len == 0U || cstr_len(cwd) >= XAIOS_XBFS_PATH_MAX) {
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
    if (source_len + cstr_len(path) >= XAIOS_XBFS_PATH_MAX) {
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

#if XAIOS_BOOT_TEST_APPS

static int is_hidden_name(const char *name) {
  return name != 0 && name[0] == '.';
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

xaios_status_t handle_ls(const char *args, char *output,
                               uint64_t output_capacity,
                               uint64_t *output_bytes) {
  uint64_t arg_index = 0;
  char token[32];
  char explicit_path[XAIOS_XBFS_PATH_MAX];
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

  char target[XAIOS_XBFS_PATH_MAX];
  if (explicit_path[0] == '\0') {
    if (copy_cstr(target, sizeof(target), remote_login_cwd()) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "ls: invalid path");
    }
  } else if (copy_cstr(target, sizeof(target), explicit_path) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "ls: invalid path");
  }

  char resolved[XAIOS_XBFS_PATH_MAX];
  char listing[XAIOS_REMOTE_LOGIN_LIST_BYTES];
  uint64_t listing_size = 0;
  if (remote_path_resolve(remote_login_cwd(), target, resolved,
                         sizeof(resolved)) != XAIOS_OK) {
    remote_login_log_failure("ls", "invalid-path", XAIOS_ERR_INVALID);
    return command_fail(output, output_capacity, output_bytes, "ls: invalid path");
  }
  xaios_xbfs_stat_t target_stat;
  if (xaiboot_fs_stat(resolved, &target_stat) == XAIOS_OK &&
      target_stat.type == 2U) {
    return append_ls_entry(output, output_capacity, output_bytes,
                           explicit_path[0] == '\0' ? resolved : explicit_path,
                           target_stat.size, target_stat.type, long_form);
  }
  {
    const xaios_initramfs_file_t *image_file = 0;
    if (initramfs_lookup(resolved, &image_file) == XAIOS_OK &&
        initramfs_directory_exists(resolved) == 0) {
      return append_ls_entry(output, output_capacity, output_bytes,
                             explicit_path[0] == '\0' ? resolved
                                                       : explicit_path,
                             image_file->size, 2U, long_form);
    }
  }
  int image_directory = initramfs_directory_exists(resolved);
  xaios_status_t list_status = xaiboot_fs_list(resolved, listing,
                                              sizeof(listing),
                                              &listing_size);
  if (image_directory != 0 && list_status != XAIOS_OK) {
    list_status = XAIOS_OK;
    listing_size = 0U;
  }
  if ((list_status != XAIOS_OK &&
       (list_status != XAIOS_ERR_NO_MEMORY || listing_size == 0U)) ||
      listing_size > sizeof(listing)) {
    klog(
        "remote-login: ls path=%s list_status=%d listing_size=%lu capacity=%lu\n",
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
    if (name_len + 1U >= XAIOS_XBFS_PATH_MAX) {
      return command_fail(output, output_capacity, output_bytes,
                          "ls: path too long");
    }
    char name[XAIOS_XBFS_PATH_MAX];
    if (copy_cstr_range(name, sizeof(name), listing + line_start, name_len) !=
        XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes, "ls: not found");
    }
    if (!show_all && is_hidden_name(name) != 0) {
      line_start = line_end + 1U;
      continue;
    }
    char child[XAIOS_XBFS_PATH_MAX];
    if (path_join(child, sizeof(child), resolved, name) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes, "ls: not found");
    }
    xaios_xbfs_stat_t child_stat;
    if (xaiboot_fs_stat(child, &child_stat) != XAIOS_OK) {
      line_start = line_end + 1U;
      continue;
    }
    if (append_ls_entry(output, output_capacity, output_bytes, name,
                        child_stat.size, child_stat.type, long_form) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes, "ls: output too large");
    }
    line_start = line_end + 1U;
  }
  /* Merge the boot image's view of this directory. xaibootFS took its turn
     above, so anything it can stat is already listed and is skipped here;
     synthetic subdirectories are deduplicated against earlier image files. */
  for (uint32_t i = 0U; i < initramfs_file_count(); ++i) {
    char name[XAIOS_XBFS_PATH_MAX];
    int is_directory = 0;
    if (initramfs_child_at(resolved, i, name, sizeof(name), &is_directory) == 0)
      continue;
    if (!show_all && is_hidden_name(name) != 0) continue;
    char child[XAIOS_XBFS_PATH_MAX];
    xaios_xbfs_stat_t child_stat;
    if (path_join(child, sizeof(child), resolved, name) != XAIOS_OK) continue;
    if (xaiboot_fs_stat(child, &child_stat) == XAIOS_OK) continue;
    if (is_directory != 0) {
      uint32_t seen = 0U;
      for (uint32_t j = 0U; j < i && seen == 0U; ++j) {
        char earlier[XAIOS_XBFS_PATH_MAX];
        int earlier_dir = 0;
        if (initramfs_child_at(resolved, j, earlier, sizeof(earlier),
                               &earlier_dir) != 0 &&
            earlier_dir != 0 && string_equal(earlier, name) == 1U)
          seen = 1U;
      }
      if (seen != 0U) continue;
    }
    const xaios_initramfs_file_t *file = initramfs_file_at(i);
    if (append_ls_entry(output, output_capacity, output_bytes, name,
                        is_directory != 0 ? 0U : file->size,
                        is_directory != 0 ? 1U : 2U, long_form) != XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "ls: output too large");
    }
  }
  return XAIOS_OK;
}

static xaios_status_t handle_find_recursive(const char *path, const char *pattern,
                                          char *output,
                                          uint64_t output_capacity,
                                          uint64_t *output_bytes,
                                          int print_entry_path) {
  xaios_xbfs_stat_t start_stat;
  char listing[XAIOS_REMOTE_LOGIN_LIST_BYTES];
  uint64_t listing_size = 0;
  if (xaiboot_fs_stat(path, &start_stat) != XAIOS_OK || start_stat.type != 1U) {
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
  if (xaiboot_fs_list(path, listing, sizeof(listing), &listing_size) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t line_start = 0;
  while (line_start < listing_size) {
    uint64_t line_end = line_start;
    while (line_end < listing_size && listing[line_end] != '\n') {
      ++line_end;
    }
    char name[XAIOS_XBFS_PATH_MAX];
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
    char child[XAIOS_XBFS_PATH_MAX];
    if (path_join(child, sizeof(child), path, name) != XAIOS_OK) {
      return XAIOS_ERR_NO_MEMORY;
    }
    xaios_xbfs_stat_t child_stat;
    if (xaiboot_fs_stat(child, &child_stat) != XAIOS_OK) {
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

xaios_status_t handle_find_cmd(const char *args, char *output,
                                    uint64_t output_capacity,
                                    uint64_t *output_bytes) {
  uint64_t arg_index = 0;
  char path_arg[XAIOS_XBFS_PATH_MAX];
  char resolved[XAIOS_XBFS_PATH_MAX];
  char token[XAIOS_XBFS_PATH_MAX];
  char pattern[XAIOS_XBFS_PATH_MAX];
  char explicit_path[XAIOS_XBFS_PATH_MAX];
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

  if (remote_path_resolve(remote_login_cwd(), explicit_path, resolved,
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

#endif /* XAIOS_BOOT_TEST_APPS */
