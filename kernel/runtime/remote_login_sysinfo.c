/*
 * Process and filesystem reporting for the remote-login shell: ps, df and du.
 *
 * Split out of remote_login.c, which keeps the command dispatch and the
 * session state these entry points read through remote_login_cwd(). The
 * helpers only these commands use -- the process-state names, the human
 * size formatter and du's recursive walk -- moved with them; nothing else in
 * remote_login.c named them.
 *
 * The body is compiled only when XAIOS_BOOT_TEST_APPS is on, exactly as it
 * was inside remote_login.c: in the shipped configuration none of these
 * commands is registered and none of this exists.
 */

#include "remote_login_internal.h"

#include <xaios/status.h>
#include <xaios/timer.h>
#include <xaios/types.h>
#include <xaios/user.h>
#include <xaios/vfs.h>
#include <xaios/xaiboot_fs.h>

#if XAIOS_BOOT_TEST_APPS

static const char *xtop_state_name(xaios_user_process_state_t state) {
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

static int xtop_state_active(xaios_user_process_state_t state) {
  return state == XAIOS_USER_PROCESS_LOADED ||
         state == XAIOS_USER_PROCESS_RUNNABLE ||
         state == XAIOS_USER_PROCESS_RUNNING ||
         state == XAIOS_USER_PROCESS_WAITING;
}

xaios_status_t handle_ps(const char *args, char *output,
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
        (show_all == 0 && xtop_state_active(process.state) == 0)) {
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
                  xtop_state_name(process.state));
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

xaios_status_t handle_df(const char *args, char *output,
                          uint64_t output_capacity,
                          uint64_t *output_bytes) {
  uint64_t index = 0U;
  uint64_t block_size = 512U;
  int human = 0;
  uint32_t paths = 0U;
  char path[XAIOS_XBFS_PATH_MAX];
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
    char resolved[XAIOS_XBFS_PATH_MAX];
    xaios_vfs_statfs_t statfs;
    if (remote_path_resolve(remote_login_cwd(), path, resolved,
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
  xaios_xbfs_stat_t stat;
  if (xaiboot_fs_stat(path, &stat) != XAIOS_OK) return XAIOS_ERR_NOT_FOUND;
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
  char listing[XAIOS_XBFS_MAX_LIST_BYTES];
  uint64_t listing_size = 0U;
  uint64_t total = 0U;
  if (xaiboot_fs_list(path, listing, sizeof(listing), &listing_size) != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  uint64_t line_start = 0U;
  while (line_start < listing_size) {
    uint64_t line_end = line_start;
    while (line_end < listing_size && listing[line_end] != '\n') ++line_end;
    if (line_end > line_start) {
      char name[XAIOS_XBFS_PATH_MAX];
      char child[XAIOS_XBFS_PATH_MAX];
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

xaios_status_t handle_du(const char *args, char *output,
                          uint64_t output_capacity,
                          uint64_t *output_bytes) {
  uint64_t index = 0U;
  uint32_t paths = 0U;
  int print_files = 0;
  int summary = 0;
  int human = 0;
  char token[XAIOS_XBFS_PATH_MAX];
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
    char resolved[XAIOS_XBFS_PATH_MAX];
    uint64_t total = 0U;
    if (remote_path_resolve(remote_login_cwd(), token, resolved,
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
    if (du_path(remote_login_cwd(), print_files, summary, human, output,
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
      output_append(output, output_capacity, output_bytes, remote_login_cwd());
      output_append(output, output_capacity, output_bytes, "\n");
    }
  }
  return XAIOS_OK;
}

#endif /* XAIOS_BOOT_TEST_APPS */
