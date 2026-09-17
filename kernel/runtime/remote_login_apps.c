/*
 * The remote application table and its launcher, split out of remote_login.c.
 * This code came from the shipped-configuration arm of that file, so the whole
 * translation unit carries the same guard: it is compiled when
 * XAIOS_BOOT_TEST_APPS is off, which is the image that ships. remote_login.c
 * looks a command up with remote_login_app_find and launches it with
 * remote_login_app_run (or remote_login_app_run_file, for an app-store image).
 */

#include <xaios/initramfs.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/klog_ring.h>
#include <xaios/security.h>
#include <xaios/status.h>
#include <xaios/types.h>
#include <xaios/user.h>
#include <xaios/xaiboot_fs.h>

#include "remote_login_internal.h"

#ifndef XAIOS_FAILURE_TEST_APP
#define XAIOS_FAILURE_TEST_APP 0
#endif

#if !XAIOS_BOOT_TEST_APPS

#define REMOTE_APP(command_, path_, capabilities_)                            \
  {command_, path_, capabilities_, 0U, 0U, 1U}
#define REMOTE_TERMINAL_APP(command_, path_, capabilities_)                   \
  {command_, path_, capabilities_, 1U, 0U, 1U}
#define REMOTE_UTILITY_APP(command_, capabilities_)                           \
  {command_, "/bin/" command_, capabilities_, 1U, 1U, 0U}

static const remote_login_app_definition_t g_remote_apps[] = {
    REMOTE_APP("hello", "/bin/hello", XAIOS_CAP_LOG | XAIOS_CAP_EXIT),
    REMOTE_APP("helloworldc99", "/bin/helloworldc99",
               XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT),
    /* XAIOS_CAP_NET is what authorizes net_resolve. Without it xapt can open
       sockets but cannot turn a name into an address, so a configured host
       works only as a literal and every hostname fails identically whether or
       not it is DNSSEC-signed. */
    REMOTE_APP("xapt", "/bin/xapt",
     XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT | XAIOS_CAP_TIME |
         XAIOS_CAP_FS_READ | XAIOS_CAP_FS_WRITE |
         XAIOS_CAP_NET | XAIOS_CAP_NET_SOCKET |
         XAIOS_CAP_RANDOM |
         XAIOS_CAP_CONTROL_QUERY | XAIOS_CAP_CONTROL_ADMIN |
         XAIOS_CAP_UPDATE | XAIOS_CAP_ADMIN),
    REMOTE_TERMINAL_APP("nano", "/bin/nano",
     XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT | XAIOS_CAP_FS_READ |
         XAIOS_CAP_FS_WRITE | XAIOS_CAP_REMOTE_LOGIN),
    REMOTE_TERMINAL_APP("xtop", "/bin/xtop",
                        XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                            XAIOS_CAP_CONTROL_QUERY),
    REMOTE_TERMINAL_APP("pong", "/bin/pong",
                        XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT),
    /* Operator control surface. Arguments are forwarded verbatim to the
       control protocol, which authorizes them under the observer role. */
    {"xaiosctl", "/bin/xaiosctl",
     XAIOS_CAP_CONSOLE | XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_TIME |
         XAIOS_CAP_CONTROL_QUERY | XAIOS_CAP_STORAGE_READ,
     1U, 0U, 0U},
    REMOTE_APP("sysinfo", "/bin/sysinfo",
               XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_TIME),
    REMOTE_APP("systest", "/bin/systest",
     XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_FS_READ |
         XAIOS_CAP_FS_WRITE),
    REMOTE_APP("smptest", "/bin/smptest",
     XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_OSCTL | XAIOS_CAP_SMP |
         XAIOS_CAP_THREADS),
    REMOTE_APP("nettest", "/bin/nettest",
     XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_OSCTL | XAIOS_CAP_NET |
         XAIOS_CAP_TIME),
    REMOTE_APP("sshtest", "/bin/sshtest",
               XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_REMOTE_LOGIN),
    REMOTE_APP("lstm-xor", "/bin/lstm-xor",
               XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_CPU_AI |
                   XAIOS_CAP_ML),
    REMOTE_APP("mltest", "/bin/mltest",
               XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_CPU_AI |
                   XAIOS_CAP_ML),
    REMOTE_APP("posix-shell", "/bin/posix-shell",
               XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_REMOTE_LOGIN),
    REMOTE_APP("agenttest", "/bin/agenttest",
     XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_AGENT | XAIOS_CAP_CPU_AI |
         XAIOS_CAP_ML),
    REMOTE_UTILITY_APP("ls", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                XAIOS_CAP_FS_READ),
    REMOTE_UTILITY_APP("mkdir", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                   XAIOS_CAP_FS_READ | XAIOS_CAP_FS_WRITE),
    REMOTE_UTILITY_APP("touch", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                   XAIOS_CAP_FS_READ | XAIOS_CAP_FS_WRITE),
    REMOTE_UTILITY_APP("cp", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                XAIOS_CAP_FS_READ | XAIOS_CAP_FS_WRITE),
    REMOTE_UTILITY_APP("mv", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                XAIOS_CAP_FS_READ | XAIOS_CAP_FS_WRITE),
    REMOTE_UTILITY_APP("rm", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                XAIOS_CAP_FS_READ | XAIOS_CAP_FS_WRITE),
    REMOTE_UTILITY_APP("rmdir", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                   XAIOS_CAP_FS_READ | XAIOS_CAP_FS_WRITE),
    REMOTE_UTILITY_APP("stat", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                  XAIOS_CAP_FS_READ),
    REMOTE_UTILITY_APP("cat", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                 XAIOS_CAP_FS_READ),
    REMOTE_UTILITY_APP("head", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                  XAIOS_CAP_FS_READ),
    REMOTE_UTILITY_APP("tail", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                  XAIOS_CAP_FS_READ),
    REMOTE_UTILITY_APP("less", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                  XAIOS_CAP_FS_READ),
    REMOTE_UTILITY_APP("grep", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                  XAIOS_CAP_FS_READ),
    REMOTE_UTILITY_APP("find", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                  XAIOS_CAP_FS_READ),
    REMOTE_UTILITY_APP("sed", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                 XAIOS_CAP_FS_READ | XAIOS_CAP_FS_WRITE),
    REMOTE_UTILITY_APP("write", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                   XAIOS_CAP_FS_READ | XAIOS_CAP_FS_WRITE),
    REMOTE_UTILITY_APP("tar", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                 XAIOS_CAP_FS_READ | XAIOS_CAP_FS_WRITE),
    REMOTE_UTILITY_APP("cpio", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                  XAIOS_CAP_FS_READ | XAIOS_CAP_FS_WRITE),
    REMOTE_UTILITY_APP("zip", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                 XAIOS_CAP_FS_READ | XAIOS_CAP_FS_WRITE),
    REMOTE_UTILITY_APP("unzip", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                   XAIOS_CAP_FS_READ | XAIOS_CAP_FS_WRITE),
    REMOTE_UTILITY_APP("ps", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                XAIOS_CAP_CONTROL_QUERY),
    REMOTE_UTILITY_APP("df", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                XAIOS_CAP_CONTROL_QUERY |
                                XAIOS_CAP_STORAGE_READ),
    REMOTE_UTILITY_APP("du", XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT |
                                XAIOS_CAP_FS_READ),
#if XAIOS_FAILURE_TEST_APP
    REMOTE_APP("app-fail", "/bin/app-fail", XAIOS_CAP_LOG | XAIOS_CAP_EXIT),
    REMOTE_APP("app-crash", "/bin/app-crash",
               XAIOS_CAP_LOG | XAIOS_CAP_EXIT),
#endif
};

const remote_login_app_definition_t *remote_login_app_find(const char *command) {
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

/* The most console output one application run hands back. */
#define REMOTE_APP_CONSOLE_CAPTURE_MAX UINT64_C(65536)

xaios_status_t remote_login_app_run_file(
    const remote_login_app_definition_t *app, const xaios_initramfs_file_t *file,
    const char *args, char *output,
    uint64_t output_capacity, uint64_t *output_bytes) {
  const char *argv[XAIOS_USER_ARG_MAX];
  char argument_storage[XAIOS_USER_ARG_MAX - 1U][XAIOS_XBFS_PATH_MAX];
  uint32_t argc = 1U;
  uint64_t argument_cursor = 0U;
  uint64_t argument_bytes = 0U;
  char *log;
  char *console;
  uint64_t cursor;
  uint64_t start_cursor = 0U;
  uint64_t next_cursor = 0U;
  uint64_t latest_cursor = 0U;
  uint32_t log_bytes;
  uint64_t console_bytes;
  uint64_t console_capacity;
  int exit_code = 0;
  xaios_status_t status;

  if (app == 0 || file == 0 || args == 0 || file->executable == 0U) {
    return command_fail(output, output_capacity, output_bytes,
                        "application: executable unavailable");
  }
  argv[0] = app->command;
  if (app->pass_cwd != 0U) argv[argc++] = remote_login_cwd();
  if (app->raw_arguments != 0U && args[0] != '\0') {
    if (cstr_len(args) + 1U > XAIOS_USER_ARG_BYTES_MAX) {
      return command_fail(output, output_capacity, output_bytes,
                          "application: argument data exceeds limit");
    }
    argv[argc++] = args;
  } else {
    while (has_more_args(args, argument_cursor) != 0) {
      uint64_t before = argument_cursor;
      if (argc >= XAIOS_USER_ARG_MAX ||
          token_next(args, &argument_cursor, argument_storage[argc - 1U],
                     sizeof(argument_storage[0])) != XAIOS_OK) {
        return command_fail(output, output_capacity, output_bytes,
                            "application: too many or oversized arguments");
      }
      argument_bytes += argument_cursor - before;
      if (argument_bytes > XAIOS_USER_ARG_BYTES_MAX) {
        return command_fail(output, output_capacity, output_bytes,
                            "application: argument data exceeds limit");
      }
      argv[argc] = argument_storage[argc - 1U];
      ++argc;
    }
  }

  log = (char *)kheap_alloc(XAIOS_KLOG_FLUSH_MAX, 16U);
  if (log == 0) {
    return command_fail(output, output_capacity, output_bytes,
                        "application: output buffer unavailable");
  }
  /* Capture as much as the caller can take back, rather than a fixed eight
     kilobytes: a screen-sized frame from a terminal application is larger
     than that, and a capture that stops early hands back a torn frame. The
     ceiling keeps one command from asking for the whole heap. */
  console_capacity = output_capacity;
  if (console_capacity > REMOTE_APP_CONSOLE_CAPTURE_MAX) {
    console_capacity = REMOTE_APP_CONSOLE_CAPTURE_MAX;
  }
  if (console_capacity < XAIOS_KLOG_FLUSH_MAX) {
    console_capacity = XAIOS_KLOG_FLUSH_MAX;
  }
  console = (char *)kheap_alloc(console_capacity, 16U);
  if (console == 0) {
    kheap_free(log);
    return command_fail(output, output_capacity, output_bytes,
                        "application: output buffer unavailable");
  }
  cursor = klog_ring_total_written();
  if (klog_console_capture_begin(console, console_capacity) == 0) {
    kheap_free(console);
    kheap_free(log);
    return command_fail(output, output_capacity, output_bytes,
                        "application: output capture unavailable");
  }
  status = user_process_run_transient_args(file, app->capabilities, argc, argv,
                                           &exit_code);
  console_bytes = klog_console_capture_end();
  log_bytes = klog_ring_snapshot(log, XAIOS_KLOG_FLUSH_MAX, cursor,
                                 &start_cursor, &next_cursor, &latest_cursor);
  if (status == XAIOS_OK) {
    for (uint64_t i = 0U; i < console_bytes; ++i) {
      (void)output_append_char(output, output_capacity, output_bytes, console[i]);
    }
    append_app_log_lines(output, output_capacity, output_bytes, log, log_bytes,
                         app->path);
  }
  kheap_free(console);
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
  if (app->report_completion != 0U) {
    output_append(output, output_capacity, output_bytes, app->command);
    output_append(output, output_capacity, output_bytes, ": complete\n");
  }
  return XAIOS_OK;
}

xaios_status_t remote_login_app_run(
    const remote_login_app_definition_t *app, const char *args, char *output,
    uint64_t output_capacity, uint64_t *output_bytes) {
  const xaios_initramfs_file_t *file = 0;
  if (app == 0 || initramfs_lookup(app->path, &file) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "application: executable unavailable");
  }
  return remote_login_app_run_file(app, file, args, output, output_capacity,
                                output_bytes);
}

#endif /* !XAIOS_BOOT_TEST_APPS */
