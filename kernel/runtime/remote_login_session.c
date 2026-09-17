/*
 * Remote-login session state: the per-session context table and the working
 * directory a command runs in, the cached local account name, the execute
 * entry points and the boot self-test.
 *
 * Split out of remote_login.c, which keeps the command dispatcher
 * (remote_login_exec) because the shell help catalog that
 * tests/repository/check-user-docs.py extracts lives in its body. The session
 * table and the cwd pointer moved together because remote_login_execute_session
 * swaps the process-wide cwd for the duration of one command -- the table and
 * the pointer cannot live apart. remote_ensure_parent came along as the
 * shell's other path helper and keeps its unguarded linkage: the redirect and
 * pipe driver calls it in every configuration.
 *
 * remote_login_handle_pwd and remote_login_handle_cd were `static` here; the
 * dispatcher that calls them is now in another translation unit, so they lose
 * `static` and are declared in remote_login_session_internal.h. path_join
 * stays boot-test-only and keeps that guard.
 */

#include "remote_login_internal.h"
#include "remote_login_session_internal.h"

#include <xaios/assert.h>
#include <xaios/initramfs.h>
#include <xaios/klog.h>
#include <xaios/operations.h>
#include <xaios/remote_login.h>
#include <xaios/security.h>
#include <xaios/status.h>
#include <xaios/types.h>
#include <xaios/xaiboot_fs.h>

static uint64_t g_remote_login_sessions;
static uint64_t g_remote_login_commands;
static uint64_t g_remote_login_denials;
#define XAIOS_REMOTE_LOGIN_MAX_SESSIONS 64U
typedef struct remote_login_context {
  uint64_t session_id;
  char cwd[XAIOS_XBFS_PATH_MAX];
  uint32_t active;
  /* When this context was last named, on a counter that only goes up. It
     exists so a full table can give up its oldest entry instead of refusing
     everything -- see remote_login_context_get. */
  uint64_t last_used;
} remote_login_context_t;
static uint64_t g_remote_login_context_clock;
static uint64_t g_remote_login_context_evictions;
static remote_login_context_t
    g_remote_login_contexts[XAIOS_REMOTE_LOGIN_MAX_SESSIONS];
static char g_remote_login_default_cwd[XAIOS_XBFS_PATH_MAX] = "/";
static char *g_remote_login_cwd = g_remote_login_default_cwd;

const char *remote_login_cwd(void) { return g_remote_login_cwd; }

xaios_status_t remote_ensure_parent(const char *path) {
  uint64_t len = cstr_len(path);
  if (len == 0U) {
    return XAIOS_ERR_INVALID;
  }
  if (len == 1U && path[0] == '/') {
    return XAIOS_OK;
  }
  if (path[len - 1U] == '/') {
    return XAIOS_ERR_INVALID;
  }
  uint64_t parent_len = len - 1U;
  while (parent_len > 0U && path[parent_len] != '/') {
    --parent_len;
  }
  char parent[XAIOS_XBFS_PATH_MAX];
  xaios_xbfs_stat_t parent_stat;
  if (parent_len == 0U) {
    if (copy_cstr(parent, sizeof(parent), "/") != XAIOS_OK) {
      return XAIOS_ERR_INVALID;
    }
  } else if (parent_len == 1U) {
    if (copy_cstr(parent, sizeof(parent), "/") != XAIOS_OK) {
      return XAIOS_ERR_INVALID;
    }
  } else {
    if (copy_cstr_range(parent, sizeof(parent), path, parent_len) != XAIOS_OK) {
      return XAIOS_ERR_INVALID;
    }
  }
  return xaiboot_fs_stat(parent, &parent_stat) == XAIOS_OK &&
                     parent_stat.type == 1U
             ? XAIOS_OK
             : XAIOS_ERR_INVALID;
}

xaios_status_t remote_login_handle_pwd(char *output, uint64_t output_capacity,
                               uint64_t *output_bytes) {
  output_append(output, output_capacity, output_bytes, g_remote_login_cwd);
  output_append(output, output_capacity, output_bytes, "\n");
  return XAIOS_OK;
}

xaios_status_t remote_login_handle_cd(const char *arg, char *output,
                              uint64_t output_capacity,
                              uint64_t *output_bytes) {
  const char *target = (arg == 0 || arg[0] == '\0') ? "/" : arg;
  char resolved[XAIOS_XBFS_PATH_MAX];
  xaios_xbfs_stat_t stat;
  if (remote_path_resolve(g_remote_login_cwd, target, resolved,
                         sizeof(resolved)) != XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes, "cd: invalid path");
  }
  if (string_equal(resolved, "/") == 1U) {
    if (copy_cstr(g_remote_login_cwd, XAIOS_XBFS_PATH_MAX, resolved) !=
        XAIOS_OK) {
      return command_fail(output, output_capacity, output_bytes,
                          "cd: path too long");
    }
    output_append(output, output_capacity, output_bytes, resolved);
    output_append(output, output_capacity, output_bytes, "\n");
    return XAIOS_OK;
  }
  if ((xaiboot_fs_stat(resolved, &stat) != XAIOS_OK || stat.type != 1U) &&
      initramfs_directory_exists(resolved) == 0) {
    return command_fail(output, output_capacity, output_bytes,
                        "cd: not a directory");
  }
  if (copy_cstr(g_remote_login_cwd, XAIOS_XBFS_PATH_MAX, resolved) !=
      XAIOS_OK) {
    return command_fail(output, output_capacity, output_bytes,
                        "cd: path too long");
  }
  output_append(output, output_capacity, output_bytes, resolved);
  output_append(output, output_capacity, output_bytes, "\n");
  return XAIOS_OK;
}

/* The name of the account this machine has.

   This used to be the literal "admin", which was true of every image because
   every image packaged the same credential. A machine that makes its own
   account during setup can be called something else, and refusing that name
   would let a person log in at the console and then have every command they
   typed denied.

   Read from the account file sshd authenticates against, so the two cannot
   disagree about who exists, and cached after the first read: it changes only
   when a machine is set up, which happens before anything dispatches a
   command. Falls back to "admin", the account every packaged image has. */
#define REMOTE_LOGIN_ACCOUNT_MAX 64U

static char g_local_account[REMOTE_LOGIN_ACCOUNT_MAX];
static uint32_t g_local_account_loaded;

static int local_account_is(const char *user) {
  if (g_local_account_loaded == 0U) {
    char record[256];
    uint64_t read_bytes = 0U;
    uint64_t used = 0U;
    if (xaiboot_fs_read("/etc/xaios_sshd_users", record, sizeof(record) - 1U,
                        &read_bytes) == XAIOS_OK && read_bytes != 0U) {
      record[read_bytes] = '\0';
      /* Comment lines are not the account. Take the first record's name,
         which is the text before its first colon. */
      uint64_t start = 0U;
      while (start < read_bytes) {
        uint64_t end = start;
        while (end < read_bytes && record[end] != '\n') ++end;
        if (record[start] != '#' && end > start) {
          for (uint64_t i = start; i < end; ++i) {
            if (record[i] == ':') break;
            if (used + 1U >= sizeof(g_local_account)) { used = 0U; break; }
            g_local_account[used++] = record[i];
          }
          if (used != 0U) break;
        }
        start = end + 1U;
      }
    }
    if (used == 0U) {
      static const char fallback[] = "admin";
      for (used = 0U; used < sizeof(fallback) - 1U; ++used) {
        g_local_account[used] = fallback[used];
      }
    }
    g_local_account[used] = '\0';
    g_local_account_loaded = 1U;
  }
  return string_equal(user, g_local_account);
}

/* Forget the cached name.

   The cache is filled by the first command dispatched, and boot self-tests
   dispatch several before setup has run -- so without this the machine
   remembers "admin" from its own self-test and then denies every command the
   person who just set it up types. Called when an account is installed. */
void remote_login_forget_account(void) { g_local_account_loaded = 0U; }

xaios_status_t remote_login_execute(const char *user, const char *command,
                                  char *output, uint64_t output_capacity,
                                  uint64_t *output_bytes) {
  if (user == 0 || command == 0 || output == 0 || output_bytes == 0 ||
      output_capacity < 2U) {
    ++g_remote_login_denials;
    return XAIOS_ERR_INVALID;
  }
  if (!local_account_is(user)) {
    ++g_remote_login_denials;
    klog("remote-login: denied reason=unknown-user\n");
    return XAIOS_ERR_INVALID;
  }
  if (security_reject_credential_material(command) != XAIOS_OK) {
    ++g_remote_login_denials;
    klog("remote-login: denied user=%s reason=secret-material\n", user);
    return XAIOS_ERR_INVALID;
  }
  if (operations_rescue_mode() != 0U &&
      operations_command_allowed_in_rescue(command) == 0U) {
    ++g_remote_login_denials;
    output[0] = '\0';
    *output_bytes = 0U;
    output_append(output, output_capacity, output_bytes,
                  "xaios: rescue mode permits diagnostics and filesystem "
                  "repair commands only\n");
    return XAIOS_ERR_INVALID;
  }

  uint64_t offset = 0;
  output[0] = '\0';
  ++g_remote_login_sessions;
  ++g_remote_login_commands;
  klog("remote-login: ssh-compatible session opened user=%s\n", user);
  klog("remote-login: command dispatch started\n");

  if (remote_login_exec_pipeline(command, output, output_capacity, &offset) !=
      XAIOS_OK) {
    *output_bytes = offset;
    klog("remote-login: command dispatch failed offset=%lu\n", offset);
    ++g_remote_login_denials;
    return XAIOS_ERR_INVALID;
  }

  *output_bytes = offset;
  klog("remote-login: session complete authenticated=1 commands=1 bytes=%lu\n",
       offset);
  return XAIOS_OK;
}

static remote_login_context_t *remote_login_context_find(uint64_t session_id) {
  for (uint32_t i = 0U; i < XAIOS_REMOTE_LOGIN_MAX_SESSIONS; ++i) {
    if (g_remote_login_contexts[i].active != 0U &&
        g_remote_login_contexts[i].session_id == session_id) {
      g_remote_login_contexts[i].last_used = ++g_remote_login_context_clock;
      return &g_remote_login_contexts[i];
    }
  }
  return 0;
}

static remote_login_context_t *remote_login_context_get(uint64_t session_id) {
  remote_login_context_t *context = remote_login_context_find(session_id);
  if (context != 0) return context;
  remote_login_context_t *oldest = &g_remote_login_contexts[0];
  for (uint32_t i = 0U; i < XAIOS_REMOTE_LOGIN_MAX_SESSIONS; ++i) {
    if (g_remote_login_contexts[i].active == 0U) {
      context = &g_remote_login_contexts[i];
      break;
    }
    if (g_remote_login_contexts[i].last_used < oldest->last_used) {
      oldest = &g_remote_login_contexts[i];
    }
  }
  if (context == 0) {
    /* The table is full, and the oldest entry gives way rather than the new
       session being refused.
       Refusing was the old behaviour and it is what made B-25 unrecoverable.
       A context here is a cache of one thing -- a session's working directory
       -- and losing one costs a shell its cwd, which resets to /. Refusing
       one costs the machine every command, for as long as it stays up, with
       SFTP still answering so it does not even look broken. Between a
       forgotten directory and a machine that will not take a command, the
       directory is the cheaper thing to lose.
       This is a backstop, not the fix: sshd closes what it opens now, so a
       table that fills means something is leaking again. Hence the log --
       the original defect's whole difficulty was that it was silent. */
    context = oldest;
    ++g_remote_login_context_evictions;
    klog("remote-login: session table full at %u; evicting session=%lu to "
         "admit session=%lu (evictions=%lu)\n",
         XAIOS_REMOTE_LOGIN_MAX_SESSIONS, context->session_id, session_id,
         g_remote_login_context_evictions);
  }
  context->session_id = session_id;
  context->active = 1U;
  context->last_used = ++g_remote_login_context_clock;
  context->cwd[0] = '/';
  context->cwd[1] = '\0';
  return context;
}

uint64_t remote_login_open_session_count(void) {
  uint64_t open = 0U;
  for (uint32_t i = 0U; i < XAIOS_REMOTE_LOGIN_MAX_SESSIONS; ++i) {
    if (g_remote_login_contexts[i].active != 0U) ++open;
  }
  return open;
}

uint64_t remote_login_session_eviction_count(void) {
  return g_remote_login_context_evictions;
}

xaios_status_t remote_login_execute_session(
    uint64_t session_id, const char *user, const char *command, char *output,
    uint64_t output_capacity, uint64_t *output_bytes) {
  if (session_id == 0U) return XAIOS_ERR_INVALID;
  remote_login_context_t *context = remote_login_context_get(session_id);
  if (context == 0) return XAIOS_ERR_NO_MEMORY;
  char *previous_cwd = g_remote_login_cwd;
  g_remote_login_cwd = context->cwd;
  xaios_status_t status = remote_login_execute(
      user, command, output, output_capacity, output_bytes);
  g_remote_login_cwd = previous_cwd;
  return status;
}

xaios_status_t remote_login_close_session(uint64_t session_id) {
  remote_login_context_t *context = remote_login_context_find(session_id);
  if (session_id == 0U || context == 0) return XAIOS_ERR_NOT_FOUND;
  for (uint64_t i = 0U; i < sizeof(*context); ++i) {
    ((uint8_t *)context)[i] = 0U;
  }
  return XAIOS_OK;
}

uint64_t remote_login_session_count(void) {
  return g_remote_login_sessions;
}

uint64_t remote_login_command_count(void) {
  return g_remote_login_commands;
}

uint64_t remote_login_denial_count(void) {
  return g_remote_login_denials;
}

void remote_login_self_test(void) {
  char output[192];
  uint64_t out = 0;
  uint64_t saved_sessions = g_remote_login_sessions;
  uint64_t saved_commands = g_remote_login_commands;
  uint64_t saved_denials = g_remote_login_denials;
  g_remote_login_sessions = 0U;
  g_remote_login_commands = 0U;
  g_remote_login_denials = 0U;
  for (uint32_t i = 0U; i < XAIOS_REMOTE_LOGIN_MAX_SESSIONS; ++i) {
    g_remote_login_contexts[i].active = 0U;
  }

  kassert(remote_login_execute("admin", "shell", output, sizeof(output),
                               &out) == XAIOS_ERR_INVALID);
  remote_login_context_t *first = remote_login_context_get(101U);
  kassert(first != 0);
  kassert(copy_cstr(first->cwd, sizeof(first->cwd), "/state") == XAIOS_OK);
  kassert(remote_login_execute_session(101U, "admin", "pwd", output,
                                       sizeof(output), &out) == XAIOS_OK);
  kassert(out >= 7U && output[0] == '/' && output[1] == 's');
  kassert(remote_login_execute_session(202U, "admin", "pwd", output,
                                       sizeof(output), &out) == XAIOS_OK);
  kassert(out == 2U && output[0] == '/' && output[1] == '\n');
  kassert(remote_login_close_session(101U) == XAIOS_OK);
  kassert(remote_login_close_session(202U) == XAIOS_OK);
  kassert(remote_login_close_session(202U) == XAIOS_ERR_NOT_FOUND);
  klog("remote-login: isolated session cwd self-test passed\n");

  /* What a full table does, which is B-25's other half.
     Before, the sixty-fifth session was refused and so was every session
     after it, for the life of the machine -- a guest that booted perfectly
     and answered "Command execution failed" to everything. Now the table
     gives up its least recently used entry, so a leak degrades to a lost
     working directory instead of a machine that will not take a command.
     Filled the long way round, through the same entry point sshd uses, so
     this tests the path rather than the table. */
  uint64_t evictions_before = remote_login_session_eviction_count();
  for (uint64_t id = 1000U;
       id < 1000U + (uint64_t)XAIOS_REMOTE_LOGIN_MAX_SESSIONS; ++id) {
    kassert(remote_login_execute_session(id, "admin", "pwd", output,
                                         sizeof(output), &out) == XAIOS_OK);
  }
  kassert(remote_login_open_session_count() ==
          (uint64_t)XAIOS_REMOTE_LOGIN_MAX_SESSIONS);
  kassert(remote_login_session_eviction_count() == evictions_before);
  /* The sixty-fifth. It must be served, not refused. */
  kassert(remote_login_execute_session(2000U, "admin", "pwd", output,
                                       sizeof(output), &out) == XAIOS_OK);
  kassert(remote_login_session_eviction_count() == evictions_before + 1U);
  /* And the one evicted is the oldest -- 1000, which nothing has named since
     it was created -- rather than one still in use. */
  kassert(remote_login_close_session(1000U) == XAIOS_ERR_NOT_FOUND);
  kassert(remote_login_close_session(2000U) == XAIOS_OK);
  for (uint64_t id = 1001U;
       id < 1000U + (uint64_t)XAIOS_REMOTE_LOGIN_MAX_SESSIONS; ++id) {
    kassert(remote_login_close_session(id) == XAIOS_OK);
  }
  kassert(remote_login_open_session_count() == 0U);
  klog("remote-login: a full session table evicts its oldest entry rather "
       "than refusing every session after it\n");
  kassert(remote_login_execute("admin", "cat /state/xaios_host_key", output,
                               sizeof(output), &out) == XAIOS_ERR_INVALID);
  kassert(remote_login_execute("admin", "cat /state/control/config.bin", output,
                               sizeof(output), &out) == XAIOS_ERR_INVALID);
  klog("remote-login: sensitive administrative paths denied\n");
  kassert(remote_login_execute("admin", "shell", output, sizeof(output),
                               &out) == XAIOS_ERR_INVALID);
  klog("remote-login: self-test passed sessions=%lu commands=%lu denials=%lu\n",
       remote_login_session_count(), remote_login_command_count(),
       remote_login_denial_count());
  g_remote_login_sessions = saved_sessions;
  g_remote_login_commands = saved_commands;
  g_remote_login_denials = saved_denials;
}

#if XAIOS_BOOT_TEST_APPS
xaios_status_t path_join(char *out, uint64_t out_capacity, const char *base,
                         const char *name) {
  if (out == 0 || out_capacity == 0U || base == 0 || name == 0) {
    return XAIOS_ERR_INVALID;
  }
  if (string_equal(name, ".") == 1U || string_equal(name, "..") == 1U) {
    return copy_cstr(out, out_capacity, name);
  }
  uint64_t base_len = cstr_len(base);
  uint64_t name_len = cstr_len(name);
  if (base_len == 0U || name_len == 0U ||
      (base_len + name_len + 1U) > out_capacity ||
      (base_len + name_len + 2U) > out_capacity) {
    return XAIOS_ERR_NO_MEMORY;
  }
  if (string_equal(base, "/") == 1U) {
    out[0] = '/';
    (void)copy_cstr_range(out + 1U, out_capacity - 1U, name, name_len);
    return XAIOS_OK;
  }
  out[0] = '\0';
  if (copy_cstr_range(out, out_capacity, base, base_len) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  if (out[base_len - 1U] != '/') {
    if (base_len + 1U >= out_capacity) {
      return XAIOS_ERR_NO_MEMORY;
    }
    out[base_len] = '/';
    ++base_len;
  }
  if (base_len + name_len + 1U > out_capacity) {
    return XAIOS_ERR_NO_MEMORY;
  }
  for (uint64_t i = 0; i < name_len; ++i) {
    out[base_len + i] = name[i];
  }
  out[base_len + name_len] = '\0';
  return XAIOS_OK;
}
#endif
