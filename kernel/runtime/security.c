#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/security.h>
#include <xaios/syscall.h>

#include "security_internal.h"

/*
 * Picard — “I will not sacrifice the Enterprise. Not again! The line must be
 * drawn here! This far, no further!”
 */

/* C-01: these are audit totals, updated from whichever CPU took the
   syscall, and this file holds no tables at all. That makes atomics the
   right instrument rather than a guard: the capability checks here sit on
   the syscall path, and serialising every one of them across all cores to
   protect a set of counters would cost far more than it buys. */
static uint64_t g_denied_operations;
static uint64_t g_capability_denials;
static uint64_t g_fs_denials;
static uint64_t g_workspace_denials;
static uint64_t g_sandbox_denials;
static uint64_t g_rollback_denials;
static uint64_t g_update_policy_rejects;
static uint64_t g_signature_accepts;
static uint64_t g_signature_rejects;
static uint64_t g_credential_rejects;
static uint64_t g_admin_denials;
static uint64_t g_update_authorizations;
static uint64_t g_update_replay_rejects;
static uint64_t g_key_accepts;
static uint64_t g_key_rejects;
static uint64_t g_sandbox_escape_rejects;

int security_starts_with(const char *text, const char *prefix) {
  if (text == 0 || prefix == 0) {
    return 0;
  }
  while (*prefix != '\0') {
    if (*text != *prefix) {
      return 0;
    }
    ++text;
    ++prefix;
  }
  return 1;
}

int security_contains(const char *text, const char *needle) {
  if (text == 0 || needle == 0 || *needle == '\0') {
    return 0;
  }

  for (const char *cursor = text; *cursor != '\0'; ++cursor) {
    const char *hay = cursor;
    const char *pat = needle;
    while (*hay != '\0' && *pat != '\0' && *hay == *pat) {
      ++hay;
      ++pat;
    }
    if (*pat == '\0') {
      return 1;
    }
  }

  return 0;
}

uint64_t security_cstr_length(const char *text) {
  uint64_t len = 0;
  if (text == 0) {
    return 0;
  }
  while (text[len] != '\0') {
    ++len;
  }
  return len;
}

static int path_in_tree(const char *path, const char *root) {
  uint64_t root_len = security_cstr_length(root);
  if (!security_starts_with(path, root)) {
    return 0;
  }
  return path[root_len] == '\0' || path[root_len] == '/';
}

xaios_status_t reject_security_operation(const char *reason) {
  __sync_fetch_and_add(&g_denied_operations, 1U);
  klog("security: denied operation reason=%s\n", reason);
  return XAIOS_ERR_INVALID;
}

/* Counter seeds for the signed-update policy in security_update.c and the
   credential scanner in security_credential.c. Each performs exactly the one
   atomic increment the unsplit file performed inline at that point. */
void security_note_credential_reject(void) {
  __sync_fetch_and_add(&g_credential_rejects, 1U);
}

void security_note_signature_reject(void) {
  __sync_fetch_and_add(&g_signature_rejects, 1U);
}

void security_note_update_policy_reject(void) {
  __sync_fetch_and_add(&g_update_policy_rejects, 1U);
}

void security_note_key_reject(void) {
  __sync_fetch_and_add(&g_key_rejects, 1U);
}

void security_note_update_replay_reject(void) {
  __sync_fetch_and_add(&g_update_replay_rejects, 1U);
}

void security_note_key_accept(void) {
  __sync_fetch_and_add(&g_key_accepts, 1U);
}

void security_note_signature_accept(void) {
  __sync_fetch_and_add(&g_signature_accepts, 1U);
}

void security_note_update_authorization(void) {
  __sync_fetch_and_add(&g_update_authorizations, 1U);
}

void security_policy_init(void) {
  g_denied_operations = 0;
  g_capability_denials = 0;
  g_fs_denials = 0;
  g_workspace_denials = 0;
  g_sandbox_denials = 0;
  g_rollback_denials = 0;
  g_update_policy_rejects = 0;
  g_signature_accepts = 0;
  g_signature_rejects = 0;
  g_credential_rejects = 0;
  g_admin_denials = 0;
  g_update_authorizations = 0;
  g_update_replay_rejects = 0;
  g_key_accepts = 0;
  g_key_rejects = 0;
  g_sandbox_escape_rejects = 0;
  security_reset_update_key_state();
  klog("security: policy initialized mode=development signed_updates=dev-public-key admin=required replay=monotonic\n");
}

void security_record_denied_operation(void) {
  __sync_fetch_and_add(&g_denied_operations, 1U);
}

xaios_status_t security_authorize_capability(const char *operation,
                                            uint64_t granted,
                                            uint64_t required) {
  (void)operation;
  if ((granted & required) == required) {
    return XAIOS_OK;
  }
  __sync_fetch_and_add(&g_capability_denials, 1U);
  return reject_security_operation("missing-capability");
}

xaios_status_t security_authorize_fs_read(const char *path) {
  if (security_reject_credential_material(path) != XAIOS_OK) {
    __sync_fetch_and_add(&g_fs_denials, 1U);
    return XAIOS_ERR_INVALID;
  }
  if ((path[0] == '/' && path[1] == '\0') || path_in_tree(path, "/bin") ||
      security_starts_with(path, "/etc/") || path_in_tree(path, "/tmp") ||
      path_in_tree(path, "/home") || path_in_tree(path, "/apps") ||
      path_in_tree(path, "/state") || path_in_tree(path, "/logs") ||
      path_in_tree(path, "/models") || path_in_tree(path, "/update")) {
    return XAIOS_OK;
  }
  __sync_fetch_and_add(&g_fs_denials, 1U);
  return reject_security_operation("fs-read-denied");
}

xaios_status_t security_authorize_fs_write(const char *path) {
  if (security_reject_credential_material(path) != XAIOS_OK) {
    __sync_fetch_and_add(&g_fs_denials, 1U);
    return XAIOS_ERR_INVALID;
  }
  if (security_starts_with(path, "/etc/xaios_ssh_client_identity") &&
      path[sizeof("/etc/xaios_ssh_client_identity") - 1U] == '\0') {
    __sync_fetch_and_add(&g_fs_denials, 1U);
    return reject_security_operation("credential-write-denied");
  }
  if (path_in_tree(path, "/tmp") || path_in_tree(path, "/home") ||
      path_in_tree(path, "/apps") || path_in_tree(path, "/state") ||
      path_in_tree(path, "/logs") || path_in_tree(path, "/update") ||
      path_in_tree(path, "/models/.staging")) {
    return XAIOS_OK;
  }
  __sync_fetch_and_add(&g_fs_denials, 1U);
  return reject_security_operation("fs-write-denied");
}

xaios_status_t security_authorize_git_workspace(uint32_t workspace_id,
                                               uint32_t owner_cell_id,
                                               uint32_t actor_cell_id,
                                               const char *operation) {
  (void)workspace_id;
  if (security_reject_credential_material(operation) != XAIOS_OK) {
    __sync_fetch_and_add(&g_workspace_denials, 1U);
    return XAIOS_ERR_INVALID;
  }
  if (actor_cell_id == owner_cell_id) {
    return XAIOS_OK;
  }
  __sync_fetch_and_add(&g_workspace_denials, 1U);
  return reject_security_operation("git-workspace-owner-mismatch");
}

xaios_status_t security_authorize_sandbox(uint32_t sandbox_id,
                                         uint32_t owner_cell_id,
                                         uint32_t actor_cell_id,
                                         const char *operation) {
  (void)sandbox_id;
  if (security_reject_credential_material(operation) != XAIOS_OK) {
    __sync_fetch_and_add(&g_sandbox_denials, 1U);
    return XAIOS_ERR_INVALID;
  }
  if (actor_cell_id == owner_cell_id) {
    return XAIOS_OK;
  }
  __sync_fetch_and_add(&g_sandbox_denials, 1U);
  return reject_security_operation("sandbox-owner-mismatch");
}

xaios_status_t security_authorize_rollback(const char *target,
                                          uint32_t authorized) {
  if (security_reject_credential_material(target) != XAIOS_OK) {
    __sync_fetch_and_add(&g_rollback_denials, 1U);
    return XAIOS_ERR_INVALID;
  }
  if (authorized != 0) {
    return XAIOS_OK;
  }
  __sync_fetch_and_add(&g_rollback_denials, 1U);
  return reject_security_operation("rollback-denied");
}

xaios_status_t security_authorize_admin(const char *operation,
                                       uint64_t granted) {
  if (security_reject_credential_material(operation) != XAIOS_OK) {
    __sync_fetch_and_add(&g_admin_denials, 1U);
    return XAIOS_ERR_INVALID;
  }
  if ((granted & XAIOS_CAP_ADMIN) == XAIOS_CAP_ADMIN) {
    return XAIOS_OK;
  }
  __sync_fetch_and_add(&g_admin_denials, 1U);
  __sync_fetch_and_add(&g_capability_denials, 1U);
  return reject_security_operation("admin-capability-denied");
}

xaios_status_t security_validate_sandbox_path(const char *path) {
  const char *cursor = path;
  if (security_reject_credential_material(path) != XAIOS_OK) {
    __sync_fetch_and_add(&g_sandbox_escape_rejects, 1U);
    return XAIOS_ERR_INVALID;
  }
  if (path == 0 || path[0] != '/') {
    __sync_fetch_and_add(&g_sandbox_escape_rejects, 1U);
    return reject_security_operation("sandbox-path-relative");
  }
  while (*cursor != '\0') {
    if (cursor[0] == '/' && cursor[1] == '/') {
      __sync_fetch_and_add(&g_sandbox_escape_rejects, 1U);
      return reject_security_operation("sandbox-path-escape");
    }
    if (cursor[0] == '.' && cursor[1] == '.' &&
        (cursor == path || cursor[-1] == '/') &&
        (cursor[2] == '/' || cursor[2] == '\0')) {
      __sync_fetch_and_add(&g_sandbox_escape_rejects, 1U);
      return reject_security_operation("sandbox-path-escape");
    }
    ++cursor;
  }
  return XAIOS_OK;
}

xaios_status_t security_validate_benchmark_record(const char *record) {
  if (security_reject_credential_material(record) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  if (record == 0 || !security_contains(record, "\"design_targets\":true")) {
    return reject_security_operation("benchmark-record-policy");
  }
  return XAIOS_OK;
}

uint64_t security_denied_operation_count(void) {
  return g_denied_operations;
}

uint64_t security_capability_denial_count(void) {
  return g_capability_denials;
}

uint64_t security_fs_denial_count(void) {
  return g_fs_denials;
}

uint64_t security_workspace_denial_count(void) {
  return g_workspace_denials;
}

uint64_t security_sandbox_denial_count(void) {
  return g_sandbox_denials;
}

uint64_t security_rollback_denial_count(void) {
  return g_rollback_denials;
}

uint64_t security_update_policy_reject_count(void) {
  return g_update_policy_rejects;
}

uint64_t security_signature_accept_count(void) {
  return g_signature_accepts;
}

uint64_t security_signature_reject_count(void) {
  return g_signature_rejects;
}

uint64_t security_credential_reject_count(void) {
  return g_credential_rejects;
}

uint64_t security_admin_denial_count(void) {
  return g_admin_denials;
}

uint64_t security_update_authorization_count(void) {
  return g_update_authorizations;
}

uint64_t security_update_replay_reject_count(void) {
  return g_update_replay_rejects;
}

uint64_t security_key_accept_count(void) {
  return g_key_accepts;
}

uint64_t security_key_reject_count(void) {
  return g_key_rejects;
}

uint64_t security_sandbox_escape_reject_count(void) {
  return g_sandbox_escape_rejects;
}

void security_self_test(void) {
  security_policy_init();
  const char credential_fixture[] = {
      'g', 'i', 't', 'h', 'u', 'b', '_', 'p', 'a', 't', '_',
      'e', 'x', 'a', 'm', 'p', 'l', 'e', '\0'};
  kassert(security_reject_credential_material("normal-update-request") ==
          XAIOS_OK);
  kassert(security_reject_credential_material(credential_fixture) ==
          XAIOS_ERR_INVALID);
  kassert(security_validate_update_signature("unsigned-update") ==
          XAIOS_ERR_INVALID);
  kassert(security_authorize_capability("service.update", 0U, 16U) ==
          XAIOS_ERR_INVALID);
  kassert(security_authorize_fs_read("/etc/services/source-index.svc") ==
          XAIOS_OK);
  kassert(security_authorize_fs_write("/etc/services/source-index.svc") ==
          XAIOS_ERR_INVALID);
  kassert(security_authorize_fs_read("/models/active-package") == XAIOS_OK);
  kassert(security_authorize_fs_write("/models/active-package") ==
          XAIOS_ERR_INVALID);
  kassert(security_authorize_fs_write("/models/.staging/package") ==
          XAIOS_OK);
  kassert(security_authorize_fs_read("/update/xapt/catalog") == XAIOS_OK);
  kassert(security_authorize_fs_write("/update/xapt/catalog") == XAIOS_OK);
  kassert(security_authorize_git_workspace(0, 1, 2, "patch") ==
          XAIOS_ERR_INVALID);
  kassert(security_authorize_sandbox(0, 1, 2, "build") ==
          XAIOS_ERR_INVALID);
  kassert(security_authorize_rollback("/init", 0) == XAIOS_ERR_INVALID);
  kassert(security_authorize_admin("admin.shell", 0) == XAIOS_ERR_INVALID);
  kassert(security_validate_sandbox_path("/workspace/1/../escape") ==
          XAIOS_ERR_INVALID);
  kassert(security_validate_benchmark_record(
              "{\"design_targets\":true,\"latency\":\"target\"}") ==
          XAIOS_OK);
  kassert(security_validate_benchmark_record("token=bad") ==
          XAIOS_ERR_INVALID);
  kassert(security_validate_update_signature(
              "xaios-update:v2:gen=1:sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:key=BAD:sig=00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") ==
          XAIOS_ERR_INVALID);
  kassert(security_authorize_update_signature(
              "xaios-update:v2:gen=1:sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:key=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a:sig=c9c9bb8ffe9e6e31ea6d56c0f956305045a3e74e3336428858897bd6cfde3b303d32bf21cfabbfed492191658a4a6472ec1ade6cb63636d4c74da5fb5eecf10e",
              XAIOS_CAP_UPDATE) == XAIOS_ERR_INVALID);
  kassert(security_validate_update_signature(
              "xaios-update:v2:gen=1:sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:key=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a:sig=c8c9bb8ffe9e6e31ea6d56c0f956305045a3e74e3336428858897bd6cfde3b303d32bf21cfabbfed492191658a4a6472ec1ade6cb63636d4c74da5fb5eecf10e") ==
          XAIOS_ERR_INVALID);
  kassert(security_authorize_update_signature(
              "xaios-update:v2:gen=1:sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:key=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a:sig=c9c9bb8ffe9e6e31ea6d56c0f956305045a3e74e3336428858897bd6cfde3b303d32bf21cfabbfed492191658a4a6472ec1ade6cb63636d4c74da5fb5eecf10e",
              XAIOS_CAP_UPDATE | XAIOS_CAP_ADMIN) ==
          XAIOS_OK);
  kassert(security_validate_update_signature(
              "xaios-update:v2:gen=1:sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:key=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a:sig=c9c9bb8ffe9e6e31ea6d56c0f956305045a3e74e3336428858897bd6cfde3b303d32bf21cfabbfed492191658a4a6472ec1ade6cb63636d4c74da5fb5eecf10e") ==
          XAIOS_ERR_INVALID);
  kassert(g_credential_rejects == 2);
  kassert(g_signature_rejects == 4);
  kassert(g_signature_accepts == 1);
  kassert(g_capability_denials == 3);
  kassert(g_fs_denials == 2);
  kassert(g_workspace_denials == 1);
  kassert(g_sandbox_denials == 1);
  kassert(g_rollback_denials == 1);
  kassert(g_update_policy_rejects == 4);
  kassert(g_admin_denials == 2);
  kassert(g_update_authorizations == 1);
  kassert(g_update_replay_rejects == 1);
  kassert(g_key_accepts == 1);
  kassert(g_key_rejects == 1);
  kassert(g_sandbox_escape_rejects == 1);
  kassert(g_denied_operations == 15);
  klog("security: self-test passed denied=%lu capability_denials=%lu fs_denials=%lu workspace_denials=%lu sandbox_denials=%lu rollback_denials=%lu update_policy_rejects=%lu credential_rejects=%lu signature_accepts=%lu signature_rejects=%lu admin_denials=%lu update_authorizations=%lu update_replay_rejects=%lu key_accepts=%lu key_rejects=%lu sandbox_escape_rejects=%lu\n",
       g_denied_operations, g_capability_denials, g_fs_denials,
       g_workspace_denials, g_sandbox_denials, g_rollback_denials,
       g_update_policy_rejects, g_credential_rejects, g_signature_accepts,
       g_signature_rejects, g_admin_denials, g_update_authorizations,
       g_update_replay_rejects, g_key_accepts, g_key_rejects,
       g_sandbox_escape_rejects);
}
