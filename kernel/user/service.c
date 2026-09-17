#include <xaios/assert.h>
#include <xaios/ai_cell.h>
#include <xaios/cpu_ai_runtime.h>
#include <xaios/klog.h>
#include <xaios/xaiboot_fs.h>
#include <xaios/network_stack.h>
#include <xaios/persistence.h>
#include <xaios/security.h>
#include <xaios/smp.h>
#include <xaios/spinlock.h>
#include <xaios/service.h>
#include <xaios/syscall.h>
#include <xaios/timer.h>
#include <xaios/update.h>
#include <xaios/user.h>

#include "service_internal.h"

#define XAIOS_OSCTL_MAX_TOKENS 8U

/* C-01: the service records, the crash-dump table and the counters now live
   in service_registry.c, but they are still reached from service_start,
   service_stop, service_restart, service_rollback and service_update, all of
   which are syscalls and so run on whichever CPU the calling thread occupies.
   A few of these functions call each other, so the guard counts depth; see
   xaios_reentrant_lock. The lock itself stays here, around the public entry
   points, exactly where it was. */
static xaios_reentrant_lock_t g_service_guard =
    XAIOS_REENTRANT_LOCK_INIT("service guard");

static void service_lock(void) {
  xaios_reentrant_lock(&g_service_guard, smp_cpu_id());
}

static void service_unlock(void) { xaios_reentrant_unlock(&g_service_guard); }

static xaios_status_t handle_status(const char *service_name) {
  xaios_service_t *service = svc_find_service(service_name);
  if (service == 0) {
    return XAIOS_ERR_INVALID;
  }
  klog(
      "osctl: %s state=%s starts=%lu restarts=%lu logs=%lu restart_policy=%s "
      "log_policy=%s max_restarts=%lu exit_code=%u\n",
      service->name, svc_state_name(service->state), service->starts,
      service->restart_attempts, service->log_records,
      service->restart_policy, service->log_policy,
      (unsigned long)service->max_restarts, (unsigned)service->exit_code);
  return XAIOS_OK;
}

static xaios_status_t handle_admin_policy(void) {
  if (svc_require_admin_capability() != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  ++svc_admin_policy_export_count;
  klog("admin: policy ssh_only=1 password_login=0 admin_cap_required=1 remote_safe_allowlist=1 exports=%lu\n",
       svc_admin_policy_export_count);
  return XAIOS_OK;
}

static xaios_status_t handle_admin_status(const char *service_name,
                                         uint32_t persist) {
  xaios_service_t *service = svc_find_service(service_name);
  if (svc_require_admin_capability() != XAIOS_OK || service == 0) {
    return XAIOS_ERR_INVALID;
  }
  klog("admin: status service=%s state=%s starts=%lu restarts=%lu logs=%lu crashes=%lu cleanups=%lu\n",
       service->name, svc_state_name(service->state), service->starts,
       service->restart_attempts, service->log_records, service->crash_count,
       service->cleanup_count);
  if (persist != 0 &&
      xaiboot_fs_record_admin_status(service->name,
                                     svc_state_name(service->state),
                                     (uint32_t)service->starts,
                                     (uint32_t)service->restart_attempts,
                                     (uint32_t)service->log_records) !=
          XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  ++svc_admin_status_export_count;
  return XAIOS_OK;
}

static xaios_status_t handle_admin_logs(const char *service_name) {
  xaios_service_t *service = svc_find_service(service_name);
  if (svc_require_admin_capability() != XAIOS_OK || service == 0) {
    return XAIOS_ERR_INVALID;
  }
  ++svc_admin_log_read_count;
  klog("admin: logs service=%s records=%lu log_policy=%s exit_code=%u reads=%lu\n",
       service->name, service->log_records, service->log_policy,
       (unsigned)service->exit_code, svc_admin_log_read_count);
  return XAIOS_OK;
}

static xaios_status_t handle_admin_remote_safe(const char *command) {
  if (svc_require_admin_capability() != XAIOS_OK || command == 0 ||
      svc_token_safe(command) == 0) {
    return XAIOS_ERR_INVALID;
  }
  if (svc_str_eq(command, "status") || svc_str_eq(command, "logs") ||
      svc_str_eq(command, "export")) {
    ++svc_admin_remote_safe_accept_count;
    klog("admin: remote-safe command=%s accepted accepts=%lu\n", command,
         svc_admin_remote_safe_accept_count);
    return XAIOS_OK;
  }
  ++svc_admin_remote_safe_reject_count;
  klog("admin: remote-safe command=%s rejected rejects=%lu\n", command,
       svc_admin_remote_safe_reject_count);
  return XAIOS_ERR_INVALID;
}

static xaios_status_t handle_log(const char *service_name, const char *message) {
  xaios_service_t *service = svc_find_service(service_name);
  if (service == 0 || !svc_token_safe(message)) {
    return XAIOS_ERR_INVALID;
  }
  if (security_reject_credential_material(message) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  ++service->log_records;
  ++svc_log_record_count;
  klog("service-manager: log %s %s records=%lu\n", service_name, message,
       service->log_records);
  return XAIOS_OK;
}

static xaios_status_t service_status_unlocked(const char *name) {
  return handle_status(name);
}

xaios_status_t service_status(const char *name) {
  service_lock();
  xaios_status_t result = service_status_unlocked(name);
  service_unlock();
  return result;
}

static xaios_status_t service_start_unlocked(const char *name) {
  xaios_service_t *service = svc_find_service(name);
  if (service == 0) {
    return XAIOS_ERR_INVALID;
  }
  return svc_start_service(service);
}

xaios_status_t service_start(const char *name) {
  service_lock();
  xaios_status_t result = service_start_unlocked(name);
  service_unlock();
  return result;
}

static xaios_status_t service_stop_unlocked(const char *name) {
  return svc_handle_stop(name);
}

xaios_status_t service_stop(const char *name) {
  service_lock();
  xaios_status_t result = service_stop_unlocked(name);
  service_unlock();
  return result;
}

static xaios_status_t service_restart_unlocked(const char *name) {
  return svc_handle_restart(name);
}

xaios_status_t service_restart(const char *name) {
  service_lock();
  xaios_status_t result = service_restart_unlocked(name);
  service_unlock();
  return result;
}

static xaios_status_t service_rollback_unlocked(const char *name) {
  return svc_handle_rollback(name);
}

xaios_status_t service_rollback(const char *name) {
  service_lock();
  xaios_status_t result = service_rollback_unlocked(name);
  service_unlock();
  return result;
}

static xaios_status_t service_update_unlocked(const char *signature) {
  return svc_handle_update(signature);
}

xaios_status_t service_update(const char *signature) {
  service_lock();
  xaios_status_t result = service_update_unlocked(signature);
  service_unlock();
  return result;
}

static xaios_status_t service_exit_unlocked(const char *name, int exit_code) {
  xaios_service_t *service = svc_find_service(name);
  return svc_mark_service_exit(service, exit_code, 0);
}

xaios_status_t service_exit(const char *name, int exit_code) {
  service_lock();
  xaios_status_t result = service_exit_unlocked(name, exit_code);
  service_unlock();
  return result;
}

static xaios_status_t tokenize_command(char *command, uint32_t *argc,
                                     const char *tokens[XAIOS_OSCTL_MAX_TOKENS]) {
  uint32_t count = 0;
  char *cursor = command;
  while (*cursor != '\0') {
    while (*cursor == ' ' || *cursor == '\t') {
      ++cursor;
    }
    if (*cursor == '\0') {
      break;
    }
    if (count >= XAIOS_OSCTL_MAX_TOKENS) {
      return XAIOS_ERR_INVALID;
    }

    tokens[count++] = cursor;

    while (*cursor != '\0' && *cursor != ' ' && *cursor != '\t') {
      ++cursor;
    }
    if (*cursor == ' ' || *cursor == '\t') {
      *cursor = '\0';
      ++cursor;
    }
  }

  if (count == 0) {
    return XAIOS_ERR_INVALID;
  }
  if (argc != 0) {
    argc[0] = count;
  }
  return XAIOS_OK;
}

static xaios_status_t handle_osctl_command(const char *action,
                                          uint32_t argc) {
  if (action == 0 || argc != 2U) {
    return XAIOS_ERR_INVALID;
  }

  if (svc_str_eq(action, "status")) {
    klog("osctl: status legacy=1 processes=%lu services=%lu ai_cells=%lu\n",
         user_process_active_count(), service_transition_count(),
         ai_cell_transition_count());
    return XAIOS_OK;
  }
  if (svc_str_eq(action, "ps")) {
    klog("osctl: ps slots=%u loaded=%lu runnable=%lu running=%lu exited=%lu failed=%lu scheduled=%lu active=%lu\n",
         XAIOS_MAX_USER_PROCESSES, user_process_loaded_count(),
         user_process_runnable_count(), user_process_running_count(),
         user_process_exited_count(), user_process_failed_count(),
         user_process_scheduled_count(), user_process_active_count());
    return XAIOS_OK;
  }
  if (svc_str_eq(action, "services")) {
    klog("osctl: services transitions=%lu restarts=%lu crashes=%lu cleanups=%lu descriptors=%lu logs=%lu\n",
         service_transition_count(), service_restart_count(),
         service_crash_count(), service_cleanup_count(),
         service_child_descriptor_count(), service_log_record_count());
    return XAIOS_OK;
  }
  if (svc_str_eq(action, "cells")) {
    klog("osctl: cells transitions=%lu admissions=%lu rejects=%lu queue_binds=%lu workspace_binds=%lu conflicts=%lu\n",
         ai_cell_transition_count(), ai_cell_resource_admission_count(),
         ai_cell_resource_reject_count(), ai_cell_queue_bind_count(),
         ai_cell_workspace_bind_count(), ai_cell_conflict_count());
    return XAIOS_OK;
  }
  if (svc_str_eq(action, "fs")) {
    klog("osctl: fs files=%lu directories=%lu writes=%lu reads=%lu commits=%lu rollbacks=%lu checksum_errors=%lu\n",
         xaiboot_fs_file_count(), xaiboot_fs_directory_count(),
         xaiboot_fs_write_count(), xaiboot_fs_read_count(),
         xaiboot_fs_commit_count(), xaiboot_fs_rollback_count(),
         xaiboot_fs_checksum_error_count());
    return XAIOS_OK;
  }
  if (svc_str_eq(action, "net")) {
    klog("osctl: net udp_tx=%lu udp_rx=%lu tcp_established=%lu tcp_closed=%lu rx=%lu tx=%lu drops=%lu flow_mismatches=%lu\n",
         network_stack_udp_tx_count(), network_stack_udp_rx_count(),
         network_stack_tcp_established_count(), network_stack_tcp_closed_count(),
         network_stack_rx_packet_count(), network_stack_tx_packet_count(),
         network_stack_packet_drop_count(),
         network_stack_flow_core_mismatch_count());
    return XAIOS_OK;
  }
  if (svc_str_eq(action, "telemetry")) {
    klog("osctl: telemetry cpu_ai_loads=%lu shared_binds=%lu kv_writes=%lu security_denials=%lu updates=%lu rollbacks=%lu\n",
         cpu_ai_runtime_model_load_count(),
         cpu_ai_runtime_shared_weight_bind_count(),
         cpu_ai_runtime_kv_write_count(), security_denied_operation_count(),
         update_transaction_count(), update_rollback_count());
    return XAIOS_OK;
  }
  if (svc_str_eq(action, "update")) {
    klog("osctl: update transactions=%lu staged=%lu committed=%lu failures=%lu recoveries=%lu rejects=%lu\n",
         update_transaction_count(), update_stage_count(), update_commit_count(),
         update_failure_count(), update_recovery_count(), update_reject_count());
    return XAIOS_OK;
  }
  if (svc_str_eq(action, "rollback")) {
    klog("osctl: rollback persistence=%lu xaiboot_fs=%lu update=%lu boot_fallbacks=%lu\n",
         persistence_rollback_count(), xaiboot_fs_rollback_count(),
         update_rollback_count(), update_boot_fallback_count());
    return XAIOS_OK;
  }

  klog("osctl: unsupported command name='%s' argc=%lu\n", action,
       (unsigned long)argc);
  return XAIOS_ERR_INVALID;
}

xaios_status_t osctl_execute(const char *command) {
  if (command == 0 || command[0] == '\0') {
    klog("service: osctl rejected command: empty\n");
    return XAIOS_ERR_INVALID;
  }

  char copy[XAIOS_CMD_TOKEN_BUFFER];
  for (uint32_t i = 0; i < XAIOS_CMD_TOKEN_BUFFER; ++i) {
    copy[i] = '\0';
  }
  uint32_t i = 0;
  for (; i < XAIOS_CMD_TOKEN_BUFFER; ++i) {
    copy[i] = command[i];
    if (command[i] == '\0') {
      break;
    }
  }
  if (i == XAIOS_CMD_TOKEN_BUFFER) {
    klog("service: osctl command too long\n");
    return XAIOS_ERR_INVALID;
  }

  const char *tokens[XAIOS_OSCTL_MAX_TOKENS];
  for (uint32_t j = 0; j < XAIOS_OSCTL_MAX_TOKENS; ++j) {
    tokens[j] = 0;
  }
  uint32_t argc = 0;
  if (tokenize_command(copy, &argc, tokens) != XAIOS_OK || argc < 2U) {
    klog("service: osctl parse failed argc=%lu command='%s'\n",
         (unsigned long)argc, copy);
    return XAIOS_ERR_INVALID;
  }

  for (uint32_t token_index = 0; token_index < argc; ++token_index) {
    if (!svc_token_safe(tokens[token_index])) {
      klog("service: osctl invalid token index=%lu value='%s'\n",
           (unsigned long)token_index,
           tokens[token_index] != 0 ? tokens[token_index] : "(null)");
      return XAIOS_ERR_INVALID;
    }
  }

  if (svc_str_eq(tokens[0], "osctl")) {
    return handle_osctl_command(tokens[1], argc);
  }

  if (svc_str_eq(tokens[0], "admin")) {
    const char *action = tokens[1];
    if (svc_str_eq(action, "policy") && argc == 2U) {
      return handle_admin_policy();
    }
    if (svc_str_eq(action, "status") && argc == 3U) {
      return handle_admin_status(tokens[2], 0);
    }
    if (svc_str_eq(action, "export") && argc == 3U) {
      return handle_admin_status(tokens[2], 1);
    }
    if (svc_str_eq(action, "logs") && argc == 3U) {
      return handle_admin_logs(tokens[2]);
    }
    if (svc_str_eq(action, "remote-safe") && argc == 3U) {
      return handle_admin_remote_safe(tokens[2]);
    }
    klog("admin: unsupported command name='%s' argc=%lu\n", action,
         (unsigned long)argc);
    return XAIOS_ERR_INVALID;
  }

  if (!svc_str_eq(tokens[0], "service")) {
    klog("service: osctl expected 'service' or 'admin' got token0='%s'\n",
         tokens[0]);
    return XAIOS_ERR_INVALID;
  }
  if (argc < 3U) {
    return XAIOS_ERR_INVALID;
  }

  const char *action = tokens[1];
  const char *service = tokens[2];
  if (tokens[1][0] == '/') {
    action = tokens[2];
    service = tokens[1];
  }

  if (!svc_token_safe(action)) {
    return XAIOS_ERR_INVALID;
  }

  if (svc_str_eq(action, "define") && argc == 5U) {
    return svc_handle_define(service, tokens[3], tokens[4]);
  }
  if (svc_str_eq(action, "status") && argc == 3U) {
    return handle_status(service);
  }
  if (svc_str_eq(action, "configure") && argc == 6U) {
    klog("service: osctl command argc=%lu token3=%s token4=%s token5=%s\n",
         (unsigned long)argc, tokens[3], tokens[4], tokens[5]);
    return svc_configure_service(service, tokens[3], tokens[4], tokens[5]);
  }
  if (svc_str_eq(action, "log") && argc == 4U) {
    return handle_log(service, tokens[3]);
  }
  if (svc_str_eq(action, "restart") && argc == 3U) {
    return svc_handle_restart(service);
  }
  if (svc_str_eq(action, "crash") && argc == 4U) {
    return svc_handle_crash(service, tokens[3]);
  }
  if (svc_str_eq(action, "start") && argc == 3U) {
    return svc_handle_start(service);
  }
  if (svc_str_eq(action, "stop") && argc == 3U) {
    return svc_handle_stop(service);
  }
  if (svc_str_eq(action, "rollback") && argc == 3U) {
    return svc_handle_rollback(service);
  }
  if (svc_str_eq(action, "update") && argc == 4U) {
    return svc_handle_update(tokens[3]);
  }

  klog("service: osctl unsupported command name='%s' argc=%lu\n", action,
       (unsigned long)argc);
  return XAIOS_ERR_INVALID;
}
