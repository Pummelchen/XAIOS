/* Service lifecycle: start, stop, restart, rollback, crash handling, the
   watchdog and the supervisor self-test.

   The supervision policy lives here; the records, counters and configuration
   parser live in service_registry.c. Nothing here takes the reentrant
   service lock: the public entry points in service.c take it around the
   calls they always took it around, and the unlocked watchdog path stays
   unlocked. */

#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/security.h>
#include <xaios/service.h>
#include <xaios/syscall.h>
#include <xaios/timer.h>
#include <xaios/user.h>
#include <xaios/xaiboot_fs.h>

#include "service_internal.h"

static void persist_service_state(xaios_service_t *service) {
  if (service == 0 || !svc_str_eq(service->name, svc_child_service_name)) {
    return;
  }
  xaios_status_t status = xaiboot_fs_record_service_state(
      service->name, svc_state_name(service->state));
  if (status == XAIOS_OK) {
    klog("service: %s mutable-state persisted state=%s\n", service->name,
         svc_state_name(service->state));
  } else {
    klog("service: %s mutable-state persist failed state=%s status=%u\n",
         service->name, svc_state_name(service->state),
         (unsigned)status);
  }
}

xaios_status_t svc_start_service(xaios_service_t *service) {
  if (service == 0) {
    return XAIOS_ERR_INVALID;
  }
  if (service->state != XAIOS_SERVICE_STOPPED &&
      service->state != XAIOS_SERVICE_EXITED &&
      service->state != XAIOS_SERVICE_FAILED) {
    return XAIOS_ERR_INVALID;
  }
  if (service->state != XAIOS_SERVICE_STOPPED &&
      service->max_restarts != UINT32_C(0xffffffff) &&
      service->starts >= service->max_restarts) {
    return XAIOS_ERR_INVALID;
  }

  service->state = XAIOS_SERVICE_STARTING;
  ++service->starts;
  ++svc_transition_count;
  service->last_start_ns = wall_time_now_ns();
  service->last_heartbeat_ns = service->last_start_ns;
  service->watchdog_enabled = 1;
  service->backoff_ns = 0;
  klog("service: %s state=starting parent=%s\n", service->name,
       service->parent_name != 0 ? service->parent_name : "(root)");
  service->state = XAIOS_SERVICE_RUNNING;
  ++svc_transition_count;
  klog("service: %s state=running parent=%s\n", service->name,
       service->parent_name != 0 ? service->parent_name : "(root)");
  persist_service_state(service);
  return XAIOS_OK;
}

static void cleanup_service_runtime(xaios_service_t *service,
                                    const char *reason) {
  if (service == 0) {
    return;
  }
  ++service->cleanup_count;
  ++svc_cleanup_count;
  klog("service-supervisor: cleanup %s reason=%s cleanups=%lu\n",
       service->name, reason, service->cleanup_count);
}

static xaios_status_t supervisor_restart_failed_child(xaios_service_t *service) {
  if (service == 0) {
    return XAIOS_ERR_INVALID;
  }
  if (!svc_str_eq(service->restart_policy, svc_policy_always) &&
      !svc_str_eq(service->restart_policy, svc_policy_on_failure)) {
    klog("service-supervisor: restart skipped %s policy=%s\n",
         service->name, service->restart_policy);
    return XAIOS_ERR_INVALID;
  }
  ++service->restart_attempts;
  if (service->max_restarts != UINT32_C(0xffffffff) &&
      service->restart_attempts > service->max_restarts) {
    klog("service-supervisor: restart blocked %s max_restarts=%lu attempts=%lu\n",
         service->name, (unsigned long)service->max_restarts,
         service->restart_attempts);
    return XAIOS_ERR_INVALID;
  }

  /* Exponential backoff */
  if (service->backoff_ns == 0) {
    service->backoff_ns = XAIOS_BACKOFF_BASE_NS;
  } else {
    service->backoff_ns *= 2U;
    if (service->backoff_ns > XAIOS_BACKOFF_CAP_NS) {
      service->backoff_ns = XAIOS_BACKOFF_CAP_NS;
    }
  }
  klog("service-supervisor: backoff %s delay=%lu ns\n",
       service->name, service->backoff_ns);

  cleanup_service_runtime(service, "crash");
  service->state = XAIOS_SERVICE_STOPPED;
  ++svc_transition_count;
  klog("service-supervisor: restarting child %s parent=%s attempt=%lu\n",
       service->name, service->parent_name != 0 ? service->parent_name : "(root)",
       service->restart_attempts);
  if (svc_start_service(service) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  ++svc_restart_count;
  return XAIOS_OK;
}

xaios_status_t svc_mark_service_exit(xaios_service_t *service, int exit_code,
                                     uint32_t supervise) {
  if (service == 0 || service->state != XAIOS_SERVICE_RUNNING) {
    return XAIOS_ERR_INVALID;
  }

  service->exit_code = exit_code;
  service->state =
      exit_code == 0 ? XAIOS_SERVICE_EXITED : XAIOS_SERVICE_FAILED;
  ++svc_transition_count;
  if (exit_code != 0) {
    ++service->crash_count;
    ++svc_crash_count;
  }
  klog("service: %s state=%s exit_code=%u\n", service->name,
       svc_state_name(service->state), (unsigned)exit_code);
  persist_service_state(service);

  /* Capture crash dump on non-zero exit */
  if (exit_code != 0) {
    uint32_t idx = svc_crash_dump_count % XAIOS_CRASH_DUMP_MAX;
    xaios_crash_record_t *rec = &svc_crash_dumps[idx];
    rec->service_name = service->name;
    rec->exit_code = exit_code;
    rec->crash_timestamp_ns = wall_time_now_ns();
    rec->restart_count = service->restart_attempts;
    rec->uptime_ns = service->last_start_ns > 0
                         ? (rec->crash_timestamp_ns - service->last_start_ns)
                         : 0;
    ++svc_crash_dump_count;
    klog("service-supervisor: crash-dump %s code=%u uptime=%lu ns dumps=%u\n",
         service->name, (unsigned)exit_code, rec->uptime_ns,
         svc_crash_dump_count);
  }

  if (supervise != 0 && exit_code != 0) {
    return supervisor_restart_failed_child(service);
  }
  if (exit_code == 0) {
    cleanup_service_runtime(service, "exit");
  }
  return XAIOS_OK;
}

xaios_status_t svc_handle_restart(const char *service_name) {
  xaios_service_t *service = svc_find_service(service_name);
  if (service == 0) {
    return XAIOS_ERR_INVALID;
  }

  ++service->restart_attempts;
  if (svc_str_eq(service->restart_policy, svc_policy_never)) {
    klog("service-manager: restart denied %s policy=%s attempts=%lu\n",
         service->name, service->restart_policy, service->restart_attempts);
    return XAIOS_ERR_INVALID;
  }

  if (service->max_restarts != UINT32_C(0xffffffff) &&
      service->restart_attempts > service->max_restarts) {
    klog("service-manager: restart denied %s max_restarts=%lu attempts=%lu\n",
         service->name, (unsigned long)service->max_restarts,
         service->restart_attempts);
    return XAIOS_ERR_INVALID;
  }

  service->state = XAIOS_SERVICE_STOPPED;
  ++svc_transition_count;
  klog("service-manager: restart allowed %s attempts=%lu\n",
       service->name, service->restart_attempts);
  if (svc_start_service(service) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  ++svc_restart_count;
  return XAIOS_OK;
}

xaios_status_t svc_handle_start(const char *service_name) {
  xaios_service_t *service = svc_find_service(service_name);
  if (service == 0) {
    return XAIOS_ERR_INVALID;
  }
  return svc_start_service(service);
}

xaios_status_t svc_handle_update(const char *signature) {
  if (signature == 0 || signature[0] == '\0') {
    security_record_denied_operation();
    return XAIOS_ERR_INVALID;
  }
  if (security_reject_credential_material(signature) != XAIOS_OK) {
    ++svc_init_service.update_rejections;
    return XAIOS_ERR_INVALID;
  }
  if (svc_require_service_capability(XAIOS_CAP_UPDATE) != XAIOS_OK) {
    ++svc_init_service.update_rejections;
    const xaios_user_process_t *process = user_current_process();
    uint64_t granted = process != 0 ? process->capability_mask : 0;
    (void)security_authorize_capability("service.update", granted,
                                        XAIOS_CAP_UPDATE);
    return XAIOS_ERR_INVALID;
  }

  if (svc_token_safe(signature) == 0 ||
      security_authorize_update_signature(signature,
                                          user_current_process()
                                              ->capability_mask) != XAIOS_OK) {
    ++svc_init_service.update_rejections;
    return XAIOS_ERR_INVALID;
  }

  ++svc_init_service.update_attempts;
  klog("service-manager: update token accepted length=%lu\n",
       (unsigned long)svc_token_length(signature));
  return XAIOS_OK;
}

xaios_status_t svc_handle_rollback(const char *service_name) {
  if (!svc_str_eq(service_name, svc_init_service.name)) {
    return XAIOS_ERR_INVALID;
  }
  if (svc_require_service_capability(XAIOS_CAP_SERVICE_ROLLBACK) != XAIOS_OK) {
    ++svc_init_service.rollback_count;
    (void)security_authorize_rollback(service_name, 0);
    return XAIOS_ERR_INVALID;
  }
  if (security_authorize_rollback(service_name, 1) != XAIOS_OK) {
    ++svc_init_service.rollback_count;
    return XAIOS_ERR_INVALID;
  }

  svc_snapshot_restore(&svc_init_service);
  ++svc_init_service.rollback_count;
  klog("service-manager: rollback /init restart=%s log=%s max_restarts=%lu\n",
       svc_init_service.restart_policy, svc_init_service.log_policy,
       (unsigned long)svc_init_service.max_restarts);
  return XAIOS_OK;
}

xaios_status_t svc_handle_stop(const char *service_name) {
  xaios_service_t *service = svc_find_service(service_name);
  return svc_mark_service_exit(service, 0, 0);
}

static xaios_status_t parse_exit_code_token(const char *token, int *exit_code) {
  const char *value = 0;
  uint32_t parsed = 0;
  if (exit_code == 0 ||
      svc_parse_key_value(token, "code", &value) != XAIOS_OK ||
      svc_parse_u32(value, &parsed) != XAIOS_OK || parsed == 0 ||
      parsed > INT32_MAX) {
    return XAIOS_ERR_INVALID;
  }
  *exit_code = (int)parsed;
  return XAIOS_OK;
}

xaios_status_t svc_handle_crash(const char *service_name,
                                const char *code_token) {
  xaios_service_t *service = svc_find_service(service_name);
  int exit_code = 0;
  if (service == 0 ||
      parse_exit_code_token(code_token, &exit_code) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  klog("service-supervisor: observed crash %s code=%u parent=%s\n",
       service->name, (unsigned)exit_code,
       service->parent_name != 0 ? service->parent_name : "(root)");
  return svc_mark_service_exit(service, exit_code, 1);
}

xaios_status_t svc_handle_define(const char *service_name,
                                 const char *parent_token,
                                 const char *restart_token) {
  const char *parent = 0;
  const char *restart = 0;
  xaios_service_t *parent_service = 0;
  if (!svc_str_eq(service_name, svc_child_service_name) ||
      svc_parse_key_value(parent_token, "parent", &parent) != XAIOS_OK ||
      svc_parse_key_value(restart_token, "restart", &restart) != XAIOS_OK ||
      !svc_str_eq(parent, svc_child_parent_name) ||
      (!svc_str_eq(restart, svc_policy_never) &&
       !svc_str_eq(restart, svc_policy_always))) {
    return XAIOS_ERR_INVALID;
  }
  parent_service = svc_find_service(parent);
  if (parent_service == 0) {
    return XAIOS_ERR_INVALID;
  }

  svc_reset_service(&svc_child_service, svc_child_service_name);
  svc_child_service.parent_name = svc_child_parent_name;
  svc_child_service.restart_policy =
      svc_str_eq(restart, svc_policy_always) ? svc_policy_always
                                             : svc_policy_never;
  ++svc_child_descriptor_count;
  ++svc_tree_edge_count;
  ++parent_service->child_count;
  klog("service-manager: defined child %s parent=%s restart=%s descriptors=%lu\n",
       svc_child_service.name, svc_child_parent_name,
       svc_child_service.restart_policy, svc_child_descriptor_count);
  klog("service-supervisor: tree parent=%s child=%s children=%lu edges=%lu\n",
       parent_service->name, svc_child_service.name, parent_service->child_count,
       svc_tree_edge_count);
  return XAIOS_OK;
}

void service_supervisor_init(void) {
  svc_reset_service(&svc_init_service, svc_init_service_name);
  svc_reset_service(&svc_manager_service, svc_manager_service_name);
  svc_reset_service(&svc_worker_service, svc_worker_service_name);
  svc_reset_service(&svc_child_service, 0);
  svc_child_descriptor_count = 0;
  svc_tree_edge_count = 0;
  svc_transition_count = 0;
  svc_restart_count = 0;
  svc_crash_count = 0;
  svc_cleanup_count = 0;
  svc_log_record_count = 0;
  svc_admin_policy_export_count = 0;
  svc_admin_status_export_count = 0;
  svc_admin_log_read_count = 0;
  svc_admin_remote_safe_accept_count = 0;
  svc_admin_remote_safe_reject_count = 0;
  svc_admin_command_denial_count = 0;
  svc_crash_dump_count = 0;
  for (uint32_t i = 0; i < XAIOS_CRASH_DUMP_MAX; ++i) {
    svc_crash_dumps[i].service_name = 0;
    svc_crash_dumps[i].exit_code = 0;
    svc_crash_dumps[i].crash_timestamp_ns = 0;
    svc_crash_dumps[i].restart_count = 0;
    svc_crash_dumps[i].uptime_ns = 0;
  }
  svc_snapshot_capture(&svc_init_service);
  klog("service: supervisor initialized\n");
}

xaios_status_t service_start_init(void) {
  return service_start(svc_init_service_name);
}

xaios_status_t service_heartbeat(const char *name) {
  xaios_service_t *service = svc_find_service(name);
  if (service == 0 || service->state != XAIOS_SERVICE_RUNNING) {
    return XAIOS_ERR_INVALID;
  }
  service->last_heartbeat_ns = wall_time_now_ns();
  return XAIOS_OK;
}

void service_watchdog_check(void) {
  uint64_t now = wall_time_now_ns();
  xaios_service_t *services[] = {&svc_init_service, &svc_manager_service,
                                &svc_worker_service, &svc_child_service};
  for (uint32_t i = 0; i < 4; ++i) {
    xaios_service_t *svc = services[i];
    if (svc->state != XAIOS_SERVICE_RUNNING || svc->watchdog_enabled == 0) {
      continue;
    }
    if (svc->last_heartbeat_ns == 0) {
      continue;
    }
    uint64_t elapsed = now - svc->last_heartbeat_ns;
    if (elapsed > XAIOS_WATCHDOG_TIMEOUT_NS) {
      klog("service-watchdog: %s heartbeat timeout elapsed=%lu ns\n",
           svc->name, elapsed);
      svc_mark_service_exit(svc, -1, 1);
    }
  }
}

void service_supervisor_self_test(void) {
  service_supervisor_init();
  kassert(osctl_execute("service status /init") == XAIOS_OK);
  kassert(osctl_execute(
             "service configure /init restart=never log=serial max_restarts=0") ==
         XAIOS_OK);
  kassert(osctl_execute("service log /init manager-ready") == XAIOS_OK);
  kassert(osctl_execute("service restart /init") == XAIOS_ERR_INVALID);
  kassert(osctl_execute("service start /init") == XAIOS_OK);
  kassert(osctl_execute("service status /init") == XAIOS_OK);
  kassert(osctl_execute(
              "service define /svc/source-index parent=/init restart=never") ==
          XAIOS_OK);
  kassert(osctl_execute("service start /svc/source-index") == XAIOS_OK);
  kassert(osctl_execute("service status /svc/source-index") == XAIOS_OK);
  kassert(osctl_execute(
              "service configure /svc/source-index restart=always log=serial max_restarts=2") ==
          XAIOS_OK);
  kassert(osctl_execute("service log /svc/source-index crash-test") == XAIOS_OK);
  kassert(osctl_execute("service crash /svc/source-index code=7") == XAIOS_OK);
  kassert(osctl_execute("service status /svc/source-index") == XAIOS_OK);
  kassert(service_exit("/init", 0) == XAIOS_OK);
  kassert(osctl_execute("service status /init") == XAIOS_OK);
  kassert(osctl_execute("service rollback /init") == XAIOS_ERR_INVALID);
  kassert(osctl_execute("service destroy /init") == XAIOS_ERR_INVALID);
  kassert(osctl_execute("service update /init test") == XAIOS_ERR_INVALID);
  kassert(osctl_execute("admin policy") == XAIOS_ERR_INVALID);
  kassert(service_tree_edge_count() == 1);
  kassert(service_restart_count() == 1);
  kassert(service_crash_count() == 1);
  kassert(service_cleanup_count() >= 1);
  kassert(service_log_record_count() >= 2);

  /* Test on-failure policy */
  svc_reset_service(&svc_child_service, 0);
  kassert(osctl_execute(
              "service define /svc/source-index parent=/init restart=on-failure") ==
          XAIOS_OK);
  kassert(osctl_execute(
              "service configure /svc/source-index restart=on-failure log=serial max_restarts=5") ==
          XAIOS_OK);
  kassert(osctl_execute("service start /svc/source-index") == XAIOS_OK);
  /* Clean exit should NOT restart under on-failure */
  kassert(service_exit("/svc/source-index", 0) == XAIOS_OK);
  kassert(svc_child_service.state == XAIOS_SERVICE_EXITED);

  /* Crash should produce crash dump */
  kassert(osctl_execute("service start /svc/source-index") == XAIOS_OK);
  kassert(osctl_execute("service crash /svc/source-index code=11") == XAIOS_OK);
  kassert(svc_crash_dump_count >= 2);
  kassert(svc_crash_dumps[(svc_crash_dump_count - 1U) % XAIOS_CRASH_DUMP_MAX].exit_code == 11);

  /* Verify backoff increased */
  kassert(svc_child_service.backoff_ns >= XAIOS_BACKOFF_BASE_NS);

  klog("service: supervisor self-test passed\n");
}
