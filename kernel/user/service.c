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

#define XAIOS_CMD_TOKEN_BUFFER 160U
#define XAIOS_OSCTL_MAX_TOKENS 8U
#define XAIOS_POLICY_COPY_SIZE 16U

static const char k_policy_never[] = "never";
static const char k_policy_always[] = "always";
static const char k_policy_on_failure[] = "on-failure";
static const char k_policy_default[] = "unset";
static const char k_log_serial[] = "serial";
static const char k_log_off[] = "off";
static const char k_init_service_name[] = "/init";
static const char k_manager_service_name[] = "/bin/service-manager";
static const char k_worker_service_name[] = "/bin/xaios-worker";
static const char k_child_service_name[] = "/svc/source-index";
static const char k_child_parent_name[] = "/init";

/* C-01: these service records and the crash-dump table are reached from
   service_start, service_stop, service_restart, service_rollback and
   service_update, all of which are syscalls and so run on whichever CPU the
   calling thread occupies. A few of these functions call each other, so the
   guard counts depth; see xaios_reentrant_lock. */
static xaios_reentrant_lock_t g_service_guard = XAIOS_REENTRANT_LOCK_INIT;

static void service_lock(void) {
  xaios_reentrant_lock(&g_service_guard, smp_cpu_id());
}

static void service_unlock(void) { xaios_reentrant_unlock(&g_service_guard); }

static xaios_service_t g_init_service;
static xaios_service_t g_manager_service;
static xaios_service_t g_worker_service;
static xaios_service_t g_child_service;
static uint64_t g_child_descriptor_count;
static uint64_t g_service_tree_edge_count;
static uint64_t g_service_transition_count;
static uint64_t g_service_restart_count;
static uint64_t g_service_crash_count;
static uint64_t g_service_cleanup_count;
static uint64_t g_service_log_record_count;
static uint64_t g_admin_policy_export_count;
static uint64_t g_admin_status_export_count;
static uint64_t g_admin_log_read_count;
static uint64_t g_admin_remote_safe_accept_count;
static uint64_t g_admin_remote_safe_reject_count;
static uint64_t g_admin_command_denial_count;

/* Crash dump ring buffer */
static xaios_crash_record_t g_crash_dumps[XAIOS_CRASH_DUMP_MAX];
static uint32_t g_crash_dump_count;

static int str_eq(const char *lhs, const char *rhs) {
  if (lhs == 0 || rhs == 0) {
    return 0;
  }

  while (*lhs != '\0' && *rhs != '\0') {
    if (*lhs != *rhs) {
      return 0;
    }
    ++lhs;
    ++rhs;
  }

  return *lhs == *rhs;
}

static uint8_t token_length(const char *token) {
  uint8_t len = 0;
  if (token == 0) {
    return 0;
  }
  while (token[len] != '\0' && len < UINT8_MAX) {
    ++len;
  }
  return len;
}

static void copy_str(char dst[XAIOS_POLICY_COPY_SIZE], const char *src) {
  if (dst == 0) {
    return;
  }
  uint8_t i = 0;
  while (i + 1U < XAIOS_POLICY_COPY_SIZE && src != 0 && src[i] != '\0') {
    dst[i] = src[i];
    ++i;
  }
  dst[i] = '\0';
}

static const char *service_state_name(xaios_service_state_t state) {
  switch (state) {
  case XAIOS_SERVICE_STOPPED:
    return "stopped";
  case XAIOS_SERVICE_STARTING:
    return "starting";
  case XAIOS_SERVICE_RUNNING:
    return "running";
  case XAIOS_SERVICE_EXITED:
    return "exited";
  case XAIOS_SERVICE_FAILED:
    return "failed";
  default:
    return "unknown";
  }
}

static xaios_status_t require_service_capability(uint64_t capability) {
  if (user_current_process() == 0) {
    return XAIOS_ERR_INVALID;
  }
  return user_process_has_capability(capability);
}

static xaios_status_t require_admin_capability(void) {
  const xaios_user_process_t *process = user_current_process();
  uint64_t granted = process != 0 ? process->capability_mask : 0;
  if (process == 0 ||
      user_process_has_capability(XAIOS_CAP_ADMIN) != XAIOS_OK) {
    ++g_admin_command_denial_count;
    if (process != 0) {
      (void)security_authorize_capability("admin.control", granted,
                                          XAIOS_CAP_ADMIN);
    }
    return XAIOS_ERR_INVALID;
  }
  return XAIOS_OK;
}

static xaios_status_t parse_u32(const char *value, uint32_t *out) {
  uint32_t parsed = 0;
  const char *cursor = value;
  if (out == 0 || value == 0 || *value == '\0') {
    return XAIOS_ERR_INVALID;
  }

  while (*cursor != '\0') {
    if (*cursor < '0' || *cursor > '9') {
      return XAIOS_ERR_INVALID;
    }
    if (parsed > (UINT32_MAX - (uint32_t)(*cursor - '0')) / 10U) {
      return XAIOS_ERR_INVALID;
    }
    parsed = (parsed * 10U) + (uint32_t)(*cursor - '0');
    ++cursor;
  }

  *out = parsed;
  return XAIOS_OK;
}

static void service_snapshot_capture(xaios_service_t *service) {
  copy_str(service->restart_policy_snapshot, service->restart_policy);
  copy_str(service->log_policy_snapshot, service->log_policy);
  service->max_restarts_snapshot = service->max_restarts;
  service->starts_snapshot = service->starts;
  service->restart_attempts_snapshot = service->restart_attempts;
  service->log_records_snapshot = service->log_records;
}

static void reset_service(xaios_service_t *service, const char *name) {
  service->name = name;
  service->parent_name = 0;
  service->restart_policy = k_policy_default;
  service->log_policy = k_log_off;
  service->max_restarts = UINT32_C(0xffffffff);
  service->state = XAIOS_SERVICE_STOPPED;
  service->exit_code = 0;
  service->starts = 0;
  service->restart_attempts = 0;
  service->log_records = 0;
  service->child_count = 0;
  service->crash_count = 0;
  service->cleanup_count = 0;
  service->update_attempts = 0;
  service->update_rejections = 0;
  service->rollback_count = 0;
  service->backoff_ns = 0;
  service->last_start_ns = 0;
  service->last_heartbeat_ns = 0;
  service->watchdog_enabled = 0;
  copy_str(service->restart_policy_snapshot, k_policy_default);
  copy_str(service->log_policy_snapshot, k_log_off);
  service->max_restarts_snapshot = service->max_restarts;
  service->starts_snapshot = 0;
  service->restart_attempts_snapshot = 0;
  service->log_records_snapshot = 0;
}

static xaios_service_t *find_service(const char *name) {
  if (str_eq(name, g_init_service.name)) {
    return &g_init_service;
  }
  if (str_eq(name, g_manager_service.name)) {
    return &g_manager_service;
  }
  if (str_eq(name, g_worker_service.name)) {
    return &g_worker_service;
  }
  if (g_child_service.name != 0 && str_eq(name, g_child_service.name)) {
    return &g_child_service;
  }
  return 0;
}

static void persist_service_state(xaios_service_t *service) {
  if (service == 0 || !str_eq(service->name, k_child_service_name)) {
    return;
  }
  xaios_status_t status = xaiboot_fs_record_service_state(
      service->name, service_state_name(service->state));
  if (status == XAIOS_OK) {
    klog("service: %s mutable-state persisted state=%s\n", service->name,
         service_state_name(service->state));
  } else {
    klog("service: %s mutable-state persist failed state=%s status=%u\n",
         service->name, service_state_name(service->state),
         (unsigned)status);
  }
}

static void service_snapshot_restore(xaios_service_t *service) {
  service->restart_policy = service->restart_policy_snapshot;
  service->log_policy = service->log_policy_snapshot;

  if (service->restart_policy[0] == '\0') {
    service->restart_policy = k_policy_default;
  }
  if (service->log_policy[0] == '\0') {
    service->log_policy = k_log_off;
  }

  service->max_restarts = service->max_restarts_snapshot;
  service->starts = service->starts_snapshot;
  service->restart_attempts = service->restart_attempts_snapshot;
  service->log_records = service->log_records_snapshot;
}

typedef struct service_config {
  const char *restart_policy;
  const char *log_policy;
  uint32_t max_restarts;
  uint32_t seen_fields;
} service_config_t;

static xaios_status_t parse_key_value(const char *token, const char *expected_key,
                                    const char **value_out) {
  if (token == 0) {
    return XAIOS_ERR_INVALID;
  }

  const char *sep = token;
  while (*sep != '\0' && *sep != '=') {
    ++sep;
  }
  if (*sep != '=' || sep == token) {
    return XAIOS_ERR_INVALID;
  }

  uint8_t key_len = token_length(token);
  if (expected_key != 0) {
    uint8_t expect_len = token_length(expected_key);
    uint8_t actual_len = (uint8_t)(sep - token);
    if (actual_len != expect_len) {
      return XAIOS_ERR_INVALID;
    }
    for (uint8_t i = 0; i < actual_len; ++i) {
      if (token[i] != expected_key[i]) {
        return XAIOS_ERR_INVALID;
      }
    }
  }

  if (sep[1] == '\0' || key_len >= XAIOS_CMD_TOKEN_BUFFER) {
    return XAIOS_ERR_INVALID;
  }

  if (value_out != 0) {
    value_out[0] = sep + 1U;
  }
  return XAIOS_OK;
}

static xaios_status_t parse_restart_token(const char *token, service_config_t *config) {
  const char *value = 0;
  if (parse_key_value(token, "restart", &value) != XAIOS_OK) {
    klog("service-manager: invalid restart field='%s'\n", token);
    return XAIOS_ERR_INVALID;
  }
  if (!str_eq(value, k_policy_never) && !str_eq(value, k_policy_always) &&
      !str_eq(value, k_policy_on_failure)) {
    return XAIOS_ERR_INVALID;
  }
  config->restart_policy = value;
  config->seen_fields |= 1U;
  return XAIOS_OK;
}

static xaios_status_t parse_log_token(const char *token, service_config_t *config) {
  const char *value = 0;
  if (parse_key_value(token, "log", &value) != XAIOS_OK) {
    klog("service-manager: invalid log field='%s'\n", token);
    return XAIOS_ERR_INVALID;
  }
  if (!str_eq(value, k_log_serial) && !str_eq(value, k_log_off)) {
    return XAIOS_ERR_INVALID;
  }
  config->log_policy = value;
  config->seen_fields |= 2U;
  return XAIOS_OK;
}

static xaios_status_t parse_max_restarts_token(const char *token,
                                             service_config_t *config) {
  const char *value = 0;
  if (parse_key_value(token, "max_restarts", &value) != XAIOS_OK) {
    klog("service-manager: invalid max_restarts field='%s'\n", token);
    return XAIOS_ERR_INVALID;
  }
  if (parse_u32(value, &config->max_restarts) != XAIOS_OK) {
    klog("service-manager: invalid max_restarts value='%s'\n", value);
    return XAIOS_ERR_INVALID;
  }
  config->seen_fields |= 4U;
  return XAIOS_OK;
}

static xaios_status_t apply_service_config(xaios_service_t *service,
                                          const service_config_t *config) {
  if (service == 0 || config == 0 ||
      (config->seen_fields & 7U) != 7U ||
      config->restart_policy == 0 ||
      config->log_policy == 0) {
    return XAIOS_ERR_INVALID;
  }

  service->restart_policy = k_policy_default;
  service->log_policy = k_log_off;
  service->max_restarts = config->max_restarts;

  if (str_eq(config->restart_policy, k_policy_never)) {
    service->restart_policy = k_policy_never;
  } else if (str_eq(config->restart_policy, k_policy_always)) {
    service->restart_policy = k_policy_always;
  } else if (str_eq(config->restart_policy, k_policy_on_failure)) {
    service->restart_policy = k_policy_on_failure;
  } else {
    return XAIOS_ERR_INVALID;
  }

  if (str_eq(config->log_policy, k_log_serial)) {
    service->log_policy = k_log_serial;
  } else if (str_eq(config->log_policy, k_log_off)) {
    service->log_policy = k_log_off;
  } else {
    return XAIOS_ERR_INVALID;
  }

  service_snapshot_capture(service);
  klog(
      "service-manager: configured %s restart=%s log=%s max_restarts=%lu\n",
      service->name, service->restart_policy, service->log_policy,
      (unsigned long)service->max_restarts);
  return XAIOS_OK;
}

static xaios_status_t configure_service(const char *service_name,
                                       const char *token3, const char *token4,
                                       const char *token5) {
  xaios_service_t *service = find_service(service_name);
  service_config_t config;
  config.restart_policy = 0;
  config.log_policy = 0;
  config.max_restarts = 0;
  config.seen_fields = 0;

  if (service == 0 || token3 == 0 || token4 == 0 || token5 == 0) {
    return XAIOS_ERR_INVALID;
  }

  if (parse_restart_token(token3, &config) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  if (parse_log_token(token4, &config) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  if (parse_max_restarts_token(token5, &config) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }

  return apply_service_config(service, &config);
}

static int token_safe(const char *token) {
  if (token == 0 || *token == '\0') {
    return 0;
  }
  for (uint32_t i = 0; token[i] != '\0'; ++i) {
    if (token[i] < ' ' || token[i] > '~') {
      return 0;
    }
  }
  return 1;
}

static xaios_status_t handle_status(const char *service_name) {
  xaios_service_t *service = find_service(service_name);
  if (service == 0) {
    return XAIOS_ERR_INVALID;
  }
  klog(
      "osctl: %s state=%s starts=%lu restarts=%lu logs=%lu restart_policy=%s "
      "log_policy=%s max_restarts=%lu exit_code=%u\n",
      service->name, service_state_name(service->state), service->starts,
      service->restart_attempts, service->log_records,
      service->restart_policy, service->log_policy,
      (unsigned long)service->max_restarts, (unsigned)service->exit_code);
  return XAIOS_OK;
}

static xaios_status_t handle_admin_policy(void) {
  if (require_admin_capability() != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  ++g_admin_policy_export_count;
  klog("admin: policy ssh_only=1 password_login=0 admin_cap_required=1 remote_safe_allowlist=1 exports=%lu\n",
       g_admin_policy_export_count);
  return XAIOS_OK;
}

static xaios_status_t handle_admin_status(const char *service_name,
                                         uint32_t persist) {
  xaios_service_t *service = find_service(service_name);
  if (require_admin_capability() != XAIOS_OK || service == 0) {
    return XAIOS_ERR_INVALID;
  }
  klog("admin: status service=%s state=%s starts=%lu restarts=%lu logs=%lu crashes=%lu cleanups=%lu\n",
       service->name, service_state_name(service->state), service->starts,
       service->restart_attempts, service->log_records, service->crash_count,
       service->cleanup_count);
  if (persist != 0 &&
      xaiboot_fs_record_admin_status(service->name,
                                     service_state_name(service->state),
                                     (uint32_t)service->starts,
                                     (uint32_t)service->restart_attempts,
                                     (uint32_t)service->log_records) !=
          XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  ++g_admin_status_export_count;
  return XAIOS_OK;
}

static xaios_status_t handle_admin_logs(const char *service_name) {
  xaios_service_t *service = find_service(service_name);
  if (require_admin_capability() != XAIOS_OK || service == 0) {
    return XAIOS_ERR_INVALID;
  }
  ++g_admin_log_read_count;
  klog("admin: logs service=%s records=%lu log_policy=%s exit_code=%u reads=%lu\n",
       service->name, service->log_records, service->log_policy,
       (unsigned)service->exit_code, g_admin_log_read_count);
  return XAIOS_OK;
}

static xaios_status_t handle_admin_remote_safe(const char *command) {
  if (require_admin_capability() != XAIOS_OK || command == 0 ||
      token_safe(command) == 0) {
    return XAIOS_ERR_INVALID;
  }
  if (str_eq(command, "status") || str_eq(command, "logs") ||
      str_eq(command, "export")) {
    ++g_admin_remote_safe_accept_count;
    klog("admin: remote-safe command=%s accepted accepts=%lu\n", command,
         g_admin_remote_safe_accept_count);
    return XAIOS_OK;
  }
  ++g_admin_remote_safe_reject_count;
  klog("admin: remote-safe command=%s rejected rejects=%lu\n", command,
       g_admin_remote_safe_reject_count);
  return XAIOS_ERR_INVALID;
}

static xaios_status_t handle_log(const char *service_name, const char *message) {
  xaios_service_t *service = find_service(service_name);
  if (service == 0 || !token_safe(message)) {
    return XAIOS_ERR_INVALID;
  }
  if (security_reject_credential_material(message) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  ++service->log_records;
  ++g_service_log_record_count;
  klog("service-manager: log %s %s records=%lu\n", service_name, message,
       service->log_records);
  return XAIOS_OK;
}

static xaios_status_t start_service(xaios_service_t *service) {
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
  ++g_service_transition_count;
  service->last_start_ns = wall_time_now_ns();
  service->last_heartbeat_ns = service->last_start_ns;
  service->watchdog_enabled = 1;
  service->backoff_ns = 0;
  klog("service: %s state=starting parent=%s\n", service->name,
       service->parent_name != 0 ? service->parent_name : "(root)");
  service->state = XAIOS_SERVICE_RUNNING;
  ++g_service_transition_count;
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
  ++g_service_cleanup_count;
  klog("service-supervisor: cleanup %s reason=%s cleanups=%lu\n",
       service->name, reason, service->cleanup_count);
}

static xaios_status_t supervisor_restart_failed_child(xaios_service_t *service) {
  if (service == 0) {
    return XAIOS_ERR_INVALID;
  }
  if (!str_eq(service->restart_policy, k_policy_always) &&
      !str_eq(service->restart_policy, k_policy_on_failure)) {
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
  ++g_service_transition_count;
  klog("service-supervisor: restarting child %s parent=%s attempt=%lu\n",
       service->name, service->parent_name != 0 ? service->parent_name : "(root)",
       service->restart_attempts);
  if (start_service(service) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  ++g_service_restart_count;
  return XAIOS_OK;
}

static xaios_status_t mark_service_exit(xaios_service_t *service, int exit_code,
                                       uint32_t supervise) {
  if (service == 0 || service->state != XAIOS_SERVICE_RUNNING) {
    return XAIOS_ERR_INVALID;
  }

  service->exit_code = exit_code;
  service->state =
      exit_code == 0 ? XAIOS_SERVICE_EXITED : XAIOS_SERVICE_FAILED;
  ++g_service_transition_count;
  if (exit_code != 0) {
    ++service->crash_count;
    ++g_service_crash_count;
  }
  klog("service: %s state=%s exit_code=%u\n", service->name,
       service_state_name(service->state), (unsigned)exit_code);
  persist_service_state(service);

  /* Capture crash dump on non-zero exit */
  if (exit_code != 0) {
    uint32_t idx = g_crash_dump_count % XAIOS_CRASH_DUMP_MAX;
    xaios_crash_record_t *rec = &g_crash_dumps[idx];
    rec->service_name = service->name;
    rec->exit_code = exit_code;
    rec->crash_timestamp_ns = wall_time_now_ns();
    rec->restart_count = service->restart_attempts;
    rec->uptime_ns = service->last_start_ns > 0
                         ? (rec->crash_timestamp_ns - service->last_start_ns)
                         : 0;
    ++g_crash_dump_count;
    klog("service-supervisor: crash-dump %s code=%u uptime=%lu ns dumps=%u\n",
         service->name, (unsigned)exit_code, rec->uptime_ns,
         g_crash_dump_count);
  }

  if (supervise != 0 && exit_code != 0) {
    return supervisor_restart_failed_child(service);
  }
  if (exit_code == 0) {
    cleanup_service_runtime(service, "exit");
  }
  return XAIOS_OK;
}

static xaios_status_t handle_restart(const char *service_name) {
  xaios_service_t *service = find_service(service_name);
  if (service == 0) {
    return XAIOS_ERR_INVALID;
  }

  ++service->restart_attempts;
  if (str_eq(service->restart_policy, k_policy_never)) {
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
  ++g_service_transition_count;
  klog("service-manager: restart allowed %s attempts=%lu\n",
       service->name, service->restart_attempts);
  if (start_service(service) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  ++g_service_restart_count;
  return XAIOS_OK;
}

static xaios_status_t handle_start(const char *service_name) {
  xaios_service_t *service = find_service(service_name);
  if (service == 0) {
    return XAIOS_ERR_INVALID;
  }
  return start_service(service);
}

static xaios_status_t handle_update(const char *signature) {
  if (signature == 0 || signature[0] == '\0') {
    security_record_denied_operation();
    return XAIOS_ERR_INVALID;
  }
  if (security_reject_credential_material(signature) != XAIOS_OK) {
    ++g_init_service.update_rejections;
    return XAIOS_ERR_INVALID;
  }
  if (require_service_capability(XAIOS_CAP_UPDATE) != XAIOS_OK) {
    ++g_init_service.update_rejections;
    const xaios_user_process_t *process = user_current_process();
    uint64_t granted = process != 0 ? process->capability_mask : 0;
    (void)security_authorize_capability("service.update", granted,
                                        XAIOS_CAP_UPDATE);
    return XAIOS_ERR_INVALID;
  }

  if (token_safe(signature) == 0 ||
      security_authorize_update_signature(signature,
                                          user_current_process()
                                              ->capability_mask) != XAIOS_OK) {
    ++g_init_service.update_rejections;
    return XAIOS_ERR_INVALID;
  }

  ++g_init_service.update_attempts;
  klog("service-manager: update token accepted length=%lu\n",
       (unsigned long)token_length(signature));
  return XAIOS_OK;
}

static xaios_status_t handle_rollback(const char *service_name) {
  if (!str_eq(service_name, g_init_service.name)) {
    return XAIOS_ERR_INVALID;
  }
  if (require_service_capability(XAIOS_CAP_SERVICE_ROLLBACK) != XAIOS_OK) {
    ++g_init_service.rollback_count;
    (void)security_authorize_rollback(service_name, 0);
    return XAIOS_ERR_INVALID;
  }
  if (security_authorize_rollback(service_name, 1) != XAIOS_OK) {
    ++g_init_service.rollback_count;
    return XAIOS_ERR_INVALID;
  }

  service_snapshot_restore(&g_init_service);
  ++g_init_service.rollback_count;
  klog("service-manager: rollback /init restart=%s log=%s max_restarts=%lu\n",
       g_init_service.restart_policy, g_init_service.log_policy,
       (unsigned long)g_init_service.max_restarts);
  return XAIOS_OK;
}

static xaios_status_t handle_stop(const char *service_name) {
  xaios_service_t *service = find_service(service_name);
  return mark_service_exit(service, 0, 0);
}

static xaios_status_t parse_exit_code_token(const char *token, int *exit_code) {
  const char *value = 0;
  uint32_t parsed = 0;
  if (exit_code == 0 || parse_key_value(token, "code", &value) != XAIOS_OK ||
      parse_u32(value, &parsed) != XAIOS_OK || parsed == 0 ||
      parsed > INT32_MAX) {
    return XAIOS_ERR_INVALID;
  }
  *exit_code = (int)parsed;
  return XAIOS_OK;
}

static xaios_status_t handle_crash(const char *service_name,
                                  const char *code_token) {
  xaios_service_t *service = find_service(service_name);
  int exit_code = 0;
  if (service == 0 ||
      parse_exit_code_token(code_token, &exit_code) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  klog("service-supervisor: observed crash %s code=%u parent=%s\n",
       service->name, (unsigned)exit_code,
       service->parent_name != 0 ? service->parent_name : "(root)");
  return mark_service_exit(service, exit_code, 1);
}

static xaios_status_t handle_define(const char *service_name,
                                   const char *parent_token,
                                   const char *restart_token) {
  const char *parent = 0;
  const char *restart = 0;
  xaios_service_t *parent_service = 0;
  if (!str_eq(service_name, k_child_service_name) ||
      parse_key_value(parent_token, "parent", &parent) != XAIOS_OK ||
      parse_key_value(restart_token, "restart", &restart) != XAIOS_OK ||
      !str_eq(parent, k_child_parent_name) ||
      (!str_eq(restart, k_policy_never) && !str_eq(restart, k_policy_always))) {
    return XAIOS_ERR_INVALID;
  }
  parent_service = find_service(parent);
  if (parent_service == 0) {
    return XAIOS_ERR_INVALID;
  }

  reset_service(&g_child_service, k_child_service_name);
  g_child_service.parent_name = k_child_parent_name;
  g_child_service.restart_policy =
      str_eq(restart, k_policy_always) ? k_policy_always : k_policy_never;
  ++g_child_descriptor_count;
  ++g_service_tree_edge_count;
  ++parent_service->child_count;
  klog("service-manager: defined child %s parent=%s restart=%s descriptors=%lu\n",
       g_child_service.name, k_child_parent_name, g_child_service.restart_policy,
       g_child_descriptor_count);
  klog("service-supervisor: tree parent=%s child=%s children=%lu edges=%lu\n",
       parent_service->name, g_child_service.name, parent_service->child_count,
       g_service_tree_edge_count);
  return XAIOS_OK;
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

void service_supervisor_init(void) {
  reset_service(&g_init_service, k_init_service_name);
  reset_service(&g_manager_service, k_manager_service_name);
  reset_service(&g_worker_service, k_worker_service_name);
  reset_service(&g_child_service, 0);
  g_child_descriptor_count = 0;
  g_service_tree_edge_count = 0;
  g_service_transition_count = 0;
  g_service_restart_count = 0;
  g_service_crash_count = 0;
  g_service_cleanup_count = 0;
  g_service_log_record_count = 0;
  g_admin_policy_export_count = 0;
  g_admin_status_export_count = 0;
  g_admin_log_read_count = 0;
  g_admin_remote_safe_accept_count = 0;
  g_admin_remote_safe_reject_count = 0;
  g_admin_command_denial_count = 0;
  g_crash_dump_count = 0;
  for (uint32_t i = 0; i < XAIOS_CRASH_DUMP_MAX; ++i) {
    g_crash_dumps[i].service_name = 0;
    g_crash_dumps[i].exit_code = 0;
    g_crash_dumps[i].crash_timestamp_ns = 0;
    g_crash_dumps[i].restart_count = 0;
    g_crash_dumps[i].uptime_ns = 0;
  }
  service_snapshot_capture(&g_init_service);
  klog("service: supervisor initialized\n");
}

xaios_status_t service_start_init(void) {
  return service_start(k_init_service_name);
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

xaios_status_t service_snapshot(const char *name, xaios_service_t *snapshot) {
  xaios_service_t *service = find_service(name);
  if (service == 0 || snapshot == 0) {
    return XAIOS_ERR_NOT_FOUND;
  }
  *snapshot = *service;
  return XAIOS_OK;
}

uint32_t service_count(void) {
  return g_child_service.name != 0 ? 4U : 3U;
}

xaios_status_t service_snapshot_at(uint32_t index,
                                   xaios_service_t *snapshot) {
  xaios_service_t *service = 0;
  if (snapshot == 0) return XAIOS_ERR_INVALID;
  switch (index) {
    case 0U: service = &g_init_service; break;
    case 1U: service = &g_manager_service; break;
    case 2U: service = &g_worker_service; break;
    case 3U:
      if (g_child_service.name != 0) service = &g_child_service;
      break;
    default: break;
  }
  if (service == 0) return XAIOS_ERR_NOT_FOUND;
  *snapshot = *service;
  return XAIOS_OK;
}

static xaios_status_t service_start_unlocked(const char *name) {
  xaios_service_t *service = find_service(name);
  if (service == 0) {
    return XAIOS_ERR_INVALID;
  }
  return start_service(service);
}

xaios_status_t service_start(const char *name) {
  service_lock();
  xaios_status_t result = service_start_unlocked(name);
  service_unlock();
  return result;
}

static xaios_status_t service_stop_unlocked(const char *name) {
  return handle_stop(name);
}

xaios_status_t service_stop(const char *name) {
  service_lock();
  xaios_status_t result = service_stop_unlocked(name);
  service_unlock();
  return result;
}

static xaios_status_t service_restart_unlocked(const char *name) {
  return handle_restart(name);
}

xaios_status_t service_restart(const char *name) {
  service_lock();
  xaios_status_t result = service_restart_unlocked(name);
  service_unlock();
  return result;
}

static xaios_status_t service_rollback_unlocked(const char *name) {
  return handle_rollback(name);
}

xaios_status_t service_rollback(const char *name) {
  service_lock();
  xaios_status_t result = service_rollback_unlocked(name);
  service_unlock();
  return result;
}

static xaios_status_t service_update_unlocked(const char *signature) {
  return handle_update(signature);
}

xaios_status_t service_update(const char *signature) {
  service_lock();
  xaios_status_t result = service_update_unlocked(signature);
  service_unlock();
  return result;
}

static xaios_status_t service_exit_unlocked(const char *name, int exit_code) {
  xaios_service_t *service = find_service(name);
  return mark_service_exit(service, exit_code, 0);
}

xaios_status_t service_exit(const char *name, int exit_code) {
  service_lock();
  xaios_status_t result = service_exit_unlocked(name, exit_code);
  service_unlock();
  return result;
}

xaios_status_t service_heartbeat(const char *name) {
  xaios_service_t *service = find_service(name);
  if (service == 0 || service->state != XAIOS_SERVICE_RUNNING) {
    return XAIOS_ERR_INVALID;
  }
  service->last_heartbeat_ns = wall_time_now_ns();
  return XAIOS_OK;
}

void service_watchdog_check(void) {
  uint64_t now = wall_time_now_ns();
  xaios_service_t *services[] = {&g_init_service, &g_manager_service,
                                &g_worker_service, &g_child_service};
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
      mark_service_exit(svc, -1, 1);
    }
  }
}

uint32_t service_crash_dump_count(void) {
  return g_crash_dump_count;
}

const xaios_crash_record_t *service_crash_dump_get(uint32_t index) {
  if (index >= XAIOS_CRASH_DUMP_MAX) {
    return 0;
  }
  return &g_crash_dumps[index];
}

static xaios_status_t handle_osctl_command(const char *action,
                                          uint32_t argc) {
  if (action == 0 || argc != 2U) {
    return XAIOS_ERR_INVALID;
  }

  if (str_eq(action, "status")) {
    klog("osctl: status legacy=1 processes=%lu services=%lu ai_cells=%lu\n",
         user_process_active_count(), service_transition_count(),
         ai_cell_transition_count());
    return XAIOS_OK;
  }
  if (str_eq(action, "ps")) {
    klog("osctl: ps slots=%u loaded=%lu runnable=%lu running=%lu exited=%lu failed=%lu scheduled=%lu active=%lu\n",
         XAIOS_MAX_USER_PROCESSES, user_process_loaded_count(),
         user_process_runnable_count(), user_process_running_count(),
         user_process_exited_count(), user_process_failed_count(),
         user_process_scheduled_count(), user_process_active_count());
    return XAIOS_OK;
  }
  if (str_eq(action, "services")) {
    klog("osctl: services transitions=%lu restarts=%lu crashes=%lu cleanups=%lu descriptors=%lu logs=%lu\n",
         service_transition_count(), service_restart_count(),
         service_crash_count(), service_cleanup_count(),
         service_child_descriptor_count(), service_log_record_count());
    return XAIOS_OK;
  }
  if (str_eq(action, "cells")) {
    klog("osctl: cells transitions=%lu admissions=%lu rejects=%lu queue_binds=%lu workspace_binds=%lu conflicts=%lu\n",
         ai_cell_transition_count(), ai_cell_resource_admission_count(),
         ai_cell_resource_reject_count(), ai_cell_queue_bind_count(),
         ai_cell_workspace_bind_count(), ai_cell_conflict_count());
    return XAIOS_OK;
  }
  if (str_eq(action, "fs")) {
    klog("osctl: fs files=%lu directories=%lu writes=%lu reads=%lu commits=%lu rollbacks=%lu checksum_errors=%lu\n",
         xaiboot_fs_file_count(), xaiboot_fs_directory_count(),
         xaiboot_fs_write_count(), xaiboot_fs_read_count(),
         xaiboot_fs_commit_count(), xaiboot_fs_rollback_count(),
         xaiboot_fs_checksum_error_count());
    return XAIOS_OK;
  }
  if (str_eq(action, "net")) {
    klog("osctl: net udp_tx=%lu udp_rx=%lu tcp_established=%lu tcp_closed=%lu rx=%lu tx=%lu drops=%lu flow_mismatches=%lu\n",
         network_stack_udp_tx_count(), network_stack_udp_rx_count(),
         network_stack_tcp_established_count(), network_stack_tcp_closed_count(),
         network_stack_rx_packet_count(), network_stack_tx_packet_count(),
         network_stack_packet_drop_count(),
         network_stack_flow_core_mismatch_count());
    return XAIOS_OK;
  }
  if (str_eq(action, "telemetry")) {
    klog("osctl: telemetry cpu_ai_loads=%lu shared_binds=%lu kv_writes=%lu security_denials=%lu updates=%lu rollbacks=%lu\n",
         cpu_ai_runtime_model_load_count(),
         cpu_ai_runtime_shared_weight_bind_count(),
         cpu_ai_runtime_kv_write_count(), security_denied_operation_count(),
         update_transaction_count(), update_rollback_count());
    return XAIOS_OK;
  }
  if (str_eq(action, "update")) {
    klog("osctl: update transactions=%lu staged=%lu committed=%lu failures=%lu recoveries=%lu rejects=%lu\n",
         update_transaction_count(), update_stage_count(), update_commit_count(),
         update_failure_count(), update_recovery_count(), update_reject_count());
    return XAIOS_OK;
  }
  if (str_eq(action, "rollback")) {
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
    if (!token_safe(tokens[token_index])) {
      klog("service: osctl invalid token index=%lu value='%s'\n",
           (unsigned long)token_index,
           tokens[token_index] != 0 ? tokens[token_index] : "(null)");
      return XAIOS_ERR_INVALID;
    }
  }

  if (str_eq(tokens[0], "osctl")) {
    return handle_osctl_command(tokens[1], argc);
  }

  if (str_eq(tokens[0], "admin")) {
    const char *action = tokens[1];
    if (str_eq(action, "policy") && argc == 2U) {
      return handle_admin_policy();
    }
    if (str_eq(action, "status") && argc == 3U) {
      return handle_admin_status(tokens[2], 0);
    }
    if (str_eq(action, "export") && argc == 3U) {
      return handle_admin_status(tokens[2], 1);
    }
    if (str_eq(action, "logs") && argc == 3U) {
      return handle_admin_logs(tokens[2]);
    }
    if (str_eq(action, "remote-safe") && argc == 3U) {
      return handle_admin_remote_safe(tokens[2]);
    }
    klog("admin: unsupported command name='%s' argc=%lu\n", action,
         (unsigned long)argc);
    return XAIOS_ERR_INVALID;
  }

  if (!str_eq(tokens[0], "service")) {
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

  if (!token_safe(action)) {
    return XAIOS_ERR_INVALID;
  }

  if (str_eq(action, "define") && argc == 5U) {
    return handle_define(service, tokens[3], tokens[4]);
  }
  if (str_eq(action, "status") && argc == 3U) {
    return handle_status(service);
  }
  if (str_eq(action, "configure") && argc == 6U) {
    klog("service: osctl command argc=%lu token3=%s token4=%s token5=%s\n",
         (unsigned long)argc, tokens[3], tokens[4], tokens[5]);
    return configure_service(service, tokens[3], tokens[4], tokens[5]);
  }
  if (str_eq(action, "log") && argc == 4U) {
    return handle_log(service, tokens[3]);
  }
  if (str_eq(action, "restart") && argc == 3U) {
    return handle_restart(service);
  }
  if (str_eq(action, "crash") && argc == 4U) {
    return handle_crash(service, tokens[3]);
  }
  if (str_eq(action, "start") && argc == 3U) {
    return handle_start(service);
  }
  if (str_eq(action, "stop") && argc == 3U) {
    return handle_stop(service);
  }
  if (str_eq(action, "rollback") && argc == 3U) {
    return handle_rollback(service);
  }
  if (str_eq(action, "update") && argc == 4U) {
    return handle_update(tokens[3]);
  }

  klog("service: osctl unsupported command name='%s' argc=%lu\n", action,
       (unsigned long)argc);
  return XAIOS_ERR_INVALID;
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
  reset_service(&g_child_service, 0);
  kassert(osctl_execute(
              "service define /svc/source-index parent=/init restart=on-failure") ==
          XAIOS_OK);
  kassert(osctl_execute(
              "service configure /svc/source-index restart=on-failure log=serial max_restarts=5") ==
          XAIOS_OK);
  kassert(osctl_execute("service start /svc/source-index") == XAIOS_OK);
  /* Clean exit should NOT restart under on-failure */
  kassert(service_exit("/svc/source-index", 0) == XAIOS_OK);
  kassert(g_child_service.state == XAIOS_SERVICE_EXITED);

  /* Crash should produce crash dump */
  kassert(osctl_execute("service start /svc/source-index") == XAIOS_OK);
  kassert(osctl_execute("service crash /svc/source-index code=11") == XAIOS_OK);
  kassert(g_crash_dump_count >= 2);
  kassert(g_crash_dumps[(g_crash_dump_count - 1U) % XAIOS_CRASH_DUMP_MAX].exit_code == 11);

  /* Verify backoff increased */
  kassert(g_child_service.backoff_ns >= XAIOS_BACKOFF_BASE_NS);

  klog("service: supervisor self-test passed\n");
}

uint64_t service_child_descriptor_count(void) {
  return g_child_descriptor_count;
}

uint64_t service_tree_edge_count(void) {
  return g_service_tree_edge_count;
}

uint64_t service_transition_count(void) {
  return g_service_transition_count;
}

uint64_t service_restart_count(void) {
  return g_service_restart_count;
}

uint64_t service_crash_count(void) {
  return g_service_crash_count;
}

uint64_t service_cleanup_count(void) {
  return g_service_cleanup_count;
}

uint64_t service_log_record_count(void) {
  return g_service_log_record_count;
}

uint64_t service_admin_policy_export_count(void) {
  return g_admin_policy_export_count;
}

uint64_t service_admin_status_export_count(void) {
  return g_admin_status_export_count;
}

uint64_t service_admin_log_read_count(void) {
  return g_admin_log_read_count;
}

uint64_t service_admin_remote_safe_accept_count(void) {
  return g_admin_remote_safe_accept_count;
}

uint64_t service_admin_remote_safe_reject_count(void) {
  return g_admin_remote_safe_reject_count;
}

uint64_t service_admin_command_denial_count(void) {
  return g_admin_command_denial_count;
}
