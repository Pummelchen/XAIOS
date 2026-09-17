/* Service registry: the four service records, the crash-dump ring, the
   service counters, the configuration parser and the public snapshot and
   counter accessors.

   The reentrant service lock stays in service.c beside the public entry
   points that take it, so nothing here locks: callers arrive either already
   holding the lock or, for the lock-free readers, exactly as before the
   split. */

#include <xaios/klog.h>
#include <xaios/security.h>
#include <xaios/service.h>
#include <xaios/syscall.h>
#include <xaios/user.h>

#include "service_internal.h"

#define XAIOS_POLICY_COPY_SIZE 16U

const char svc_policy_never[] = "never";
const char svc_policy_always[] = "always";
const char svc_policy_on_failure[] = "on-failure";
const char svc_policy_default[] = "unset";
const char svc_log_serial[] = "serial";
const char svc_log_off[] = "off";
const char svc_init_service_name[] = "/init";
const char svc_manager_service_name[] = "/bin/service-manager";
const char svc_worker_service_name[] = "/bin/xaios-worker";
const char svc_child_service_name[] = "/svc/source-index";
const char svc_child_parent_name[] = "/init";

/* C-01: these service records and the crash-dump table are reached from
   service_start, service_stop, service_restart, service_rollback and
   service_update, all of which are syscalls and so run on whichever CPU the
   calling thread occupies. A few of these functions call each other, so the
   guard counts depth; see xaios_reentrant_lock. The guard itself lives in
   service.c, next to the public entry points that take it. */
xaios_service_t svc_init_service;
xaios_service_t svc_manager_service;
xaios_service_t svc_worker_service;
xaios_service_t svc_child_service;
uint64_t svc_child_descriptor_count;
uint64_t svc_tree_edge_count;
uint64_t svc_transition_count;
uint64_t svc_restart_count;
uint64_t svc_crash_count;
uint64_t svc_cleanup_count;
uint64_t svc_log_record_count;
uint64_t svc_admin_policy_export_count;
uint64_t svc_admin_status_export_count;
uint64_t svc_admin_log_read_count;
uint64_t svc_admin_remote_safe_accept_count;
uint64_t svc_admin_remote_safe_reject_count;
uint64_t svc_admin_command_denial_count;

/* Crash dump ring buffer */
xaios_crash_record_t svc_crash_dumps[XAIOS_CRASH_DUMP_MAX];
uint32_t svc_crash_dump_count;

int svc_str_eq(const char *lhs, const char *rhs) {
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

uint8_t svc_token_length(const char *token) {
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

int svc_token_safe(const char *token) {
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

const char *svc_state_name(xaios_service_state_t state) {
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

xaios_status_t svc_require_service_capability(uint64_t capability) {
  if (user_current_process() == 0) {
    return XAIOS_ERR_INVALID;
  }
  return user_process_has_capability(capability);
}

xaios_status_t svc_require_admin_capability(void) {
  const xaios_user_process_t *process = user_current_process();
  uint64_t granted = process != 0 ? process->capability_mask : 0;
  if (process == 0 ||
      user_process_has_capability(XAIOS_CAP_ADMIN) != XAIOS_OK) {
    ++svc_admin_command_denial_count;
    if (process != 0) {
      (void)security_authorize_capability("admin.control", granted,
                                          XAIOS_CAP_ADMIN);
    }
    return XAIOS_ERR_INVALID;
  }
  return XAIOS_OK;
}

xaios_status_t svc_parse_u32(const char *value, uint32_t *out) {
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

void svc_snapshot_capture(xaios_service_t *service) {
  copy_str(service->restart_policy_snapshot, service->restart_policy);
  copy_str(service->log_policy_snapshot, service->log_policy);
  service->max_restarts_snapshot = service->max_restarts;
  service->starts_snapshot = service->starts;
  service->restart_attempts_snapshot = service->restart_attempts;
  service->log_records_snapshot = service->log_records;
}

void svc_reset_service(xaios_service_t *service, const char *name) {
  service->name = name;
  service->parent_name = 0;
  service->restart_policy = svc_policy_default;
  service->log_policy = svc_log_off;
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
  copy_str(service->restart_policy_snapshot, svc_policy_default);
  copy_str(service->log_policy_snapshot, svc_log_off);
  service->max_restarts_snapshot = service->max_restarts;
  service->starts_snapshot = 0;
  service->restart_attempts_snapshot = 0;
  service->log_records_snapshot = 0;
}

xaios_service_t *svc_find_service(const char *name) {
  if (svc_str_eq(name, svc_init_service.name)) {
    return &svc_init_service;
  }
  if (svc_str_eq(name, svc_manager_service.name)) {
    return &svc_manager_service;
  }
  if (svc_str_eq(name, svc_worker_service.name)) {
    return &svc_worker_service;
  }
  if (svc_child_service.name != 0 && svc_str_eq(name, svc_child_service.name)) {
    return &svc_child_service;
  }
  return 0;
}

void svc_snapshot_restore(xaios_service_t *service) {
  service->restart_policy = service->restart_policy_snapshot;
  service->log_policy = service->log_policy_snapshot;

  if (service->restart_policy[0] == '\0') {
    service->restart_policy = svc_policy_default;
  }
  if (service->log_policy[0] == '\0') {
    service->log_policy = svc_log_off;
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

xaios_status_t svc_parse_key_value(const char *token, const char *expected_key,
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

  uint8_t key_len = svc_token_length(token);
  if (expected_key != 0) {
    uint8_t expect_len = svc_token_length(expected_key);
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
  if (svc_parse_key_value(token, "restart", &value) != XAIOS_OK) {
    klog("service-manager: invalid restart field='%s'\n", token);
    return XAIOS_ERR_INVALID;
  }
  if (!svc_str_eq(value, svc_policy_never) &&
      !svc_str_eq(value, svc_policy_always) &&
      !svc_str_eq(value, svc_policy_on_failure)) {
    return XAIOS_ERR_INVALID;
  }
  config->restart_policy = value;
  config->seen_fields |= 1U;
  return XAIOS_OK;
}

static xaios_status_t parse_log_token(const char *token, service_config_t *config) {
  const char *value = 0;
  if (svc_parse_key_value(token, "log", &value) != XAIOS_OK) {
    klog("service-manager: invalid log field='%s'\n", token);
    return XAIOS_ERR_INVALID;
  }
  if (!svc_str_eq(value, svc_log_serial) && !svc_str_eq(value, svc_log_off)) {
    return XAIOS_ERR_INVALID;
  }
  config->log_policy = value;
  config->seen_fields |= 2U;
  return XAIOS_OK;
}

static xaios_status_t parse_max_restarts_token(const char *token,
                                             service_config_t *config) {
  const char *value = 0;
  if (svc_parse_key_value(token, "max_restarts", &value) != XAIOS_OK) {
    klog("service-manager: invalid max_restarts field='%s'\n", token);
    return XAIOS_ERR_INVALID;
  }
  if (svc_parse_u32(value, &config->max_restarts) != XAIOS_OK) {
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

  service->restart_policy = svc_policy_default;
  service->log_policy = svc_log_off;
  service->max_restarts = config->max_restarts;

  if (svc_str_eq(config->restart_policy, svc_policy_never)) {
    service->restart_policy = svc_policy_never;
  } else if (svc_str_eq(config->restart_policy, svc_policy_always)) {
    service->restart_policy = svc_policy_always;
  } else if (svc_str_eq(config->restart_policy, svc_policy_on_failure)) {
    service->restart_policy = svc_policy_on_failure;
  } else {
    return XAIOS_ERR_INVALID;
  }

  if (svc_str_eq(config->log_policy, svc_log_serial)) {
    service->log_policy = svc_log_serial;
  } else if (svc_str_eq(config->log_policy, svc_log_off)) {
    service->log_policy = svc_log_off;
  } else {
    return XAIOS_ERR_INVALID;
  }

  svc_snapshot_capture(service);
  klog(
      "service-manager: configured %s restart=%s log=%s max_restarts=%lu\n",
      service->name, service->restart_policy, service->log_policy,
      (unsigned long)service->max_restarts);
  return XAIOS_OK;
}

xaios_status_t svc_configure_service(const char *service_name,
                                     const char *token3, const char *token4,
                                     const char *token5) {
  xaios_service_t *service = svc_find_service(service_name);
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

xaios_status_t service_snapshot(const char *name, xaios_service_t *snapshot) {
  xaios_service_t *service = svc_find_service(name);
  if (service == 0 || snapshot == 0) {
    return XAIOS_ERR_NOT_FOUND;
  }
  *snapshot = *service;
  return XAIOS_OK;
}

uint32_t service_count(void) {
  return svc_child_service.name != 0 ? 4U : 3U;
}

xaios_status_t service_snapshot_at(uint32_t index,
                                   xaios_service_t *snapshot) {
  xaios_service_t *service = 0;
  if (snapshot == 0) return XAIOS_ERR_INVALID;
  switch (index) {
    case 0U: service = &svc_init_service; break;
    case 1U: service = &svc_manager_service; break;
    case 2U: service = &svc_worker_service; break;
    case 3U:
      if (svc_child_service.name != 0) service = &svc_child_service;
      break;
    default: break;
  }
  if (service == 0) return XAIOS_ERR_NOT_FOUND;
  *snapshot = *service;
  return XAIOS_OK;
}

uint32_t service_crash_dump_count(void) {
  return svc_crash_dump_count;
}

const xaios_crash_record_t *service_crash_dump_get(uint32_t index) {
  if (index >= XAIOS_CRASH_DUMP_MAX) {
    return 0;
  }
  return &svc_crash_dumps[index];
}

uint64_t service_child_descriptor_count(void) {
  return svc_child_descriptor_count;
}

uint64_t service_tree_edge_count(void) {
  return svc_tree_edge_count;
}

uint64_t service_transition_count(void) {
  return svc_transition_count;
}

uint64_t service_restart_count(void) {
  return svc_restart_count;
}

uint64_t service_crash_count(void) {
  return svc_crash_count;
}

uint64_t service_cleanup_count(void) {
  return svc_cleanup_count;
}

uint64_t service_log_record_count(void) {
  return svc_log_record_count;
}

uint64_t service_admin_policy_export_count(void) {
  return svc_admin_policy_export_count;
}

uint64_t service_admin_status_export_count(void) {
  return svc_admin_status_export_count;
}

uint64_t service_admin_log_read_count(void) {
  return svc_admin_log_read_count;
}

uint64_t service_admin_remote_safe_accept_count(void) {
  return svc_admin_remote_safe_accept_count;
}

uint64_t service_admin_remote_safe_reject_count(void) {
  return svc_admin_remote_safe_reject_count;
}

uint64_t service_admin_command_denial_count(void) {
  return svc_admin_command_denial_count;
}
