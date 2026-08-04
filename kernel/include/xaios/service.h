#ifndef XAIOS_SERVICE_H
#define XAIOS_SERVICE_H

#include <xaios/status.h>
#include <xaios/types.h>

typedef enum xaios_service_state {
  XAIOS_SERVICE_STOPPED = 0,
  XAIOS_SERVICE_STARTING = 1,
  XAIOS_SERVICE_RUNNING = 2,
  XAIOS_SERVICE_EXITED = 3,
  XAIOS_SERVICE_FAILED = 4,
} xaios_service_state_t;

#define XAIOS_CRASH_DUMP_MAX 8U
#define XAIOS_BACKOFF_BASE_NS UINT64_C(1000000000)
#define XAIOS_BACKOFF_CAP_NS UINT64_C(60000000000)
#define XAIOS_WATCHDOG_TIMEOUT_NS UINT64_C(30000000000)

typedef struct xaios_crash_record {
  const char *service_name;
  int exit_code;
  uint64_t crash_timestamp_ns;
  uint64_t restart_count;
  uint64_t uptime_ns;
} xaios_crash_record_t;

typedef struct xaios_service {
  const char *name;
  const char *parent_name;
  const char *restart_policy;
  const char *log_policy;
  uint32_t max_restarts;
  xaios_service_state_t state;
  int exit_code;
  uint64_t starts;
  uint64_t restart_attempts;
  uint64_t log_records;
  uint64_t child_count;
  uint64_t crash_count;
  uint64_t cleanup_count;
  uint64_t update_attempts;
  uint64_t update_rejections;
  uint64_t rollback_count;

  /* Tier 2: backoff, heartbeat, watchdog */
  uint64_t backoff_ns;
  uint64_t last_start_ns;
  uint64_t last_heartbeat_ns;
  uint32_t watchdog_enabled;

  char restart_policy_snapshot[16];
  char log_policy_snapshot[16];
  uint32_t max_restarts_snapshot;
  uint64_t starts_snapshot;
  uint64_t restart_attempts_snapshot;
  uint64_t log_records_snapshot;
} xaios_service_t;

void service_supervisor_init(void);
xaios_status_t service_start_init(void);
xaios_status_t service_status(const char *name);
xaios_status_t service_snapshot(const char *name, xaios_service_t *snapshot);
xaios_status_t service_start(const char *name);
xaios_status_t service_stop(const char *name);
xaios_status_t service_restart(const char *name);
xaios_status_t service_rollback(const char *name);
xaios_status_t service_update(const char *signature);
xaios_status_t service_exit(const char *name, int exit_code);
xaios_status_t osctl_execute(const char *command);
void service_supervisor_self_test(void);
xaios_status_t service_heartbeat(const char *name);
void service_watchdog_check(void);
uint32_t service_crash_dump_count(void);
const xaios_crash_record_t *service_crash_dump_get(uint32_t index);
uint64_t service_child_descriptor_count(void);
uint64_t service_tree_edge_count(void);
uint64_t service_transition_count(void);
uint64_t service_restart_count(void);
uint64_t service_crash_count(void);
uint64_t service_cleanup_count(void);
uint64_t service_log_record_count(void);
uint64_t service_admin_policy_export_count(void);
uint64_t service_admin_status_export_count(void);
uint64_t service_admin_log_read_count(void);
uint64_t service_admin_remote_safe_accept_count(void);
uint64_t service_admin_remote_safe_reject_count(void);
uint64_t service_admin_command_denial_count(void);

#endif
