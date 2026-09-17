/* Private declarations shared by the three files of the kernel service
   supervisor: service.c (the locked public entry points and the osctl front
   end), service_registry.c (records, counters and configuration) and
   service_lifecycle.c (start, stop and supervision).

   Each symbol below is defined exactly once, in service_registry.c or
   service_lifecycle.c, and carries the svc_ prefix because it now crosses a
   translation unit. The reentrant service lock stays private to service.c;
   no function here takes it, so the critical sections are exactly the ones
   the public entry points always had. */

#ifndef XAIOS_KERNEL_USER_SERVICE_INTERNAL_H
#define XAIOS_KERNEL_USER_SERVICE_INTERNAL_H

#include <xaios/service.h>

/* osctl command lines are bounded here; both service.c and the registry
   parser use the same limit. */
#define XAIOS_CMD_TOKEN_BUFFER 160U

/* Policy names, log modes and service names. */
extern const char svc_policy_never[];
extern const char svc_policy_always[];
extern const char svc_policy_on_failure[];
extern const char svc_policy_default[];
extern const char svc_log_serial[];
extern const char svc_log_off[];
extern const char svc_init_service_name[];
extern const char svc_manager_service_name[];
extern const char svc_worker_service_name[];
extern const char svc_child_service_name[];
extern const char svc_child_parent_name[];

/* The four service records, the crash-dump ring and the counters. */
extern xaios_service_t svc_init_service;
extern xaios_service_t svc_manager_service;
extern xaios_service_t svc_worker_service;
extern xaios_service_t svc_child_service;
extern uint64_t svc_child_descriptor_count;
extern uint64_t svc_tree_edge_count;
extern uint64_t svc_transition_count;
extern uint64_t svc_restart_count;
extern uint64_t svc_crash_count;
extern uint64_t svc_cleanup_count;
extern uint64_t svc_log_record_count;
extern uint64_t svc_admin_policy_export_count;
extern uint64_t svc_admin_status_export_count;
extern uint64_t svc_admin_log_read_count;
extern uint64_t svc_admin_remote_safe_accept_count;
extern uint64_t svc_admin_remote_safe_reject_count;
extern uint64_t svc_admin_command_denial_count;
extern xaios_crash_record_t svc_crash_dumps[XAIOS_CRASH_DUMP_MAX];
extern uint32_t svc_crash_dump_count;

/* Registry helpers (service_registry.c). */
int svc_str_eq(const char *lhs, const char *rhs);
uint8_t svc_token_length(const char *token);
int svc_token_safe(const char *token);
const char *svc_state_name(xaios_service_state_t state);
xaios_status_t svc_require_service_capability(uint64_t capability);
xaios_status_t svc_require_admin_capability(void);
xaios_status_t svc_parse_u32(const char *value, uint32_t *out);
xaios_status_t svc_parse_key_value(const char *token, const char *expected_key,
                                   const char **value_out);
void svc_snapshot_capture(xaios_service_t *service);
void svc_snapshot_restore(xaios_service_t *service);
void svc_reset_service(xaios_service_t *service, const char *name);
xaios_service_t *svc_find_service(const char *name);
xaios_status_t svc_configure_service(const char *service_name,
                                     const char *token3, const char *token4,
                                     const char *token5);

/* Lifecycle and supervision (service_lifecycle.c). */
xaios_status_t svc_start_service(xaios_service_t *service);
xaios_status_t svc_mark_service_exit(xaios_service_t *service, int exit_code,
                                     uint32_t supervise);
xaios_status_t svc_handle_restart(const char *service_name);
xaios_status_t svc_handle_start(const char *service_name);
xaios_status_t svc_handle_update(const char *signature);
xaios_status_t svc_handle_rollback(const char *service_name);
xaios_status_t svc_handle_stop(const char *service_name);
xaios_status_t svc_handle_crash(const char *service_name,
                                const char *code_token);
xaios_status_t svc_handle_define(const char *service_name,
                                 const char *parent_token,
                                 const char *restart_token);

#endif /* XAIOS_KERNEL_USER_SERVICE_INTERNAL_H */
