#ifndef SSHD_CONFIG_H
#define SSHD_CONFIG_H

/*
 * Declarations shared between sshd.c and sshd_config.c.
 *
 * These are private to the server, like sshd_internal.h: sshd.h stays the
 * public header for callers outside this directory. The runtime-configuration
 * record -- the rule that decides whether it is valid, the load that applies
 * it, the option values the rest of the server reads through accessors, and
 * the control commands that reload it -- lives in sshd_config.c, together with
 * the service-selection file, because "which services this machine was told to
 * start" is another option it was given.
 *
 * The record and the password-auth flag stay defined in sshd.c, next to
 * process_connection() and sshd_run(), which read them directly; the module
 * writes them through the declarations below, so nothing is defined twice and
 * no accessor hands back a pointer into module state.
 */

#include <stdint.h>
#include <xaios_user.h>

/* The loaded runtime configuration. Defined in sshd.c, read there by the
 * connection state machine (max_auth_attempts) and the accept path
 * (max_connections), and written in sshd_config.c by load_runtime_config(). */
extern xaios_admin_config_user_t g_runtime_config;

/* Nonzero while password authentication is offered. Defined in sshd.c and read
 * by the console UI as well; written in sshd_config.c by load_runtime_config().
 */
extern uint32_t g_password_auth_enabled;

/* From sshd_config.c: load the runtime-configuration record from the durable
 * volume. Returns 0 on success, -1 when it is absent or fails its checksum and
 * bounds checks. Called at startup by sshd_run() and again after a control
 * command changes it. */
int load_runtime_config(void);

/* From sshd_config.c: whether the machine was told to start the named service.
 * A machine that has never been set up has no list and starts everything. */
int service_enabled(const char *name);

#endif /* SSHD_CONFIG_H */
