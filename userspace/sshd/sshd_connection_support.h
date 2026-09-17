#ifndef SSHD_CONNECTION_SUPPORT_H
#define SSHD_CONNECTION_SUPPORT_H

/*
 * Declarations shared between sshd.c and sshd_connection_support.c.
 *
 * These are private to the server, like sshd_internal.h and sshd_auth.h:
 * sshd.h stays the public header for callers outside this directory. What
 * lives here is the small per-connection support that the state machine in
 * process_connection() and the service loop in sshd_run() both use, and which
 * is neither of those hubs: the reason slot the machine records before it
 * closes, the clock those two read, the IPv4 readiness check the loop makes
 * before it listens, the wire-level validators the machine applies to the
 * client version and its own auth-failure reply, and the constant-time zero
 * scan it applies to every SSH name field. None of them holds connection
 * state beyond the one close-reason slot.
 *
 * The reason slot stays a single slot: sshd is single-threaded and the
 * service loop reads it immediately after the call that set it, so one
 * pointer is the whole requirement. sshd_close_reason() hands back the
 * pointer that was stored -- always a string literal or null, never a pointer
 * into module state -- and sshd_run() reads it before the next connection
 * clears it.
 */

#include <stdint.h>

#include "ssh_connection.h"

/* The close reason. sshd_run() clears it at the top of a connection's turn,
 * sets it from a timeout, and reads it after process_connection() returns;
 * sshd_close_because() is the machine's "remember why and return -1" form. */
void sshd_close_reason_set(const char *reason);
const char *sshd_close_reason(void);
int sshd_close_because(const char *reason);

/* The monotonic clock, in nanoseconds. */
uint64_t sshd_timer_now(void);

/* Zero when the interface has a usable IPv4 address, -1 otherwise. */
int sshd_verify_ipv4_ready(void);

/* Nonzero when the size bytes contain a NUL, which no SSH name field may. */
int sshd_bytes_have_zero(const uint8_t *data, uint32_t size);

/* Nonzero when the buffer is a well-formed "SSH-2.0-..." identification
 * string ending in a newline and containing only printable characters. */
int sshd_valid_client_version(const uint8_t *version, uint32_t length);

/* Write SSH_MSG_USERAUTH_FAILURE with the methods currently offered. */
int sshd_send_auth_failure(ssh_connection_t *conn);

#endif /* SSHD_CONNECTION_SUPPORT_H */
