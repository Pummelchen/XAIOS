#ifndef SSHD_DIAGNOSTICS_H
#define SSHD_DIAGNOSTICS_H

/*
 * Declarations shared between sshd.c and sshd_diagnostics.c.
 *
 * These are private to the server, like sshd_internal.h: sshd.h stays the
 * public header for callers outside this directory. What crosses here is the
 * console-visible account of a connection's life and of the service loop that
 * serves it -- why a connection was refused before it was served, why one that
 * was served is being let go, and how long a pass of the loop, or the wait at
 * the end of it, actually took. None of this is the audit file; that lives in
 * sshd_audit.c, and these lines exist because the guest console is the only
 * surface a soak or a gate reads.
 *
 * Every counter behind these lines is the module's own. The two numbers the
 * rest of sshd.c also needs -- the running close count that log_durable_cost()
 * is given, and the active-connection count the stall reports print -- cross
 * as an argument and as a read-only accessor rather than as exported state.
 */

#include <stdint.h>
#include <xaios_user.h>

/* Say on the console why a connection was refused before it was served.
 * `observed` is the running count for that reason and `detail` the limit or
 * observed value that produced it. */
void log_connection_refusal(const char *reason, uint32_t observed,
                            uint32_t detail);

/* Why a connection that was served is being let go, one console line per
 * close.
 *
 * `reason` is the caller's own account -- the reason the connection recorded
 * for itself, or "transport"/"protocol" when it recorded none. `count` is the
 * running close count sshd.c keeps and also hands to log_durable_cost(); the
 * module does not hold it. */
void log_connection_close(const char *reason, uint64_t sockfd, uint32_t state,
                          uint64_t held_ns, uint32_t count);

/* When one pass of the service loop took long enough to be a network outage,
 * name the phase it was spent in; and when the wait at the end of a pass came
 * back later than it was asked to. Both report only past
 * SSHD_LOOP_STALL_REPORT_NS. */
void report_service_loop_stall(uint64_t started, uint64_t after_console,
                               uint64_t after_udp, uint64_t after_accept,
                               uint64_t after_connections, uint64_t ended);
void report_wait_overrun(uint64_t requested, uint64_t started,
                         uint64_t ended);

/* From sshd.c: the active-connection count the two reports print, read out of
 * the server statistics that stay in sshd.c next to the accept path that
 * updates them. */
uint32_t sshd_active_connections(void);

#endif /* SSHD_DIAGNOSTICS_H */
