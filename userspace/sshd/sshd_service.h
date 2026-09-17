#ifndef SSHD_SERVICE_H
#define SSHD_SERVICE_H

/*
 * Declarations shared between sshd.c and sshd_service.c.
 *
 * These are private to the server, like sshd_internal.h: sshd.h stays the
 * public header for callers outside this directory. The service loop and the
 * console tick that feeds it moved out of sshd.c into sshd_service.c as whole
 * functions -- console_tick() and sshd_run() -- so what crosses here is only
 * what one of the two still has to reach across the boundary.
 *
 * sshd.c keeps main(), the connection state machine in process_connection(),
 * and the console session identity and helpers around it. The service loop
 * reaches process_connection() by name, so it is declared here and defined
 * once, in sshd.c. The connection statistics and the running close count the
 * loop updates are static to sshd_service.c, next to the accept path that
 * updates them; the one number the rest of the server reads back -- the
 * active-connection count -- crosses through the read-only scalar accessor
 * sshd_active_connections() declared in sshd_diagnostics.h, not as exported
 * state.
 */

#include <stdint.h>

#include "ssh_connection.h"

/* Defined in sshd.c. Process one step for a connection. Returns 0 if the
 * connection should remain, -1 if it is closed or done. Called by sshd_run()
 * in sshd_service.c; it stays the same function with the same name and
 * signature, now external so the move could leave it in the parent. */
int process_connection(ssh_connection_t *conn);

#endif /* SSHD_SERVICE_H */
