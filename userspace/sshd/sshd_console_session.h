#ifndef SSHD_CONSOLE_SESSION_H
#define SSHD_CONSOLE_SESSION_H

/*
 * Declarations shared between sshd.c and sshd_console_session.c.
 *
 * These are private to the server, like sshd_console_ui.h: sshd.h stays the
 * public header for callers outside this directory. The console's command
 * dispatcher and its login submissions live in sshd_console_session.c; sshd.c
 * keeps the console_tick() hub that feeds them, the console's own session
 * identity, and the connection state machine.
 *
 * The command line stays defined in sshd.c, next to console_tick(), because
 * that hub edits it one keystroke at a time; the module reads and edits the
 * same buffer through the declaration below, so it is not defined twice.
 */

#include <stdint.h>

/* The console command line console_tick() edits, and the command buffer size
 * both sides use. Defined in sshd.c. */
#define SSHD_CONSOLE_COMMAND_MAX UINT32_C(256)
extern char g_console_command[SSHD_CONSOLE_COMMAND_MAX];

/* From sshd.c: the console's own session identity, set when a name is accepted
 * at the prompt. Called by the login submission below; it stays in sshd.c
 * beside the state it names. */
void console_set_username(const char *username);

/* From sshd_console_session.c. Both are the transitions console_tick() drives:
 * console_execute_command() runs the line a shell prompt returned, and
 * console_submit_auth() submits the line a login or password prompt returned.
 */
void console_execute_command(void);
void console_submit_auth(void);

#endif /* SSHD_CONSOLE_SESSION_H */
