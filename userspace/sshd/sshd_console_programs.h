#ifndef SSHD_CONSOLE_PROGRAMS_H
#define SSHD_CONSOLE_PROGRAMS_H

/*
 * Declarations shared between sshd.c and sshd_console_programs.c.
 *
 * These are private to the server, like sshd_internal.h and
 * sshd_console_screen.h: sshd.h stays the public header for callers outside
 * this directory. The child process behind the console's xtop, its receive
 * buffer and its framing live in sshd_console_programs.c; sshd.c keeps the
 * console_tick() loop that feeds it and the command dispatcher that calls into
 * it, and reaches the child through the functions below.
 */

#include <stdint.h>
#include <xaios_user.h>

/* The console's own login session. The account it runs as is the caller's to
   choose, so it crosses as a function argument rather than being read back out
   of sshd.c's console state. */
#define SSHD_CONSOLE_SESSION_ID UINT64_C(0xfffffffffffffffe)

/* From sshd.c, next to the console UI they write to. The program module has no
   business holding the console command buffer or the prompt's cwd lookup, so
   these two cross by name. */
void sshd_console_text(const char *text);
void sshd_console_prompt(void);

/* From sshd_console_programs.c. */

/* "xtop" with or without options, but not "xtop --plain", which asks for the
   snapshot output on purpose on either surface. */
int sshd_console_command_is_xtop(const char *command);

/* Nonzero while the console child is running. A value, not the handle: the
   handle is mutable file-scope state and stays in the module. */
int sshd_console_program_active(void);

/* Start the xtop child on the console session as `username`. Promotes the
   command in place to the same options an SSH channel would give it. Returns
   0, or -1 when the launch fails. */
int sshd_console_program_start(char *command, uint32_t capacity,
                               const char *username);

/* One keystroke to the running child, as one INPUT frame. */
void sshd_console_program_input(char value);

/* Read and paint the child's output and notice its exit; called once per
   service-loop pass. Returns the prompt itself when the child ends. */
void sshd_console_program_service(void);

#endif /* SSHD_CONSOLE_PROGRAMS_H */
