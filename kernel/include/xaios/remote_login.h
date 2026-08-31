#ifndef XAIOS_REMOTE_LOGIN_H
#define XAIOS_REMOTE_LOGIN_H

#include <xaios/status.h>
#include <xaios/types.h>

xaios_status_t remote_login_execute(const char *user, const char *command,
                                   char *output, uint64_t output_capacity,
                                   uint64_t *output_bytes);
xaios_status_t remote_login_execute_session(
    uint64_t session_id, const char *user, const char *command, char *output,
    uint64_t output_capacity, uint64_t *output_bytes);
xaios_status_t remote_login_close_session(uint64_t session_id);
uint64_t remote_login_session_count(void);
uint64_t remote_login_command_count(void);
uint64_t remote_login_denial_count(void);
void remote_login_self_test(void);

/* Drop the cached local account name, so the next command re-reads it. Called
   when setup installs an account, because boot self-tests have already cached
   the name the machine had before it had one. */
void remote_login_forget_account(void);

#endif
