#ifndef XAIOS_KERNEL_RUNTIME_REMOTE_LOGIN_SESSION_INTERNAL_H
#define XAIOS_KERNEL_RUNTIME_REMOTE_LOGIN_SESSION_INTERNAL_H

/*
 * The surface shared by remote_login.c and remote_login_session.c.
 *
 * remote_login_handle_pwd and remote_login_handle_cd were `static` while both
 * lived in remote_login.c; remote_login_exec still calls them, so the move is
 * what makes them cross. They lose `static` and gain these declarations, and
 * they are compiled in every configuration because their commands are
 * unguarded.
 */

#include "remote_login_internal.h"

xaios_status_t remote_login_handle_pwd(char *output, uint64_t output_capacity,
                                       uint64_t *output_bytes);
xaios_status_t remote_login_handle_cd(const char *arg, char *output,
                                      uint64_t output_capacity,
                                      uint64_t *output_bytes);

#endif /* XAIOS_KERNEL_RUNTIME_REMOTE_LOGIN_SESSION_INTERNAL_H */
