#ifndef XAIOS_KERNEL_RUNTIME_REMOTE_LOGIN_PARSE_INTERNAL_H
#define XAIOS_KERNEL_RUNTIME_REMOTE_LOGIN_PARSE_INTERNAL_H

/*
 * The one shell primitive remote_login_parse.c exports that
 * remote_login_internal.h does not already name: the rest of a command line
 * after a token. It was `copy_remainder` and static inside remote_login.c; the
 * split made it cross a translation-unit boundary, so it lost `static`, took
 * the module prefix and is declared here. remote_login.c's dispatcher is its
 * only caller; the function itself was compiled in every configuration before
 * and is compiled in every configuration now.
 */

#include <xaios/types.h>

/* Copies text from index to the end, skipping leading whitespace, truncated to
   out_capacity - 1 bytes and NUL-terminated. out is always terminated. */
void remote_login_remainder(const char *text, uint64_t index, char *out,
                            uint64_t out_capacity);

#endif /* XAIOS_KERNEL_RUNTIME_REMOTE_LOGIN_PARSE_INTERNAL_H */
