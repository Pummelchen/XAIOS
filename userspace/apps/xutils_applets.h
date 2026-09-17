/*
 * Private interface between xutils.c, xutils_file.c and xutils_text.c.
 *
 * xutils.c is compiled once per applet name with -DXAIOS_UTILITY_NAME, and
 * these two modules are compiled with the same flag and linked beside it into
 * every utility ELF, exactly as xutils_archive.c is.  The declarations of the
 * path, file-I/O and token helpers the modules share already live in
 * xutils_archive.h, which this header pulls in; what is added here is the
 * applet entry points the two modules define and the two output primitives
 * the text module needs, so neither side repeats a definition.
 */
#ifndef XAIOS_APPS_XUTILS_APPLETS_H
#define XAIOS_APPS_XUTILS_APPLETS_H

#include "xutils_archive.h"

/* Buffered output, owned by xutils.c. */
int xutils_append_bytes(const void *data, u64 size);
int xutils_append_char(char value);

/* File applets, defined in xutils_file.c. */
int xutils_cmd_ls(const char *args);
int xutils_cmd_mkdir(const char *args);
int xutils_cmd_touch(const char *args);
int xutils_cmd_cp(const char *args);
int xutils_cmd_mv(const char *args);
int xutils_cmd_rm(const char *args, int directories_only);
int xutils_cmd_stat(const char *args);

/* Text applets, defined in xutils_text.c. */
int xutils_cmd_cat_like(const char *args, int mode);
int xutils_cmd_grep(const char *args);
int xutils_cmd_find(const char *args);
int xutils_cmd_write(const char *args);
int xutils_cmd_sed(const char *args);

#endif /* XAIOS_APPS_XUTILS_APPLETS_H */
