/*
 * Private interface between xutils.c and xutils_archive.c.
 *
 * xutils.c is compiled once per applet name with -DXAIOS_UTILITY_NAME and the
 * archive object is linked beside it into every utility ELF.  Declarations
 * live here so neither side repeats a definition: the per-process state (the
 * scratch arena, the working directory, the output buffer) stays single
 * instanced in xutils.c, and the archive commands are defined once in
 * xutils_archive.c.
 */
#ifndef XAIOS_APPS_XUTILS_ARCHIVE_H
#define XAIOS_APPS_XUTILS_ARCHIVE_H

#include <xaios_user.h>

#define PATH_MAX 256U
#define FILE_MAX 131072U
#define LIST_MAX 16384U
#define OUTPUT_MAX 32768U
#define ENTRY_MAX 128U
#define USTAR_BLOCK 512U

extern int xaios_inflate_raw(const unsigned char *input, u64 input_size,
                             unsigned char *output, u64 output_capacity,
                             u64 *output_size);

/* Scratch arena and working directory, owned by xutils.c.  These are shared
 * storage rather than accessors: the archive commands read and fill the same
 * buffers the rest of the multi-call binary uses, and the process runs exactly
 * one applet per invocation. */
extern unsigned char xutils_scratch[FILE_MAX];
extern unsigned char xutils_aux[FILE_MAX];
extern const char *xutils_cwd;

/* Helpers that stay in xutils.c and are called from the archive module. */
int xutils_append(const char *text);
int xutils_append_u64(u64 value);
int xutils_fail(const char *message);
u64 xutils_length(const char *text);
int xutils_equal(const char *lhs, const char *rhs);
int xutils_starts(const char *text, const char *prefix);
void xutils_copy(char *dst, const char *src, u64 capacity);
int xutils_next_token(const char *text, u64 *cursor, char *token, u64 capacity);
int xutils_resolve_path(const char *input, char *output);
int xutils_join_path(const char *base, const char *name, char *output);
int xutils_basename_of(const char *path, char *name);
int xutils_read_file(const char *path, unsigned char *buffer, u64 capacity,
                     u64 *size);
int xutils_write_file(const char *path, const void *buffer, u64 size);
int xutils_list_dir(const char *path, char *listing, u64 *size);
int xutils_each_listing(const char *listing, u64 size, u64 *cursor, char *name);
int xutils_ensure_parents(const char *path);

/* Implemented in xutils_archive.c. */
int xutils_archive_safe(const char *name);
int xutils_cmd_tar(const char *args);
int xutils_cmd_zip(const char *args);
int xutils_cmd_unzip(const char *args);

#endif /* XAIOS_APPS_XUTILS_ARCHIVE_H */
