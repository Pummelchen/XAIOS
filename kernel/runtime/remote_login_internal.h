#ifndef XAIOS_KERNEL_RUNTIME_REMOTE_LOGIN_INTERNAL_H
#define XAIOS_KERNEL_RUNTIME_REMOTE_LOGIN_INTERNAL_H

/*
 * The surface shared by remote_login.c and remote_login_archive.c.
 *
 * The archive entry points live in remote_login_archive.c. Only
 * remote_login.c's command dispatch reaches them, and the archive code is
 * compiled only when XAIOS_BOOT_TEST_APPS is on -- as it was inside
 * remote_login.c -- so the declarations that exist only in that arm carry the
 * same guard. In the shipped configuration neither the entry points nor the
 * primitives they call are compiled.
 */

#include <xaios/status.h>
#include <xaios/types.h>
#include <xaios/xaiboot_fs.h>

#ifndef XAIOS_BOOT_TEST_APPS
#define XAIOS_BOOT_TEST_APPS 0
#endif

#ifndef XAIOS_REMOTE_LOGIN_LIST_BYTES
#define XAIOS_REMOTE_LOGIN_LIST_BYTES XAIOS_XBFS_MAX_LIST_BYTES
#endif

#define XAIOS_USTAR_BLOCK_SIZE UINT64_C(512)

/* The session cwd is state of remote_login.c, and the archive module reads it
   through this accessor rather than through the variable, which stays private
   because the rest of the shell reads it directly. */
const char *remote_login_cwd(void);

#if XAIOS_BOOT_TEST_APPS

/* The XAIOSARCHIVE header. handle_cpio writes it in remote_login.c and the
   archive module reads it, so it is defined once there and named here. */
extern const char g_remote_login_archive_magic[];

/* Archive entry points. handle_tar, handle_zip and handle_cpio stay in
   remote_login.c and call these across the translation-unit boundary. */
xaios_status_t archive_build_from_path(const char *source,
                                       const char *archive_path, char *archive,
                                       uint64_t archive_capacity,
                                       uint64_t *archive_size);
xaios_status_t archive_extract_to(const char *archive_path,
                                  const char *extract_base);
xaios_status_t archive_list(const char *archive_path, char *output,
                            uint64_t output_capacity, uint64_t *output_bytes);
xaios_status_t ustar_walk(const char *archive_path, const char *destination,
                          int extract, char *output, uint64_t output_capacity,
                          uint64_t *output_bytes);

/* Primitives the archive entry points call back into. They stay owned by
   remote_login.c because the rest of the shell uses them too; only their
   linkage changes so the archive module can name them. */
uint64_t cstr_len(const char *text);
void output_append(char *output, uint64_t capacity, uint64_t *offset,
                   const char *text);
xaios_status_t output_append_char(char *output, uint64_t capacity,
                                  uint64_t *offset, char value);
xaios_status_t copy_cstr(char *dst, uint64_t dst_capacity, const char *src);
xaios_status_t copy_cstr_range(char *dst, uint64_t dst_capacity,
                               const char *src, uint64_t count);
xaios_status_t remote_path_resolve(const char *cwd, const char *path, char *out,
                                   uint64_t out_capacity);
xaios_status_t remote_ensure_parent(const char *path);
xaios_status_t path_join(char *out, uint64_t out_capacity, const char *base,
                         const char *name);
xaios_status_t read_file_buffer(const char *path, char *buffer,
                                uint64_t buffer_capacity, uint64_t *out_size);
xaios_status_t write_buffer_to_path(const char *path, const char *data,
                                    uint64_t size);
xaios_status_t archive_append_entry(char *archive, uint64_t archive_capacity,
                                    uint64_t *archive_size, char kind,
                                    const char *path, const char *data,
                                    uint64_t data_size);
xaios_status_t archive_parse_entry(const char *line, uint64_t line_size,
                                   char *kind, uint64_t *data_size,
                                   uint64_t *path_len, char *path,
                                   uint64_t path_capacity);
xaios_status_t mkdir_resolved(const char *path, int parents);
xaios_status_t ustar_parse_octal(const char *field, uint64_t width,
                                 uint64_t *value);
int ustar_block_is_zero(const char *block);
xaios_status_t ustar_header_path(const char *header, char *path,
                                 uint64_t path_capacity);
int archive_path_is_safe(const char *path);
xaios_status_t pax_extract_path(const char *data, uint64_t size, char *out,
                                uint64_t out_capacity);
xaios_status_t gzip_decode(const uint8_t *input, uint64_t input_size,
                           uint8_t *output, uint64_t output_capacity,
                           uint64_t *output_size);

#endif /* XAIOS_BOOT_TEST_APPS */

#endif /* XAIOS_KERNEL_RUNTIME_REMOTE_LOGIN_INTERNAL_H */
