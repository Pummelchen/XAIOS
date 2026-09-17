#ifndef XAIOS_KERNEL_RUNTIME_REMOTE_LOGIN_INTERNAL_H
#define XAIOS_KERNEL_RUNTIME_REMOTE_LOGIN_INTERNAL_H

/*
 * The surface shared by remote_login.c and the modules split out of it:
 * remote_login_archive.c, remote_login_text.c, remote_login_path.c,
 * remote_login_sysinfo.c, remote_login_tar.c, remote_login_zip.c,
 * remote_login_exec.c, remote_login_copy.c and remote_login_apps.c.
 *
 * The archive, text and navigation entry points live in those modules. Only
 * remote_login.c's command dispatch reaches them, and the code they came from
 * was compiled only when XAIOS_BOOT_TEST_APPS is on -- as it was inside
 * remote_login.c -- so the declarations that exist only in that arm carry the
 * same guard. In the shipped configuration neither the entry points nor the
 * primitives they call are compiled.
 *
 * remote_path_resolve is the exception: the shipped shell resolves paths too,
 * so it, and the primitives remote_login_path.c needs for it, are declared in
 * every configuration.
 */

#include <xaios/initramfs.h>
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

/* The session cwd is state of remote_login.c, and the split-out modules read
   it through this accessor rather than through the variable, which stays
   private because the rest of the shell reads it directly. */
const char *remote_login_cwd(void);

/* Primitives remote_login.c owns in every configuration. remote_login_path.c
   resolves paths for the shipped shell as well as the boot-test one, so it
   needs these outside the boot-test guard. */
uint64_t cstr_len(const char *text);
int string_equal(const char *lhs, const char *rhs);
xaios_status_t copy_cstr(char *dst, uint64_t dst_capacity, const char *src);
xaios_status_t copy_cstr_range(char *dst, uint64_t dst_capacity,
                               const char *src, uint64_t count);
xaios_status_t remote_path_resolve(const char *cwd, const char *path, char *out,
                                   uint64_t out_capacity);

/* Output and tokenizing primitives remote_login.c defines in every
   configuration. remote_login.c's own shell sees them by definition order, but
   the split-out modules name them across the translation-unit boundary: the
   shipped-configuration remote_login_apps.c needs them, as do the
   boot-test-only remote_login_copy.c, remote_login_text.c and the archive
   modules, so their declarations cannot sit inside the boot-test guard. */
void output_append(char *output, uint64_t capacity, uint64_t *offset,
                   const char *text);
xaios_status_t output_append_char(char *output, uint64_t capacity,
                                  uint64_t *offset, char value);
void output_append_u64(char *output, uint64_t capacity, uint64_t *offset,
                       uint64_t value);
xaios_status_t token_next(const char *text, uint64_t *index, char *token,
                          uint64_t capacity);
int has_more_args(const char *text, uint64_t index);

/* Primitives the redirect/pipe driver calls in every configuration, so they
   are declared outside the boot-test guard as well. */
xaios_status_t command_fail(char *output, uint64_t output_capacity,
                            uint64_t *output_bytes, const char *message);
xaios_status_t remote_ensure_parent(const char *path);

/* The command dispatcher and its redirect/pipe driver. remote_login_exec
   stays in remote_login.c because the shell help catalog that
   tests/repository/check-user-docs.py extracts lives in its body;
   remote_login_exec_pipeline lives in remote_login_exec.c. Both are compiled
   in every configuration, so neither carries a guard. */
xaios_status_t remote_login_exec(const char *command, char *output,
                                 uint64_t output_capacity,
                                 uint64_t *output_bytes);
xaios_status_t remote_login_exec_pipeline(const char *command, char *output,
                                          uint64_t output_capacity,
                                          uint64_t *output_bytes);

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

/* Shell primitives that stay in remote_login.c but are now called from the
   split-out text and path modules as well. */
void remote_login_log_failure(const char *operation, const char *reason,
                              xaios_status_t status);
int string_starts_with(const char *text, const char *prefix);
uint64_t parse_decimal_uint(const char *text, uint64_t *value);
int find_match(const char *name, const char *pattern);
xaios_status_t read_file_lines(const char *path, char *buffer,
                               uint64_t buffer_capacity, uint64_t *size);
xaios_status_t remote_login_buffer_append_char(char *buffer, uint64_t capacity,
                                               uint64_t *offset, char value);
xaios_status_t remote_login_buffer_append_text(char *buffer, uint64_t capacity,
                                               uint64_t *offset,
                                               const char *text);

/* Command entry points of the split-out modules. remote_login.c's dispatch
   calls these across the translation-unit boundary. */
xaios_status_t handle_ls(const char *args, char *output,
                         uint64_t output_capacity, uint64_t *output_bytes);
xaios_status_t handle_find_cmd(const char *args, char *output,
                               uint64_t output_capacity,
                               uint64_t *output_bytes);
xaios_status_t handle_grep(const char *args, char *output,
                           uint64_t output_capacity, uint64_t *output_bytes);
xaios_status_t handle_head_tail(const char *args, int is_head, char *output,
                                uint64_t output_capacity,
                                uint64_t *output_bytes);
xaios_status_t handle_sed(const char *args, char *output,
                          uint64_t output_capacity, uint64_t *output_bytes);
xaios_status_t remote_login_handle_cat(const char *args, char *output,
                                       uint64_t output_capacity,
                                       uint64_t *output_bytes);
xaios_status_t remote_login_handle_less(const char *args, char *output,
                                        uint64_t output_capacity,
                                        uint64_t *output_bytes);

/* The file-copy handlers of remote_login_copy.c. Like the handlers above they
   came from a boot-test-only arm of remote_login.c, so they carry the same
   guard. */
xaios_status_t remote_login_copy_cp(const char *args, char *output,
                                    uint64_t output_capacity,
                                    uint64_t *output_bytes);
xaios_status_t remote_login_copy_mv(const char *args, char *output,
                                    uint64_t output_capacity,
                                    uint64_t *output_bytes);
xaios_status_t remote_login_copy_rm(const char *args, char *output,
                                    uint64_t output_capacity,
                                    uint64_t *output_bytes);
xaios_status_t remote_login_copy_rmdir(const char *args, char *output,
                                       uint64_t output_capacity,
                                       uint64_t *output_bytes);

/* The process and filesystem reporters of remote_login_sysinfo.c. Like the
   listing entry points above they come from a boot-test-only arm of
   remote_login.c, so they carry the same guard. */
xaios_status_t handle_ps(const char *args, char *output,
                         uint64_t output_capacity, uint64_t *output_bytes);
xaios_status_t handle_df(const char *args, char *output,
                         uint64_t output_capacity, uint64_t *output_bytes);
xaios_status_t handle_du(const char *args, char *output,
                         uint64_t output_capacity, uint64_t *output_bytes);

#endif /* XAIOS_BOOT_TEST_APPS */

#if !XAIOS_BOOT_TEST_APPS

/* The remote application table and its launcher, split into
   remote_login_apps.c. This is the shipped-configuration surface: the shell's
   dispatch looks a command up with remote_login_app_find and runs the
   definition it returns with remote_login_app_run. An app-store image is run
   from its own file through remote_login_app_run_file. */
typedef struct remote_login_app_definition {
  const char *command;
  const char *path;
  uint64_t capabilities;
  uint8_t raw_arguments;
  uint8_t pass_cwd;
  uint8_t report_completion;
} remote_login_app_definition_t;

const remote_login_app_definition_t *remote_login_app_find(const char *command);
xaios_status_t remote_login_app_run(const remote_login_app_definition_t *app,
                                    const char *args, char *output,
                                    uint64_t output_capacity,
                                    uint64_t *output_bytes);
xaios_status_t remote_login_app_run_file(
    const remote_login_app_definition_t *app, const xaios_initramfs_file_t *file,
    const char *args, char *output, uint64_t output_capacity,
    uint64_t *output_bytes);

#endif /* !XAIOS_BOOT_TEST_APPS */

#endif /* XAIOS_KERNEL_RUNTIME_REMOTE_LOGIN_INTERNAL_H */
