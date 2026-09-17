#ifndef XAIOS_KERNEL_RUNTIME_REMOTE_LOGIN_ARCHIVE_INTERNAL_H
#define XAIOS_KERNEL_RUNTIME_REMOTE_LOGIN_ARCHIVE_INTERNAL_H

/*
 * The surface shared by remote_login.c and the archive command handlers split
 * out of it into remote_login_tar.c and remote_login_zip.c.
 *
 * The handlers come from a boot-test-only arm of remote_login.c, so the whole
 * header carries the same guard: in the shipped configuration neither the
 * handlers nor the primitives they call into are compiled.
 *
 * A few low-level format primitives stay in remote_login.c -- exactly as the
 * ustar and gzip primitives in remote_login_internal.h do -- because both
 * archive modules and the rest of the shell name them. Losing `static` and
 * gaining a declaration here is the only change to that code.
 */

#include "remote_login_internal.h"

#if XAIOS_BOOT_TEST_APPS

#define XAIOS_ZIP_MAX_ENTRIES 128U

typedef struct xaios_zip_entry {
  char name[XAIOS_XBFS_PATH_MAX];
  uint32_t crc32;
  uint32_t size;
  uint32_t local_offset;
  uint8_t directory;
} xaios_zip_entry_t;

/* Archive command entry points. remote_login.c's dispatch calls these across
   the translation-unit boundary. */
xaios_status_t remote_login_handle_tar(const char *args, char *output,
                                       uint64_t output_capacity,
                                       uint64_t *output_bytes);
xaios_status_t remote_login_handle_zip(const char *args, char *output,
                                       uint64_t output_capacity,
                                       uint64_t *output_bytes);
xaios_status_t remote_login_handle_unzip(const char *args, char *output,
                                         uint64_t output_capacity,
                                         uint64_t *output_bytes);
xaios_status_t remote_login_handle_cpio(const char *args, char *output,
                                        uint64_t output_capacity,
                                        uint64_t *output_bytes);

/* Primitives that stay in remote_login.c because the whole shell uses them;
   the split-out modules call them across the translation-unit boundary. */
xaios_status_t remote_login_path_basename(const char *path, char *basename,
                                          uint64_t basename_capacity);
xaios_status_t remote_login_buffer_append_text(char *buffer, uint64_t capacity,
                                               uint64_t *offset,
                                               const char *text);

/* The zeroing helper the tar and zip writers share; defined in
   remote_login_tar.c. */
void remote_login_bytes_zero(void *data, uint64_t size);

/* Zip little-endian codecs and the central-directory writer that stayed in
   remote_login.c. remote_login_zip.c calls them. */
uint16_t remote_login_read_le16(const uint8_t *data);
uint32_t remote_login_read_le32(const uint8_t *data);
void remote_login_write_le16(uint8_t *data, uint16_t value);
void remote_login_write_le32(uint8_t *data, uint32_t value);
xaios_status_t remote_login_zip_finish(uint8_t *archive, uint64_t capacity,
                                       uint64_t *archive_size,
                                       const xaios_zip_entry_t *entries,
                                       uint32_t entry_count);

#endif /* XAIOS_BOOT_TEST_APPS */

#endif /* XAIOS_KERNEL_RUNTIME_REMOTE_LOGIN_ARCHIVE_INTERNAL_H */
