/*
 * Private interface between xaiboot_fs.c and xbfs_fd.c, the translation unit
 * that owns the open-file table, the whole-file staging buffer, and the
 * descriptor layer: open/read/write/seek/close, including the append fast path
 * B-45 added.
 *
 * The handle table and the staging buffer are mutable file-scope state and
 * neither is handed out. The descriptor entry points mutate them in place; the
 * one value the self-test in xaiboot_fs.c needs from a handle -- its cursor --
 * is read out through xbfs_fd_cursor, which returns a uint64_t rather than a
 * pointer into the table. The staging buffer is 256 KiB, far past any stack
 * frame, which is why it stays a static here rather than moving to a caller or
 * being read into a caller-owned local.
 *
 * Every entry point runs with the volume lock held, exactly as the static
 * functions it replaces did, and takes no lock itself.
 *
 * xbfs_open_files_forget_tree and xbfs_open_files_rebase are defined here too,
 * but declared in xbfs_internal.h because xbfs_dir.c calls them.
 */

#ifndef XAIOS_KERNEL_FS_XBFS_FD_INTERNAL_H
#define XAIOS_KERNEL_FS_XBFS_FD_INTERNAL_H

#include "xbfs_internal.h"

/* The open-file table's ceiling. It moved here with the table: the only code
   that indexes it is in xbfs_fd.c. */
#define XBFS_MAX_OPEN_FILES 256U

/* The descriptor operations. Each returns the same status and leaves the same
   state as the static function it replaces. */
int64_t xbfs_fd_open_locked(const char *path, uint32_t flags);
int64_t xbfs_fd_read_locked(uint32_t fd, void *buffer, uint64_t size);
int64_t xbfs_fd_write_locked(uint32_t fd, const void *buffer, uint64_t size);
xaios_status_t xbfs_fd_seek_locked(uint32_t fd, uint64_t offset);
xaios_status_t xbfs_fd_close_locked(uint32_t fd);

/* The bound every write through a descriptor is checked against: the smaller
   of the mounted format's per-file limit and the staging buffer. When the
   format is larger than the buffer, this is what keeps the whole-file path
   from running off the end of it. */
uint64_t xbfs_write_limit(void);

/* sizeof the staging buffer, as a value. */
uint64_t xbfs_file_staging_bytes(void);

/* The cursor of an open descriptor, or 0 when `fd` is not open. */
uint64_t xbfs_fd_cursor(uint32_t fd);

/* Clear every handle, as the self-test does before it drives the API. */
void xbfs_reset_open_files(void);

#endif /* XAIOS_KERNEL_FS_XBFS_FD_INTERNAL_H */
