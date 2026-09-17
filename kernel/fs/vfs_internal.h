/*
 * Private interface shared by the three translation units the VFS is split
 * across: vfs.c (the serialised public entry points), vfs_namespace.c (path
 * normalisation, the mount table and the namespace operations) and
 * vfs_handle.c (the handle table and the open/read/write path).
 *
 * The mount table, the handle table and the generation counter are mutable
 * file-scope state. Each is defined exactly once, in the unit that owns it,
 * and reached from the others through the extern declarations below. The
 * lock that serialises the entry points is not declared here: only vfs.c
 * touches it, and every function ending in _locked still assumes it is held.
 *
 * No accessor returns a pointer into either table across a translation unit.
 * find_handle, which does return a handle pointer, stays in vfs_handle.c with
 * the table it indexes and is static.
 */

#ifndef XAIOS_KERNEL_FS_VFS_INTERNAL_H
#define XAIOS_KERNEL_FS_VFS_INTERNAL_H

#include <xaios/vfs.h>

typedef struct vfs_mount_record {
  uint32_t active;
  uint32_t flags;
  uint64_t generation;
  uint64_t open_handles;
  char path[XAIOS_VFS_PATH_MAX];
  const xaios_vfs_backend_ops_t *ops;
  void *context;
} vfs_mount_record_t;

typedef struct vfs_handle_record {
  uint32_t active;
  uint32_t owner_id;
  uint32_t flags;
  uint32_t mount_index;
  uint64_t mount_generation;
  uint64_t backend_handle;
  uint64_t cursor;
} vfs_handle_record_t;

/* Defined in vfs_namespace.c. */
extern vfs_mount_record_t vfs_mounts[XAIOS_VFS_MAX_MOUNTS];
extern uint64_t vfs_next_generation;

/* Defined in vfs_handle.c. */
extern vfs_handle_record_t vfs_handles[XAIOS_VFS_MAX_HANDLES];

/* Defined in vfs_namespace.c; shared because vfs_init, vfs_mount_locked and
   the descriptor layer all clear records with it. */
void vfs_bytes_zero(void *buffer, uint64_t length);

/* vfs_namespace.c: the mount table and the namespace operations. */
xaios_status_t vfs_mount_locked(const char *mount_path, const xaios_vfs_backend_ops_t *ops, void *context, uint32_t flags);
xaios_status_t vfs_unmount_locked(const char *mount_path);
xaios_status_t vfs_stat_locked(const char *path, xaios_vfs_stat_t *stat);
xaios_status_t vfs_statfs_locked(const char *path, xaios_vfs_statfs_t *statfs);
xaios_status_t vfs_mkdir_locked(const char *path);
xaios_status_t vfs_rmdir_locked(const char *path);
xaios_status_t vfs_unlink_locked(const char *path);
xaios_status_t vfs_delete_locked(const char *path);
xaios_status_t vfs_rename_locked(const char *old_path, const char *new_path);
xaios_status_t vfs_list_locked(const char *path, char *buffer, uint64_t capacity, uint64_t *out_size);

/* vfs_handle.c: the descriptor table and the open/read/write path. */
int64_t vfs_open_locked(const char *path, uint32_t flags, uint32_t owner_id);
xaios_status_t vfs_close_locked(uint32_t fd, uint32_t owner_id);
xaios_status_t vfs_release_owner_locked(uint32_t owner_id);
int64_t vfs_pread_locked(uint32_t fd, uint32_t owner_id, void *buffer, uint64_t length, uint64_t offset);
int64_t vfs_pwrite_locked(uint32_t fd, uint32_t owner_id, const void *buffer, uint64_t length, uint64_t offset);
int64_t vfs_read_locked(uint32_t fd, uint32_t owner_id, void *buffer, uint64_t length);
int64_t vfs_write_locked(uint32_t fd, uint32_t owner_id, const void *buffer, uint64_t length);
xaios_status_t vfs_seek_locked(uint32_t fd, uint32_t owner_id, uint64_t offset);
xaios_status_t vfs_fsync_locked(uint32_t fd, uint32_t owner_id);
xaios_status_t vfs_truncate_locked(uint32_t fd, uint32_t owner_id, uint64_t size);
xaios_status_t vfs_fallocate_locked(uint32_t fd, uint32_t owner_id, uint64_t offset, uint64_t length);

#endif
