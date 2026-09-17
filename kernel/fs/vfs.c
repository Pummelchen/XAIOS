/*
 * The serialised public VFS entry points.
 *
 * Split out of the 757-line vfs.c: the mount table and the namespace
 * operations now live in vfs_namespace.c, and the handle table and the
 * open/read/write path in vfs_handle.c. Both declare their state and their
 * _locked entry points in vfs_internal.h. This unit keeps the lock, the
 * initialisation and the wrappers, so the locking discipline is unchanged:
 * every _locked body runs under exactly the one lock it ran under before.
 */

#include <xaios/vfs.h>
#include <xaios/spinlock.h>

#include "vfs_internal.h"

static xaios_spinlock_t g_vfs_lock = XAIOS_SPINLOCK_INIT;

xaios_status_t vfs_init(void) {
  for (uint32_t index = 0U; index < XAIOS_VFS_MAX_HANDLES; ++index) {
    if (vfs_handles[index].active != 0U) return XAIOS_ERR_BUSY;
  }
  vfs_bytes_zero(vfs_mounts, sizeof(vfs_mounts));
  vfs_bytes_zero(vfs_handles, sizeof(vfs_handles));
  if (++vfs_next_generation == 0U) ++vfs_next_generation;
  return XAIOS_OK;
}

/* Serialised public entry points.
   The handle table and mount table are reached from every CPU through the
   filesystem syscalls, and were mutated with no mutual exclusion: vfs_open
   scanned for a free slot and filled it in separate steps while vfs_close and
   vfs_release_owner cleared entries underneath it. Each entry point now runs
   under one lock; the bodies above assume it is held and must not be called
   directly. */
xaios_status_t vfs_mount(const char *mount_path, const xaios_vfs_backend_ops_t *ops, void *context, uint32_t flags) {
  xaios_spin_lock(&g_vfs_lock);
  xaios_status_t result = vfs_mount_locked(mount_path, ops, context, flags);
  xaios_spin_unlock(&g_vfs_lock);
  return result;
}

xaios_status_t vfs_unmount(const char *mount_path) {
  xaios_spin_lock(&g_vfs_lock);
  xaios_status_t result = vfs_unmount_locked(mount_path);
  xaios_spin_unlock(&g_vfs_lock);
  return result;
}

int64_t vfs_open(const char *path, uint32_t flags, uint32_t owner_id) {
  xaios_spin_lock(&g_vfs_lock);
  int64_t result = vfs_open_locked(path, flags, owner_id);
  xaios_spin_unlock(&g_vfs_lock);
  return result;
}

xaios_status_t vfs_close(uint32_t fd, uint32_t owner_id) {
  xaios_spin_lock(&g_vfs_lock);
  xaios_status_t result = vfs_close_locked(fd, owner_id);
  xaios_spin_unlock(&g_vfs_lock);
  return result;
}

xaios_status_t vfs_release_owner(uint32_t owner_id) {
  xaios_spin_lock(&g_vfs_lock);
  xaios_status_t result = vfs_release_owner_locked(owner_id);
  xaios_spin_unlock(&g_vfs_lock);
  return result;
}

int64_t vfs_pread(uint32_t fd, uint32_t owner_id, void *buffer, uint64_t length, uint64_t offset) {
  xaios_spin_lock(&g_vfs_lock);
  int64_t result = vfs_pread_locked(fd, owner_id, buffer, length, offset);
  xaios_spin_unlock(&g_vfs_lock);
  return result;
}

int64_t vfs_pwrite(uint32_t fd, uint32_t owner_id, const void *buffer, uint64_t length, uint64_t offset) {
  xaios_spin_lock(&g_vfs_lock);
  int64_t result = vfs_pwrite_locked(fd, owner_id, buffer, length, offset);
  xaios_spin_unlock(&g_vfs_lock);
  return result;
}

int64_t vfs_read(uint32_t fd, uint32_t owner_id, void *buffer, uint64_t length) {
  xaios_spin_lock(&g_vfs_lock);
  int64_t result = vfs_read_locked(fd, owner_id, buffer, length);
  xaios_spin_unlock(&g_vfs_lock);
  return result;
}

int64_t vfs_write(uint32_t fd, uint32_t owner_id, const void *buffer, uint64_t length) {
  xaios_spin_lock(&g_vfs_lock);
  int64_t result = vfs_write_locked(fd, owner_id, buffer, length);
  xaios_spin_unlock(&g_vfs_lock);
  return result;
}

xaios_status_t vfs_seek(uint32_t fd, uint32_t owner_id, uint64_t offset) {
  xaios_spin_lock(&g_vfs_lock);
  xaios_status_t result = vfs_seek_locked(fd, owner_id, offset);
  xaios_spin_unlock(&g_vfs_lock);
  return result;
}

xaios_status_t vfs_fsync(uint32_t fd, uint32_t owner_id) {
  xaios_spin_lock(&g_vfs_lock);
  xaios_status_t result = vfs_fsync_locked(fd, owner_id);
  xaios_spin_unlock(&g_vfs_lock);
  return result;
}

xaios_status_t vfs_truncate(uint32_t fd, uint32_t owner_id, uint64_t size) {
  xaios_spin_lock(&g_vfs_lock);
  xaios_status_t result = vfs_truncate_locked(fd, owner_id, size);
  xaios_spin_unlock(&g_vfs_lock);
  return result;
}

xaios_status_t vfs_fallocate(uint32_t fd, uint32_t owner_id, uint64_t offset, uint64_t length) {
  xaios_spin_lock(&g_vfs_lock);
  xaios_status_t result = vfs_fallocate_locked(fd, owner_id, offset, length);
  xaios_spin_unlock(&g_vfs_lock);
  return result;
}

xaios_status_t vfs_stat(const char *path, xaios_vfs_stat_t *stat) {
  xaios_spin_lock(&g_vfs_lock);
  xaios_status_t result = vfs_stat_locked(path, stat);
  xaios_spin_unlock(&g_vfs_lock);
  return result;
}

xaios_status_t vfs_statfs(const char *path, xaios_vfs_statfs_t *statfs) {
  xaios_spin_lock(&g_vfs_lock);
  xaios_status_t result = vfs_statfs_locked(path, statfs);
  xaios_spin_unlock(&g_vfs_lock);
  return result;
}

xaios_status_t vfs_mkdir(const char *path) {
  xaios_spin_lock(&g_vfs_lock);
  xaios_status_t result = vfs_mkdir_locked(path);
  xaios_spin_unlock(&g_vfs_lock);
  return result;
}

xaios_status_t vfs_rmdir(const char *path) {
  xaios_spin_lock(&g_vfs_lock);
  xaios_status_t result = vfs_rmdir_locked(path);
  xaios_spin_unlock(&g_vfs_lock);
  return result;
}

xaios_status_t vfs_unlink(const char *path) {
  xaios_spin_lock(&g_vfs_lock);
  xaios_status_t result = vfs_unlink_locked(path);
  xaios_spin_unlock(&g_vfs_lock);
  return result;
}

xaios_status_t vfs_delete(const char *path) {
  xaios_spin_lock(&g_vfs_lock);
  xaios_status_t result = vfs_delete_locked(path);
  xaios_spin_unlock(&g_vfs_lock);
  return result;
}

xaios_status_t vfs_rename(const char *old_path, const char *new_path) {
  xaios_spin_lock(&g_vfs_lock);
  xaios_status_t result = vfs_rename_locked(old_path, new_path);
  xaios_spin_unlock(&g_vfs_lock);
  return result;
}

xaios_status_t vfs_list(const char *path, char *buffer, uint64_t capacity, uint64_t *out_size) {
  xaios_spin_lock(&g_vfs_lock);
  xaios_status_t result = vfs_list_locked(path, buffer, capacity, out_size);
  xaios_spin_unlock(&g_vfs_lock);
  return result;
}
