/*
 * The descriptor table and the other half of the VFS: open, close,
 * release_owner and the cursor-carrying read/write/seek/fsync/truncate/
 * fallocate path.
 *
 * Split out of vfs.c, which was 757 lines. The handle table is defined here
 * because this unit owns it; the mount table lives in vfs_namespace.c and is
 * reached through vfs_internal.h. Every operation ending in _locked assumes
 * the lock in vfs.c is held, exactly as the static functions it replaces did,
 * and takes no lock itself. find_handle still returns an entry of the
 * same-unit handle table and is static, so no pointer into mutable file-scope
 * state crosses a translation unit.
 */

#include "vfs_internal.h"

vfs_handle_record_t vfs_handles[XAIOS_VFS_MAX_HANDLES];

static vfs_handle_record_t *find_handle(uint32_t fd, uint32_t owner_id) {
  if (fd == 0U || fd > XAIOS_VFS_MAX_HANDLES) return 0;
  vfs_handle_record_t *handle = &vfs_handles[fd - 1U];
  if (handle->active == 0U || handle->owner_id != owner_id ||
      handle->mount_index >= XAIOS_VFS_MAX_MOUNTS) {
    return 0;
  }
  vfs_mount_record_t *mount = &vfs_mounts[handle->mount_index];
  if (mount->active == 0U ||
      mount->generation != handle->mount_generation) {
    return 0;
  }
  return handle;
}

static int mutating_flags(uint32_t flags) {
  return (flags & (XAIOS_VFS_OPEN_WRITE | XAIOS_VFS_OPEN_CREATE |
                   XAIOS_VFS_OPEN_TRUNCATE)) != 0U;
}

int64_t vfs_open_locked(const char *path, uint32_t flags, uint32_t owner_id) {
  if (flags == 0U ||
      flags & ~(XAIOS_VFS_OPEN_READ | XAIOS_VFS_OPEN_WRITE |
                XAIOS_VFS_OPEN_CREATE | XAIOS_VFS_OPEN_TRUNCATE) ||
      (flags & (XAIOS_VFS_OPEN_READ | XAIOS_VFS_OPEN_WRITE)) == 0U ||
      ((flags & (XAIOS_VFS_OPEN_CREATE | XAIOS_VFS_OPEN_TRUNCATE)) != 0U &&
       (flags & XAIOS_VFS_OPEN_WRITE) == 0U)) {
    return XAIOS_ERR_INVALID;
  }
  xaios_vfs_resolution_t resolution;
  if (vfs_resolve(path, &resolution) != XAIOS_OK) return XAIOS_ERR_NOT_FOUND;
  vfs_mount_record_t *mount = &vfs_mounts[resolution.mount_index];
  if ((mount->flags & XAIOS_VFS_MOUNT_READ_ONLY) != 0U &&
      mutating_flags(flags)) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  uint32_t index = XAIOS_VFS_MAX_HANDLES;
  for (uint32_t candidate = 0U; candidate < XAIOS_VFS_MAX_HANDLES;
       ++candidate) {
    if (vfs_handles[candidate].active == 0U) {
      index = candidate;
      break;
    }
  }
  if (index == XAIOS_VFS_MAX_HANDLES) return XAIOS_ERR_NO_MEMORY;
  uint64_t backend_handle = 0U;
  xaios_status_t status = mount->ops->open(
      mount->context, resolution.relative_path, flags, &backend_handle);
  if (status != XAIOS_OK) return status;
  vfs_handle_record_t *handle = &vfs_handles[index];
  vfs_bytes_zero(handle, sizeof(*handle));
  handle->active = 1U;
  handle->owner_id = owner_id;
  handle->flags = flags;
  handle->mount_index = resolution.mount_index;
  handle->mount_generation = mount->generation;
  handle->backend_handle = backend_handle;
  ++mount->open_handles;
  return (int64_t)(index + 1U);
}

xaios_status_t vfs_close_locked(uint32_t fd, uint32_t owner_id) {
  vfs_handle_record_t *handle = find_handle(fd, owner_id);
  if (handle == 0) return XAIOS_ERR_INVALID;
  vfs_mount_record_t *mount = &vfs_mounts[handle->mount_index];
  xaios_status_t status =
      mount->ops->close(mount->context, handle->backend_handle);
  if (status != XAIOS_OK) return status;
  if (mount->open_handles == 0U) return XAIOS_ERR_INVALID;
  --mount->open_handles;
  vfs_bytes_zero(handle, sizeof(*handle));
  return XAIOS_OK;
}

xaios_status_t vfs_release_owner_locked(uint32_t owner_id) {
  if (owner_id == 0U) return XAIOS_ERR_INVALID;
  xaios_status_t result = XAIOS_OK;
  for (uint32_t index = 0U; index < XAIOS_VFS_MAX_HANDLES; ++index) {
    vfs_handle_record_t *handle = &vfs_handles[index];
    if (handle->active == 0U || handle->owner_id != owner_id) continue;
    if (handle->mount_index >= XAIOS_VFS_MAX_MOUNTS) {
      vfs_bytes_zero(handle, sizeof(*handle));
      result = XAIOS_ERR_INVALID;
      continue;
    }
    vfs_mount_record_t *mount = &vfs_mounts[handle->mount_index];
    if (mount->active == 0U ||
        mount->generation != handle->mount_generation) {
      vfs_bytes_zero(handle, sizeof(*handle));
      result = XAIOS_ERR_INVALID;
      continue;
    }
    if (mount->ops->close(mount->context, handle->backend_handle) != XAIOS_OK) {
      result = XAIOS_ERR_IO;
    }
    if (mount->open_handles == 0U) {
      result = XAIOS_ERR_INVALID;
    } else {
      --mount->open_handles;
    }
    vfs_bytes_zero(handle, sizeof(*handle));
  }
  return result;
}

int64_t vfs_pread_locked(uint32_t fd, uint32_t owner_id, void *buffer, uint64_t length, uint64_t offset) {
  vfs_handle_record_t *handle = find_handle(fd, owner_id);
  if (handle == 0 || buffer == 0 ||
      (handle->flags & XAIOS_VFS_OPEN_READ) == 0U) {
    return XAIOS_ERR_INVALID;
  }
  vfs_mount_record_t *mount = &vfs_mounts[handle->mount_index];
  return mount->ops->pread(mount->context, handle->backend_handle, buffer,
                           length, offset);
}

int64_t vfs_pwrite_locked(uint32_t fd, uint32_t owner_id, const void *buffer, uint64_t length, uint64_t offset) {
  vfs_handle_record_t *handle = find_handle(fd, owner_id);
  if (handle == 0 || buffer == 0 ||
      (handle->flags & XAIOS_VFS_OPEN_WRITE) == 0U) {
    return XAIOS_ERR_INVALID;
  }
  vfs_mount_record_t *mount = &vfs_mounts[handle->mount_index];
  if ((mount->flags & XAIOS_VFS_MOUNT_READ_ONLY) != 0U ||
      mount->ops->pwrite == 0) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  return mount->ops->pwrite(mount->context, handle->backend_handle, buffer,
                            length, offset);
}

int64_t vfs_read_locked(uint32_t fd, uint32_t owner_id, void *buffer, uint64_t length) {
  vfs_handle_record_t *handle = find_handle(fd, owner_id);
  if (handle == 0) return XAIOS_ERR_INVALID;
  int64_t result = vfs_pread_locked(fd, owner_id, buffer, length,
                                    handle->cursor);
  if (result > 0) {
    if ((uint64_t)result > UINT64_MAX - handle->cursor) return XAIOS_ERR_INVALID;
    handle->cursor += (uint64_t)result;
  }
  return result;
}

int64_t vfs_write_locked(uint32_t fd, uint32_t owner_id, const void *buffer, uint64_t length) {
  vfs_handle_record_t *handle = find_handle(fd, owner_id);
  if (handle == 0) return XAIOS_ERR_INVALID;
  int64_t result = vfs_pwrite_locked(fd, owner_id, buffer, length,
                                     handle->cursor);
  if (result > 0) {
    if ((uint64_t)result > UINT64_MAX - handle->cursor) return XAIOS_ERR_INVALID;
    handle->cursor += (uint64_t)result;
  }
  return result;
}

xaios_status_t vfs_seek_locked(uint32_t fd, uint32_t owner_id, uint64_t offset) {
  vfs_handle_record_t *handle = find_handle(fd, owner_id);
  if (handle == 0) return XAIOS_ERR_INVALID;
  handle->cursor = offset;
  return XAIOS_OK;
}

xaios_status_t vfs_fsync_locked(uint32_t fd, uint32_t owner_id) {
  vfs_handle_record_t *handle = find_handle(fd, owner_id);
  if (handle == 0) return XAIOS_ERR_INVALID;
  vfs_mount_record_t *mount = &vfs_mounts[handle->mount_index];
  return mount->ops->fsync != 0
             ? mount->ops->fsync(mount->context, handle->backend_handle)
             : XAIOS_ERR_UNSUPPORTED;
}

xaios_status_t vfs_truncate_locked(uint32_t fd, uint32_t owner_id, uint64_t size) {
  vfs_handle_record_t *handle = find_handle(fd, owner_id);
  if (handle == 0 || (handle->flags & XAIOS_VFS_OPEN_WRITE) == 0U) {
    return XAIOS_ERR_INVALID;
  }
  vfs_mount_record_t *mount = &vfs_mounts[handle->mount_index];
  if ((mount->flags & XAIOS_VFS_MOUNT_READ_ONLY) != 0U ||
      mount->ops->truncate == 0) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  return mount->ops->truncate(mount->context, handle->backend_handle, size);
}

xaios_status_t vfs_fallocate_locked(uint32_t fd, uint32_t owner_id, uint64_t offset, uint64_t length) {
  vfs_handle_record_t *handle = find_handle(fd, owner_id);
  if (handle == 0 || length == 0U || offset > UINT64_MAX - length ||
      (handle->flags & XAIOS_VFS_OPEN_WRITE) == 0U) {
    return XAIOS_ERR_INVALID;
  }
  vfs_mount_record_t *mount = &vfs_mounts[handle->mount_index];
  if ((mount->flags & XAIOS_VFS_MOUNT_READ_ONLY) != 0U ||
      mount->ops->fallocate == 0) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  return mount->ops->fallocate(mount->context, handle->backend_handle, offset,
                               length);
}
