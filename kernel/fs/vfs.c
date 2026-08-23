#include <xaios/vfs.h>
#include <xaios/spinlock.h>

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

static vfs_mount_record_t g_mounts[XAIOS_VFS_MAX_MOUNTS];
static xaios_spinlock_t g_vfs_lock = XAIOS_SPINLOCK_INIT;
static vfs_handle_record_t g_handles[XAIOS_VFS_MAX_HANDLES];
static uint64_t g_next_generation;

static void bytes_zero(void *buffer, uint64_t length) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0U; i < length; ++i) bytes[i] = 0U;
}

static void string_copy(char *destination, const char *source) {
  uint64_t index = 0U;
  while (source[index] != '\0') {
    destination[index] = source[index];
    ++index;
  }
  destination[index] = '\0';
}

static uint64_t string_length(const char *value) {
  uint64_t length = 0U;
  if (value == 0) return XAIOS_VFS_PATH_MAX;
  while (length < XAIOS_VFS_PATH_MAX && value[length] != '\0') ++length;
  return length;
}

static int string_equal(const char *left, const char *right) {
  for (uint64_t index = 0U; index < XAIOS_VFS_PATH_MAX; ++index) {
    if (left[index] != right[index]) return 0;
    if (left[index] == '\0') return 1;
  }
  return 0;
}

static int utf8_sequence(const uint8_t *value, uint64_t remaining,
                         uint32_t *length) {
  uint8_t first = value[0];
  if (first < 0x80U) {
    if (first < 0x20U || first == 0x7fU) return 0;
    *length = 1U;
    return 1;
  }
  uint32_t count = 0U;
  uint32_t codepoint = 0U;
  uint32_t minimum = 0U;
  if ((first & 0xe0U) == 0xc0U) {
    count = 2U;
    codepoint = first & 0x1fU;
    minimum = 0x80U;
  } else if ((first & 0xf0U) == 0xe0U) {
    count = 3U;
    codepoint = first & 0x0fU;
    minimum = 0x800U;
  } else if ((first & 0xf8U) == 0xf0U) {
    count = 4U;
    codepoint = first & 0x07U;
    minimum = 0x10000U;
  } else {
    return 0;
  }
  if (remaining < count) return 0;
  for (uint32_t index = 1U; index < count; ++index) {
    if ((value[index] & 0xc0U) != 0x80U) return 0;
    codepoint = (codepoint << 6U) | (value[index] & 0x3fU);
  }
  if (codepoint < minimum || codepoint > 0x10ffffU ||
      (codepoint >= 0xd800U && codepoint <= 0xdfffU)) {
    return 0;
  }
  *length = count;
  return 1;
}

static xaios_status_t normalize_path(const char *source, char *destination) {
  uint64_t source_length = string_length(source);
  if (source_length == 0U || source_length >= XAIOS_VFS_PATH_MAX ||
      source[0] != '/') {
    return XAIOS_ERR_INVALID;
  }
  uint64_t input = 1U;
  uint64_t output = 1U;
  uint32_t components = 0U;
  destination[0] = '/';
  while (input < source_length) {
    while (input < source_length && source[input] == '/') ++input;
    if (input == source_length) break;
    uint64_t start = input;
    while (input < source_length && source[input] != '/') {
      uint32_t sequence = 0U;
      if (!utf8_sequence((const uint8_t *)source + input,
                         source_length - input, &sequence)) {
        return XAIOS_ERR_INVALID;
      }
      input += sequence;
    }
    uint64_t component_length = input - start;
    if (component_length == 1U && source[start] == '.') continue;
    if (component_length == 2U && source[start] == '.' &&
        source[start + 1U] == '.') {
      return XAIOS_ERR_INVALID;
    }
    if (component_length == 0U ||
        component_length > XAIOS_VFS_COMPONENT_MAX ||
        ++components > XAIOS_VFS_MAX_COMPONENTS ||
        output + component_length + 1U >= XAIOS_VFS_PATH_MAX) {
      return XAIOS_ERR_INVALID;
    }
    if (output != 1U) destination[output++] = '/';
    for (uint64_t index = 0U; index < component_length; ++index) {
      destination[output++] = source[start + index];
    }
  }
  destination[output] = '\0';
  return XAIOS_OK;
}

static int mount_matches(const char *mount_path, const char *path) {
  if (mount_path[0] == '/' && mount_path[1] == '\0') return 1;
  uint64_t length = string_length(mount_path);
  for (uint64_t index = 0U; index < length; ++index) {
    if (mount_path[index] != path[index]) return 0;
  }
  return path[length] == '\0' || path[length] == '/';
}

static xaios_status_t resolve_normalized(const char *path,
                                         xaios_vfs_resolution_t *resolution) {
  uint32_t selected = XAIOS_VFS_MAX_MOUNTS;
  uint64_t selected_length = 0U;
  for (uint32_t index = 0U; index < XAIOS_VFS_MAX_MOUNTS; ++index) {
    if (g_mounts[index].active == 0U ||
        !mount_matches(g_mounts[index].path, path)) {
      continue;
    }
    uint64_t length = string_length(g_mounts[index].path);
    if (selected == XAIOS_VFS_MAX_MOUNTS || length > selected_length) {
      selected = index;
      selected_length = length;
    }
  }
  if (selected == XAIOS_VFS_MAX_MOUNTS) return XAIOS_ERR_NOT_FOUND;
  resolution->mount_index = selected;
  resolution->mount_flags = g_mounts[selected].flags;
  resolution->mount_generation = g_mounts[selected].generation;
  if (selected_length == 1U) {
    string_copy(resolution->relative_path, path);
  } else if (path[selected_length] == '\0') {
    resolution->relative_path[0] = '/';
    resolution->relative_path[1] = '\0';
  } else {
    string_copy(resolution->relative_path, path + selected_length);
  }
  return XAIOS_OK;
}

static vfs_handle_record_t *find_handle(uint32_t fd, uint32_t owner_id) {
  if (fd == 0U || fd > XAIOS_VFS_MAX_HANDLES) return 0;
  vfs_handle_record_t *handle = &g_handles[fd - 1U];
  if (handle->active == 0U || handle->owner_id != owner_id ||
      handle->mount_index >= XAIOS_VFS_MAX_MOUNTS) {
    return 0;
  }
  vfs_mount_record_t *mount = &g_mounts[handle->mount_index];
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

xaios_status_t vfs_init(void) {
  for (uint32_t index = 0U; index < XAIOS_VFS_MAX_HANDLES; ++index) {
    if (g_handles[index].active != 0U) return XAIOS_ERR_BUSY;
  }
  bytes_zero(g_mounts, sizeof(g_mounts));
  bytes_zero(g_handles, sizeof(g_handles));
  if (++g_next_generation == 0U) ++g_next_generation;
  return XAIOS_OK;
}

static xaios_status_t vfs_mount_locked(const char *mount_path, const xaios_vfs_backend_ops_t *ops, void *context, uint32_t flags) {
  if (ops == 0 || ops->open == 0 || ops->close == 0 || ops->pread == 0 ||
      ops->stat == 0 || flags & ~XAIOS_VFS_MOUNT_READ_ONLY) {
    return XAIOS_ERR_INVALID;
  }
  char normalized[XAIOS_VFS_PATH_MAX];
  if (normalize_path(mount_path, normalized) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  uint32_t available = XAIOS_VFS_MAX_MOUNTS;
  for (uint32_t index = 0U; index < XAIOS_VFS_MAX_MOUNTS; ++index) {
    if (g_mounts[index].active != 0U &&
        string_equal(g_mounts[index].path, normalized)) {
      return XAIOS_ERR_BUSY;
    }
    if (g_mounts[index].active == 0U && available == XAIOS_VFS_MAX_MOUNTS) {
      available = index;
    }
  }
  if (available == XAIOS_VFS_MAX_MOUNTS) return XAIOS_ERR_NO_MEMORY;
  vfs_mount_record_t *mount = &g_mounts[available];
  bytes_zero(mount, sizeof(*mount));
  mount->active = 1U;
  mount->flags = flags;
  if (++g_next_generation == 0U) ++g_next_generation;
  mount->generation = g_next_generation;
  mount->ops = ops;
  mount->context = context;
  string_copy(mount->path, normalized);
  return XAIOS_OK;
}

static xaios_status_t vfs_unmount_locked(const char *mount_path) {
  char normalized[XAIOS_VFS_PATH_MAX];
  if (normalize_path(mount_path, normalized) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  for (uint32_t index = 0U; index < XAIOS_VFS_MAX_MOUNTS; ++index) {
    vfs_mount_record_t *mount = &g_mounts[index];
    if (mount->active == 0U || !string_equal(mount->path, normalized)) continue;
    if (mount->open_handles != 0U) return XAIOS_ERR_BUSY;
    bytes_zero(mount, sizeof(*mount));
    return XAIOS_OK;
  }
  return XAIOS_ERR_NOT_FOUND;
}

xaios_status_t vfs_resolve(const char *path,
                           xaios_vfs_resolution_t *resolution) {
  if (resolution == 0) return XAIOS_ERR_INVALID;
  char normalized[XAIOS_VFS_PATH_MAX];
  if (normalize_path(path, normalized) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  return resolve_normalized(normalized, resolution);
}

static int64_t vfs_open_locked(const char *path, uint32_t flags, uint32_t owner_id) {
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
  vfs_mount_record_t *mount = &g_mounts[resolution.mount_index];
  if ((mount->flags & XAIOS_VFS_MOUNT_READ_ONLY) != 0U &&
      mutating_flags(flags)) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  uint32_t index = XAIOS_VFS_MAX_HANDLES;
  for (uint32_t candidate = 0U; candidate < XAIOS_VFS_MAX_HANDLES;
       ++candidate) {
    if (g_handles[candidate].active == 0U) {
      index = candidate;
      break;
    }
  }
  if (index == XAIOS_VFS_MAX_HANDLES) return XAIOS_ERR_NO_MEMORY;
  uint64_t backend_handle = 0U;
  xaios_status_t status = mount->ops->open(
      mount->context, resolution.relative_path, flags, &backend_handle);
  if (status != XAIOS_OK) return status;
  vfs_handle_record_t *handle = &g_handles[index];
  bytes_zero(handle, sizeof(*handle));
  handle->active = 1U;
  handle->owner_id = owner_id;
  handle->flags = flags;
  handle->mount_index = resolution.mount_index;
  handle->mount_generation = mount->generation;
  handle->backend_handle = backend_handle;
  ++mount->open_handles;
  return (int64_t)(index + 1U);
}

static xaios_status_t vfs_close_locked(uint32_t fd, uint32_t owner_id) {
  vfs_handle_record_t *handle = find_handle(fd, owner_id);
  if (handle == 0) return XAIOS_ERR_INVALID;
  vfs_mount_record_t *mount = &g_mounts[handle->mount_index];
  xaios_status_t status =
      mount->ops->close(mount->context, handle->backend_handle);
  if (status != XAIOS_OK) return status;
  if (mount->open_handles == 0U) return XAIOS_ERR_INVALID;
  --mount->open_handles;
  bytes_zero(handle, sizeof(*handle));
  return XAIOS_OK;
}

static xaios_status_t vfs_release_owner_locked(uint32_t owner_id) {
  if (owner_id == 0U) return XAIOS_ERR_INVALID;
  xaios_status_t result = XAIOS_OK;
  for (uint32_t index = 0U; index < XAIOS_VFS_MAX_HANDLES; ++index) {
    vfs_handle_record_t *handle = &g_handles[index];
    if (handle->active == 0U || handle->owner_id != owner_id) continue;
    if (handle->mount_index >= XAIOS_VFS_MAX_MOUNTS) {
      bytes_zero(handle, sizeof(*handle));
      result = XAIOS_ERR_INVALID;
      continue;
    }
    vfs_mount_record_t *mount = &g_mounts[handle->mount_index];
    if (mount->active == 0U ||
        mount->generation != handle->mount_generation) {
      bytes_zero(handle, sizeof(*handle));
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
    bytes_zero(handle, sizeof(*handle));
  }
  return result;
}

static int64_t vfs_pread_locked(uint32_t fd, uint32_t owner_id, void *buffer, uint64_t length, uint64_t offset) {
  vfs_handle_record_t *handle = find_handle(fd, owner_id);
  if (handle == 0 || buffer == 0 ||
      (handle->flags & XAIOS_VFS_OPEN_READ) == 0U) {
    return XAIOS_ERR_INVALID;
  }
  vfs_mount_record_t *mount = &g_mounts[handle->mount_index];
  return mount->ops->pread(mount->context, handle->backend_handle, buffer,
                           length, offset);
}

static int64_t vfs_pwrite_locked(uint32_t fd, uint32_t owner_id, const void *buffer, uint64_t length, uint64_t offset) {
  vfs_handle_record_t *handle = find_handle(fd, owner_id);
  if (handle == 0 || buffer == 0 ||
      (handle->flags & XAIOS_VFS_OPEN_WRITE) == 0U) {
    return XAIOS_ERR_INVALID;
  }
  vfs_mount_record_t *mount = &g_mounts[handle->mount_index];
  if ((mount->flags & XAIOS_VFS_MOUNT_READ_ONLY) != 0U ||
      mount->ops->pwrite == 0) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  return mount->ops->pwrite(mount->context, handle->backend_handle, buffer,
                            length, offset);
}

static int64_t vfs_read_locked(uint32_t fd, uint32_t owner_id, void *buffer, uint64_t length) {
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

static int64_t vfs_write_locked(uint32_t fd, uint32_t owner_id, const void *buffer, uint64_t length) {
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

static xaios_status_t vfs_seek_locked(uint32_t fd, uint32_t owner_id, uint64_t offset) {
  vfs_handle_record_t *handle = find_handle(fd, owner_id);
  if (handle == 0) return XAIOS_ERR_INVALID;
  handle->cursor = offset;
  return XAIOS_OK;
}

static xaios_status_t vfs_fsync_locked(uint32_t fd, uint32_t owner_id) {
  vfs_handle_record_t *handle = find_handle(fd, owner_id);
  if (handle == 0) return XAIOS_ERR_INVALID;
  vfs_mount_record_t *mount = &g_mounts[handle->mount_index];
  return mount->ops->fsync != 0
             ? mount->ops->fsync(mount->context, handle->backend_handle)
             : XAIOS_ERR_UNSUPPORTED;
}

static xaios_status_t vfs_truncate_locked(uint32_t fd, uint32_t owner_id, uint64_t size) {
  vfs_handle_record_t *handle = find_handle(fd, owner_id);
  if (handle == 0 || (handle->flags & XAIOS_VFS_OPEN_WRITE) == 0U) {
    return XAIOS_ERR_INVALID;
  }
  vfs_mount_record_t *mount = &g_mounts[handle->mount_index];
  if ((mount->flags & XAIOS_VFS_MOUNT_READ_ONLY) != 0U ||
      mount->ops->truncate == 0) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  return mount->ops->truncate(mount->context, handle->backend_handle, size);
}

static xaios_status_t vfs_fallocate_locked(uint32_t fd, uint32_t owner_id, uint64_t offset, uint64_t length) {
  vfs_handle_record_t *handle = find_handle(fd, owner_id);
  if (handle == 0 || length == 0U || offset > UINT64_MAX - length ||
      (handle->flags & XAIOS_VFS_OPEN_WRITE) == 0U) {
    return XAIOS_ERR_INVALID;
  }
  vfs_mount_record_t *mount = &g_mounts[handle->mount_index];
  if ((mount->flags & XAIOS_VFS_MOUNT_READ_ONLY) != 0U ||
      mount->ops->fallocate == 0) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  return mount->ops->fallocate(mount->context, handle->backend_handle, offset,
                               length);
}

static xaios_status_t resolve_operation(const char *path,
                                        xaios_vfs_resolution_t *resolution,
                                        vfs_mount_record_t **mount) {
  xaios_status_t status = vfs_resolve(path, resolution);
  if (status != XAIOS_OK) return status;
  *mount = &g_mounts[resolution->mount_index];
  return XAIOS_OK;
}

static xaios_status_t vfs_stat_locked(const char *path, xaios_vfs_stat_t *stat) {
  if (stat == 0) return XAIOS_ERR_INVALID;
  xaios_vfs_resolution_t resolution;
  vfs_mount_record_t *mount = 0;
  xaios_status_t status = resolve_operation(path, &resolution, &mount);
  return status == XAIOS_OK
             ? mount->ops->stat(mount->context, resolution.relative_path, stat)
             : status;
}

static xaios_status_t vfs_statfs_locked(const char *path, xaios_vfs_statfs_t *statfs) {
  if (statfs == 0) return XAIOS_ERR_INVALID;
  xaios_vfs_resolution_t resolution;
  vfs_mount_record_t *mount = 0;
  xaios_status_t status = resolve_operation(path, &resolution, &mount);
  if (status != XAIOS_OK || mount->ops->statfs == 0) {
    return status != XAIOS_OK ? status : XAIOS_ERR_UNSUPPORTED;
  }
  status = mount->ops->statfs(mount->context, statfs);
  if (status == XAIOS_OK) {
    statfs->read_only =
        (mount->flags & XAIOS_VFS_MOUNT_READ_ONLY) != 0U;
  }
  return status;
}

static xaios_status_t path_mutation(
    const char *path,
    xaios_status_t (*operation)(void *, const char *)) {
  xaios_vfs_resolution_t resolution;
  vfs_mount_record_t *mount = 0;
  xaios_status_t status = resolve_operation(path, &resolution, &mount);
  if (status != XAIOS_OK) return status;
  if ((mount->flags & XAIOS_VFS_MOUNT_READ_ONLY) != 0U) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  if (operation == 0) return XAIOS_ERR_UNSUPPORTED;
  return operation(mount->context, resolution.relative_path);
}

static xaios_status_t vfs_mkdir_locked(const char *path) {
  xaios_vfs_resolution_t resolution;
  vfs_mount_record_t *mount = 0;
  xaios_status_t status = resolve_operation(path, &resolution, &mount);
  return status == XAIOS_OK ? path_mutation(path, mount->ops->mkdir) : status;
}

static xaios_status_t vfs_rmdir_locked(const char *path) {
  xaios_vfs_resolution_t resolution;
  vfs_mount_record_t *mount = 0;
  xaios_status_t status = resolve_operation(path, &resolution, &mount);
  return status == XAIOS_OK ? path_mutation(path, mount->ops->rmdir) : status;
}

static xaios_status_t vfs_unlink_locked(const char *path) {
  xaios_vfs_resolution_t resolution;
  vfs_mount_record_t *mount = 0;
  xaios_status_t status = resolve_operation(path, &resolution, &mount);
  return status == XAIOS_OK ? path_mutation(path, mount->ops->unlink) : status;
}

static xaios_status_t vfs_delete_locked(const char *path) {
  xaios_vfs_stat_t stat;
  xaios_status_t status = vfs_stat_locked(path, &stat);
  if (status != XAIOS_OK) return status;
  return stat.type == XAIOS_VFS_TYPE_DIRECTORY ? vfs_rmdir_locked(path)
                                                : vfs_unlink_locked(path);
}

static xaios_status_t vfs_rename_locked(const char *old_path, const char *new_path) {
  xaios_vfs_resolution_t old_resolution;
  xaios_vfs_resolution_t new_resolution;
  if (vfs_resolve(old_path, &old_resolution) != XAIOS_OK ||
      vfs_resolve(new_path, &new_resolution) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  if (old_resolution.mount_index != new_resolution.mount_index) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  vfs_mount_record_t *mount = &g_mounts[old_resolution.mount_index];
  if ((mount->flags & XAIOS_VFS_MOUNT_READ_ONLY) != 0U ||
      mount->ops->rename == 0) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  return mount->ops->rename(mount->context, old_resolution.relative_path,
                            new_resolution.relative_path);
}

static xaios_status_t vfs_list_locked(const char *path, char *buffer, uint64_t capacity, uint64_t *out_size) {
  if (buffer == 0 || capacity == 0U || out_size == 0) {
    return XAIOS_ERR_INVALID;
  }
  xaios_vfs_resolution_t resolution;
  vfs_mount_record_t *mount = 0;
  char normalized[XAIOS_VFS_PATH_MAX];
  xaios_status_t status = resolve_operation(path, &resolution, &mount);
  if (status != XAIOS_OK || mount->ops->list == 0) {
    return status != XAIOS_OK ? status : XAIOS_ERR_UNSUPPORTED;
  }
  status = mount->ops->list(mount->context, resolution.relative_path, buffer,
                            capacity, out_size);
  if (status != XAIOS_OK || normalize_path(path, normalized) != XAIOS_OK) {
    return status;
  }
  /* A mount point is a directory entry of its parent, but the parent's
     backend has never heard of it: without this, /bin is fully usable yet
     absent from a listing of /. Append the basename of every mount rooted
     one level below the listed directory, unless the backend already named
     it. */
  uint64_t base_length = string_length(normalized);
  if (base_length == 1U) base_length = 0U;
  for (uint32_t index = 0U; index < XAIOS_VFS_MAX_MOUNTS; ++index) {
    const vfs_mount_record_t *candidate = &g_mounts[index];
    const char *name;
    uint64_t name_length = 0U;
    if (candidate->active == 0U || candidate == mount) continue;
    if (!mount_matches(normalized, candidate->path) ||
        string_length(candidate->path) <= base_length) {
      continue;
    }
    name = candidate->path + base_length + 1U;
    while (name[name_length] != '\0' && name[name_length] != '/')
      ++name_length;
    if (name_length == 0U || name[name_length] == '/') continue;
    /* Skip when the backend listed the same name already. */
    {
      uint64_t line = 0U;
      int present = 0;
      while (line < *out_size && present == 0) {
        uint64_t end = line;
        while (end < *out_size && buffer[end] != '\n') ++end;
        if (end - line == name_length) {
          uint64_t i = 0U;
          while (i < name_length && buffer[line + i] == name[i]) ++i;
          if (i == name_length) present = 1;
        }
        line = end + 1U;
      }
      if (present != 0) continue;
    }
    if (*out_size + name_length + 1U > capacity) return XAIOS_ERR_NO_MEMORY;
    for (uint64_t i = 0U; i < name_length; ++i)
      buffer[*out_size + i] = name[i];
    buffer[*out_size + name_length] = '\n';
    *out_size += name_length + 1U;
  }
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

