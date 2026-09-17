/*
 * Path normalisation, the mount table and the namespace half of the VFS:
 * mount/unmount, lookup and the path-based operations (stat, statfs, mkdir,
 * rmdir, unlink, delete, rename and list).
 *
 * Split out of vfs.c, which was 757 lines. The mount table and the generation
 * counter are defined here because this unit owns them; vfs_handle.c reaches
 * them through vfs_internal.h. Every operation ending in _locked assumes the
 * lock in vfs.c is held, exactly as the static functions it replaces did, and
 * takes no lock itself. The generation counter is bumped in the same order as
 * before: vfs_init first, then each mount.
 */

#include "vfs_internal.h"

vfs_mount_record_t vfs_mounts[XAIOS_VFS_MAX_MOUNTS];
uint64_t vfs_next_generation;

void vfs_bytes_zero(void *buffer, uint64_t length) {
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
    if (vfs_mounts[index].active == 0U ||
        !mount_matches(vfs_mounts[index].path, path)) {
      continue;
    }
    uint64_t length = string_length(vfs_mounts[index].path);
    if (selected == XAIOS_VFS_MAX_MOUNTS || length > selected_length) {
      selected = index;
      selected_length = length;
    }
  }
  if (selected == XAIOS_VFS_MAX_MOUNTS) return XAIOS_ERR_NOT_FOUND;
  resolution->mount_index = selected;
  resolution->mount_flags = vfs_mounts[selected].flags;
  resolution->mount_generation = vfs_mounts[selected].generation;
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

xaios_status_t vfs_mount_locked(const char *mount_path, const xaios_vfs_backend_ops_t *ops, void *context, uint32_t flags) {
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
    if (vfs_mounts[index].active != 0U &&
        string_equal(vfs_mounts[index].path, normalized)) {
      return XAIOS_ERR_BUSY;
    }
    if (vfs_mounts[index].active == 0U && available == XAIOS_VFS_MAX_MOUNTS) {
      available = index;
    }
  }
  if (available == XAIOS_VFS_MAX_MOUNTS) return XAIOS_ERR_NO_MEMORY;
  vfs_mount_record_t *mount = &vfs_mounts[available];
  vfs_bytes_zero(mount, sizeof(*mount));
  mount->active = 1U;
  mount->flags = flags;
  if (++vfs_next_generation == 0U) ++vfs_next_generation;
  mount->generation = vfs_next_generation;
  mount->ops = ops;
  mount->context = context;
  string_copy(mount->path, normalized);
  return XAIOS_OK;
}

xaios_status_t vfs_unmount_locked(const char *mount_path) {
  char normalized[XAIOS_VFS_PATH_MAX];
  if (normalize_path(mount_path, normalized) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  for (uint32_t index = 0U; index < XAIOS_VFS_MAX_MOUNTS; ++index) {
    vfs_mount_record_t *mount = &vfs_mounts[index];
    if (mount->active == 0U || !string_equal(mount->path, normalized)) continue;
    if (mount->open_handles != 0U) return XAIOS_ERR_BUSY;
    vfs_bytes_zero(mount, sizeof(*mount));
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

static xaios_status_t resolve_operation(const char *path,
                                        xaios_vfs_resolution_t *resolution,
                                        vfs_mount_record_t **mount) {
  xaios_status_t status = vfs_resolve(path, resolution);
  if (status != XAIOS_OK) return status;
  *mount = &vfs_mounts[resolution->mount_index];
  return XAIOS_OK;
}

xaios_status_t vfs_stat_locked(const char *path, xaios_vfs_stat_t *stat) {
  if (stat == 0) return XAIOS_ERR_INVALID;
  xaios_vfs_resolution_t resolution;
  vfs_mount_record_t *mount = 0;
  xaios_status_t status = resolve_operation(path, &resolution, &mount);
  return status == XAIOS_OK
             ? mount->ops->stat(mount->context, resolution.relative_path, stat)
             : status;
}

xaios_status_t vfs_statfs_locked(const char *path, xaios_vfs_statfs_t *statfs) {
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

xaios_status_t vfs_mkdir_locked(const char *path) {
  xaios_vfs_resolution_t resolution;
  vfs_mount_record_t *mount = 0;
  xaios_status_t status = resolve_operation(path, &resolution, &mount);
  return status == XAIOS_OK ? path_mutation(path, mount->ops->mkdir) : status;
}

xaios_status_t vfs_rmdir_locked(const char *path) {
  xaios_vfs_resolution_t resolution;
  vfs_mount_record_t *mount = 0;
  xaios_status_t status = resolve_operation(path, &resolution, &mount);
  return status == XAIOS_OK ? path_mutation(path, mount->ops->rmdir) : status;
}

xaios_status_t vfs_unlink_locked(const char *path) {
  xaios_vfs_resolution_t resolution;
  vfs_mount_record_t *mount = 0;
  xaios_status_t status = resolve_operation(path, &resolution, &mount);
  return status == XAIOS_OK ? path_mutation(path, mount->ops->unlink) : status;
}

xaios_status_t vfs_delete_locked(const char *path) {
  xaios_vfs_stat_t stat;
  xaios_status_t status = vfs_stat_locked(path, &stat);
  if (status != XAIOS_OK) return status;
  return stat.type == XAIOS_VFS_TYPE_DIRECTORY ? vfs_rmdir_locked(path)
                                                : vfs_unlink_locked(path);
}

xaios_status_t vfs_rename_locked(const char *old_path, const char *new_path) {
  xaios_vfs_resolution_t old_resolution;
  xaios_vfs_resolution_t new_resolution;
  if (vfs_resolve(old_path, &old_resolution) != XAIOS_OK ||
      vfs_resolve(new_path, &new_resolution) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  if (old_resolution.mount_index != new_resolution.mount_index) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  vfs_mount_record_t *mount = &vfs_mounts[old_resolution.mount_index];
  if ((mount->flags & XAIOS_VFS_MOUNT_READ_ONLY) != 0U ||
      mount->ops->rename == 0) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  return mount->ops->rename(mount->context, old_resolution.relative_path,
                            new_resolution.relative_path);
}

xaios_status_t vfs_list_locked(const char *path, char *buffer, uint64_t capacity, uint64_t *out_size) {
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
    const vfs_mount_record_t *candidate = &vfs_mounts[index];
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
