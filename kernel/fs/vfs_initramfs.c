#include <xaios/initramfs.h>
#include <xaios/vfs.h>

/* Read-only VFS view of the boot image, so userspace utilities can list and
   read what the kernel loads from it. Without this, /bin exists only as the
   kernel's private launch table: the shell can run /bin/htop while ls shows
   an empty directory, which reads as a broken system rather than a design.

   The image is immutable after initramfs_init and the mount is declared
   read-only, so the adapter carries no locking and no mutation entry points.
   Backend handles are the file's table index plus one, so zero stays the
   "no handle" value. */

#define INITRAXBFS_VFS_NAME_MAX 64U

/* One prefix per mount, not one for the adapter.

   This was a single global, which silently made the initramfs mountable
   exactly once: a second mount overwrote the prefix and the first mount's
   paths began resolving under the second's. Nothing noticed because only
   /bin was ever mounted. A live boot needs /etc from here too -- it is the
   only place the credentials exist when there is no durable volume -- so the
   prefix belongs to the mount, and the mount carries it as its context. */
#define INITRAMFS_VFS_MAX_MOUNTS 4U

static char g_mount_prefix[INITRAMFS_VFS_MAX_MOUNTS][XAIOS_VFS_PATH_MAX];
static uint32_t g_mount_count;

/* Contexts are the slot index plus one, so zero stays "no context" and a
   caller that passes none resolves against the first mount rather than
   reading a null pointer. */
static const char *prefix_of(void *context) {
  uint64_t slot = (uint64_t)(uintptr_t)context;
  if (slot == 0U || slot > INITRAMFS_VFS_MAX_MOUNTS) return "";
  return g_mount_prefix[slot - 1U];
}

static xaios_status_t absolute_path(const char *prefix, const char *relative,
                                    char *out, uint64_t capacity) {
  uint64_t used = 0U;
  if (relative == 0 || relative[0] != '/') return XAIOS_ERR_INVALID;
  while (prefix[used] != '\0') {
    if (used + 1U >= capacity) return XAIOS_ERR_INVALID;
    out[used] = prefix[used];
    ++used;
  }
  /* The mount root itself arrives as "/": the prefix already names it. */
  if (relative[1] != '\0') {
    for (uint64_t i = 0U; relative[i] != '\0'; ++i) {
      if (used + 1U >= capacity) return XAIOS_ERR_INVALID;
      out[used++] = relative[i];
    }
  }
  out[used] = '\0';
  return XAIOS_OK;
}

static xaios_status_t find_file(const char *prefix, const char *relative,
                                uint32_t *out_index) {
  char path[XAIOS_VFS_PATH_MAX];
  xaios_status_t status = absolute_path(prefix, relative, path, sizeof(path));
  if (status != XAIOS_OK) return status;
  for (uint32_t i = 0U; i < initramfs_file_count(); ++i) {
    const xaios_initramfs_file_t *file = initramfs_file_at(i);
    uint64_t j = 0U;
    while (file->path[j] != '\0' && file->path[j] == path[j]) ++j;
    if (file->path[j] == '\0' && path[j] == '\0') {
      *out_index = i;
      return XAIOS_OK;
    }
  }
  return XAIOS_ERR_NOT_FOUND;
}

static xaios_status_t initramfs_vfs_open(void *context, const char *path,
                                         uint32_t flags, uint64_t *handle) {
  uint32_t index = 0U;
  if (handle == 0 ||
      (flags & (XAIOS_VFS_OPEN_WRITE | XAIOS_VFS_OPEN_CREATE |
                XAIOS_VFS_OPEN_TRUNCATE)) != 0U) {
    return XAIOS_ERR_INVALID;
  }
  if (find_file(prefix_of(context), path, &index) != XAIOS_OK) {
    return XAIOS_ERR_NOT_FOUND;
  }
  *handle = (uint64_t)index + 1U;
  return XAIOS_OK;
}

static xaios_status_t initramfs_vfs_close(void *context, uint64_t handle) {
  (void)context;
  return handle != 0U && handle <= initramfs_file_count() ? XAIOS_OK
                                                          : XAIOS_ERR_INVALID;
}

static int64_t initramfs_vfs_pread(void *context, uint64_t handle,
                                   void *buffer, uint64_t length,
                                   uint64_t offset) {
  const xaios_initramfs_file_t *file;
  const uint8_t *base;
  uint8_t *out = (uint8_t *)buffer;
  (void)context;
  if (buffer == 0 || handle == 0U || handle > initramfs_file_count()) {
    return -1;
  }
  file = initramfs_file_at((uint32_t)(handle - 1U));
  if (file == 0 || file->base == 0) return -1;
  if (offset >= file->size) return 0;
  if (length > file->size - offset) length = file->size - offset;
  if (length > INT64_MAX) return -1;
  base = (const uint8_t *)file->base + offset;
  for (uint64_t i = 0U; i < length; ++i) out[i] = base[i];
  return (int64_t)length;
}

static xaios_status_t initramfs_vfs_stat(void *context, const char *path,
                                         xaios_vfs_stat_t *stat) {
  char absolute[XAIOS_VFS_PATH_MAX];
  uint32_t index = 0U;
  if (stat == 0) return XAIOS_ERR_INVALID;
  stat->block_count = 0U;
  stat->generation = 0U;
  stat->content_hash = 0U;
  if (find_file(prefix_of(context), path, &index) == XAIOS_OK) {
    const xaios_initramfs_file_t *file = initramfs_file_at(index);
    stat->type = 2U;
    stat->size = file->size;
    stat->content_hash = file->content_hash;
    return XAIOS_OK;
  }
  if (absolute_path(prefix_of(context), path, absolute,
                    sizeof(absolute)) == XAIOS_OK &&
      initramfs_directory_exists(absolute) != 0) {
    stat->type = 1U;
    stat->size = 0U;
    return XAIOS_OK;
  }
  return XAIOS_ERR_NOT_FOUND;
}

static xaios_status_t initramfs_vfs_statfs(void *context,
                                           xaios_vfs_statfs_t *statfs) {
  uint64_t total = 0U;
  (void)context;
  if (statfs == 0) return XAIOS_ERR_INVALID;
  for (uint32_t i = 0U; i < initramfs_file_count(); ++i) {
    total += initramfs_file_at(i)->size;
  }
  statfs->total_bytes = total;
  statfs->allocated_bytes = total;
  statfs->free_bytes = 0U;
  statfs->reserved_bytes = 0U;
  statfs->file_count = initramfs_file_count();
  statfs->directory_count = 0U;
  statfs->generation = 1U;
  statfs->block_size = 1U;
  statfs->read_only = 1U;
  statfs->format_version = 1U;
  return XAIOS_OK;
}

static xaios_status_t initramfs_vfs_list(void *context, const char *path,
                                         char *buffer, uint64_t capacity,
                                         uint64_t *out_size) {
  char absolute[XAIOS_VFS_PATH_MAX];
  uint64_t used = 0U;
  int found = 0;
  if (buffer == 0 || out_size == 0) return XAIOS_ERR_INVALID;
  if (absolute_path(prefix_of(context), path, absolute,
                    sizeof(absolute)) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  if (initramfs_directory_exists(absolute) == 0) return XAIOS_ERR_NOT_FOUND;
  for (uint32_t i = 0U; i < initramfs_file_count(); ++i) {
    char name[INITRAXBFS_VFS_NAME_MAX];
    int is_directory = 0;
    if (initramfs_child_at(absolute, i, name, sizeof(name), &is_directory) ==
        0) {
      continue;
    }
    if (is_directory != 0) {
      /* Subdirectories repeat for every file below them; keep the first. */
      char earlier[INITRAXBFS_VFS_NAME_MAX];
      int earlier_directory = 0;
      uint32_t seen = 0U;
      for (uint32_t j = 0U; j < i && seen == 0U; ++j) {
        if (initramfs_child_at(absolute, j, earlier, sizeof(earlier),
                               &earlier_directory) != 0 &&
            earlier_directory != 0) {
          uint32_t k = 0U;
          while (earlier[k] != '\0' && earlier[k] == name[k]) ++k;
          if (earlier[k] == '\0' && name[k] == '\0') seen = 1U;
        }
      }
      if (seen != 0U) continue;
    }
    for (uint64_t j = 0U; name[j] != '\0'; ++j) {
      if (used + 2U > capacity) return XAIOS_ERR_NO_MEMORY;
      buffer[used++] = name[j];
    }
    if (used + 1U > capacity) return XAIOS_ERR_NO_MEMORY;
    buffer[used++] = '\n';
    found = 1;
  }
  (void)found;
  *out_size = used;
  return XAIOS_OK;
}

static const xaios_vfs_backend_ops_t k_initramfs_ops = {
    initramfs_vfs_open, initramfs_vfs_close, initramfs_vfs_pread,
    0 /* pwrite */,     0 /* fsync */,       0 /* truncate */,
    0 /* fallocate */,  initramfs_vfs_stat,  initramfs_vfs_statfs,
    0 /* mkdir */,      0 /* rmdir */,       0 /* unlink */,
    0 /* rename */,     initramfs_vfs_list,
};

xaios_status_t vfs_mount_initramfs(const char *mount_path) {
  uint64_t i = 0U;
  if (mount_path == 0 || mount_path[0] != '/' || mount_path[1] == '\0') {
    return XAIOS_ERR_INVALID;
  }
  if (g_mount_count >= INITRAMFS_VFS_MAX_MOUNTS) return XAIOS_ERR_NO_MEMORY;
  char *prefix = g_mount_prefix[g_mount_count];
  while (mount_path[i] != '\0') {
    if (i + 1U >= XAIOS_VFS_PATH_MAX) return XAIOS_ERR_INVALID;
    prefix[i] = mount_path[i];
    ++i;
  }
  prefix[i] = '\0';
  if (initramfs_directory_exists(prefix) == 0) return XAIOS_ERR_NOT_FOUND;
  /* Claim the slot only once the mount is going to be attempted, so a
     rejected path does not consume one. */
  void *context = (void *)(uintptr_t)(uint64_t)(g_mount_count + 1U);
  xaios_status_t status = vfs_mount(mount_path, &k_initramfs_ops, context,
                                    XAIOS_VFS_MOUNT_READ_ONLY);
  if (status == XAIOS_OK) ++g_mount_count;
  return status;
}
