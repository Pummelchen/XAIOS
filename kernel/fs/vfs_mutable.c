#include <xaios/mutable_fs.h>
#include <xaios/vfs.h>
#include <xaios/vfs_mutable.h>

static xaios_status_t mutable_open(void *context, const char *path,
                                   uint32_t flags, uint64_t *handle) {
  (void)context;
  int64_t fd = mutable_fs_open(path, flags);
  if (fd < 0) return (xaios_status_t)fd;
  *handle = (uint64_t)fd;
  return XAIOS_OK;
}

static xaios_status_t mutable_close(void *context, uint64_t handle) {
  (void)context;
  return handle <= UINT32_MAX ? mutable_fs_close((uint32_t)handle)
                              : XAIOS_ERR_INVALID;
}

static int64_t mutable_pread(void *context, uint64_t handle, void *buffer,
                             uint64_t length, uint64_t offset) {
  (void)context;
  if (handle > UINT32_MAX ||
      mutable_fs_seek((uint32_t)handle, offset) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  return mutable_fs_read_fd((uint32_t)handle, buffer, length);
}

static int64_t mutable_pwrite(void *context, uint64_t handle,
                              const void *buffer, uint64_t length,
                              uint64_t offset) {
  (void)context;
  if (handle > UINT32_MAX ||
      mutable_fs_seek((uint32_t)handle, offset) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  return mutable_fs_write_fd((uint32_t)handle, buffer, length);
}

static xaios_status_t mutable_fsync(void *context, uint64_t handle) {
  (void)context;
  (void)handle;
  /* MutableFS flushes each metadata/data mutation before returning. */
  return XAIOS_OK;
}

static xaios_status_t mutable_stat(void *context, const char *path,
                                   xaios_vfs_stat_t *stat) {
  (void)context;
  xaios_mfs_stat_t source;
  xaios_status_t status = mutable_fs_stat(path, &source);
  if (status != XAIOS_OK) return status;
  stat->type = source.type;
  stat->block_count = source.block_count;
  stat->size = source.size;
  stat->generation = source.generation;
  stat->content_hash = source.content_hash;
  return XAIOS_OK;
}

static xaios_status_t mutable_statfs(void *context,
                                     xaios_vfs_statfs_t *statfs) {
  (void)context;
  xaios_mfs_fsck_result_t fsck = mutable_fs_fsck();
  if (fsck.valid == 0U) return XAIOS_ERR_IO;
  uint64_t data_sectors = fsck.version >= 3U ? 256U : 96U;
  statfs->total_bytes = data_sectors * 512U;
  statfs->allocated_bytes = fsck.blocks_used * 512U;
  statfs->free_bytes = statfs->total_bytes - statfs->allocated_bytes;
  statfs->reserved_bytes = 0U;
  statfs->file_count = fsck.files;
  statfs->directory_count = fsck.directories;
  statfs->generation = 0U;
  statfs->block_size = 512U;
  statfs->read_only = 0U;
  statfs->format_version = fsck.version;
  return XAIOS_OK;
}

static xaios_status_t mutable_mkdir(void *context, const char *path) {
  (void)context;
  return mutable_fs_mkdir(path);
}

static xaios_status_t mutable_delete(void *context, const char *path) {
  (void)context;
  return mutable_fs_delete(path);
}

static xaios_status_t mutable_rename(void *context, const char *old_path,
                                     const char *new_path) {
  (void)context;
  return mutable_fs_rename(old_path, new_path);
}

static xaios_status_t mutable_list(void *context, const char *path,
                                   char *buffer, uint64_t capacity,
                                   uint64_t *out_size) {
  (void)context;
  return mutable_fs_list(path, buffer, capacity, out_size);
}

static const xaios_vfs_backend_ops_t k_mutable_ops = {
    mutable_open,
    mutable_close,
    mutable_pread,
    mutable_pwrite,
    mutable_fsync,
    0,
    0,
    mutable_stat,
    mutable_statfs,
    mutable_mkdir,
    mutable_delete,
    mutable_delete,
    mutable_rename,
    mutable_list,
};

xaios_status_t vfs_mount_mutable_root(void) {
  xaios_status_t status = vfs_init();
  if (status != XAIOS_OK) return status;
  return vfs_mount("/", &k_mutable_ops, 0, 0U);
}
