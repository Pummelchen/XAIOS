#ifndef XAIOS_VFS_H
#define XAIOS_VFS_H

#include <xaios/status.h>
#include <xaios/types.h>

#define XAIOS_VFS_PATH_MAX 1024U
#define XAIOS_VFS_COMPONENT_MAX 255U
#define XAIOS_VFS_MAX_COMPONENTS 32U
#define XAIOS_VFS_MAX_MOUNTS 16U
#define XAIOS_VFS_MAX_HANDLES 256U

#define XAIOS_VFS_OPEN_READ UINT32_C(1)
#define XAIOS_VFS_OPEN_WRITE UINT32_C(2)
#define XAIOS_VFS_OPEN_CREATE UINT32_C(4)
#define XAIOS_VFS_OPEN_TRUNCATE UINT32_C(8)

#define XAIOS_VFS_MOUNT_READ_ONLY UINT32_C(1)

#define XAIOS_VFS_TYPE_DIRECTORY UINT32_C(1)
#define XAIOS_VFS_TYPE_FILE UINT32_C(2)

typedef struct xaios_vfs_stat {
  uint32_t type;
  uint32_t block_count;
  uint64_t size;
  uint64_t generation;
  uint64_t content_hash;
} xaios_vfs_stat_t;

typedef struct xaios_vfs_statfs {
  uint64_t total_bytes;
  uint64_t allocated_bytes;
  uint64_t free_bytes;
  uint64_t reserved_bytes;
  uint64_t file_count;
  uint64_t directory_count;
  uint64_t generation;
  uint64_t block_size;
  uint32_t read_only;
  uint32_t format_version;
} xaios_vfs_statfs_t;

typedef struct xaios_vfs_backend_ops {
  xaios_status_t (*open)(void *context, const char *path, uint32_t flags,
                         uint64_t *handle);
  xaios_status_t (*close)(void *context, uint64_t handle);
  int64_t (*pread)(void *context, uint64_t handle, void *buffer,
                   uint64_t length, uint64_t offset);
  int64_t (*pwrite)(void *context, uint64_t handle, const void *buffer,
                    uint64_t length, uint64_t offset);
  xaios_status_t (*fsync)(void *context, uint64_t handle);
  xaios_status_t (*truncate)(void *context, uint64_t handle, uint64_t size);
  xaios_status_t (*fallocate)(void *context, uint64_t handle, uint64_t offset,
                              uint64_t length);
  xaios_status_t (*stat)(void *context, const char *path,
                         xaios_vfs_stat_t *stat);
  xaios_status_t (*statfs)(void *context, xaios_vfs_statfs_t *statfs);
  xaios_status_t (*mkdir)(void *context, const char *path);
  xaios_status_t (*rmdir)(void *context, const char *path);
  xaios_status_t (*unlink)(void *context, const char *path);
  xaios_status_t (*rename)(void *context, const char *old_path,
                           const char *new_path);
  xaios_status_t (*list)(void *context, const char *path, char *buffer,
                         uint64_t capacity, uint64_t *out_size);
} xaios_vfs_backend_ops_t;

typedef struct xaios_vfs_resolution {
  uint32_t mount_index;
  uint32_t mount_flags;
  uint64_t mount_generation;
  char relative_path[XAIOS_VFS_PATH_MAX];
} xaios_vfs_resolution_t;

xaios_status_t vfs_init(void);
xaios_status_t vfs_mount(const char *mount_path,
                         const xaios_vfs_backend_ops_t *ops, void *context,
                         uint32_t flags);
xaios_status_t vfs_unmount(const char *mount_path);
xaios_status_t vfs_resolve(const char *path,
                           xaios_vfs_resolution_t *resolution);
int64_t vfs_open(const char *path, uint32_t flags, uint32_t owner_id);
xaios_status_t vfs_close(uint32_t fd, uint32_t owner_id);
xaios_status_t vfs_release_owner(uint32_t owner_id);
int64_t vfs_pread(uint32_t fd, uint32_t owner_id, void *buffer,
                  uint64_t length, uint64_t offset);
int64_t vfs_pwrite(uint32_t fd, uint32_t owner_id, const void *buffer,
                   uint64_t length, uint64_t offset);
int64_t vfs_read(uint32_t fd, uint32_t owner_id, void *buffer,
                 uint64_t length);
int64_t vfs_write(uint32_t fd, uint32_t owner_id, const void *buffer,
                  uint64_t length);
xaios_status_t vfs_seek(uint32_t fd, uint32_t owner_id, uint64_t offset);
xaios_status_t vfs_fsync(uint32_t fd, uint32_t owner_id);
xaios_status_t vfs_truncate(uint32_t fd, uint32_t owner_id, uint64_t size);
xaios_status_t vfs_fallocate(uint32_t fd, uint32_t owner_id, uint64_t offset,
                             uint64_t length);
xaios_status_t vfs_stat(const char *path, xaios_vfs_stat_t *stat);
xaios_status_t vfs_statfs(const char *path, xaios_vfs_statfs_t *statfs);
xaios_status_t vfs_mkdir(const char *path);
xaios_status_t vfs_rmdir(const char *path);
xaios_status_t vfs_unlink(const char *path);
xaios_status_t vfs_delete(const char *path);
xaios_status_t vfs_rename(const char *old_path, const char *new_path);
xaios_status_t vfs_list(const char *path, char *buffer, uint64_t capacity,
                        uint64_t *out_size);

#endif
