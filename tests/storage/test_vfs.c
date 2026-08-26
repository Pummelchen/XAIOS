#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <xaios/vfs.h>

#define MOCK_HANDLES 16U
#define MOCK_RECORDS 16U

typedef struct mock_record {
  uint64_t offset;
  uint64_t length;
  uint8_t data[64];
  uint32_t valid;
} mock_record_t;

typedef struct mock_fs {
  uint64_t next_handle;
  uint64_t handles[MOCK_HANDLES];
  char handle_paths[MOCK_HANDLES][128];
  mock_record_t records[MOCK_RECORDS];
  char last_path[128];
  uint64_t max_io;
  uint32_t fail_io;
  uint64_t fsyncs;
} mock_fs_t;

static void remember_path(mock_fs_t *fs, const char *path) {
  size_t length = strlen(path);
  assert(length < sizeof(fs->last_path));
  memcpy(fs->last_path, path, length + 1U);
}

static xaios_status_t mock_open(void *context, const char *path, uint32_t flags,
                                uint64_t *handle) {
  mock_fs_t *fs = (mock_fs_t *)context;
  (void)flags;
  remember_path(fs, path);
  for (uint32_t index = 0U; index < MOCK_HANDLES; ++index) {
    if (fs->handles[index] == 0U) {
      fs->handles[index] = ++fs->next_handle;
      memcpy(fs->handle_paths[index], path, strlen(path) + 1U);
      *handle = fs->handles[index];
      return XAIOS_OK;
    }
  }
  return XAIOS_ERR_NO_MEMORY;
}

static xaios_status_t mock_close(void *context, uint64_t handle) {
  mock_fs_t *fs = (mock_fs_t *)context;
  for (uint32_t index = 0U; index < MOCK_HANDLES; ++index) {
    if (fs->handles[index] == handle) {
      fs->handles[index] = 0U;
      return XAIOS_OK;
    }
  }
  return XAIOS_ERR_INVALID;
}

static uint64_t bounded_io(mock_fs_t *fs, uint64_t length) {
  return fs->max_io != 0U && length > fs->max_io ? fs->max_io : length;
}

static int64_t mock_pwrite(void *context, uint64_t handle, const void *buffer,
                           uint64_t length, uint64_t offset) {
  mock_fs_t *fs = (mock_fs_t *)context;
  (void)handle;
  if (fs->fail_io != 0U) return XAIOS_ERR_IO;
  uint64_t count = bounded_io(fs, length);
  if (count > sizeof(fs->records[0].data)) return XAIOS_ERR_INVALID;
  for (uint32_t index = 0U; index < MOCK_RECORDS; ++index) {
    mock_record_t *record = &fs->records[index];
    if (record->valid != 0U && record->offset != offset) continue;
    record->valid = 1U;
    record->offset = offset;
    record->length = count;
    memcpy(record->data, buffer, (size_t)count);
    return (int64_t)count;
  }
  return XAIOS_ERR_NO_MEMORY;
}

static int64_t mock_pread(void *context, uint64_t handle, void *buffer,
                          uint64_t length, uint64_t offset) {
  mock_fs_t *fs = (mock_fs_t *)context;
  (void)handle;
  if (fs->fail_io != 0U) return XAIOS_ERR_IO;
  uint64_t count = bounded_io(fs, length);
  for (uint32_t index = 0U; index < MOCK_RECORDS; ++index) {
    mock_record_t *record = &fs->records[index];
    if (record->valid == 0U || offset < record->offset ||
        offset >= record->offset + record->length) {
      continue;
    }
    uint64_t within = offset - record->offset;
    if (count > record->length - within) count = record->length - within;
    memcpy(buffer, record->data + within, (size_t)count);
    return (int64_t)count;
  }
  return 0;
}

static xaios_status_t mock_fsync(void *context, uint64_t handle) {
  (void)handle;
  ++((mock_fs_t *)context)->fsyncs;
  return XAIOS_OK;
}

static xaios_status_t mock_stat(void *context, const char *path,
                                xaios_vfs_stat_t *stat) {
  mock_fs_t *fs = (mock_fs_t *)context;
  remember_path(fs, path);
  memset(stat, 0, sizeof(*stat));
  stat->type = strcmp(path, "/") == 0 ? XAIOS_VFS_TYPE_DIRECTORY
                                      : XAIOS_VFS_TYPE_FILE;
  for (uint32_t index = 0U; index < MOCK_RECORDS; ++index) {
    if (fs->records[index].valid != 0U) {
      uint64_t end = fs->records[index].offset + fs->records[index].length;
      if (end > stat->size) stat->size = end;
    }
  }
  return XAIOS_OK;
}

static xaios_status_t mock_statfs(void *context,
                                  xaios_vfs_statfs_t *statfs) {
  (void)context;
  memset(statfs, 0, sizeof(*statfs));
  statfs->total_bytes = UINT64_C(1) << 40U;
  statfs->free_bytes = statfs->total_bytes;
  statfs->block_size = 4096U;
  statfs->format_version = 1U;
  return XAIOS_OK;
}

static xaios_status_t mock_path_ok(void *context, const char *path) {
  remember_path((mock_fs_t *)context, path);
  return XAIOS_OK;
}

static xaios_status_t mock_rename(void *context, const char *old_path,
                                  const char *new_path) {
  mock_fs_t *fs = (mock_fs_t *)context;
  remember_path(fs, old_path);
  return new_path[0] == '/' ? XAIOS_OK : XAIOS_ERR_INVALID;
}

static xaios_status_t mock_list(void *context, const char *path, char *buffer,
                                uint64_t capacity, uint64_t *out_size) {
  remember_path((mock_fs_t *)context, path);
  static const char listing[] = "entry\n";
  if (capacity < sizeof(listing)) return XAIOS_ERR_NO_MEMORY;
  memcpy(buffer, listing, sizeof(listing));
  *out_size = sizeof(listing) - 1U;
  return XAIOS_OK;
}

static const xaios_vfs_backend_ops_t k_mock_ops = {
    mock_open,    mock_close,   mock_pread,   mock_pwrite, mock_fsync,
    0,            0,            mock_stat,    mock_statfs, mock_path_ok,
    mock_path_ok, mock_path_ok, mock_rename,  mock_list,
};

/* The kernel ticket lock has a fast path for the cases where it cannot or need
   not spin: one CPU online, or translation still off, where exclusives are
   unsupported. Both questions are answered by the kernel proper. The hosted
   test links only the filesystem translation unit, so it answers them here --
   one CPU, translation on -- which is the configuration these tests run in. */
uint32_t smp_online_count(void) { return 1U; }
uint32_t xaios_translation_enabled(void) { return 1U; }
uint32_t smp_locking_active(void) { return 0U; }

int main(void) {
  mock_fs_t root;
  mock_fs_t models;
  mock_fs_t readonly;
  memset(&root, 0, sizeof(root));
  memset(&models, 0, sizeof(models));
  memset(&readonly, 0, sizeof(readonly));
  assert(vfs_init() == XAIOS_OK);
  assert(vfs_mount("/", &k_mock_ops, &root, 0U) == XAIOS_OK);
  assert(vfs_mount("/models", &k_mock_ops, &models, 0U) == XAIOS_OK);
  assert(vfs_mount("/readonly", &k_mock_ops, &readonly,
                   XAIOS_VFS_MOUNT_READ_ONLY) == XAIOS_OK);

  int64_t root_fd = vfs_open("/config/value", XAIOS_VFS_OPEN_READ, 10U);
  assert(root_fd > 0 && strcmp(root.last_path, "/config/value") == 0);
  assert(vfs_close((uint32_t)root_fd, 11U) == XAIOS_ERR_INVALID);
  assert(vfs_close((uint32_t)root_fd, 10U) == XAIOS_OK);

  int64_t model_fd = vfs_open("/models/package", XAIOS_VFS_OPEN_READ |
                                                      XAIOS_VFS_OPEN_WRITE |
                                                      XAIOS_VFS_OPEN_CREATE,
                              20U);
  assert(model_fd > 0 && strcmp(models.last_path, "/package") == 0);
  assert(vfs_unmount("/models") == XAIOS_ERR_BUSY);
  static const char high_marker[] = "high-offset";
  uint64_t high_offset = (UINT64_C(4) << 30U) + 4096U;
  assert(vfs_pwrite((uint32_t)model_fd, 20U, high_marker,
                    sizeof(high_marker), high_offset) == sizeof(high_marker));
  char result[32];
  memset(result, 0, sizeof(result));
  assert(vfs_pread((uint32_t)model_fd, 20U, result, sizeof(high_marker),
                   high_offset) == sizeof(high_marker));
  assert(memcmp(result, high_marker, sizeof(high_marker)) == 0);
  assert(vfs_fsync((uint32_t)model_fd, 20U) == XAIOS_OK);
  assert(models.fsyncs == 1U);

  static const char sequence[] = "abcdef";
  assert(vfs_pwrite((uint32_t)model_fd, 20U, sequence, sizeof(sequence), 0U) ==
         sizeof(sequence));
  int64_t second_fd = vfs_open("/models/package", XAIOS_VFS_OPEN_READ, 20U);
  assert(second_fd > 0);
  assert(vfs_seek((uint32_t)model_fd, 20U, 0U) == XAIOS_OK);
  memset(result, 0, sizeof(result));
  assert(vfs_read((uint32_t)model_fd, 20U, result, 2U) == 2);
  assert(memcmp(result, "ab", 2U) == 0);
  memset(result, 0, sizeof(result));
  assert(vfs_read((uint32_t)second_fd, 20U, result, 2U) == 2);
  assert(memcmp(result, "ab", 2U) == 0);
  assert(vfs_read((uint32_t)model_fd, 20U, result, 2U) == 2);
  assert(memcmp(result, "cd", 2U) == 0);

  int64_t orphan_one = vfs_open("/models/orphan-one",
                                XAIOS_VFS_OPEN_READ, 21U);
  int64_t orphan_two = vfs_open("/models/orphan-two",
                                XAIOS_VFS_OPEN_READ, 21U);
  assert(orphan_one > 0 && orphan_two > 0);
  assert(vfs_release_owner(0U) == XAIOS_ERR_INVALID);
  assert(vfs_release_owner(21U) == XAIOS_OK);
  assert(vfs_close((uint32_t)orphan_one, 21U) == XAIOS_ERR_INVALID);
  assert(vfs_close((uint32_t)orphan_two, 21U) == XAIOS_ERR_INVALID);

  models.max_io = 3U;
  assert(vfs_seek((uint32_t)model_fd, 20U, 8192U) == XAIOS_OK);
  assert(vfs_write((uint32_t)model_fd, 20U, sequence, 6U) == 3);
  models.fail_io = 1U;
  assert(vfs_pread((uint32_t)model_fd, 20U, result, 1U, 0U) == XAIOS_ERR_IO);
  models.fail_io = 0U;

  assert(vfs_open("/readonly/file", XAIOS_VFS_OPEN_WRITE, 30U) ==
         XAIOS_ERR_UNSUPPORTED);
  assert(vfs_rename("/config/value", "/models/value") ==
         XAIOS_ERR_UNSUPPORTED);
  xaios_vfs_resolution_t resolution;
  assert(vfs_resolve("/models/../config", &resolution) ==
         XAIOS_ERR_INVALID);
  assert(vfs_resolve("/models2/file", &resolution) == XAIOS_OK);
  assert(strcmp(resolution.relative_path, "/models2/file") == 0);
  assert(vfs_resolve("/models//./package", &resolution) == XAIOS_OK);
  assert(strcmp(resolution.relative_path, "/package") == 0);

  xaios_vfs_statfs_t statfs;
  assert(vfs_statfs("/models", &statfs) == XAIOS_OK);
  assert(statfs.total_bytes == (UINT64_C(1) << 40U));
  char listing[16];
  uint64_t listing_size = 0U;
  assert(vfs_list("/models", listing, sizeof(listing), &listing_size) ==
         XAIOS_OK);
  assert(listing_size == 6U);

  assert(vfs_close((uint32_t)second_fd, 20U) == XAIOS_OK);
  assert(vfs_close((uint32_t)model_fd, 20U) == XAIOS_OK);
  assert(vfs_unmount("/models") == XAIOS_OK);
  assert(vfs_resolve("/models/package", &resolution) == XAIOS_OK);
  assert(strcmp(resolution.relative_path, "/models/package") == 0);
  assert(vfs_unmount("/readonly") == XAIOS_OK);
  assert(vfs_unmount("/") == XAIOS_OK);
  puts("vfs: mount routing, 64-bit positional I/O, and handle isolation passed");
  return 0;
}
