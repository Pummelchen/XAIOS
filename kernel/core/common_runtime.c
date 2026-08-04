#include <string.h>
#include <xaios/block_device.h>
#include <xaios/common_runtime.h>
#include <xaios/crc32.h>
#include <xaios/vfs.h>
#include <xaios_engine/architecture.h>
#include <xaios_engine/backend.h>

#define PROBE_STORAGE_SIZE 4096U

typedef struct common_probe_storage {
  uint8_t bytes[PROBE_STORAGE_SIZE];
} common_probe_storage_t;

static common_probe_storage_t g_probe_storage;

static xaios_status_t probe_read(void *context, uint64_t offset, void *buffer,
                                 uint64_t length) {
  common_probe_storage_t *storage = (common_probe_storage_t *)context;
  if (storage == 0 || buffer == 0 || offset > PROBE_STORAGE_SIZE ||
      length > PROBE_STORAGE_SIZE - offset) {
    return XAIOS_ERR_INVALID;
  }
  memcpy(buffer, storage->bytes + offset, (size_t)length);
  return XAIOS_OK;
}

static xaios_status_t probe_write(void *context, uint64_t offset,
                                  const void *buffer, uint64_t length) {
  common_probe_storage_t *storage = (common_probe_storage_t *)context;
  if (storage == 0 || buffer == 0 || offset > PROBE_STORAGE_SIZE ||
      length > PROBE_STORAGE_SIZE - offset) {
    return XAIOS_ERR_INVALID;
  }
  memcpy(storage->bytes + offset, buffer, (size_t)length);
  return XAIOS_OK;
}

static xaios_status_t probe_flush(void *context) {
  return context == 0 ? XAIOS_ERR_INVALID : XAIOS_OK;
}

static xaios_status_t probe_open(void *context, const char *path,
                                 uint32_t flags, uint64_t *handle) {
  (void)context;
  if (path == 0 || handle == 0 || strcmp(path, "/probe") != 0 ||
      flags != XAIOS_VFS_OPEN_READ) {
    return XAIOS_ERR_NOT_FOUND;
  }
  *handle = 1U;
  return XAIOS_OK;
}

static xaios_status_t probe_close(void *context, uint64_t handle) {
  (void)context;
  return handle == 1U ? XAIOS_OK : XAIOS_ERR_INVALID;
}

static int64_t probe_pread(void *context, uint64_t handle, void *buffer,
                           uint64_t length, uint64_t offset) {
  if (handle != 1U || probe_read(context, offset, buffer, length) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  return (int64_t)length;
}

static xaios_status_t probe_stat(void *context, const char *path,
                                 xaios_vfs_stat_t *stat) {
  (void)context;
  if (path == 0 || stat == 0 || strcmp(path, "/probe") != 0) {
    return XAIOS_ERR_NOT_FOUND;
  }
  memset(stat, 0, sizeof(*stat));
  stat->type = XAIOS_VFS_TYPE_FILE;
  stat->size = 512U;
  return XAIOS_OK;
}

static uint32_t probe_integrity(void) {
  static const char input[] = "123456789";
  return xaios_crc32(input, sizeof(input) - 1U) == UINT32_C(0xcbf43926);
}

static uint32_t probe_block(void) {
  static const xaios_block_backend_ops_t ops = {
      probe_read, probe_write, probe_flush, 0, 0};
  xaios_block_device_info_t info;
  xaios_block_device_t device;
  uint8_t input[512];
  uint8_t output[512];
  memset(&info, 0, sizeof(info));
  memset(&device, 0, sizeof(device));
  memset(input, 0x5a, sizeof(input));
  memset(output, 0, sizeof(output));
  memcpy(info.identifier, "/dev/common-probe", 18U);
  memcpy(info.backend, "memory", 7U);
  info.capacity_bytes = PROBE_STORAGE_SIZE;
  info.capacity_logical_sectors = PROBE_STORAGE_SIZE / 512U;
  info.logical_sector_size = 512U;
  info.physical_block_size = 512U;
  info.max_transfer_bytes = 1024U;
  info.flush_supported = 1U;
  if (block_device_test_reset() != XAIOS_OK ||
      block_device_register(&device, &info, &ops, &g_probe_storage) !=
          XAIOS_OK ||
      block_write(&device, 0U, input, sizeof(input)) != XAIOS_OK ||
      block_read(&device, 0U, output, sizeof(output)) != XAIOS_OK ||
      memcmp(input, output, sizeof(input)) != 0 ||
      block_flush(&device) != XAIOS_OK ||
      block_device_unregister(&device) != XAIOS_OK) {
    return 0U;
  }
  return 1U;
}

static uint32_t probe_vfs(void) {
  static const xaios_vfs_backend_ops_t ops = {
      probe_open, probe_close, probe_pread, 0, 0, 0, 0,
      probe_stat, 0, 0, 0, 0, 0, 0};
  uint8_t output[16];
  memset(output, 0, sizeof(output));
  if (vfs_init() != XAIOS_OK ||
      vfs_mount("/common", &ops, &g_probe_storage,
                XAIOS_VFS_MOUNT_READ_ONLY) != XAIOS_OK) {
    return 0U;
  }
  int64_t fd = vfs_open("/common/probe", XAIOS_VFS_OPEN_READ, 7U);
  if (fd <= 0 || vfs_pread((uint32_t)fd, 7U, output, sizeof(output), 0U) !=
                     (int64_t)sizeof(output) ||
      output[0] != 0x5aU || vfs_close((uint32_t)fd, 7U) != XAIOS_OK ||
      vfs_unmount("/common") != XAIOS_OK) {
    return 0U;
  }
  return 1U;
}

static uint32_t probe_engine(void) {
  const xaios_backend_t *scalar = xaios_backend_scalar();
  return scalar != 0 && scalar->validate() == XAIOS_ENGINE_OK &&
         xaios_architecture_count() >= 2U &&
         xaios_architecture_find("qwen3_5") != 0 &&
         xaios_architecture_find("kimi_k3") != 0;
}

uint32_t xaios_common_runtime_probe(void) {
  uint32_t result = 0U;
  if (probe_integrity()) result |= XAIOS_COMMON_RUNTIME_INTEGRITY;
  if (probe_block()) result |= XAIOS_COMMON_RUNTIME_BLOCK;
  if (probe_vfs()) result |= XAIOS_COMMON_RUNTIME_VFS;
  if (probe_engine()) result |= XAIOS_COMMON_RUNTIME_ENGINE;
  return result;
}
