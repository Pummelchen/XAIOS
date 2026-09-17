#include <xaios/block_device.h>
#include <xaios/klog.h>
#include <xaios/model_cache.h>

/* How much RAM /models may hold. Two hundred and fifty-six mebibytes by
   default; a machine serving a large working set is expected to raise it, and
   the cache clamps whatever it is told to a quarter of free memory so that a
   generous figure on a small guest is an intention rather than a failure. */
#ifndef XAIOS_MODEL_CACHE_MB
#define XAIOS_MODEL_CACHE_MB 256U
#endif
#include <xaios/xaiboot_fs.h>
#include <xaios/spinlock.h>
#include <xaios/status.h>
#include <xaios/vfs.h>
#include <xaios/vfs_xaifs.h>
#include <xaios/virtio_blk.h>
#include <xaios/virtio_rng.h>

#include <xaios_engine/xai_fs.h>

#include <string.h>

#include "vfs_xaifs_internal.h"

static model_vfs_context_t g_model_vfs;

/* The io, catalog, scrub and trim halves reach the model context through this
   accessor; the variable itself stays private to this file. */
model_vfs_context_t *vfs_xaifs_model(void) { return &g_model_vfs; }

typedef struct model_trim_record {
  uint32_t magic;
  uint32_t version;
  uint32_t size;
  uint32_t reserved;
  xaios_model_trim_status_t status;
} model_trim_record_t;

static int maintenance_active(uint32_t state) {
  return state == XAIOS_MODEL_MAINTENANCE_RUNNING ||
         state == XAIOS_MODEL_MAINTENANCE_PAUSED;
}

int catalog_maintenance_active(void) {
  return maintenance_active(vfs_xaifs_scrub_state()) ||
         maintenance_active(vfs_xaifs_trim_state());
}

int xaios_random(void *buffer, uint64_t size) {
  return virtio_rng_read(buffer, size) == XAIOS_OK ? 0 : -1;
}

static xaios_status_t package_has_pending_hashes(
    model_vfs_context_t *model,
    const xaios_xai_fs_package_t *package, uint32_t *pending) {
  if (model == 0 || package == 0 || pending == 0) return XAIOS_ERR_INVALID;
  *pending = 0U;
  for (uint64_t relative = 0U; relative < package->chunk_count; ++relative) {
    xaios_xai_fs_chunk_t chunk;
    xaios_engine_status_t status = xaios_xai_fs_read_chunk(
        &model->volume, package->chunk_start + relative, &chunk);
    if (status != XAIOS_ENGINE_OK) return map_engine_status(status);
    if ((chunk.flags & XAIOS_XAI_FS_CHUNK_HASH_PENDING) != 0U) {
      *pending = 1U;
      return XAIOS_OK;
    }
  }
  return XAIOS_OK;
}

static xaios_status_t model_open(void *context, const char *path,
                                 uint32_t flags, uint64_t *handle) {
  model_vfs_context_t *model = (model_vfs_context_t *)context;
  uint32_t writable = (flags & XAIOS_VFS_OPEN_WRITE) != 0U;
  if (writable && catalog_maintenance_active()) {
    return XAIOS_ERR_BUSY;
  }
  if (!writable && flags != XAIOS_VFS_OPEN_READ) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  xaios_xai_fs_package_t package;
  memset(&package, 0, sizeof(package));
  uint64_t index = 0U;
  xaios_spin_lock(&model->lock);
  xaios_status_t status = vfs_xaifs_find_package(model, path, &index, &package);
  if (status == XAIOS_OK) {
    uint32_t pending = 0U;
    status = package_has_pending_hashes(model, &package, &pending);
    if (status == XAIOS_OK && pending == 0U) {
      status = map_engine_status(xaios_xai_fs_verify_package_manifest(
          &model->volume, &package));
    }
  }
  if (status == XAIOS_OK && writable &&
      package.state != XAIOS_XAI_FS_PACKAGE_STAGING) {
    status = XAIOS_ERR_UNSUPPORTED;
  }
  if (status == XAIOS_OK && writable &&
      (flags & XAIOS_VFS_OPEN_TRUNCATE) != 0U) {
    for (uint64_t relative = 0U; relative < package.chunk_count; ++relative) {
      xaios_xai_fs_chunk_t chunk;
      xaios_engine_status_t engine_status = xaios_xai_fs_read_chunk(
          &model->volume, package.chunk_start + relative, &chunk);
      if (engine_status != XAIOS_ENGINE_OK) {
        status = map_engine_status(engine_status);
        break;
      }
      if ((chunk.flags & XAIOS_XAI_FS_CHUNK_COMPLETE) != 0U &&
          (chunk.flags & XAIOS_XAI_FS_CHUNK_ZERO) == 0U) {
        status = XAIOS_ERR_BUSY;
        break;
      }
    }
  }
  uint32_t available = MODEL_VFS_MAX_HANDLES;
  if (status == XAIOS_OK) {
    for (uint32_t candidate = 0U; candidate < MODEL_VFS_MAX_HANDLES;
         ++candidate) {
      if (model->handles[candidate].active == 0U) {
        available = candidate;
        break;
      }
    }
    if (available == MODEL_VFS_MAX_HANDLES) status = XAIOS_ERR_NO_MEMORY;
  }
  if (status == XAIOS_OK) {
    model_vfs_handle_t *opened = &model->handles[available];
    memset(opened, 0, sizeof(*opened));
    opened->active = 1U;
    opened->writable = writable;
    opened->package_index = index;
    opened->written_start = UINT64_MAX;
    *handle = (uint64_t)available + 1U;
  }
  if (status != XAIOS_OK) {
    klog("xaifs: open rejected path=%s flags=0x%x status=%d state=%u\n",
         path, flags, (int)status, package.state);
  }
  xaios_spin_unlock(&model->lock);
  return status;
}

static uint64_t package_content_hash(const uint8_t package_id[32]) {
  uint64_t value = 0U;
  for (uint32_t index = 0U; index < 8U; ++index) {
    value |= (uint64_t)package_id[index] << (index * 8U);
  }
  return value;
}

static xaios_status_t model_stat(void *context, const char *path,
                                 xaios_vfs_stat_t *stat) {
  model_vfs_context_t *model = (model_vfs_context_t *)context;
  memset(stat, 0, sizeof(*stat));
  if (strcmp(path, "/") == 0 || strcmp(path, "/.staging") == 0) {
    stat->type = XAIOS_VFS_TYPE_DIRECTORY;
    stat->generation = model->volume.generation;
    return XAIOS_OK;
  }
  xaios_xai_fs_package_t package;
  uint64_t index = 0U;
  uint64_t visible_size = 0U;
  xaios_spin_lock(&model->lock);
  xaios_status_t status = vfs_xaifs_find_package(model, path, &index, &package);
  if (status == XAIOS_OK) {
    visible_size = package.logical_size;
    if (package.state == XAIOS_XAI_FS_PACKAGE_STAGING) {
      visible_size = 0U;
      for (uint64_t relative = 0U; relative < package.chunk_count;
           ++relative) {
        xaios_xai_fs_chunk_t chunk;
        xaios_engine_status_t engine_status = xaios_xai_fs_read_chunk(
            &model->volume, package.chunk_start + relative, &chunk);
        if (engine_status != XAIOS_ENGINE_OK) {
          status = map_engine_status(engine_status);
          break;
        }
        if (chunk.logical_offset != visible_size ||
            (chunk.flags & XAIOS_XAI_FS_CHUNK_COMPLETE) == 0U) {
          break;
        }
        visible_size += chunk.length;
      }
    }
  }
  xaios_spin_unlock(&model->lock);
  if (status != XAIOS_OK) return status;
  stat->type = XAIOS_VFS_TYPE_FILE;
  stat->size = visible_size;
  uint64_t blocks = (visible_size + 4095U) / 4096U;
  stat->block_count = blocks > UINT32_MAX ? UINT32_MAX : (uint32_t)blocks;
  stat->generation = model->volume.generation;
  stat->content_hash = package_content_hash(package.package_id);
  return XAIOS_OK;
}

static xaios_status_t model_statfs(void *context,
                                   xaios_vfs_statfs_t *statfs) {
  model_vfs_context_t *model = (model_vfs_context_t *)context;
  memset(statfs, 0, sizeof(*statfs));
  statfs->total_bytes = model->volume.volume_size;
  statfs->allocated_bytes = model->volume.data_tail;
  statfs->free_bytes = model->volume.volume_size - model->volume.data_tail;
  statfs->file_count = model->volume.package_count;
  statfs->directory_count = 2U;
  statfs->generation = model->volume.generation;
  statfs->block_size = 4096U;
  statfs->read_only = model->read_only;
  statfs->format_version = 1U;
  return XAIOS_OK;
}

static char hex_digit(uint8_t value) {
  return value < 10U ? (char)('0' + value) : (char)('a' + value - 10U);
}

static xaios_status_t append_listing(char *buffer, uint64_t capacity,
                                     uint64_t *used, const char *text,
                                     uint64_t length) {
  if (length > capacity - *used || *used + length >= capacity) {
    return XAIOS_ERR_NO_MEMORY;
  }
  memcpy(buffer + *used, text, length);
  *used += length;
  return XAIOS_OK;
}

static xaios_status_t model_list(void *context, const char *path, char *buffer,
                                 uint64_t capacity, uint64_t *out_size) {
  model_vfs_context_t *model = (model_vfs_context_t *)context;
  uint32_t state = 0U;
  uint64_t used = 0U;
  if (strcmp(path, "/") == 0) {
    state = XAIOS_XAI_FS_PACKAGE_ACTIVE;
    xaios_status_t status =
        append_listing(buffer, capacity, &used, ".staging\n", 9U);
    if (status != XAIOS_OK) return status;
  } else if (strcmp(path, "/.staging") == 0) {
    state = XAIOS_XAI_FS_PACKAGE_STAGING;
  } else {
    return XAIOS_ERR_NOT_FOUND;
  }
  xaios_spin_lock(&model->lock);
  for (uint64_t index = 0U; index < model->volume.package_count; ++index) {
    xaios_xai_fs_package_t package;
    xaios_engine_status_t engine_status =
        xaios_xai_fs_read_package(&model->volume, index, &package);
    if (engine_status != XAIOS_ENGINE_OK) {
      xaios_spin_unlock(&model->lock);
      return map_engine_status(engine_status);
    }
    if (package.state != state) continue;
    if (used + MODEL_PACKAGE_NAME_LENGTH + 1U >= capacity) {
      xaios_spin_unlock(&model->lock);
      return XAIOS_ERR_NO_MEMORY;
    }
    for (uint32_t byte = 0U; byte < 32U; ++byte) {
      buffer[used++] = hex_digit(package.package_id[byte] >> 4U);
      buffer[used++] = hex_digit(package.package_id[byte] & 15U);
    }
    buffer[used++] = '\n';
  }
  xaios_spin_unlock(&model->lock);
  buffer[used] = '\0';
  *out_size = used;
  return XAIOS_OK;
}

static const xaios_vfs_backend_ops_t k_model_ops = {
    model_open, vfs_xaifs_close, vfs_xaifs_pread, vfs_xaifs_pwrite,
    vfs_xaifs_fsync, 0, 0, model_stat, model_statfs, 0, 0, 0, 0, model_list,
};

static void copy_mount_path(char destination[XAIOS_VFS_PATH_MAX],
                            const char *source) {
  uint64_t index = 0U;
  while (index + 1U < XAIOS_VFS_PATH_MAX && source[index] != '\0') {
    destination[index] = source[index];
    ++index;
  }
  destination[index] = '\0';
}

static xaios_status_t mount_model_device(xaios_block_device_t *device,
                                         virtio_block_handle_t *handle,
                                         uint32_t owns_block_open,
                                         const char *mount_path,
                                         uint32_t read_only) {
  if (g_model_vfs.mounted != 0U || device == 0 || mount_path == 0 ||
      read_only > 1U) {
    return XAIOS_ERR_INVALID;
  }
  memset(&g_model_vfs, 0, sizeof(g_model_vfs));
  xaios_spin_init(&g_model_vfs.lock);
  g_model_vfs.handle = handle;
  g_model_vfs.device = device;
  g_model_vfs.owns_block_open = owns_block_open;
  g_model_vfs.read_only = read_only;
  if (g_model_vfs.device == 0 ||
      block_device_info(g_model_vfs.device, &g_model_vfs.device_info) !=
          XAIOS_OK ||
      g_model_vfs.device_info.logical_sector_size >
          MODEL_READER_MAX_SECTOR_SIZE) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  xaios_xai_fs_reader_t reader = {
      &g_model_vfs, vfs_xaifs_read_at, g_model_vfs.device_info.capacity_bytes};
  xaios_engine_status_t engine_status = xaios_xai_fs_open(
      &reader, vfs_xaifs_verify_signature, 0, g_model_vfs.scratch,
      sizeof(g_model_vfs.scratch), &g_model_vfs.volume);
  if (engine_status != XAIOS_ENGINE_OK) {
    return map_engine_status(engine_status);
  }
  xaios_status_t status =
      vfs_mount(mount_path, &k_model_ops, &g_model_vfs,
                read_only != 0U ? XAIOS_VFS_MOUNT_READ_ONLY : 0U);
  if (status != XAIOS_OK) {
    return status;
  }
  g_model_vfs.mounted = 1U;
  copy_mount_path(g_model_vfs.mount_path, mount_path);
  /* The read cache, sized for a machine that streams model weights. The
     figure is a reservation rather than a consumption: memory is taken as
     chunks earn it and handed back as they lose it, so a volume nobody reads
     costs nothing. */
  model_cache_init((uint64_t)XAIOS_MODEL_CACHE_MB * UINT64_C(1048576));
  vfs_xaifs_scrub_load();
  vfs_xaifs_trim_load();
  klog("xaifs: mounted %s device=%s generation=%lu packages=%lu bytes=%lu policy=%s\n",
       mount_path, g_model_vfs.device_info.identifier,
       g_model_vfs.volume.generation,
       g_model_vfs.volume.package_count, g_model_vfs.volume.volume_size,
       read_only != 0U ? "read-only" : "rw-staging-active-immutable");
  return XAIOS_OK;
}

xaios_status_t vfs_mount_xai_fs(uint32_t virtio_slot) {
  if (g_model_vfs.mounted != 0U) return XAIOS_ERR_BUSY;
  virtio_block_handle_t *handle = 0;
  xaios_status_t status = virtio_block_open_slot(virtio_slot, &handle);
  if (status != XAIOS_OK) return status;
  xaios_block_device_t *device = virtio_block_device_h(handle);
  status = mount_model_device(device, handle, 0U, "/models", 0U);
  if (status != XAIOS_OK) virtio_block_close(handle);
  return status;
}

xaios_status_t vfs_mount_model_device(const char *device_identifier,
                                      const char *mount_path,
                                      uint32_t read_only) {
  if (g_model_vfs.mounted != 0U) return XAIOS_ERR_BUSY;
  xaios_block_device_t *device = 0;
  xaios_status_t status = block_device_open(device_identifier, &device);
  if (status != XAIOS_OK) return status;
  status = mount_model_device(device, 0, 1U, mount_path, read_only);
  if (status != XAIOS_OK) (void)block_device_close(device);
  return status;
}

xaios_status_t vfs_unmount_xai_fs(const char *mount_path) {
  if (mount_path == 0 || g_model_vfs.mounted == 0U ||
      strcmp(mount_path, g_model_vfs.mount_path) != 0) {
    return XAIOS_ERR_NOT_FOUND;
  }
  if (catalog_maintenance_active()) {
    return XAIOS_ERR_BUSY;
  }
  xaios_status_t status = vfs_unmount(mount_path);
  if (status != XAIOS_OK) return status;
  xaios_block_device_t *device = g_model_vfs.device;
  virtio_block_handle_t *handle = g_model_vfs.handle;
  uint32_t owns_block_open = g_model_vfs.owns_block_open;
  memset(&g_model_vfs, 0, sizeof(g_model_vfs));
  if (owns_block_open != 0U) {
    return block_device_close(device);
  }
  if (handle != 0) virtio_block_close(handle);
  return XAIOS_OK;
}

xaios_status_t vfs_xaifs_target_mounted(const char *device_identifier,
                                        uint32_t *mounted) {
  if (device_identifier == 0 || mounted == 0) return XAIOS_ERR_INVALID;
  *mounted =
      g_model_vfs.mounted != 0U &&
              strcmp(device_identifier, g_model_vfs.device_info.identifier) == 0
          ? 1U
          : 0U;
  return XAIOS_OK;
}

xaios_status_t vfs_xaifs_mount_status(xaios_model_mount_status_t *status) {
  if (status == 0 || g_model_vfs.mounted == 0U) {
    return status == 0 ? XAIOS_ERR_INVALID : XAIOS_ERR_NOT_FOUND;
  }
  memset(status, 0, sizeof(*status));
  xaios_spin_lock(&g_model_vfs.lock);
  status->device = g_model_vfs.device_info;
  status->generation = g_model_vfs.volume.generation;
  status->package_count = g_model_vfs.volume.package_count;
  for (uint64_t index = 0U; index < g_model_vfs.volume.package_count; ++index) {
    xaios_xai_fs_package_t package;
    xaios_engine_status_t engine_status =
        xaios_xai_fs_read_package(&g_model_vfs.volume, index, &package);
    if (engine_status != XAIOS_ENGINE_OK) {
      xaios_spin_unlock(&g_model_vfs.lock);
      memset(status, 0, sizeof(*status));
      return map_engine_status(engine_status);
    }
    if (package.state == XAIOS_XAI_FS_PACKAGE_ACTIVE) {
      ++status->active_packages;
    } else if (package.state == XAIOS_XAI_FS_PACKAGE_STAGING) {
      ++status->staging_packages;
    } else if (package.state == XAIOS_XAI_FS_PACKAGE_QUARANTINED) {
      ++status->quarantined_packages;
    }
  }
  status->mounted = 1U;
  xaios_spin_unlock(&g_model_vfs.lock);
  return XAIOS_OK;
}

