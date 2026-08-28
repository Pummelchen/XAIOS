#include <xaios/block_device.h>
#include <xaios/klog.h>
#include <xaios/xaiboot_fs.h>
#include <xaios/spinlock.h>
#include <xaios/status.h>
#include <xaios/vfs.h>
#include <xaios/vfs_model.h>
#include <xaios/virtio_blk.h>
#include <xaios/virtio_rng.h>

#include <xaios_engine/model_volume.h>

#include <string.h>

#define MODEL_READER_SCRATCH_SIZE UINT64_C(65536)
#define MODEL_READER_MAX_SECTOR_SIZE UINT64_C(4096)
#define MODEL_PACKAGE_NAME_LENGTH 64U
#define MODEL_VFS_MAX_HANDLES 64U
#define MODEL_SCRUB_MAGIC UINT32_C(0x58415343)
#define MODEL_SCRUB_VERSION UINT32_C(1)
#define MODEL_SCRUB_STATE_PATH "/state/modelfs-scrub.bin"
#define MODEL_TRIM_MAGIC UINT32_C(0x58415452)
#define MODEL_TRIM_VERSION UINT32_C(1)
#define MODEL_TRIM_STATE_PATH "/state/modelfs-trim.bin"
#define MODEL_TRIM_STEP_LIMIT UINT64_C(67108864)

typedef struct model_vfs_handle {
  uint32_t active;
  uint32_t writable;
  uint64_t package_index;
  uint64_t written_start;
  uint64_t written_end;
} model_vfs_handle_t;

typedef struct model_vfs_context {
  virtio_block_handle_t *handle;
  xaios_block_device_t *device;
  xaios_block_device_info_t device_info;
  xaios_model_volume_t volume;
  xaios_spinlock_t lock;
  uint8_t bounce[MODEL_READER_MAX_SECTOR_SIZE];
  uint8_t scratch[MODEL_READER_SCRATCH_SIZE];
  model_vfs_handle_t handles[MODEL_VFS_MAX_HANDLES];
  uint32_t mounted;
  uint32_t owns_block_open;
  uint32_t read_only;
  char mount_path[XAIOS_VFS_PATH_MAX];
} model_vfs_context_t;

static model_vfs_context_t g_model_vfs;
static xaios_model_scrub_status_t g_model_scrub;
static uint8_t g_model_scrub_scratch[MODEL_READER_SCRATCH_SIZE];
static xaios_model_trim_status_t g_model_trim;

typedef struct model_scrub_record {
  uint32_t magic;
  uint32_t version;
  uint32_t size;
  uint32_t reserved;
  xaios_model_scrub_status_t status;
} model_scrub_record_t;

typedef struct model_trim_record {
  uint32_t magic;
  uint32_t version;
  uint32_t size;
  uint32_t reserved;
  xaios_model_trim_status_t status;
} model_trim_record_t;

static void scrub_load(void);
static void trim_load(void);
static xaios_status_t staging_path_from_id(const char *package_id,
                                           char path[82]);

static int maintenance_active(uint32_t state) {
  return state == XAIOS_MODEL_MAINTENANCE_RUNNING ||
         state == XAIOS_MODEL_MAINTENANCE_PAUSED;
}

static int catalog_maintenance_active(void) {
  return maintenance_active(g_model_scrub.state) ||
         maintenance_active(g_model_trim.state);
}

int xaios_random(void *buffer, uint64_t size) {
  return virtio_rng_read(buffer, size) == XAIOS_OK ? 0 : -1;
}

extern int xaios_ed25519_verify(const uint8_t signature[64],
                                const uint8_t *message,
                                uint32_t message_len,
                                const uint8_t public_key[32]);

static xaios_engine_status_t verify_signature(
    void *context, const uint8_t public_key[32], const uint8_t signature[64],
    const uint8_t message[32]) {
  (void)context;
  return xaios_ed25519_verify(signature, message, 32U, public_key) == 0
             ? XAIOS_ENGINE_OK
             : XAIOS_ENGINE_ERR_CHECKSUM;
}

static xaios_engine_status_t model_read_at(void *context, uint64_t offset,
                                           void *destination, size_t length) {
  model_vfs_context_t *model = (model_vfs_context_t *)context;
  uint64_t sector_size = model->device_info.logical_sector_size;
  if (destination == 0 || length == 0U || sector_size == 0U ||
      sector_size > sizeof(model->bounce) || offset > UINT64_MAX - length ||
      offset + length > model->device_info.capacity_bytes) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  uint8_t *output = (uint8_t *)destination;
  uint64_t remaining = (uint64_t)length;
  while (remaining != 0U) {
    uint64_t within = offset % sector_size;
    if (within == 0U && remaining >= sector_size) {
      uint64_t count = remaining;
      uint64_t limit = model->device_info.max_transfer_bytes;
      if (limit != 0U && count > limit) count = limit;
      count -= count % sector_size;
      if (block_read(model->device, offset, output, count) != XAIOS_OK) {
        return XAIOS_ENGINE_ERR_IO;
      }
      offset += count;
      output += count;
      remaining -= count;
      continue;
    }
    uint64_t sector_offset = offset - within;
    if (block_read(model->device, sector_offset, model->bounce,
                   sector_size) != XAIOS_OK) {
      return XAIOS_ENGINE_ERR_IO;
    }
    uint64_t count = sector_size - within;
    if (count > remaining) count = remaining;
    memcpy(output, model->bounce + within, count);
    offset += count;
    output += count;
    remaining -= count;
  }
  return XAIOS_ENGINE_OK;
}

static xaios_engine_status_t model_write_at(void *context, uint64_t offset,
                                            const void *source,
                                            size_t length) {
  model_vfs_context_t *model = (model_vfs_context_t *)context;
  uint64_t sector_size = model->device_info.logical_sector_size;
  if (source == 0 || length == 0U || sector_size == 0U ||
      sector_size > sizeof(model->bounce) || offset > UINT64_MAX - length ||
      offset + length > model->device_info.capacity_bytes) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  const uint8_t *input = (const uint8_t *)source;
  uint64_t remaining = (uint64_t)length;
  while (remaining != 0U) {
    uint64_t within = offset % sector_size;
    if (within == 0U && remaining >= sector_size) {
      uint64_t count = remaining;
      uint64_t limit = model->device_info.max_transfer_bytes;
      if (limit != 0U && count > limit) count = limit;
      count -= count % sector_size;
      if (block_write(model->device, offset, input, count) != XAIOS_OK) {
        return XAIOS_ENGINE_ERR_IO;
      }
      offset += count;
      input += count;
      remaining -= count;
      continue;
    }
    uint64_t sector_offset = offset - within;
    if (block_read(model->device, sector_offset, model->bounce, sector_size) !=
        XAIOS_OK) {
      return XAIOS_ENGINE_ERR_IO;
    }
    uint64_t count = sector_size - within;
    if (count > remaining) count = remaining;
    memcpy(model->bounce + within, input, count);
    if (block_write(model->device, sector_offset, model->bounce, sector_size) !=
        XAIOS_OK) {
      return XAIOS_ENGINE_ERR_IO;
    }
    offset += count;
    input += count;
    remaining -= count;
  }
  return XAIOS_ENGINE_OK;
}

static xaios_engine_status_t model_flush(void *context) {
  model_vfs_context_t *model = (model_vfs_context_t *)context;
  return block_flush(model->device) == XAIOS_OK ? XAIOS_ENGINE_OK
                                                 : XAIOS_ENGINE_ERR_IO;
}

static xaios_status_t map_engine_status(xaios_engine_status_t status) {
  if (status == XAIOS_ENGINE_OK) return XAIOS_OK;
  if (status == XAIOS_ENGINE_ERR_IO || status == XAIOS_ENGINE_ERR_CHECKSUM) {
    return XAIOS_ERR_IO;
  }
  if (status == XAIOS_ENGINE_ERR_UNSUPPORTED ||
      status == XAIOS_ENGINE_ERR_CAPABILITY) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  return XAIOS_ERR_INVALID;
}

static int hex_value(char value) {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  if (value >= 'A' && value <= 'F') return value - 'A' + 10;
  return -1;
}

static int parse_package_path(const char *path, uint32_t *required_state,
                              uint8_t package_id[32]) {
  const char *name = 0;
  if (strncmp(path, "/.staging/", 10U) == 0) {
    *required_state = XAIOS_MODEL_VOLUME_PACKAGE_STAGING;
    name = path + 10U;
  } else if (path[0] == '/') {
    *required_state = XAIOS_MODEL_VOLUME_PACKAGE_ACTIVE;
    name = path + 1U;
  } else {
    return 0;
  }
  for (uint32_t index = 0U; index < MODEL_PACKAGE_NAME_LENGTH; ++index) {
    int high = hex_value(name[index]);
    int low = index + 1U < MODEL_PACKAGE_NAME_LENGTH
                  ? hex_value(name[index + 1U])
                  : -1;
    if ((index & 1U) != 0U) continue;
    if (high < 0 || low < 0) return 0;
    package_id[index / 2U] = (uint8_t)((high << 4U) | low);
  }
  return name[MODEL_PACKAGE_NAME_LENGTH] == '\0';
}

static int package_id_equal(const uint8_t left[32], const uint8_t right[32]) {
  uint8_t difference = 0U;
  for (uint32_t index = 0U; index < 32U; ++index) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0U;
}

static xaios_status_t find_package(model_vfs_context_t *model,
                                   const char *path, uint64_t *index,
                                   xaios_model_volume_package_t *package) {
  uint32_t required_state = 0U;
  uint8_t package_id[32];
  if (!parse_package_path(path, &required_state, package_id)) {
    return XAIOS_ERR_NOT_FOUND;
  }
  for (uint64_t current = 0U; current < model->volume.package_count;
       ++current) {
    xaios_engine_status_t status =
        xaios_model_volume_read_package(&model->volume, current, package);
    if (status != XAIOS_ENGINE_OK) return map_engine_status(status);
    if (package->state == required_state &&
        package_id_equal(package->package_id, package_id)) {
      *index = current;
      return XAIOS_OK;
    }
  }
  return XAIOS_ERR_NOT_FOUND;
}

static xaios_status_t package_has_pending_hashes(
    model_vfs_context_t *model,
    const xaios_model_volume_package_t *package, uint32_t *pending) {
  if (model == 0 || package == 0 || pending == 0) return XAIOS_ERR_INVALID;
  *pending = 0U;
  for (uint64_t relative = 0U; relative < package->chunk_count; ++relative) {
    xaios_model_volume_chunk_t chunk;
    xaios_engine_status_t status = xaios_model_volume_read_chunk(
        &model->volume, package->chunk_start + relative, &chunk);
    if (status != XAIOS_ENGINE_OK) return map_engine_status(status);
    if ((chunk.flags & XAIOS_MODEL_VOLUME_CHUNK_HASH_PENDING) != 0U) {
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
  xaios_model_volume_package_t package;
  memset(&package, 0, sizeof(package));
  uint64_t index = 0U;
  xaios_spin_lock(&model->lock);
  xaios_status_t status = find_package(model, path, &index, &package);
  if (status == XAIOS_OK) {
    uint32_t pending = 0U;
    status = package_has_pending_hashes(model, &package, &pending);
    if (status == XAIOS_OK && pending == 0U) {
      status = map_engine_status(xaios_model_volume_verify_package_manifest(
          &model->volume, &package));
    }
  }
  if (status == XAIOS_OK && writable &&
      package.state != XAIOS_MODEL_VOLUME_PACKAGE_STAGING) {
    status = XAIOS_ERR_UNSUPPORTED;
  }
  if (status == XAIOS_OK && writable &&
      (flags & XAIOS_VFS_OPEN_TRUNCATE) != 0U) {
    for (uint64_t relative = 0U; relative < package.chunk_count; ++relative) {
      xaios_model_volume_chunk_t chunk;
      xaios_engine_status_t engine_status = xaios_model_volume_read_chunk(
          &model->volume, package.chunk_start + relative, &chunk);
      if (engine_status != XAIOS_ENGINE_OK) {
        status = map_engine_status(engine_status);
        break;
      }
      if ((chunk.flags & XAIOS_MODEL_VOLUME_CHUNK_COMPLETE) != 0U &&
          (chunk.flags & XAIOS_MODEL_VOLUME_CHUNK_ZERO) == 0U) {
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
    klog("modelfs: open rejected path=%s flags=0x%x status=%d state=%u\n",
         path, flags, (int)status, package.state);
  }
  xaios_spin_unlock(&model->lock);
  return status;
}

static model_vfs_handle_t *model_find_handle(model_vfs_context_t *model,
                                              uint64_t handle) {
  if (handle == 0U || handle > MODEL_VFS_MAX_HANDLES) return 0;
  model_vfs_handle_t *opened = &model->handles[handle - 1U];
  return opened->active != 0U ? opened : 0;
}

static xaios_status_t model_sync_handle_locked(model_vfs_context_t *model,
                                                model_vfs_handle_t *opened) {
  xaios_model_volume_writer_t writer = {
      model, model_write_at, model_flush};
  if (opened->written_start == UINT64_MAX) {
    return map_engine_status(model_flush(model));
  }
  xaios_model_volume_package_t package;
  xaios_engine_status_t engine_status = xaios_model_volume_read_package(
      &model->volume, opened->package_index, &package);
  if (engine_status != XAIOS_ENGINE_OK) return map_engine_status(engine_status);
  uint64_t completed = 0U;
  engine_status = xaios_model_volume_commit_staging_range(
      &model->volume, &package, &writer, opened->written_start,
      opened->written_end - opened->written_start, model->scratch,
      sizeof(model->scratch), &completed);
  if (engine_status != XAIOS_ENGINE_OK) return map_engine_status(engine_status);
  klog("modelfs: staging fsync record=%lu range=%lu:%lu completed=%lu generation=%lu\n",
       package.record_id, opened->written_start,
       opened->written_end - opened->written_start, completed,
       model->volume.generation);
  opened->written_start = UINT64_MAX;
  opened->written_end = 0U;
  return XAIOS_OK;
}

static xaios_status_t model_close(void *context, uint64_t handle) {
  model_vfs_context_t *model = (model_vfs_context_t *)context;
  xaios_spin_lock(&model->lock);
  model_vfs_handle_t *opened = model_find_handle(model, handle);
  if (opened == 0) {
    xaios_spin_unlock(&model->lock);
    return XAIOS_ERR_INVALID;
  }
  xaios_status_t status = opened->writable != 0U
                              ? model_sync_handle_locked(model, opened)
                              : XAIOS_OK;
  memset(opened, 0, sizeof(*opened));
  xaios_spin_unlock(&model->lock);
  return status;
}

static int64_t model_pread(void *context, uint64_t handle, void *buffer,
                           uint64_t length, uint64_t offset) {
  model_vfs_context_t *model = (model_vfs_context_t *)context;
  if (buffer == 0 || length > INT64_MAX) {
    return XAIOS_ERR_INVALID;
  }
  if (length == 0U) return 0;
  xaios_spin_lock(&model->lock);
  model_vfs_handle_t *opened = model_find_handle(model, handle);
  if (opened == 0) {
    xaios_spin_unlock(&model->lock);
    return XAIOS_ERR_INVALID;
  }
  xaios_model_volume_package_t package;
  xaios_engine_status_t engine_status = xaios_model_volume_read_package(
      &model->volume, opened->package_index, &package);
  if (engine_status != XAIOS_ENGINE_OK ||
      package.state == XAIOS_MODEL_VOLUME_PACKAGE_QUARANTINED) {
    xaios_spin_unlock(&model->lock);
    return engine_status == XAIOS_ENGINE_OK ? XAIOS_ERR_IO
                                            : map_engine_status(engine_status);
  }
  if (offset >= package.logical_size) {
    xaios_spin_unlock(&model->lock);
    return 0;
  }
  if (length > package.logical_size - offset) {
    length = package.logical_size - offset;
  }
  uint64_t bad_offset = UINT64_MAX;
  engine_status = xaios_model_volume_pread_verified(
      &model->volume, &package, offset, buffer, (size_t)length,
      model->scratch, sizeof(model->scratch), &bad_offset);
  xaios_spin_unlock(&model->lock);
  if (engine_status != XAIOS_ENGINE_OK) {
    klog("modelfs: package read rejected record=%lu offset=%lu bad=%lu status=%d\n",
         package.record_id, offset, bad_offset, (int)engine_status);
    return map_engine_status(engine_status);
  }
  return (int64_t)length;
}

static int64_t model_pwrite(void *context, uint64_t handle,
                            const void *buffer, uint64_t length,
                            uint64_t offset) {
  model_vfs_context_t *model = (model_vfs_context_t *)context;
  if (buffer == 0 || length == 0U || length > INT64_MAX ||
      offset > UINT64_MAX - length) {
    return length == 0U ? 0 : XAIOS_ERR_INVALID;
  }
  xaios_spin_lock(&model->lock);
  model_vfs_handle_t *opened = model_find_handle(model, handle);
  if (opened == 0 || opened->writable == 0U) {
    xaios_spin_unlock(&model->lock);
    return XAIOS_ERR_INVALID;
  }
  xaios_model_volume_package_t package;
  xaios_engine_status_t engine_status = xaios_model_volume_read_package(
      &model->volume, opened->package_index, &package);
  if (engine_status == XAIOS_ENGINE_OK) {
    uint64_t end = offset + length;
    if (opened->written_start != UINT64_MAX &&
        (end < opened->written_start || offset > opened->written_end)) {
      xaios_status_t sync_status = model_sync_handle_locked(model, opened);
      if (sync_status != XAIOS_OK) {
        xaios_spin_unlock(&model->lock);
        return sync_status;
      }
    }
    xaios_model_volume_writer_t writer = {
        model, model_write_at, model_flush};
    engine_status = xaios_model_volume_pwrite_staging(
        &model->volume, &package, &writer, offset, buffer, (size_t)length);
  }
  if (engine_status == XAIOS_ENGINE_OK) {
    uint64_t end = offset + length;
    if (opened->written_start == UINT64_MAX || offset < opened->written_start) {
      opened->written_start = offset;
    }
    if (end > opened->written_end) opened->written_end = end;
  }
  if (engine_status != XAIOS_ENGINE_OK) {
    klog("modelfs: staging pwrite rejected record=%lu offset=%lu length=%lu status=%d\n",
         package.record_id, offset, length, (int)engine_status);
  }
  xaios_spin_unlock(&model->lock);
  return engine_status == XAIOS_ENGINE_OK ? (int64_t)length
                                           : map_engine_status(engine_status);
}

xaios_status_t vfs_model_register_staging(
    const xaios_model_registration_t *registration, uint64_t *generation) {
  if (registration == 0 || generation == 0 || g_model_vfs.mounted == 0U) {
    return XAIOS_ERR_INVALID;
  }
  xaios_spin_lock(&g_model_vfs.lock);
  if (g_model_vfs.read_only != 0U || catalog_maintenance_active()) {
    xaios_spin_unlock(&g_model_vfs.lock);
    return g_model_vfs.read_only != 0U ? XAIOS_ERR_UNSUPPORTED
                                       : XAIOS_ERR_BUSY;
  }
  xaios_model_volume_package_t package_template;
  memset(&package_template, 0, sizeof(package_template));
  memcpy(package_template.model_uuid, registration->model_uuid, 16U);
  memcpy(package_template.package_id, registration->package_id, 32U);
  memcpy(package_template.signer_public_key, registration->signer_public_key,
         32U);
  memcpy(package_template.signature, registration->signature, 64U);
  memcpy(package_template.source_revision, registration->source_revision, 32U);
  package_template.logical_size = registration->logical_size;
  package_template.chunk_size = g_model_vfs.volume.chunk_size;
  memcpy(package_template.architecture_id, registration->architecture_id,
         sizeof(package_template.architecture_id));
  memcpy(package_template.target_id, registration->target_id,
         sizeof(package_template.target_id));
  xaios_model_volume_writer_t writer = {
      &g_model_vfs, model_write_at, model_flush};
  xaios_model_volume_package_t registered;
  xaios_status_t status = map_engine_status(xaios_model_volume_register_staging(
      &g_model_vfs.volume, &package_template, &writer, g_model_vfs.scratch,
      sizeof(g_model_vfs.scratch), &registered));
  if (status == XAIOS_OK) *generation = g_model_vfs.volume.generation;
  xaios_spin_unlock(&g_model_vfs.lock);
  if (status == XAIOS_OK) {
    klog("modelfs: registered dynamic staging package record=%lu bytes=%lu generation=%lu\n",
         registered.record_id, registered.logical_size, *generation);
  }
  return status;
}

xaios_status_t vfs_model_cleanup_staging(const char *package_id,
                                          uint64_t *generation,
                                          uint64_t *reclaimed_bytes) {
  char path[82];
  if (generation == 0 || reclaimed_bytes == 0 ||
      g_model_vfs.mounted == 0U ||
      staging_path_from_id(package_id, path) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  xaios_spin_lock(&g_model_vfs.lock);
  if (g_model_vfs.read_only != 0U || catalog_maintenance_active()) {
    xaios_spin_unlock(&g_model_vfs.lock);
    return g_model_vfs.read_only != 0U ? XAIOS_ERR_UNSUPPORTED
                                       : XAIOS_ERR_BUSY;
  }
  for (uint32_t index = 0U; index < MODEL_VFS_MAX_HANDLES; ++index) {
    if (g_model_vfs.handles[index].active != 0U) {
      xaios_spin_unlock(&g_model_vfs.lock);
      return XAIOS_ERR_BUSY;
    }
  }
  uint64_t package_index = 0U;
  xaios_model_volume_package_t package;
  xaios_status_t status =
      find_package(&g_model_vfs, path, &package_index, &package);
  if (status == XAIOS_OK) {
    xaios_model_volume_writer_t writer = {
        &g_model_vfs, model_write_at, model_flush};
    status = map_engine_status(xaios_model_volume_remove_staging(
        &g_model_vfs.volume, &package, &writer, g_model_vfs.scratch,
        sizeof(g_model_vfs.scratch), reclaimed_bytes));
  }
  if (status == XAIOS_OK) *generation = g_model_vfs.volume.generation;
  xaios_spin_unlock(&g_model_vfs.lock);
  if (status == XAIOS_OK) {
    klog("modelfs: cleaned staging package=%s reclaimed=%lu generation=%lu\n",
         package_id, *reclaimed_bytes, *generation);
  }
  return status;
}

static xaios_status_t scrub_persist_locked(void) {
  model_scrub_record_t record;
  memset(&record, 0, sizeof(record));
  record.magic = MODEL_SCRUB_MAGIC;
  record.version = MODEL_SCRUB_VERSION;
  record.size = sizeof(record);
  record.status = g_model_scrub;
  return xaiboot_fs_write(MODEL_SCRUB_STATE_PATH, &record, sizeof(record));
}

static void scrub_load(void) {
  model_scrub_record_t record;
  uint64_t size = 0U;
  memset(&g_model_scrub, 0, sizeof(g_model_scrub));
  if (xaiboot_fs_read(MODEL_SCRUB_STATE_PATH, &record, sizeof(record),
                      &size) != XAIOS_OK ||
      size != sizeof(record) || record.magic != MODEL_SCRUB_MAGIC ||
      record.version != MODEL_SCRUB_VERSION || record.size != sizeof(record) ||
      memcmp(record.status.volume_uuid, g_model_vfs.volume.volume_uuid, 16U) !=
          0 ||
      record.status.generation != g_model_vfs.volume.generation ||
      (record.status.state != XAIOS_MODEL_MAINTENANCE_RUNNING &&
       record.status.state != XAIOS_MODEL_MAINTENANCE_PAUSED)) {
    memset(&g_model_scrub, 0, sizeof(g_model_scrub));
    return;
  }
  g_model_scrub = record.status;
  klog("modelfs: resumed scrub state=%u package=%lu chunk=%lu checked=%lu\n",
       g_model_scrub.state, g_model_scrub.package_index,
       g_model_scrub.chunk_index, g_model_scrub.checked_bytes);
}

xaios_status_t vfs_model_scrub_start(xaios_model_scrub_status_t *status) {
  if (status == 0 || g_model_vfs.mounted == 0U) return XAIOS_ERR_INVALID;
  xaios_spin_lock(&g_model_vfs.lock);
  if (maintenance_active(g_model_scrub.state) ||
      maintenance_active(g_model_trim.state)) {
    xaios_spin_unlock(&g_model_vfs.lock);
    return XAIOS_ERR_BUSY;
  }
  memset(&g_model_scrub, 0, sizeof(g_model_scrub));
  memcpy(g_model_scrub.volume_uuid, g_model_vfs.volume.volume_uuid, 16U);
  g_model_scrub.generation = g_model_vfs.volume.generation;
  g_model_scrub.bad_logical_offset = UINT64_MAX;
  g_model_scrub.state = XAIOS_MODEL_MAINTENANCE_RUNNING;
  for (uint64_t package_index = 0U;
       package_index < g_model_vfs.volume.package_count; ++package_index) {
    xaios_model_volume_package_t package;
    if (xaios_model_volume_read_package(&g_model_vfs.volume, package_index,
                                        &package) != XAIOS_ENGINE_OK) {
      g_model_scrub.state = XAIOS_MODEL_MAINTENANCE_FAILED;
      ++g_model_scrub.error_count;
      break;
    }
    if (package.state == XAIOS_MODEL_VOLUME_PACKAGE_QUARANTINED) continue;
    for (uint64_t relative = 0U; relative < package.chunk_count; ++relative) {
      xaios_model_volume_chunk_t chunk;
      if (xaios_model_volume_read_chunk(
              &g_model_vfs.volume, package.chunk_start + relative, &chunk) !=
          XAIOS_ENGINE_OK) {
        g_model_scrub.state = XAIOS_MODEL_MAINTENANCE_FAILED;
        ++g_model_scrub.error_count;
        break;
      }
      if ((chunk.flags & XAIOS_MODEL_VOLUME_CHUNK_COMPLETE) != 0U) {
        if (chunk.length > UINT64_MAX - g_model_scrub.total_bytes) {
          g_model_scrub.state = XAIOS_MODEL_MAINTENANCE_FAILED;
          ++g_model_scrub.error_count;
          break;
        }
        g_model_scrub.total_bytes += chunk.length;
      }
    }
    if (g_model_scrub.state == XAIOS_MODEL_MAINTENANCE_FAILED) break;
  }
  xaios_status_t persist = scrub_persist_locked();
  if (persist != XAIOS_OK) g_model_scrub.state = XAIOS_MODEL_MAINTENANCE_FAILED;
  *status = g_model_scrub;
  xaios_spin_unlock(&g_model_vfs.lock);
  return persist;
}

xaios_status_t vfs_model_scrub_step(xaios_model_scrub_status_t *status) {
  if (status == 0 || g_model_vfs.mounted == 0U) return XAIOS_ERR_INVALID;
  xaios_model_volume_t snapshot;
  xaios_model_volume_package_t package;
  xaios_model_volume_chunk_t chunk;
  xaios_spin_lock(&g_model_vfs.lock);
  if (g_model_scrub.state != XAIOS_MODEL_MAINTENANCE_RUNNING) {
    *status = g_model_scrub;
    xaios_spin_unlock(&g_model_vfs.lock);
    return XAIOS_OK;
  }
  if (g_model_scrub.generation != g_model_vfs.volume.generation) {
    g_model_scrub.state = XAIOS_MODEL_MAINTENANCE_FAILED;
    ++g_model_scrub.error_count;
    (void)scrub_persist_locked();
    *status = g_model_scrub;
    xaios_spin_unlock(&g_model_vfs.lock);
    return XAIOS_ERR_BUSY;
  }
  for (;;) {
    if (g_model_scrub.package_index >= g_model_vfs.volume.package_count) {
      g_model_scrub.state = XAIOS_MODEL_MAINTENANCE_COMPLETE;
      xaios_status_t persist = scrub_persist_locked();
      *status = g_model_scrub;
      xaios_spin_unlock(&g_model_vfs.lock);
      return persist;
    }
    xaios_engine_status_t package_status = xaios_model_volume_read_package(
        &g_model_vfs.volume, g_model_scrub.package_index, &package);
    if (package_status != XAIOS_ENGINE_OK) {
      g_model_scrub.state = XAIOS_MODEL_MAINTENANCE_FAILED;
      ++g_model_scrub.error_count;
      (void)scrub_persist_locked();
      *status = g_model_scrub;
      xaios_spin_unlock(&g_model_vfs.lock);
      return map_engine_status(package_status);
    }
    if (package.state == XAIOS_MODEL_VOLUME_PACKAGE_QUARANTINED ||
        g_model_scrub.chunk_index >= package.chunk_count) {
      ++g_model_scrub.package_index;
      g_model_scrub.chunk_index = 0U;
      continue;
    }
    xaios_engine_status_t chunk_status = xaios_model_volume_read_chunk(
        &g_model_vfs.volume, package.chunk_start + g_model_scrub.chunk_index,
        &chunk);
    if (chunk_status != XAIOS_ENGINE_OK) {
      g_model_scrub.state = XAIOS_MODEL_MAINTENANCE_FAILED;
      ++g_model_scrub.error_count;
      (void)scrub_persist_locked();
      *status = g_model_scrub;
      xaios_spin_unlock(&g_model_vfs.lock);
      return map_engine_status(chunk_status);
    }
    if ((chunk.flags & XAIOS_MODEL_VOLUME_CHUNK_COMPLETE) == 0U) {
      ++g_model_scrub.chunk_index;
      xaios_status_t persist = scrub_persist_locked();
      *status = g_model_scrub;
      xaios_spin_unlock(&g_model_vfs.lock);
      return persist;
    }
    snapshot = g_model_vfs.volume;
    break;
  }
  xaios_spin_unlock(&g_model_vfs.lock);

  uint64_t bad_offset = UINT64_MAX;
  xaios_engine_status_t verified = xaios_model_volume_verify_range(
      &snapshot, &package, chunk.logical_offset, chunk.length,
      g_model_scrub_scratch, sizeof(g_model_scrub_scratch), &bad_offset);

  xaios_spin_lock(&g_model_vfs.lock);
  if (g_model_scrub.state != XAIOS_MODEL_MAINTENANCE_RUNNING ||
      g_model_scrub.generation != g_model_vfs.volume.generation) {
    *status = g_model_scrub;
    xaios_spin_unlock(&g_model_vfs.lock);
    return XAIOS_ERR_BUSY;
  }
  if (verified != XAIOS_ENGINE_OK) {
    xaios_model_volume_writer_t writer = {
        &g_model_vfs, model_write_at, model_flush};
    xaios_engine_status_t quarantined =
        xaios_model_volume_quarantine_package(
            &g_model_vfs.volume, &package, &writer, g_model_vfs.scratch,
            sizeof(g_model_vfs.scratch));
    memcpy(g_model_scrub.bad_package_id, package.package_id, 32U);
    g_model_scrub.bad_logical_offset = bad_offset;
    ++g_model_scrub.error_count;
    g_model_scrub.state = XAIOS_MODEL_MAINTENANCE_FAILED;
    if (quarantined == XAIOS_ENGINE_OK) {
      g_model_scrub.generation = g_model_vfs.volume.generation;
    }
    (void)scrub_persist_locked();
    *status = g_model_scrub;
    xaios_spin_unlock(&g_model_vfs.lock);
    return quarantined == XAIOS_ENGINE_OK ? map_engine_status(verified)
                                          : map_engine_status(quarantined);
  }
  g_model_scrub.checked_bytes += chunk.length;
  ++g_model_scrub.chunk_index;
  xaios_status_t persist = scrub_persist_locked();
  *status = g_model_scrub;
  xaios_spin_unlock(&g_model_vfs.lock);
  return persist;
}

xaios_status_t vfs_model_scrub_status(xaios_model_scrub_status_t *status) {
  if (status == 0 || g_model_vfs.mounted == 0U) return XAIOS_ERR_INVALID;
  xaios_spin_lock(&g_model_vfs.lock);
  *status = g_model_scrub;
  xaios_spin_unlock(&g_model_vfs.lock);
  return XAIOS_OK;
}

static xaios_status_t scrub_set_state(uint32_t required, uint32_t next,
                                      xaios_model_scrub_status_t *status) {
  if (status == 0 || g_model_vfs.mounted == 0U) return XAIOS_ERR_INVALID;
  xaios_spin_lock(&g_model_vfs.lock);
  if (g_model_scrub.state != required) {
    xaios_spin_unlock(&g_model_vfs.lock);
    return XAIOS_ERR_BUSY;
  }
  g_model_scrub.state = next;
  xaios_status_t persist = scrub_persist_locked();
  *status = g_model_scrub;
  xaios_spin_unlock(&g_model_vfs.lock);
  return persist;
}

xaios_status_t vfs_model_scrub_pause(xaios_model_scrub_status_t *status) {
  return scrub_set_state(XAIOS_MODEL_MAINTENANCE_RUNNING,
                         XAIOS_MODEL_MAINTENANCE_PAUSED, status);
}

xaios_status_t vfs_model_scrub_resume(xaios_model_scrub_status_t *status) {
  return scrub_set_state(XAIOS_MODEL_MAINTENANCE_PAUSED,
                         XAIOS_MODEL_MAINTENANCE_RUNNING, status);
}

xaios_status_t vfs_model_scrub_cancel(xaios_model_scrub_status_t *status) {
  if (g_model_scrub.state == XAIOS_MODEL_MAINTENANCE_RUNNING) {
    return scrub_set_state(XAIOS_MODEL_MAINTENANCE_RUNNING,
                           XAIOS_MODEL_MAINTENANCE_CANCELLED, status);
  }
  return scrub_set_state(XAIOS_MODEL_MAINTENANCE_PAUSED,
                         XAIOS_MODEL_MAINTENANCE_CANCELLED, status);
}

static xaios_status_t trim_persist_locked(void) {
  model_trim_record_t record;
  memset(&record, 0, sizeof(record));
  record.magic = MODEL_TRIM_MAGIC;
  record.version = MODEL_TRIM_VERSION;
  record.size = sizeof(record);
  record.status = g_model_trim;
  return xaiboot_fs_write(MODEL_TRIM_STATE_PATH, &record, sizeof(record));
}

static void trim_load(void) {
  model_trim_record_t record;
  uint64_t size = 0U;
  memset(&g_model_trim, 0, sizeof(g_model_trim));
  if (xaiboot_fs_read(MODEL_TRIM_STATE_PATH, &record, sizeof(record), &size) !=
          XAIOS_OK ||
      size != sizeof(record) || record.magic != MODEL_TRIM_MAGIC ||
      record.version != MODEL_TRIM_VERSION || record.size != sizeof(record) ||
      memcmp(record.status.volume_uuid, g_model_vfs.volume.volume_uuid, 16U) !=
          0 ||
      record.status.generation != g_model_vfs.volume.generation ||
      record.status.state != XAIOS_MODEL_MAINTENANCE_RUNNING) {
    memset(&g_model_trim, 0, sizeof(g_model_trim));
    return;
  }
  g_model_trim = record.status;
  klog("modelfs: resumed trim chunk=%lu cursor=%lu processed=%lu eligible=%lu dry_run=%u\n",
       g_model_trim.chunk_index, g_model_trim.cursor_offset,
       g_model_trim.trimmed_bytes, g_model_trim.eligible_bytes,
       g_model_trim.dry_run);
}

static int trim_aligned_extent(uint64_t offset, uint64_t length,
                               uint64_t *aligned_offset,
                               uint64_t *aligned_length) {
  uint64_t granularity = g_model_vfs.device_info.discard_granularity;
  uint64_t alignment = g_model_vfs.device_info.discard_alignment;
  if (aligned_offset == 0 || aligned_length == 0 || length == 0U ||
      granularity == 0U || offset > UINT64_MAX - length) {
    return 0;
  }
  alignment %= granularity;
  uint64_t remainder = offset % granularity;
  uint64_t delta =
      (alignment + granularity - remainder) % granularity;
  if (delta > length || offset > UINT64_MAX - delta) return 0;
  uint64_t start = offset + delta;
  uint64_t available = length - delta;
  uint64_t count = available - available % granularity;
  if (count == 0U) return 0;
  *aligned_offset = start;
  *aligned_length = count;
  return 1;
}

static xaios_status_t trim_extent_for_index(uint64_t index, uint64_t *offset,
                                            uint64_t *length) {
  if (offset == 0 || length == 0) return XAIOS_ERR_INVALID;
  if (index < g_model_vfs.volume.chunk_count) {
    xaios_model_volume_chunk_t chunk;
    xaios_engine_status_t engine_status = xaios_model_volume_read_chunk(
        &g_model_vfs.volume, index, &chunk);
    if (engine_status != XAIOS_ENGINE_OK) {
      return map_engine_status(engine_status);
    }
    if ((chunk.flags & XAIOS_MODEL_VOLUME_CHUNK_FREE) == 0U) {
      return XAIOS_ERR_NOT_FOUND;
    }
    return trim_aligned_extent(chunk.physical_offset, chunk.extent_length,
                               offset, length)
               ? XAIOS_OK
               : XAIOS_ERR_NOT_FOUND;
  }
  if (index == g_model_vfs.volume.chunk_count &&
      g_model_vfs.volume.data_tail < g_model_vfs.volume.volume_size &&
      trim_aligned_extent(g_model_vfs.volume.data_tail,
                          g_model_vfs.volume.volume_size -
                              g_model_vfs.volume.data_tail,
                          offset, length)) {
    return XAIOS_OK;
  }
  return XAIOS_ERR_NOT_FOUND;
}

static int range_contains(uint64_t extent_offset, uint64_t extent_length,
                          uint64_t offset, uint64_t length) {
  return extent_offset <= offset && extent_length != 0U && length != 0U &&
         extent_offset <= UINT64_MAX - extent_length &&
         offset <= UINT64_MAX - length &&
         offset + length <= extent_offset + extent_length;
}

xaios_status_t vfs_model_trim_start(uint32_t dry_run, uint32_t all_free,
                                    uint64_t offset, uint64_t length,
                                    xaios_model_trim_status_t *status) {
  if (status == 0 || g_model_vfs.mounted == 0U || dry_run > 1U ||
      all_free > 1U || (all_free != 0U && (offset != 0U || length != 0U)) ||
      (all_free == 0U &&
       (length == 0U || offset > UINT64_MAX - length))) {
    return XAIOS_ERR_INVALID;
  }
  xaios_spin_lock(&g_model_vfs.lock);
  if (g_model_vfs.read_only != 0U || catalog_maintenance_active()) {
    xaios_spin_unlock(&g_model_vfs.lock);
    return g_model_vfs.read_only != 0U ? XAIOS_ERR_UNSUPPORTED
                                       : XAIOS_ERR_BUSY;
  }
  if (g_model_vfs.device_info.discard_supported == 0U ||
      g_model_vfs.device_info.discard_granularity == 0U) {
    xaios_spin_unlock(&g_model_vfs.lock);
    return XAIOS_ERR_UNSUPPORTED;
  }
  if (dry_run == 0U && block_flush(g_model_vfs.device) != XAIOS_OK) {
    xaios_spin_unlock(&g_model_vfs.lock);
    return XAIOS_ERR_IO;
  }

  memset(&g_model_trim, 0, sizeof(g_model_trim));
  memcpy(g_model_trim.volume_uuid, g_model_vfs.volume.volume_uuid, 16U);
  g_model_trim.generation = g_model_vfs.volume.generation;
  g_model_trim.dry_run = dry_run;
  g_model_trim.all_free = all_free;
  g_model_trim.state = XAIOS_MODEL_MAINTENANCE_RUNNING;

  if (all_free != 0U) {
    for (uint64_t index = 0U; index <= g_model_vfs.volume.chunk_count;
         ++index) {
      uint64_t free_offset = 0U;
      uint64_t free_length = 0U;
      xaios_status_t found =
          trim_extent_for_index(index, &free_offset, &free_length);
      if (found == XAIOS_ERR_NOT_FOUND) continue;
      if (found != XAIOS_OK ||
          free_length > UINT64_MAX - g_model_trim.eligible_bytes) {
        ++g_model_trim.error_count;
        g_model_trim.state = XAIOS_MODEL_MAINTENANCE_FAILED;
        break;
      }
      g_model_trim.eligible_bytes += free_length;
    }
  } else {
    uint64_t aligned_offset = 0U;
    uint64_t aligned_length = 0U;
    if (!trim_aligned_extent(offset, length, &aligned_offset,
                             &aligned_length)) {
      xaios_spin_unlock(&g_model_vfs.lock);
      return XAIOS_ERR_INVALID;
    }
    uint64_t selected = UINT64_MAX;
    for (uint64_t index = 0U; index <= g_model_vfs.volume.chunk_count;
         ++index) {
      uint64_t free_offset = 0U;
      uint64_t free_length = 0U;
      xaios_status_t found =
          trim_extent_for_index(index, &free_offset, &free_length);
      if (found != XAIOS_OK) continue;
      if (range_contains(free_offset, free_length, aligned_offset,
                         aligned_length)) {
        selected = index;
        break;
      }
    }
    if (selected == UINT64_MAX) {
      xaios_spin_unlock(&g_model_vfs.lock);
      return XAIOS_ERR_INVALID;
    }
    g_model_trim.chunk_index = selected;
    g_model_trim.requested_offset = aligned_offset;
    g_model_trim.requested_length = aligned_length;
    g_model_trim.eligible_bytes = aligned_length;
  }
  if (g_model_trim.eligible_bytes == 0U) {
    g_model_trim.state = XAIOS_MODEL_MAINTENANCE_COMPLETE;
  }
  xaios_status_t persist = trim_persist_locked();
  if (persist != XAIOS_OK) {
    ++g_model_trim.error_count;
    g_model_trim.state = XAIOS_MODEL_MAINTENANCE_FAILED;
  }
  *status = g_model_trim;
  xaios_spin_unlock(&g_model_vfs.lock);
  return persist;
}

xaios_status_t vfs_model_trim_step(xaios_model_trim_status_t *status) {
  if (status == 0 || g_model_vfs.mounted == 0U) return XAIOS_ERR_INVALID;
  xaios_spin_lock(&g_model_vfs.lock);
  if (g_model_trim.state != XAIOS_MODEL_MAINTENANCE_RUNNING) {
    *status = g_model_trim;
    xaios_spin_unlock(&g_model_vfs.lock);
    return XAIOS_OK;
  }
  if (g_model_trim.generation != g_model_vfs.volume.generation) {
    ++g_model_trim.error_count;
    g_model_trim.state = XAIOS_MODEL_MAINTENANCE_FAILED;
    (void)trim_persist_locked();
    *status = g_model_trim;
    xaios_spin_unlock(&g_model_vfs.lock);
    return XAIOS_ERR_BUSY;
  }

  uint64_t extent_offset = 0U;
  uint64_t extent_length = 0U;
  for (;;) {
    if (g_model_trim.chunk_index > g_model_vfs.volume.chunk_count) {
      g_model_trim.state = XAIOS_MODEL_MAINTENANCE_COMPLETE;
      xaios_status_t persist = trim_persist_locked();
      *status = g_model_trim;
      xaios_spin_unlock(&g_model_vfs.lock);
      return persist;
    }
    xaios_status_t found = trim_extent_for_index(
        g_model_trim.chunk_index, &extent_offset, &extent_length);
    if (found == XAIOS_ERR_NOT_FOUND) {
      ++g_model_trim.chunk_index;
      g_model_trim.cursor_offset = 0U;
      continue;
    }
    if (found != XAIOS_OK) {
      ++g_model_trim.error_count;
      g_model_trim.state = XAIOS_MODEL_MAINTENANCE_FAILED;
      (void)trim_persist_locked();
      *status = g_model_trim;
      xaios_spin_unlock(&g_model_vfs.lock);
      return found;
    }
    if (g_model_trim.all_free == 0U) {
      extent_offset = g_model_trim.requested_offset;
      extent_length = g_model_trim.requested_length;
    }
    if (g_model_trim.cursor_offset == 0U) {
      g_model_trim.cursor_offset = extent_offset;
    }
    if (!range_contains(extent_offset, extent_length,
                        g_model_trim.cursor_offset,
                        g_model_vfs.device_info.discard_granularity)) {
      ++g_model_trim.chunk_index;
      g_model_trim.cursor_offset = 0U;
      if (g_model_trim.all_free == 0U) {
        g_model_trim.state = XAIOS_MODEL_MAINTENANCE_COMPLETE;
      }
      continue;
    }
    break;
  }

  uint64_t extent_end = extent_offset + extent_length;
  uint64_t count = extent_end - g_model_trim.cursor_offset;
  if (count > MODEL_TRIM_STEP_LIMIT) count = MODEL_TRIM_STEP_LIMIT;
  count -= count % g_model_vfs.device_info.discard_granularity;
  if (count == 0U) {
    ++g_model_trim.error_count;
    g_model_trim.state = XAIOS_MODEL_MAINTENANCE_FAILED;
    (void)trim_persist_locked();
    *status = g_model_trim;
    xaios_spin_unlock(&g_model_vfs.lock);
    return XAIOS_ERR_INVALID;
  }
  xaios_status_t operation = XAIOS_OK;
  if (g_model_trim.dry_run == 0U) {
    operation = block_discard(g_model_vfs.device,
                              g_model_trim.cursor_offset, count);
  }
  if (operation != XAIOS_OK) {
    ++g_model_trim.error_count;
    g_model_trim.state = XAIOS_MODEL_MAINTENANCE_FAILED;
    (void)trim_persist_locked();
    *status = g_model_trim;
    xaios_spin_unlock(&g_model_vfs.lock);
    return operation;
  }
  if (count > UINT64_MAX - g_model_trim.trimmed_bytes) {
    ++g_model_trim.error_count;
    g_model_trim.state = XAIOS_MODEL_MAINTENANCE_FAILED;
  } else {
    g_model_trim.trimmed_bytes += count;
    ++g_model_trim.trimmed_ranges;
    g_model_trim.cursor_offset += count;
    if (g_model_trim.cursor_offset == extent_end) {
      ++g_model_trim.chunk_index;
      g_model_trim.cursor_offset = 0U;
      if (g_model_trim.all_free == 0U) {
        g_model_trim.state = XAIOS_MODEL_MAINTENANCE_COMPLETE;
      }
    }
    if (g_model_trim.all_free != 0U &&
        g_model_trim.chunk_index > g_model_vfs.volume.chunk_count) {
      g_model_trim.state = XAIOS_MODEL_MAINTENANCE_COMPLETE;
    }
  }
  xaios_status_t persist = trim_persist_locked();
  if (persist != XAIOS_OK) {
    ++g_model_trim.error_count;
    g_model_trim.state = XAIOS_MODEL_MAINTENANCE_FAILED;
  }
  *status = g_model_trim;
  xaios_spin_unlock(&g_model_vfs.lock);
  return persist;
}

xaios_status_t vfs_model_trim_status(xaios_model_trim_status_t *status) {
  if (status == 0 || g_model_vfs.mounted == 0U) return XAIOS_ERR_INVALID;
  xaios_spin_lock(&g_model_vfs.lock);
  *status = g_model_trim;
  xaios_spin_unlock(&g_model_vfs.lock);
  return XAIOS_OK;
}

xaios_status_t vfs_model_trim_cancel(xaios_model_trim_status_t *status) {
  if (status == 0 || g_model_vfs.mounted == 0U) return XAIOS_ERR_INVALID;
  xaios_spin_lock(&g_model_vfs.lock);
  if (g_model_trim.state != XAIOS_MODEL_MAINTENANCE_RUNNING) {
    xaios_spin_unlock(&g_model_vfs.lock);
    return XAIOS_ERR_BUSY;
  }
  g_model_trim.state = XAIOS_MODEL_MAINTENANCE_CANCELLED;
  xaios_status_t persist = trim_persist_locked();
  *status = g_model_trim;
  xaios_spin_unlock(&g_model_vfs.lock);
  return persist;
}

static xaios_status_t model_fsync(void *context, uint64_t handle) {
  model_vfs_context_t *model = (model_vfs_context_t *)context;
  xaios_spin_lock(&model->lock);
  model_vfs_handle_t *opened = model_find_handle(model, handle);
  xaios_status_t status =
      opened != 0 && opened->writable != 0U
          ? model_sync_handle_locked(model, opened)
          : XAIOS_ERR_INVALID;
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
  xaios_model_volume_package_t package;
  uint64_t index = 0U;
  uint64_t visible_size = 0U;
  xaios_spin_lock(&model->lock);
  xaios_status_t status = find_package(model, path, &index, &package);
  if (status == XAIOS_OK) {
    visible_size = package.logical_size;
    if (package.state == XAIOS_MODEL_VOLUME_PACKAGE_STAGING) {
      visible_size = 0U;
      for (uint64_t relative = 0U; relative < package.chunk_count;
           ++relative) {
        xaios_model_volume_chunk_t chunk;
        xaios_engine_status_t engine_status = xaios_model_volume_read_chunk(
            &model->volume, package.chunk_start + relative, &chunk);
        if (engine_status != XAIOS_ENGINE_OK) {
          status = map_engine_status(engine_status);
          break;
        }
        if (chunk.logical_offset != visible_size ||
            (chunk.flags & XAIOS_MODEL_VOLUME_CHUNK_COMPLETE) == 0U) {
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
    state = XAIOS_MODEL_VOLUME_PACKAGE_ACTIVE;
    xaios_status_t status =
        append_listing(buffer, capacity, &used, ".staging\n", 9U);
    if (status != XAIOS_OK) return status;
  } else if (strcmp(path, "/.staging") == 0) {
    state = XAIOS_MODEL_VOLUME_PACKAGE_STAGING;
  } else {
    return XAIOS_ERR_NOT_FOUND;
  }
  xaios_spin_lock(&model->lock);
  for (uint64_t index = 0U; index < model->volume.package_count; ++index) {
    xaios_model_volume_package_t package;
    xaios_engine_status_t engine_status =
        xaios_model_volume_read_package(&model->volume, index, &package);
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
    model_open, model_close, model_pread, model_pwrite, model_fsync, 0, 0,
    model_stat, model_statfs, 0, 0, 0, 0, model_list,
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
  xaios_model_volume_reader_t reader = {
      &g_model_vfs, model_read_at, g_model_vfs.device_info.capacity_bytes};
  xaios_engine_status_t engine_status = xaios_model_volume_open(
      &reader, verify_signature, 0, g_model_vfs.scratch,
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
  scrub_load();
  trim_load();
  klog("modelfs: mounted %s device=%s generation=%lu packages=%lu bytes=%lu policy=%s\n",
       mount_path, g_model_vfs.device_info.identifier,
       g_model_vfs.volume.generation,
       g_model_vfs.volume.package_count, g_model_vfs.volume.volume_size,
       read_only != 0U ? "read-only" : "rw-staging-active-immutable");
  return XAIOS_OK;
}

xaios_status_t vfs_mount_model_volume(uint32_t virtio_slot) {
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

xaios_status_t vfs_unmount_model_volume(const char *mount_path) {
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

xaios_status_t vfs_model_target_mounted(const char *device_identifier,
                                        uint32_t *mounted) {
  if (device_identifier == 0 || mounted == 0) return XAIOS_ERR_INVALID;
  *mounted =
      g_model_vfs.mounted != 0U &&
              strcmp(device_identifier, g_model_vfs.device_info.identifier) == 0
          ? 1U
          : 0U;
  return XAIOS_OK;
}

static xaios_status_t staging_path_from_id(const char *package_id,
                                           char path[82]) {
  if (package_id == 0) return XAIOS_ERR_INVALID;
  memcpy(path, "/.staging/", 10U);
  for (uint32_t index = 0U; index < MODEL_PACKAGE_NAME_LENGTH; ++index) {
    if (hex_value(package_id[index]) < 0) return XAIOS_ERR_INVALID;
    path[10U + index] = package_id[index];
  }
  if (package_id[MODEL_PACKAGE_NAME_LENGTH] != '\0') {
    return XAIOS_ERR_INVALID;
  }
  path[74] = '\0';
  return XAIOS_OK;
}

xaios_status_t vfs_model_verify_staging(const char *package_id,
                                         uint64_t *generation) {
  char path[82];
  if (generation == 0 || g_model_vfs.mounted == 0U ||
      staging_path_from_id(package_id, path) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  xaios_spin_lock(&g_model_vfs.lock);
  if (catalog_maintenance_active()) {
    xaios_spin_unlock(&g_model_vfs.lock);
    return XAIOS_ERR_BUSY;
  }
  uint64_t package_index = 0U;
  xaios_model_volume_package_t package;
  xaios_status_t status =
      find_package(&g_model_vfs, path, &package_index, &package);
  uint64_t bad_offset = UINT64_MAX;
  if (status == XAIOS_OK) {
    status = map_engine_status(xaios_model_volume_verify_package(
        &g_model_vfs.volume, &package, g_model_vfs.scratch,
        sizeof(g_model_vfs.scratch), &bad_offset));
  }
  if (status == XAIOS_OK) *generation = g_model_vfs.volume.generation;
  xaios_spin_unlock(&g_model_vfs.lock);
  if (status != XAIOS_OK) {
    klog("modelfs: verify rejected package=%s bad_offset=%lu status=%d\n",
         package_id, bad_offset, (int)status);
  }
  return status;
}

xaios_status_t vfs_model_activate_staging(const char *package_id,
                                           uint64_t *generation) {
  char path[82];
  if (generation == 0 || g_model_vfs.mounted == 0U ||
      staging_path_from_id(package_id, path) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  xaios_spin_lock(&g_model_vfs.lock);
  if (catalog_maintenance_active()) {
    xaios_spin_unlock(&g_model_vfs.lock);
    return XAIOS_ERR_BUSY;
  }
  uint64_t package_index = 0U;
  xaios_model_volume_package_t package;
  xaios_status_t status =
      find_package(&g_model_vfs, path, &package_index, &package);
  if (status == XAIOS_OK) {
    for (uint32_t index = 0U; index < MODEL_VFS_MAX_HANDLES; ++index) {
      if (g_model_vfs.handles[index].active != 0U &&
          g_model_vfs.handles[index].writable != 0U &&
          g_model_vfs.handles[index].package_index == package_index) {
        status = XAIOS_ERR_BUSY;
        break;
      }
    }
  }
  if (status == XAIOS_OK) {
    xaios_model_volume_writer_t writer = {
        &g_model_vfs, model_write_at, model_flush};
    status = map_engine_status(xaios_model_volume_activate_staging(
        &g_model_vfs.volume, &package, &writer, g_model_vfs.scratch,
        sizeof(g_model_vfs.scratch)));
  }
  if (status == XAIOS_OK) *generation = g_model_vfs.volume.generation;
  xaios_spin_unlock(&g_model_vfs.lock);
  if (status == XAIOS_OK) {
    klog("modelfs: activated package=%s generation=%lu\n", package_id,
         *generation);
  } else {
    klog("modelfs: activation rejected package=%s status=%d\n", package_id,
         (int)status);
  }
  return status;
}

xaios_status_t vfs_model_mount_status(xaios_model_mount_status_t *status) {
  if (status == 0 || g_model_vfs.mounted == 0U) {
    return status == 0 ? XAIOS_ERR_INVALID : XAIOS_ERR_NOT_FOUND;
  }
  memset(status, 0, sizeof(*status));
  xaios_spin_lock(&g_model_vfs.lock);
  status->device = g_model_vfs.device_info;
  status->generation = g_model_vfs.volume.generation;
  status->package_count = g_model_vfs.volume.package_count;
  for (uint64_t index = 0U; index < g_model_vfs.volume.package_count; ++index) {
    xaios_model_volume_package_t package;
    xaios_engine_status_t engine_status =
        xaios_model_volume_read_package(&g_model_vfs.volume, index, &package);
    if (engine_status != XAIOS_ENGINE_OK) {
      xaios_spin_unlock(&g_model_vfs.lock);
      memset(status, 0, sizeof(*status));
      return map_engine_status(engine_status);
    }
    if (package.state == XAIOS_MODEL_VOLUME_PACKAGE_ACTIVE) {
      ++status->active_packages;
    } else if (package.state == XAIOS_MODEL_VOLUME_PACKAGE_STAGING) {
      ++status->staging_packages;
    } else if (package.state == XAIOS_MODEL_VOLUME_PACKAGE_QUARANTINED) {
      ++status->quarantined_packages;
    }
  }
  status->mounted = 1U;
  xaios_spin_unlock(&g_model_vfs.lock);
  return XAIOS_OK;
}

void vfs_model_self_test(void) {
  char listing[128];
  uint64_t listing_size = 0U;
  if (g_model_vfs.mounted == 0U) {
    klog("modelfs: self-test skipped no volume\n");
    return;
  }
  if (vfs_list("/models", listing, sizeof(listing), &listing_size) !=
          XAIOS_OK ||
      listing_size < 9U || strncmp(listing, ".staging\n", 9U) != 0) {
    klog("modelfs: self-test failed listing\n");
    return;
  }
  if (listing_size == 9U) {
    klog("modelfs: self-test metadata passed; no active packages\n");
    return;
  }
  if (listing_size < 74U) {
    klog("modelfs: self-test failed package name\n");
    return;
  }
  char path[73];
  memcpy(path, "/models/", 8U);
  memcpy(path + 8U, listing + 9U, MODEL_PACKAGE_NAME_LENGTH);
  path[72] = '\0';
  xaios_vfs_stat_t stat;
  int64_t fd = vfs_open(path, XAIOS_VFS_OPEN_READ, UINT32_C(0x4d4f444c));
  uint8_t data[8192];
  if (fd <= 0 || vfs_stat(path, &stat) != XAIOS_OK) {
    klog("modelfs: self-test failed package open/stat\n");
    if (fd > 0) (void)vfs_close((uint32_t)fd, UINT32_C(0x4d4f444c));
    return;
  }
  uint64_t offset = stat.size > sizeof(data) ? stat.size - sizeof(data) : 0U;
  uint64_t count = stat.size < sizeof(data) ? stat.size : sizeof(data);
  if (count == 0U ||
      vfs_pread((uint32_t)fd, UINT32_C(0x4d4f444c), data, count, offset) !=
          (int64_t)count) {
    klog("modelfs: self-test failed package read\n");
    (void)vfs_close((uint32_t)fd, UINT32_C(0x4d4f444c));
    return;
  }
  if (vfs_close((uint32_t)fd, UINT32_C(0x4d4f444c)) != XAIOS_OK ||
      vfs_open(path, XAIOS_VFS_OPEN_WRITE, UINT32_C(0x4d4f444c)) !=
          XAIOS_ERR_UNSUPPORTED) {
    klog("modelfs: self-test failed active immutability policy\n");
    return;
  }

  char staging_listing[256];
  uint64_t staging_listing_size = 0U;
  if (vfs_list("/models/.staging", staging_listing,
               sizeof(staging_listing), &staging_listing_size) != XAIOS_OK ||
      staging_listing_size < MODEL_PACKAGE_NAME_LENGTH + 1U) {
    klog("modelfs: self-test failed staging listing\n");
    return;
  }
  char staging_path[82];
  memcpy(staging_path, "/models/.staging/", 17U);
  memcpy(staging_path + 17U, staging_listing, MODEL_PACKAGE_NAME_LENGTH);
  staging_path[81] = '\0';
  for (uint64_t index = 0U; index < 4096U; ++index) {
    data[index] = (uint8_t)((index * 7U + 3U) & 0xffU);
  }
  uint32_t staging_ready = 0U;
  int64_t staging_read = vfs_open(staging_path, XAIOS_VFS_OPEN_READ,
                                  UINT32_C(0x4d4f444c));
  if (staging_read > 0) {
    uint8_t existing[4096];
    int64_t existing_length =
        vfs_pread((uint32_t)staging_read, UINT32_C(0x4d4f444c), existing,
                  sizeof(existing), 0U);
    if (existing_length == (int64_t)sizeof(existing)) {
      staging_ready = 1U;
      for (uint64_t index = 0U; index < sizeof(existing); ++index) {
        if (existing[index] != (uint8_t)((index * 7U + 3U) & 0xffU)) {
          staging_ready = 0U;
          break;
        }
      }
    }
    (void)vfs_close((uint32_t)staging_read, UINT32_C(0x4d4f444c));
  }
  if (staging_ready == 0U) {
    fd = vfs_open(staging_path,
                  XAIOS_VFS_OPEN_WRITE | XAIOS_VFS_OPEN_CREATE |
                      XAIOS_VFS_OPEN_TRUNCATE,
                  UINT32_C(0x4d4f444c));
    if (fd <= 0) {
      klog("modelfs: self-test failed staging open status=%d\n", (int)fd);
      return;
    }
    int64_t written = vfs_pwrite((uint32_t)fd, UINT32_C(0x4d4f444c),
                                 data, 4096U, 0U);
    if (written != 4096) {
      klog("modelfs: self-test failed staging write status=%d\n",
           (int)written);
      (void)vfs_close((uint32_t)fd, UINT32_C(0x4d4f444c));
      return;
    }
    xaios_status_t sync_status =
        vfs_fsync((uint32_t)fd, UINT32_C(0x4d4f444c));
    if (sync_status != XAIOS_OK) {
      klog("modelfs: self-test failed staging fsync status=%d\n",
           (int)sync_status);
      (void)vfs_close((uint32_t)fd, UINT32_C(0x4d4f444c));
      return;
    }
    xaios_status_t close_status =
        vfs_close((uint32_t)fd, UINT32_C(0x4d4f444c));
    if (close_status != XAIOS_OK) {
      klog("modelfs: self-test failed staging close status=%d\n",
           (int)close_status);
      return;
    }
  }
  memset(data, 0, 4096U);
  fd = vfs_open(staging_path, XAIOS_VFS_OPEN_READ,
                UINT32_C(0x4d4f444c));
  if (fd <= 0 ||
      vfs_pread((uint32_t)fd, UINT32_C(0x4d4f444c), data, 4096U, 0U) !=
          4096 ||
      vfs_close((uint32_t)fd, UINT32_C(0x4d4f444c)) != XAIOS_OK) {
    klog("modelfs: self-test failed committed staging read\n");
    if (fd > 0) (void)vfs_close((uint32_t)fd, UINT32_C(0x4d4f444c));
    return;
  }
  for (uint64_t index = 0U; index < 4096U; ++index) {
    if (data[index] != (uint8_t)((index * 7U + 3U) & 0xffU)) {
      klog("modelfs: self-test failed staging data index=%lu\n", index);
      return;
    }
  }
  if (vfs_open(staging_path,
               XAIOS_VFS_OPEN_WRITE | XAIOS_VFS_OPEN_TRUNCATE,
               UINT32_C(0x4d4f444c)) != XAIOS_ERR_BUSY) {
    klog("modelfs: self-test failed resumable truncate protection\n");
    return;
  }
  klog("modelfs: signed active read and crash-consistent staging write self-test passed active_bytes=%lu staging_bytes=4096\n",
       count);
}
