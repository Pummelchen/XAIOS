/* The scrub/verify job of the model VFS.
 *
 * Split out of vfs_xaifs.c so no source file exceeds 500 lines. What moves
 * here is the whole scrub region: the persisted record, the package and chunk
 * walk, the range verification, and the start/step/status/pause/resume/cancel
 * entry points the control protocol calls. The trim job lives in
 * vfs_xaifs_trim.c; the mount and the block/engine glue stay in vfs_xaifs.c,
 * and the files share the model context layout and the helpers through
 * vfs_xaifs_internal.h.
 *
 * `g_model_scrub' and its verification scratch buffer move with this file; the
 * shared model context does not, and is reached through vfs_xaifs_model(). The
 * alias below keeps the moved code reading exactly as it did against the
 * variable. The block-write callbacks the quarantine path needs are defined in
 * vfs_xaifs.c and declared in vfs_xaifs_internal.h.
 */

#include "vfs_xaifs_internal.h"

#include <xaios/klog.h>
#include <xaios/xaiboot_fs.h>

#include <string.h>

#define MODEL_SCRUB_MAGIC UINT32_C(0x58415343)
#define MODEL_SCRUB_VERSION UINT32_C(1)
#define MODEL_SCRUB_STATE_PATH "/state/modelfs-scrub.bin"

typedef struct model_scrub_record {
  uint32_t magic;
  uint32_t version;
  uint32_t size;
  uint32_t reserved;
  xaios_model_scrub_status_t status;
} model_scrub_record_t;

static xaios_model_scrub_status_t g_model_scrub;
static uint8_t g_model_scrub_scratch[MODEL_READER_SCRATCH_SIZE];
#define g_model_vfs (*vfs_xaifs_model())

uint32_t vfs_xaifs_scrub_state(void) { return g_model_scrub.state; }

static xaios_status_t scrub_persist_locked(void) {
  model_scrub_record_t record;
  memset(&record, 0, sizeof(record));
  record.magic = MODEL_SCRUB_MAGIC;
  record.version = MODEL_SCRUB_VERSION;
  record.size = sizeof(record);
  record.status = g_model_scrub;
  return xaiboot_fs_write(MODEL_SCRUB_STATE_PATH, &record, sizeof(record));
}

void vfs_xaifs_scrub_load(void) {
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
  klog("xaifs: resumed scrub state=%u package=%lu chunk=%lu checked=%lu\n",
       g_model_scrub.state, g_model_scrub.package_index,
       g_model_scrub.chunk_index, g_model_scrub.checked_bytes);
}

xaios_status_t vfs_xaifs_scrub_start(xaios_model_scrub_status_t *status) {
  if (status == 0 || g_model_vfs.mounted == 0U) return XAIOS_ERR_INVALID;
  xaios_spin_lock(&g_model_vfs.lock);
  if (catalog_maintenance_active()) {
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
    xaios_xai_fs_package_t package;
    if (xaios_xai_fs_read_package(&g_model_vfs.volume, package_index,
                                        &package) != XAIOS_ENGINE_OK) {
      g_model_scrub.state = XAIOS_MODEL_MAINTENANCE_FAILED;
      ++g_model_scrub.error_count;
      break;
    }
    if (package.state == XAIOS_XAI_FS_PACKAGE_QUARANTINED) continue;
    for (uint64_t relative = 0U; relative < package.chunk_count; ++relative) {
      xaios_xai_fs_chunk_t chunk;
      if (xaios_xai_fs_read_chunk(
              &g_model_vfs.volume, package.chunk_start + relative, &chunk) !=
          XAIOS_ENGINE_OK) {
        g_model_scrub.state = XAIOS_MODEL_MAINTENANCE_FAILED;
        ++g_model_scrub.error_count;
        break;
      }
      if ((chunk.flags & XAIOS_XAI_FS_CHUNK_COMPLETE) != 0U) {
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

xaios_status_t vfs_xaifs_scrub_step(xaios_model_scrub_status_t *status) {
  if (status == 0 || g_model_vfs.mounted == 0U) return XAIOS_ERR_INVALID;
  xaios_xai_fs_t snapshot;
  xaios_xai_fs_package_t package;
  xaios_xai_fs_chunk_t chunk;
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
    xaios_engine_status_t package_status = xaios_xai_fs_read_package(
        &g_model_vfs.volume, g_model_scrub.package_index, &package);
    if (package_status != XAIOS_ENGINE_OK) {
      g_model_scrub.state = XAIOS_MODEL_MAINTENANCE_FAILED;
      ++g_model_scrub.error_count;
      (void)scrub_persist_locked();
      *status = g_model_scrub;
      xaios_spin_unlock(&g_model_vfs.lock);
      return map_engine_status(package_status);
    }
    if (package.state == XAIOS_XAI_FS_PACKAGE_QUARANTINED ||
        g_model_scrub.chunk_index >= package.chunk_count) {
      ++g_model_scrub.package_index;
      g_model_scrub.chunk_index = 0U;
      continue;
    }
    xaios_engine_status_t chunk_status = xaios_xai_fs_read_chunk(
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
    if ((chunk.flags & XAIOS_XAI_FS_CHUNK_COMPLETE) == 0U) {
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
  xaios_engine_status_t verified = xaios_xai_fs_verify_range(
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
    xaios_xai_fs_writer_t writer = {
        &g_model_vfs, vfs_xaifs_write_at, vfs_xaifs_flush};
    xaios_engine_status_t quarantined =
        xaios_xai_fs_quarantine_package(
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

xaios_status_t vfs_xaifs_scrub_status(xaios_model_scrub_status_t *status) {
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

xaios_status_t vfs_xaifs_scrub_pause(xaios_model_scrub_status_t *status) {
  return scrub_set_state(XAIOS_MODEL_MAINTENANCE_RUNNING,
                         XAIOS_MODEL_MAINTENANCE_PAUSED, status);
}

xaios_status_t vfs_xaifs_scrub_resume(xaios_model_scrub_status_t *status) {
  return scrub_set_state(XAIOS_MODEL_MAINTENANCE_PAUSED,
                         XAIOS_MODEL_MAINTENANCE_RUNNING, status);
}

xaios_status_t vfs_xaifs_scrub_cancel(xaios_model_scrub_status_t *status) {
  if (g_model_scrub.state == XAIOS_MODEL_MAINTENANCE_RUNNING) {
    return scrub_set_state(XAIOS_MODEL_MAINTENANCE_RUNNING,
                           XAIOS_MODEL_MAINTENANCE_CANCELLED, status);
  }
  return scrub_set_state(XAIOS_MODEL_MAINTENANCE_PAUSED,
                         XAIOS_MODEL_MAINTENANCE_CANCELLED, status);
}
