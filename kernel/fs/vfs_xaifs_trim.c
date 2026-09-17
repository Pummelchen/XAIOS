/* The trim job of the model VFS.
 *
 * Split out of vfs_xaifs.c so no source file exceeds 500 lines. What moves
 * here is the whole trim region: the persisted record, the free-extent
 * arithmetic, and the start/step/status/cancel entry points the control
 * protocol calls. The scrub job, the mount and the block/engine glue stay in
 * vfs_xaifs.c, and the two files share the model context layout and the
 * helpers through vfs_xaifs_internal.h.
 *
 * `g_model_trim' moves with this file; the shared model context does not, and
 * is reached through vfs_xaifs_model(). The alias below keeps the moved code
 * reading exactly as it did against the variable.
 */

#include "vfs_xaifs_internal.h"

#include <xaios/klog.h>
#include <xaios/xaiboot_fs.h>

#include <string.h>

#define MODEL_TRIM_MAGIC UINT32_C(0x58415452)
#define MODEL_TRIM_VERSION UINT32_C(1)
#define MODEL_TRIM_STATE_PATH "/state/modelfs-trim.bin"
#define MODEL_TRIM_STEP_LIMIT UINT64_C(67108864)

typedef struct model_trim_record {
  uint32_t magic;
  uint32_t version;
  uint32_t size;
  uint32_t reserved;
  xaios_model_trim_status_t status;
} model_trim_record_t;

static xaios_model_trim_status_t g_model_trim;
#define g_model_vfs (*vfs_xaifs_model())

static xaios_status_t trim_persist_locked(void) {
  model_trim_record_t record;
  memset(&record, 0, sizeof(record));
  record.magic = MODEL_TRIM_MAGIC;
  record.version = MODEL_TRIM_VERSION;
  record.size = sizeof(record);
  record.status = g_model_trim;
  return xaiboot_fs_write(MODEL_TRIM_STATE_PATH, &record, sizeof(record));
}

void vfs_xaifs_trim_load(void) {
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
  klog("xaifs: resumed trim chunk=%lu cursor=%lu processed=%lu eligible=%lu dry_run=%u\n",
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
    xaios_xai_fs_chunk_t chunk;
    xaios_engine_status_t engine_status = xaios_xai_fs_read_chunk(
        &g_model_vfs.volume, index, &chunk);
    if (engine_status != XAIOS_ENGINE_OK) {
      return map_engine_status(engine_status);
    }
    if ((chunk.flags & XAIOS_XAI_FS_CHUNK_FREE) == 0U) {
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

xaios_status_t vfs_xaifs_trim_start(uint32_t dry_run, uint32_t all_free,
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

xaios_status_t vfs_xaifs_trim_step(xaios_model_trim_status_t *status) {
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

xaios_status_t vfs_xaifs_trim_status(xaios_model_trim_status_t *status) {
  if (status == 0 || g_model_vfs.mounted == 0U) return XAIOS_ERR_INVALID;
  xaios_spin_lock(&g_model_vfs.lock);
  *status = g_model_trim;
  xaios_spin_unlock(&g_model_vfs.lock);
  return XAIOS_OK;
}

xaios_status_t vfs_xaifs_trim_cancel(xaios_model_trim_status_t *status) {
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

/* The scrub half of vfs_xaifs.c asks whether a trim is in flight: scrub and
   trim exclude each other, so this value is read while holding the model
   lock. The state is copied out rather than the variable exported. */
uint32_t vfs_xaifs_trim_state(void) { return g_model_trim.state; }
