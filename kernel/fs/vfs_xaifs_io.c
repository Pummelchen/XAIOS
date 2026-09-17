/* The block and engine glue, and the read/write path, of the model VFS.
 *
 * Split out of vfs_xaifs.c so no source file exceeds 500 lines. What moves
 * here is everything that turns VFS operations into engine calls over the
 * block device: the reader and signature callbacks the engine is opened with,
 * the sector-aligned block writer and flush, engine-status mapping, the
 * verified read cache that serves whole chunks from RAM, and the handle
 * pread/pwrite/fsync/close operations. The mount, the catalog and the staging
 * lifecycle stay in vfs_xaifs.c and vfs_xaifs_catalog.c; the files share the
 * model context layout and the exported helpers through
 * vfs_xaifs_internal.h.
 *
 * The functions that receive the model context as a parameter keep doing so.
 * The model lock is taken and released exactly where it was; nothing about the
 * critical sections changes by moving them here.
 */

#include "vfs_xaifs_internal.h"

#include <xaios/klog.h>
#include <xaios/model_cache.h>

#include <string.h>

extern int xaios_ed25519_verify(const uint8_t signature[64],
                                const uint8_t *message,
                                uint32_t message_len,
                                const uint8_t public_key[32]);

xaios_engine_status_t vfs_xaifs_verify_signature(
    void *context, const uint8_t public_key[32], const uint8_t signature[64],
    const uint8_t message[32]) {
  (void)context;
  return xaios_ed25519_verify(signature, message, 32U, public_key) == 0
             ? XAIOS_ENGINE_OK
             : XAIOS_ENGINE_ERR_CHECKSUM;
}

xaios_engine_status_t vfs_xaifs_read_at(void *context, uint64_t offset,
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

xaios_engine_status_t vfs_xaifs_write_at(void *context, uint64_t offset,
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

xaios_engine_status_t vfs_xaifs_flush(void *context) {
  model_vfs_context_t *model = (model_vfs_context_t *)context;
  return block_flush(model->device) == XAIOS_OK ? XAIOS_ENGINE_OK
                                                 : XAIOS_ENGINE_ERR_IO;
}

xaios_status_t map_engine_status(xaios_engine_status_t status) {
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

static model_vfs_handle_t *model_find_handle(model_vfs_context_t *model,
                                              uint64_t handle) {
  if (handle == 0U || handle > MODEL_VFS_MAX_HANDLES) return 0;
  model_vfs_handle_t *opened = &model->handles[handle - 1U];
  return opened->active != 0U ? opened : 0;
}

static xaios_status_t model_sync_handle_locked(model_vfs_context_t *model,
                                                model_vfs_handle_t *opened) {
  xaios_xai_fs_writer_t writer = {
      model, vfs_xaifs_write_at, vfs_xaifs_flush};
  if (opened->written_start == UINT64_MAX) {
    return map_engine_status(vfs_xaifs_flush(model));
  }
  xaios_xai_fs_package_t package;
  xaios_engine_status_t engine_status = xaios_xai_fs_read_package(
      &model->volume, opened->package_index, &package);
  if (engine_status != XAIOS_ENGINE_OK) return map_engine_status(engine_status);
  uint64_t completed = 0U;
  engine_status = xaios_xai_fs_commit_staging_range(
      &model->volume, &package, &writer, opened->written_start,
      opened->written_end - opened->written_start, model->scratch,
      sizeof(model->scratch), &completed);
  if (engine_status != XAIOS_ENGINE_OK) return map_engine_status(engine_status);
  klog("xaifs: staging fsync record=%lu range=%lu:%lu completed=%lu generation=%lu\n",
       package.record_id, opened->written_start,
       opened->written_end - opened->written_start, completed,
       model->volume.generation);
  opened->written_start = UINT64_MAX;
  opened->written_end = 0U;
  return XAIOS_OK;
}

xaios_status_t vfs_xaifs_close(void *context, uint64_t handle) {
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

/* Read a package range, serving whole chunks out of RAM where they are held.
 *
 * The engine's verified read is the reference and does all the work that
 * matters: it hashes a chunk before it hands any of it over. What this adds is
 * the observation that a chunk which has already passed that test does not
 * need to pass it again while nothing has written to the volume -- so a chunk
 * read often enough is kept, and a hit is a copy rather than a read plus a
 * megabyte of SHA-256.
 *
 * The cache is consulted a chunk at a time because a chunk is what the
 * checksum covers. That also fixes the case the measurements were worst on: a
 * small window inside a large chunk used to hash the whole chunk to deliver a
 * fraction of it, and now pays that once and serves the neighbours from
 * memory.
 *
 * Only active packages. A staging package is being written and its chunks
 * change underneath; the cache refuses them rather than tracking mutations it
 * cannot see.
 *
 * Called with the model lock held, which is the only thing serialising the
 * cache. */
static xaios_engine_status_t model_pread_cached(
    model_vfs_context_t *model, const xaios_xai_fs_package_t *package,
    uint64_t offset, void *destination, size_t length,
    uint64_t *bad_logical_offset) {
  /* A new catalog moves chunks, so a key from the old one means nothing. */
  model_cache_invalidate(model->volume.generation);

  if (package->state != XAIOS_XAI_FS_PACKAGE_ACTIVE) {
    return xaios_xai_fs_pread_verified(&model->volume, package, offset,
                                       destination, length, model->scratch,
                                       sizeof(model->scratch),
                                       bad_logical_offset);
  }

  uint8_t *out = (uint8_t *)destination;
  uint64_t requested_end = offset + (uint64_t)length;
  uint64_t delivered = 0U;

  /* Which chunks the request touches, by arithmetic rather than by looking.
     A package's chunks tile its logical space in order and all but the last
     are exactly chunk_size, so the index is a division -- and walking the
     whole table instead was O(chunk_count) volume reads per request. That is
     invisible on a package with one chunk and ruinous on one with thirty-two
     thousand, which is what half a terabyte comes to. */
  if (package->chunk_size == 0U) return XAIOS_ENGINE_ERR_INVALID;
  uint64_t first = offset / package->chunk_size;
  uint64_t last = (requested_end - 1U) / package->chunk_size;
  if (first >= package->chunk_count) return XAIOS_ENGINE_ERR_INVALID;
  if (last >= package->chunk_count) last = package->chunk_count - 1U;

  for (uint64_t relative = first; relative <= last; ++relative) {
    uint64_t chunk_index = package->chunk_start + relative;
    xaios_xai_fs_chunk_t chunk;
    if (model->chunk_memo_valid != 0U &&
        model->chunk_memo_generation == model->volume.generation &&
        model->chunk_memo_index == chunk_index) {
      chunk = model->chunk_memo;
    } else if (xaios_xai_fs_read_chunk(&model->volume, chunk_index, &chunk) !=
               XAIOS_ENGINE_OK) {
      return XAIOS_ENGINE_ERR_INVALID;
    } else {
      model->chunk_memo = chunk;
      model->chunk_memo_index = chunk_index;
      model->chunk_memo_generation = model->volume.generation;
      model->chunk_memo_valid = 1U;
    }
    /* The arithmetic above assumed the tiling. Check it rather than trust it:
       a catalog that disagreed would otherwise serve one chunk's bytes as
       another's, which is precisely the quietly-wrong answer this path exists
       to prevent. */
    if (chunk.logical_offset != relative * package->chunk_size ||
        chunk.record_id != package->record_id ||
        (chunk.flags & XAIOS_XAI_FS_CHUNK_COMPLETE) == 0U) {
      return XAIOS_ENGINE_ERR_INVALID;
    }
    uint64_t chunk_end = chunk.logical_offset + chunk.length;
    if (chunk_end <= offset || chunk.logical_offset >= requested_end) continue;

    uint64_t slice_start = offset > chunk.logical_offset ? offset
                                                         : chunk.logical_offset;
    uint64_t slice_end = requested_end < chunk_end ? requested_end : chunk_end;
    uint64_t within = slice_start - chunk.logical_offset;
    uint64_t count = slice_end - slice_start;
    uint8_t *slice = out + (slice_start - offset);

    if (model_cache_read(chunk.physical_offset, within, slice, count) != 0) {
      delivered += count;
      continue;
    }

    /* Not held. If this chunk has been wanted often enough to earn the RAM,
       read all of it into the cache -- verified, because that is the only way
       it goes in -- and serve this slice out of what was read. */
    void *room = model_cache_reserve(chunk.physical_offset, chunk.length);
    if (room != 0) {
      uint64_t bad = UINT64_MAX;
      xaios_engine_status_t status = xaios_xai_fs_pread_verified(
          &model->volume, package, chunk.logical_offset, room,
          (size_t)chunk.length, model->scratch, sizeof(model->scratch), &bad);
      if (status != XAIOS_ENGINE_OK) {
        model_cache_abandon(chunk.physical_offset);
        *bad_logical_offset = bad;
        return status;
      }
      model_cache_commit(chunk.physical_offset);
      (void)model_cache_read(chunk.physical_offset, within, slice, count);
      delivered += count;
      continue;
    }

    xaios_engine_status_t status = xaios_xai_fs_pread_verified(
        &model->volume, package, slice_start, slice, (size_t)count,
        model->scratch, sizeof(model->scratch), bad_logical_offset);
    if (status != XAIOS_ENGINE_OK) return status;
    delivered += count;
  }
  /* The engine's read makes the same check, and for the same reason: a gap in
     the extent map would leave part of the buffer untouched, and handing that
     back is exactly the quietly-wrong result this path exists to prevent. */
  return delivered == (uint64_t)length ? XAIOS_ENGINE_OK
                                       : XAIOS_ENGINE_ERR_INVALID;
}

int64_t vfs_xaifs_pread(void *context, uint64_t handle, void *buffer,
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
  xaios_xai_fs_package_t package;
  xaios_engine_status_t engine_status = xaios_xai_fs_read_package(
      &model->volume, opened->package_index, &package);
  if (engine_status != XAIOS_ENGINE_OK ||
      package.state == XAIOS_XAI_FS_PACKAGE_QUARANTINED) {
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
  engine_status = model_pread_cached(model, &package, offset, buffer,
                                     (size_t)length, &bad_offset);
  xaios_spin_unlock(&model->lock);
  if (engine_status != XAIOS_ENGINE_OK) {
    klog("xaifs: package read rejected record=%lu offset=%lu bad=%lu status=%d\n",
         package.record_id, offset, bad_offset, (int)engine_status);
    return map_engine_status(engine_status);
  }
  return (int64_t)length;
}

int64_t vfs_xaifs_pwrite(void *context, uint64_t handle,
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
  xaios_xai_fs_package_t package;
  xaios_engine_status_t engine_status = xaios_xai_fs_read_package(
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
    xaios_xai_fs_writer_t writer = {
        model, vfs_xaifs_write_at, vfs_xaifs_flush};
    engine_status = xaios_xai_fs_pwrite_staging(
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
    klog("xaifs: staging pwrite rejected record=%lu offset=%lu length=%lu status=%d\n",
         package.record_id, offset, length, (int)engine_status);
  }
  xaios_spin_unlock(&model->lock);
  return engine_status == XAIOS_ENGINE_OK ? (int64_t)length
                                           : map_engine_status(engine_status);
}

xaios_status_t vfs_xaifs_fsync(void *context, uint64_t handle) {
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
