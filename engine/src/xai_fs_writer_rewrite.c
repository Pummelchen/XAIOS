/* Catalog rewrite paths: package removal and staging commit rebuild the
 * catalog. Split from `xai_fs_writer.c`; see `xai_fs_writer_parts.h`. */

#include <xaios_engine/xai_fs.h>
#include <string.h>
#include "sha256.h"
#include "xai_fs_writer_internal.h"
#include "xai_fs_writer_parts.h"

xaios_engine_status_t xai_fs_writer_remove_package_in_state(
    xaios_xai_fs_t *volume,
    const xaios_xai_fs_package_t *package,
    const xaios_xai_fs_writer_t *writer, void *scratch,
    size_t scratch_size, uint32_t required_state,
    uint64_t *reclaimed_bytes) {
  if (reclaimed_bytes != NULL) *reclaimed_bytes = 0U;
  if (volume == NULL || package == NULL || writer == NULL ||
      writer->write_at == NULL || writer->flush == NULL || scratch == NULL ||
      scratch_size < XAI_FS_WRITER_SCRATCH_MIN ||
      package->state != required_state ||
      volume->package_count == 0U || volume->generation == UINT64_MAX ||
      volume->catalog_generation == UINT64_MAX) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  uint64_t target_index = UINT64_MAX;
  xaios_xai_fs_package_t target;
  memset(&target, 0, sizeof(target));
  for (uint64_t index = 0U; index < volume->package_count; ++index) {
    xaios_xai_fs_package_t current;
    xaios_engine_status_t status =
        xaios_xai_fs_read_package(volume, index, &current);
    if (status != XAIOS_ENGINE_OK) return status;
    if (current.record_id == package->record_id) {
      if (current.state != required_state ||
          memcmp(current.package_id, package->package_id, 32U) != 0) {
        return XAIOS_ENGINE_ERR_CAPABILITY;
      }
      target_index = index;
      target = current;
    }
  }
  if (target_index == UINT64_MAX) return XAIOS_ENGINE_ERR_INVALID;

  uint64_t free_runs = 0U;
  uint64_t reclaimed = 0U;
  uint64_t run_end = 0U;
  int run_active = 0;
  for (uint64_t relative = 0U; relative < target.chunk_count; ++relative) {
    xaios_xai_fs_chunk_t chunk;
    xaios_engine_status_t status = xaios_xai_fs_read_chunk(
        volume, target.chunk_start + relative, &chunk);
    if (status != XAIOS_ENGINE_OK) return status;
    if (chunk.extent_length == 0U) continue;
    if (chunk.extent_length > UINT64_MAX - reclaimed) {
      return XAIOS_ENGINE_ERR_OVERFLOW;
    }
    reclaimed += chunk.extent_length;
    if (!run_active || chunk.physical_offset != run_end) {
      if (free_runs == UINT64_MAX) return XAIOS_ENGINE_ERR_OVERFLOW;
      ++free_runs;
    }
    if (checked_add(chunk.physical_offset, chunk.extent_length, &run_end) !=
        XAIOS_ENGINE_OK) {
      return XAIOS_ENGINE_ERR_OVERFLOW;
    }
    run_active = 1;
  }

  if (volume->free_extent_count > volume->chunk_count ||
      target.chunk_count > volume->chunk_count - volume->free_extent_count) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  uint64_t new_free_count = 0U;
  uint64_t retained_owned =
      volume->chunk_count - volume->free_extent_count - target.chunk_count;
  uint64_t new_chunk_count = 0U;
  if (checked_add(volume->free_extent_count, free_runs, &new_free_count) !=
          XAIOS_ENGINE_OK ||
      checked_add(new_free_count, retained_owned, &new_chunk_count) !=
          XAIOS_ENGINE_OK) {
    return XAIOS_ENGINE_ERR_OVERFLOW;
  }
  uint64_t new_package_count = volume->package_count - 1U;
  uint64_t package_bytes = 0U;
  uint64_t chunk_bytes = 0U;
  uint64_t catalog_length = 0U;
  if (checked_multiply(new_package_count,
                       XAIOS_XAI_FS_PACKAGE_RECORD_SIZE,
                       &package_bytes) != XAIOS_ENGINE_OK ||
      checked_multiply(new_chunk_count, XAIOS_XAI_FS_CHUNK_RECORD_SIZE,
                       &chunk_bytes) != XAIOS_ENGINE_OK ||
      checked_add(XAIOS_XAI_FS_CATALOG_HEADER_SIZE, package_bytes,
                  &catalog_length) != XAIOS_ENGINE_OK ||
      checked_add(catalog_length, chunk_bytes, &catalog_length) !=
          XAIOS_ENGINE_OK) {
    return XAIOS_ENGINE_ERR_OVERFLOW;
  }
  uint64_t catalog_offset = 0U;
  uint64_t final_tail = 0U;
  uint64_t data_floor = 0U;
  if (xai_fs_writer_data_high_water(volume, &data_floor) != XAIOS_ENGINE_OK ||
      xai_fs_writer_choose_catalog_slot(volume, data_floor, catalog_length, &catalog_offset,
                          &final_tail) != XAIOS_ENGINE_OK) {
    return XAIOS_ENGINE_ERR_CAPABILITY;
  }

  xaios_xai_fs_t next = *volume;
  next.generation = volume->generation + 1U;
  next.catalog_generation = volume->catalog_generation + 1U;
  next.catalog_offset = catalog_offset;
  next.catalog_length = catalog_length;
  next.data_tail = final_tail;
  next.package_count = new_package_count;
  next.chunk_count = new_chunk_count;
  next.package_offset = XAIOS_XAI_FS_CATALOG_HEADER_SIZE;
  next.chunk_offset = XAIOS_XAI_FS_CATALOG_HEADER_SIZE + package_bytes;
  next.free_extent_count = new_free_count;

  uint8_t header[256];
  xai_fs_writer_encode_catalog_header(&next, next.catalog_generation, final_tail, header);
  xaios_engine_sha256_context_t catalog_sha;
  xaios_engine_sha256_init(&catalog_sha);
  xaios_engine_status_t status =
      write_exact(writer, catalog_offset, header, sizeof(header));
  if (status != XAIOS_ENGINE_OK) return status;
  xaios_engine_sha256_update(&catalog_sha, header, sizeof(header));

  uint8_t raw_package[384];
  uint64_t package_destination = catalog_offset + next.package_offset;
  uint64_t written_packages = 0U;
  uint64_t owned_cursor = new_free_count;
  for (uint64_t index = 0U; index < volume->package_count; ++index) {
    if (index == target_index) continue;
    xaios_xai_fs_package_t current;
    status = xaios_xai_fs_read_package(volume, index, &current);
    if (status != XAIOS_ENGINE_OK) return status;
    current.chunk_start = owned_cursor;
    if (checked_add(owned_cursor, current.chunk_count, &owned_cursor) !=
        XAIOS_ENGINE_OK) {
      return XAIOS_ENGINE_ERR_OVERFLOW;
    }
    encode_package_record(&current, raw_package);
    status = write_exact(
        writer, package_destination + written_packages * sizeof(raw_package),
        raw_package, sizeof(raw_package));
    if (status != XAIOS_ENGINE_OK) return status;
    xaios_engine_sha256_update(&catalog_sha, raw_package, sizeof(raw_package));
    ++written_packages;
  }
  if (written_packages != new_package_count) return XAIOS_ENGINE_ERR_INVALID;

  uint8_t raw_chunk[128];
  uint64_t chunk_destination = catalog_offset + next.chunk_offset;
  uint64_t written_chunks = 0U;
  for (uint64_t index = 0U; index < volume->chunk_count; ++index) {
    xaios_xai_fs_chunk_t current;
    status = xaios_xai_fs_read_chunk(volume, index, &current);
    if (status != XAIOS_ENGINE_OK) return status;
    if ((current.flags & XAIOS_XAI_FS_CHUNK_FREE) == 0U) continue;
    encode_chunk_record(&current, raw_chunk);
    status = write_exact(writer,
                         chunk_destination + written_chunks * sizeof(raw_chunk),
                         raw_chunk, sizeof(raw_chunk));
    if (status != XAIOS_ENGINE_OK) return status;
    xaios_engine_sha256_update(&catalog_sha, raw_chunk, sizeof(raw_chunk));
    ++written_chunks;
  }

  uint64_t run_start = 0U;
  uint64_t run_length = 0U;
  for (uint64_t relative = 0U; relative <= target.chunk_count; ++relative) {
    xaios_xai_fs_chunk_t current;
    memset(&current, 0, sizeof(current));
    if (relative < target.chunk_count) {
      status = xaios_xai_fs_read_chunk(
          volume, target.chunk_start + relative, &current);
      if (status != XAIOS_ENGINE_OK) return status;
    }
    if (current.extent_length != 0U &&
        (run_length == 0U || current.physical_offset == run_start + run_length)) {
      if (run_length == 0U) run_start = current.physical_offset;
      if (current.extent_length > UINT64_MAX - run_length) {
        return XAIOS_ENGINE_ERR_OVERFLOW;
      }
      run_length += current.extent_length;
      continue;
    }
    if (run_length != 0U) {
      xaios_xai_fs_chunk_t free_chunk;
      memset(&free_chunk, 0, sizeof(free_chunk));
      free_chunk.physical_offset = run_start;
      free_chunk.length = run_length;
      free_chunk.extent_length = run_length;
      free_chunk.flags = XAIOS_XAI_FS_CHUNK_COMPLETE |
                         XAIOS_XAI_FS_CHUNK_FREE;
      encode_chunk_record(&free_chunk, raw_chunk);
      status = write_exact(
          writer, chunk_destination + written_chunks * sizeof(raw_chunk),
          raw_chunk, sizeof(raw_chunk));
      if (status != XAIOS_ENGINE_OK) return status;
      xaios_engine_sha256_update(&catalog_sha, raw_chunk, sizeof(raw_chunk));
      ++written_chunks;
      run_length = 0U;
    }
    if (current.extent_length != 0U) {
      run_start = current.physical_offset;
      run_length = current.extent_length;
    }
  }

  for (uint64_t package_index = 0U;
       package_index < volume->package_count; ++package_index) {
    if (package_index == target_index) continue;
    xaios_xai_fs_package_t current_package;
    status = xaios_xai_fs_read_package(volume, package_index,
                                             &current_package);
    if (status != XAIOS_ENGINE_OK) return status;
    for (uint64_t relative = 0U; relative < current_package.chunk_count;
         ++relative) {
      xaios_xai_fs_chunk_t current;
      status = xaios_xai_fs_read_chunk(
          volume, current_package.chunk_start + relative, &current);
      if (status != XAIOS_ENGINE_OK ||
          (current.flags & XAIOS_XAI_FS_CHUNK_FREE) != 0U) {
        return status == XAIOS_ENGINE_OK ? XAIOS_ENGINE_ERR_INVALID : status;
      }
      encode_chunk_record(&current, raw_chunk);
      status = write_exact(
          writer, chunk_destination + written_chunks * sizeof(raw_chunk),
          raw_chunk, sizeof(raw_chunk));
      if (status != XAIOS_ENGINE_OK) return status;
      xaios_engine_sha256_update(&catalog_sha, raw_chunk, sizeof(raw_chunk));
      ++written_chunks;
    }
  }
  if (written_chunks != new_chunk_count) return XAIOS_ENGINE_ERR_INVALID;

  uint8_t catalog_hash[32];
  xaios_engine_sha256_final(&catalog_sha, catalog_hash);
  status = writer->flush(writer->context);
  if (status != XAIOS_ENGINE_OK) return status;
  uint8_t *superblock = (uint8_t *)scratch;
  xai_fs_writer_encode_superblock(&next, next.generation, next.catalog_offset,
                    next.catalog_generation, next.data_tail, catalog_hash,
                    superblock);
  uint32_t next_slot = 1U - volume->selected_superblock;
  status = write_exact(writer,
                       (uint64_t)next_slot *
                           XAIOS_XAI_FS_SUPERBLOCK_SIZE,
                       superblock, 4096U);
  if (status != XAIOS_ENGINE_OK) return status;
  status = writer->flush(writer->context);
  if (status != XAIOS_ENGINE_OK) return status;
  next.selected_superblock = next_slot;
  memcpy(next.catalog_hash, catalog_hash, sizeof(catalog_hash));
  *volume = next;
  if (reclaimed_bytes != NULL) *reclaimed_bytes = reclaimed;
  return XAIOS_ENGINE_OK;
}

/* What one commit learned about a chunk, so it does not have to learn it
   twice.
   
   A commit walks the chunk table once to find out whether anything is ready
   -- there is no point writing a new catalog otherwise -- and then again to
   write it. Both walks asked the same question of the same chunks, and the
   question costs a full read of the chunk off the volume and a SHA-256 over
   it. For a two mebibyte chunk that was four mebibytes of reading and hashing
   per commit where two would do.
   
   The window a single fsync covers is one dirty range, which in practice is
   the one chunk that was just written. Sixteen entries is far more than that
   and still small enough to sit on the stack. A range wider than the memo
   falls back to asking again, which is slower and correct, rather than
   wrong. */
#define COMMIT_MEMO_ENTRIES 16U

typedef struct commit_memo_entry {
  uint64_t chunk_index;
  uint8_t learned_checksum[32];
  uint8_t should_complete;
  uint8_t valid;
} commit_memo_entry_t;

typedef struct commit_memo {
  commit_memo_entry_t entries[COMMIT_MEMO_ENTRIES];
  uint32_t used;
} commit_memo_t;

static void commit_memo_record(commit_memo_t *memo, uint64_t chunk_index,
                               int should_complete,
                               const uint8_t learned_checksum[32]) {
  if (memo->used >= COMMIT_MEMO_ENTRIES) return;
  commit_memo_entry_t *entry = &memo->entries[memo->used++];
  entry->chunk_index = chunk_index;
  entry->should_complete = should_complete != 0 ? 1U : 0U;
  entry->valid = 1U;
  memcpy(entry->learned_checksum, learned_checksum, 32U);
}

static int commit_memo_lookup(const commit_memo_t *memo, uint64_t chunk_index,
                              int *should_complete,
                              uint8_t learned_checksum[32]) {
  for (uint32_t index = 0U; index < memo->used; ++index) {
    const commit_memo_entry_t *entry = &memo->entries[index];
    if (entry->valid != 0U && entry->chunk_index == chunk_index) {
      *should_complete = entry->should_complete != 0U ? 1 : 0;
      memcpy(learned_checksum, entry->learned_checksum, 32U);
      return 1;
    }
  }
  return 0;
}

xaios_engine_status_t xaios_xai_fs_commit_staging_range(
    xaios_xai_fs_t *volume,
    const xaios_xai_fs_package_t *package,
    const xaios_xai_fs_writer_t *writer, uint64_t offset,
    uint64_t length, void *scratch, size_t scratch_size,
    uint64_t *completed_chunks) {
  uint64_t end = 0U;
  if (completed_chunks != NULL) *completed_chunks = 0U;
  if (volume == NULL || package == NULL || writer == NULL ||
      writer->write_at == NULL || writer->flush == NULL || scratch == NULL ||
      scratch_size < XAI_FS_WRITER_SCRATCH_MIN || length == 0U ||
      package->state != XAIOS_XAI_FS_PACKAGE_STAGING ||
      checked_add(offset, length, &end) != XAIOS_ENGINE_OK ||
      end > package->logical_size) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  /* The data before the catalog that will vouch for it, and before the
     superblock that publishes the catalog. The flush lower down, between the
     catalog and the superblock, separates data from superblock too, so on a
     device that loses only unflushed writes either one alone is enough --
     qemu-power-loss-gate passes with either deleted and fails with both, and
     that is the whole of what was measured. Keep both anyway: the redundancy
     is a fact about today's write order rather than a property anyone
     designed, and it costs one flush per commit to not depend on it. */
  xaios_engine_status_t status = writer->flush(writer->context);
  if (status != XAIOS_ENGINE_OK) return status;
  uint8_t *io_scratch = (uint8_t *)scratch + 4096U;
  size_t io_scratch_size = scratch_size - 4096U;
  uint64_t ready = 0U;
  commit_memo_t memo;
  memset(&memo, 0, sizeof(memo));
  for (uint64_t relative = 0U; relative < package->chunk_count; ++relative) {
    uint64_t chunk_index = package->chunk_start + relative;
    xaios_xai_fs_chunk_t chunk;
    status = xaios_xai_fs_read_chunk(volume, chunk_index, &chunk);
    if (status != XAIOS_ENGINE_OK) return status;
    int should_complete = 0;
    uint8_t learned_checksum[32];
    status = chunk_completion_status(volume, package, &chunk, offset, length,
                                     io_scratch, io_scratch_size,
                                     &should_complete, learned_checksum);
    if (status != XAIOS_ENGINE_OK) return status;
    /* Only chunks the range touched cost anything to decide, and only those
       are worth remembering; the rest answered from their flags alone. */
    if (ranges_intersect(chunk.logical_offset, chunk.length, offset, length)) {
      commit_memo_record(&memo, chunk_index, should_complete,
                         learned_checksum);
    }
    if (should_complete) {
      ++ready;
    }
  }
  if (ready == 0U) return XAIOS_ENGINE_OK;

  uint64_t catalog_offset = 0U;
  uint64_t final_tail = 0U;
  uint64_t data_floor = 0U;
  if (xai_fs_writer_data_high_water(volume, &data_floor) != XAIOS_ENGINE_OK ||
      xai_fs_writer_choose_catalog_slot(volume, data_floor, volume->catalog_length,
                          &catalog_offset, &final_tail) != XAIOS_ENGINE_OK) {
    return XAIOS_ENGINE_ERR_CAPABILITY;
  }

  uint64_t catalog_generation = volume->catalog_generation + 1U;
  uint64_t generation = volume->generation + 1U;
  if (catalog_generation == 0U || generation == 0U) {
    return XAIOS_ENGINE_ERR_OVERFLOW;
  }
  uint8_t header[256];
  xai_fs_writer_encode_catalog_header(volume, catalog_generation, final_tail, header);
  xaios_engine_sha256_context_t catalog_sha;
  xaios_engine_sha256_init(&catalog_sha);
  status = write_exact(writer, catalog_offset, header, sizeof(header));
  if (status != XAIOS_ENGINE_OK) return status;
  xaios_engine_sha256_update(&catalog_sha, header, sizeof(header));

  uint8_t package_raw[384];
  uint64_t source_package_base = 0U;
  uint64_t destination_package_base = 0U;
  if (checked_add(volume->catalog_offset, volume->package_offset,
                  &source_package_base) != XAIOS_ENGINE_OK ||
      checked_add(catalog_offset, volume->package_offset,
                  &destination_package_base) != XAIOS_ENGINE_OK) {
    return XAIOS_ENGINE_ERR_OVERFLOW;
  }
  for (uint64_t index = 0U; index < volume->package_count; ++index) {
    uint64_t relative = 0U;
    uint64_t source = 0U;
    uint64_t destination = 0U;
    if (checked_multiply(index, sizeof(package_raw), &relative) !=
            XAIOS_ENGINE_OK ||
        checked_add(source_package_base, relative, &source) !=
            XAIOS_ENGINE_OK ||
        checked_add(destination_package_base, relative, &destination) !=
            XAIOS_ENGINE_OK) {
      return XAIOS_ENGINE_ERR_OVERFLOW;
    }
    status = read_exact(volume, source, package_raw, sizeof(package_raw));
    if (status != XAIOS_ENGINE_OK) return status;
    status = write_exact(writer, destination, package_raw, sizeof(package_raw));
    if (status != XAIOS_ENGINE_OK) return status;
    xaios_engine_sha256_update(&catalog_sha, package_raw, sizeof(package_raw));
  }

  uint8_t chunk_raw[128];
  uint64_t source_chunk_base = 0U;
  uint64_t destination_chunk_base = 0U;
  if (checked_add(volume->catalog_offset, volume->chunk_offset,
                  &source_chunk_base) != XAIOS_ENGINE_OK ||
      checked_add(catalog_offset, volume->chunk_offset,
                  &destination_chunk_base) != XAIOS_ENGINE_OK) {
    return XAIOS_ENGINE_ERR_OVERFLOW;
  }
  for (uint64_t index = 0U; index < volume->chunk_count; ++index) {
    uint64_t relative = 0U;
    uint64_t source = 0U;
    uint64_t destination = 0U;
    if (checked_multiply(index, sizeof(chunk_raw), &relative) !=
            XAIOS_ENGINE_OK ||
        checked_add(source_chunk_base, relative, &source) !=
            XAIOS_ENGINE_OK ||
        checked_add(destination_chunk_base, relative, &destination) !=
            XAIOS_ENGINE_OK) {
      return XAIOS_ENGINE_ERR_OVERFLOW;
    }
    status = read_exact(volume, source, chunk_raw, sizeof(chunk_raw));
    if (status != XAIOS_ENGINE_OK) return status;
    xaios_xai_fs_chunk_t chunk;
    status = xaios_xai_fs_read_chunk(volume, index, &chunk);
    if (status != XAIOS_ENGINE_OK) return status;
    int should_complete = 0;
    uint8_t learned_checksum[32];
    if (!commit_memo_lookup(&memo, index, &should_complete,
                            learned_checksum)) {
      status = chunk_completion_status(volume, package, &chunk, offset, length,
                                       io_scratch, io_scratch_size,
                                       &should_complete, learned_checksum);
      if (status != XAIOS_ENGINE_OK) return status;
    }
    if (should_complete) {
      uint32_t learned =
          chunk.flags & XAIOS_XAI_FS_CHUNK_HASH_PENDING;
      chunk.flags |= XAIOS_XAI_FS_CHUNK_COMPLETE;
      chunk.flags &= ~XAIOS_XAI_FS_CHUNK_HASH_PENDING;
      store_le32(chunk_raw + 32U, chunk.flags);
      if (learned != 0U) {
        memcpy(chunk_raw + 40U, learned_checksum, 32U);
      }
    }
    status = write_exact(writer, destination, chunk_raw, sizeof(chunk_raw));
    if (status != XAIOS_ENGINE_OK) return status;
    xaios_engine_sha256_update(&catalog_sha, chunk_raw, sizeof(chunk_raw));
  }
  uint8_t catalog_hash[32];
  xaios_engine_sha256_final(&catalog_sha, catalog_hash);
  /* Before the superblock, not after. A device with a volatile write cache is
     free to persist these in any order, and publishing a superblock that
     points at a catalog the device has not written yet is exactly the failure
     the A/B scheme cannot recover from. qemu-write-ordering-gate checks that
     this flush is actually issued; removing it makes that gate fail on every
     commit, which is how it was verified to be capable of failing. */
  status = writer->flush(writer->context);
  if (status != XAIOS_ENGINE_OK) return status;

  uint8_t *superblock = (uint8_t *)scratch;
  xai_fs_writer_encode_superblock(volume, generation, catalog_offset, catalog_generation,
                    final_tail, catalog_hash, superblock);
  uint32_t next_slot = 1U - volume->selected_superblock;
  status = write_exact(writer,
                       (uint64_t)next_slot *
                           XAIOS_XAI_FS_SUPERBLOCK_SIZE,
                       superblock, 4096U);
  if (status != XAIOS_ENGINE_OK) return status;
  status = writer->flush(writer->context);
  if (status != XAIOS_ENGINE_OK) return status;

  volume->generation = generation;
  volume->catalog_generation = catalog_generation;
  volume->catalog_offset = catalog_offset;
  volume->data_tail = final_tail;
  volume->selected_superblock = next_slot;
  memcpy(volume->catalog_hash, catalog_hash, sizeof(catalog_hash));
  if (completed_chunks != NULL) *completed_chunks = ready;
  return XAIOS_ENGINE_OK;
}
