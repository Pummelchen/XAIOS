/* The xaiFS writer's staging path: write package data into a staging
 * package's extents, register the staging package in a fresh catalog, and
 * activate it once every chunk verifies. Split from `xai_fs_writer.c`
 * unchanged; the catalog/superblock encoders it calls stay there and
 * `xai_fs_writer_parts.h` declares them.
 */

#include <xaios_engine/xai_fs.h>

#include <string.h>

#include "sha256.h"
#include "xai_fs_writer_internal.h"
#include "xai_fs_writer_parts.h"

xaios_engine_status_t xaios_xai_fs_pwrite_staging(
    const xaios_xai_fs_t *volume,
    const xaios_xai_fs_package_t *package,
    const xaios_xai_fs_writer_t *writer, uint64_t offset,
    const void *source, size_t length) {
  uint64_t end = 0U;
  if (volume == NULL || package == NULL || writer == NULL ||
      writer->write_at == NULL || source == NULL || length == 0U ||
      package->state != XAIOS_XAI_FS_PACKAGE_STAGING ||
      checked_add(offset, (uint64_t)length, &end) != XAIOS_ENGINE_OK ||
      end > package->logical_size) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  const uint8_t *input = (const uint8_t *)source;
  uint64_t cursor = offset;
  uint64_t remaining = (uint64_t)length;
  for (uint64_t relative = 0U;
       relative < package->chunk_count && remaining != 0U; ++relative) {
    xaios_xai_fs_chunk_t chunk;
    xaios_engine_status_t status = xaios_xai_fs_read_chunk(
        volume, package->chunk_start + relative, &chunk);
    if (status != XAIOS_ENGINE_OK) return status;
    uint64_t chunk_end = 0U;
    if (checked_add(chunk.logical_offset, chunk.length, &chunk_end) !=
        XAIOS_ENGINE_OK) {
      return XAIOS_ENGINE_ERR_OVERFLOW;
    }
    if (cursor >= chunk_end) continue;
    if (cursor < chunk.logical_offset || chunk.record_id != package->record_id ||
        (chunk.flags & (XAIOS_XAI_FS_CHUNK_COMPLETE |
                        XAIOS_XAI_FS_CHUNK_ZERO |
                        XAIOS_XAI_FS_CHUNK_FREE)) != 0U) {
      return XAIOS_ENGINE_ERR_CAPABILITY;
    }
    uint64_t within = cursor - chunk.logical_offset;
    uint64_t count = chunk.length - within;
    if (count > remaining) count = remaining;
    status = write_exact(writer, chunk.physical_offset + within, input,
                         (size_t)count);
    if (status != XAIOS_ENGINE_OK) return status;
    cursor += count;
    input += count;
    remaining -= count;
  }
  return remaining == 0U ? XAIOS_ENGINE_OK : XAIOS_ENGINE_ERR_INVALID;
}

xaios_engine_status_t xaios_xai_fs_register_staging(
    xaios_xai_fs_t *volume,
    const xaios_xai_fs_package_t *package_template,
    const xaios_xai_fs_writer_t *writer, void *scratch,
    size_t scratch_size, xaios_xai_fs_package_t *registered_package) {
  if (volume == NULL || package_template == NULL || writer == NULL ||
      writer->write_at == NULL || writer->flush == NULL || scratch == NULL ||
      scratch_size < XAI_FS_WRITER_SCRATCH_MIN ||
      registered_package == NULL ||
      !bytes_nonzero(package_template->model_uuid, 16U) ||
      !bytes_nonzero(package_template->package_id, 32U) ||
      !bytes_nonzero(package_template->signer_public_key, 32U) ||
      !bytes_nonzero(package_template->signature, 64U) ||
      !bytes_nonzero(package_template->source_revision, 32U) ||
      package_template->logical_size == 0U ||
      (package_template->chunk_size != 0U &&
       package_template->chunk_size != volume->chunk_size) ||
      !valid_ascii(package_template->architecture_id) ||
      !valid_target(package_template->target_id)) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  if (volume->package_count == UINT64_MAX || volume->chunk_count == UINT64_MAX ||
      volume->generation == UINT64_MAX ||
      volume->catalog_generation == UINT64_MAX) {
    return XAIOS_ENGINE_ERR_OVERFLOW;
  }

  uint64_t record_id = 1U;
  for (uint64_t index = 0U; index < volume->package_count; ++index) {
    xaios_xai_fs_package_t current;
    xaios_engine_status_t status =
        xaios_xai_fs_read_package(volume, index, &current);
    if (status != XAIOS_ENGINE_OK) return status;
    if (memcmp(current.package_id, package_template->package_id, 32U) == 0) {
      return XAIOS_ENGINE_ERR_CAPABILITY;
    }
    if (current.record_id >= record_id) {
      if (current.record_id == UINT64_MAX) return XAIOS_ENGINE_ERR_OVERFLOW;
      record_id = current.record_id + 1U;
    }
  }

  uint64_t added_chunks = package_template->logical_size / volume->chunk_size;
  if (package_template->logical_size % volume->chunk_size != 0U) {
    if (added_chunks == UINT64_MAX) return XAIOS_ENGINE_ERR_OVERFLOW;
    ++added_chunks;
  }
  uint64_t required_data_bytes = 0U;
  if (align_up(package_template->logical_size, XAI_FS_BLOCK_SIZE,
               &required_data_bytes) != XAIOS_ENGINE_OK) {
    return XAIOS_ENGINE_ERR_OVERFLOW;
  }
  uint64_t selected_free_index = UINT64_MAX;
  xaios_xai_fs_chunk_t selected_free;
  memset(&selected_free, 0, sizeof(selected_free));
  for (uint64_t index = 0U; index < volume->chunk_count; ++index) {
    xaios_xai_fs_chunk_t current;
    xaios_engine_status_t status =
        xaios_xai_fs_read_chunk(volume, index, &current);
    if (status != XAIOS_ENGINE_OK) return status;
    if ((current.flags & XAIOS_XAI_FS_CHUNK_FREE) != 0U &&
        current.extent_length >= required_data_bytes) {
      selected_free_index = index;
      selected_free = current;
      break;
    }
  }

  uint64_t new_package_count = volume->package_count + 1U;
  uint64_t new_free_count = volume->free_extent_count;
  if (selected_free_index != UINT64_MAX &&
      selected_free.extent_length == required_data_bytes) {
    if (new_free_count == 0U) return XAIOS_ENGINE_ERR_INVALID;
    --new_free_count;
  }
  uint64_t owned_chunk_count = 0U;
  uint64_t new_chunk_count = 0U;
  uint64_t package_bytes = 0U;
  uint64_t chunk_bytes = 0U;
  uint64_t catalog_length = 0U;
  if (volume->free_extent_count > volume->chunk_count ||
      checked_add(volume->chunk_count - volume->free_extent_count,
                  added_chunks, &owned_chunk_count) != XAIOS_ENGINE_OK ||
      checked_add(new_free_count, owned_chunk_count, &new_chunk_count) !=
          XAIOS_ENGINE_OK ||
      checked_multiply(new_package_count, XAIOS_XAI_FS_PACKAGE_RECORD_SIZE,
                       &package_bytes) != XAIOS_ENGINE_OK ||
      checked_multiply(new_chunk_count, XAIOS_XAI_FS_CHUNK_RECORD_SIZE,
                       &chunk_bytes) != XAIOS_ENGINE_OK ||
      checked_add(XAIOS_XAI_FS_CATALOG_HEADER_SIZE, package_bytes,
                  &catalog_length) != XAIOS_ENGINE_OK ||
      checked_add(catalog_length, chunk_bytes, &catalog_length) !=
          XAIOS_ENGINE_OK) {
    return XAIOS_ENGINE_ERR_OVERFLOW;
  }

  uint64_t package_data_offset = selected_free.physical_offset;
  uint64_t data_end = volume->data_tail;
  if (selected_free_index == UINT64_MAX) {
    if (align_up(volume->data_tail, volume->chunk_size,
                 &package_data_offset) != XAIOS_ENGINE_OK ||
        checked_add(package_data_offset, required_data_bytes, &data_end) !=
            XAIOS_ENGINE_OK) {
      return XAIOS_ENGINE_ERR_OVERFLOW;
    }
  }
  uint64_t catalog_offset = 0U;
  uint64_t final_tail = 0U;
  uint64_t existing_high_water = 0U;
  if (xai_fs_writer_data_high_water(volume, &existing_high_water) != XAIOS_ENGINE_OK) {
    return XAIOS_ENGINE_ERR_OVERFLOW;
  }
  /* This call may be extending the data itself, so the floor is whichever is
     higher: what the volume already holds, or what this staging just took. */
  uint64_t data_floor =
      data_end > existing_high_water ? data_end : existing_high_water;
  if (xai_fs_writer_choose_catalog_slot(volume, data_floor, catalog_length, &catalog_offset,
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
  next.free_extent_count = new_free_count;
  next.package_offset = XAIOS_XAI_FS_CATALOG_HEADER_SIZE;
  next.chunk_offset = XAIOS_XAI_FS_CATALOG_HEADER_SIZE + package_bytes;

  uint8_t header[256];
  xai_fs_writer_encode_catalog_header(&next, next.catalog_generation, final_tail, header);
  xaios_engine_sha256_context_t catalog_sha;
  xaios_engine_sha256_init(&catalog_sha);
  xaios_engine_status_t status =
      write_exact(writer, catalog_offset, header, sizeof(header));
  if (status != XAIOS_ENGINE_OK) return status;
  xaios_engine_sha256_update(&catalog_sha, header, sizeof(header));

  uint8_t raw_package[384];
  uint64_t destination = catalog_offset + next.package_offset;
  uint64_t owned_cursor = new_free_count;
  for (uint64_t index = 0U; index < volume->package_count; ++index) {
    xaios_xai_fs_package_t current;
    status = xaios_xai_fs_read_package(volume, index, &current);
    if (status != XAIOS_ENGINE_OK) return status;
    current.chunk_start = owned_cursor;
    if (checked_add(owned_cursor, current.chunk_count, &owned_cursor) !=
        XAIOS_ENGINE_OK) {
      return XAIOS_ENGINE_ERR_OVERFLOW;
    }
    encode_package_record(&current, raw_package);
    status = write_exact(writer, destination + index * sizeof(raw_package),
                         raw_package, sizeof(raw_package));
    if (status != XAIOS_ENGINE_OK) return status;
    xaios_engine_sha256_update(&catalog_sha, raw_package, sizeof(raw_package));
  }

  xaios_xai_fs_package_t package = *package_template;
  package.state = XAIOS_XAI_FS_PACKAGE_STAGING;
  package.record_id = record_id;
  package.chunk_size = volume->chunk_size;
  package.chunk_start = owned_cursor;
  package.chunk_count = added_chunks;
  encode_package_record(&package, raw_package);
  status = write_exact(writer,
                       destination + volume->package_count * sizeof(raw_package),
                       raw_package, sizeof(raw_package));
  if (status != XAIOS_ENGINE_OK) return status;
  xaios_engine_sha256_update(&catalog_sha, raw_package, sizeof(raw_package));

  uint8_t raw_chunk[128];
  destination = catalog_offset + next.chunk_offset;
  uint64_t written_chunks = 0U;
  for (uint64_t index = 0U; index < volume->chunk_count; ++index) {
    xaios_xai_fs_chunk_t current;
    status = xaios_xai_fs_read_chunk(volume, index, &current);
    if (status != XAIOS_ENGINE_OK) return status;
    if ((current.flags & XAIOS_XAI_FS_CHUNK_FREE) == 0U) continue;
    if (index == selected_free_index) {
      if (current.extent_length == required_data_bytes) continue;
      current.physical_offset += required_data_bytes;
      current.length -= required_data_bytes;
      current.extent_length -= required_data_bytes;
    }
    encode_chunk_record(&current, raw_chunk);
    status = write_exact(writer, destination + written_chunks * sizeof(raw_chunk),
                         raw_chunk, sizeof(raw_chunk));
    if (status != XAIOS_ENGINE_OK) return status;
    xaios_engine_sha256_update(&catalog_sha, raw_chunk, sizeof(raw_chunk));
    ++written_chunks;
  }

  for (uint64_t package_index = 0U;
       package_index < volume->package_count; ++package_index) {
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
          writer, destination + written_chunks * sizeof(raw_chunk), raw_chunk,
          sizeof(raw_chunk));
      if (status != XAIOS_ENGINE_OK) return status;
      xaios_engine_sha256_update(&catalog_sha, raw_chunk, sizeof(raw_chunk));
      ++written_chunks;
    }
  }

  uint64_t data_cursor = package_data_offset;
  uint64_t logical_cursor = 0U;
  for (uint64_t index = 0U; index < added_chunks; ++index) {
    xaios_xai_fs_chunk_t chunk;
    memset(&chunk, 0, sizeof(chunk));
    chunk.record_id = record_id;
    chunk.logical_offset = logical_cursor;
    chunk.physical_offset = data_cursor;
    chunk.length = package.logical_size - logical_cursor;
    if (chunk.length > volume->chunk_size) chunk.length = volume->chunk_size;
    if (align_up(chunk.length, XAI_FS_BLOCK_SIZE,
                 &chunk.extent_length) != XAIOS_ENGINE_OK) {
      return XAIOS_ENGINE_ERR_OVERFLOW;
    }
    chunk.flags = XAIOS_XAI_FS_CHUNK_HASH_PENDING;
    encode_chunk_record(&chunk, raw_chunk);
    status = write_exact(writer,
                         destination + written_chunks * sizeof(raw_chunk),
                         raw_chunk, sizeof(raw_chunk));
    if (status != XAIOS_ENGINE_OK) return status;
    xaios_engine_sha256_update(&catalog_sha, raw_chunk, sizeof(raw_chunk));
    data_cursor += chunk.extent_length;
    logical_cursor += chunk.length;
    ++written_chunks;
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
  *registered_package = package;
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaios_xai_fs_activate_staging(
    xaios_xai_fs_t *volume,
    const xaios_xai_fs_package_t *package,
    const xaios_xai_fs_writer_t *writer, void *scratch,
    size_t scratch_size) {
  if (volume == NULL || package == NULL || writer == NULL ||
      writer->write_at == NULL || writer->flush == NULL || scratch == NULL ||
      scratch_size < XAI_FS_WRITER_SCRATCH_MIN ||
      package->state != XAIOS_XAI_FS_PACKAGE_STAGING) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  xaios_engine_status_t status = writer->flush(writer->context);
  if (status != XAIOS_ENGINE_OK) return status;
  if (xaios_xai_fs_verify_package_manifest(volume, package) !=
      XAIOS_ENGINE_OK) {
    return XAIOS_ENGINE_ERR_CHECKSUM;
  }
  uint64_t bad_offset = UINT64_MAX;
  status = xaios_xai_fs_verify_package(
      volume, package, scratch, scratch_size, &bad_offset);
  if (status != XAIOS_ENGINE_OK) return status;

  uint64_t target_index = UINT64_MAX;
  for (uint64_t index = 0U; index < volume->package_count; ++index) {
    xaios_xai_fs_package_t current;
    status = xaios_xai_fs_read_package(volume, index, &current);
    if (status != XAIOS_ENGINE_OK) return status;
    if (current.record_id == package->record_id) {
      if (memcmp(current.package_id, package->package_id,
                 sizeof(current.package_id)) != 0 ||
          current.state != XAIOS_XAI_FS_PACKAGE_STAGING) {
        return XAIOS_ENGINE_ERR_INVALID;
      }
      target_index = index;
    } else if (current.state == XAIOS_XAI_FS_PACKAGE_ACTIVE &&
               memcmp(current.model_uuid, package->model_uuid,
                      sizeof(current.model_uuid)) == 0) {
      return XAIOS_ENGINE_ERR_CAPABILITY;
    }
  }
  if (target_index == UINT64_MAX) return XAIOS_ENGINE_ERR_INVALID;

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
    if (index == target_index) {
      store_le32(package_raw, XAIOS_XAI_FS_PACKAGE_ACTIVE);
    }
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
    status = write_exact(writer, destination, chunk_raw, sizeof(chunk_raw));
    if (status != XAIOS_ENGINE_OK) return status;
    xaios_engine_sha256_update(&catalog_sha, chunk_raw, sizeof(chunk_raw));
  }

  uint8_t catalog_hash[32];
  xaios_engine_sha256_final(&catalog_sha, catalog_hash);
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
  return XAIOS_ENGINE_OK;
}
