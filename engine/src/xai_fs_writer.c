#include <xaios_engine/xai_fs.h>

#include <string.h>

#include "sha256.h"
#include "xai_fs_writer_internal.h"
#include "xai_fs_writer_parts.h"

#define XAI_FS_MIN_CHUNK_SIZE UINT64_C(2097152)
/* 64 MiB, which is what the format says and what the reader and the host tool
 * have accepted since the cap was raised. This constant was left at 16 MiB by
 * that change -- `78bafd1` touched `engine/src/xai_fs.c`, the Python tool and
 * `wiki/Filesystem-and-Storage.md` and not this file -- so the C writer could
 * neither format nor accept a volume in the (16, 64] MiB range that
 * `docs/MODELFS-FORMAT.md` says is legal, the reader will open, and
 * `tools/xaios_xai_fs.py` will write. One format with two caps is one cap
 * nobody can rely on; the reader's own comment argues the higher one is where
 * the limit stops binding. */
#define XAI_FS_MAX_CHUNK_SIZE UINT64_C(67108864)

/* The two chunk-size bounds are read out of this file as text by
 * `tests/repository/check-xai-fs-chunk-bounds.py`, which compares them with
 * the reader, the host tool and the format document. `valid_chunk_size` is
 * their only user, so it stays next to them; everything else it lived
 * beside is in `xai_fs_writer_util.c`. */
static int valid_chunk_size(uint64_t value) {
  return value >= XAI_FS_MIN_CHUNK_SIZE &&
         value <= XAI_FS_MAX_CHUNK_SIZE &&
         (value & (value - 1U)) == 0U;
}

void xai_fs_writer_encode_catalog_header(const xaios_xai_fs_t *volume,
                                  uint64_t generation, uint64_t data_tail,
                                  uint8_t raw[256]) {
  memset(raw, 0, 256U);
  memcpy(raw, "XAICAT1\0", 8U);
  store_le16(raw + 8U, 1U);
  store_le16(raw + 10U, 0U);
  raw[12] = 1U;
  raw[13] = 1U;
  store_le64(raw + 16U, XAIOS_XAI_FS_CATALOG_HEADER_SIZE);
  store_le64(raw + 24U, generation);
  memcpy(raw + 32U, volume->volume_uuid, 16U);
  store_le64(raw + 48U, XAIOS_XAI_FS_PACKAGE_RECORD_SIZE);
  store_le64(raw + 56U, volume->package_count);
  store_le64(raw + 64U, XAIOS_XAI_FS_CHUNK_RECORD_SIZE);
  store_le64(raw + 72U, volume->chunk_count);
  store_le64(raw + 80U, volume->package_offset);
  store_le64(raw + 88U, volume->chunk_offset);
  store_le64(raw + 96U, volume->catalog_length);
  store_le64(raw + 112U, data_tail);
  store_le64(raw + 120U, volume->free_extent_count);
  uint8_t digest[32];
  sha256(raw, 256U, digest);
  memcpy(raw + 144U, digest, sizeof(digest));
}

/* Where the package data ends, independent of where the catalog happens to be.
 *
 * data_tail has served as both the allocation cursor and the end of the live
 * catalog, and because a commit wrote its new catalog *at* data_tail and then
 * moved data_tail past it, every commit permanently consumed a catalog's worth
 * of volume that nothing ever reclaimed. Measured on a 256 MB volume: 8192
 * bytes a commit, 23799 commits until the volume is full. A 500 GB package
 * ingested a chunk at a time would strand something like 131 GB of dead
 * catalogs behind it, and the ingest after that would have nowhere to go.
 *
 * The two ideas had to be separated. This is the first: the highest byte any
 * extent actually occupies, which is what the catalog must sit above and what
 * new extents must be allocated above. */
xaios_engine_status_t xai_fs_writer_data_high_water(const xaios_xai_fs_t *volume,
                                             uint64_t *high_water) {
  uint64_t highest = XAIOS_XAI_FS_DATA_START;
  for (uint64_t index = 0U; index < volume->chunk_count; ++index) {
    xaios_xai_fs_chunk_t chunk;
    xaios_engine_status_t status =
        xaios_xai_fs_read_chunk(volume, index, &chunk);
    if (status != XAIOS_ENGINE_OK) return status;
    /* A sparse-zero chunk owns no bytes on the volume. */
    if ((chunk.flags & XAIOS_XAI_FS_CHUNK_ZERO) != 0U &&
        chunk.extent_length == 0U) {
      continue;
    }
    uint64_t end = 0U;
    if (checked_add(chunk.physical_offset, chunk.extent_length, &end) !=
        XAIOS_ENGINE_OK) {
      return XAIOS_ENGINE_ERR_OVERFLOW;
    }
    if (end > highest) highest = end;
  }
  *high_water = highest;
  return XAIOS_ENGINE_OK;
}

/* Pick which of two catalog slots to write, and where the volume then ends.
 *
 * Two fixed slots directly above the data, used alternately. The new catalog
 * never lands on the live one, which is what the whole crash-safety argument
 * needs -- a reader following the old superblock must still find the old
 * catalog intact until the superblock flips. And because there are two of them
 * rather than a fresh one each time, a run of commits that allocates no new
 * data consumes no new volume, which is every commit of an ingest. */
xaios_engine_status_t xai_fs_writer_choose_catalog_slot(
    const xaios_xai_fs_t *volume, uint64_t data_floor, uint64_t catalog_length,
    uint64_t *catalog_offset, uint64_t *final_tail) {
  uint64_t first = 0U;
  uint64_t second = 0U;
  uint64_t second_end = 0U;
  uint64_t tail = 0U;
  if (align_up(data_floor, XAI_FS_BLOCK_SIZE, &first) != XAIOS_ENGINE_OK ||
      checked_add(first, catalog_length, &second) != XAIOS_ENGINE_OK ||
      align_up(second, XAI_FS_BLOCK_SIZE, &second) != XAIOS_ENGINE_OK ||
      checked_add(second, catalog_length, &second_end) != XAIOS_ENGINE_OK ||
      align_up(second_end, XAI_FS_BLOCK_SIZE, &tail) != XAIOS_ENGINE_OK ||
      tail > volume->volume_size) {
    return XAIOS_ENGINE_ERR_CAPABILITY;
  }
  /* Anything but the slot in use. A volume whose live catalog is somewhere
     else entirely -- one written before this scheme existed -- takes the first
     slot, which is equally not where it is now. */
  *catalog_offset = volume->catalog_offset == first ? second : first;
  *final_tail = tail;
  return XAIOS_ENGINE_OK;
}

void xai_fs_writer_encode_superblock(const xaios_xai_fs_t *volume,
                              uint64_t generation, uint64_t catalog_offset,
                              uint64_t catalog_generation,
                              uint64_t data_tail,
                              const uint8_t catalog_hash[32],
                              uint8_t raw[4096]) {
  memset(raw, 0, 4096U);
  memcpy(raw, "XAIOSV1\0", 8U);
  store_le16(raw + 8U, 1U);
  store_le16(raw + 10U, 0U);
  raw[12] = 1U;
  raw[13] = 1U;
  store_le64(raw + 16U, XAIOS_XAI_FS_SUPERBLOCK_SIZE);
  store_le64(raw + 24U, XAI_FS_BLOCK_SIZE);
  store_le64(raw + 32U, volume->chunk_size);
  store_le64(raw + 40U, volume->volume_size);
  store_le64(raw + 48U, generation);
  store_le64(raw + 56U, catalog_offset);
  store_le64(raw + 64U, volume->catalog_length);
  store_le64(raw + 72U, catalog_generation);
  store_le64(raw + 80U, data_tail);
  memcpy(raw + 88U, volume->volume_uuid, 16U);
  memcpy(raw + 104U, catalog_hash, 32U);
  uint8_t digest[32];
  sha256(raw, 4096U, digest);
  memcpy(raw + 136U, digest, sizeof(digest));
}

xaios_engine_status_t xaios_xai_fs_format(
    const xaios_xai_fs_writer_t *writer, uint64_t volume_size,
    uint64_t chunk_size, const uint8_t volume_uuid[16], void *scratch,
    size_t scratch_size) {
  if (writer == NULL || writer->write_at == NULL || writer->flush == NULL ||
      scratch == NULL || scratch_size < XAI_FS_WRITER_SCRATCH_MIN ||
      !valid_chunk_size(chunk_size) || !valid_uuid(volume_uuid) ||
      volume_size < XAIOS_XAI_FS_DATA_START ||
      chunk_size > volume_size / 4U) {
    return XAIOS_ENGINE_ERR_INVALID;
  }

  xaios_xai_fs_t volume;
  memset(&volume, 0, sizeof(volume));
  memcpy(volume.volume_uuid, volume_uuid, sizeof(volume.volume_uuid));
  volume.volume_size = volume_size;
  volume.generation = 1U;
  volume.catalog_offset = 2U * XAIOS_XAI_FS_SUPERBLOCK_SIZE;
  volume.catalog_length = XAIOS_XAI_FS_CATALOG_HEADER_SIZE;
  volume.catalog_generation = 1U;
  volume.data_tail = XAIOS_XAI_FS_DATA_START;
  volume.chunk_size = chunk_size;
  volume.package_offset = XAIOS_XAI_FS_CATALOG_HEADER_SIZE;
  volume.chunk_offset = XAIOS_XAI_FS_CATALOG_HEADER_SIZE;

  uint64_t catalog_end = 0U;
  if (checked_add(volume.catalog_offset, volume.catalog_length,
                  &catalog_end) != XAIOS_ENGINE_OK ||
      catalog_end > volume.data_tail || volume.data_tail > volume_size) {
    return XAIOS_ENGINE_ERR_OVERFLOW;
  }

  uint8_t *superblock = (uint8_t *)scratch;
  uint8_t *catalog = superblock + XAIOS_XAI_FS_SUPERBLOCK_SIZE;
  xai_fs_writer_encode_catalog_header(&volume, volume.catalog_generation, volume.data_tail,
                        catalog);
  sha256(catalog, (size_t)volume.catalog_length, volume.catalog_hash);
  xai_fs_writer_encode_superblock(&volume, volume.generation, volume.catalog_offset,
                    volume.catalog_generation, volume.data_tail,
                    volume.catalog_hash, superblock);

  xaios_engine_status_t status = write_exact(
      writer, volume.catalog_offset, catalog, (size_t)volume.catalog_length);
  if (status != XAIOS_ENGINE_OK) return status;
  status = writer->flush(writer->context);
  if (status != XAIOS_ENGINE_OK) return status;
  status = write_exact(writer, XAIOS_XAI_FS_SUPERBLOCK_SIZE,
                       superblock, (size_t)XAIOS_XAI_FS_SUPERBLOCK_SIZE);
  if (status != XAIOS_ENGINE_OK) return status;
  status = writer->flush(writer->context);
  if (status != XAIOS_ENGINE_OK) return status;
  status = write_exact(writer, 0U, superblock,
                       (size_t)XAIOS_XAI_FS_SUPERBLOCK_SIZE);
  if (status != XAIOS_ENGINE_OK) return status;
  return writer->flush(writer->context);
}

xaios_engine_status_t xaios_xai_fs_grow(
    xaios_xai_fs_t *volume,
    const xaios_xai_fs_writer_t *writer, uint64_t new_volume_size,
    void *scratch, size_t scratch_size) {
  if (volume == NULL || writer == NULL || writer->write_at == NULL ||
      writer->flush == NULL || scratch == NULL || scratch_size < 4096U ||
      new_volume_size <= volume->volume_size ||
      new_volume_size > volume->reader.size ||
      new_volume_size < volume->data_tail) {
    return new_volume_size < volume->volume_size
               ? XAIOS_ENGINE_ERR_UNSUPPORTED
               : XAIOS_ENGINE_ERR_INVALID;
  }
  if (volume->generation == UINT64_MAX) return XAIOS_ENGINE_ERR_OVERFLOW;
  xaios_xai_fs_t grown = *volume;
  grown.volume_size = new_volume_size;
  grown.generation = volume->generation + 1U;
  uint32_t next_slot = 1U - volume->selected_superblock;
  uint8_t *superblock = (uint8_t *)scratch;
  xai_fs_writer_encode_superblock(&grown, grown.generation, grown.catalog_offset,
                    grown.catalog_generation, grown.data_tail,
                    grown.catalog_hash, superblock);
  xaios_engine_status_t status = write_exact(
      writer, (uint64_t)next_slot * XAIOS_XAI_FS_SUPERBLOCK_SIZE,
      superblock, (size_t)XAIOS_XAI_FS_SUPERBLOCK_SIZE);
  if (status != XAIOS_ENGINE_OK) return status;
  status = writer->flush(writer->context);
  if (status != XAIOS_ENGINE_OK) return status;
  volume->volume_size = grown.volume_size;
  volume->generation = grown.generation;
  volume->selected_superblock = next_slot;
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaios_xai_fs_repair_superblock(
    xaios_xai_fs_t *volume,
    const xaios_xai_fs_writer_t *writer, void *scratch,
    size_t scratch_size) {
  if (volume == NULL || writer == NULL || writer->write_at == NULL ||
      writer->flush == NULL || scratch == NULL || scratch_size < 4096U) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  uint32_t repair_slot = 1U - volume->selected_superblock;
  uint8_t *superblock = (uint8_t *)scratch;
  xai_fs_writer_encode_superblock(volume, volume->generation, volume->catalog_offset,
                    volume->catalog_generation, volume->data_tail,
                    volume->catalog_hash, superblock);
  xaios_engine_status_t status = write_exact(
      writer, (uint64_t)repair_slot * XAIOS_XAI_FS_SUPERBLOCK_SIZE,
      superblock, (size_t)XAIOS_XAI_FS_SUPERBLOCK_SIZE);
  if (status != XAIOS_ENGINE_OK) return status;
  return writer->flush(writer->context);
}

xaios_engine_status_t xaios_xai_fs_remove_staging(
    xaios_xai_fs_t *volume,
    const xaios_xai_fs_package_t *package,
    const xaios_xai_fs_writer_t *writer, void *scratch,
    size_t scratch_size, uint64_t *reclaimed_bytes) {
  return xai_fs_writer_remove_package_in_state(
      volume, package, writer, scratch, scratch_size,
      XAIOS_XAI_FS_PACKAGE_STAGING, reclaimed_bytes);
}

xaios_engine_status_t xaios_xai_fs_remove_quarantined(
    xaios_xai_fs_t *volume,
    const xaios_xai_fs_package_t *package,
    const xaios_xai_fs_writer_t *writer, void *scratch,
    size_t scratch_size, uint64_t *reclaimed_bytes) {
  return xai_fs_writer_remove_package_in_state(
      volume, package, writer, scratch, scratch_size,
      XAIOS_XAI_FS_PACKAGE_QUARANTINED, reclaimed_bytes);
}

static int replica_identity_matches(
    const xaios_xai_fs_package_t *target,
    const xaios_xai_fs_package_t *replica) {
  return target != NULL && replica != NULL &&
         target->logical_size == replica->logical_size &&
         target->chunk_size == replica->chunk_size &&
         memcmp(target->model_uuid, replica->model_uuid,
                sizeof(target->model_uuid)) == 0 &&
         memcmp(target->package_id, replica->package_id,
                sizeof(target->package_id)) == 0 &&
         memcmp(target->signer_public_key, replica->signer_public_key,
                sizeof(target->signer_public_key)) == 0 &&
         memcmp(target->signature, replica->signature,
                sizeof(target->signature)) == 0 &&
         memcmp(target->source_revision, replica->source_revision,
                sizeof(target->source_revision)) == 0 &&
         memcmp(target->architecture_id, replica->architecture_id,
                sizeof(target->architecture_id)) == 0 &&
         memcmp(target->target_id, replica->target_id,
                sizeof(target->target_id)) == 0;
}

xaios_engine_status_t xaios_xai_fs_repair_from_replica(
    xaios_xai_fs_t *target,
    const xaios_xai_fs_package_t *target_package,
    const xaios_xai_fs_t *replica,
    const xaios_xai_fs_package_t *replica_package,
    const xaios_xai_fs_writer_t *target_writer, void *scratch,
    size_t scratch_size, uint64_t *copied_bytes) {
  if (copied_bytes != NULL) *copied_bytes = 0U;
  if (target == NULL || target_package == NULL || replica == NULL ||
      replica_package == NULL || target_writer == NULL ||
      target_writer->write_at == NULL || target_writer->flush == NULL ||
      scratch == NULL || scratch_size < XAI_FS_WRITER_SCRATCH_MIN ||
      target == replica || target->reader.context == replica->reader.context ||
      target_package->state != XAIOS_XAI_FS_PACKAGE_QUARANTINED ||
      replica_package->state != XAIOS_XAI_FS_PACKAGE_ACTIVE ||
      !replica_identity_matches(target_package, replica_package) ||
      target->chunk_size != replica->chunk_size) {
    return XAIOS_ENGINE_ERR_INVALID;
  }

  uint64_t bad_offset = UINT64_MAX;
  xaios_engine_status_t status = xaios_xai_fs_verify_package(
      replica, replica_package, scratch, scratch_size, &bad_offset);
  if (status != XAIOS_ENGINE_OK) return status;

  status = xaios_xai_fs_remove_quarantined(
      target, target_package, target_writer, scratch, scratch_size, NULL);
  if (status != XAIOS_ENGINE_OK) return status;

  xaios_xai_fs_package_t replacement;
  status = xaios_xai_fs_register_staging(
      target, replica_package, target_writer, scratch, scratch_size,
      &replacement);
  if (status != XAIOS_ENGINE_OK) return status;

  uint8_t *buffer = (uint8_t *)scratch;
  for (uint64_t relative = 0U; relative < replacement.chunk_count; ++relative) {
    xaios_xai_fs_chunk_t chunk;
    status = xaios_xai_fs_read_chunk(target,
                                           replacement.chunk_start + relative,
                                           &chunk);
    if (status != XAIOS_ENGINE_OK || chunk.record_id != replacement.record_id) {
      return status == XAIOS_ENGINE_OK ? XAIOS_ENGINE_ERR_INVALID : status;
    }
    uint64_t copied_chunk = 0U;
    while (copied_chunk < chunk.length) {
      uint64_t remaining = chunk.length - copied_chunk;
      size_t length = remaining < (uint64_t)scratch_size
                          ? (size_t)remaining
                          : scratch_size;
      uint64_t offset = chunk.logical_offset + copied_chunk;
      status = xaios_xai_fs_pread(replica, replica_package, offset,
                                        buffer, length);
      if (status != XAIOS_ENGINE_OK) return status;
      status = xaios_xai_fs_pwrite_staging(target, &replacement,
                                                 target_writer, offset, buffer,
                                                 length);
      if (status != XAIOS_ENGINE_OK) return status;
      copied_chunk += (uint64_t)length;
    }
    uint64_t completed = 0U;
    status = xaios_xai_fs_commit_staging_range(
        target, &replacement, target_writer, chunk.logical_offset, chunk.length,
        scratch, scratch_size, &completed);
    if (status != XAIOS_ENGINE_OK) return status;
    if (completed != 1U) return XAIOS_ENGINE_ERR_INVALID;
  }

  status = xaios_xai_fs_activate_staging(
      target, &replacement, target_writer, scratch, scratch_size);
  if (status != XAIOS_ENGINE_OK) return status;
  if (copied_bytes != NULL) *copied_bytes = replacement.logical_size;
  return XAIOS_ENGINE_OK;
}

static xaios_engine_status_t publish_package_state(
    xaios_xai_fs_t *volume,
    const xaios_xai_fs_package_t *package, uint32_t new_state,
    const xaios_xai_fs_writer_t *writer, void *scratch,
    size_t scratch_size) {
  if (volume == NULL || package == NULL || writer == NULL ||
      writer->write_at == NULL || writer->flush == NULL || scratch == NULL ||
      scratch_size < XAI_FS_WRITER_SCRATCH_MIN ||
      (new_state != XAIOS_XAI_FS_PACKAGE_ACTIVE &&
       new_state != XAIOS_XAI_FS_PACKAGE_QUARANTINED)) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  uint64_t target_index = UINT64_MAX;
  for (uint64_t index = 0U; index < volume->package_count; ++index) {
    xaios_xai_fs_package_t current;
    xaios_engine_status_t status =
        xaios_xai_fs_read_package(volume, index, &current);
    if (status != XAIOS_ENGINE_OK) return status;
    if (current.record_id == package->record_id) {
      if (memcmp(current.package_id, package->package_id, 32U) != 0 ||
          current.state != package->state) {
        return XAIOS_ENGINE_ERR_INVALID;
      }
      target_index = index;
    }
  }
  if (target_index == UINT64_MAX || package->state == new_state) {
    return XAIOS_ENGINE_ERR_INVALID;
  }

  uint64_t catalog_offset = 0U;
  uint64_t final_tail = 0U;
  uint64_t data_floor = 0U;
  if (xai_fs_writer_data_high_water(volume, &data_floor) != XAIOS_ENGINE_OK ||
      xai_fs_writer_choose_catalog_slot(volume, data_floor, volume->catalog_length,
                          &catalog_offset, &final_tail) != XAIOS_ENGINE_OK || volume->generation == UINT64_MAX ||
      volume->catalog_generation == UINT64_MAX) {
    return XAIOS_ENGINE_ERR_CAPABILITY;
  }
  uint64_t catalog_generation = volume->catalog_generation + 1U;
  uint64_t generation = volume->generation + 1U;
  uint8_t header[256];
  xai_fs_writer_encode_catalog_header(volume, catalog_generation, final_tail, header);
  xaios_engine_sha256_context_t catalog_sha;
  xaios_engine_sha256_init(&catalog_sha);
  xaios_engine_status_t status =
      write_exact(writer, catalog_offset, header, sizeof(header));
  if (status != XAIOS_ENGINE_OK) return status;
  xaios_engine_sha256_update(&catalog_sha, header, sizeof(header));

  uint8_t package_raw[384];
  uint64_t source_package_base =
      volume->catalog_offset + volume->package_offset;
  uint64_t destination_package_base = catalog_offset + volume->package_offset;
  for (uint64_t index = 0U; index < volume->package_count; ++index) {
    status = read_exact(volume, source_package_base + index * 384U,
                        package_raw, sizeof(package_raw));
    if (status != XAIOS_ENGINE_OK) return status;
    if (index == target_index) store_le32(package_raw, new_state);
    status = write_exact(writer, destination_package_base + index * 384U,
                         package_raw, sizeof(package_raw));
    if (status != XAIOS_ENGINE_OK) return status;
    xaios_engine_sha256_update(&catalog_sha, package_raw, sizeof(package_raw));
  }

  uint8_t chunk_raw[128];
  uint64_t source_chunk_base = volume->catalog_offset + volume->chunk_offset;
  uint64_t destination_chunk_base = catalog_offset + volume->chunk_offset;
  for (uint64_t index = 0U; index < volume->chunk_count; ++index) {
    status = read_exact(volume, source_chunk_base + index * 128U, chunk_raw,
                        sizeof(chunk_raw));
    if (status != XAIOS_ENGINE_OK) return status;
    status = write_exact(writer, destination_chunk_base + index * 128U,
                         chunk_raw, sizeof(chunk_raw));
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

xaios_engine_status_t xaios_xai_fs_quarantine_package(
    xaios_xai_fs_t *volume,
    const xaios_xai_fs_package_t *package,
    const xaios_xai_fs_writer_t *writer, void *scratch,
    size_t scratch_size) {
  if (package == NULL ||
      (package->state != XAIOS_XAI_FS_PACKAGE_ACTIVE &&
       package->state != XAIOS_XAI_FS_PACKAGE_STAGING)) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  return publish_package_state(
      volume, package, XAIOS_XAI_FS_PACKAGE_QUARANTINED, writer,
      scratch, scratch_size);
}
