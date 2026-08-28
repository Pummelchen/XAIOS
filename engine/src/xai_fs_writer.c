#include <xaios_engine/xai_fs.h>

#include <string.h>

#include "sha256.h"

#define XAI_FS_BLOCK_SIZE UINT64_C(4096)
#define XAI_FS_WRITER_SCRATCH_MIN UINT64_C(8192)
#define XAI_FS_MIN_CHUNK_SIZE UINT64_C(2097152)
#define XAI_FS_MAX_CHUNK_SIZE UINT64_C(16777216)

static void store_le16(uint8_t output[2], uint16_t value) {
  output[0] = (uint8_t)value;
  output[1] = (uint8_t)(value >> 8U);
}

static void store_le32(uint8_t output[4], uint32_t value) {
  for (uint32_t index = 0U; index < 4U; ++index) {
    output[index] = (uint8_t)(value >> (index * 8U));
  }
}

static void store_le64(uint8_t output[8], uint64_t value) {
  for (uint32_t index = 0U; index < 8U; ++index) {
    output[index] = (uint8_t)(value >> (index * 8U));
  }
}

static xaios_engine_status_t checked_add(uint64_t left, uint64_t right,
                                         uint64_t *result) {
  if (result == NULL || right > UINT64_MAX - left) {
    return XAIOS_ENGINE_ERR_OVERFLOW;
  }
  *result = left + right;
  return XAIOS_ENGINE_OK;
}

static xaios_engine_status_t checked_multiply(uint64_t left, uint64_t right,
                                              uint64_t *result) {
  if (result == NULL || (left != 0U && right > UINT64_MAX / left)) {
    return XAIOS_ENGINE_ERR_OVERFLOW;
  }
  *result = left * right;
  return XAIOS_ENGINE_OK;
}

static xaios_engine_status_t align_up(uint64_t value, uint64_t alignment,
                                      uint64_t *result) {
  uint64_t adjusted = 0U;
  if (alignment == 0U || (alignment & (alignment - 1U)) != 0U ||
      checked_add(value, alignment - 1U, &adjusted) != XAIOS_ENGINE_OK) {
    return XAIOS_ENGINE_ERR_OVERFLOW;
  }
  *result = adjusted & ~(alignment - 1U);
  return XAIOS_ENGINE_OK;
}

static xaios_engine_status_t read_exact(
    const xaios_xai_fs_t *volume, uint64_t offset, void *destination,
    size_t length) {
  uint64_t end = 0U;
  if (volume == NULL || volume->reader.read_at == NULL || destination == NULL ||
      length == 0U ||
      checked_add(offset, (uint64_t)length, &end) != XAIOS_ENGINE_OK ||
      end > volume->reader.size) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  return volume->reader.read_at(volume->reader.context, offset, destination,
                                length);
}

static xaios_engine_status_t write_exact(
    const xaios_xai_fs_writer_t *writer, uint64_t offset,
    const void *source, size_t length) {
  if (writer == NULL || writer->write_at == NULL || source == NULL ||
      length == 0U) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  return writer->write_at(writer->context, offset, source, length);
}

static void sha256(const void *data, size_t length, uint8_t digest[32]) {
  xaios_engine_sha256_context_t context;
  xaios_engine_sha256_init(&context);
  xaios_engine_sha256_update(&context, data, length);
  xaios_engine_sha256_final(&context, digest);
}

static int ranges_intersect(uint64_t first_offset, uint64_t first_length,
                            uint64_t second_offset, uint64_t second_length) {
  uint64_t first_end = 0U;
  uint64_t second_end = 0U;
  if (checked_add(first_offset, first_length, &first_end) != XAIOS_ENGINE_OK ||
      checked_add(second_offset, second_length, &second_end) !=
          XAIOS_ENGINE_OK) {
    return 0;
  }
  return first_offset < second_end && second_offset < first_end;
}

static int valid_chunk_size(uint64_t value) {
  return value >= XAI_FS_MIN_CHUNK_SIZE &&
         value <= XAI_FS_MAX_CHUNK_SIZE &&
         (value & (value - 1U)) == 0U;
}

static int valid_uuid(const uint8_t uuid[16]) {
  if (uuid == NULL) return 0;
  uint8_t combined = 0U;
  for (size_t index = 0U; index < 16U; ++index) combined |= uuid[index];
  return combined != 0U;
}

static int bytes_nonzero(const uint8_t *bytes, size_t length) {
  uint8_t combined = 0U;
  if (bytes == NULL) return 0;
  for (size_t index = 0U; index < length; ++index) combined |= bytes[index];
  return combined != 0U;
}

static int valid_ascii(const char value[33]) {
  if (value == NULL) return 0;
  for (size_t index = 0U; index < 33U; ++index) {
    uint8_t byte = (uint8_t)value[index];
    if (byte == 0U) return index != 0U;
    if (index == 32U || byte < 0x20U || byte > 0x7eU) return 0;
  }
  return 0;
}

static int valid_target(const char *target) {
  static const char *const targets[] = {
      "portable", "apple-neon", "apple-accelerate", "intel-avx2",
      "intel-avx512-vnni", "intel-amx"};
  if (!valid_ascii(target)) return 0;
  for (size_t index = 0U; index < sizeof(targets) / sizeof(targets[0]);
       ++index) {
    if (strcmp(target, targets[index]) == 0) return 1;
  }
  return 0;
}

static void encode_ascii(uint8_t output[32], const char *value) {
  memset(output, 0, 32U);
  size_t length = strlen(value);
  memcpy(output, value, length);
}

static void encode_package_record(
    const xaios_xai_fs_package_t *package, uint8_t raw[384]) {
  memset(raw, 0, 384U);
  store_le32(raw, package->state);
  store_le64(raw + 8U, package->record_id);
  memcpy(raw + 16U, package->model_uuid, 16U);
  memcpy(raw + 32U, package->package_id, 32U);
  memcpy(raw + 64U, package->signer_public_key, 32U);
  memcpy(raw + 96U, package->signature, 64U);
  memcpy(raw + 160U, package->source_revision, 32U);
  store_le64(raw + 192U, package->logical_size);
  store_le64(raw + 200U, package->chunk_size);
  store_le64(raw + 208U, package->chunk_start);
  store_le64(raw + 216U, package->chunk_count);
  encode_ascii(raw + 224U, package->architecture_id);
  encode_ascii(raw + 256U, package->target_id);
}

static void encode_chunk_record(const xaios_xai_fs_chunk_t *chunk,
                                uint8_t raw[128]) {
  memset(raw, 0, 128U);
  store_le64(raw, chunk->record_id);
  store_le64(raw + 8U, chunk->logical_offset);
  store_le64(raw + 16U, chunk->physical_offset);
  store_le64(raw + 24U, chunk->length);
  store_le32(raw + 32U, chunk->flags);
  memcpy(raw + 40U, chunk->checksum, 32U);
  store_le64(raw + 72U, chunk->extent_length);
}

static xaios_engine_status_t hash_physical_range(
    const xaios_xai_fs_t *volume, uint64_t physical_offset,
    uint64_t length, void *scratch, size_t scratch_size, uint8_t digest[32]) {
  if (scratch == NULL || scratch_size == 0U || length == 0U) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  xaios_engine_sha256_context_t context;
  xaios_engine_sha256_init(&context);
  uint64_t completed = 0U;
  while (completed < length) {
    uint64_t remaining = length - completed;
    size_t count = remaining < (uint64_t)scratch_size
                       ? (size_t)remaining
                       : scratch_size;
    xaios_engine_status_t status = read_exact(
        volume, physical_offset + completed, scratch, count);
    if (status != XAIOS_ENGINE_OK) return status;
    xaios_engine_sha256_update(&context, scratch, count);
    completed += (uint64_t)count;
  }
  xaios_engine_sha256_final(&context, digest);
  return XAIOS_ENGINE_OK;
}

static xaios_engine_status_t chunk_completion_status(
    const xaios_xai_fs_t *volume,
    const xaios_xai_fs_package_t *package,
    const xaios_xai_fs_chunk_t *chunk, uint64_t offset, uint64_t length,
    void *scratch, size_t scratch_size, int *should_complete,
    uint8_t learned_checksum[32]) {
  if (should_complete == NULL || learned_checksum == NULL) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  *should_complete = 0;
  memset(learned_checksum, 0, 32U);
  if (chunk->record_id != package->record_id ||
      (chunk->flags & (XAIOS_XAI_FS_CHUNK_COMPLETE |
                       XAIOS_XAI_FS_CHUNK_ZERO |
                       XAIOS_XAI_FS_CHUNK_FREE)) != 0U ||
      !ranges_intersect(chunk->logical_offset, chunk->length, offset, length)) {
    return XAIOS_ENGINE_OK;
  }
  if ((chunk->flags & XAIOS_XAI_FS_CHUNK_HASH_PENDING) != 0U &&
      (offset > chunk->logical_offset ||
       length < chunk->length ||
       offset + length < chunk->logical_offset + chunk->length)) {
    return XAIOS_ENGINE_OK;
  }
  uint8_t digest[32];
  xaios_engine_status_t status = hash_physical_range(
      volume, chunk->physical_offset, chunk->length, scratch, scratch_size,
      digest);
  if (status != XAIOS_ENGINE_OK) return status;
  if ((chunk->flags & XAIOS_XAI_FS_CHUNK_HASH_PENDING) != 0U) {
    memcpy(learned_checksum, digest, sizeof(digest));
    *should_complete = 1;
  } else {
    *should_complete = memcmp(digest, chunk->checksum, sizeof(digest)) == 0;
  }
  return XAIOS_ENGINE_OK;
}

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

static void encode_catalog_header(const xaios_xai_fs_t *volume,
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

static void encode_superblock(const xaios_xai_fs_t *volume,
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
  encode_catalog_header(&volume, volume.catalog_generation, volume.data_tail,
                        catalog);
  sha256(catalog, (size_t)volume.catalog_length, volume.catalog_hash);
  encode_superblock(&volume, volume.generation, volume.catalog_offset,
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
  encode_superblock(&grown, grown.generation, grown.catalog_offset,
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
  encode_superblock(volume, volume->generation, volume->catalog_offset,
                    volume->catalog_generation, volume->data_tail,
                    volume->catalog_hash, superblock);
  xaios_engine_status_t status = write_exact(
      writer, (uint64_t)repair_slot * XAIOS_XAI_FS_SUPERBLOCK_SIZE,
      superblock, (size_t)XAIOS_XAI_FS_SUPERBLOCK_SIZE);
  if (status != XAIOS_ENGINE_OK) return status;
  return writer->flush(writer->context);
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
  uint64_t catalog_end = 0U;
  uint64_t final_tail = 0U;
  if (align_up(data_end, XAI_FS_BLOCK_SIZE, &catalog_offset) !=
          XAIOS_ENGINE_OK ||
      checked_add(catalog_offset, catalog_length, &catalog_end) !=
          XAIOS_ENGINE_OK ||
      align_up(catalog_end, XAI_FS_BLOCK_SIZE, &final_tail) !=
          XAIOS_ENGINE_OK ||
      final_tail > volume->volume_size) {
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
  encode_catalog_header(&next, next.catalog_generation, final_tail, header);
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
  encode_superblock(&next, next.generation, next.catalog_offset,
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

static xaios_engine_status_t remove_package_in_state(
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
  uint64_t catalog_end = 0U;
  uint64_t final_tail = 0U;
  if (align_up(volume->data_tail, XAI_FS_BLOCK_SIZE, &catalog_offset) !=
          XAIOS_ENGINE_OK ||
      checked_add(catalog_offset, catalog_length, &catalog_end) !=
          XAIOS_ENGINE_OK ||
      align_up(catalog_end, XAI_FS_BLOCK_SIZE, &final_tail) !=
          XAIOS_ENGINE_OK ||
      final_tail > volume->volume_size) {
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
  encode_catalog_header(&next, next.catalog_generation, final_tail, header);
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
  encode_superblock(&next, next.generation, next.catalog_offset,
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

xaios_engine_status_t xaios_xai_fs_remove_staging(
    xaios_xai_fs_t *volume,
    const xaios_xai_fs_package_t *package,
    const xaios_xai_fs_writer_t *writer, void *scratch,
    size_t scratch_size, uint64_t *reclaimed_bytes) {
  return remove_package_in_state(
      volume, package, writer, scratch, scratch_size,
      XAIOS_XAI_FS_PACKAGE_STAGING, reclaimed_bytes);
}

xaios_engine_status_t xaios_xai_fs_remove_quarantined(
    xaios_xai_fs_t *volume,
    const xaios_xai_fs_package_t *package,
    const xaios_xai_fs_writer_t *writer, void *scratch,
    size_t scratch_size, uint64_t *reclaimed_bytes) {
  return remove_package_in_state(
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
  xaios_engine_status_t status = writer->flush(writer->context);
  if (status != XAIOS_ENGINE_OK) return status;
  uint8_t *io_scratch = (uint8_t *)scratch + 4096U;
  size_t io_scratch_size = scratch_size - 4096U;
  uint64_t ready = 0U;
  for (uint64_t relative = 0U; relative < package->chunk_count; ++relative) {
    xaios_xai_fs_chunk_t chunk;
    status = xaios_xai_fs_read_chunk(
        volume, package->chunk_start + relative, &chunk);
    if (status != XAIOS_ENGINE_OK) return status;
    int should_complete = 0;
    uint8_t learned_checksum[32];
    status = chunk_completion_status(volume, package, &chunk, offset, length,
                                     io_scratch, io_scratch_size,
                                     &should_complete, learned_checksum);
    if (status != XAIOS_ENGINE_OK) return status;
    if (should_complete) {
      ++ready;
    }
  }
  if (ready == 0U) return XAIOS_ENGINE_OK;

  uint64_t catalog_offset = 0U;
  uint64_t catalog_end = 0U;
  uint64_t final_tail = 0U;
  if (align_up(volume->data_tail, XAI_FS_BLOCK_SIZE, &catalog_offset) !=
          XAIOS_ENGINE_OK ||
      checked_add(catalog_offset, volume->catalog_length, &catalog_end) !=
          XAIOS_ENGINE_OK ||
      align_up(catalog_end, XAI_FS_BLOCK_SIZE, &final_tail) !=
          XAIOS_ENGINE_OK ||
      final_tail > volume->volume_size) {
    return XAIOS_ENGINE_ERR_CAPABILITY;
  }

  uint64_t catalog_generation = volume->catalog_generation + 1U;
  uint64_t generation = volume->generation + 1U;
  if (catalog_generation == 0U || generation == 0U) {
    return XAIOS_ENGINE_ERR_OVERFLOW;
  }
  uint8_t header[256];
  encode_catalog_header(volume, catalog_generation, final_tail, header);
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
    status = chunk_completion_status(volume, package, &chunk, offset, length,
                                     io_scratch, io_scratch_size,
                                     &should_complete, learned_checksum);
    if (status != XAIOS_ENGINE_OK) return status;
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
  status = writer->flush(writer->context);
  if (status != XAIOS_ENGINE_OK) return status;

  uint8_t *superblock = (uint8_t *)scratch;
  encode_superblock(volume, generation, catalog_offset, catalog_generation,
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
  uint64_t catalog_end = 0U;
  uint64_t final_tail = 0U;
  if (align_up(volume->data_tail, XAI_FS_BLOCK_SIZE, &catalog_offset) !=
          XAIOS_ENGINE_OK ||
      checked_add(catalog_offset, volume->catalog_length, &catalog_end) !=
          XAIOS_ENGINE_OK ||
      align_up(catalog_end, XAI_FS_BLOCK_SIZE, &final_tail) !=
          XAIOS_ENGINE_OK ||
      final_tail > volume->volume_size || volume->generation == UINT64_MAX ||
      volume->catalog_generation == UINT64_MAX) {
    return XAIOS_ENGINE_ERR_CAPABILITY;
  }
  uint64_t catalog_generation = volume->catalog_generation + 1U;
  uint64_t generation = volume->generation + 1U;
  uint8_t header[256];
  encode_catalog_header(volume, catalog_generation, final_tail, header);
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
  encode_superblock(volume, generation, catalog_offset, catalog_generation,
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
  uint64_t catalog_end = 0U;
  uint64_t final_tail = 0U;
  if (align_up(volume->data_tail, XAI_FS_BLOCK_SIZE, &catalog_offset) !=
          XAIOS_ENGINE_OK ||
      checked_add(catalog_offset, volume->catalog_length, &catalog_end) !=
          XAIOS_ENGINE_OK ||
      align_up(catalog_end, XAI_FS_BLOCK_SIZE, &final_tail) !=
          XAIOS_ENGINE_OK ||
      final_tail > volume->volume_size) {
    return XAIOS_ENGINE_ERR_CAPABILITY;
  }
  uint64_t catalog_generation = volume->catalog_generation + 1U;
  uint64_t generation = volume->generation + 1U;
  if (catalog_generation == 0U || generation == 0U) {
    return XAIOS_ENGINE_ERR_OVERFLOW;
  }

  uint8_t header[256];
  encode_catalog_header(volume, catalog_generation, final_tail, header);
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
  encode_superblock(volume, generation, catalog_offset, catalog_generation,
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
