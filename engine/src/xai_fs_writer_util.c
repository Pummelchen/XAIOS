/* The xaiFS writer's helpers: little-endian codecs, checked arithmetic, the
 * record encoders and the chunk-completion check.
 *
 * Split out of `xai_fs_writer.c` unchanged. The writer's entry points still
 * call these; `xai_fs_writer_internal.h` is the seam. `valid_chunk_size` did
 * not come along because it reads the two chunk-size bounds, which
 * `tests/repository/check-xai-fs-chunk-bounds.py` compares by reading them out
 * of `xai_fs_writer.c` -- see that header.
 */

#include <xaios_engine/xai_fs.h>

#include <string.h>

#include "sha256.h"
#include "xai_fs_writer_internal.h"

void store_le16(uint8_t output[2], uint16_t value) {
  output[0] = (uint8_t)value;
  output[1] = (uint8_t)(value >> 8U);
}

void store_le32(uint8_t output[4], uint32_t value) {
  for (uint32_t index = 0U; index < 4U; ++index) {
    output[index] = (uint8_t)(value >> (index * 8U));
  }
}

void store_le64(uint8_t output[8], uint64_t value) {
  for (uint32_t index = 0U; index < 8U; ++index) {
    output[index] = (uint8_t)(value >> (index * 8U));
  }
}

xaios_engine_status_t checked_add(uint64_t left, uint64_t right,
                                         uint64_t *result) {
  if (result == NULL || right > UINT64_MAX - left) {
    return XAIOS_ENGINE_ERR_OVERFLOW;
  }
  *result = left + right;
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t checked_multiply(uint64_t left, uint64_t right,
                                              uint64_t *result) {
  if (result == NULL || (left != 0U && right > UINT64_MAX / left)) {
    return XAIOS_ENGINE_ERR_OVERFLOW;
  }
  *result = left * right;
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t align_up(uint64_t value, uint64_t alignment,
                                      uint64_t *result) {
  uint64_t adjusted = 0U;
  if (alignment == 0U || (alignment & (alignment - 1U)) != 0U ||
      checked_add(value, alignment - 1U, &adjusted) != XAIOS_ENGINE_OK) {
    return XAIOS_ENGINE_ERR_OVERFLOW;
  }
  *result = adjusted & ~(alignment - 1U);
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t read_exact(
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

xaios_engine_status_t write_exact(
    const xaios_xai_fs_writer_t *writer, uint64_t offset,
    const void *source, size_t length) {
  if (writer == NULL || writer->write_at == NULL || source == NULL ||
      length == 0U) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  return writer->write_at(writer->context, offset, source, length);
}

void sha256(const void *data, size_t length, uint8_t digest[32]) {
  xaios_engine_sha256_context_t context;
  xaios_engine_sha256_init(&context);
  xaios_engine_sha256_update(&context, data, length);
  xaios_engine_sha256_final(&context, digest);
}

int ranges_intersect(uint64_t first_offset, uint64_t first_length,
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

int valid_uuid(const uint8_t uuid[16]) {
  if (uuid == NULL) return 0;
  uint8_t combined = 0U;
  for (size_t index = 0U; index < 16U; ++index) combined |= uuid[index];
  return combined != 0U;
}

int bytes_nonzero(const uint8_t *bytes, size_t length) {
  uint8_t combined = 0U;
  if (bytes == NULL) return 0;
  for (size_t index = 0U; index < length; ++index) combined |= bytes[index];
  return combined != 0U;
}

int valid_ascii(const char value[33]) {
  if (value == NULL) return 0;
  for (size_t index = 0U; index < 33U; ++index) {
    uint8_t byte = (uint8_t)value[index];
    if (byte == 0U) return index != 0U;
    if (index == 32U || byte < 0x20U || byte > 0x7eU) return 0;
  }
  return 0;
}

int valid_target(const char *target) {
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

void encode_package_record(
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

void encode_chunk_record(const xaios_xai_fs_chunk_t *chunk,
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

xaios_engine_status_t chunk_completion_status(
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
