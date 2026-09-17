/* The xaiFS reader's byte codec and checked arithmetic.
 *
 * Split out of `xai_fs.c` unchanged apart from the `xai_fs_codec_` prefix the
 * shared header explains. `xai_fs.c` (the volume open/probe path) and
 * `xai_fs_read.c` (the verify/read path) are its only callers.
 */

#include <xaios_engine/xai_fs.h>

#include "sha256.h"
#include "xai_fs_codec.h"

uint16_t xai_fs_codec_load_le16(const uint8_t *value) {
  return (uint16_t)value[0] | ((uint16_t)value[1] << 8U);
}

uint32_t xai_fs_codec_load_le32(const uint8_t *value) {
  return (uint32_t)value[0] | ((uint32_t)value[1] << 8U) |
         ((uint32_t)value[2] << 16U) | ((uint32_t)value[3] << 24U);
}

uint64_t xai_fs_codec_load_le64(const uint8_t *value) {
  uint64_t result = 0U;
  for (uint32_t index = 0U; index < 8U; ++index) {
    result |= (uint64_t)value[index] << (index * 8U);
  }
  return result;
}

void xai_fs_codec_store_le32(uint8_t output[4], uint32_t value) {
  for (uint32_t index = 0U; index < 4U; ++index) {
    output[index] = (uint8_t)(value >> (index * 8U));
  }
}

void xai_fs_codec_store_le64(uint8_t output[8], uint64_t value) {
  for (uint32_t index = 0U; index < 8U; ++index) {
    output[index] = (uint8_t)(value >> (index * 8U));
  }
}

int xai_fs_codec_bytes_zero(const uint8_t *bytes, size_t length) {
  uint8_t combined = 0U;
  for (size_t index = 0U; index < length; ++index) combined |= bytes[index];
  return combined == 0U;
}

int xai_fs_codec_power_of_two(uint64_t value) {
  return value != 0U && (value & (value - 1U)) == 0U;
}

xaios_engine_status_t xai_fs_codec_checked_add(uint64_t left, uint64_t right,
                                         uint64_t *result) {
  if (right > UINT64_MAX - left) return XAIOS_ENGINE_ERR_OVERFLOW;
  *result = left + right;
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xai_fs_codec_checked_multiply(uint64_t left, uint64_t right,
                                              uint64_t *result) {
  if (left != 0U && right > UINT64_MAX / left) {
    return XAIOS_ENGINE_ERR_OVERFLOW;
  }
  *result = left * right;
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xai_fs_codec_range_valid(uint64_t offset, uint64_t length,
                                         uint64_t limit) {
  uint64_t end = 0U;
  if (xai_fs_codec_checked_add(offset, length, &end) != XAIOS_ENGINE_OK || end > limit) {
    return XAIOS_ENGINE_ERR_OVERFLOW;
  }
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xai_fs_codec_read_exact(
    const xaios_xai_fs_reader_t *reader, uint64_t offset,
    void *destination, size_t length) {
  if (reader == NULL || reader->read_at == NULL || destination == NULL ||
      length == 0U || xai_fs_codec_range_valid(offset, (uint64_t)length, reader->size) !=
                          XAIOS_ENGINE_OK) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  return reader->read_at(reader->context, offset, destination, length);
}

void xai_fs_codec_sha256(const void *data, size_t length, uint8_t digest[32]) {
  xaios_engine_sha256_context_t context;
  xaios_engine_sha256_init(&context);
  xaios_engine_sha256_update(&context, data, length);
  xaios_engine_sha256_final(&context, digest);
}

xaios_engine_status_t xai_fs_codec_hash_reader_range(
    const xaios_xai_fs_reader_t *reader, uint64_t offset,
    uint64_t length, void *scratch, size_t scratch_size, uint8_t digest[32]) {
  if (scratch == NULL || scratch_size == 0U ||
      xai_fs_codec_range_valid(offset, length, reader->size) != XAIOS_ENGINE_OK) {
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
    xaios_engine_status_t status =
        xai_fs_codec_read_exact(reader, offset + completed, scratch, count);
    if (status != XAIOS_ENGINE_OK) return status;
    xaios_engine_sha256_update(&context, scratch, count);
    completed += (uint64_t)count;
  }
  xaios_engine_sha256_final(&context, digest);
  return XAIOS_ENGINE_OK;
}
