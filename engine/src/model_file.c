#include <xaios_engine/model_file.h>

#include <string.h>

static int bytes_equal(const uint8_t *left, const uint8_t *right,
                       size_t length) {
  uint8_t difference = 0U;
  for (size_t index = 0U; index < length; ++index) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0U;
}

static int range_valid(uint64_t offset, uint64_t length, uint64_t limit) {
  return length != 0U && offset <= limit && length <= limit - offset;
}

static void metric_add(uint64_t *metric, uint64_t value) {
  *metric = value > UINT64_MAX - *metric ? UINT64_MAX : *metric + value;
}

static xaios_engine_status_t read_chunk(
    xaios_model_file_t *file, uint64_t relative,
    xaios_model_volume_chunk_t *chunk) {
  if (relative >= file->package.chunk_count ||
      file->package.chunk_start > UINT64_MAX - relative) {
    return XAIOS_ENGINE_ERR_OVERFLOW;
  }
  xaios_engine_status_t status = xaios_model_volume_read_chunk(
      file->volume, file->package.chunk_start + relative, chunk);
  if (status != XAIOS_ENGINE_OK ||
      chunk->record_id != file->package.record_id ||
      (chunk->flags & XAIOS_MODEL_VOLUME_CHUNK_FREE) != 0U) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  return XAIOS_ENGINE_OK;
}

static xaios_engine_status_t verification_bytes_for_range(
    xaios_model_file_t *file, uint64_t offset, uint64_t length,
    uint64_t *out_bytes) {
  uint64_t end = offset + length;
  uint64_t bytes = 0U;
  if (out_bytes == NULL) return XAIOS_ENGINE_ERR_INVALID;
  for (uint64_t relative = 0U; relative < file->package.chunk_count;
       ++relative) {
    xaios_model_volume_chunk_t chunk;
    if (read_chunk(file, relative, &chunk) != XAIOS_ENGINE_OK ||
        chunk.logical_offset > UINT64_MAX - chunk.length) {
      return XAIOS_ENGINE_ERR_INVALID;
    }
    uint64_t chunk_end = chunk.logical_offset + chunk.length;
    if (chunk_end <= offset || chunk.logical_offset >= end) continue;
    if (bytes > UINT64_MAX - chunk.length) {
      return XAIOS_ENGINE_ERR_OVERFLOW;
    }
    bytes += chunk.length;
  }
  *out_bytes = bytes;
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaios_model_file_open(
    const xaios_model_volume_t *volume, const uint8_t package_id[32],
    uint32_t allow_staging, xaios_model_file_t *file) {
  if (volume == NULL || package_id == NULL || file == NULL ||
      allow_staging > 1U) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  memset(file, 0, sizeof(*file));
  for (uint64_t index = 0U; index < volume->package_count; ++index) {
    xaios_model_volume_package_t package;
    xaios_engine_status_t status =
        xaios_model_volume_read_package(volume, index, &package);
    if (status != XAIOS_ENGINE_OK) return status;
    if (!bytes_equal(package.package_id, package_id, 32U)) continue;
    if (package.state != XAIOS_MODEL_VOLUME_PACKAGE_ACTIVE &&
        !(allow_staging != 0U &&
          package.state == XAIOS_MODEL_VOLUME_PACKAGE_STAGING)) {
      return XAIOS_ENGINE_ERR_CAPABILITY;
    }
    status = xaios_model_volume_verify_package_manifest(volume, &package);
    if (status != XAIOS_ENGINE_OK) return status;
    file->volume = volume;
    file->package = package;
    file->package_index = index;
    file->open = 1U;
    return XAIOS_ENGINE_OK;
  }
  return XAIOS_ENGINE_ERR_INVALID;
}

xaios_engine_status_t xaios_model_file_verify_range(
    xaios_model_file_t *file, uint64_t offset, uint64_t length,
    void *scratch, size_t scratch_size, uint64_t *bad_logical_offset) {
  if (file == NULL || file->open == 0U ||
      !range_valid(offset, length, file->package.logical_size)) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  xaios_engine_status_t status = xaios_model_volume_verify_range(
      file->volume, &file->package, offset, length, scratch, scratch_size,
      bad_logical_offset);
  if (status == XAIOS_ENGINE_OK) {
    uint64_t verified_bytes = 0U;
    status = verification_bytes_for_range(file, offset, length,
                                          &verified_bytes);
    if (status == XAIOS_ENGINE_OK) {
      metric_add(&file->metrics.verification_bytes, verified_bytes);
    }
  }
  if (status != XAIOS_ENGINE_OK) {
    metric_add(&file->metrics.failures, 1U);
  }
  return status;
}

xaios_engine_status_t xaios_model_file_pread(
    xaios_model_file_t *file, uint64_t offset, void *destination,
    size_t length, void *scratch, size_t scratch_size,
    uint64_t *bad_logical_offset) {
  if (file == NULL || file->open == 0U || destination == NULL || length == 0U ||
      !range_valid(offset, (uint64_t)length, file->package.logical_size)) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  metric_add(&file->metrics.read_calls, 1U);
  metric_add(&file->metrics.requested_bytes, (uint64_t)length);
  xaios_engine_status_t status = xaios_model_file_verify_range(
      file, offset, (uint64_t)length, scratch, scratch_size,
      bad_logical_offset);
  if (status != XAIOS_ENGINE_OK) return status;
  status = xaios_model_volume_pread(file->volume, &file->package, offset,
                                    destination, length);
  if (status == XAIOS_ENGINE_OK)
    metric_add(&file->metrics.delivered_bytes, (uint64_t)length);
  else
    metric_add(&file->metrics.failures, 1U);
  return status;
}

xaios_engine_status_t xaios_model_file_extent_map(
    xaios_model_file_t *file, xaios_model_file_extent_t *extents,
    uint64_t capacity, uint64_t *out_count) {
  if (file == NULL || file->open == 0U || out_count == NULL ||
      (capacity != 0U && extents == NULL)) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  *out_count = file->package.chunk_count;
  if (capacity < file->package.chunk_count) return XAIOS_ENGINE_ERR_CAPABILITY;
  for (uint64_t relative = 0U; relative < file->package.chunk_count;
       ++relative) {
    xaios_model_volume_chunk_t chunk;
    xaios_engine_status_t status = read_chunk(file, relative, &chunk);
    if (status != XAIOS_ENGINE_OK) return status;
    extents[relative].logical_offset = chunk.logical_offset;
    extents[relative].physical_offset = chunk.physical_offset;
    extents[relative].length = chunk.length;
    extents[relative].zero =
        (chunk.flags & XAIOS_MODEL_VOLUME_CHUNK_ZERO) != 0U;
  }
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaios_model_file_prefetch(
    xaios_model_file_t *file, uint64_t offset, uint64_t length,
    xaios_model_file_prefetch_fn prefetch, void *context) {
  if (file == NULL || file->open == 0U || prefetch == NULL ||
      !range_valid(offset, length, file->package.logical_size)) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  uint64_t end = offset + length;
  for (uint64_t relative = 0U; relative < file->package.chunk_count;
       ++relative) {
    xaios_model_volume_chunk_t chunk;
    xaios_engine_status_t status = read_chunk(file, relative, &chunk);
    if (status != XAIOS_ENGINE_OK) return status;
    if (chunk.logical_offset > UINT64_MAX - chunk.length) {
      return XAIOS_ENGINE_ERR_OVERFLOW;
    }
    uint64_t chunk_end = chunk.logical_offset + chunk.length;
    if (chunk_end <= offset || chunk.logical_offset >= end ||
        (chunk.flags & XAIOS_MODEL_VOLUME_CHUNK_ZERO) != 0U) {
      continue;
    }
    uint64_t logical_start = offset > chunk.logical_offset
                                 ? offset
                                 : chunk.logical_offset;
    uint64_t logical_end = end < chunk_end ? end : chunk_end;
    uint64_t within = logical_start - chunk.logical_offset;
    if (chunk.physical_offset > UINT64_MAX - within) {
      return XAIOS_ENGINE_ERR_OVERFLOW;
    }
    uint64_t physical = chunk.physical_offset + within;
    uint64_t count = logical_end - logical_start;
    status = prefetch(context, physical, count);
    if (status != XAIOS_ENGINE_OK) {
      metric_add(&file->metrics.failures, 1U);
      return status;
    }
    metric_add(&file->metrics.prefetch_calls, 1U);
    metric_add(&file->metrics.prefetched_bytes, count);
  }
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaios_model_file_read_into_arena(
    xaios_model_file_t *file, uint64_t offset, void *destination,
    size_t length, uint64_t required_alignment, void *scratch,
    size_t scratch_size, uint64_t *bad_logical_offset) {
  if (required_alignment == 0U ||
      (required_alignment & (required_alignment - 1U)) != 0U ||
      destination == NULL ||
      ((uint64_t)(uintptr_t)destination & (required_alignment - 1U)) != 0U) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  return xaios_model_file_pread(file, offset, destination, length, scratch,
                                scratch_size, bad_logical_offset);
}

void xaios_model_file_close(xaios_model_file_t *file) {
  if (file != NULL) memset(file, 0, sizeof(*file));
}
