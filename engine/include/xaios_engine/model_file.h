#ifndef XAIOS_ENGINE_MODEL_FILE_H
#define XAIOS_ENGINE_MODEL_FILE_H

#include <stddef.h>
#include <stdint.h>

#include <xaios_engine/model_volume.h>

typedef xaios_engine_status_t (*xaios_model_file_prefetch_fn)(
    void *context, uint64_t physical_offset, uint64_t length);

typedef struct xaios_model_file_extent {
  uint64_t logical_offset;
  uint64_t physical_offset;
  uint64_t length;
  uint32_t zero;
} xaios_model_file_extent_t;

typedef struct xaios_model_file_metrics {
  uint64_t read_calls;
  uint64_t requested_bytes;
  uint64_t delivered_bytes;
  uint64_t verification_bytes;
  uint64_t prefetch_calls;
  uint64_t prefetched_bytes;
  uint64_t failures;
} xaios_model_file_metrics_t;

typedef struct xaios_model_file {
  const xaios_model_volume_t *volume;
  xaios_model_volume_package_t package;
  uint64_t package_index;
  xaios_model_file_metrics_t metrics;
  uint32_t open;
} xaios_model_file_t;

xaios_engine_status_t xaios_model_file_open(
    const xaios_model_volume_t *volume, const uint8_t package_id[32],
    uint32_t allow_staging, xaios_model_file_t *file);
xaios_engine_status_t xaios_model_file_pread(
    xaios_model_file_t *file, uint64_t offset, void *destination,
    size_t length, void *scratch, size_t scratch_size,
    uint64_t *bad_logical_offset);
xaios_engine_status_t xaios_model_file_verify_range(
    xaios_model_file_t *file, uint64_t offset, uint64_t length,
    void *scratch, size_t scratch_size, uint64_t *bad_logical_offset);
xaios_engine_status_t xaios_model_file_extent_map(
    xaios_model_file_t *file, xaios_model_file_extent_t *extents,
    uint64_t capacity, uint64_t *out_count);
xaios_engine_status_t xaios_model_file_prefetch(
    xaios_model_file_t *file, uint64_t offset, uint64_t length,
    xaios_model_file_prefetch_fn prefetch, void *context);
xaios_engine_status_t xaios_model_file_read_into_arena(
    xaios_model_file_t *file, uint64_t offset, void *destination,
    size_t length, uint64_t required_alignment, void *scratch,
    size_t scratch_size, uint64_t *bad_logical_offset);
void xaios_model_file_close(xaios_model_file_t *file);

#endif
