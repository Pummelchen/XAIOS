#ifndef XAIOS_ENGINE_PACKED_H
#define XAIOS_ENGINE_PACKED_H

#include <stddef.h>
#include <stdint.h>

#include <xaios_engine/model_v2.h>

typedef enum xaios_packed_dtype {
  XAIOS_PACKED_INT4 = 1,
  XAIOS_PACKED_INT6 = 2
} xaios_packed_dtype_t;

typedef enum xaios_packed_implementation {
  XAIOS_PACKED_IMPL_SCALAR = 1,
  XAIOS_PACKED_IMPL_NEON = 2,
  XAIOS_PACKED_IMPL_AVX2 = 3
} xaios_packed_implementation_t;

typedef struct xaios_packed_matrix {
  const uint8_t *data;
  uint64_t data_size;
  const float *scales;
  uint64_t scale_count;
  uint64_t rows;
  uint64_t columns;
  uint64_t group_size;
  xaios_packed_dtype_t dtype;
} xaios_packed_matrix_t;

xaios_engine_status_t xaios_packed_matrix_required_bytes(
    uint64_t element_count, xaios_packed_dtype_t dtype,
    uint64_t *required_bytes);
xaios_engine_status_t xaios_packed_matrix_validate(
    const xaios_packed_matrix_t *matrix);
xaios_engine_status_t xaios_packed_gemv_scalar(
    const xaios_packed_matrix_t *matrix, const float *input, float *output);
xaios_engine_status_t xaios_packed_gemv_neon(
    const xaios_packed_matrix_t *matrix, const float *input, float *output);
xaios_engine_status_t xaios_packed_gemv_avx2(
    const xaios_packed_matrix_t *matrix, const float *input, float *output);
xaios_engine_status_t xaios_packed_gemv(
    const xaios_packed_matrix_t *matrix, const float *input, float *output,
    xaios_packed_implementation_t *implementation);
xaios_engine_status_t xaios_packed_gemm_scalar(
    const xaios_packed_matrix_t *matrix, const float *input,
    uint64_t input_rows, uint64_t input_stride, float *output,
    uint64_t output_stride);
xaios_engine_status_t xaios_packed_gemm(
    const xaios_packed_matrix_t *matrix, const float *input,
    uint64_t input_rows, uint64_t input_stride, float *output,
    uint64_t output_stride, xaios_packed_implementation_t *implementation);
int xaios_packed_neon_available(void);
int xaios_packed_avx2_available(void);

#endif
