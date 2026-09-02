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
  XAIOS_PACKED_IMPL_AVX2 = 3,
  XAIOS_PACKED_IMPL_SVE = 4
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
/* SVE2. Preferred over NEON where both exist, because its vector length is
   whatever the hardware has rather than fixed at 128 bits -- the same source
   runs wider on a machine that is wider. Availability is a runtime question
   and is answered by a differential check against the scalar reference, not
   by asking the CPU what it supports: a backend that is fast and wrong would
   pass every capability probe it was given. */
xaios_engine_status_t xaios_packed_gemv_sve(
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
/* The platform declares whether SVE may be executed at all; the engine then
   still has to prove the kernel agrees with the scalar reference before using
   it. Never declared means never attempted, which is the safe default: an SVE
   instruction on a CPU without SVE traps. */
void xaios_packed_declare_sve_supported(int supported);
int xaios_packed_sve_available(void);
int xaios_packed_avx2_available(void);

#endif
