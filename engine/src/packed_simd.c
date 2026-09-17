#include "packed_internal.h"

/* The architecture kernels, split out of packed.c. They all call the same
   integer codecs and group arithmetic, which live in packed.c and are
   declared in packed_internal.h; the arithmetic inside each loop is
   unchanged, so the scalar reference and the accelerated paths still agree
   bit for bit. Each kernel keeps its public name and signature from
   packed.h. */

#if XAIOS_PACKED_HAS_SVE
__attribute__((target("+sve2")))
#endif
xaios_engine_status_t xaios_packed_gemv_sve(
    const xaios_packed_matrix_t *matrix, const float *input, float *output) {
#if XAIOS_PACKED_HAS_SVE
  xaios_engine_status_t status = xaios_packed_matrix_validate(matrix);
  if (status != XAIOS_ENGINE_OK || input == NULL || output == NULL) {
    return status == XAIOS_ENGINE_OK ? XAIOS_ENGINE_ERR_INVALID : status;
  }
  uint64_t groups = xaios_packed_group_count(matrix);
  for (uint64_t row = 0U; row < matrix->rows; ++row) {
    float sum = 0.0f;
    for (uint64_t group = 0U; group < groups; ++group) {
      uint64_t start = group * matrix->group_size;
      uint64_t end = start + matrix->group_size;
      if (end < start || end > matrix->columns) end = matrix->columns;
      float scale = matrix->scales[row * groups + group];
      svfloat32_t accumulator = svdup_f32(0.0f);
      /* No tail loop, and that is the point of the instruction set rather
         than a shortcut. svwhilelt builds a predicate that is true only for
         the lanes still inside the row, so the final iteration processes a
         partial vector instead of needing a scalar remainder written
         separately -- which is where a hand-written tail and its main loop
         drift apart and produce two answers. */
      for (uint64_t column = start; column < end;
           column += svcntw()) {
        svbool_t active = svwhilelt_b32((uint64_t)column, end);
        /* The weights are unpacked to int32 through memory rather than with
           a gather. They are 4 or 6 bits packed across byte boundaries, so
           there is no lane-aligned load that recovers them; doing the
           unpacking in scalar code and loading the result keeps this kernel
           bit-identical to the reference by construction. */
        int32_t lanes[256];
        uint64_t width = svcntw();
        if (width > (uint64_t)(sizeof(lanes) / sizeof(lanes[0]))) {
          /* A vector wider than this buffer is possible in principle -- the
             architecture allows up to 2048 bits, which is 64 words, but a
             future one could go further. Refusing is correct; guessing is
             not. */
          return XAIOS_ENGINE_ERR_UNSUPPORTED;
        }
        for (uint64_t lane = 0U; lane < width; ++lane) {
          uint64_t column_index = column + lane;
          lanes[lane] = column_index < end
                            ? xaios_packed_unpack_weight(
                                  matrix,
                                  row * matrix->columns + column_index)
                            : 0;
        }
        svfloat32_t weights =
            svmul_n_f32_x(active, svcvt_f32_s32_x(active,
                                                  svld1_s32(active, lanes)),
                          scale);
        /* Merging, not "don't care", and not because anything caught it.
           The _x forms leave inactive lanes architecturally undefined, which
           is free when the result is consumed under the same predicate. This
           accumulator is not: svaddv below sums the whole vector, so a lane
           left undefined by the final partial iteration is added to the
           total. _m keeps those lanes as they were.
           Worth being exact about the evidence, because the tempting story is
           wrong: this was *not* what the differential check rejected. Built
           with _x the check passes here -- QEMU's inactive lanes come back
           usable. That is the argument for _m rather than against it. Code
           that depends on undefined lanes and happens to work on one
           implementation is a latent bug, not a working kernel, and the only
           reason it looks fine is that nothing has disagreed yet. */
        accumulator = svmla_f32_m(active, accumulator,
                                  svld1_f32(active, input + column), weights);
      }
      sum += svaddv_f32(svptrue_b32(), accumulator);
    }
    output[row] = sum;
  }
  return XAIOS_ENGINE_OK;
#else
  (void)matrix;
  (void)input;
  (void)output;
  return XAIOS_ENGINE_ERR_UNSUPPORTED;
#endif
}

xaios_engine_status_t xaios_packed_gemv_neon(
    const xaios_packed_matrix_t *matrix, const float *input, float *output) {
#if XAIOS_PACKED_HAS_NEON
  xaios_engine_status_t status = xaios_packed_matrix_validate(matrix);
  if (status != XAIOS_ENGINE_OK || input == NULL || output == NULL) {
    return status == XAIOS_ENGINE_OK ? XAIOS_ENGINE_ERR_INVALID : status;
  }
  uint64_t groups = xaios_packed_group_count(matrix);
  for (uint64_t row = 0U; row < matrix->rows; ++row) {
    float sum = 0.0f;
    for (uint64_t group = 0U; group < groups; ++group) {
      uint64_t start = group * matrix->group_size;
      uint64_t end = start + matrix->group_size;
      if (end < start || end > matrix->columns) end = matrix->columns;
      float32x4_t accumulator = vdupq_n_f32(0.0f);
      float scale = matrix->scales[row * groups + group];
      uint64_t column = start;
      for (; end - column >= 4U; column += 4U) {
        int32_t lanes[4];
        for (uint32_t lane = 0U; lane < 4U; ++lane) {
          uint64_t index = row * matrix->columns + column + lane;
          lanes[lane] = xaios_packed_unpack_weight(matrix, index);
        }
        float32x4_t weights =
            vmulq_n_f32(vcvtq_f32_s32(vld1q_s32(lanes)), scale);
        accumulator = vfmaq_f32(accumulator, vld1q_f32(input + column),
                                weights);
      }
      sum += vaddvq_f32(accumulator);
      for (; column < end; ++column) {
        uint64_t index = row * matrix->columns + column;
        sum += (float)xaios_packed_unpack_weight(matrix, index) * scale *
               input[column];
      }
    }
    output[row] = sum;
  }
  return XAIOS_ENGINE_OK;
#else
  (void)matrix;
  (void)input;
  (void)output;
  return XAIOS_ENGINE_ERR_UNSUPPORTED;
#endif
}

#if XAIOS_PACKED_HAS_X86_64
__attribute__((target("avx2")))
static xaios_engine_status_t packed_gemv_avx2_impl(
    const xaios_packed_matrix_t *matrix, const float *input, float *output) {
  uint64_t groups = xaios_packed_group_count(matrix);
  for (uint64_t row = 0U; row < matrix->rows; ++row) {
    float sum = 0.0f;
    for (uint64_t group = 0U; group < groups; ++group) {
      uint64_t start = group * matrix->group_size;
      uint64_t end = start + matrix->group_size;
      if (end < start || end > matrix->columns) end = matrix->columns;
      __m256 accumulator = _mm256_setzero_ps();
      __m256 scale = _mm256_set1_ps(matrix->scales[row * groups + group]);
      uint64_t column = start;
      for (; end - column >= 8U; column += 8U) {
        int32_t lanes[8];
        for (uint32_t lane = 0U; lane < 8U; ++lane) {
          uint64_t index = row * matrix->columns + column + lane;
          lanes[lane] = xaios_packed_unpack_weight(matrix, index);
        }
        __m256 weights = _mm256_mul_ps(
            _mm256_cvtepi32_ps(
                _mm256_loadu_si256((const __m256i *)(const void *)lanes)),
            scale);
        accumulator = _mm256_add_ps(
            accumulator,
            _mm256_mul_ps(weights, _mm256_loadu_ps(input + column)));
      }
      float partial[8];
      _mm256_storeu_ps(partial, accumulator);
      for (uint32_t lane = 0U; lane < 8U; ++lane) sum += partial[lane];
      float scalar_scale = matrix->scales[row * groups + group];
      for (; column < end; ++column) {
        uint64_t index = row * matrix->columns + column;
        sum += (float)xaios_packed_unpack_weight(matrix, index) *
               scalar_scale * input[column];
      }
    }
    output[row] = sum;
  }
  return XAIOS_ENGINE_OK;
}
#endif

xaios_engine_status_t xaios_packed_gemv_avx2(
    const xaios_packed_matrix_t *matrix, const float *input, float *output) {
#if XAIOS_PACKED_HAS_X86_64
  xaios_engine_status_t status = xaios_packed_matrix_validate(matrix);
  if (status != XAIOS_ENGINE_OK || input == NULL || output == NULL) {
    return status == XAIOS_ENGINE_OK ? XAIOS_ENGINE_ERR_INVALID : status;
  }
  if (!xaios_packed_x86_avx2_usable()) return XAIOS_ENGINE_ERR_UNSUPPORTED;
  return packed_gemv_avx2_impl(matrix, input, output);
#else
  (void)matrix;
  (void)input;
  (void)output;
  return XAIOS_ENGINE_ERR_UNSUPPORTED;
#endif
}
