#include <xaios_engine/backend.h>

#include <stddef.h>

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#define XAIOS_BACKEND_HAS_X86_64 1
#else
#define XAIOS_BACKEND_HAS_X86_64 0
#endif

static xaios_engine_status_t unsupported_prepare(
    const xaios_model_v2_package_t *package,
    xaios_backend_context_t **context) {
  if (package == NULL || context == NULL) return XAIOS_ENGINE_ERR_INVALID;
  *context = NULL;
  return XAIOS_ENGINE_ERR_UNSUPPORTED;
}

static xaios_engine_status_t unsupported_select_layout(
    const xaios_model_v2_package_t *package,
    const xaios_model_v2_tensor_t *tensor, uint32_t *layout_id) {
  if (package == NULL || tensor == NULL || layout_id == NULL) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  *layout_id = 0U;
  return XAIOS_ENGINE_ERR_UNSUPPORTED;
}

static xaios_engine_status_t unsupported_execute(
    xaios_backend_context_t *context) {
  (void)context;
  return XAIOS_ENGINE_ERR_UNSUPPORTED;
}

static xaios_engine_status_t unsupported_verify(
    xaios_backend_context_t *context, uint64_t position_count) {
  (void)context;
  return position_count == 0U ? XAIOS_ENGINE_ERR_INVALID
                              : XAIOS_ENGINE_ERR_UNSUPPORTED;
}

#if XAIOS_BACKEND_HAS_X86_64
__attribute__((target("avx2")))
static xaios_engine_status_t avx2_dense_projection_impl(
    const float *input, const float *weights, const float *bias, float *output,
    uint64_t rows, uint64_t columns) {
  for (uint64_t row = 0U; row < rows; ++row) {
    __m256 accumulator = _mm256_setzero_ps();
    uint64_t column = 0U;
    for (; columns - column >= 8U; column += 8U) {
      accumulator = _mm256_add_ps(
          accumulator,
          _mm256_mul_ps(_mm256_loadu_ps(weights + row * columns + column),
                        _mm256_loadu_ps(input + column)));
    }
    float lanes[8];
    _mm256_storeu_ps(lanes, accumulator);
    float sum = bias == NULL ? 0.0f : bias[row];
    for (uint32_t lane = 0U; lane < 8U; ++lane) sum += lanes[lane];
    for (; column < columns; ++column) {
      sum += weights[row * columns + column] * input[column];
    }
    output[row] = sum;
  }
  return XAIOS_ENGINE_OK;
}
#endif

static xaios_engine_status_t avx2_dense_projection(
    const float *input, const float *weights, const float *bias, float *output,
    uint64_t rows, uint64_t columns) {
  if (input == NULL || weights == NULL || output == NULL || rows == 0U ||
      columns == 0U) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  if (rows > UINT64_MAX / columns) return XAIOS_ENGINE_ERR_OVERFLOW;
#if XAIOS_BACKEND_HAS_X86_64
  if (!xaios_packed_avx2_available()) return XAIOS_ENGINE_ERR_UNSUPPORTED;
  return avx2_dense_projection_impl(input, weights, bias, output, rows,
                                    columns);
#else
  (void)bias;
  return XAIOS_ENGINE_ERR_UNSUPPORTED;
#endif
}

static xaios_engine_status_t avx2_packed_gemv(
    const xaios_packed_matrix_t *matrix, const float *input, float *output) {
  return xaios_packed_gemv_avx2(matrix, input, output);
}

static xaios_engine_status_t avx2_packed_gemm(
    const xaios_packed_matrix_t *matrix, const float *input,
    uint64_t input_rows, uint64_t input_stride, float *output,
    uint64_t output_stride) {
  if (!xaios_packed_avx2_available()) return XAIOS_ENGINE_ERR_UNSUPPORTED;
  if (matrix == NULL || input == NULL || output == NULL || input_rows == 0U ||
      input_stride < matrix->columns || output_stride < matrix->rows) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  if (input_rows > 1U &&
      (input_stride > UINT64_MAX / (input_rows - 1U) ||
       output_stride > UINT64_MAX / (input_rows - 1U))) {
    return XAIOS_ENGINE_ERR_OVERFLOW;
  }
  for (uint64_t row = 0U; row < input_rows; ++row) {
    xaios_engine_status_t status = xaios_packed_gemv_avx2(
        matrix, input + row * input_stride, output + row * output_stride);
    if (status != XAIOS_ENGINE_OK) return status;
  }
  return XAIOS_ENGINE_OK;
}

static xaios_engine_status_t avx2_validate(void) {
  if (!xaios_packed_avx2_available()) return XAIOS_ENGINE_ERR_CAPABILITY;
  static const float input[9] = {1.0f, -2.0f, 0.5f, 3.0f, -1.0f,
                                 2.0f, 0.25f, -0.5f, 4.0f};
  static const float weights[9] = {2.0f, 1.0f, 4.0f, -1.0f, 0.5f,
                                   3.0f, -2.0f, 1.0f, 0.25f};
  float output = 0.0f;
  xaios_engine_status_t status =
      avx2_dense_projection(input, weights, NULL, &output, 1U, 9U);
  return status == XAIOS_ENGINE_OK && output == 4.5f
             ? XAIOS_ENGINE_OK
             : XAIOS_ENGINE_ERR_CAPABILITY;
}

static uint64_t avx2_probe_capabilities(void) {
  return avx2_validate() == XAIOS_ENGINE_OK
             ? XAIOS_BACKEND_CAP_SCALAR | XAIOS_BACKEND_CAP_AVX2
             : 0U;
}

static uint64_t avx2_scratch_size(const xaios_model_v2_package_t *package) {
  (void)package;
  return 0U;
}

static void avx2_synchronize(xaios_backend_context_t *context) {
  (void)context;
}

static void avx2_destroy(xaios_backend_context_t *context) {
  (void)context;
}

static const xaios_backend_t k_avx2_backend = {
    "x86-avx2-experimental",
    XAIOS_BACKEND_CAP_SCALAR | XAIOS_BACKEND_CAP_AVX2,
    avx2_probe_capabilities,
    avx2_validate,
    unsupported_select_layout,
    unsupported_prepare,
    unsupported_execute,
    unsupported_execute,
    unsupported_verify,
    avx2_dense_projection,
    avx2_packed_gemv,
    avx2_packed_gemm,
    unsupported_execute,
    unsupported_execute,
    unsupported_execute,
    unsupported_execute,
    avx2_scratch_size,
    avx2_synchronize,
    avx2_destroy};

const xaios_backend_t *xaios_backend_avx2(void) {
  return avx2_validate() == XAIOS_ENGINE_OK ? &k_avx2_backend : NULL;
}
