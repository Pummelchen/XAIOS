#include <xaios_engine/backend.h>

#include <stddef.h>

#if defined(__aarch64__) && defined(__ARM_NEON)
#include <arm_neon.h>
#define XAIOS_BACKEND_HAS_NEON 1
#else
#define XAIOS_BACKEND_HAS_NEON 0
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

static xaios_engine_status_t neon_dense_projection(
    const float *input, const float *weights, const float *bias, float *output,
    uint64_t rows, uint64_t columns) {
#if XAIOS_BACKEND_HAS_NEON
  if (input == NULL || weights == NULL || output == NULL || rows == 0U ||
      columns == 0U) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  if (rows > UINT64_MAX / columns) return XAIOS_ENGINE_ERR_OVERFLOW;
  for (uint64_t row = 0U; row < rows; ++row) {
    float32x4_t accumulator = vdupq_n_f32(0.0f);
    uint64_t column = 0U;
    for (; columns - column >= 4U; column += 4U) {
      accumulator = vfmaq_f32(
          accumulator, vld1q_f32(weights + row * columns + column),
          vld1q_f32(input + column));
    }
    float sum = vaddvq_f32(accumulator);
    for (; column < columns; ++column) {
      sum += weights[row * columns + column] * input[column];
    }
    output[row] = sum + (bias == NULL ? 0.0f : bias[row]);
  }
  return XAIOS_ENGINE_OK;
#else
  (void)input;
  (void)weights;
  (void)bias;
  (void)output;
  (void)rows;
  (void)columns;
  return XAIOS_ENGINE_ERR_UNSUPPORTED;
#endif
}

static xaios_engine_status_t neon_packed_gemv(
    const xaios_packed_matrix_t *matrix, const float *input, float *output) {
  return xaios_packed_neon_available()
             ? xaios_packed_gemv_neon(matrix, input, output)
             : XAIOS_ENGINE_ERR_UNSUPPORTED;
}

static xaios_engine_status_t neon_packed_gemm(
    const xaios_packed_matrix_t *matrix, const float *input,
    uint64_t input_rows, uint64_t input_stride, float *output,
    uint64_t output_stride) {
  if (!xaios_packed_neon_available()) return XAIOS_ENGINE_ERR_UNSUPPORTED;
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
    xaios_engine_status_t status = xaios_packed_gemv_neon(
        matrix, input + row * input_stride, output + row * output_stride);
    if (status != XAIOS_ENGINE_OK) return status;
  }
  return XAIOS_ENGINE_OK;
}

static xaios_engine_status_t neon_validate(void) {
  if (!xaios_packed_neon_available()) return XAIOS_ENGINE_ERR_CAPABILITY;
  static const float input[5] = {1.0f, -2.0f, 0.5f, 3.0f, -1.0f};
  static const float weights[5] = {2.0f, 1.0f, 4.0f, -1.0f, 0.5f};
  float output = 0.0f;
  xaios_engine_status_t status =
      neon_dense_projection(input, weights, NULL, &output, 1U, 5U);
  return status == XAIOS_ENGINE_OK && output == -1.5f
             ? XAIOS_ENGINE_OK
             : XAIOS_ENGINE_ERR_CAPABILITY;
}

static uint64_t neon_probe_capabilities(void) {
  return neon_validate() == XAIOS_ENGINE_OK
             ? XAIOS_BACKEND_CAP_SCALAR | XAIOS_BACKEND_CAP_NEON
             : 0U;
}

static uint64_t neon_scratch_size(const xaios_model_v2_package_t *package) {
  (void)package;
  return 0U;
}

static void neon_synchronize(xaios_backend_context_t *context) {
  (void)context;
}

static void neon_destroy(xaios_backend_context_t *context) {
  (void)context;
}

static const xaios_backend_t k_neon_backend = {
    "aarch64-neon-experimental",
    XAIOS_BACKEND_CAP_SCALAR | XAIOS_BACKEND_CAP_NEON,
    neon_probe_capabilities,
    neon_validate,
    unsupported_select_layout,
    unsupported_prepare,
    unsupported_execute,
    unsupported_execute,
    unsupported_verify,
    neon_dense_projection,
    neon_packed_gemv,
    neon_packed_gemm,
    unsupported_execute,
    unsupported_execute,
    unsupported_execute,
    unsupported_execute,
    neon_scratch_size,
    neon_synchronize,
    neon_destroy};

const xaios_backend_t *xaios_backend_neon(void) {
  return neon_validate() == XAIOS_ENGINE_OK ? &k_neon_backend : NULL;
}
