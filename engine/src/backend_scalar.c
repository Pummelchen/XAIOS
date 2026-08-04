#include <xaios_engine/backend.h>

#include <stddef.h>

static xaios_engine_status_t unsupported_prepare(
    const xaios_model_v2_package_t *package,
    xaios_backend_context_t **context) {
  if (package == NULL || context == NULL) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
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

static xaios_engine_status_t scalar_dense_projection(
    const float *input, const float *weights, const float *bias, float *output,
    uint64_t rows, uint64_t columns) {
  if (input == NULL || weights == NULL || output == NULL || rows == 0U ||
      columns == 0U) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  if (rows > UINT64_MAX / columns) {
    return XAIOS_ENGINE_ERR_OVERFLOW;
  }
  for (uint64_t row = 0; row < rows; ++row) {
    float sum = bias == NULL ? 0.0f : bias[row];
    for (uint64_t column = 0; column < columns; ++column) {
      sum += weights[(row * columns) + column] * input[column];
    }
    output[row] = sum;
  }
  return XAIOS_ENGINE_OK;
}

static xaios_engine_status_t scalar_packed_gemv(
    const xaios_packed_matrix_t *matrix, const float *input, float *output) {
  return xaios_packed_gemv_scalar(matrix, input, output);
}

static xaios_engine_status_t scalar_packed_gemm(
    const xaios_packed_matrix_t *matrix, const float *input,
    uint64_t input_rows, uint64_t input_stride, float *output,
    uint64_t output_stride) {
  return xaios_packed_gemm_scalar(matrix, input, input_rows, input_stride,
                                  output, output_stride);
}

static uint64_t scalar_scratch_size(
    const xaios_model_v2_package_t *package) {
  (void)package;
  return 0;
}

static void scalar_synchronize(xaios_backend_context_t *context) {
  (void)context;
}

static void scalar_destroy(xaios_backend_context_t *context) {
  (void)context;
}

static xaios_engine_status_t scalar_validate(void) {
  const float input[3] = {1.0f, -2.0f, 0.5f};
  const float weights[6] = {2.0f, 1.0f, 4.0f, -1.0f, 3.0f, 2.0f};
  const float bias[2] = {0.25f, -0.5f};
  float output[2] = {0.0f, 0.0f};
  xaios_engine_status_t status = scalar_dense_projection(
      input, weights, bias, output, 2U, 3U);
  if (status != XAIOS_ENGINE_OK || output[0] != 2.25f ||
      output[1] != -6.5f) {
    return XAIOS_ENGINE_ERR_CAPABILITY;
  }
  return XAIOS_ENGINE_OK;
}

static uint64_t scalar_probe_capabilities(void) {
  return scalar_validate() == XAIOS_ENGINE_OK ? XAIOS_BACKEND_CAP_SCALAR : 0U;
}

static const xaios_backend_t k_scalar_backend = {
    "scalar-reference",
    XAIOS_BACKEND_CAP_SCALAR,
    scalar_probe_capabilities,
    scalar_validate,
    unsupported_select_layout,
    unsupported_prepare,
    unsupported_execute,
    unsupported_execute,
    unsupported_verify,
    scalar_dense_projection,
    scalar_packed_gemv,
    scalar_packed_gemm,
    unsupported_execute,
    unsupported_execute,
    unsupported_execute,
    unsupported_execute,
    scalar_scratch_size,
    scalar_synchronize,
    scalar_destroy};

const xaios_backend_t *xaios_backend_scalar(void) {
  return &k_scalar_backend;
}

const xaios_backend_t *xaios_backend_select(uint64_t required_capabilities) {
  const uint64_t available = XAIOS_BACKEND_CAP_SCALAR |
                             XAIOS_BACKEND_CAP_NEON |
                             XAIOS_BACKEND_CAP_AVX2;
  if ((required_capabilities & ~available) != 0U) {
    return NULL;
  }
  if ((required_capabilities & XAIOS_BACKEND_CAP_NEON) != 0U) {
    const xaios_backend_t *neon = xaios_backend_neon();
    return neon != NULL && neon->validate() == XAIOS_ENGINE_OK ? neon : NULL;
  }
  if ((required_capabilities & XAIOS_BACKEND_CAP_AVX2) != 0U) {
    const xaios_backend_t *avx2 = xaios_backend_avx2();
    return avx2 != NULL && avx2->validate() == XAIOS_ENGINE_OK ? avx2 : NULL;
  }
  return scalar_validate() == XAIOS_ENGINE_OK ? &k_scalar_backend : NULL;
}
