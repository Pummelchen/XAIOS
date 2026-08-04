#include <xaios_engine/packed.h>

#if defined(__aarch64__) && defined(__ARM_NEON)
#include <arm_neon.h>
#define XAIOS_PACKED_HAS_NEON 1
#else
#define XAIOS_PACKED_HAS_NEON 0
#endif

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#define XAIOS_PACKED_HAS_X86_64 1
#else
#define XAIOS_PACKED_HAS_X86_64 0
#endif

static xaios_engine_status_t checked_multiply(uint64_t left, uint64_t right,
                                               uint64_t *result) {
  if (result == NULL || (left != 0U && right > UINT64_MAX / left)) {
    return XAIOS_ENGINE_ERR_OVERFLOW;
  }
  *result = left * right;
  return XAIOS_ENGINE_OK;
}

static int8_t unpack_int4(const uint8_t *data, uint64_t index) {
  uint8_t value = (data[index / 2U] >> ((index & 1U) * 4U)) & 0x0fU;
  return (int8_t)(value >= 8U ? (int32_t)value - 16 : value);
}

static int8_t unpack_int6(const uint8_t *data, uint64_t index) {
  uint64_t block = index / 4U;
  uint32_t packed = (uint32_t)data[block * 3U] |
                    ((uint32_t)data[block * 3U + 1U] << 8U) |
                    ((uint32_t)data[block * 3U + 2U] << 16U);
  uint8_t value = (uint8_t)((packed >> ((index & 3U) * 6U)) & 0x3fU);
  return (int8_t)(value >= 32U ? (int32_t)value - 64 : value);
}

static int8_t unpack_weight(const xaios_packed_matrix_t *matrix,
                            uint64_t index) {
  return matrix->dtype == XAIOS_PACKED_INT4
             ? unpack_int4(matrix->data, index)
             : unpack_int6(matrix->data, index);
}

static uint64_t group_count(const xaios_packed_matrix_t *matrix) {
  return 1U + (matrix->columns - 1U) / matrix->group_size;
}

xaios_engine_status_t xaios_packed_matrix_required_bytes(
    uint64_t element_count, xaios_packed_dtype_t dtype,
    uint64_t *required_bytes) {
  if (element_count == 0U || required_bytes == NULL) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  if (dtype == XAIOS_PACKED_INT4) {
    *required_bytes = 1U + (element_count - 1U) / 2U;
    return XAIOS_ENGINE_OK;
  }
  if (dtype == XAIOS_PACKED_INT6) {
    uint64_t blocks = 1U + (element_count - 1U) / 4U;
    return checked_multiply(blocks, 3U, required_bytes);
  }
  return XAIOS_ENGINE_ERR_UNSUPPORTED;
}

xaios_engine_status_t xaios_packed_matrix_validate(
    const xaios_packed_matrix_t *matrix) {
  if (matrix == NULL || matrix->data == NULL || matrix->scales == NULL ||
      matrix->rows == 0U || matrix->columns == 0U ||
      matrix->group_size == 0U) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  uint64_t elements = 0U;
  uint64_t required_data = 0U;
  uint64_t required_scales = 0U;
  xaios_engine_status_t status =
      checked_multiply(matrix->rows, matrix->columns, &elements);
  if (status != XAIOS_ENGINE_OK) return status;
  status = xaios_packed_matrix_required_bytes(elements, matrix->dtype,
                                              &required_data);
  if (status != XAIOS_ENGINE_OK) return status;
  status = checked_multiply(matrix->rows, group_count(matrix),
                            &required_scales);
  if (status != XAIOS_ENGINE_OK) return status;
  if (matrix->data_size < required_data ||
      matrix->scale_count < required_scales) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaios_packed_gemv_scalar(
    const xaios_packed_matrix_t *matrix, const float *input, float *output) {
  xaios_engine_status_t status = xaios_packed_matrix_validate(matrix);
  if (status != XAIOS_ENGINE_OK || input == NULL || output == NULL) {
    return status == XAIOS_ENGINE_OK ? XAIOS_ENGINE_ERR_INVALID : status;
  }
  uint64_t groups = group_count(matrix);
  for (uint64_t row = 0U; row < matrix->rows; ++row) {
    float sum = 0.0f;
    for (uint64_t group = 0U; group < groups; ++group) {
      uint64_t start = group * matrix->group_size;
      uint64_t end = start + matrix->group_size;
      if (end < start || end > matrix->columns) end = matrix->columns;
      float scale = matrix->scales[row * groups + group];
      for (uint64_t column = start; column < end; ++column) {
        uint64_t index = row * matrix->columns + column;
        sum += (float)unpack_weight(matrix, index) * scale * input[column];
      }
    }
    output[row] = sum;
  }
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaios_packed_gemv_neon(
    const xaios_packed_matrix_t *matrix, const float *input, float *output) {
#if XAIOS_PACKED_HAS_NEON
  xaios_engine_status_t status = xaios_packed_matrix_validate(matrix);
  if (status != XAIOS_ENGINE_OK || input == NULL || output == NULL) {
    return status == XAIOS_ENGINE_OK ? XAIOS_ENGINE_ERR_INVALID : status;
  }
  uint64_t groups = group_count(matrix);
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
          lanes[lane] = unpack_weight(matrix, index);
        }
        float32x4_t weights =
            vmulq_n_f32(vcvtq_f32_s32(vld1q_s32(lanes)), scale);
        accumulator = vfmaq_f32(accumulator, vld1q_f32(input + column),
                                weights);
      }
      sum += vaddvq_f32(accumulator);
      for (; column < end; ++column) {
        uint64_t index = row * matrix->columns + column;
        sum += (float)unpack_weight(matrix, index) * scale * input[column];
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
static void x86_cpuid(uint32_t leaf, uint32_t subleaf, uint32_t *eax,
                      uint32_t *ebx, uint32_t *ecx, uint32_t *edx) {
  __asm__ volatile("cpuid"
                   : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
                   : "a"(leaf), "c"(subleaf));
}

static uint64_t x86_xgetbv(uint32_t index) {
  uint32_t low = 0U;
  uint32_t high = 0U;
  __asm__ volatile("xgetbv" : "=a"(low), "=d"(high) : "c"(index));
  return (uint64_t)low | ((uint64_t)high << 32U);
}

static int x86_avx2_usable(void) {
  uint32_t eax = 0U;
  uint32_t ebx = 0U;
  uint32_t ecx = 0U;
  uint32_t edx = 0U;
  x86_cpuid(0U, 0U, &eax, &ebx, &ecx, &edx);
  if (eax < 7U) return 0;
  x86_cpuid(1U, 0U, &eax, &ebx, &ecx, &edx);
  if ((ecx & (UINT32_C(1) << 27U)) == 0U ||
      (ecx & (UINT32_C(1) << 28U)) == 0U ||
      (x86_xgetbv(0U) & UINT64_C(6)) != UINT64_C(6)) {
    return 0;
  }
  x86_cpuid(7U, 0U, &eax, &ebx, &ecx, &edx);
  return (ebx & (UINT32_C(1) << 5U)) != 0U;
}

__attribute__((target("avx2")))
static xaios_engine_status_t packed_gemv_avx2_impl(
    const xaios_packed_matrix_t *matrix, const float *input, float *output) {
  uint64_t groups = group_count(matrix);
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
          lanes[lane] = unpack_weight(matrix, index);
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
        sum += (float)unpack_weight(matrix, index) * scalar_scale *
               input[column];
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
  if (!x86_avx2_usable()) return XAIOS_ENGINE_ERR_UNSUPPORTED;
  return packed_gemv_avx2_impl(matrix, input, output);
#else
  (void)matrix;
  (void)input;
  (void)output;
  return XAIOS_ENGINE_ERR_UNSUPPORTED;
#endif
}

static int close_enough(float left, float right) {
  float difference = left > right ? left - right : right - left;
  float magnitude = left < 0.0f ? -left : left;
  if ((right < 0.0f ? -right : right) > magnitude) {
    magnitude = right < 0.0f ? -right : right;
  }
  return difference <= 0.0001f * (1.0f + magnitude);
}

int xaios_packed_neon_available(void) {
#if XAIOS_PACKED_HAS_NEON
  static int cached;
  int observed = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
  if (observed != 0) return observed > 0;
  static const uint8_t data[3] = {0xe1U, 0xc3U, 0x05U};
  static const float scales[2] = {0.5f, 2.0f};
  static const float input[5] = {2.0f, 1.0f, -1.0f, 0.5f, 3.0f};
  xaios_packed_matrix_t matrix = {
      data, sizeof(data), scales, 2U, 1U, 5U, 3U, XAIOS_PACKED_INT4};
  float scalar = 0.0f;
  float neon = 0.0f;
  int valid = xaios_packed_gemv_scalar(&matrix, input, &scalar) ==
                  XAIOS_ENGINE_OK &&
              xaios_packed_gemv_neon(&matrix, input, &neon) ==
                  XAIOS_ENGINE_OK &&
              close_enough(scalar, 24.5f) && close_enough(scalar, neon);
  __atomic_store_n(&cached, valid ? 1 : -1, __ATOMIC_RELEASE);
  return valid;
#else
  return 0;
#endif
}

int xaios_packed_avx2_available(void) {
#if XAIOS_PACKED_HAS_X86_64
  static int cached;
  int observed = __atomic_load_n(&cached, __ATOMIC_ACQUIRE);
  if (observed != 0) return observed > 0;
  if (!x86_avx2_usable()) {
    __atomic_store_n(&cached, -1, __ATOMIC_RELEASE);
    return 0;
  }
  static const uint8_t int4_data[6] = {0xe1U, 0xc3U, 0xa5U,
                                       0x07U, 0x89U, 0x0bU};
  static const uint8_t int6_data[9] = {0xe0U, 0x0fU, 0x04U,
                                       0xdfU, 0x81U, 0x3fU,
                                       0x30U, 0x00U, 0x00U};
  static const float int4_scales[3] = {0.5f, 2.0f, 0.25f};
  static const float int6_scales[3] = {0.25f, 0.5f, 2.0f};
  static const float int4_input[9] = {2.0f, 1.0f, -1.0f, 0.5f, 3.0f,
                                      -2.0f, 4.0f, 0.25f, -0.5f};
  static const float int6_input[9] = {1.0f, -2.0f, 0.5f, 3.0f, -1.0f,
                                      2.0f, 0.25f, -0.5f, 4.0f};
  xaios_packed_matrix_t int4_matrix = {int4_data,
                                        sizeof(int4_data),
                                        int4_scales,
                                        3U,
                                        1U,
                                        9U,
                                        3U,
                                        XAIOS_PACKED_INT4};
  xaios_packed_matrix_t int6_matrix = {int6_data,
                                        sizeof(int6_data),
                                        int6_scales,
                                        3U,
                                        1U,
                                        9U,
                                        3U,
                                        XAIOS_PACKED_INT6};
  float scalar4 = 0.0f;
  float avx4 = 0.0f;
  float scalar6 = 0.0f;
  float avx6 = 0.0f;
  int valid =
      xaios_packed_gemv_scalar(&int4_matrix, int4_input, &scalar4) ==
          XAIOS_ENGINE_OK &&
      xaios_packed_gemv_avx2(&int4_matrix, int4_input, &avx4) ==
          XAIOS_ENGINE_OK &&
      xaios_packed_gemv_scalar(&int6_matrix, int6_input, &scalar6) ==
          XAIOS_ENGINE_OK &&
      xaios_packed_gemv_avx2(&int6_matrix, int6_input, &avx6) ==
          XAIOS_ENGINE_OK &&
      close_enough(scalar4, avx4) && close_enough(scalar6, -161.5f) &&
      close_enough(scalar6, avx6);
  __atomic_store_n(&cached, valid ? 1 : -1, __ATOMIC_RELEASE);
  return valid;
#else
  return 0;
#endif
}

xaios_engine_status_t xaios_packed_gemv(
    const xaios_packed_matrix_t *matrix, const float *input, float *output,
    xaios_packed_implementation_t *implementation) {
  if (xaios_packed_avx2_available()) {
    xaios_engine_status_t status =
        xaios_packed_gemv_avx2(matrix, input, output);
    if (status == XAIOS_ENGINE_OK) {
      if (implementation != NULL) *implementation = XAIOS_PACKED_IMPL_AVX2;
      return status;
    }
    if (status != XAIOS_ENGINE_ERR_UNSUPPORTED) return status;
  }
  if (xaios_packed_neon_available()) {
    xaios_engine_status_t status =
        xaios_packed_gemv_neon(matrix, input, output);
    if (status == XAIOS_ENGINE_OK) {
      if (implementation != NULL) *implementation = XAIOS_PACKED_IMPL_NEON;
      return status;
    }
    if (status != XAIOS_ENGINE_ERR_UNSUPPORTED) return status;
  }
  xaios_engine_status_t status =
      xaios_packed_gemv_scalar(matrix, input, output);
  if (status == XAIOS_ENGINE_OK && implementation != NULL) {
    *implementation = XAIOS_PACKED_IMPL_SCALAR;
  }
  return status;
}

xaios_engine_status_t xaios_packed_gemm(
    const xaios_packed_matrix_t *matrix, const float *input,
    uint64_t input_rows, uint64_t input_stride, float *output,
    uint64_t output_stride, xaios_packed_implementation_t *implementation) {
  xaios_engine_status_t status = xaios_packed_matrix_validate(matrix);
  if (status != XAIOS_ENGINE_OK || input == NULL || output == NULL ||
      input_rows == 0U || input_stride < matrix->columns ||
      output_stride < matrix->rows) {
    return status == XAIOS_ENGINE_OK ? XAIOS_ENGINE_ERR_INVALID : status;
  }
  if (input_rows > 1U &&
      (input_stride > UINT64_MAX / (input_rows - 1U) ||
       output_stride > UINT64_MAX / (input_rows - 1U))) {
    return XAIOS_ENGINE_ERR_OVERFLOW;
  }
  xaios_packed_implementation_t selected = XAIOS_PACKED_IMPL_SCALAR;
  for (uint64_t row = 0U; row < input_rows; ++row) {
    status = xaios_packed_gemv(matrix, input + row * input_stride,
                               output + row * output_stride, &selected);
    if (status != XAIOS_ENGINE_OK) return status;
  }
  if (implementation != NULL) *implementation = selected;
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaios_packed_gemm_scalar(
    const xaios_packed_matrix_t *matrix, const float *input,
    uint64_t input_rows, uint64_t input_stride, float *output,
    uint64_t output_stride) {
  xaios_engine_status_t status = xaios_packed_matrix_validate(matrix);
  if (status != XAIOS_ENGINE_OK || input == NULL || output == NULL ||
      input_rows == 0U || input_stride < matrix->columns ||
      output_stride < matrix->rows) {
    return status == XAIOS_ENGINE_OK ? XAIOS_ENGINE_ERR_INVALID : status;
  }
  if (input_rows > 1U &&
      (input_stride > UINT64_MAX / (input_rows - 1U) ||
       output_stride > UINT64_MAX / (input_rows - 1U))) {
    return XAIOS_ENGINE_ERR_OVERFLOW;
  }
  for (uint64_t row = 0U; row < input_rows; ++row) {
    status = xaios_packed_gemv_scalar(
        matrix, input + row * input_stride, output + row * output_stride);
    if (status != XAIOS_ENGINE_OK) return status;
  }
  return XAIOS_ENGINE_OK;
}
