#include <xaios/ai_kernels.h>
#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/math_intrinsics.h>

/*
 * Janeway — “Is it? You've scanned our vessel. You know we can match your
 * firepower.”
 */

/*
 * AI compute kernels for AArch64 with NEON SIMD where validated.
 *
 * Implements:
 * - NEON vectorized matrix multiplication
 * - Bounded work-unit distribution
 * - Multiple quantization formats (FP32, FP16, INT8, INT4, Q8.8)
 */

/* NEON where it exists; the scalar path everywhere else.
   The guard used to refuse to compile on anything but AArch64 and x86-64,
   which conflated "has a vector unit this file uses" with "is a supported
   architecture". The scalar implementations below are complete and correct
   on their own -- they are what the accelerated paths are checked against --
   so an architecture without a vector backend here is slower, not unbuilt. */
#if defined(__aarch64__)
#include <arm_neon.h>
#endif

typedef union xaios_float32_bits {
  uint32_t bits;
  float value;
} xaios_float32_bits_t;

static float fp16_from_bits(uint16_t bits) {
  uint32_t sign = ((uint32_t)bits & UINT32_C(0x8000)) << 16U;
  uint32_t exponent = ((uint32_t)bits >> 10U) & UINT32_C(0x1f);
  uint32_t mantissa = (uint32_t)bits & UINT32_C(0x3ff);
  uint32_t converted;
  if (exponent == 0U) {
    if (mantissa == 0U) {
      converted = sign;
    } else {
      uint32_t normalized_exponent = 113U;
      while ((mantissa & UINT32_C(0x400)) == 0U) {
        mantissa <<= 1U;
        --normalized_exponent;
      }
      mantissa &= UINT32_C(0x3ff);
      converted = sign | (normalized_exponent << 23U) | (mantissa << 13U);
    }
  } else if (exponent == UINT32_C(0x1f)) {
    converted = sign | UINT32_C(0x7f800000) | (mantissa << 13U);
  } else {
    converted = sign | ((exponent + 112U) << 23U) | (mantissa << 13U);
  }
  xaios_float32_bits_t result = {.bits = converted};
  return result.value;
}

static uint16_t fp16_to_bits(float value) {
  xaios_float32_bits_t source = {.value = value};
  uint32_t sign = (source.bits >> 16U) & UINT32_C(0x8000);
  uint32_t exponent = (source.bits >> 23U) & UINT32_C(0xff);
  uint32_t mantissa = source.bits & UINT32_C(0x7fffff);
  if (exponent == UINT32_C(0xff)) {
    uint16_t payload = (uint16_t)(mantissa >> 13U);
    if (mantissa != 0U && payload == 0U) payload = 1U;
    return (uint16_t)(sign | UINT32_C(0x7c00) | payload);
  }

  int32_t half_exponent = (int32_t)exponent - 112;
  if (half_exponent >= 31) return (uint16_t)(sign | UINT32_C(0x7c00));
  if (half_exponent <= 0) {
    if (half_exponent < -10) return (uint16_t)sign;
    mantissa |= UINT32_C(0x800000);
    uint32_t shift = (uint32_t)(14 - half_exponent);
    uint32_t half_mantissa = mantissa >> shift;
    uint32_t remainder_mask = (UINT32_C(1) << shift) - 1U;
    uint32_t remainder = mantissa & remainder_mask;
    uint32_t halfway = UINT32_C(1) << (shift - 1U);
    if (remainder > halfway ||
        (remainder == halfway && (half_mantissa & 1U) != 0U)) {
      ++half_mantissa;
    }
    return (uint16_t)(sign | half_mantissa);
  }

  uint32_t half_mantissa = mantissa >> 13U;
  uint32_t remainder = mantissa & UINT32_C(0x1fff);
  if (remainder > UINT32_C(0x1000) ||
      (remainder == UINT32_C(0x1000) && (half_mantissa & 1U) != 0U)) {
    ++half_mantissa;
    if (half_mantissa == UINT32_C(0x400)) {
      half_mantissa = 0U;
      ++half_exponent;
      if (half_exponent >= 31) {
        return (uint16_t)(sign | UINT32_C(0x7c00));
      }
    }
  }
  return (uint16_t)(sign | ((uint32_t)half_exponent << 10U) |
                    half_mantissa);
}

static int32_t narrow_accumulator(int64_t value);

static void bytes_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0; i < size; ++i) {
    bytes[i] = 0;
  }
}

/*
 * NEON-optimized INT8 matrix multiplication
 *
 * Processes up to 8 output columns per iteration. Tail lanes are copied to a
 * bounded local vector so no input or output access crosses the matrix edge.
 */
#if defined(__aarch64__)
static void matmul_int8_native(const int8_t *mat_a, const int8_t *mat_b,
                             int32_t *result, uint32_t rows_a,
                             uint32_t cols_a, uint32_t cols_b) {
  for (uint32_t i = 0; i < rows_a; ++i) {
    for (uint32_t j = 0; j < cols_b; j += 8) {
      /* Process 8 columns at once */
      uint32_t remaining = cols_b - j;
      uint32_t process = remaining < 8 ? remaining : 8;

      int32x4_t acc_low = vdupq_n_s32(0);
      int32x4_t acc_high = vdupq_n_s32(0);

      for (uint32_t k = 0; k < cols_a; ++k) {
        int8_t b_lanes[8] = {0, 0, 0, 0, 0, 0, 0, 0};
        for (uint32_t lane = 0U; lane < process; ++lane) {
          b_lanes[lane] = mat_b[(uint64_t)k * cols_b + j + lane];
        }
        int8x8_t b_vec = vld1_s8(b_lanes);

        /* Broadcast element from mat_a */
        int8_t a_val = mat_a[i * cols_a + k];
        int8x8_t a_vec = vdup_n_s8(a_val);

        /* Widening multiply: int8 × int8 → int16 */
        int16x8_t prod = vmull_s8(a_vec, b_vec);

        /* Widen to int32 and accumulate */
        acc_low = vaddw_s16(acc_low, vget_low_s16(prod));
        acc_high = vaddw_high_s16(acc_high, prod);
      }

      int32_t lanes[8];
      vst1q_s32(lanes, acc_low);
      vst1q_s32(lanes + 4U, acc_high);
      for (uint32_t lane = 0U; lane < process; ++lane) {
        result[(uint64_t)i * cols_b + j + lane] = lanes[lane];
      }
    }
  }
}

/*
 * NEON-optimized FP16 matrix multiplication
 *
 * Processes up to 8 output columns per iteration.
 */
__attribute__((target("+fullfp16")))
static void matmul_fp16_native(const uint16_t *mat_a, const uint16_t *mat_b,
                             uint16_t *result, uint32_t rows_a,
                             uint32_t cols_a, uint32_t cols_b) {
  for (uint32_t i = 0; i < rows_a; ++i) {
    for (uint32_t j = 0; j < cols_b; j += 8) {
      uint32_t remaining = cols_b - j;
      uint32_t process = remaining < 8 ? remaining : 8;

      float16x8_t acc = vdupq_n_f16(0.0f);

      for (uint32_t k = 0; k < cols_a; ++k) {
        __fp16 b_lanes[8] = {0};
        for (uint32_t lane = 0U; lane < process; ++lane) {
          b_lanes[lane] =
              *(const __fp16 *)&mat_b[(uint64_t)k * cols_b + j + lane];
        }
        float16x8_t b_vec = vld1q_f16(b_lanes);

        /* Broadcast FP16 element from mat_a */
        __fp16 a_val = *(const __fp16 *)&mat_a[i * cols_a + k];
        float16x8_t a_vec = vdupq_n_f16(a_val);

        /* FP16 multiply-accumulate */
        acc = vfmaq_f16(acc, a_vec, b_vec);
      }

      /* Store results */
      if (process == 8) {
        __fp16 *out_ptr = (__fp16 *)&result[i * cols_b + j];
        vst1q_f16(out_ptr, acc);
      } else {
        /* Manual lane extraction (vgetq_lane_f16 requires constant index) */
        __fp16 lanes[8];
        vst1q_f16(lanes, acc);
        for (uint32_t p = 0; p < process; ++p) {
          result[i * cols_b + j + p] = *(const uint16_t *)&lanes[p];
        }
      }
    }
  }
}
#else
static void matmul_int8_native(const int8_t *mat_a, const int8_t *mat_b,
                              int32_t *result, uint32_t rows_a,
                              uint32_t cols_a, uint32_t cols_b) {
  for (uint32_t row = 0U; row < rows_a; ++row) {
    for (uint32_t column = 0U; column < cols_b; ++column) {
      int64_t accumulator = 0;
      for (uint32_t inner = 0U; inner < cols_a; ++inner) {
        accumulator += (int32_t)mat_a[(uint64_t)row * cols_a + inner] *
                       (int32_t)mat_b[(uint64_t)inner * cols_b + column];
      }
      result[(uint64_t)row * cols_b + column] =
          narrow_accumulator(accumulator);
    }
  }
}

static void matmul_fp16_native(const uint16_t *mat_a, const uint16_t *mat_b,
                              uint16_t *result, uint32_t rows_a,
                              uint32_t cols_a, uint32_t cols_b) {
  for (uint32_t row = 0U; row < rows_a; ++row) {
    for (uint32_t column = 0U; column < cols_b; ++column) {
      float accumulator = 0.0f;
      for (uint32_t inner = 0U; inner < cols_a; ++inner) {
        accumulator +=
            fp16_from_bits(mat_a[(uint64_t)row * cols_a + inner]) *
            fp16_from_bits(mat_b[(uint64_t)inner * cols_b + column]);
      }
      result[(uint64_t)row * cols_b + column] =
          fp16_to_bits(accumulator);
    }
  }
}
#endif

/*
 * Signed packed helpers. Values are unpacked only while resident in the inner
 * dot product; complete matrices are never expanded into temporary buffers.
 */
static int8_t unpack_int4(const uint8_t *packed, uint64_t index) {
  uint8_t value =
      (packed[index / 2U] >> ((index & 1U) * 4U)) & UINT8_C(0x0f);
  return (int8_t)(value >= 8U ? (int32_t)value - 16 : value);
}

static int8_t unpack_int6(const uint8_t *packed, uint64_t index) {
  uint64_t block = index / 4U;
  uint32_t word = (uint32_t)packed[block * 3U] |
                  ((uint32_t)packed[block * 3U + 1U] << 8U) |
                  ((uint32_t)packed[block * 3U + 2U] << 16U);
  uint8_t value =
      (uint8_t)((word >> ((index & 3U) * 6U)) & UINT32_C(0x3f));
  return (int8_t)(value >= 32U ? (int32_t)value - 64 : value);
}

static int32_t narrow_accumulator(int64_t value) {
  if (value > INT32_MAX) return INT32_MAX;
  if (value < INT32_MIN) return INT32_MIN;
  return (int32_t)value;
}

static void matmul_int4_packed_rows(const uint8_t *mat_a,
                                    const uint8_t *mat_b, int32_t *result,
                                    uint32_t row_start, uint32_t row_count,
                                    uint32_t cols_a, uint32_t cols_b) {
  for (uint32_t local_row = 0U; local_row < row_count; ++local_row) {
    uint64_t row = (uint64_t)row_start + local_row;
    for (uint32_t column = 0U; column < cols_b; ++column) {
      int64_t accumulator = 0;
      for (uint32_t inner = 0U; inner < cols_a; ++inner) {
        int8_t left = unpack_int4(mat_a, row * cols_a + inner);
        int8_t right =
            unpack_int4(mat_b, (uint64_t)inner * cols_b + column);
        accumulator += (int32_t)left * (int32_t)right;
      }
      result[(uint64_t)local_row * cols_b + column] =
          narrow_accumulator(accumulator);
    }
  }
}

static void matmul_int6_packed_rows(const uint8_t *mat_a,
                                    const uint8_t *mat_b, int32_t *result,
                                    uint32_t row_start, uint32_t row_count,
                                    uint32_t cols_a, uint32_t cols_b) {
  for (uint32_t local_row = 0U; local_row < row_count; ++local_row) {
    uint64_t row = (uint64_t)row_start + local_row;
    for (uint32_t column = 0U; column < cols_b; ++column) {
      int64_t accumulator = 0;
      for (uint32_t inner = 0U; inner < cols_a; ++inner) {
        int8_t left = unpack_int6(mat_a, row * cols_a + inner);
        int8_t right =
            unpack_int6(mat_b, (uint64_t)inner * cols_b + column);
        accumulator += (int32_t)left * (int32_t)right;
      }
      result[(uint64_t)local_row * cols_b + column] =
          narrow_accumulator(accumulator);
    }
  }
}

/*
 * Legacy Q8.8 scalar matrix multiplication (fallback)
 */
static void matmul_q88_scalar(const int16_t *mat_a, const int16_t *mat_b,
                              int16_t *result, uint32_t rows_a,
                              uint32_t cols_a, uint32_t cols_b) {
  for (uint32_t i = 0; i < rows_a; ++i) {
    for (uint32_t j = 0; j < cols_b; ++j) {
      int32_t acc = 0;
      for (uint32_t k = 0; k < cols_a; ++k) {
        acc += (int32_t)mat_a[i * cols_a + k] * (int32_t)mat_b[k * cols_b + j];
      }
      result[i * cols_b + j] = (int16_t)(acc >> 8);
    }
  }
}

/*
 * Main matmul dispatcher - selects optimized kernel based on quantization
 */
void ai_kernel_matmul(const void *mat_a, const void *mat_b, void *result,
                     uint32_t rows_a, uint32_t cols_a, uint32_t cols_b,
                     xaios_quantization_t quant) {
  kassert(mat_a != 0 && mat_b != 0 && result != 0);
  kassert(rows_a > 0 && cols_a > 0 && cols_b > 0);

  switch (quant) {
    case XAIOS_QUANT_INT8:
      matmul_int8_native((const int8_t *)mat_a, (const int8_t *)mat_b,
                      (int32_t *)result, rows_a, cols_a, cols_b);
      break;

    case XAIOS_QUANT_INT6:
      matmul_int6_packed_rows((const uint8_t *)mat_a,
                              (const uint8_t *)mat_b, (int32_t *)result, 0U,
                              rows_a, cols_a, cols_b);
      break;

    case XAIOS_QUANT_FP16:
      matmul_fp16_native((const uint16_t *)mat_a, (const uint16_t *)mat_b,
                      (uint16_t *)result, rows_a, cols_a, cols_b);
      break;

    case XAIOS_QUANT_INT4:
      matmul_int4_packed_rows((const uint8_t *)mat_a,
                              (const uint8_t *)mat_b, (int32_t *)result, 0U,
                              rows_a, cols_a, cols_b);
      break;

    case XAIOS_QUANT_Q88:
      matmul_q88_scalar((const int16_t *)mat_a, (const int16_t *)mat_b,
                       (int16_t *)result, rows_a, cols_a, cols_b);
      break;

    case XAIOS_QUANT_FP32:
    default: {
      const float *a = (const float *)mat_a;
      const float *b = (const float *)mat_b;
      float *r = (float *)result;
      for (uint32_t i = 0; i < rows_a; ++i) {
        for (uint32_t j = 0; j < cols_b; ++j) {
          float acc = 0.0f;
          for (uint32_t k = 0; k < cols_a; ++k) {
            acc += a[i * cols_a + k] * b[k * cols_b + j];
          }
          r[i * cols_b + j] = acc;
        }
      }
      break;
    }
  }
}

/*
 * Multi-threaded matmul work unit execution
 */
static void matmul_work_thread(void *arg) {
  xaios_matmul_work_t *work = (xaios_matmul_work_t *)arg;
  uint32_t rows = work->row_end - work->row_start;
  uint64_t input_index = (uint64_t)work->row_start * work->cols_a;
  uint64_t output_index = (uint64_t)work->row_start * work->cols_b;
  if (work->quant == XAIOS_QUANT_INT4) {
    matmul_int4_packed_rows((const uint8_t *)work->mat_a,
                            (const uint8_t *)work->mat_b,
                            (int32_t *)work->result + output_index,
                            work->row_start, rows, work->cols_a,
                            work->cols_b);
  } else if (work->quant == XAIOS_QUANT_INT6) {
    matmul_int6_packed_rows((const uint8_t *)work->mat_a,
                            (const uint8_t *)work->mat_b,
                            (int32_t *)work->result + output_index,
                            work->row_start, rows, work->cols_a,
                            work->cols_b);
  } else if (work->quant == XAIOS_QUANT_INT8) {
    ai_kernel_matmul((const int8_t *)work->mat_a + input_index, work->mat_b,
                     (int32_t *)work->result + output_index, rows,
                     work->cols_a, work->cols_b, work->quant);
  } else if (work->quant == XAIOS_QUANT_FP16) {
    ai_kernel_matmul((const uint16_t *)work->mat_a + input_index, work->mat_b,
                     (uint16_t *)work->result + output_index, rows,
                     work->cols_a, work->cols_b, work->quant);
  } else if (work->quant == XAIOS_QUANT_Q88) {
    ai_kernel_matmul((const int16_t *)work->mat_a + input_index, work->mat_b,
                     (int16_t *)work->result + output_index, rows,
                     work->cols_a, work->cols_b, work->quant);
  } else {
    ai_kernel_matmul((const float *)work->mat_a + input_index, work->mat_b,
                     (float *)work->result + output_index, rows, work->cols_a,
                     work->cols_b, work->quant);
  }
}

void ai_kernel_matmul_multithread(const xaios_matmul_work_t *work_units,
                                  uint32_t num_threads) {
  kassert(work_units != 0 && num_threads > 0);

  /* Work units are deterministic and bounded; persistent pool dispatch is not
   * yet integrated, so this compatibility entrypoint remains sequential. */
  for (uint32_t t = 0; t < num_threads; ++t) {
    matmul_work_thread((void *)&work_units[t]);
  }
}

/*
 * Forward pass with activation
 */
void ai_kernel_forward(const void *input, const void *weights,
                      const void *bias, void *output,
                      uint32_t batch, uint32_t in_dim, uint32_t out_dim,
                      xaios_quantization_t quant, xaios_activation_t activation) {
  kassert(input != 0 && weights != 0 && output != 0);

  /* Step 1: Matrix multiplication */
  ai_kernel_matmul(input, weights, output, batch, in_dim, out_dim, quant);

  /* Step 2: Add bias (if present) */
  if (bias != 0) {
    if (quant == XAIOS_QUANT_INT8) {
      int32_t *out = (int32_t *)output;
      const int8_t *b = (const int8_t *)bias;
      for (uint32_t i = 0; i < batch; ++i) {
        for (uint32_t j = 0; j < out_dim; ++j) {
          out[i * out_dim + j] += b[j];
        }
      }
    } else if (quant == XAIOS_QUANT_FP16) {
      uint16_t *out = (uint16_t *)output;
      const uint16_t *b = (const uint16_t *)bias;
      for (uint32_t i = 0; i < batch; ++i) {
        for (uint32_t j = 0; j < out_dim; ++j) {
          float val = fp16_from_bits(out[i * out_dim + j]) +
                      fp16_from_bits(b[j]);
          out[i * out_dim + j] = fp16_to_bits(val);
        }
      }
    }
  }

  /* Step 3: Apply activation function */
  if (activation == XAIOS_ACT_RELU) {
    if (quant == XAIOS_QUANT_INT8) {
      int32_t *out = (int32_t *)output;
      for (uint32_t i = 0; i < batch * out_dim; ++i) {
        if (out[i] < 0) out[i] = 0;
      }
    } else if (quant == XAIOS_QUANT_FP16) {
      uint16_t *out = (uint16_t *)output;
      for (uint32_t i = 0; i < batch * out_dim; ++i) {
        float val = fp16_from_bits(out[i]);
        if (val < 0.0f) {
          uint16_t zero = 0;
          out[i] = zero;
        }
      }
    }
  }
}

/*
 * Quantization: FP32 → INT8 with per-channel scales
 */
xaios_status_t ai_kernel_quantize_fp32_to_int8(const float *fp32, int8_t *int8,
                                               float *scales, uint32_t count) {
  kassert(fp32 != 0 && int8 != 0 && scales != 0);

  /* Find max absolute value for scaling */
  float max_val = 0.0f;
  for (uint32_t i = 0; i < count; ++i) {
    float abs_val = fp32[i] < 0 ? -fp32[i] : fp32[i];
    if (abs_val > max_val) {
      max_val = abs_val;
    }
  }

  if (max_val == 0.0f) {
    *scales = 1.0f;
    bytes_zero(int8, count);
    return XAIOS_OK;
  }

  /* Compute scale factor */
  *scales = max_val / 127.0f;

  float scale = *scales;
  float inv_scale = 1.0f / scale;

  for (uint32_t i = 0; i < count; i += 4) {
    uint32_t remaining = count - i;
    uint32_t process = remaining < 4U ? remaining : 4U;
    if (process >= 4U) {
#if defined(__aarch64__)
      float32x4_t inv_scale_vec = vdupq_n_f32(inv_scale);
      float32x4_t vals = vld1q_f32(&fp32[i]);
      float32x4_t scaled = vmulq_f32(vals, inv_scale_vec);
      int32x4_t rounded = vcvtnq_s32_f32(scaled);
      int32_t out[4];
      vst1q_s32(out, rounded);
      for (uint32_t j = 0U; j < 4U; ++j) {
        if (out[j] < -127) out[j] = -127;
        if (out[j] > 127) out[j] = 127;
        int8[i + j] = (int8_t)out[j];
      }
#else
      for (uint32_t j = 0U; j < 4U; ++j) {
        float scaled = fp32[i + j] * inv_scale;
        int32_t rounded =
            (int32_t)(scaled >= 0.0f ? scaled + 0.5f : scaled - 0.5f);
        if (rounded < -127) rounded = -127;
        if (rounded > 127) rounded = 127;
        int8[i + j] = (int8_t)rounded;
      }
#endif
    } else {
      for (uint32_t j = 0U; j < process; ++j) {
        float scaled = fp32[i + j] * inv_scale;
        int32_t rounded =
            (int32_t)(scaled >= 0.0f ? scaled + 0.5f : scaled - 0.5f);
        if (rounded < -127) rounded = -127;
        if (rounded > 127) rounded = 127;
        int8[i + j] = (int8_t)rounded;
      }
    }
  }

  return XAIOS_OK;
}

/*
 * Quantization: FP32 → INT4 (bit-packed)
 */
xaios_status_t ai_kernel_quantize_fp32_to_int4(const float *fp32, int8_t *int4,
                                               float *scales, uint32_t count) {
  kassert(fp32 != 0 && int4 != 0 && scales != 0);

  /* Find max for scaling */
  float max_val = 0.0f;
  for (uint32_t i = 0; i < count; ++i) {
    float abs_val = fp32[i] < 0 ? -fp32[i] : fp32[i];
    if (abs_val > max_val) {
      max_val = abs_val;
    }
  }

  if (max_val == 0.0f) {
    *scales = 1.0f;
    bytes_zero(int4, (count + 1U) / 2U);
    return XAIOS_OK;
  }

  *scales = max_val / 7.0f;  /* INT4 range: -7 to +7 */
  float inv_scale = 1.0f / *scales;

  /* Quantize and pack 2 values per byte */
  for (uint32_t i = 0; i < count; i += 2) {
    int8_t low = (int8_t)(fp32[i] * inv_scale);
    int8_t high = (i + 1 < count) ? (int8_t)(fp32[i + 1] * inv_scale) : 0;

    /* Clamp to INT4 range */
    if (low < -7) low = -7;
    if (low > 7) low = 7;
    if (high < -7) high = -7;
    if (high > 7) high = 7;

    /* Pack: low nibble + high nibble */
    int4[i / 2] = (low & 0x0F) | ((high & 0x0F) << 4);
  }

  return XAIOS_OK;
}

/*
 * Dequantization: INT8 → FP32
 */
xaios_status_t ai_kernel_dequantize_int8_to_fp32(const int8_t *int8,
                                                 const float *scales,
                                                 float *fp32, uint32_t count) {
  kassert(int8 != 0 && scales != 0 && fp32 != 0);

  float scale = *scales;
#if defined(__aarch64__)
  float32x4_t scale_vec = vdupq_n_f32(scale);
#endif

  for (uint32_t i = 0; i < count; i += 4) {
    uint32_t remaining = count - i;
    uint32_t process = remaining < 4 ? remaining : 4;

#if defined(__aarch64__)
    int8_t vals[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    for (uint32_t j = 0; j < process; ++j) {
      vals[j] = int8[i + j];
    }

    int8x8_t int8_vec = vld1_s8(vals);
    int16x8_t widened = vmovl_s8(int8_vec);
    int32x4_t int32_vec = vmovl_s16(vget_low_s16(widened));
    float32x4_t fp32_vec = vcvtq_f32_s32(int32_vec);
    fp32_vec = vmulq_f32(fp32_vec, scale_vec);

    float out[4];
    vst1q_f32(out, fp32_vec);

    for (uint32_t j = 0; j < process; ++j) {
      fp32[i + j] = out[j];
    }
#else
    for (uint32_t j = 0U; j < process; ++j) {
      fp32[i + j] = (float)int8[i + j] * scale;
    }
#endif
  }

  return XAIOS_OK;
}

/*
 * Paged attention kernel
 *
 * Computes scaled dot-product self-attention over query tokens.
 * Uses proper softmax: exp(score - max) / sum(exp(score - max)).
 * kv_pages/page_table reserved for Phase 2 paged KV cache integration.
 */
void ai_kernel_paged_attention(const void *query, const void **kv_pages,
                              const uint32_t *page_table, void *output,
                              uint32_t num_tokens, uint32_t head_dim,
                              uint32_t num_pages, uint32_t block_size) {
  /* Phase 2 paged KV integration deferred */
  (void)kv_pages;
  (void)page_table;
  (void)num_pages;
  (void)block_size;

  const float *q = (const float *)query;
  float *out = (float *)output;

  for (uint32_t i = 0; i < num_tokens; ++i) {
    float max_val = -1e30f;
    float sum = 0.0f;

    /* Pass 1: compute scores and find max */
    for (uint32_t j = 0; j < num_tokens; ++j) {
      float score = 0.0f;
      for (uint32_t k = 0; k < head_dim; ++k) {
        score += q[i * head_dim + k] * q[j * head_dim + k];
      }
      score /= (float)head_dim;

      if (score > max_val) {
        max_val = score;
      }
    }

    /* Pass 2: compute softmax and weighted output */
    for (uint32_t k = 0; k < head_dim; ++k) {
      out[i * head_dim + k] = 0.0f;
    }

    for (uint32_t j = 0; j < num_tokens; ++j) {
      float score = 0.0f;
      for (uint32_t k = 0; k < head_dim; ++k) {
        score += q[i * head_dim + k] * q[j * head_dim + k];
      }
      score /= (float)head_dim;

      float exp_score = xaios_expf(score - max_val);
      sum += exp_score;

      for (uint32_t k = 0; k < head_dim; ++k) {
        out[i * head_dim + k] += exp_score * q[j * head_dim + k];
      }
    }

    /* Normalize */
    if (sum > 0.0f) {
      for (uint32_t k = 0; k < head_dim; ++k) {
        out[i * head_dim + k] /= sum;
      }
    }
  }
}

/*
 * Quantization: FP32 → INT6 with per-channel scales
 *
 * INT6 packing: 4 values per 3 bytes (24 bits = 4 × 6 bits)
 * Range: -32 to +31 (signed 6-bit)
 */
xaios_status_t ai_kernel_quantize_fp32_to_int6(const float *fp32, int8_t *int6,
                                               float *scales, uint32_t count) {
  kassert(fp32 != 0 && int6 != 0 && scales != 0);
  
  /* Find max absolute value for scaling */
  float max_val = 0.0f;
  for (uint32_t i = 0; i < count; ++i) {
    float abs_val = fp32[i] < 0 ? -fp32[i] : fp32[i];
    if (abs_val > max_val) {
      max_val = abs_val;
    }
  }
  
  if (max_val == 0.0f) {
    *scales = 1.0f;
    bytes_zero(int6, (count * 3 + 3) / 4);  /* 4 values per 3 bytes */
    return XAIOS_OK;
  }
  
  /* Compute scale factor (INT6 range: -32 to +31) */
  *scales = max_val / 31.0f;
  float inv_scale = 1.0f / *scales;
  
  /* Quantize and pack 4 values per 3 bytes */
  for (uint32_t i = 0; i < count; i += 4) {
    int32_t vals[4] = {0, 0, 0, 0};
    uint32_t remaining = count - i;
    uint32_t process = remaining < 4 ? remaining : 4;
    
    /* Quantize to INT6 range */
    for (uint32_t j = 0; j < process; ++j) {
      int32_t q = (int32_t)(fp32[i + j] * inv_scale);
      if (q < -32) q = -32;
      if (q > 31) q = 31;
      vals[j] = q & 0x3F;  /* Mask to 6 bits */
    }
    
    /* Pack 4× 6-bit values into 3 bytes */
    uint32_t packed = vals[0] | (vals[1] << 6) | (vals[2] << 12) | (vals[3] << 18);
    
    int6[i / 4 * 3] = (int8_t)(packed & 0xFF);
    int6[i / 4 * 3 + 1] = (int8_t)((packed >> 8) & 0xFF);
    int6[i / 4 * 3 + 2] = (int8_t)((packed >> 16) & 0xFF);
  }
  
  return XAIOS_OK;
}

/*
 * Dequantization: INT6 → FP32
 */
xaios_status_t ai_kernel_dequantize_int6_to_fp32(const int8_t *int6,
                                                 const float *scales,
                                                 float *fp32, uint32_t count) {
  kassert(int6 != 0 && scales != 0 && fp32 != 0);
  
  float scale = *scales;
  
  /* Unpack and dequantize 4 values per 3 bytes */
  for (uint32_t i = 0; i < count; i += 4) {
    uint32_t remaining = count - i;
    uint32_t process = remaining < 4 ? remaining : 4;
    
    /* Unpack 3 bytes to 4× 6-bit values */
    uint32_t packed = (uint32_t)(uint8_t)int6[i / 4 * 3] |
                     ((uint32_t)(uint8_t)int6[i / 4 * 3 + 1] << 8) |
                     ((uint32_t)(uint8_t)int6[i / 4 * 3 + 2] << 16);
    
    int32_t vals[4];
    vals[0] = (int32_t)(packed << 26) >> 26;  /* Sign-extend bits 0-5 */
    vals[1] = (int32_t)(packed << 20) >> 26;  /* Sign-extend bits 6-11 */
    vals[2] = (int32_t)(packed << 14) >> 26;  /* Sign-extend bits 12-17 */
    vals[3] = (int32_t)(packed << 8) >> 26;   /* Sign-extend bits 18-23 */
    
    /* Dequantize */
    for (uint32_t j = 0; j < process; ++j) {
      fp32[i + j] = (float)vals[j] * scale;
    }
  }
  
  return XAIOS_OK;
}

/*
 * Rotary Position Embedding (RoPE)
 *
 * Applies rotary position embeddings to query and key tensors.
 * Used by modern transformers (Qwen, Llama, etc.) for positional encoding.
 *
 * Algorithm:
 *   For each position p and dimension i:
 *     theta_i = 1 / (theta_base^(2*i/head_dim))
 *     freq = p * theta_i
 *     q[..., 2i]   = q[..., 2i]   * cos(freq) - q[..., 2i+1] * sin(freq)
 *     q[..., 2i+1] = q[..., 2i]   * sin(freq) + q[..., 2i+1] * cos(freq)
 *
 * NEON-optimized: processes 4 dimensions per iteration using float32x4_t.
 */
void ai_kernel_rope_apply(float *query, float *key,
                         uint32_t num_tokens, uint32_t head_dim,
                         uint32_t position_offset, float theta_base) {
  kassert(query != 0 || key != 0);
  kassert(head_dim > 0 && head_dim % 2 == 0); /* Must be even for RoPE */

  uint32_t half_dim = head_dim / 2;

  /* Precompute inverse log theta for frequency calculation */
  float inv_log_theta = 1.0f / xaios_logf(theta_base);

  /* Process each token */
  for (uint32_t token_idx = 0; token_idx < num_tokens; ++token_idx) {
    uint32_t position = position_offset + token_idx;

    /* Process query tensor */
    if (query) {
      float *q = &query[token_idx * head_dim];

      /* NEON vectorized RoPE: process 4 dimensions at once */
      for (uint32_t i = 0; i < half_dim; i += 4) {
        uint32_t remaining = half_dim - i;
        uint32_t process = remaining < 4 ? remaining : 4;

        /* Compute frequencies: freq_j = position / (theta_base^(j/half_dim)) */
        float freqs[4];
        for (uint32_t j = 0; j < process; ++j) {
          float exponent = -(float)(i + j) / (float)half_dim;
          freqs[j] = position * xaios_expf(exponent * inv_log_theta);
        }

        /* Load current query values */
        float q_even[4], q_odd[4];
        for (uint32_t j = 0; j < process; ++j) {
          q_even[j] = q[(i + j) * 2];
          q_odd[j] = q[(i + j) * 2 + 1];
        }

        /* Compute sin/cos */
        float cos_vals[4], sin_vals[4];
        for (uint32_t j = 0; j < process; ++j) {
          cos_vals[j] = xaios_cosf(freqs[j]);
          sin_vals[j] = xaios_sinf(freqs[j]);
        }

        /* Apply RoPE rotation using NEON */
        for (uint32_t j = 0; j < process; ++j) {
          float q_e = q_even[j];
          float q_o = q_odd[j];
          float c = cos_vals[j];
          float s = sin_vals[j];

          /* Rotation matrix: [cos -sin; sin cos] */
          q[(i + j) * 2] = q_e * c - q_o * s;
          q[(i + j) * 2 + 1] = q_e * s + q_o * c;
        }
      }
    }

    /* Process key tensor */
    if (key) {
      float *k = &key[token_idx * head_dim];

      /* NEON vectorized RoPE: process 4 dimensions at once */
      for (uint32_t i = 0; i < half_dim; i += 4) {
        uint32_t remaining = half_dim - i;
        uint32_t process = remaining < 4 ? remaining : 4;

        /* Compute frequencies */
        float freqs[4];
        for (uint32_t j = 0; j < process; ++j) {
          float exponent = -(float)(i + j) / (float)half_dim;
          freqs[j] = position * xaios_expf(exponent * inv_log_theta);
        }

        /* Load current key values */
        float k_even[4], k_odd[4];
        for (uint32_t j = 0; j < process; ++j) {
          k_even[j] = k[(i + j) * 2];
          k_odd[j] = k[(i + j) * 2 + 1];
        }

        /* Compute sin/cos */
        float cos_vals[4], sin_vals[4];
        for (uint32_t j = 0; j < process; ++j) {
          cos_vals[j] = xaios_cosf(freqs[j]);
          sin_vals[j] = xaios_sinf(freqs[j]);
        }

        /* Apply RoPE rotation */
        for (uint32_t j = 0; j < process; ++j) {
          float k_e = k_even[j];
          float k_o = k_odd[j];
          float c = cos_vals[j];
          float s = sin_vals[j];

          k[(i + j) * 2] = k_e * c - k_o * s;
          k[(i + j) * 2 + 1] = k_e * s + k_o * c;
        }
      }
    }
  }
}

static void pack_int4_fixture(const int8_t *values, uint32_t count,
                              uint8_t *packed) {
  bytes_zero(packed, (count + 1U) / 2U);
  for (uint32_t index = 0U; index < count; ++index) {
    packed[index / 2U] |=
        ((uint8_t)values[index] & UINT8_C(0x0f))
        << ((index & 1U) * 4U);
  }
}

static void pack_int6_fixture(const int8_t *values, uint32_t count,
                              uint8_t *packed) {
  bytes_zero(packed, ((count + 3U) / 4U) * 3U);
  for (uint32_t index = 0U; index < count; ++index) {
    uint32_t value = (uint8_t)values[index] & UINT32_C(0x3f);
    uint32_t block = index / 4U;
    uint32_t shift = (index & 3U) * 6U;
    uint32_t word = (uint32_t)packed[block * 3U] |
                    ((uint32_t)packed[block * 3U + 1U] << 8U) |
                    ((uint32_t)packed[block * 3U + 2U] << 16U);
    word |= value << shift;
    packed[block * 3U] = (uint8_t)word;
    packed[block * 3U + 1U] = (uint8_t)(word >> 8U);
    packed[block * 3U + 2U] = (uint8_t)(word >> 16U);
  }
}

void ai_kernel_self_test(void) {
  static const uint16_t fp16_finite_cases[] = {
      UINT16_C(0x0000), UINT16_C(0x8000), UINT16_C(0x0001),
      UINT16_C(0x03ff), UINT16_C(0x0400), UINT16_C(0x3c00),
      UINT16_C(0xc000), UINT16_C(0x7bff), UINT16_C(0x7c00),
      UINT16_C(0xfc00)};
  for (uint32_t index = 0U;
       index < sizeof(fp16_finite_cases) / sizeof(fp16_finite_cases[0]);
       ++index) {
    uint16_t bits = fp16_finite_cases[index];
    kassert(fp16_to_bits(fp16_from_bits(bits)) == bits);
  }

  static const int8_t int4_a[10] = {1, -2, 3, -4, 5,
                                    -1, 2, -3, 4, -5};
  static const int8_t int4_b[15] = {1, 2, 3, -1, 0, 1, 2, -2,
                                    1, 0, 1, -1, 3, 2, -2};
  uint8_t packed4_a[5];
  uint8_t packed4_b[8];
  int32_t result4[6];
  pack_int4_fixture(int4_a, 10U, packed4_a);
  pack_int4_fixture(int4_b, 15U, packed4_b);
  ai_kernel_matmul(packed4_a, packed4_b, result4, 2U, 5U, 3U,
                   XAIOS_QUANT_INT4);
  static const int32_t expected4[6] = {24, 2, -2, -24, -2, 2};
  for (uint32_t index = 0U; index < 6U; ++index) {
    kassert(result4[index] == expected4[index]);
  }

  static const int8_t int6_a[5] = {-32, -1, 0, 1, 31};
  static const int8_t int6_b[10] = {1, -1, 2, -2, 3,
                                    -3, 4, -4, 5, -5};
  uint8_t packed6_a[6];
  uint8_t packed6_b[9];
  int32_t result6[2];
  pack_int6_fixture(int6_a, 5U, packed6_a);
  pack_int6_fixture(int6_b, 10U, packed6_b);
  ai_kernel_matmul(packed6_a, packed6_b, result6, 1U, 5U, 2U,
                   XAIOS_QUANT_INT6);
  kassert(result6[0] == 125 && result6[1] == -125);

  int32_t work_result[6] = {0, 0, 0, 0, 0, 0};
  xaios_matmul_work_t work = {packed4_a, packed4_b, work_result,
                              1U,        2U,        5U,
                              3U,        XAIOS_QUANT_INT4};
  ai_kernel_matmul_multithread(&work, 1U);
  kassert(work_result[0] == 0 && work_result[1] == 0 &&
          work_result[2] == 0 && work_result[3] == -24 &&
          work_result[4] == -2 && work_result[5] == 2);
  klog("ai-kernel: scalar fp16 and packed no-expand self-test passed fp16=10 int4=6 int6=2\n");
}
