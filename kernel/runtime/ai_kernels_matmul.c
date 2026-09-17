#include <xaios/ai_kernels.h>
#include <xaios/assert.h>

#include "ai_kernels_internal.h"

/* NEON where it exists; the scalar path everywhere else.
   The guard used to refuse to compile on anything but AArch64 and x86-64,
   which conflated "has a vector unit this file uses" with "is a supported
   architecture". The scalar implementations below are complete and correct
   on their own -- they are what the accelerated paths are checked against --
   so an architecture without a vector backend here is slower, not unbuilt. */
#if defined(__aarch64__)
#include <arm_neon.h>
#endif

/*
 * AI matrix kernels: the NEON and scalar matrix multiplications, the packed
 * INT4/INT6 row kernels, the legacy Q8.8 scalar kernel, the quantization
 * dispatcher, the bounded work-unit entrypoints and the forward pass with bias
 * and activation. Moved verbatim out of ai_kernels.c so no source file exceeds
 * 500 lines; the numeric results are bit-identical.
 */

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
          ai_kernels_narrow_accumulator(accumulator);
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
            ai_kernels_fp16_from_bits(mat_a[(uint64_t)row * cols_a + inner]) *
            ai_kernels_fp16_from_bits(mat_b[(uint64_t)inner * cols_b + column]);
      }
      result[(uint64_t)row * cols_b + column] =
          ai_kernels_fp16_to_bits(accumulator);
    }
  }
}
#endif

static void matmul_int4_packed_rows(const uint8_t *mat_a,
                                    const uint8_t *mat_b, int32_t *result,
                                    uint32_t row_start, uint32_t row_count,
                                    uint32_t cols_a, uint32_t cols_b) {
  for (uint32_t local_row = 0U; local_row < row_count; ++local_row) {
    uint64_t row = (uint64_t)row_start + local_row;
    for (uint32_t column = 0U; column < cols_b; ++column) {
      int64_t accumulator = 0;
      for (uint32_t inner = 0U; inner < cols_a; ++inner) {
        int8_t left = ai_kernels_unpack_int4(mat_a, row * cols_a + inner);
        int8_t right =
            ai_kernels_unpack_int4(mat_b, (uint64_t)inner * cols_b + column);
        accumulator += (int32_t)left * (int32_t)right;
      }
      result[(uint64_t)local_row * cols_b + column] =
          ai_kernels_narrow_accumulator(accumulator);
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
        int8_t left = ai_kernels_unpack_int6(mat_a, row * cols_a + inner);
        int8_t right =
            ai_kernels_unpack_int6(mat_b, (uint64_t)inner * cols_b + column);
        accumulator += (int32_t)left * (int32_t)right;
      }
      result[(uint64_t)local_row * cols_b + column] =
          ai_kernels_narrow_accumulator(accumulator);
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
          float val = ai_kernels_fp16_from_bits(out[i * out_dim + j]) +
                      ai_kernels_fp16_from_bits(b[j]);
          out[i * out_dim + j] = ai_kernels_fp16_to_bits(val);
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
        float val = ai_kernels_fp16_from_bits(out[i]);
        if (val < 0.0f) {
          uint16_t zero = 0;
          out[i] = zero;
        }
      }
    }
  }
}
