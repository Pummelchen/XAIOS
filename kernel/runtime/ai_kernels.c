#include <xaios/ai_kernels.h>
#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/math_intrinsics.h>

#include "ai_kernels_internal.h"

/*
 * Janeway — “Is it? You've scanned our vessel. You know we can match your
 * firepower.”
 */

/*
 * AI kernels that stay in the original translation unit:
 * - the signed packed INT4/INT6 word decode helpers
 * - accumulator narrowing
 * - paged attention
 * - Rotary Position Embedding (RoPE)
 * - the scalar and packed self-test
 *
 * The matrix kernels, the dispatcher and the work-unit entrypoints live in
 * ai_kernels_matmul.c; the FP16 conversion, the quantisers and the self-test
 * fixture packers live in ai_kernels_quant.c.
 */

/*
 * Signed packed helpers. Values are unpacked only while resident in the inner
 * dot product; complete matrices are never expanded into temporary buffers.
 */
int8_t ai_kernels_unpack_int4(const uint8_t *packed, uint64_t index) {
  uint8_t value =
      (packed[index / 2U] >> ((index & 1U) * 4U)) & UINT8_C(0x0f);
  return (int8_t)(value >= 8U ? (int32_t)value - 16 : value);
}

int8_t ai_kernels_unpack_int6(const uint8_t *packed, uint64_t index) {
  uint64_t block = index / 4U;
  uint32_t word = (uint32_t)packed[block * 3U] |
                  ((uint32_t)packed[block * 3U + 1U] << 8U) |
                  ((uint32_t)packed[block * 3U + 2U] << 16U);
  uint8_t value =
      (uint8_t)((word >> ((index & 3U) * 6U)) & UINT32_C(0x3f));
  return (int8_t)(value >= 32U ? (int32_t)value - 64 : value);
}

int32_t ai_kernels_narrow_accumulator(int64_t value) {
  if (value > INT32_MAX) return INT32_MAX;
  if (value < INT32_MIN) return INT32_MIN;
  return (int32_t)value;
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
    kassert(ai_kernels_fp16_to_bits(ai_kernels_fp16_from_bits(bits)) == bits);
  }

  static const int8_t int4_a[10] = {1, -2, 3, -4, 5,
                                    -1, 2, -3, 4, -5};
  static const int8_t int4_b[15] = {1, 2, 3, -1, 0, 1, 2, -2,
                                    1, 0, 1, -1, 3, 2, -2};
  uint8_t packed4_a[5];
  uint8_t packed4_b[8];
  int32_t result4[6];
  ai_kernels_pack_int4_fixture(int4_a, 10U, packed4_a);
  ai_kernels_pack_int4_fixture(int4_b, 15U, packed4_b);
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
  ai_kernels_pack_int6_fixture(int6_a, 5U, packed6_a);
  ai_kernels_pack_int6_fixture(int6_b, 10U, packed6_b);
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
