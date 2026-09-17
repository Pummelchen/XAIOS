#include <xaios/ai_kernels.h>
#include <xaios/assert.h>

#include "ai_kernels_internal.h"

/* NEON where it exists; the scalar path everywhere else. The scalar
   implementations are complete and correct on their own -- they are what the
   accelerated paths are checked against -- so an architecture without a
   vector backend here is slower, not unbuilt. */
#if defined(__aarch64__)
#include <arm_neon.h>
#endif

/*
 * AI quantisation kernels: FP16 bit conversion, byte zeroing, the FP32 -> INT8,
 * INT4 and INT6 quantisers, the INT8/INT6 dequantisers and the packed fixture
 * builders the self-test uses. Moved verbatim out of ai_kernels.c so no source
 * file exceeds 500 lines; the numeric results are bit-identical.
 */

typedef union xaios_float32_bits {
  uint32_t bits;
  float value;
} xaios_float32_bits_t;

float ai_kernels_fp16_from_bits(uint16_t bits) {
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

uint16_t ai_kernels_fp16_to_bits(float value) {
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

static void bytes_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0; i < size; ++i) {
    bytes[i] = 0;
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

void ai_kernels_pack_int4_fixture(const int8_t *values, uint32_t count,
                              uint8_t *packed) {
  bytes_zero(packed, (count + 1U) / 2U);
  for (uint32_t index = 0U; index < count; ++index) {
    packed[index / 2U] |=
        ((uint8_t)values[index] & UINT8_C(0x0f))
        << ((index & 1U) * 4U);
  }
}

void ai_kernels_pack_int6_fixture(const int8_t *values, uint32_t count,
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
