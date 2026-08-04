#include <xaios_engine/backend.h>
#include <xaios_engine/packed.h>

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint32_t next_random(uint32_t *state) {
  *state = *state * UINT32_C(1664525) + UINT32_C(1013904223);
  return *state;
}

static void pack_values(xaios_packed_dtype_t dtype, const int8_t *values,
                        uint64_t count, uint8_t *packed,
                        uint64_t packed_size) {
  memset(packed, 0, (size_t)packed_size);
  for (uint64_t index = 0U; index < count; ++index) {
    if (dtype == XAIOS_PACKED_INT4) {
      packed[index / 2U] |=
          (uint8_t)((uint8_t)values[index] & 0x0fU)
          << ((index & 1U) * 4U);
    } else {
      uint32_t value = (uint8_t)values[index] & 0x3fU;
      uint64_t block = index / 4U;
      uint32_t shift = (uint32_t)(index & 3U) * 6U;
      uint32_t word = (uint32_t)packed[block * 3U] |
                      ((uint32_t)packed[block * 3U + 1U] << 8U) |
                      ((uint32_t)packed[block * 3U + 2U] << 16U);
      word |= value << shift;
      packed[block * 3U] = (uint8_t)word;
      packed[block * 3U + 1U] = (uint8_t)(word >> 8U);
      packed[block * 3U + 2U] = (uint8_t)(word >> 16U);
    }
  }
}

static int close_enough(float left, float right) {
  float difference = left > right ? left - right : right - left;
  float magnitude = left < 0.0f ? -left : left;
  float other = right < 0.0f ? -right : right;
  if (other > magnitude) magnitude = other;
  return difference <= 0.0002f * (1.0f + magnitude);
}

static void reference(const int8_t *weights, const float *scales,
                      uint64_t rows, uint64_t columns, uint64_t group_size,
                      const float *input, float *output) {
  uint64_t groups = 1U + (columns - 1U) / group_size;
  for (uint64_t row = 0U; row < rows; ++row) {
    float sum = 0.0f;
    for (uint64_t column = 0U; column < columns; ++column) {
      uint64_t group = column / group_size;
      sum += (float)weights[row * columns + column] *
             scales[row * groups + group] * input[column];
    }
    output[row] = sum;
  }
}

static void test_dtype(xaios_packed_dtype_t dtype) {
  static const uint64_t groups_to_test[] = {1U, 3U, 8U, 16U, 31U};
  uint32_t random_state = UINT32_C(0x93a21f07) + (uint32_t)dtype;
  for (uint64_t columns = 1U; columns <= 37U; ++columns) {
    uint64_t rows = 1U + columns % 5U;
    uint64_t elements = rows * columns;
    int8_t weights[192];
    uint8_t packed[192];
    float input[40];
    for (uint64_t index = 0U; index < elements; ++index) {
      uint32_t span = dtype == XAIOS_PACKED_INT4 ? 16U : 64U;
      weights[index] = (int8_t)((int32_t)(next_random(&random_state) % span) -
                                (int32_t)(span / 2U));
    }
    for (uint64_t index = 0U; index < columns; ++index) {
      input[index] = (float)((int32_t)(next_random(&random_state) % 17U) - 8) /
                     8.0f;
    }
    uint64_t packed_size = 0U;
    assert(xaios_packed_matrix_required_bytes(elements, dtype, &packed_size) ==
           XAIOS_ENGINE_OK);
    assert(packed_size <= sizeof(packed));
    pack_values(dtype, weights, elements, packed, packed_size);

    for (size_t group_index = 0U;
         group_index < sizeof(groups_to_test) / sizeof(groups_to_test[0]);
         ++group_index) {
      uint64_t group_size = groups_to_test[group_index];
      uint64_t group_count = 1U + (columns - 1U) / group_size;
      float scales[192];
      for (uint64_t index = 0U; index < rows * group_count; ++index) {
        scales[index] = (float)(1U + next_random(&random_state) % 7U) / 16.0f;
      }
      xaios_packed_matrix_t matrix = {
          packed, packed_size, scales, rows * group_count, rows, columns,
          group_size, dtype};
      float expected[8];
      float scalar_guarded[10];
      float auto_guarded[10];
      for (size_t index = 0U; index < 10U; ++index) {
        scalar_guarded[index] = 12345.0f;
        auto_guarded[index] = 12345.0f;
      }
      reference(weights, scales, rows, columns, group_size, input, expected);
      assert(xaios_packed_gemv_scalar(&matrix, input, scalar_guarded + 1U) ==
             XAIOS_ENGINE_OK);
      xaios_packed_implementation_t implementation = 0;
      assert(xaios_packed_gemv(&matrix, input, auto_guarded + 1U,
                               &implementation) == XAIOS_ENGINE_OK);
      assert(scalar_guarded[0] == 12345.0f &&
             scalar_guarded[rows + 1U] == 12345.0f);
      assert(auto_guarded[0] == 12345.0f &&
             auto_guarded[rows + 1U] == 12345.0f);
      assert(implementation ==
             (xaios_packed_avx2_available()
                  ? XAIOS_PACKED_IMPL_AVX2
                  : (xaios_packed_neon_available() ? XAIOS_PACKED_IMPL_NEON
                                                   : XAIOS_PACKED_IMPL_SCALAR)));
      for (uint64_t row = 0U; row < rows; ++row) {
        assert(close_enough(expected[row], scalar_guarded[row + 1U]));
        assert(close_enough(expected[row], auto_guarded[row + 1U]));
      }

      float batch_input[3U * 40U];
      float batch_output[3U * 10U];
      float batch_scalar[3U * 10U];
      uint64_t input_stride = columns + 2U;
      uint64_t output_stride = rows + 2U;
      for (uint64_t batch = 0U; batch < 3U; ++batch) {
        for (uint64_t column = 0U; column < columns; ++column) {
          batch_input[batch * input_stride + column] =
              input[column] + (float)batch * 0.125f;
        }
      }
      for (size_t index = 0U; index < sizeof(batch_output) / sizeof(float);
           ++index) {
        batch_output[index] = 54321.0f;
        batch_scalar[index] = 54321.0f;
      }
      assert(xaios_packed_gemm_scalar(&matrix, batch_input, 3U, input_stride,
                                      batch_scalar, output_stride) ==
             XAIOS_ENGINE_OK);
      assert(xaios_packed_gemm(&matrix, batch_input, 3U, input_stride,
                               batch_output, output_stride,
                               &implementation) == XAIOS_ENGINE_OK);
      for (uint64_t batch = 0U; batch < 3U; ++batch) {
        for (uint64_t row = 0U; row < rows; ++row) {
          assert(close_enough(batch_scalar[batch * output_stride + row],
                              batch_output[batch * output_stride + row]));
        }
        assert(batch_output[batch * output_stride + rows] == 54321.0f);
      }
    }
  }
}

static void test_rejections(void) {
  uint8_t data[3] = {0U, 0U, 0U};
  float scales[2] = {1.0f, 1.0f};
  float input[2] = {0.0f, 0.0f};
  float output[2] = {0.0f, 0.0f};
  xaios_packed_matrix_t matrix = {
      data, sizeof(data), scales, 2U, 1U, 2U, 1U, XAIOS_PACKED_INT6};
  assert(xaios_packed_matrix_validate(&matrix) == XAIOS_ENGINE_OK);
  matrix.data_size = 2U;
  assert(xaios_packed_matrix_validate(&matrix) == XAIOS_ENGINE_ERR_INVALID);
  matrix.data_size = 3U;
  matrix.scale_count = 1U;
  assert(xaios_packed_matrix_validate(&matrix) == XAIOS_ENGINE_ERR_INVALID);
  matrix.scale_count = 2U;
  matrix.dtype = (xaios_packed_dtype_t)99;
  assert(xaios_packed_matrix_validate(&matrix) ==
         XAIOS_ENGINE_ERR_UNSUPPORTED);
  matrix.dtype = XAIOS_PACKED_INT6;
  matrix.rows = UINT64_MAX;
  assert(xaios_packed_matrix_validate(&matrix) == XAIOS_ENGINE_ERR_OVERFLOW);
  matrix.rows = 1U;
  assert(xaios_packed_gemm(&matrix, input, 1U, 1U, output, 1U, NULL) ==
         XAIOS_ENGINE_ERR_INVALID);
}

int main(void) {
  test_dtype(XAIOS_PACKED_INT4);
  test_dtype(XAIOS_PACKED_INT6);
  test_rejections();
  const xaios_backend_t *scalar = xaios_backend_scalar();
  assert(scalar != NULL && scalar->packed_gemv != NULL &&
         scalar->packed_gemm != NULL);
  const xaios_backend_t *neon = xaios_backend_select(XAIOS_BACKEND_CAP_NEON);
  assert((neon != NULL) == (xaios_packed_neon_available() != 0));
  const xaios_backend_t *avx2 = xaios_backend_select(XAIOS_BACKEND_CAP_AVX2);
  assert((avx2 != NULL) == (xaios_packed_avx2_available() != 0));
  puts(xaios_packed_avx2_available()
           ? "packed: INT4/INT6 scalar and AVX2 differential tails passed"
           : (xaios_packed_neon_available()
                  ? "packed: INT4/INT6 scalar and NEON differential tails passed"
                  : "packed: INT4/INT6 scalar tails passed; SIMD unavailable"));
  return 0;
}
