#ifndef XAIOS_ENGINE_BACKEND_H
#define XAIOS_ENGINE_BACKEND_H

#include <stddef.h>
#include <stdint.h>

#include <xaios_engine/model_v2.h>
#include <xaios_engine/packed.h>

#define XAIOS_BACKEND_CAP_SCALAR UINT64_C(1)
#define XAIOS_BACKEND_CAP_NEON (UINT64_C(1) << 1)
#define XAIOS_BACKEND_CAP_AVX2 (UINT64_C(1) << 2)
#define XAIOS_BACKEND_CAP_AVX512 (UINT64_C(1) << 3)
#define XAIOS_BACKEND_CAP_VNNI (UINT64_C(1) << 4)
#define XAIOS_BACKEND_CAP_AMX (UINT64_C(1) << 5)
#define XAIOS_BACKEND_CAP_METAL (UINT64_C(1) << 6)
#define XAIOS_BACKEND_CAP_SVE (UINT64_C(1) << 7)
#define XAIOS_BACKEND_CAP_SVE2 (UINT64_C(1) << 8)

typedef struct xaios_backend_context xaios_backend_context_t;

typedef struct xaios_backend {
  const char *backend_id;
  uint64_t capabilities;
  uint64_t (*probe_capabilities)(void);
  xaios_engine_status_t (*validate)(void);
  xaios_engine_status_t (*select_layout)(
      const xaios_model_v2_package_t *package,
      const xaios_model_v2_tensor_t *tensor, uint32_t *layout_id);
  xaios_engine_status_t (*prepare_model)(
      const xaios_model_v2_package_t *package,
      xaios_backend_context_t **context);
  xaios_engine_status_t (*prefill)(xaios_backend_context_t *context);
  xaios_engine_status_t (*decode)(xaios_backend_context_t *context);
  xaios_engine_status_t (*verify)(xaios_backend_context_t *context,
                                  uint64_t position_count);
  xaios_engine_status_t (*dense_projection)(
      const float *input, const float *weights, const float *bias,
      float *output, uint64_t rows, uint64_t columns);
  xaios_engine_status_t (*packed_gemv)(
      const xaios_packed_matrix_t *matrix, const float *input, float *output);
  xaios_engine_status_t (*packed_gemm)(
      const xaios_packed_matrix_t *matrix, const float *input,
      uint64_t input_rows, uint64_t input_stride, float *output,
      uint64_t output_stride);
  xaios_engine_status_t (*attention_update)(xaios_backend_context_t *context);
  xaios_engine_status_t (*router)(xaios_backend_context_t *context);
  xaios_engine_status_t (*expert_forward)(xaios_backend_context_t *context);
  xaios_engine_status_t (*reduce)(xaios_backend_context_t *context);
  uint64_t (*scratch_size)(const xaios_model_v2_package_t *package);
  void (*synchronize)(xaios_backend_context_t *context);
  void (*destroy)(xaios_backend_context_t *context);
} xaios_backend_t;

const xaios_backend_t *xaios_backend_scalar(void);
const xaios_backend_t *xaios_backend_neon(void);
const xaios_backend_t *xaios_backend_avx2(void);
const xaios_backend_t *xaios_backend_select(uint64_t required_capabilities);

#endif
