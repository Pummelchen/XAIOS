#ifndef XAIOS_ENGINE_ARCHITECTURE_H
#define XAIOS_ENGINE_ARCHITECTURE_H

#include <stddef.h>
#include <stdint.h>

#include <xaios_engine/model_v2.h>

typedef enum xaios_architecture_status {
  XAIOS_ARCHITECTURE_INTERFACE_ONLY = 1,
  XAIOS_ARCHITECTURE_SCALAR_CORRECTNESS_COMPLETE = 2,
  XAIOS_ARCHITECTURE_OPTIMIZED_EXPERIMENTAL = 3,
  XAIOS_ARCHITECTURE_PRODUCTION_SUPPORTED = 4
} xaios_architecture_status_t;

typedef enum xaios_plan_kind {
  XAIOS_PLAN_PREFILL = 1,
  XAIOS_PLAN_DECODE = 2,
  XAIOS_PLAN_VERIFY = 3
} xaios_plan_kind_t;

typedef struct xaios_architecture_config {
  const void *data;
  uint64_t size;
} xaios_architecture_config_t;

typedef struct xaios_execution_plan {
  xaios_plan_kind_t kind;
  uint64_t operator_count;
  uint64_t scratch_bytes;
  uint64_t state_bytes;
} xaios_execution_plan_t;

typedef struct xaios_source_tensor_metadata {
  const char *name;
  uint32_t rank;
  uint16_t logical_dtype;
  uint16_t stored_dtype;
  const uint64_t *dimensions;
} xaios_source_tensor_metadata_t;

typedef struct xaios_tensor_mapping {
  uint32_t semantic_role;
  uint64_t layer_id;
  uint64_t expert_id;
} xaios_tensor_mapping_t;

typedef enum xaios_state_kind {
  XAIOS_STATE_ATTENTION_KV = 1,
  XAIOS_STATE_RECURRENT = 2,
  XAIOS_STATE_CONVOLUTION = 3,
  XAIOS_STATE_KDA = 4,
  XAIOS_STATE_GATED_MLA = 5,
  XAIOS_STATE_POSITION = 6
} xaios_state_kind_t;

typedef struct xaios_state_layout {
  xaios_state_kind_t kind;
  uint16_t element_dtype;
  uint64_t alignment;
  uint64_t bytes_per_session;
} xaios_state_layout_t;

typedef struct xaios_architecture_adapter {
  const char *architecture_id;
  xaios_architecture_status_t status;
  xaios_engine_status_t (*validate_config)(
      const xaios_architecture_config_t *config);
  xaios_engine_status_t (*map_tensor)(
      const xaios_architecture_config_t *config,
      const xaios_source_tensor_metadata_t *source,
      xaios_tensor_mapping_t *mapping);
  xaios_engine_status_t (*build_plan)(
      const xaios_architecture_config_t *config, xaios_plan_kind_t kind,
      xaios_execution_plan_t *plan);
  xaios_engine_status_t (*state_layout)(
      const xaios_architecture_config_t *config, uint64_t state_index,
      xaios_state_layout_t *layout);
  xaios_engine_status_t (*layer_scratch_size)(
      const xaios_architecture_config_t *config, uint64_t layer_index,
      uint64_t *scratch_bytes);
  xaios_engine_status_t (*validate_backend)(uint64_t backend_capabilities);
} xaios_architecture_adapter_t;

const xaios_architecture_adapter_t *xaios_architecture_find(
    const char *architecture_id);
size_t xaios_architecture_count(void);
const xaios_architecture_adapter_t *xaios_architecture_at(size_t index);

#endif
