#include <xaios_engine/architecture.h>

#include <string.h>

static xaios_engine_status_t interface_only_validate(
    const xaios_architecture_config_t *config) {
  if (config == NULL || config->data == NULL || config->size == 0U) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  return XAIOS_ENGINE_ERR_UNSUPPORTED;
}

static xaios_engine_status_t interface_only_plan(
    const xaios_architecture_config_t *config, xaios_plan_kind_t kind,
    xaios_execution_plan_t *plan) {
  if (config == NULL || config->data == NULL || config->size == 0U ||
      plan == NULL || kind < XAIOS_PLAN_PREFILL || kind > XAIOS_PLAN_VERIFY) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  memset(plan, 0, sizeof(*plan));
  plan->kind = kind;
  return XAIOS_ENGINE_ERR_UNSUPPORTED;
}

static xaios_engine_status_t interface_only_map_tensor(
    const xaios_architecture_config_t *config,
    const xaios_source_tensor_metadata_t *source,
    xaios_tensor_mapping_t *mapping) {
  if (config == NULL || config->data == NULL || config->size == 0U ||
      source == NULL || source->name == NULL || source->rank == 0U ||
      source->dimensions == NULL || mapping == NULL) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  memset(mapping, 0, sizeof(*mapping));
  return XAIOS_ENGINE_ERR_UNSUPPORTED;
}

static xaios_engine_status_t interface_only_state_layout(
    const xaios_architecture_config_t *config, uint64_t state_index,
    xaios_state_layout_t *layout) {
  (void)state_index;
  if (config == NULL || config->data == NULL || config->size == 0U ||
      layout == NULL) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  memset(layout, 0, sizeof(*layout));
  return XAIOS_ENGINE_ERR_UNSUPPORTED;
}

static xaios_engine_status_t interface_only_scratch_size(
    const xaios_architecture_config_t *config, uint64_t layer_index,
    uint64_t *scratch_bytes) {
  (void)layer_index;
  if (config == NULL || config->data == NULL || config->size == 0U ||
      scratch_bytes == NULL) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  *scratch_bytes = 0U;
  return XAIOS_ENGINE_ERR_UNSUPPORTED;
}

static xaios_engine_status_t interface_only_backend(uint64_t capabilities) {
  (void)capabilities;
  return XAIOS_ENGINE_ERR_UNSUPPORTED;
}

/*
 * IDs come from package configuration fields, not roadmap display names.
 * xaios_fixture is synthetic test metadata; Kimi K3 uses kimi_k3.
 */
static const xaios_architecture_adapter_t k_adapters[] = {
    {"xaios_fixture", XAIOS_ARCHITECTURE_INTERFACE_ONLY,
     interface_only_validate, interface_only_map_tensor, interface_only_plan,
     interface_only_state_layout, interface_only_scratch_size,
     interface_only_backend},
    {"kimi_k3", XAIOS_ARCHITECTURE_INTERFACE_ONLY,
     interface_only_validate, interface_only_map_tensor, interface_only_plan,
     interface_only_state_layout, interface_only_scratch_size,
     interface_only_backend}};

const xaios_architecture_adapter_t *xaios_architecture_find(
    const char *architecture_id) {
  if (architecture_id == NULL) {
    return NULL;
  }
  for (size_t i = 0; i < sizeof(k_adapters) / sizeof(k_adapters[0]); ++i) {
    if (strcmp(k_adapters[i].architecture_id, architecture_id) == 0) {
      return &k_adapters[i];
    }
  }
  return NULL;
}

size_t xaios_architecture_count(void) {
  return sizeof(k_adapters) / sizeof(k_adapters[0]);
}

const xaios_architecture_adapter_t *xaios_architecture_at(size_t index) {
  return index < xaios_architecture_count() ? &k_adapters[index] : NULL;
}
