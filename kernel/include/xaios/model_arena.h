#ifndef XAIOS_MODEL_ARENA_H
#define XAIOS_MODEL_ARENA_H

#include <xaios/status.h>
#include <xaios/types.h>

#define XAIOS_MODEL_ARENA_NAME_MAX 32U

typedef struct xaios_model_arena {
  uint32_t arena_id;
  const char *name;
  const void *base;
  uint64_t size;
  uint32_t ref_count;
  uint32_t read_only;
} xaios_model_arena_t;

typedef struct xaios_model_mapping {
  uint64_t model_id;
  const char *name;
  const void *base;
  uint64_t size;
  uint64_t ref_count;
  uint32_t read_only;
} xaios_model_mapping_t;

void model_arena_init(void);
xaios_status_t model_arena_register_fixture_copy(
    uint32_t arena_id, const char *name, const void *base, uint64_t size);
xaios_status_t model_arena_unregister(uint32_t arena_id);
xaios_status_t model_arena_acquire(uint32_t arena_id,
                                  const xaios_model_arena_t **arena);
xaios_status_t model_arena_release(uint32_t arena_id);
xaios_status_t model_mapping_register_immutable(
    uint64_t model_id, const char *name, const void *base, uint64_t size);
xaios_status_t model_mapping_unregister(uint64_t model_id);
xaios_status_t model_mapping_acquire(uint64_t model_id,
                                     const xaios_model_mapping_t **mapping);
xaios_status_t model_mapping_release(uint64_t model_id);
void model_arena_self_test(void);

#endif
