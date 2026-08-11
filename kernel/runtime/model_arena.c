#include <xaios/arena.h>
#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/kheap.h>
#include <xaios/model_arena.h>
#include <xaios/spinlock.h>
#include <xaios/vmm.h>

/*
 * Picard — “I am Locutus of Borg. Resistance is futile. Your life as it has
 * been is over.”
 */

#define MAX_MODEL_ARENAS 4U

static xaios_model_arena_t g_model_arenas[MAX_MODEL_ARENAS];

typedef struct model_mapping_node {
  xaios_model_mapping_t mapping;
  struct model_mapping_node *next;
} model_mapping_node_t;

static model_mapping_node_t *g_model_mappings;
static xaios_spinlock_t g_model_mapping_lock = XAIOS_SPINLOCK_INIT;

static int str_nonempty(const char *value) {
  return value != 0 && value[0] != '\0';
}

static void copy_bytes(void *dst, const void *src, uint64_t size) {
  uint8_t *out = (uint8_t *)dst;
  const uint8_t *in = (const uint8_t *)src;
  for (uint64_t i = 0; i < size; ++i) {
    out[i] = in[i];
  }
}

static xaios_status_t map_as_read_only(const xaios_arena_t *arena) {
  xaios_arena_t *arena_rw = (xaios_arena_t *)arena;
  const uint64_t base = arena_rw->base;
  const uint32_t flags = XAIOS_VMM_PRESENT;

  for (uint64_t i = 0; i < arena_rw->page_count; ++i) {
    const uint64_t va = base + (i * UINT64_C(4096));
    const uint64_t pa = (uint64_t)(uintptr_t)arena_rw->pages[i];
    if (vmm_unmap_page(va) != XAIOS_OK) {
      return XAIOS_ERR_INVALID;
    }
    if (vmm_map_page(va, pa, flags) != XAIOS_OK) {
      return XAIOS_ERR_INVALID;
    }
  }
  return XAIOS_OK;
}

void model_arena_init(void) {
  for (uint32_t i = 0; i < MAX_MODEL_ARENAS; ++i) {
    g_model_arenas[i].arena_id = i;
    g_model_arenas[i].name = 0;
    g_model_arenas[i].base = 0;
    g_model_arenas[i].size = 0;
    g_model_arenas[i].ref_count = 0;
    g_model_arenas[i].read_only = 1;
  }
  g_model_mappings = 0;
  xaios_spin_init(&g_model_mapping_lock);

  klog("model-arena: registry initialized\n");
}

xaios_status_t model_arena_register_fixture_copy(
    uint32_t arena_id, const char *name, const void *base, uint64_t size) {
  if (arena_id >= MAX_MODEL_ARENAS || !str_nonempty(name) || base == 0 ||
      size == 0) {
    return XAIOS_ERR_INVALID;
  }

  const xaios_arena_t *arena = 0;
  if (arena_create(arena_id, XAIOS_ARENA_MODEL_WEIGHTS, 0, name, size,
                   XAIOS_ARENA_FLAG_SHARED,
                   &arena) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }

  const uint64_t copy_size = size < arena->size ? size : arena->size;
  copy_bytes((void *)(uintptr_t)arena->base, base, copy_size);
  if (map_as_read_only(arena) != XAIOS_OK) {
    kassert(arena_destroy(arena_id) == XAIOS_OK);
    return XAIOS_ERR_INVALID;
  }

  g_model_arenas[arena_id].name = name;
  g_model_arenas[arena_id].base = (const void *)(uintptr_t)arena->base;
  g_model_arenas[arena_id].size = arena->size;
  g_model_arenas[arena_id].ref_count = 0;
  g_model_arenas[arena_id].read_only = 1;
  klog("model-arena: registered id=%u name=%s base=0x%lx size=%lu\n",
       arena_id, name, (uint64_t)(uintptr_t)g_model_arenas[arena_id].base,
       g_model_arenas[arena_id].size);
  return XAIOS_OK;
}

static model_mapping_node_t *find_mapping_locked(uint64_t model_id) {
  model_mapping_node_t *node = g_model_mappings;
  while (node != 0) {
    if (node->mapping.model_id == model_id) return node;
    node = node->next;
  }
  return 0;
}

xaios_status_t model_mapping_register_immutable(
    uint64_t model_id, const char *name, const void *base, uint64_t size) {
  if (model_id == 0U || !str_nonempty(name) || base == 0 || size == 0U ||
      ((uint64_t)(uintptr_t)base & UINT64_C(4095)) != 0U ||
      size > UINT64_MAX - (uint64_t)(uintptr_t)base) {
    return XAIOS_ERR_INVALID;
  }
  if (vmm_validate_range_flags(
          (uint64_t)(uintptr_t)base, size, XAIOS_VMM_PRESENT,
          XAIOS_VMM_WRITABLE | XAIOS_VMM_USER | XAIOS_VMM_DEVICE) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  model_mapping_node_t *node =
      (model_mapping_node_t *)kheap_calloc(sizeof(*node), 16U);
  if (node == 0) return XAIOS_ERR_NO_MEMORY;
  node->mapping = (xaios_model_mapping_t){
      model_id, name, base, size, 0U, 1U};
  xaios_spin_lock(&g_model_mapping_lock);
  if (find_mapping_locked(model_id) != 0) {
    xaios_spin_unlock(&g_model_mapping_lock);
    kheap_free(node);
    return XAIOS_ERR_INVALID;
  }
  node->next = g_model_mappings;
  g_model_mappings = node;
  xaios_spin_unlock(&g_model_mapping_lock);
  klog("model-mapping: registered immutable id=%lu name=%s base=0x%lx size=%lu copy=0\n",
       model_id, name, (uint64_t)(uintptr_t)base, size);
  return XAIOS_OK;
}

xaios_status_t model_mapping_unregister(uint64_t model_id) {
  xaios_spin_lock(&g_model_mapping_lock);
  model_mapping_node_t **link = &g_model_mappings;
  while (*link != 0 && (*link)->mapping.model_id != model_id) {
    link = &(*link)->next;
  }
  if (*link == 0 || (*link)->mapping.ref_count != 0U) {
    xaios_spin_unlock(&g_model_mapping_lock);
    return XAIOS_ERR_INVALID;
  }
  model_mapping_node_t *removed = *link;
  *link = removed->next;
  xaios_spin_unlock(&g_model_mapping_lock);
  kheap_free(removed);
  return XAIOS_OK;
}

xaios_status_t model_mapping_acquire(uint64_t model_id,
                                     const xaios_model_mapping_t **mapping) {
  xaios_spin_lock(&g_model_mapping_lock);
  model_mapping_node_t *node = find_mapping_locked(model_id);
  if (node == 0) {
    xaios_spin_unlock(&g_model_mapping_lock);
    return XAIOS_ERR_INVALID;
  }
  if (node->mapping.ref_count == UINT64_MAX) {
    xaios_spin_unlock(&g_model_mapping_lock);
    return XAIOS_ERR_INVALID;
  }
  ++node->mapping.ref_count;
  if (mapping != 0) *mapping = &node->mapping;
  xaios_spin_unlock(&g_model_mapping_lock);
  return XAIOS_OK;
}

xaios_status_t model_mapping_release(uint64_t model_id) {
  xaios_spin_lock(&g_model_mapping_lock);
  model_mapping_node_t *node = find_mapping_locked(model_id);
  if (node == 0 || node->mapping.ref_count == 0U) {
    xaios_spin_unlock(&g_model_mapping_lock);
    return XAIOS_ERR_INVALID;
  }
  --node->mapping.ref_count;
  xaios_spin_unlock(&g_model_mapping_lock);
  return XAIOS_OK;
}

xaios_status_t model_arena_unregister(uint32_t arena_id) {
  if (arena_id >= MAX_MODEL_ARENAS || g_model_arenas[arena_id].base == 0 ||
      g_model_arenas[arena_id].ref_count != 0) {
    return XAIOS_ERR_INVALID;
  }

  g_model_arenas[arena_id].name = 0;
  g_model_arenas[arena_id].base = 0;
  g_model_arenas[arena_id].size = 0;
  g_model_arenas[arena_id].read_only = 1;
  kassert(arena_destroy(arena_id) == XAIOS_OK);
  klog("model-arena: unregistered id=%u\n", arena_id);
  return XAIOS_OK;
}

xaios_status_t model_arena_acquire(uint32_t arena_id,
                                  const xaios_model_arena_t **arena) {
  if (arena_id >= MAX_MODEL_ARENAS || g_model_arenas[arena_id].base == 0) {
    return XAIOS_ERR_INVALID;
  }

  ++g_model_arenas[arena_id].ref_count;
  kassert(arena_acquire(arena_id, 0) == XAIOS_OK);
  if (arena != 0) {
    *arena = &g_model_arenas[arena_id];
  }
  return XAIOS_OK;
}

xaios_status_t model_arena_release(uint32_t arena_id) {
  if (arena_id >= MAX_MODEL_ARENAS || g_model_arenas[arena_id].ref_count == 0) {
    return XAIOS_ERR_INVALID;
  }

  --g_model_arenas[arena_id].ref_count;
  kassert(arena_release(arena_id) == XAIOS_OK);
  return XAIOS_OK;
}

void model_arena_self_test(void) {
  model_arena_init();
  static const uint8_t tiny_model_seed[4096] = {0xaa};
  kassert(model_arena_register_fixture_copy(
              1, "tiny-shared-weights", tiny_model_seed, 4096) == XAIOS_OK);
  const xaios_model_arena_t *a = 0;
  const xaios_model_arena_t *b = 0;
  kassert(model_arena_acquire(1, &a) == XAIOS_OK);
  kassert(model_arena_acquire(1, &b) == XAIOS_OK);
  kassert(a == b);
  kassert(a->read_only != 0);
  kassert(a->ref_count == 2);
  kassert(model_arena_release(1) == XAIOS_OK);
  kassert(model_arena_release(1) == XAIOS_OK);
  const uint64_t large_id = UINT64_C(0x100000001);
  const xaios_model_mapping_t *mapping = 0;
  kassert(model_mapping_register_immutable(
              large_id, "tiny-immutable-mapping", a->base, a->size) ==
          XAIOS_OK);
  kassert(model_mapping_acquire(large_id, &mapping) == XAIOS_OK);
  kassert(mapping != 0 && mapping->base == a->base &&
          mapping->size == a->size && mapping->read_only != 0U);
  kassert(model_mapping_release(large_id) == XAIOS_OK);
  kassert(model_mapping_unregister(large_id) == XAIOS_OK);
  klog("model-arena: shared read-only arena self-test passed fixture_copy=1 immutable_mapping=1 copy=0\n");
}
