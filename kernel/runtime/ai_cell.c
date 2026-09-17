#include <xaios/arena.h>
#include <xaios/ai_cell.h>
#include <xaios/assert.h>
#include <xaios/cpu_ai_runtime.h>
#include <xaios/core_lease.h>
#include <xaios/klog.h>
#include <xaios/model_arena.h>
#include <xaios/network_stack.h>

#include "ai_cell_internal.h"

#define CELL_KV_ARENA_BASE 4U
#define CELL_SOURCE_ARENA_BASE 8U
#define CELL_BUILD_ARENA_BASE 12U
#define CELL_LOG_ARENA_BASE 16U
#define PAGE_SIZE UINT64_C(4096)

static xaios_ai_cell_t g_ai_cells[MAX_AI_CELLS];
static uint8_t g_nic_queue_owner[MAX_NIC_QUEUES];
static uint8_t g_workspace_owner[MAX_WORKSPACES + 1U];
static uint64_t g_transition_count;
static uint64_t g_descriptor_accept_count;
static uint64_t g_descriptor_reject_count;
static uint64_t g_resource_admission_count;
static uint64_t g_resource_reject_count;
static uint64_t g_arena_pages_reserved;
static uint64_t g_arena_bytes_reserved;
static uint64_t g_arena_pages_peak;
static uint64_t g_arena_bytes_peak;
static uint64_t g_queue_bind_count;
static uint64_t g_queue_release_count;
static uint64_t g_workspace_bind_count;
static uint64_t g_workspace_release_count;
static uint64_t g_conflict_count;

/* The two admission counters stay here, beside the accessors that read them.
   ai_cell_descriptor.c reaches them through these seeds, each of which is the
   single increment the unsplit file performed inline. */
void ai_cell_note_descriptor_reject(void) {
  ++g_descriptor_reject_count;
}

void ai_cell_note_resource_reject(void) {
  ++g_resource_reject_count;
}

static uint64_t align_up(uint64_t value, uint64_t align) {
  return (value + align - 1U) & ~(align - 1U);
}

static uint64_t pages_for_bytes(uint64_t bytes) {
  return align_up(bytes, PAGE_SIZE) / PAGE_SIZE;
}

static xaios_ai_cell_t *cell_by_id(uint32_t cell_id) {
  if (cell_id >= MAX_AI_CELLS) {
    return 0;
  }
  return &g_ai_cells[cell_id];
}

static xaios_status_t bind_nic_queue(uint32_t cell_id, uint32_t queue_id) {
  if (queue_id >= MAX_NIC_QUEUES || g_nic_queue_owner[queue_id] != 0) {
    ++g_conflict_count;
    return XAIOS_ERR_BUSY;
  }
  xaios_ai_cell_t *cell = cell_by_id(cell_id);
  if (cell == 0 ||
      network_stack_bind_queue(cell_id, queue_id, cell->manifest.core_mask) !=
          XAIOS_OK) {
    ++g_resource_reject_count;
    return XAIOS_ERR_BUSY;
  }
  g_nic_queue_owner[queue_id] = (uint8_t)(cell_id + 1U);
  ++g_queue_bind_count;
  return XAIOS_OK;
}

static void release_nic_queue(uint32_t cell_id, uint32_t queue_id) {
  if (queue_id < MAX_NIC_QUEUES &&
      g_nic_queue_owner[queue_id] == (uint8_t)(cell_id + 1U)) {
    g_nic_queue_owner[queue_id] = 0;
    kassert(network_stack_release_queue(queue_id, cell_id) == XAIOS_OK);
    ++g_queue_release_count;
  }
}

static xaios_status_t bind_workspace(uint32_t cell_id, uint32_t workspace_id) {
  if (workspace_id == 0 || workspace_id > MAX_WORKSPACES ||
      g_workspace_owner[workspace_id] != 0) {
    ++g_conflict_count;
    return XAIOS_ERR_BUSY;
  }
  g_workspace_owner[workspace_id] = (uint8_t)(cell_id + 1U);
  ++g_workspace_bind_count;
  return XAIOS_OK;
}

static void release_workspace(uint32_t cell_id, uint32_t workspace_id) {
  if (workspace_id <= MAX_WORKSPACES &&
      g_workspace_owner[workspace_id] == (uint8_t)(cell_id + 1U)) {
    g_workspace_owner[workspace_id] = 0;
    ++g_workspace_release_count;
  }
}

static void destroy_cell_arenas(xaios_ai_cell_t *cell) {
  uint64_t released_pages = 0;
  uint64_t released_bytes = 0;
  if (cell->kv_cache_arena_id != 0) {
    released_pages += pages_for_bytes(cell->manifest.kv_cache_bytes);
    released_bytes += cell->manifest.kv_cache_bytes;
    kassert(arena_destroy(cell->kv_cache_arena_id) == XAIOS_OK);
  }
  if (cell->source_index_arena_id != 0) {
    released_pages += pages_for_bytes(cell->manifest.source_index_bytes);
    released_bytes += cell->manifest.source_index_bytes;
    kassert(arena_destroy(cell->source_index_arena_id) == XAIOS_OK);
  }
  if (cell->build_output_arena_id != 0) {
    released_pages += pages_for_bytes(CELL_BUILD_OUTPUT_BYTES);
    released_bytes += CELL_BUILD_OUTPUT_BYTES;
    kassert(arena_destroy(cell->build_output_arena_id) == XAIOS_OK);
  }
  if (cell->log_arena_id != 0) {
    released_pages += pages_for_bytes(CELL_LOG_BYTES);
    released_bytes += CELL_LOG_BYTES;
    kassert(arena_destroy(cell->log_arena_id) == XAIOS_OK);
  }
  if (released_pages <= g_arena_pages_reserved) {
    g_arena_pages_reserved -= released_pages;
  } else {
    g_arena_pages_reserved = 0;
  }
  if (released_bytes <= g_arena_bytes_reserved) {
    g_arena_bytes_reserved -= released_bytes;
  } else {
    g_arena_bytes_reserved = 0;
  }
  cell->kv_cache_arena_id = 0;
  cell->source_index_arena_id = 0;
  cell->build_output_arena_id = 0;
  cell->log_arena_id = 0;
  cell->kv_cache_base = 0;
  cell->source_index_base = 0;
  cell->build_output_base = 0;
  cell->log_base = 0;
}

static xaios_status_t reserve_memory_arenas(xaios_ai_cell_t *cell) {
  const xaios_arena_t *kv = 0;
  const xaios_arena_t *source = 0;
  const xaios_arena_t *build = 0;
  const xaios_arena_t *log = 0;
  uint32_t kv_id = CELL_KV_ARENA_BASE + cell->cell_id;
  uint32_t source_id = CELL_SOURCE_ARENA_BASE + cell->cell_id;
  uint32_t build_id = CELL_BUILD_ARENA_BASE + cell->cell_id;
  uint32_t log_id = CELL_LOG_ARENA_BASE + cell->cell_id;

  if (arena_create(kv_id, XAIOS_ARENA_KV_CACHE, cell->cell_id,
                   "cell-kv-cache", cell->manifest.kv_cache_bytes, 0,
                   &kv) != XAIOS_OK) {
    ++g_resource_reject_count;
    destroy_cell_arenas(cell);
    return XAIOS_ERR_NO_MEMORY;
  }
  cell->kv_cache_arena_id = kv_id;

  if (arena_create(source_id, XAIOS_ARENA_SOURCE_INDEX, cell->cell_id,
                   "cell-source-index", cell->manifest.source_index_bytes, 0,
                   &source) != XAIOS_OK) {
    ++g_resource_reject_count;
    destroy_cell_arenas(cell);
    return XAIOS_ERR_NO_MEMORY;
  }
  cell->source_index_arena_id = source_id;

  if (arena_create(build_id, XAIOS_ARENA_BUILD_OUTPUT, cell->cell_id,
                   "cell-build-output", CELL_BUILD_OUTPUT_BYTES, 0,
                   &build) != XAIOS_OK) {
    ++g_resource_reject_count;
    destroy_cell_arenas(cell);
    return XAIOS_ERR_NO_MEMORY;
  }
  cell->build_output_arena_id = build_id;

  if (arena_create(log_id, XAIOS_ARENA_LOG, cell->cell_id, "cell-log",
                   CELL_LOG_BYTES, 0, &log) != XAIOS_OK) {
    ++g_resource_reject_count;
    destroy_cell_arenas(cell);
    return XAIOS_ERR_NO_MEMORY;
  }
  cell->log_arena_id = log_id;

  cell->kv_cache_base = kv->base;
  cell->source_index_base = source->base;
  cell->build_output_base = build->base;
  cell->log_base = log->base;
  g_arena_pages_reserved +=
      pages_for_bytes(cell->manifest.kv_cache_bytes) +
      pages_for_bytes(cell->manifest.source_index_bytes) +
      pages_for_bytes(CELL_BUILD_OUTPUT_BYTES) +
      pages_for_bytes(CELL_LOG_BYTES);
  g_arena_bytes_reserved += cell->manifest.kv_cache_bytes +
                            cell->manifest.source_index_bytes +
                            CELL_BUILD_OUTPUT_BYTES + CELL_LOG_BYTES;
  if (g_arena_pages_reserved > g_arena_pages_peak) {
    g_arena_pages_peak = g_arena_pages_reserved;
  }
  if (g_arena_bytes_reserved > g_arena_bytes_peak) {
    g_arena_bytes_peak = g_arena_bytes_reserved;
  }
  return XAIOS_OK;
}

static void copy_manifest(xaios_ai_cell_manifest_t *dst,
                          const xaios_ai_cell_manifest_t *src,
                          xaios_ai_cell_t *cell) {
  ai_cell_copy_name(cell->name_storage, src->name);
  dst->name = cell->name_storage;
  dst->core_mask = src->core_mask;
  dst->model_arena_id = src->model_arena_id;
  dst->kv_cache_bytes = src->kv_cache_bytes;
  dst->source_index_bytes = src->source_index_bytes;
  dst->nic_queue_id = src->nic_queue_id;
  dst->git_workspace_id = src->git_workspace_id;
}

void ai_cell_runtime_init(void) {
  core_lease_init();
  g_transition_count = 0;
  g_descriptor_accept_count = 0;
  g_descriptor_reject_count = 0;
  g_resource_admission_count = 0;
  g_resource_reject_count = 0;
  g_arena_pages_reserved = 0;
  g_arena_bytes_reserved = 0;
  g_arena_pages_peak = 0;
  g_arena_bytes_peak = 0;
  g_queue_bind_count = 0;
  g_queue_release_count = 0;
  g_workspace_bind_count = 0;
  g_workspace_release_count = 0;
  g_conflict_count = 0;
  for (uint32_t i = 0; i < MAX_NIC_QUEUES; ++i) {
    g_nic_queue_owner[i] = 0;
  }
  for (uint32_t i = 0; i <= MAX_WORKSPACES; ++i) {
    g_workspace_owner[i] = 0;
  }
  for (uint32_t i = 0; i < MAX_AI_CELLS; ++i) {
    g_ai_cells[i].cell_id = i;
    g_ai_cells[i].state = XAIOS_AI_CELL_EMPTY;
    g_ai_cells[i].name_storage[0] = '\0';
    g_ai_cells[i].lifecycle_generation = 0;
    g_ai_cells[i].kv_cache_arena_id = 0;
    g_ai_cells[i].source_index_arena_id = 0;
    g_ai_cells[i].build_output_arena_id = 0;
    g_ai_cells[i].log_arena_id = 0;
    g_ai_cells[i].kv_cache_base = 0;
    g_ai_cells[i].source_index_base = 0;
    g_ai_cells[i].build_output_base = 0;
    g_ai_cells[i].log_base = 0;
  }
  klog("ai-cell: runtime initialized\n");
}

xaios_status_t ai_cell_create_from_descriptor(
    const xaios_ai_cell_descriptor_v1_t *descriptor) {
  xaios_ai_cell_manifest_t manifest;
  if (ai_cell_validate_descriptor(descriptor, &manifest) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  xaios_status_t status = ai_cell_create(descriptor->cell_id, &manifest);
  if (status == XAIOS_OK) {
    ++g_descriptor_accept_count;
    klog("ai-cell: descriptor accepted version=%u bytes=%u cell=%u name=%s flags=0x%x checksum=0x%lx\n",
         descriptor->version, descriptor->descriptor_bytes,
         descriptor->cell_id, descriptor->name, descriptor->flags,
         descriptor->checksum);
  }
  return status;
}

xaios_status_t ai_cell_create(uint32_t cell_id,
                             const xaios_ai_cell_manifest_t *manifest) {
  xaios_ai_cell_t *cell = cell_by_id(cell_id);
  if (cell == 0 || cell->state != XAIOS_AI_CELL_EMPTY ||
      ai_cell_validate_manifest(manifest) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }

  copy_manifest(&cell->manifest, manifest, cell);
  cell->state = XAIOS_AI_CELL_CREATED;
  ++cell->lifecycle_generation;
  ++g_transition_count;
  klog("ai-cell: %u created name=%s core_mask=0x%x model_arena=%u\n",
       cell_id, manifest->name, manifest->core_mask, manifest->model_arena_id);
  return XAIOS_OK;
}

xaios_status_t ai_cell_prepare(uint32_t cell_id) {
  xaios_ai_cell_t *cell = cell_by_id(cell_id);
  if (cell == 0 || cell->state != XAIOS_AI_CELL_CREATED) {
    return XAIOS_ERR_INVALID;
  }
  const xaios_model_arena_t *arena = 0;
  if (model_arena_acquire(cell->manifest.model_arena_id, &arena) != XAIOS_OK) {
    ++g_resource_reject_count;
    cell->state = XAIOS_AI_CELL_FAILED;
    ++g_transition_count;
    return XAIOS_ERR_INVALID;
  }
  if (core_lease_acquire(cell_id, cell->manifest.core_mask) != XAIOS_OK) {
    ++g_conflict_count;
    ++g_resource_reject_count;
    kassert(model_arena_release(cell->manifest.model_arena_id) == XAIOS_OK);
    cell->state = XAIOS_AI_CELL_FAILED;
    ++g_transition_count;
    return XAIOS_ERR_INVALID;
  }
  if (bind_nic_queue(cell_id, cell->manifest.nic_queue_id) != XAIOS_OK ||
      bind_workspace(cell_id, cell->manifest.git_workspace_id) != XAIOS_OK ||
      reserve_memory_arenas(cell) != XAIOS_OK) {
    ++g_resource_reject_count;
    release_nic_queue(cell_id, cell->manifest.nic_queue_id);
    release_workspace(cell_id, cell->manifest.git_workspace_id);
    kassert(core_lease_release(cell_id) == XAIOS_OK);
    kassert(model_arena_release(cell->manifest.model_arena_id) == XAIOS_OK);
    cell->state = XAIOS_AI_CELL_FAILED;
    ++g_transition_count;
    return XAIOS_ERR_INVALID;
  }
  if (cpu_ai_runtime_bind_model_with_kv(cell_id, cell->manifest.model_arena_id,
                                        cell->kv_cache_base,
                                        cell->manifest.kv_cache_bytes) !=
      XAIOS_OK) {
    ++g_resource_reject_count;
    destroy_cell_arenas(cell);
    release_nic_queue(cell_id, cell->manifest.nic_queue_id);
    release_workspace(cell_id, cell->manifest.git_workspace_id);
    kassert(core_lease_release(cell_id) == XAIOS_OK);
    kassert(model_arena_release(cell->manifest.model_arena_id) == XAIOS_OK);
    cell->state = XAIOS_AI_CELL_FAILED;
    ++g_transition_count;
    return XAIOS_ERR_INVALID;
  }

  cell->state = XAIOS_AI_CELL_READY;
  ++g_transition_count;
  ++g_resource_admission_count;
  klog("ai-cell: %u ready shared_model=%s refs=%u kv=0x%lx source=0x%lx build=0x%lx log=0x%lx nic_queue=%u workspace=%u\n",
       cell_id, arena->name, arena->ref_count, cell->kv_cache_base,
       cell->source_index_base, cell->build_output_base, cell->log_base,
       cell->manifest.nic_queue_id, cell->manifest.git_workspace_id);
  return XAIOS_OK;
}

xaios_status_t ai_cell_start(uint32_t cell_id) {
  xaios_ai_cell_t *cell = cell_by_id(cell_id);
  if (cell == 0 || cell->state != XAIOS_AI_CELL_READY) {
    return XAIOS_ERR_INVALID;
  }

  cell->state = XAIOS_AI_CELL_RUNNING;
  ++g_transition_count;
  klog("ai-cell: %u running\n", cell_id);
  return XAIOS_OK;
}

xaios_status_t ai_cell_stop(uint32_t cell_id) {
  xaios_ai_cell_t *cell = cell_by_id(cell_id);
  if (cell == 0 || cell->state != XAIOS_AI_CELL_RUNNING) {
    return XAIOS_ERR_INVALID;
  }

  kassert(cpu_ai_runtime_unbind_model(cell_id) == XAIOS_OK);
  kassert(model_arena_release(cell->manifest.model_arena_id) == XAIOS_OK);
  kassert(core_lease_release(cell_id) == XAIOS_OK);
  release_nic_queue(cell_id, cell->manifest.nic_queue_id);
  release_workspace(cell_id, cell->manifest.git_workspace_id);
  destroy_cell_arenas(cell);
  cell->state = XAIOS_AI_CELL_STOPPED;
  ++g_transition_count;
  klog("ai-cell: %u stopped\n", cell_id);
  return XAIOS_OK;
}

uint64_t ai_cell_transition_count(void) {
  return g_transition_count;
}

uint64_t ai_cell_descriptor_accept_count(void) {
  return g_descriptor_accept_count;
}

uint64_t ai_cell_descriptor_reject_count(void) {
  return g_descriptor_reject_count;
}

uint64_t ai_cell_resource_admission_count(void) {
  return g_resource_admission_count;
}

uint64_t ai_cell_resource_reject_count(void) {
  return g_resource_reject_count;
}

uint64_t ai_cell_arena_pages_reserved(void) {
  return g_arena_pages_reserved;
}

uint64_t ai_cell_arena_bytes_reserved(void) {
  return g_arena_bytes_reserved;
}

uint64_t ai_cell_arena_pages_peak(void) {
  return g_arena_pages_peak;
}

uint64_t ai_cell_arena_bytes_peak(void) {
  return g_arena_bytes_peak;
}

uint64_t ai_cell_queue_bind_count(void) {
  return g_queue_bind_count;
}

uint64_t ai_cell_queue_release_count(void) {
  return g_queue_release_count;
}

uint64_t ai_cell_workspace_bind_count(void) {
  return g_workspace_bind_count;
}

uint64_t ai_cell_workspace_release_count(void) {
  return g_workspace_release_count;
}

uint64_t ai_cell_conflict_count(void) {
  return g_conflict_count;
}
