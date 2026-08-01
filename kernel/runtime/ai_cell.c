#include <xaios/arena.h>
#include <xaios/ai_cell.h>
#include <xaios/assert.h>
#include <xaios/cpu_ai_runtime.h>
#include <xaios/core_lease.h>
#include <xaios/klog.h>
#include <xaios/model_arena.h>
#include <xaios/network_stack.h>

#define MAX_AI_CELLS 5U
#define MAX_NIC_QUEUES 4U
#define MAX_WORKSPACES 2U
#define CELL_KV_ARENA_BASE 4U
#define CELL_SOURCE_ARENA_BASE 8U
#define CELL_BUILD_ARENA_BASE 12U
#define CELL_LOG_ARENA_BASE 16U
#define CELL_BUILD_OUTPUT_BYTES UINT64_C(65536)
#define CELL_LOG_BYTES UINT64_C(65536)
#define PAGE_SIZE UINT64_C(4096)
#define FNV1A64_OFFSET UINT64_C(14695981039346656037)
#define FNV1A64_PRIME UINT64_C(1099511628211)

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

static int str_nonempty(const char *value) {
  return value != 0 && value[0] != '\0';
}

static int str_equal(const char *lhs, const char *rhs) {
  if (lhs == 0 || rhs == 0) {
    return 0;
  }
  for (uint32_t i = 0;; ++i) {
    if (lhs[i] != rhs[i]) {
      return 0;
    }
    if (lhs[i] == '\0') {
      return 1;
    }
  }
}

static uint32_t string_length_bounded(const char *value, uint32_t limit) {
  uint32_t len = 0;
  if (value == 0) {
    return 0;
  }
  while (len < limit && value[len] != '\0') {
    ++len;
  }
  return len;
}

static void copy_name(char *dst, const char *src) {
  uint32_t i = 0;
  if (src == 0) {
    dst[0] = '\0';
    return;
  }
  for (; i + 1U < XAIOS_AI_CELL_DESCRIPTOR_NAME_MAX && src[i] != '\0'; ++i) {
    dst[i] = src[i];
  }
  dst[i] = '\0';
}

static uint64_t align_up(uint64_t value, uint64_t align) {
  return (value + align - 1U) & ~(align - 1U);
}

static uint64_t pages_for_bytes(uint64_t bytes) {
  return align_up(bytes, PAGE_SIZE) / PAGE_SIZE;
}

static uint64_t fnv1a64_with_zero_checksum(
    const xaios_ai_cell_descriptor_v1_t *descriptor) {
  const uint8_t *bytes = (const uint8_t *)(const void *)descriptor;
  uint64_t hash = FNV1A64_OFFSET;
  const uint64_t checksum_offset =
      (uint64_t)((const uint8_t *)(const void *)&descriptor->checksum - bytes);
  for (uint64_t i = 0; i < sizeof(*descriptor); ++i) {
    uint8_t value = bytes[i];
    if (i >= checksum_offset && i < checksum_offset + sizeof(uint64_t)) {
      value = 0;
    }
    hash ^= value;
    hash *= FNV1A64_PRIME;
  }
  return hash;
}

static int descriptor_name_valid(const char *name) {
  uint32_t len = string_length_bounded(name, XAIOS_AI_CELL_DESCRIPTOR_NAME_MAX);
  if (len == 0 || len >= XAIOS_AI_CELL_DESCRIPTOR_NAME_MAX) {
    return 0;
  }
  return name[len] == '\0';
}

static xaios_ai_cell_t *cell_by_id(uint32_t cell_id) {
  if (cell_id >= MAX_AI_CELLS) {
    return 0;
  }
  return &g_ai_cells[cell_id];
}

static xaios_status_t validate_manifest(const xaios_ai_cell_manifest_t *manifest) {
  if (manifest == 0 || !str_nonempty(manifest->name)) {
    ++g_resource_reject_count;
    return XAIOS_ERR_INVALID;
  }
  if (manifest->core_mask == 0 || manifest->kv_cache_bytes == 0 ||
      manifest->source_index_bytes == 0) {
    ++g_resource_reject_count;
    return XAIOS_ERR_INVALID;
  }
  if (manifest->git_workspace_id == 0 ||
      manifest->git_workspace_id > MAX_WORKSPACES ||
      manifest->nic_queue_id >= MAX_NIC_QUEUES) {
    ++g_resource_reject_count;
    return XAIOS_ERR_INVALID;
  }

  const xaios_model_arena_t *arena = 0;
  if (model_arena_acquire(manifest->model_arena_id, &arena) != XAIOS_OK) {
    ++g_resource_reject_count;
    return XAIOS_ERR_INVALID;
  }
  kassert(model_arena_release(manifest->model_arena_id) == XAIOS_OK);
  return XAIOS_OK;
}

static xaios_status_t validate_descriptor(
    const xaios_ai_cell_descriptor_v1_t *descriptor,
    xaios_ai_cell_manifest_t *manifest) {
  if (descriptor == 0 || manifest == 0 ||
      descriptor->magic != XAIOS_AI_CELL_DESCRIPTOR_MAGIC ||
      descriptor->version != XAIOS_AI_CELL_DESCRIPTOR_VERSION ||
      descriptor->descriptor_bytes != sizeof(xaios_ai_cell_descriptor_v1_t) ||
      (descriptor->flags & XAIOS_AI_CELL_DESCRIPTOR_REQUIRED_FLAGS) !=
          XAIOS_AI_CELL_DESCRIPTOR_REQUIRED_FLAGS ||
      (descriptor->flags & ~XAIOS_AI_CELL_DESCRIPTOR_REQUIRED_FLAGS) != 0 ||
      descriptor->cell_id >= MAX_AI_CELLS ||
      descriptor->reserved0 != 0 ||
      !descriptor_name_valid(descriptor->name) ||
      descriptor->build_output_bytes != CELL_BUILD_OUTPUT_BYTES ||
      descriptor->log_bytes != CELL_LOG_BYTES ||
      fnv1a64_with_zero_checksum(descriptor) != descriptor->checksum) {
    ++g_descriptor_reject_count;
    ++g_resource_reject_count;
    return XAIOS_ERR_INVALID;
  }

  manifest->name = descriptor->name;
  manifest->core_mask = descriptor->core_mask;
  manifest->model_arena_id = descriptor->model_arena_id;
  manifest->kv_cache_bytes = descriptor->kv_cache_bytes;
  manifest->source_index_bytes = descriptor->source_index_bytes;
  manifest->nic_queue_id = descriptor->nic_queue_id;
  manifest->git_workspace_id = descriptor->git_workspace_id;
  if (validate_manifest(manifest) != XAIOS_OK) {
    ++g_descriptor_reject_count;
    return XAIOS_ERR_INVALID;
  }
  return XAIOS_OK;
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
  copy_name(cell->name_storage, src->name);
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
  if (validate_descriptor(descriptor, &manifest) != XAIOS_OK) {
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
      validate_manifest(manifest) != XAIOS_OK) {
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

static void fill_descriptor(xaios_ai_cell_descriptor_v1_t *descriptor,
                            uint32_t cell_id, const char *name,
                            uint32_t core_mask, uint32_t model_arena_id,
                            uint32_t nic_queue_id, uint32_t workspace_id,
                            uint64_t kv_bytes, uint64_t source_bytes) {
  descriptor->magic = XAIOS_AI_CELL_DESCRIPTOR_MAGIC;
  descriptor->version = XAIOS_AI_CELL_DESCRIPTOR_VERSION;
  descriptor->descriptor_bytes = sizeof(xaios_ai_cell_descriptor_v1_t);
  descriptor->flags = XAIOS_AI_CELL_DESCRIPTOR_REQUIRED_FLAGS;
  descriptor->cell_id = cell_id;
  descriptor->core_mask = core_mask;
  descriptor->model_arena_id = model_arena_id;
  descriptor->nic_queue_id = nic_queue_id;
  descriptor->git_workspace_id = workspace_id;
  descriptor->reserved0 = 0;
  descriptor->kv_cache_bytes = kv_bytes;
  descriptor->source_index_bytes = source_bytes;
  descriptor->build_output_bytes = CELL_BUILD_OUTPUT_BYTES;
  descriptor->log_bytes = CELL_LOG_BYTES;
  copy_name(descriptor->name, name);
  descriptor->checksum = 0;
  descriptor->checksum = fnv1a64_with_zero_checksum(descriptor);
}

static void copy_descriptor(xaios_ai_cell_descriptor_v1_t *dst,
                            const xaios_ai_cell_descriptor_v1_t *src) {
  uint8_t *out = (uint8_t *)(void *)dst;
  const uint8_t *in = (const uint8_t *)(const void *)src;
  for (uint64_t i = 0; i < sizeof(*dst); ++i) {
    out[i] = in[i];
  }
}

void ai_cell_self_test(void) {
  ai_cell_runtime_init();
  xaios_ai_cell_manifest_t invalid;
  invalid.name = "invalid";
  invalid.core_mask = 0;
  invalid.model_arena_id = 2;
  invalid.kv_cache_bytes = 4096;
  invalid.source_index_bytes = 4096;
  invalid.nic_queue_id = 1;
  invalid.git_workspace_id = 1;
  kassert(ai_cell_create(0, &invalid) == XAIOS_ERR_INVALID);

  invalid.core_mask = 0x8;
  invalid.model_arena_id = 99;
  invalid.git_workspace_id = 1;
  kassert(ai_cell_create(3, &invalid) == XAIOS_ERR_INVALID);

  invalid.model_arena_id = 2;
  invalid.git_workspace_id = 99;
  kassert(ai_cell_create(3, &invalid) == XAIOS_ERR_INVALID);

  xaios_ai_cell_descriptor_v1_t descriptor;
  xaios_ai_cell_descriptor_v1_t bad_descriptor;
  fill_descriptor(&descriptor, 0, "codex-app-agent", 0x2, 2, 1, 1,
                  64 * 1024, 128 * 1024);

  copy_descriptor(&bad_descriptor, &descriptor);
  bad_descriptor.checksum ^= UINT64_C(1);
  kassert(ai_cell_create_from_descriptor(&bad_descriptor) == XAIOS_ERR_INVALID);

  copy_descriptor(&bad_descriptor, &descriptor);
  bad_descriptor.version = 99;
  bad_descriptor.checksum = fnv1a64_with_zero_checksum(&bad_descriptor);
  kassert(ai_cell_create_from_descriptor(&bad_descriptor) == XAIOS_ERR_INVALID);

  copy_descriptor(&bad_descriptor, &descriptor);
  bad_descriptor.flags &= ~XAIOS_AI_CELL_DESCRIPTOR_FLAG_PRIVATE_KV;
  bad_descriptor.checksum = fnv1a64_with_zero_checksum(&bad_descriptor);
  kassert(ai_cell_create_from_descriptor(&bad_descriptor) == XAIOS_ERR_INVALID);

  copy_descriptor(&bad_descriptor, &descriptor);
  bad_descriptor.cell_id = 3;
  bad_descriptor.model_arena_id = 99;
  bad_descriptor.checksum = fnv1a64_with_zero_checksum(&bad_descriptor);
  kassert(ai_cell_create_from_descriptor(&bad_descriptor) == XAIOS_ERR_INVALID);

  kassert(ai_cell_create_from_descriptor(&descriptor) == XAIOS_OK);
  kassert(ai_cell_prepare(0) == XAIOS_OK);
  kassert(ai_cell_start(0) == XAIOS_OK);
  char output[32];
  uint64_t out = 0;
  const uint8_t piece[] = {'A', 'B', 'C', 'D'};
  kassert(cpu_ai_runtime_fixture_decode_piece(0, piece, sizeof(piece), output,
                                             sizeof(output), &out) ==
          XAIOS_OK);
  kassert(cpu_ai_runtime_decode_count(0) == 1);
  kassert(output[0] == '1');
  kassert(output[1] == 'B');
  kassert(output[2] == '1');
  kassert(output[3] == 'F');
  kassert(output[4] == '2');
  kassert(output[5] == '3');
  kassert(output[6] == '2');
  kassert(output[7] == '7');
  kassert(output[8] == '\0');

  xaios_ai_cell_descriptor_v1_t conflict;
  fill_descriptor(&conflict, 1, "core-conflict-agent", 0x2, 2, 2, 2,
                  64 * 1024, 128 * 1024);
  kassert(ai_cell_create_from_descriptor(&conflict) == XAIOS_OK);
  kassert(ai_cell_prepare(1) == XAIOS_ERR_INVALID);

  xaios_ai_cell_descriptor_v1_t nic_conflict;
  fill_descriptor(&nic_conflict, 2, "nic-conflict-agent", 0x4, 2, 1, 2,
                  64 * 1024, 128 * 1024);
  kassert(ai_cell_create_from_descriptor(&nic_conflict) == XAIOS_OK);
  kassert(ai_cell_prepare(2) == XAIOS_ERR_INVALID);

  xaios_ai_cell_descriptor_v1_t workspace_conflict;
  fill_descriptor(&workspace_conflict, 4, "workspace-conflict-agent", 0x4, 2,
                  2, 1, 64 * 1024, 128 * 1024);
  kassert(ai_cell_create_from_descriptor(&workspace_conflict) == XAIOS_OK);
  kassert(ai_cell_prepare(4) == XAIOS_ERR_INVALID);

  xaios_ai_cell_descriptor_v1_t shared;
  fill_descriptor(&shared, 3, "shared-weight-agent", 0x4, 2, 2, 2,
                  64 * 1024, 128 * 1024);
  kassert(ai_cell_create_from_descriptor(&shared) == XAIOS_OK);
  kassert(ai_cell_prepare(3) == XAIOS_OK);
  kassert(ai_cell_start(3) == XAIOS_OK);
  kassert(cpu_ai_runtime_fixture_decode_piece(3, piece, sizeof(piece), output,
                                             sizeof(output), &out) ==
          XAIOS_OK);
  kassert(str_equal(output, "1B1F2327"));
  kassert(ai_cell_arena_pages_reserved() == 160);
  kassert(ai_cell_arena_bytes_reserved() == 655360);
  kassert(ai_cell_arena_pages_peak() == 160);
  kassert(ai_cell_arena_bytes_peak() == 655360);
  kassert(ai_cell_stop(3) == XAIOS_OK);
  kassert(ai_cell_arena_pages_reserved() == 80);
  kassert(ai_cell_arena_bytes_reserved() == 327680);
  klog("ai-cell: multi-cell shared model/private kv self-test passed\n");

  kassert(ai_cell_stop(0) == XAIOS_OK);
  kassert(ai_cell_arena_pages_reserved() == 0);
  kassert(ai_cell_arena_bytes_reserved() == 0);
  kassert(ai_cell_descriptor_accept_count() == 5);
  kassert(ai_cell_descriptor_reject_count() == 4);
  kassert(ai_cell_resource_admission_count() == 2);
  kassert(ai_cell_resource_reject_count() >= 10);
  kassert(ai_cell_queue_bind_count() == 3);
  kassert(ai_cell_queue_release_count() == 3);
  kassert(ai_cell_workspace_bind_count() == 2);
  kassert(ai_cell_workspace_release_count() == 2);
  kassert(ai_cell_conflict_count() == 3);
  klog("ai-cell: descriptor ABI self-test passed accepts=%lu rejects=%lu checksum=0x%lx\n",
       ai_cell_descriptor_accept_count(), ai_cell_descriptor_reject_count(),
       descriptor.checksum);
  klog("ai-cell: resource contract self-test passed admissions=%lu rejects=%lu arena_pages=%lu arena_bytes=%lu queue_binds=%lu queue_releases=%lu workspace_binds=%lu workspace_releases=%lu conflicts=%lu\n",
       ai_cell_resource_admission_count(), ai_cell_resource_reject_count(),
       ai_cell_arena_pages_peak(), ai_cell_arena_bytes_peak(),
       ai_cell_queue_bind_count(), ai_cell_queue_release_count(),
       ai_cell_workspace_bind_count(), ai_cell_workspace_release_count(),
       ai_cell_conflict_count());
  klog("ai-cell: lifecycle self-test passed\n");
}
