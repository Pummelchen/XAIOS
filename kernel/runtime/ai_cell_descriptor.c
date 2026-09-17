/*
 * The AI cell descriptor ABI and its admission checks, moved out of
 * ai_cell.c. See ai_cell_internal.h: the shared limits and the two
 * admission-counter seeds live there, and every decision below -- magic,
 * version, descriptor size, flags, cell id, reserved field, name, the two
 * fixed arena sizes, the checksum, and the manifest fields -- is the check
 * the unsplit file made, byte for byte. No limit or boundary changed.
 *
 * The descriptor builders (ai_cell_fill_descriptor/ai_cell_copy_descriptor)
 * moved with the checksum they share; the boot self-test in
 * ai_cell_self_test.c builds its fixtures through them.
 */

#include "ai_cell_internal.h"

#include <xaios/assert.h>
#include <xaios/model_arena.h>

#define FNV1A64_OFFSET UINT64_C(14695981039346656037)
#define FNV1A64_PRIME UINT64_C(1099511628211)

static int str_nonempty(const char *value) {
  return value != 0 && value[0] != '\0';
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

void ai_cell_copy_name(char *dst, const char *src) {
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

uint64_t ai_cell_descriptor_checksum(
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

xaios_status_t ai_cell_validate_manifest(
    const xaios_ai_cell_manifest_t *manifest) {
  if (manifest == 0 || !str_nonempty(manifest->name)) {
    ai_cell_note_resource_reject();
    return XAIOS_ERR_INVALID;
  }
  if (manifest->core_mask == 0 || manifest->kv_cache_bytes == 0 ||
      manifest->source_index_bytes == 0) {
    ai_cell_note_resource_reject();
    return XAIOS_ERR_INVALID;
  }
  if (manifest->git_workspace_id == 0 ||
      manifest->git_workspace_id > MAX_WORKSPACES ||
      manifest->nic_queue_id >= MAX_NIC_QUEUES) {
    ai_cell_note_resource_reject();
    return XAIOS_ERR_INVALID;
  }

  const xaios_model_arena_t *arena = 0;
  if (model_arena_acquire(manifest->model_arena_id, &arena) != XAIOS_OK) {
    ai_cell_note_resource_reject();
    return XAIOS_ERR_INVALID;
  }
  kassert(model_arena_release(manifest->model_arena_id) == XAIOS_OK);
  return XAIOS_OK;
}

xaios_status_t ai_cell_validate_descriptor(
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
      ai_cell_descriptor_checksum(descriptor) != descriptor->checksum) {
    ai_cell_note_descriptor_reject();
    ai_cell_note_resource_reject();
    return XAIOS_ERR_INVALID;
  }

  manifest->name = descriptor->name;
  manifest->core_mask = descriptor->core_mask;
  manifest->model_arena_id = descriptor->model_arena_id;
  manifest->kv_cache_bytes = descriptor->kv_cache_bytes;
  manifest->source_index_bytes = descriptor->source_index_bytes;
  manifest->nic_queue_id = descriptor->nic_queue_id;
  manifest->git_workspace_id = descriptor->git_workspace_id;
  if (ai_cell_validate_manifest(manifest) != XAIOS_OK) {
    ai_cell_note_descriptor_reject();
    return XAIOS_ERR_INVALID;
  }
  return XAIOS_OK;
}

void ai_cell_fill_descriptor(xaios_ai_cell_descriptor_v1_t *descriptor,
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
  ai_cell_copy_name(descriptor->name, name);
  descriptor->checksum = 0;
  descriptor->checksum = ai_cell_descriptor_checksum(descriptor);
}

void ai_cell_copy_descriptor(xaios_ai_cell_descriptor_v1_t *dst,
                             const xaios_ai_cell_descriptor_v1_t *src) {
  uint8_t *out = (uint8_t *)(void *)dst;
  const uint8_t *in = (const uint8_t *)(const void *)src;
  for (uint64_t i = 0; i < sizeof(*dst); ++i) {
    out[i] = in[i];
  }
}
