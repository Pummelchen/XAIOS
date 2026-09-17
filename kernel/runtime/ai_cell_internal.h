/*
 * Private interface shared by the three translation units of the AI cell
 * runtime, after ai_cell.c was split so no source file exceeds 500 lines.
 *
 * ai_cell.c keeps the lifecycle, the NIC-queue and workspace binding, and the
 * arena reservation/accounting. The descriptor ABI and its admission checks
 * -- the checksum, the manifest check, the descriptor check and the two
 * builders -- live in ai_cell_descriptor.c. The boot self-test lives in
 * ai_cell_self_test.c.
 *
 * Everything that crosses a file boundary is declared here. The names carry
 * the module's ai_cell_ prefix because they are new global symbols; the two
 * accessor pairs that the public ai_cell.h already declares are unchanged.
 *
 * The limits below are the ones both the lifecycle and the ABI code must
 * agree on. They are the same constants the unsplit file defined, with the
 * same values; no boundary, limit or admission decision moved.
 *
 * Counter ownership. The two admission counters stay static in ai_cell.c,
 * beside the accessors that read them. ai_cell_descriptor.c reaches them
 * through the two note_* seeds below, each of which performs exactly the one
 * increment the unsplit code performed inline, at the same point in the same
 * order. These counters take no lock before or after, so no critical section
 * changes shape.
 */
#ifndef XAIOS_KERNEL_RUNTIME_AI_CELL_INTERNAL_H
#define XAIOS_KERNEL_RUNTIME_AI_CELL_INTERNAL_H

#include <xaios/ai_cell.h>
#include <xaios/types.h>

/* Admission limits and the two fixed arena sizes, shared by both sides. */
#define MAX_AI_CELLS 5U
#define MAX_NIC_QUEUES 4U
#define MAX_WORKSPACES 2U
#define CELL_BUILD_OUTPUT_BYTES UINT64_C(65536)
#define CELL_LOG_BYTES UINT64_C(65536)

/* Descriptor ABI, defined once in ai_cell_descriptor.c. */
uint64_t ai_cell_descriptor_checksum(
    const xaios_ai_cell_descriptor_v1_t *descriptor);
void ai_cell_copy_name(char *dst, const char *src);
xaios_status_t ai_cell_validate_manifest(
    const xaios_ai_cell_manifest_t *manifest);
xaios_status_t ai_cell_validate_descriptor(
    const xaios_ai_cell_descriptor_v1_t *descriptor,
    xaios_ai_cell_manifest_t *manifest);
void ai_cell_fill_descriptor(xaios_ai_cell_descriptor_v1_t *descriptor,
                             uint32_t cell_id, const char *name,
                             uint32_t core_mask, uint32_t model_arena_id,
                             uint32_t nic_queue_id, uint32_t workspace_id,
                             uint64_t kv_bytes, uint64_t source_bytes);
void ai_cell_copy_descriptor(xaios_ai_cell_descriptor_v1_t *dst,
                             const xaios_ai_cell_descriptor_v1_t *src);

/* Admission-counter seeds, defined once in ai_cell.c. Each performs the single
   increment the unsplit file performed inline. */
void ai_cell_note_descriptor_reject(void);
void ai_cell_note_resource_reject(void);

#endif /* XAIOS_KERNEL_RUNTIME_AI_CELL_INTERNAL_H */
