/*
 * Private interface shared by the three translation units of the git
 * workspace runtime, after git_workspace.c was split so no source file
 * exceeds 500 lines.
 *
 * git_workspace.c keeps the workspace table, the create/sync/patch/revert
 * state machine and the five lifecycle counters. The blob hashing and the
 * line-based diff live in git_workspace_hash.c, together with the two
 * counters and the two accessors they feed. The boot self-test lives in
 * git_workspace_selftest.c.
 *
 * Everything that crosses a file boundary is declared here. The names carry
 * the module's git_workspace_ prefix because they are new global symbols; the
 * functions the public git_workspace.h already declares are unchanged.
 *
 * Counter ownership. g_blob_hash_count and g_diff_count moved with the code
 * that increments them, so git_workspace_hash.c owns both counters and the
 * accessors that read them. git_workspace_runtime_init() reaches them through
 * git_workspace_hash_stats_reset(), which performs exactly the two
 * assignments the unsplit init performed inline, at the same point in the
 * same order. Neither counter takes a lock before or after, so no critical
 * section changes shape.
 *
 * The three *_as functions below are the actor-checked entry points the
 * unsplit file kept static. The self-test calls them directly, so they can no
 * longer be static; their bodies, guards and return values are unchanged.
 */
#ifndef XAIOS_KERNEL_RUNTIME_GIT_WORKSPACE_INTERNAL_H
#define XAIOS_KERNEL_RUNTIME_GIT_WORKSPACE_INTERNAL_H

#include <xaios/git_workspace.h>
#include <xaios/types.h>

/* Defined once in git_workspace_hash.c. Zeroes the blob-hash and diff
   counters exactly where git_workspace_runtime_init() zeroed them inline. */
void git_workspace_hash_stats_reset(void);

/* Actor-checked entry points, defined once in git_workspace.c. */
xaios_status_t git_workspace_sync_start_as(uint32_t actor_cell_id,
                                           uint32_t workspace_id,
                                           const char *revision);
xaios_status_t git_workspace_patch_apply_start_as(uint32_t actor_cell_id,
                                                  uint32_t workspace_id,
                                                  const char *patch_id,
                                                  uint64_t patch_bytes);
xaios_status_t git_workspace_patch_revert_start_as(uint32_t actor_cell_id,
                                                   uint32_t workspace_id);

#endif /* XAIOS_KERNEL_RUNTIME_GIT_WORKSPACE_INTERNAL_H */
