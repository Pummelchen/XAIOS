/*
 * The git workspace boot self-test, moved out of git_workspace.c so no source
 * file exceeds 500 lines. It drives the public git_workspace.h lifecycle
 * exactly as before and reaches the three actor-checked entry points through
 * git_workspace_internal.h, which is why those three are no longer static.
 * Every assertion, expected value, log line and ordering is the one the
 * unsplit file contained, including the blob-hash and diff checks behind the
 * "git-workspace: blob hash and diff self-test passed" boot gate.
 */

#include <xaios/assert.h>
#include <xaios/git_workspace.h>
#include <xaios/klog.h>

#include "git_workspace_internal.h"

void git_workspace_self_test(void) {
  git_workspace_runtime_init();

  xaios_git_workspace_manifest_t invalid;
  invalid.workspace_id = 0;
  invalid.owner_cell_id = 0;
  invalid.repo_path = "repo/app";
  invalid.branch = "main";
  invalid.starting_revision = "r1";
  invalid.patch_buffer_bytes = 32 * 1024;
  kassert(git_workspace_create(&invalid) == XAIOS_ERR_INVALID);

  invalid.owner_cell_id = 1;
  invalid.repo_path = "/repo/app";
  invalid.patch_buffer_bytes = 0;
  kassert(git_workspace_create(&invalid) == XAIOS_ERR_INVALID);

  invalid.patch_buffer_bytes = 32 * 1024;
  kassert(git_workspace_create(&invalid) == XAIOS_OK);
  kassert(git_workspace_create(&invalid) == XAIOS_ERR_BUSY);

  xaios_git_workspace_manifest_t conflict;
  conflict.workspace_id = 1;
  conflict.owner_cell_id = 2;
  conflict.repo_path = "/repo/conflict";
  conflict.branch = "main";
  conflict.starting_revision = "r1";
  conflict.patch_buffer_bytes = 32 * 1024;
  kassert(git_workspace_create(&conflict) == XAIOS_OK);

  kassert(git_workspace_sync_start_as(3, 0, "r2-denied") ==
          XAIOS_ERR_INVALID);
  kassert(git_workspace_sync_start(0, "r2") == XAIOS_OK);
  kassert(git_workspace_sync_finish(0) == XAIOS_OK);

  kassert(git_workspace_patch_apply_finish(0) == XAIOS_ERR_INVALID);
  kassert(git_workspace_patch_apply_start_as(3, 0, "feature/denied", 128) ==
          XAIOS_ERR_INVALID);
  kassert(git_workspace_patch_apply_start(0, "token=bad", 128) ==
          XAIOS_ERR_INVALID);

  kassert(git_workspace_sync_start(1, "conflict") == XAIOS_OK);
  kassert(git_workspace_sync_finish(1) == XAIOS_ERR_INVALID);

  kassert(git_workspace_patch_apply_start(0, "feature/add-logging", 2048) ==
          XAIOS_OK);
  kassert(git_workspace_patch_apply_finish(0) == XAIOS_OK);
  kassert(git_workspace_patch_revert_start_as(3, 0) == XAIOS_ERR_INVALID);
  kassert(git_workspace_patch_revert_start(0) == XAIOS_OK);
  kassert(git_workspace_patch_revert_finish(0) == XAIOS_OK);

  kassert(git_workspace_patch_apply_start(0, "feature/mem", 70000) ==
          XAIOS_ERR_NO_MEMORY);
  kassert(git_workspace_patch_apply_start(0, "conflict-patch", 128) ==
          XAIOS_ERR_INVALID);

  kassert(git_workspace_sync_start(0, "r3") == XAIOS_OK);
  kassert(git_workspace_sync_finish(0) == XAIOS_OK);
  kassert(git_workspace_sync_finish(0) == XAIOS_ERR_INVALID);

  kassert(git_workspace_sync_start(0, "r4") == XAIOS_OK);
  kassert(git_workspace_sync_start(0, "r5") == XAIOS_ERR_INVALID);
  kassert(git_workspace_sync_finish(0) == XAIOS_OK);

  klog("git-workspace: self-test passed sync=%lu apply=%lu revert=%lu conflicts=%lu\n",
       git_workspace_sync_count(), git_workspace_apply_count(),
       git_workspace_revert_count(), git_workspace_conflict_count());

  /* blob hash test */
  {
    const char blob[] = "hello world\n";
    uint8_t hash[32];
    kassert(git_workspace_compute_blob_hash(blob, sizeof(blob) - 1,
                                            hash) == XAIOS_OK);
    kassert(git_workspace_compute_blob_hash(0, 0, hash) == XAIOS_ERR_INVALID);
    kassert(git_workspace_blob_hash_count() == 1);
  }

  /* diff test */
  {
    const char old_text[] = "line1\nline2\nline3\n";
    const char new_text[] = "line1\nmodified\nline3\n";
    xaios_git_workspace_diff_hunk_t hunks[4];
    uint32_t hc = 0;
    kassert(git_workspace_compute_diff(old_text, sizeof(old_text) - 1,
                                       new_text, sizeof(new_text) - 1,
                                       hunks, 4, &hc) == XAIOS_OK);
    kassert(hc == 1);
    kassert(hunks[0].old_start == 2);
    kassert(hunks[0].old_count == 1);
    kassert(hunks[0].new_start == 2);
    kassert(hunks[0].new_count == 1);
    kassert(git_workspace_diff_count() == 1);
  }

  klog("git-workspace: blob hash and diff self-test passed hashes=%lu diffs=%lu\n",
       git_workspace_blob_hash_count(), git_workspace_diff_count());
}
