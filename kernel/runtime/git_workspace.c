#include <xaios/assert.h>
#include <xaios/git_workspace.h>
#include <xaios/klog.h>
#include <xaios/security.h>
#include <xaios/sha256.h>

#define MAX_GIT_WORKSPACES 3U
#define MAX_PATCH_STACK 4U
#define GIT_WORKSPACE_PATCH_BUFFER_MAX (64U * 1024U)

typedef struct {
  xaios_git_workspace_state_t state;
  uint32_t workspace_id;
  uint32_t owner_cell_id;
  const char *repo_path;
  char branch[XAIOS_GIT_WORKSPACE_BRANCH_MAX];
  char current_revision[XAIOS_GIT_WORKSPACE_REVISION_MAX];
  char target_revision[XAIOS_GIT_WORKSPACE_REVISION_MAX];
  char pending_patch_id[XAIOS_GIT_WORKSPACE_PATCH_ID_MAX];
  char patch_stack[MAX_PATCH_STACK][XAIOS_GIT_WORKSPACE_PATCH_ID_MAX];
  uint64_t patch_buffer_bytes;
  uint32_t patch_depth;
  uint32_t patch_next_index;
  uint32_t sync_generation;
} xaios_git_workspace_t;

static xaios_git_workspace_t g_workspaces[MAX_GIT_WORKSPACES];
static uint64_t g_active_count;
static uint64_t g_sync_count;
static uint64_t g_apply_count;
static uint64_t g_revert_count;
static uint64_t g_conflict_count;
static uint64_t g_blob_hash_count;
static uint64_t g_diff_count;

static int str_nonempty(const char *value) {
  return value != 0 && value[0] != '\0';
}

static uint32_t string_length(const char *value) {
  uint32_t len = 0;
  while (value[len] != '\0') {
    ++len;
  }
  return len;
}

static int str_prefix(const char *value, const char *prefix) {
  if (!str_nonempty(value) || !str_nonempty(prefix)) {
    return 0;
  }
  while (*prefix != '\0') {
    if (*value != *prefix) {
      return 0;
    }
    ++value;
    ++prefix;
  }
  return 1;
}

static int copy_if_fits(char *dst, uint32_t dst_size, const char *src,
                        uint32_t *out_len) {
  if (dst_size == 0) {
    return 0;
  }

  uint32_t len = 0;
  while (src[len] != '\0' && (len + 1U) < dst_size) {
    dst[len] = src[len];
    ++len;
  }
  dst[len] = '\0';
  if (src[len] != '\0') {
    return 0;
  }

  if (out_len != 0) {
    *out_len = len;
  }
  return 1;
}

static int str_eq(const char *lhs, const char *rhs) {
  if (!str_nonempty(lhs) || !str_nonempty(rhs)) {
    return 0;
  }
  while (*lhs != '\0' && *rhs != '\0') {
    if (*lhs != *rhs) {
      return 0;
    }
    ++lhs;
    ++rhs;
  }
  return *lhs == *rhs;
}

static xaios_git_workspace_t *lookup_workspace(uint32_t workspace_id) {
  if (workspace_id >= MAX_GIT_WORKSPACES) {
    return 0;
  }
  return &g_workspaces[workspace_id];
}

static int is_conflict_revision(const char *revision) {
  return str_eq(revision, "conflict") || str_eq(revision, "x-conflict");
}

static int validate_manifest(const xaios_git_workspace_manifest_t *manifest) {
  if (manifest == 0 || manifest->workspace_id >= MAX_GIT_WORKSPACES ||
      manifest->owner_cell_id >= 4U ||
      !str_prefix(manifest->repo_path, "/repo/") ||
      !str_nonempty(manifest->branch) ||
      string_length(manifest->branch) >= XAIOS_GIT_WORKSPACE_BRANCH_MAX ||
      !str_nonempty(manifest->starting_revision) ||
      string_length(manifest->starting_revision) >=
          XAIOS_GIT_WORKSPACE_REVISION_MAX ||
      manifest->patch_buffer_bytes == 0 ||
      manifest->patch_buffer_bytes > GIT_WORKSPACE_PATCH_BUFFER_MAX) {
    return 0;
  }

  return 1;
}

static xaios_status_t authorize_workspace_actor(
    const xaios_git_workspace_t *workspace, uint32_t actor_cell_id,
    const char *operation) {
  if (workspace == 0) {
    return XAIOS_ERR_INVALID;
  }
  return security_authorize_git_workspace(workspace->workspace_id,
                                          workspace->owner_cell_id,
                                          actor_cell_id, operation);
}

void git_workspace_runtime_init(void) {
  for (uint32_t i = 0; i < MAX_GIT_WORKSPACES; ++i) {
    g_workspaces[i].state = XAIOS_GIT_WORKSPACE_EMPTY;
    g_workspaces[i].workspace_id = 0;
    g_workspaces[i].owner_cell_id = 0;
    g_workspaces[i].repo_path = 0;
    g_workspaces[i].branch[0] = '\0';
    g_workspaces[i].current_revision[0] = '\0';
    g_workspaces[i].target_revision[0] = '\0';
    g_workspaces[i].pending_patch_id[0] = '\0';
    g_workspaces[i].patch_buffer_bytes = 0;
    g_workspaces[i].patch_depth = 0;
    g_workspaces[i].patch_next_index = 0;
    g_workspaces[i].sync_generation = 0;
  }
  for (uint32_t i = 0; i < MAX_GIT_WORKSPACES; ++i) {
    for (uint32_t j = 0; j < MAX_PATCH_STACK; ++j) {
      for (uint32_t k = 0; k < XAIOS_GIT_WORKSPACE_PATCH_ID_MAX; ++k) {
        g_workspaces[i].patch_stack[j][k] = '\0';
      }
    }
  }

  g_active_count = 0;
  g_sync_count = 0;
  g_apply_count = 0;
  g_revert_count = 0;
  g_conflict_count = 0;
  g_blob_hash_count = 0;
  g_diff_count = 0;
  klog("git-workspace: runtime initialized\n");
}

xaios_status_t git_workspace_create(
    const xaios_git_workspace_manifest_t *manifest) {
  if (!validate_manifest(manifest)) {
    return XAIOS_ERR_INVALID;
  }

  xaios_git_workspace_t *workspace = lookup_workspace(manifest->workspace_id);
  if (workspace == 0 || workspace->state != XAIOS_GIT_WORKSPACE_EMPTY) {
    return XAIOS_ERR_BUSY;
  }

  workspace->state = XAIOS_GIT_WORKSPACE_READY;
  workspace->workspace_id = manifest->workspace_id;
  workspace->owner_cell_id = manifest->owner_cell_id;
  workspace->repo_path = manifest->repo_path;
  workspace->patch_buffer_bytes = manifest->patch_buffer_bytes;
  if (!copy_if_fits(workspace->branch, sizeof(workspace->branch),
                    manifest->branch, 0) ||
      !copy_if_fits(workspace->current_revision,
                    sizeof(workspace->current_revision),
                    manifest->starting_revision, 0)) {
    workspace->state = XAIOS_GIT_WORKSPACE_EMPTY;
    return XAIOS_ERR_INVALID;
  }

  for (uint32_t i = 0; i < MAX_PATCH_STACK; ++i) {
    workspace->patch_stack[i][0] = '\0';
  }
  workspace->target_revision[0] = '\0';
  workspace->pending_patch_id[0] = '\0';
  workspace->patch_depth = 0;
  workspace->patch_next_index = 0;
  workspace->sync_generation = 1;

  ++g_active_count;
  klog("git-workspace: %u created owner=%u repo=%s branch=%s revision=%s\n",
       workspace->workspace_id, workspace->owner_cell_id, workspace->repo_path,
       workspace->branch, workspace->current_revision);
  return XAIOS_OK;
}

static xaios_status_t git_workspace_sync_start_as(uint32_t actor_cell_id,
                                                 uint32_t workspace_id,
                                                 const char *revision) {
  xaios_git_workspace_t *workspace = lookup_workspace(workspace_id);
  if (workspace == 0 || workspace->state == XAIOS_GIT_WORKSPACE_EMPTY ||
      workspace->state == XAIOS_GIT_WORKSPACE_SYNCING ||
      workspace->state == XAIOS_GIT_WORKSPACE_APPLYING_PATCH ||
      workspace->state == XAIOS_GIT_WORKSPACE_REVERTING_PATCH ||
      !str_nonempty(revision) ||
      string_length(revision) >= XAIOS_GIT_WORKSPACE_REVISION_MAX) {
    return XAIOS_ERR_INVALID;
  }
  if (authorize_workspace_actor(workspace, actor_cell_id, "sync") != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }

  if (str_eq(workspace->current_revision, revision)) {
    klog("git-workspace: %u sync skipped revision=%s\n", workspace_id,
         revision);
    return XAIOS_OK;
  }

  workspace->state = XAIOS_GIT_WORKSPACE_SYNCING;
  copy_if_fits(workspace->target_revision,
               sizeof(workspace->target_revision), revision, 0);
  ++g_sync_count;
  klog("git-workspace: %u sync start target=%s\n", workspace_id, revision);
  return XAIOS_OK;
}

xaios_status_t git_workspace_sync_start(uint32_t workspace_id,
                                      const char *revision) {
  xaios_git_workspace_t *workspace = lookup_workspace(workspace_id);
  if (workspace == 0) {
    return XAIOS_ERR_INVALID;
  }
  return git_workspace_sync_start_as(workspace->owner_cell_id, workspace_id,
                                     revision);
}

xaios_status_t git_workspace_sync_finish(uint32_t workspace_id) {
  xaios_git_workspace_t *workspace = lookup_workspace(workspace_id);
  if (workspace == 0 || workspace->state != XAIOS_GIT_WORKSPACE_SYNCING ||
      !str_nonempty(workspace->target_revision)) {
    return XAIOS_ERR_INVALID;
  }

  if (is_conflict_revision(workspace->target_revision)) {
    workspace->state = XAIOS_GIT_WORKSPACE_FAILED;
    ++g_conflict_count;
    klog("git-workspace: %u sync failed conflict revision=%s\n", workspace_id,
         workspace->target_revision);
    workspace->target_revision[0] = '\0';
    return XAIOS_ERR_INVALID;
  }

  copy_if_fits(workspace->current_revision, sizeof(workspace->current_revision),
               workspace->target_revision, 0);
  workspace->target_revision[0] = '\0';
  workspace->state = XAIOS_GIT_WORKSPACE_READY;
  workspace->patch_depth = 0;
  workspace->patch_next_index = 0;
  for (uint32_t i = 0; i < MAX_PATCH_STACK; ++i) {
    workspace->patch_stack[i][0] = '\0';
  }
  ++workspace->sync_generation;
  klog("git-workspace: %u synced revision=%s generation=%u\n", workspace_id,
       workspace->current_revision, workspace->sync_generation);
  return XAIOS_OK;
}

static xaios_status_t git_workspace_patch_apply_start_as(
    uint32_t actor_cell_id, uint32_t workspace_id, const char *patch_id,
    uint64_t patch_bytes) {
  xaios_git_workspace_t *workspace = lookup_workspace(workspace_id);
  if (workspace == 0 || workspace->state != XAIOS_GIT_WORKSPACE_READY ||
      !str_nonempty(patch_id) ||
      string_length(patch_id) >= XAIOS_GIT_WORKSPACE_PATCH_ID_MAX ||
      patch_bytes == 0) {
    return XAIOS_ERR_INVALID;
  }
  if (security_reject_credential_material(patch_id) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  if (authorize_workspace_actor(workspace, actor_cell_id, "patch") !=
      XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }

  if (patch_bytes > workspace->patch_buffer_bytes) {
    return XAIOS_ERR_NO_MEMORY;
  }

  if (workspace->patch_depth >= MAX_PATCH_STACK) {
    return XAIOS_ERR_NO_MEMORY;
  }

  if (!copy_if_fits(workspace->pending_patch_id,
                    sizeof(workspace->pending_patch_id), patch_id, 0)) {
    return XAIOS_ERR_INVALID;
  }

  if (str_prefix(patch_id, "conflict")) {
    ++g_conflict_count;
    workspace->state = XAIOS_GIT_WORKSPACE_FAILED;
    workspace->pending_patch_id[0] = '\0';
    return XAIOS_ERR_INVALID;
  }

  workspace->state = XAIOS_GIT_WORKSPACE_APPLYING_PATCH;
  klog("git-workspace: %u apply start patch=%s bytes=%lu\n", workspace_id,
       patch_id, patch_bytes);
  ++g_apply_count;

  return XAIOS_OK;
}

xaios_status_t git_workspace_patch_apply_start(uint32_t workspace_id,
                                             const char *patch_id,
                                             uint64_t patch_bytes) {
  xaios_git_workspace_t *workspace = lookup_workspace(workspace_id);
  if (workspace == 0) {
    return XAIOS_ERR_INVALID;
  }
  return git_workspace_patch_apply_start_as(workspace->owner_cell_id,
                                            workspace_id, patch_id,
                                            patch_bytes);
}

xaios_status_t git_workspace_patch_apply_finish(uint32_t workspace_id) {
  xaios_git_workspace_t *workspace = lookup_workspace(workspace_id);
  if (workspace == 0 ||
      workspace->state != XAIOS_GIT_WORKSPACE_APPLYING_PATCH ||
      !str_nonempty(workspace->pending_patch_id)) {
    return XAIOS_ERR_INVALID;
  }

  copy_if_fits(workspace->patch_stack[workspace->patch_next_index],
               sizeof(workspace->patch_stack[0]),
               workspace->pending_patch_id, 0);
  workspace->pending_patch_id[0] = '\0';
  ++workspace->patch_depth;
  workspace->patch_next_index =
      (workspace->patch_next_index + 1U) % MAX_PATCH_STACK;
  workspace->state = XAIOS_GIT_WORKSPACE_READY;
  klog("git-workspace: %u patch applied id=%s depth=%u\n", workspace_id,
       workspace->patch_stack[(workspace->patch_next_index + MAX_PATCH_STACK - 1U) %
                                  MAX_PATCH_STACK],
       workspace->patch_depth);
  return XAIOS_OK;
}

static xaios_status_t git_workspace_patch_revert_start_as(
    uint32_t actor_cell_id, uint32_t workspace_id) {
  xaios_git_workspace_t *workspace = lookup_workspace(workspace_id);
  if (workspace == 0 || workspace->state != XAIOS_GIT_WORKSPACE_READY ||
      workspace->patch_depth == 0) {
    return XAIOS_ERR_INVALID;
  }
  if (authorize_workspace_actor(workspace, actor_cell_id, "revert") !=
      XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }

  uint32_t index =
      (workspace->patch_next_index + MAX_PATCH_STACK - 1U) % MAX_PATCH_STACK;
  if (!str_nonempty(workspace->patch_stack[index])) {
    return XAIOS_ERR_INVALID;
  }
  copy_if_fits(workspace->pending_patch_id,
               sizeof(workspace->pending_patch_id),
               workspace->patch_stack[index], 0);
  workspace->state = XAIOS_GIT_WORKSPACE_REVERTING_PATCH;
  klog("git-workspace: %u revert start patch=%s\n", workspace_id,
       workspace->pending_patch_id);
  return XAIOS_OK;
}

xaios_status_t git_workspace_patch_revert_start(uint32_t workspace_id) {
  xaios_git_workspace_t *workspace = lookup_workspace(workspace_id);
  if (workspace == 0) {
    return XAIOS_ERR_INVALID;
  }
  return git_workspace_patch_revert_start_as(workspace->owner_cell_id,
                                             workspace_id);
}

xaios_status_t git_workspace_patch_revert_finish(uint32_t workspace_id) {
  xaios_git_workspace_t *workspace = lookup_workspace(workspace_id);
  if (workspace == 0 ||
      workspace->state != XAIOS_GIT_WORKSPACE_REVERTING_PATCH ||
      !str_nonempty(workspace->pending_patch_id)) {
    return XAIOS_ERR_INVALID;
  }

  uint32_t index =
      (workspace->patch_next_index + MAX_PATCH_STACK - 1U) % MAX_PATCH_STACK;
  workspace->patch_stack[index][0] = '\0';
  workspace->patch_next_index =
      index;
  if (workspace->patch_depth > 0) {
    --workspace->patch_depth;
  }
  ++g_revert_count;
  workspace->pending_patch_id[0] = '\0';
  workspace->state = XAIOS_GIT_WORKSPACE_READY;
  klog("git-workspace: %u patch reverted depth=%u\n", workspace_id,
       workspace->patch_depth);
  return XAIOS_OK;
}

uint64_t git_workspace_active_count(void) {
  return g_active_count;
}

uint64_t git_workspace_sync_count(void) {
  return g_sync_count;
}

uint64_t git_workspace_apply_count(void) {
  return g_apply_count;
}

uint64_t git_workspace_revert_count(void) {
  return g_revert_count;
}

uint64_t git_workspace_conflict_count(void) {
  return g_conflict_count;
}

uint64_t git_workspace_blob_hash_count(void) {
  return g_blob_hash_count;
}

uint64_t git_workspace_diff_count(void) {
  return g_diff_count;
}

xaios_status_t git_workspace_compute_blob_hash(const void *content,
                                               uint64_t content_bytes,
                                               uint8_t hash[32]) {
  if (content == 0 || hash == 0) {
    return XAIOS_ERR_INVALID;
  }
  /* Git blob format: "blob <size>\0<content>" */
  char header[32];
  uint32_t hlen = 0;
  const char prefix[] = "blob ";
  for (uint32_t i = 0; i < 5; ++i) { header[hlen++] = prefix[i]; }
  /* write size as decimal */
  char digits[20];
  uint32_t dcount = 0;
  uint64_t tmp = content_bytes;
  if (tmp == 0) {
    digits[dcount++] = '0';
  } else {
    while (tmp != 0 && dcount < sizeof(digits)) {
      digits[dcount++] = (char)('0' + (tmp % 10U));
      tmp /= 10U;
    }
  }
  while (dcount > 0) { header[hlen++] = digits[--dcount]; }
  header[hlen++] = '\0';

  xaios_sha256_ctx_t ctx;
  xaios_sha256_init(&ctx);
  xaios_sha256_update(&ctx, header, hlen);
  xaios_sha256_update(&ctx, content, content_bytes);
  xaios_sha256_final(&ctx, hash);
  ++g_blob_hash_count;
  return XAIOS_OK;
}

static uint32_t count_lines(const char *text, uint64_t bytes) {
  if (text == 0 || bytes == 0) { return 0; }
  uint32_t lines = 1;
  for (uint64_t i = 0; i < bytes; ++i) {
    if (text[i] == '\n') { ++lines; }
  }
  return lines;
}

static uint32_t get_line_start(const char *text, uint64_t bytes,
                                uint32_t line_idx, uint64_t *out_start,
                                uint64_t *out_len) {
  uint32_t cur = 0;
  uint64_t start = 0;
  for (uint64_t i = 0; i <= bytes; ++i) {
    if (i == bytes || text[i] == '\n') {
      if (cur == line_idx) {
        *out_start = start;
        *out_len = i - start;
        return 1;
      }
      ++cur;
      start = i + 1;
    }
  }
  return 0;
}

static int lines_equal(const char *a, uint64_t a_len,
                        const char *b, uint64_t b_len) {
  if (a_len != b_len) { return 0; }
  for (uint64_t i = 0; i < a_len; ++i) {
    if (a[i] != b[i]) { return 0; }
  }
  return 1;
}

xaios_status_t git_workspace_compute_diff(const char *old_text,
                                         uint64_t old_bytes,
                                         const char *new_text,
                                         uint64_t new_bytes,
    xaios_git_workspace_diff_hunk_t *hunks, uint32_t hunk_capacity,
    uint32_t *hunk_count) {
  if (old_text == 0 || new_text == 0 || hunks == 0 || hunk_count == 0) {
    return XAIOS_ERR_INVALID;
  }
  *hunk_count = 0;

  uint32_t old_lines = count_lines(old_text, old_bytes);
  uint32_t new_lines = count_lines(new_text, new_bytes);
  /* The emitted diff is bounded by hunk_capacity below. A line cap was
     computed here from XAIOS_GIT_WORKSPACE_DIFF_MAX_LINES but never read, so
     it never applied; the dead computation is removed rather than switched on,
     because enforcing it would start truncating any diff past 32 lines. */

  uint32_t oi = 0;
  uint32_t ni = 0;
  uint32_t hc = 0;

  while (oi < old_lines || ni < new_lines) {
    if (hc >= hunk_capacity) { break; }
    /* find matching lines */
    uint64_t os = 0, ol = 0, ns = 0, nl = 0;
    int have_old = get_line_start(old_text, old_bytes, oi, &os, &ol);
    int have_new = get_line_start(new_text, new_bytes, ni, &ns, &nl);

    if (have_old && have_new && lines_equal(old_text + os, ol,
                                             new_text + ns, nl)) {
      ++oi;
      ++ni;
      continue;
    }
    /* mismatch - record hunk */
    uint32_t hunk_old_start = oi + 1;
    uint32_t hunk_new_start = ni + 1;
    uint32_t old_consumed = 0;
    uint32_t new_consumed = 0;

    /* advance old past mismatch */
    if (have_old && (!have_new || !lines_equal(old_text + os, ol,
                                                 new_text + ns, nl))) {
      ++oi;
      ++old_consumed;
    }
    if (have_new && (!have_old || !lines_equal(old_text + os, ol,
                                                 new_text + ns, nl))) {
      ++ni;
      ++new_consumed;
    }
    /* consume adjacent mismatches */
    while (oi < old_lines || ni < new_lines) {
      have_old = get_line_start(old_text, old_bytes, oi, &os, &ol);
      have_new = get_line_start(new_text, new_bytes, ni, &ns, &nl);
      if (have_old && have_new && lines_equal(old_text + os, ol,
                                               new_text + ns, nl)) {
        break;
      }
      if (have_old && oi < old_lines) { ++oi; ++old_consumed; }
      if (have_new && ni < new_lines) { ++ni; ++new_consumed; }
    }

    hunks[hc].old_start = hunk_old_start;
    hunks[hc].old_count = old_consumed;
    hunks[hc].new_start = hunk_new_start;
    hunks[hc].new_count = new_consumed;
    ++hc;
  }

  *hunk_count = hc;
  ++g_diff_count;
  klog("git-workspace: diff computed old_lines=%u new_lines=%u hunks=%u\n",
       old_lines, new_lines, hc);
  return XAIOS_OK;
}

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
