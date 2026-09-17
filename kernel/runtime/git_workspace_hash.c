/*
 * The git blob hash and the line-based diff, moved out of git_workspace.c so
 * no source file exceeds 500 lines. Both computations are byte-for-byte the
 * ones the unsplit file contained: the "blob <size>\0" header fed to sha256
 * ahead of the content, and the bounded hunk scan over the two texts. The two
 * counters they own and the accessors that read them moved with them;
 * git_workspace_hash_stats_reset() is the pair of assignments
 * git_workspace_runtime_init() used to make inline, at the same point in the
 * same order. See git_workspace_internal.h for what crosses a file boundary.
 */

#include <xaios/git_workspace.h>
#include <xaios/klog.h>
#include <xaios/sha256.h>

#include "git_workspace_internal.h"

static uint64_t g_blob_hash_count;
static uint64_t g_diff_count;

void git_workspace_hash_stats_reset(void) {
  g_blob_hash_count = 0;
  g_diff_count = 0;
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
