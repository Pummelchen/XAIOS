/* B-01: what a known_hosts file longer than one read does.
 *
 * The outbound SSH client used to read this file with a single call into a
 * four-kilobyte buffer and scan whatever came back. Two things follow, and
 * both were seen as "outbound ProxyJump failed host key verification,
 * intermittently":
 *
 *   - A host whose entry lies past the buffer looks exactly like a host with
 *     no entry, so the client appends its key as new. For a host that already
 *     had a *different* key stored, that is host key verification switched
 *     off, silently, in the direction that matters.
 *   - Where the cut lands inside a stored line, the half that survives fails
 *     to parse and the connection is refused for a mismatch that had not
 *     happened.
 *
 * Neither depends on the host or the network. Both depend on how long the
 * file happens to be, which is why they came and went.
 *
 * The old reader is reproduced here as `legacy_scan` and required to fail on
 * each case, because a test that only exercised the new one would pass
 * equally against code that never had the defect.
 */
#include "../../userspace/sshd/ssh_known_hosts.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct {
  const char *data;
  unsigned long long size;
  /* The most any one read returns. Zero means "as much as asked for" --
     a filesystem is entitled to return less, and that is the same defect at
     a smaller size. */
  unsigned long long chunk_cap;
  int fail_after;
  int reads;
} file_t;

static long long file_read(void *context, void *buffer,
                           unsigned long long size,
                           unsigned long long offset) {
  file_t *file = (file_t *)context;
  if (file->fail_after >= 0 && file->reads >= file->fail_after) return -1;
  ++file->reads;
  if (offset >= file->size) return 0;
  unsigned long long available = file->size - offset;
  if (available < size) size = available;
  if (file->chunk_cap != 0U && size > file->chunk_cap) size = file->chunk_cap;
  memcpy(buffer, file->data + offset, (size_t)size);
  return (long long)size;
}

/* The reader as it was: one call, four kilobytes, scan what arrived. */
static ssh_known_host_result_t legacy_scan(const char *data,
                                           unsigned long long size,
                                           const char *expected,
                                           uint32_t expected_length,
                                           const uint8_t key[32]) {
  char contents[4096];
  unsigned long long length = size < sizeof(contents) - 1U
                                  ? size
                                  : sizeof(contents) - 1U;
  memcpy(contents, data, (size_t)length);
  contents[length] = '\0';
  uint32_t position = 0U;
  while (position < (uint32_t)length) {
    uint32_t line_start = position;
    while (position < (uint32_t)length && contents[position] != '\n')
      ++position;
    uint32_t line_end = position++;
    uint32_t split = line_start;
    while (split < line_end && contents[split] != ' ') ++split;
    if (split - line_start != expected_length || split >= line_end ||
        memcmp(contents + line_start, expected, expected_length) != 0) {
      continue;
    }
    if (line_end - split - 1U != 64U) return SSH_KNOWN_HOST_MISMATCH;
    for (uint32_t i = 0U; i < 32U; ++i) {
      char high = contents[split + 1U + i * 2U];
      char low = contents[split + 2U + i * 2U];
      char want[3];
      snprintf(want, sizeof(want), "%02x", key[i]);
      if (high != want[0] || low != want[1]) return SSH_KNOWN_HOST_MISMATCH;
    }
    return SSH_KNOWN_HOST_MATCH;
  }
  /* Not found. The caller then appended the key as new, which is the whole
     difficulty: this answer is indistinguishable from "the file does not
     mention this host". */
  return SSH_KNOWN_HOST_ABSENT;
}

static uint8_t key_a[32];
static uint8_t key_b[32];

static void fill_keys(void) {
  for (uint32_t i = 0U; i < 32U; ++i) {
    key_a[i] = (uint8_t)(i * 7U + 1U);
    key_b[i] = (uint8_t)(i * 11U + 3U);
  }
}

static uint32_t append_entry(char *out, uint32_t used, const char *host,
                             const uint8_t key[32]) {
  return used + ssh_known_hosts_format(out + used, SSH_KNOWN_HOSTS_LINE_MAX,
                                       host, (uint32_t)strlen(host), key);
}

int main(void) {
  fill_keys();
  static char file[65536];
  const char *target = "jump.example:22";
  uint32_t used = 0U;

  /* --- the ordinary case, which both readers get right ---------------- */
  used = append_entry(file, 0U, target, key_a);
  file_t small = {file, used, 0U, -1, 0};
  assert(ssh_known_hosts_scan(file_read, &small, target,
                              (uint32_t)strlen(target), key_a) ==
         SSH_KNOWN_HOST_MATCH);
  assert(legacy_scan(file, used, target, (uint32_t)strlen(target), key_a) ==
         SSH_KNOWN_HOST_MATCH);
  file_t small_b = {file, used, 0U, -1, 0};
  assert(ssh_known_hosts_scan(file_read, &small_b, target,
                              (uint32_t)strlen(target), key_b) ==
         SSH_KNOWN_HOST_MISMATCH);
  printf("  ok   a file with one entry: match, and a different key does not\n");

  /* --- the entry past the old reader's buffer -------------------------- */
  used = 0U;
  for (uint32_t i = 0U; used < 4300U; ++i) {
    char other[64];
    snprintf(other, sizeof(other), "filler%u.example:22", i);
    used = append_entry(file, used, other, key_b);
  }
  uint32_t target_offset = used;
  used = append_entry(file, used, target, key_a);
  assert(target_offset > 4096U);

  file_t beyond = {file, used, 0U, -1, 0};
  assert(ssh_known_hosts_scan(file_read, &beyond, target,
                              (uint32_t)strlen(target), key_a) ==
         SSH_KNOWN_HOST_MATCH);
  /* The negative control: the old reader says the host is unknown, and the
     caller then records the key as new. */
  assert(legacy_scan(file, used, target, (uint32_t)strlen(target), key_a) ==
         SSH_KNOWN_HOST_ABSENT);
  /* And it says the same for a key that does *not* match, which is the
     security consequence rather than an inconvenience. */
  assert(legacy_scan(file, used, target, (uint32_t)strlen(target), key_b) ==
         SSH_KNOWN_HOST_ABSENT);
  file_t beyond_b = {file, used, 0U, -1, 0};
  assert(ssh_known_hosts_scan(file_read, &beyond_b, target,
                              (uint32_t)strlen(target), key_b) ==
         SSH_KNOWN_HOST_MISMATCH);
  printf("  ok   an entry past four kilobytes is found, and a wrong key for "
         "it is still refused\n");

  /* --- the cut landing inside the entry -------------------------------- */
  /* Placed exactly, not approximately: the claim is about a line the old
     reader saw the front of and not the back, and padding "until roughly
     four kilobytes" lands somewhere else depending on how many digits the
     filler names happen to have. Names are fixed width so the arithmetic
     holds, and the straddle is asserted before it is relied on. */
  used = 0U;
  for (uint32_t i = 0U; used + SSH_KNOWN_HOSTS_LINE_MAX < 4050U; ++i) {
    char other[64];
    snprintf(other, sizeof(other), "pad%04u.example:22", i);
    used = append_entry(file, used, other, key_b);
  }
  while (used < 4050U) file[used++] = '\n';
  uint32_t straddle_start = used;
  used = append_entry(file, used, target, key_a);
  assert(straddle_start < 4095U && used > 4095U);

  file_t straddled = {file, used, 0U, -1, 0};
  assert(ssh_known_hosts_scan(file_read, &straddled, target,
                              (uint32_t)strlen(target), key_a) ==
         SSH_KNOWN_HOST_MATCH);
  /* The old reader saw the host name and part of the key, and refused the
     connection for a mismatch that had not happened. */
  assert(legacy_scan(file, used, target, (uint32_t)strlen(target), key_a) ==
         SSH_KNOWN_HOST_MISMATCH);
  printf("  ok   an entry the old reader cut in half (bytes %u..%u, cut at "
         "4095) is matched, where the old reader refused it as a mismatch\n",
         straddle_start, used);

  /* --- a short read, which a filesystem may always return -------------- */
  file_t dribble = {file, used, 7U, -1, 0};
  assert(ssh_known_hosts_scan(file_read, &dribble, target,
                              (uint32_t)strlen(target), key_a) ==
         SSH_KNOWN_HOST_MATCH);
  printf("  ok   seven bytes at a time still finds it\n");

  /* --- a line longer than any this program writes ---------------------- */
  used = 0U;
  for (uint32_t i = 0U; i < SSH_KNOWN_HOSTS_LINE_MAX + 200U; ++i) {
    file[used++] = 'x';
  }
  file[used++] = '\n';
  used = append_entry(file, used, target, key_a);
  file_t overlong = {file, used, 0U, -1, 0};
  assert(ssh_known_hosts_scan(file_read, &overlong, target,
                              (uint32_t)strlen(target), key_a) ==
         SSH_KNOWN_HOST_MATCH);
  printf("  ok   an over-long line is skipped as text, not truncated into a "
         "record\n");

  /* --- a final line with no newline ------------------------------------ */
  used = append_entry(file, 0U, target, key_a) - 1U;
  file_t unterminated = {file, used, 0U, -1, 0};
  assert(ssh_known_hosts_scan(file_read, &unterminated, target,
                              (uint32_t)strlen(target), key_a) ==
         SSH_KNOWN_HOST_MATCH);
  printf("  ok   a last line with no newline is still a line\n");

  /* --- a file that cannot be read -------------------------------------- */
  used = append_entry(file, 0U, target, key_a);
  file_t broken = {file, used, 16U, 1, 0};
  assert(ssh_known_hosts_scan(file_read, &broken, target,
                              (uint32_t)strlen(target), key_a) ==
         SSH_KNOWN_HOST_UNREADABLE);
  printf("  ok   a file that cannot be read is unreadable, never absent -- "
         "the caller refuses instead of trusting a new key\n");

  printf("known-hosts: the file is read whole, and no length of it turns a "
         "stored key into an unknown one\n");
  return 0;
}
