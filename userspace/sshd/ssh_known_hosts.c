#include "ssh_known_hosts.h"

static int hex_value(char character) {
  if (character >= '0' && character <= '9') return character - '0';
  if (character >= 'a' && character <= 'f') return character - 'a' + 10;
  if (character >= 'A' && character <= 'F') return character - 'A' + 10;
  return -1;
}

static int bytes_equal(const unsigned char *a, const unsigned char *b,
                       uint32_t size) {
  for (uint32_t i = 0U; i < size; ++i) {
    if (a[i] != b[i]) return 0;
  }
  return 1;
}

/* Does this line name the host, and if so does its key match?
   Returns non-zero when the line names the host -- the answer is then in
   `*result` -- and zero when it is about some other host. */
static int line_matches(const char *line, uint32_t line_length,
                        const char *expected, uint32_t expected_length,
                        const uint8_t public_key[32],
                        ssh_known_host_result_t *result) {
  uint32_t split = 0U;
  while (split < line_length && line[split] != ' ') ++split;
  if (split != expected_length || split >= line_length ||
      !bytes_equal((const unsigned char *)line,
                   (const unsigned char *)expected, expected_length)) {
    return 0;
  }
  if (line_length - split - 1U != 64U) {
    *result = SSH_KNOWN_HOST_MISMATCH;
    return 1;
  }
  for (uint32_t i = 0U; i < 32U; ++i) {
    int high = hex_value(line[split + 1U + i * 2U]);
    int low = hex_value(line[split + 2U + i * 2U]);
    if (high < 0 || low < 0 ||
        public_key[i] != (unsigned char)((uint32_t)high * 16U +
                                         (uint32_t)low)) {
      *result = SSH_KNOWN_HOST_MISMATCH;
      return 1;
    }
  }
  *result = SSH_KNOWN_HOST_MATCH;
  return 1;
}

ssh_known_host_result_t ssh_known_hosts_scan(ssh_known_hosts_read_fn read_fn,
                                             void *context,
                                             const char *expected,
                                             uint32_t expected_length,
                                             const uint8_t public_key[32]) {
  char chunk[SSH_KNOWN_HOSTS_CHUNK];
  char line[SSH_KNOWN_HOSTS_LINE_MAX];
  uint32_t line_used = 0U;
  uint32_t overlong = 0U;
  unsigned long long offset = 0U;
  ssh_known_host_result_t result = SSH_KNOWN_HOST_ABSENT;
  for (;;) {
    long long got = read_fn(context, chunk, sizeof(chunk), offset);
    if (got < 0) return SSH_KNOWN_HOST_UNREADABLE;
    if (got == 0) break;
    offset += (unsigned long long)got;
    for (long long i = 0; i < got; ++i) {
      char character = chunk[i];
      if (character != '\n') {
        /* A line longer than any this program writes is text, not a record.
           It is skipped rather than truncated into something that might
           accidentally match. */
        if (line_used < sizeof(line)) line[line_used++] = character;
        else overlong = 1U;
        continue;
      }
      if (overlong == 0U &&
          line_matches(line, line_used, expected, expected_length, public_key,
                       &result)) {
        return result;
      }
      line_used = 0U;
      overlong = 0U;
    }
  }
  /* A last line with no newline is still a line. */
  if (line_used != 0U && overlong == 0U &&
      line_matches(line, line_used, expected, expected_length, public_key,
                   &result)) {
    return result;
  }
  return SSH_KNOWN_HOST_ABSENT;
}

uint32_t ssh_known_hosts_format(char *out, uint32_t capacity,
                                const char *expected, uint32_t expected_length,
                                const uint8_t public_key[32]) {
  static const char hex[] = "0123456789abcdef";
  uint32_t needed = expected_length + 1U + 64U + 1U;
  if (capacity < needed) return 0U;
  uint32_t used = 0U;
  for (uint32_t i = 0U; i < expected_length; ++i) out[used++] = expected[i];
  out[used++] = ' ';
  for (uint32_t i = 0U; i < 32U; ++i) {
    out[used++] = hex[public_key[i] >> 4U];
    out[used++] = hex[public_key[i] & 0x0fU];
  }
  out[used++] = '\n';
  return used;
}
