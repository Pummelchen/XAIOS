#ifndef SSH_KNOWN_HOSTS_H
#define SSH_KNOWN_HOSTS_H

#include <stdint.h>

/* Reading a known_hosts file, apart from the machine it is stored on.
 *
 * Separate from ssh_client.c because the property this has to hold is one
 * about text and boundaries, and it can be argued with directly rather than
 * only through a booted guest dialling a real host. The file access is a
 * callback for the same reason.
 *
 * B-01 lived in the version of this that read the file with one call into a
 * four-kilobyte buffer. A file longer than the buffer -- or a short read,
 * which a filesystem is entitled to return -- looked exactly like a file that
 * did not mention the host: the caller then appended the key as new, which is
 * host key verification switched off for a host that already had a different
 * key. And where the cut landed inside a stored line, the half that survived
 * failed to parse and the connection was refused for a mismatch that had not
 * happened. Both come and go with the length of the file, which is what
 * "intermittent" looked like from outside.
 */

#define SSH_CLIENT_HOST_NAME_MAX 128U
/* The longest host name, a colon, five digits of port, a space, sixty-four
   hex characters and a newline. */
#define SSH_KNOWN_HOSTS_LINE_MAX (SSH_CLIENT_HOST_NAME_MAX + 80U)
#define SSH_KNOWN_HOSTS_CHUNK 1024U

typedef enum {
  SSH_KNOWN_HOST_MATCH = 0,
  SSH_KNOWN_HOST_MISMATCH = 1,
  SSH_KNOWN_HOST_ABSENT = 2,
  /* Never the same as ABSENT: a file that cannot be read may already name a
     different key for this host. */
  SSH_KNOWN_HOST_UNREADABLE = 3
} ssh_known_host_result_t;

/* Fill `buffer` with up to `size` bytes from `offset`. Negative is an error;
   zero is end of file. */
typedef long long (*ssh_known_hosts_read_fn)(void *context, void *buffer,
                                             unsigned long long size,
                                             unsigned long long offset);

ssh_known_host_result_t ssh_known_hosts_scan(ssh_known_hosts_read_fn read_fn,
                                             void *context,
                                             const char *expected,
                                             uint32_t expected_length,
                                             const uint8_t public_key[32]);

/* The line this program writes for a host, without a trailing newline test:
   `<host>:<port> <64 hex characters>\n`. Returns the length written, or 0 if
   it would not fit. */
uint32_t ssh_known_hosts_format(char *out, uint32_t capacity,
                                const char *expected, uint32_t expected_length,
                                const uint8_t public_key[32]);

#endif
