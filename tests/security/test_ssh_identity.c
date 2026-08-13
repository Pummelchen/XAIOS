#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "ssh_identity.h"
#include "tweetnacl_subset.h"

static char file_buffer[8193];

int xaios_random(void *buffer, uint64_t length) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0U; i < length; ++i) bytes[i] = (uint8_t)(i * 31U + 9U);
  return 0;
}

static int test_identity(const char *path, const char *passphrase) {
  FILE *file = fopen(path, "rb");
  if (file == NULL) return -1;
  size_t length = fread(file_buffer, 1U, sizeof(file_buffer), file);
  if (ferror(file) || !feof(file) || fclose(file) != 0 ||
      length == 0U || length > 8192U) return -1;
  ssh_identity_t identity;
  if (ssh_identity_parse_openssh(file_buffer, (uint32_t)length, passphrase,
                                 &identity) != 0) return -1;
  static const uint8_t message[] = "XAIOS OpenSSH identity test";
  uint8_t signature[64];
  if (xaios_ed25519_sign(signature, message, sizeof(message) - 1U,
                         identity.public_key, identity.seed) != 0 ||
      xaios_ed25519_verify(signature, message, sizeof(message) - 1U,
                           identity.public_key) != 0) return -1;
  return 0;
}

int main(int argc, char **argv) {
  if (argc != 3 || test_identity(argv[1], "") != 0 ||
      test_identity(argv[2], "xaios-test-passphrase") != 0 ||
      test_identity(argv[2], "wrong-passphrase") == 0) {
    fputs("OpenSSH Ed25519 identity tests failed\n", stderr);
    return 1;
  }
  puts("OpenSSH Ed25519 identity tests passed");
  return 0;
}
