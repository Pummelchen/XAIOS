/* The two SHA-256 implementations must agree, on everything.
 *
 * One is the scalar reference; the other is the same algorithm expressed in
 * the four ARMv8 instructions built for it, and it is installed at boot on any
 * CPU that reports the extension. Every model chunk XAIOS hands out is
 * verified with whichever one is installed, and every package it signs is
 * signed with it. A compressor that is fast and wrong would corrupt both
 * silently and keep passing its own checks, because both sides of every
 * comparison would be the new implementation.
 *
 * So the comparison is against the other implementation, not against itself:
 * every length from zero to four kibibytes, so the tail lands at every offset
 * within a block, and a range of split points, so the partial-block path feeds
 * the whole-block path at every alignment.
 *
 * On an architecture with no accelerated compressor there is nothing to
 * compare and this passes without doing anything. The same comparison runs
 * inside XAIOS at every boot, where it decides whether the accelerated path is
 * installed at all.
 */
/* Both compressors, same inputs, over every length that crosses a block
   boundary in a different place. A hash that is fast and wrong is worse than
   no acceleration at all, so this is the check that decides. */
#include "sha256.h"
#include <stdio.h>
#include <string.h>

static void digest_of(const unsigned char *data, size_t length,
                      unsigned char out[32]) {
  xaios_engine_sha256_context_t context;
  xaios_engine_sha256_init(&context);
  xaios_engine_sha256_update(&context, data, length);
  xaios_engine_sha256_final(&context, out);
}

int main(void) {
  static unsigned char buffer[4096];
  for (size_t i = 0; i < sizeof(buffer); ++i) buffer[i] = (unsigned char)(i * 131 + 7);
  xaios_engine_sha256_compress_fn hardware =
      xaios_engine_sha256_hardware_compressor();
  if (hardware == 0) {
    /* No accelerated compressor exists for this architecture, so there is
       nothing to compare against and nothing to get wrong. CI's runners are
       x86_64 and land here; the comparison runs on an ARM host, and inside
       XAIOS itself at every boot -- engine_sha256_dispatch refuses to install
       the accelerated path unless it reproduces the scalar one first, and
       says which it chose. */
    printf("engine sha256: no accelerated compressor for this architecture, "
           "scalar path is the only one\n");
    return 0;
  }

  static const unsigned char abc[32] = {
      0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,
      0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,
      0xf2,0x00,0x15,0xad};
  unsigned char got[32];
  xaios_engine_sha256_install_compressor(hardware);
  digest_of((const unsigned char *)"abc", 3, got);
  if (memcmp(got, abc, 32) != 0) { printf("FAIL accelerated abc vector\n"); return 1; }

  for (size_t length = 0; length <= sizeof(buffer); ++length) {
    unsigned char scalar[32];
    unsigned char accelerated[32];
    xaios_engine_sha256_install_compressor(0);
    digest_of(buffer, length, scalar);
    xaios_engine_sha256_install_compressor(hardware);
    digest_of(buffer, length, accelerated);
    if (memcmp(scalar, accelerated, 32) != 0) {
      printf("FAIL at length %zu\n", length);
      return 1;
    }
  }
  /* Split updates, so the partial-block path feeds the whole-block path. */
  for (size_t split = 1; split < 200; ++split) {
    unsigned char scalar[32];
    unsigned char accelerated[32];
    xaios_engine_sha256_context_t context;
    xaios_engine_sha256_install_compressor(0);
    digest_of(buffer, sizeof(buffer), scalar);
    xaios_engine_sha256_install_compressor(hardware);
    xaios_engine_sha256_init(&context);
    xaios_engine_sha256_update(&context, buffer, split);
    xaios_engine_sha256_update(&context, buffer + split, sizeof(buffer) - split);
    xaios_engine_sha256_final(&context, accelerated);
    if (memcmp(scalar, accelerated, 32) != 0) {
      printf("FAIL at split %zu\n", split);
      return 1;
    }
  }
  printf("engine sha256: accelerated and scalar agree on 0..4096 bytes and 199 split points\n");
  return 0;
}
