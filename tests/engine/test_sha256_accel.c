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

#if defined(__x86_64__)
/* CPUID.(EAX=07H,ECX=0):EBX[29] is the SHA extension; CPUID.(EAX=01H):ECX[19]
   is the SSE4.1 the compressor also uses. Leaf 7 is read only after the
   maximum leaf says it exists, because reading past it returns another leaf's
   contents rather than zero. */
static int host_has_sha(void) {
  unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
  __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                   : "a"(0u), "c"(0u));
  if (eax < 7u) return 0;
  __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                   : "a"(1u), "c"(0u));
  if ((ecx & (1u << 19)) == 0u) return 0;
  __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                   : "a"(7u), "c"(0u));
  return (ebx & (1u << 29)) != 0u;
}
#endif

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
       nothing to compare against and nothing to get wrong. The comparison
       still runs inside XAIOS at every boot -- engine_sha256_dispatch refuses
       to install the accelerated path unless it reproduces the scalar one
       first, and says which it chose. */
    printf("engine sha256: no accelerated compressor for this architecture, "
           "scalar path is the only one\n");
    return 0;
  }
#if defined(__x86_64__)
  /* Having a compressor is not the same as being able to run it. SHA-NI is
     optional on x86-64 and plenty of hosts lack it -- the Intel Xeon this
     project qualifies against is a Skylake, which does not have it at all --
     so installing it unconditionally would execute an undefined instruction
     rather than fail a comparison. This is the caller's question to ask, and
     the header says so; inside XAIOS the dispatcher asks CPUID for the same
     thing, and so does this.

     Asked with CPUID rather than `__builtin_cpu_supports("sha")`, which is
     not a portable question: clang accepts that feature string only from a
     certain version, and the older one CI builds with rejects it outright --
     "invalid cpu feature string for builtin", a compile error rather than a
     wrong answer. The instruction is in every x86-64 that could run this
     test. */
  if (!host_has_sha()) {
    printf("engine sha256: this host has no SHA extension, scalar path is "
           "the only one it can run\n");
    return 0;
  }
#endif

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
