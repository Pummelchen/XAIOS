/* SHA-256 on the instructions the CPU has for it.
 *
 * Every byte read out of a model package is hashed before it is handed over,
 * because that is what makes a bit that rotted on the disk a failed read
 * rather than a wrong answer. Measured, that check -- not the disk -- is what
 * bounds a model read: 87 MB/s through the verified path against 1.7 GB/s
 * from the block device underneath it. Twenty times slower, and all of it
 * inside the compression function.
 *
 * ARMv8 has four instructions that do that function's work directly. This is
 * the same algorithm expressed in them: SHA256H and SHA256H2 perform four
 * rounds each, SHA256SU0 and SHA256SU1 extend the message schedule. Nothing
 * about the result changes -- the digest is the digest -- so the scalar
 * implementation stays as the reference and this stands beside it.
 *
 * It is not always there. The extension is optional in ARMv8-A, and XAIOS
 * builds for the ARMv8.0 baseline on purpose, so the caller has to ask the
 * CPU first and install this only if the answer is yes. That check does not
 * belong here: it is a privileged register read on the kernel and an auxiliary
 * vector on a host, and this file is compiled into both.
 */
#include "sha256.h"

#if defined(__aarch64__)

#include <arm_neon.h>

/* Asking clang for these four instructions in this function only, rather than
   raising the target for the whole build. The rest of the kernel still
   compiles for ARMv8.0 with no SIMD at all; a machine without the extension
   never reaches this code because the dispatcher never installs it. */
__attribute__((target("+sha2")))
static void compress_blocks(uint32_t state[8], const uint8_t *blocks,
                            size_t count) {
  static const uint32_t k_round[64] = {
      0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU,
      0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U, 0xd807aa98U, 0x12835b01U,
      0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U,
      0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
      0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U,
      0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U,
      0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
      0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
      0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U,
      0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U, 0x1e376c08U,
      0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU,
      0x682e6ff3U, 0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
      0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U};

  uint32x4_t abcd = vld1q_u32(state);
  uint32x4_t efgh = vld1q_u32(state + 4);

  while (count-- != 0U) {
    const uint32x4_t saved_abcd = abcd;
    const uint32x4_t saved_efgh = efgh;

    /* The message words are big-endian on the wire and host-endian in the
       registers, so each quarter is byte-reversed as it is loaded. */
    uint32x4_t w0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(blocks)));
    uint32x4_t w1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(blocks + 16)));
    uint32x4_t w2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(blocks + 32)));
    uint32x4_t w3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(blocks + 48)));
    blocks += 64;

    uint32x4_t work = vaddq_u32(w0, vld1q_u32(&k_round[0]));
    uint32x4_t hold;

/* Four rounds, plus the schedule update for the words those rounds' successors
   will need. The ordering is not free to rearrange: the round constants for
   the next four rounds are added to the *next* message block while it is still
   unextended, which is why `work` is built from `m1` rather than from the
   block this quarter just extended. */
#define SHA256_SCHEDULED(current, m1, m2, m3, next_k)                        \
  do {                                                                       \
    (current) = vsha256su0q_u32((current), (m1));                            \
    hold = abcd;                                                             \
    abcd = vsha256hq_u32(abcd, efgh, work);                                  \
    efgh = vsha256h2q_u32(efgh, hold, work);                                 \
    (current) = vsha256su1q_u32((current), (m2), (m3));                      \
    work = vaddq_u32((m1), vld1q_u32(&k_round[(next_k)]));                   \
  } while (0)

/* The last sixteen rounds have nothing left to schedule. */
#define SHA256_PLAIN(next_message, next_k)                                   \
  do {                                                                       \
    hold = abcd;                                                             \
    abcd = vsha256hq_u32(abcd, efgh, work);                                  \
    efgh = vsha256h2q_u32(efgh, hold, work);                                 \
    work = vaddq_u32((next_message), vld1q_u32(&k_round[(next_k)]));         \
  } while (0)

    SHA256_SCHEDULED(w0, w1, w2, w3, 4);
    SHA256_SCHEDULED(w1, w2, w3, w0, 8);
    SHA256_SCHEDULED(w2, w3, w0, w1, 12);
    SHA256_SCHEDULED(w3, w0, w1, w2, 16);
    SHA256_SCHEDULED(w0, w1, w2, w3, 20);
    SHA256_SCHEDULED(w1, w2, w3, w0, 24);
    SHA256_SCHEDULED(w2, w3, w0, w1, 28);
    SHA256_SCHEDULED(w3, w0, w1, w2, 32);
    SHA256_SCHEDULED(w0, w1, w2, w3, 36);
    SHA256_SCHEDULED(w1, w2, w3, w0, 40);
    SHA256_SCHEDULED(w2, w3, w0, w1, 44);
    SHA256_SCHEDULED(w3, w0, w1, w2, 48);
    SHA256_PLAIN(w1, 52);
    SHA256_PLAIN(w2, 56);
    SHA256_PLAIN(w3, 60);
#undef SHA256_SCHEDULED
#undef SHA256_PLAIN

    /* Rounds sixty to sixty-three: nothing follows, so nothing is prepared. */
    hold = abcd;
    abcd = vsha256hq_u32(abcd, efgh, work);
    efgh = vsha256h2q_u32(efgh, hold, work);

    abcd = vaddq_u32(abcd, saved_abcd);
    efgh = vaddq_u32(efgh, saved_efgh);
  }

  vst1q_u32(state, abcd);
  vst1q_u32(state + 4, efgh);
}

xaios_engine_sha256_compress_fn xaios_engine_sha256_hardware_compressor(void) {
  return compress_blocks;
}

#else

xaios_engine_sha256_compress_fn xaios_engine_sha256_hardware_compressor(void) {
  return 0;
}

#endif
