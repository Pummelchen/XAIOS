/* Ask this CPU whether it can do SHA-256 itself, and check the answer.
 *
 * The engine's hash is on the hot path of every model read: a chunk is hashed
 * before its bytes are handed over, which is what turns a rotted bit into a
 * failed read rather than a wrong tensor. Measured, that check is what bounds
 * the read -- 87 MB/s through the verified path against 1.7 GB/s from the
 * device under it -- and it is entirely the compression function.
 *
 * ARMv8 has instructions for that function, optionally. XAIOS builds for the
 * ARMv8.0 baseline because that is what QEMU's default model decodes, so the
 * accelerated compressor cannot simply be linked in: it has to be selected
 * after asking ID_AA64ISAR0_EL1 whether the SHA2 extension is present. That
 * register is readable at EL1 and traps at EL0, which is why this lives in
 * the kernel and not beside the compressor it installs.
 *
 * Detection alone is not enough to install it. A hash that is fast and wrong
 * corrupts every package it signs and every verification it passes, silently,
 * and would keep passing its own checks because both sides would be the new
 * implementation. So this hashes known vectors and a multi-block input both
 * ways -- scalar reference and candidate -- and installs the candidate only if
 * they produce the same digests. A disagreement leaves the scalar path in
 * place and says so; the machine stays correct and slow rather than fast and
 * unsound.
 */
#include <xaios/engine_sha256_dispatch.h>

#include <xaios/klog.h>

#include "../../engine/src/sha256.h"

#include <stdint.h>

#define SHA2_FIELD_SHIFT 12U
#define SHA2_FIELD_MASK 0xfU

#if defined(__aarch64__)
static uint64_t isar0(void) {
  uint64_t value;
  __asm__ volatile("mrs %0, ID_AA64ISAR0_EL1" : "=r"(value));
  return value;
}

static int cpu_has_sha256(void) {
  return ((isar0() >> SHA2_FIELD_SHIFT) & SHA2_FIELD_MASK) != 0U;
}
#else
static int cpu_has_sha256(void) { return 0; }
#endif

static int digests_differ(const uint8_t first[32], const uint8_t second[32]) {
  for (uint32_t index = 0U; index < 32U; ++index) {
    if (first[index] != second[index]) return 1;
  }
  return 0;
}

static void digest_of(const uint8_t *data, uint64_t length,
                      uint8_t digest[32]) {
  xaios_engine_sha256_context_t context;
  xaios_engine_sha256_init(&context);
  xaios_engine_sha256_update(&context, data, (size_t)length);
  xaios_engine_sha256_final(&context, digest);
}

/* Long enough to cross the block boundary several times, and not a multiple of
   64, so the tail path and the whole-block path are both exercised. */
#define PROBE_BYTES 1000U

/* Every length from nothing to this, which crosses the 64-byte block boundary
   four times over and puts the tail at every offset within one. */
#define SWEEP_BYTES 300U

void engine_sha256_dispatch_init(void) {
  static const uint8_t expected_abc[32] = {
      0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
      0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
      0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
  static uint8_t probe[PROBE_BYTES];
  for (uint32_t index = 0U; index < PROBE_BYTES; ++index) {
    probe[index] = (uint8_t)((index * 131U + 7U) & 0xffU);
  }

  /* The reference answers, taken with nothing installed. */
  xaios_engine_sha256_install_compressor(0);
  uint8_t scalar_abc[32];
  uint8_t scalar_probe[32];
  digest_of((const uint8_t *)"abc", 3U, scalar_abc);
  digest_of(probe, PROBE_BYTES, scalar_probe);
  if (digests_differ(scalar_abc, expected_abc)) {
    klog("engine-sha256: scalar reference does not match the NIST vector; "
         "hashing is not trustworthy on this build\n");
    return;
  }

  int available = cpu_has_sha256();
  xaios_engine_sha256_compress_fn candidate =
      available ? xaios_engine_sha256_hardware_compressor() : 0;
  /* Buildable without the accelerated path, so the scalar figure can be
     rebuilt from this same tree and compared rather than remembered. Nothing
     in CI sets it; a build with it set is not the build that ships. */
#if defined(XAIOS_ENGINE_SHA256_SCALAR_ONLY)
  candidate = 0;
  klog("engine-sha256: scalar path forced at build time; this CPU %s the "
       "SHA2 extension\n", available ? "has" : "lacks");
  return;
#endif
  if (candidate == 0) {
    klog("engine-sha256: scalar path; this CPU reports no SHA2 extension\n");
    return;
  }

  xaios_engine_sha256_install_compressor(candidate);
  uint8_t hardware_abc[32];
  uint8_t hardware_probe[32];
  digest_of((const uint8_t *)"abc", 3U, hardware_abc);
  digest_of(probe, PROBE_BYTES, hardware_probe);
  if (digests_differ(hardware_abc, scalar_abc) ||
      digests_differ(hardware_probe, scalar_probe)) {
    xaios_engine_sha256_install_compressor(0);
    klog("engine-sha256: accelerated compressor disagreed with the reference; "
         "staying scalar\n");
    return;
  }

  /* Every length across several block boundaries, not just two samples.
     A compressor can be right on one input and wrong on the tail handling of
     another, and this is the only place the two implementations are compared
     on the architecture that actually runs the fast one -- CI's runners are
     x86_64, where there is no accelerated compressor to compare against, so
     the hosted test skips. If this check is weak, nothing else is looking. */
  uint32_t checked = 0U;
  for (uint32_t length = 0U; length <= SWEEP_BYTES; ++length) {
    uint8_t scalar_digest[32];
    uint8_t hardware_digest[32];
    xaios_engine_sha256_install_compressor(0);
    digest_of(probe, length, scalar_digest);
    xaios_engine_sha256_install_compressor(candidate);
    digest_of(probe, length, hardware_digest);
    if (digests_differ(scalar_digest, hardware_digest)) {
      xaios_engine_sha256_install_compressor(0);
      klog("engine-sha256: accelerated compressor disagreed with the "
           "reference at %u bytes; staying scalar\n", length);
      return;
    }
    ++checked;
  }
  klog("engine-sha256: accelerated path installed, verified against the "
       "scalar reference on %u lengths up to %u bytes\n", checked,
       SWEEP_BYTES);
}
