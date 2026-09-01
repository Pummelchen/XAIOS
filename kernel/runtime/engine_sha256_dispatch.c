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
#elif defined(__x86_64__)
/* CPUID is not privileged, so unlike the ARM path this same question could be
   asked from userspace. It is asked here anyway, because the answer has to be
   acted on in the one place that installs the compressor. */
static void cpuid_count(uint32_t leaf, uint32_t subleaf, uint32_t *eax,
                        uint32_t *ebx, uint32_t *ecx, uint32_t *edx) {
  __asm__ volatile("cpuid"
                   : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
                   : "a"(leaf), "c"(subleaf));
}

/* CPUID.(EAX=07H,ECX=0):EBX[29] is the SHA extension. CPUID.(EAX=01H):ECX[19]
   is SSE4.1, which the compressor also uses -- for the byte shuffle, the
   blend and the alignr that assemble the state and the schedule. No CPU ships
   one without the other, but the compressor needs both to run and asking for
   what it needs costs one more read. Leaf 7 does not exist on every CPU that
   answers CPUID at all, so the maximum leaf is checked first; reading past it
   returns another leaf's contents rather than zero. */
#define X86_LEAF7_SHA_BIT (UINT32_C(1) << 29)
#define X86_LEAF1_SSE41_BIT (UINT32_C(1) << 19)

static int cpu_has_sha256(void) {
  uint32_t eax = 0U, ebx = 0U, ecx = 0U, edx = 0U;
  cpuid_count(0U, 0U, &eax, &ebx, &ecx, &edx);
  if (eax < 7U) return 0;
  cpuid_count(1U, 0U, &eax, &ebx, &ecx, &edx);
  if ((ecx & X86_LEAF1_SSE41_BIT) == 0U) return 0;
  cpuid_count(7U, 0U, &eax, &ebx, &ecx, &edx);
  return (ebx & X86_LEAF7_SHA_BIT) != 0U;
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
    /* Two different answers, and saying which matters. "This CPU reports no
       SHA2 extension" was printed on x86-64 for as long as there was no x86
       compressor at all -- a statement about the CPU that nothing had asked
       it, on a target whose emulated CPU advertises the extension. */
    if (xaios_engine_sha256_hardware_compressor() == 0) {
      klog("engine-sha256: scalar path; no accelerated compressor is built "
           "for this architecture\n");
    } else {
      klog("engine-sha256: scalar path; this CPU reports no SHA2 "
           "extension\n");
    }
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
     another, and for either architecture this may be the only place the two
     implementations are ever compared: the hosted test runs whichever the
     build host can execute, and a host without the extension -- most x86-64
     CPUs, including the Xeon this project qualifies against -- skips it.
     If this check is weak, nothing else is looking. */
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
