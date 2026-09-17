#ifndef XAIOS_ENGINE_PACKED_INTERNAL_H
#define XAIOS_ENGINE_PACKED_INTERNAL_H

/* Shared by packed.c and packed_simd.c: the feature detection they must agree
   on, and the integer helpers the scalar reference path and the architecture
   kernels both call. The helpers carry no floating point, so moving the call
   across a translation unit cannot change a result. */

#include <xaios_engine/packed.h>

#if defined(__aarch64__) && defined(__ARM_NEON)
#include <arm_neon.h>
#define XAIOS_PACKED_HAS_NEON 1
#else
#define XAIOS_PACKED_HAS_NEON 0
#endif

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#define XAIOS_PACKED_HAS_X86_64 1
#else
#define XAIOS_PACKED_HAS_X86_64 0
#endif

/* SVE is compiled in wherever the toolchain has the intrinsics, and the one
   function that uses them carries its own target attribute.
   The obvious guard -- __ARM_FEATURE_SVE -- is wrong here, and quietly so.
   That macro is defined only when the whole translation unit is built with
   +sve, which this kernel is not and must not be: compiling every function
   in this file for SVE would let the compiler emit SVE instructions in code
   that runs on CPUs without it. Guarding on it therefore compiled the SVE
   kernel out entirely, and the differential check below reported "declined"
   -- which looked exactly like a kernel that had been tested and rejected
   rather than one that was never built.
   Per-function targeting gets both: the rest of the file stays baseline, and
   the SVE kernel is present and only ever called after the platform has said
   the instructions will not trap. */
#if defined(__aarch64__) && defined(__has_include)
#if __has_include(<arm_sve.h>)
#include <arm_sve.h>
#define XAIOS_PACKED_HAS_SVE 1
#endif
#endif
#ifndef XAIOS_PACKED_HAS_SVE
#define XAIOS_PACKED_HAS_SVE 0
#endif

/* Defined once in packed.c, called from both translation units. These were
   file-static helpers before the kernels moved; they keep their bodies and
   gain the module prefix because they now cross a boundary. */
int8_t xaios_packed_unpack_weight(const xaios_packed_matrix_t *matrix,
                                  uint64_t index);
uint64_t xaios_packed_group_count(const xaios_packed_matrix_t *matrix);

#if XAIOS_PACKED_HAS_X86_64
/* The CPUID/XGETBV usability probe, defined in packed.c beside the
   availability check that also asks it and called by the AVX2 kernel. */
int xaios_packed_x86_avx2_usable(void);
#endif

#endif /* XAIOS_ENGINE_PACKED_INTERNAL_H */
