#ifndef XAIOS_CPU_FEATURES_H
#define XAIOS_CPU_FEATURES_H

#include <xaios/types.h>

/* What this machine's CPUs can do, asked of the hardware rather than assumed
   from the architecture. Every field is 1 for present, 0 for absent; a field
   that does not apply to an architecture is 0, not unknown, because a CPU
   that is not x86 has no AVX and that is a fact rather than a gap. */
typedef struct xaios_cpu_features {
  uint32_t neon;
  uint32_t sve;
  uint32_t avx2;
  uint32_t avx512;
  uint32_t vnni;
  uint32_t amx;
  uint32_t rvv;  /* the RISC-V vector extension */
  uint32_t sstc; /* a supervisor timer comparator, so no firmware call per tick */
} xaios_cpu_features_t;

void cpu_features_query(xaios_cpu_features_t *features);

#endif
