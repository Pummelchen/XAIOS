#include <xaios/cpu_features.h>

uint32_t aarch64_sve_enabled(void);

static void zero(xaios_cpu_features_t *f) {
  f->neon = 0U; f->sve = 0U; f->avx2 = 0U; f->avx512 = 0U;
  f->vnni = 0U; f->amx = 0U; f->rvv = 0U; f->sstc = 0U;
}

void cpu_features_query(xaios_cpu_features_t *features) {
  if (features == 0) return;
  zero(features);
  /* Advanced SIMD is architecturally mandatory for AArch64 application-level
     code, so this is a fact about the architecture rather than a probe. */
  features->neon = 1U;
  features->sve = aarch64_sve_enabled() != 0U ? 1U : 0U;
}
