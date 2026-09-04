#include <xaios/cpu_features.h>

static void cpuid(uint32_t leaf, uint32_t subleaf, uint32_t *a, uint32_t *b,
                  uint32_t *c, uint32_t *d) {
  __asm__ volatile("cpuid"
                   : "=a"(*a), "=b"(*b), "=c"(*c), "=d"(*d)
                   : "a"(leaf), "c"(subleaf));
}

/* CPUID leaf 7, sub-leaf 0, as Intel and AMD both document it. These report
   what the silicon has; whether the kernel has enabled the wider state for
   userspace is a separate question, answered by the engine's own probes. */
void cpu_features_query(xaios_cpu_features_t *features) {
  uint32_t a = 0U, b = 0U, c = 0U, d = 0U;
  if (features == 0) return;
  features->neon = 0U; features->sve = 0U; features->rvv = 0U;
  features->sstc = 0U;
  cpuid(0U, 0U, &a, &b, &c, &d);
  if (a < 7U) {
    features->avx2 = 0U; features->avx512 = 0U; features->vnni = 0U;
    features->amx = 0U;
    return;
  }
  cpuid(7U, 0U, &a, &b, &c, &d);
  features->avx2 = (b >> 5) & 1U;
  features->avx512 = (b >> 16) & 1U;    /* AVX512F */
  features->vnni = (c >> 11) & 1U;      /* AVX512_VNNI */
  features->amx = (d >> 24) & 1U;       /* AMX-TILE */
}
