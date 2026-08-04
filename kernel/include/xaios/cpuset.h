#ifndef XAIOS_CPUSET_H
#define XAIOS_CPUSET_H

#include <xaios/types.h>

/*
 * Runtime-sized CPU set. The owner supplies zeroed storage containing
 * xaios_cpuset_words(cpu_capacity) uint64_t words. This keeps topology-sized
 * state proportional to the CPUs admitted by the platform instead of imposing
 * a compile-time CPU ceiling.
 */
typedef struct xaios_cpuset {
  uint64_t *bits;
  uint32_t word_count;
  uint32_t cpu_capacity;
} xaios_cpuset_t;

static inline uint32_t xaios_cpuset_words(uint32_t cpu_capacity) {
  return cpu_capacity == 0U ? 0U : ((cpu_capacity - 1U) / 64U) + 1U;
}

static inline void xaios_cpuset_init(xaios_cpuset_t *set, uint64_t *storage,
                                     uint32_t cpu_capacity) {
  set->bits = storage;
  set->word_count = xaios_cpuset_words(cpu_capacity);
  set->cpu_capacity = cpu_capacity;
  for (uint32_t i = 0; i < set->word_count; ++i) {
    set->bits[i] = 0U;
  }
}

static inline void xaios_cpuset_zero(xaios_cpuset_t *set) {
  for (uint32_t i = 0; i < set->word_count; ++i) {
    set->bits[i] = 0U;
  }
}

static inline void xaios_cpuset_set(xaios_cpuset_t *set, uint32_t cpu) {
  if (cpu < set->cpu_capacity) {
    set->bits[cpu / 64U] |= UINT64_C(1) << (cpu % 64U);
  }
}

static inline void xaios_cpuset_clear(xaios_cpuset_t *set, uint32_t cpu) {
  if (cpu < set->cpu_capacity) {
    set->bits[cpu / 64U] &= ~(UINT64_C(1) << (cpu % 64U));
  }
}

static inline int xaios_cpuset_test(const xaios_cpuset_t *set, uint32_t cpu) {
  if (cpu >= set->cpu_capacity) {
    return 0;
  }
  return (set->bits[cpu / 64U] & (UINT64_C(1) << (cpu % 64U))) != 0;
}

static inline uint32_t xaios_cpuset_count(const xaios_cpuset_t *set) {
  uint32_t count = 0U;
  for (uint32_t i = 0; i < set->word_count; ++i) {
    uint64_t word = set->bits[i];
    while (word != 0U) {
      word &= word - 1U;
      ++count;
    }
  }
  return count;
}

/* Returns cpu_capacity when the set is empty. */
static inline uint32_t xaios_cpuset_first(const xaios_cpuset_t *set) {
  for (uint32_t cpu = 0U; cpu < set->cpu_capacity; ++cpu) {
    if (xaios_cpuset_test(set, cpu) != 0) {
      return cpu;
    }
  }
  return set->cpu_capacity;
}

static inline int xaios_cpuset_compatible(const xaios_cpuset_t *lhs,
                                          const xaios_cpuset_t *rhs) {
  return lhs->cpu_capacity == rhs->cpu_capacity &&
         lhs->word_count == rhs->word_count;
}

static inline void xaios_cpuset_or(xaios_cpuset_t *dst,
                                   const xaios_cpuset_t *src) {
  if (xaios_cpuset_compatible(dst, src) == 0) {
    return;
  }
  for (uint32_t i = 0; i < dst->word_count; ++i) {
    dst->bits[i] |= src->bits[i];
  }
}

static inline void xaios_cpuset_and(xaios_cpuset_t *dst,
                                    const xaios_cpuset_t *src) {
  if (xaios_cpuset_compatible(dst, src) == 0) {
    return;
  }
  for (uint32_t i = 0; i < dst->word_count; ++i) {
    dst->bits[i] &= src->bits[i];
  }
}

#endif
