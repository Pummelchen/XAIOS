#ifndef SSH_UTILS_H
#define SSH_UTILS_H

#include <xaios/types.h>

/* Memory copy: byte-by-byte for freestanding environment */
static inline void ssh_mem_copy(void *d, const void *s, uint64_t n) {
  uint8_t *o = (uint8_t *)d;
  const uint8_t *i = (const uint8_t *)s;
  for (uint64_t j = 0; j < n; ++j) o[j] = i[j];
}

/* Memory zero */
static inline void ssh_mem_zero(void *p, uint64_t n) {
  uint8_t *b = (uint8_t *)p;
  for (uint64_t i = 0; i < n; ++i) b[i] = 0;
}

/* String length */
static inline uint32_t ssh_str_len(const char *s) {
  uint32_t n = 0;
  while (s[n]) ++n;
  return n;
}

/* String equality */
static inline int ssh_str_eq(const char *lhs, const char *rhs) {
  if (lhs == 0 || rhs == 0) return 0;
  for (uint32_t i = 0;; ++i) {
    if (lhs[i] != rhs[i]) return 0;
    if (lhs[i] == '\0') return 1;
  }
}

#endif
