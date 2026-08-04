/*
 * Freestanding C runtime string/memory functions for XAIOS kernel.
 *
 * These replace libstd functions (memcpy, memset, strlen, strncmp)
 * which are not available in the freestanding AArch64 build environment.
 * The compiler may implicitly generate calls to memcpy/memset for
 * struct copies and zero-initialization.
 */

#include <xaios/types.h>
#include <string.h>

void *memcpy(void *dst, const void *src, size_t n) {
  uint8_t *d = (uint8_t *)dst;
  const uint8_t *s = (const uint8_t *)src;
  for (uint64_t i = 0; i < n; ++i) {
    d[i] = s[i];
  }
  return dst;
}

void *memset(void *dst, int value, size_t n) {
  uint8_t *d = (uint8_t *)dst;
  uint8_t v = (uint8_t)value;
  for (uint64_t i = 0; i < n; ++i) {
    d[i] = v;
  }
  return dst;
}

void *memmove(void *dst, const void *src, size_t n) {
  uint8_t *d = (uint8_t *)dst;
  const uint8_t *s = (const uint8_t *)src;
  if (d < s) {
    for (uint64_t i = 0; i < n; ++i) {
      d[i] = s[i];
    }
  } else if (d > s) {
    for (uint64_t i = n; i > 0; --i) {
      d[i - 1] = s[i - 1];
    }
  }
  return dst;
}

size_t strlen(const char *s) {
  size_t len = 0;
  while (s[len] != '\0') {
    ++len;
  }
  return len;
}

int strncmp(const char *a, const char *b, size_t n) {
  for (uint64_t i = 0; i < n; ++i) {
    if (a[i] != b[i]) {
      return (int)(uint8_t)a[i] - (int)(uint8_t)b[i];
    }
    if (a[i] == '\0') {
      return 0;
    }
  }
  return 0;
}

int memcmp(const void *left, const void *right, size_t n) {
  const uint8_t *a = (const uint8_t *)left;
  const uint8_t *b = (const uint8_t *)right;
  for (uint64_t i = 0; i < n; ++i) {
    if (a[i] != b[i]) return (int)a[i] - (int)b[i];
  }
  return 0;
}

int strcmp(const char *left, const char *right) {
  uint64_t index = 0U;
  while (left[index] == right[index]) {
    if (left[index] == '\0') return 0;
    ++index;
  }
  return (int)(uint8_t)left[index] - (int)(uint8_t)right[index];
}
