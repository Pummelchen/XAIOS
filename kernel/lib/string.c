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

/* Eight bytes at a time where the addresses allow it.
 *
 * These were byte loops, which is every copy the kernel makes: block bounce
 * buffers, filesystem reads, the model cache serving a hit. A two-mebibyte
 * chunk copied a byte at a time is two million iterations, and it showed --
 * the read cache measured 232 MB/s serving hits out of RAM, which is not a
 * memory bandwidth, it is the cost of the loop.
 *
 * Only when both addresses are eight-aligned. Unaligned wide accesses are
 * fine on normal memory on both architectures, but the kernel also copies to
 * and from device memory, where an unaligned access faults on AArch64 and
 * reports no syndrome to a hypervisor. Aligning the destination first and
 * then requiring both to agree keeps the wide path to the case that is
 * certainly safe, which is also the common one: pages, sectors and chunks are
 * all aligned far past eight. */
void *memcpy(void *dst, const void *src, size_t n) {
  uint8_t *d = (uint8_t *)dst;
  const uint8_t *s = (const uint8_t *)src;
  uint64_t i = 0;

  while (i < n && (((uintptr_t)(d + i)) & 7U) != 0U) {
    d[i] = s[i];
    ++i;
  }
  if ((((uintptr_t)(s + i)) & 7U) == 0U) {
    while (i + 8U <= n) {
      *(uint64_t *)(void *)(d + i) = *(const uint64_t *)(const void *)(s + i);
      i += 8U;
    }
  }
  for (; i < n; ++i) {
    d[i] = s[i];
  }
  return dst;
}

void *memset(void *dst, int value, size_t n) {
  uint8_t *d = (uint8_t *)dst;
  uint8_t v = (uint8_t)value;
  uint64_t i = 0;

  while (i < n && (((uintptr_t)(d + i)) & 7U) != 0U) {
    d[i] = v;
    ++i;
  }
  uint64_t wide = (uint64_t)v;
  wide |= wide << 8U;
  wide |= wide << 16U;
  wide |= wide << 32U;
  while (i + 8U <= n) {
    *(uint64_t *)(void *)(d + i) = wide;
    i += 8U;
  }
  for (; i < n; ++i) {
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
