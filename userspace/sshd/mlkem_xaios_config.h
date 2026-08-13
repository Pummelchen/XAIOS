#ifndef XAIOS_MLKEM_CONFIG_H
#define XAIOS_MLKEM_CONFIG_H

#include <stddef.h>
#include <stdint.h>

#define MLK_CONFIG_PARAMETER_SET 768
#define MLK_CONFIG_NAMESPACE_PREFIX xaios_mlkem768
#define MLK_CONFIG_NO_ASM
#define MLK_CONFIG_CUSTOM_MEMCPY
#define MLK_CONFIG_CUSTOM_MEMSET
#define MLK_CONFIG_CUSTOM_ZEROIZE

static inline void *mlk_memcpy(void *destination, const void *source,
                               size_t length) {
  uint8_t *output = (uint8_t *)destination;
  const uint8_t *input = (const uint8_t *)source;
  for (size_t i = 0U; i < length; ++i) output[i] = input[i];
  return destination;
}

static inline void *mlk_memset(void *buffer, int value, size_t length) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (size_t i = 0U; i < length; ++i) bytes[i] = (uint8_t)value;
  return buffer;
}

static inline void mlk_zeroize(void *buffer, size_t length) {
  volatile uint8_t *bytes = (volatile uint8_t *)buffer;
  while (length != 0U) {
    *bytes++ = 0U;
    --length;
  }
}

#endif
