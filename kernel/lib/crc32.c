#include <xaios/crc32.h>

uint32_t xaios_crc32_begin(void) { return UINT32_C(0xffffffff); }

uint32_t xaios_crc32_update(uint32_t state, const void *data, uint64_t length) {
  const uint8_t *bytes = (const uint8_t *)data;
  for (uint64_t i = 0U; i < length; ++i) {
    state ^= bytes[i];
    for (uint32_t bit = 0U; bit < 8U; ++bit) {
      uint32_t mask = (uint32_t)(0U - (state & 1U));
      state = (state >> 1U) ^ (UINT32_C(0xedb88320) & mask);
    }
  }
  return state;
}

uint32_t xaios_crc32_finish(uint32_t state) {
  return state ^ UINT32_C(0xffffffff);
}

uint32_t xaios_crc32(const void *data, uint64_t length) {
  return xaios_crc32_finish(
      xaios_crc32_update(xaios_crc32_begin(), data, length));
}
