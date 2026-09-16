/* Big-endian load and store. See webtransport/endian.h.
 *
 * Byte shifts in both directions, so that neither the host's byte order nor the
 * alignment of the pointer matters. The 24-bit forms are the reason this is a
 * file rather than four macros: a 24-bit field appears in QUIC's varint prefix
 * and in TLS's handshake length, and both are written by hand exactly once here
 * rather than at each site.
 */

#include "webtransport/endian.h"

uint16_t wt_load_be16(const uint8_t *p) {
  return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

uint32_t wt_load_be24(const uint8_t *p) {
  return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | (uint32_t)p[2];
}

uint32_t wt_load_be32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

uint64_t wt_load_be64(const uint8_t *p) {
  return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
         ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
         ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
         ((uint64_t)p[6] << 8) | (uint64_t)p[7];
}

void wt_store_be16(uint8_t *p, uint16_t value) {
  p[0] = (uint8_t)((value >> 8) & 0xFFU);
  p[1] = (uint8_t)(value & 0xFFU);
}

void wt_store_be24(uint8_t *p, uint32_t value) {
  p[0] = (uint8_t)((value >> 16) & 0xFFU);
  p[1] = (uint8_t)((value >> 8) & 0xFFU);
  p[2] = (uint8_t)(value & 0xFFU);
}

void wt_store_be32(uint8_t *p, uint32_t value) {
  p[0] = (uint8_t)((value >> 24) & 0xFFU);
  p[1] = (uint8_t)((value >> 16) & 0xFFU);
  p[2] = (uint8_t)((value >> 8) & 0xFFU);
  p[3] = (uint8_t)(value & 0xFFU);
}

void wt_store_be64(uint8_t *p, uint64_t value) {
  p[0] = (uint8_t)((value >> 56) & 0xFFU);
  p[1] = (uint8_t)((value >> 48) & 0xFFU);
  p[2] = (uint8_t)((value >> 40) & 0xFFU);
  p[3] = (uint8_t)((value >> 32) & 0xFFU);
  p[4] = (uint8_t)((value >> 24) & 0xFFU);
  p[5] = (uint8_t)((value >> 16) & 0xFFU);
  p[6] = (uint8_t)((value >> 8) & 0xFFU);
  p[7] = (uint8_t)(value & 0xFFU);
}
