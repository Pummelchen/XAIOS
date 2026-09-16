/* WebTransport C99: big-endian integer load and store.
 *
 * Every multibyte integer on the wire in QUIC, TLS and HTTP/3 is big-endian, so
 * these are the only byte-order conversions the protocol code needs. They are
 * written as byte shifts rather than as casts or memcpy-plus-swap, because a
 * cast would depend on the host's alignment and byte order and would be
 * undefined behaviour on an unaligned pointer -- and a peer controls where these
 * pointers point.
 *
 * The 24-bit forms exist because QUIC's varint length prefix and TLS's handshake
 * length are both 24 bits wide, and they are the two places a 24-bit value
 * appears.
 */

#ifndef WEBTRANSPORT_ENDIAN_H
#define WEBTRANSPORT_ENDIAN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint16_t wt_load_be16(const uint8_t *p);
uint32_t wt_load_be24(const uint8_t *p);
uint32_t wt_load_be32(const uint8_t *p);
uint64_t wt_load_be64(const uint8_t *p);

void wt_store_be16(uint8_t *p, uint16_t value);
void wt_store_be24(uint8_t *p, uint32_t value);
void wt_store_be32(uint8_t *p, uint32_t value);
void wt_store_be64(uint8_t *p, uint64_t value);

/* The number of bytes each form occupies, so that a caller sizing a buffer does
 * not write the literal 3 in one place and 4 in another. */
#define WT_BE16_SIZE 2U
#define WT_BE24_SIZE 3U
#define WT_BE32_SIZE 4U
#define WT_BE64_SIZE 8U

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_ENDIAN_H */
