/* QPACK's prefixed integers and strings (RFC 9204 section 4.1). */

#include <string.h>

#include "webtransport/http3/qpack.h"
#include "webtransport/quic/varint.h"

/* RFC 9204 section 4.1.1: "the value is limited to 62 bits", so anything larger
 * is a malformed representation rather than a big number this endpoint declines. */
#define WT_QPACK_INTEGER_MAX WT_QUIC_VARINT_MAX

wt_status_t wt_qpack_integer_decode(wt_cursor_t *c, unsigned prefix_bits, uint64_t *out_value) {
  uint64_t prefix_max;
  uint64_t value;
  uint8_t first;
  unsigned shift;

  if (c == NULL || out_value == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (prefix_bits == 0U || prefix_bits > 8U) return WT_ERR_INVALID_ARGUMENT;

  prefix_max = ((uint64_t)1U << prefix_bits) - 1U;
  first = wt_cursor_u8(c);
  if (wt_cursor_failed(c)) return WT_ERR_TRUNCATED;
  value = (uint64_t)first & prefix_max;
  if (value < prefix_max) {
    *out_value = value;
    return WT_OK;
  }

  /* The prefix is full, so the rest arrives seven bits at a time until a byte
   * without the continuation bit. `shift` tracks how far the next group is moved,
   * and it is what the 62-bit bound is checked against: a group that would land
   * at or above bit 63 is refused rather than wrapped. */
  shift = 0U;
  for (;;) {
    uint8_t byte = wt_cursor_u8(c);
    if (wt_cursor_failed(c)) return WT_ERR_TRUNCATED;
    if (shift >= 63U) return WT_ERR_PROTOCOL;
    value += ((uint64_t)byte & (uint64_t)0x7fU) << shift;
    if (value > WT_QPACK_INTEGER_MAX) return WT_ERR_PROTOCOL;
    if ((byte & 0x80U) == 0U) break;
    shift += 7U;
  }
  *out_value = value;
  return WT_OK;
}

wt_status_t wt_qpack_integer_encode(wt_writer_t *w, unsigned prefix_bits, uint8_t prefix_flags,
                                    uint64_t value) {
  uint64_t prefix_max;

  if (w == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (prefix_bits == 0U || prefix_bits > 8U) return WT_ERR_INVALID_ARGUMENT;
  if (value > WT_QPACK_INTEGER_MAX) return WT_ERR_INVALID_ARGUMENT;
  if (prefix_bits < 8U && (prefix_flags & (uint8_t)((1U << prefix_bits) - 1U)) != 0U) {
    /* A flag bit inside the prefix would collide with the value's low bits.
     * Refused rather than masked: a caller that set one meant something else, and
     * silently dropping it would change the representation it asked for. */
    return WT_ERR_INVALID_ARGUMENT;
  }

  prefix_max = ((uint64_t)1U << prefix_bits) - 1U;
  if (value < prefix_max) {
    wt_writer_u8(w, (uint8_t)(prefix_flags | (uint8_t)value));
    return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
  }

  wt_writer_u8(w, (uint8_t)(prefix_flags | (uint8_t)prefix_max));
  value -= prefix_max;
  while (value >= 128U) {
    wt_writer_u8(w, (uint8_t)((value & 0x7fU) | 0x80U));
    value >>= 7;
  }
  wt_writer_u8(w, (uint8_t)value);
  return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
}

wt_status_t wt_qpack_string_decode(wt_cursor_t *c, const uint8_t **out_bytes, size_t *out_length,
                                   int *out_huffman) {
  uint64_t length;
  const uint8_t *bytes;

  if (c == NULL || out_bytes == NULL || out_length == NULL) return WT_ERR_INVALID_ARGUMENT;

  /* The H bit is the top bit of the length's first byte (section 4.1.2), so the
   * length integer itself has the seven-bit prefix below it. The byte is peeked
   * at rather than read, because the integer decoder owns the read. */
  {
    size_t available = 0U;
    const uint8_t *rest = wt_cursor_rest(c, &available);
    wt_status_t status;

    if (rest == NULL || available == 0U) return WT_ERR_TRUNCATED;
    if (out_huffman != NULL) *out_huffman = (rest[0] & 0x80U) != 0U;
    status = wt_qpack_integer_decode(c, 7U, &length);
    /* A malformed length is section 8's DECOMPRESSION_FAILED at the caller, but
     * the difference between "the bytes ran out" and "the integer is not one"
     * is worth keeping until then. */
    if (status != WT_OK) return status;
  }
  if (length > (uint64_t)SIZE_MAX) return WT_ERR_LIMIT;
  bytes = wt_cursor_bytes(c, (size_t)length);
  if (bytes == NULL && length != 0U) return WT_ERR_TRUNCATED;
  *out_bytes = bytes;
  *out_length = (size_t)length;
  return WT_OK;
}

wt_status_t wt_qpack_string_encode_coded(wt_writer_t *w, const uint8_t *bytes, size_t length,
                                        int huffman, uint8_t *scratch, size_t scratch_capacity) {
  const uint8_t *wire = bytes;
  size_t wire_length = length;

  if (w == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (bytes == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (scratch == NULL && scratch_capacity != 0U) return WT_ERR_INVALID_ARGUMENT;
  if ((uint64_t)length > WT_QPACK_INTEGER_MAX) return WT_ERR_INVALID_ARGUMENT;

  if (huffman) {
    uint8_t *coded = scratch;
    size_t coded_length = 0U;
    size_t needed = 0U;
    wt_status_t status = wt_qpack_huffman_encoded_size(bytes, length, &needed);

    if (status != WT_OK) return status;
    if (needed > scratch_capacity) return WT_ERR_LIMIT;
    status = wt_qpack_huffman_encode(bytes, length, coded, scratch_capacity, &coded_length);
    if (status != WT_OK) return status;
    wire = coded;
    wire_length = coded_length;
  }

  /* The H bit sits above the length's seven-bit prefix, so it is the only flag. */
  if (wt_qpack_integer_encode(w, 7U, huffman ? 0x80U : 0x00U, (uint64_t)wire_length) != WT_OK) {
    return WT_ERR_LIMIT;
  }
  if (wire_length != 0U) wt_writer_bytes(w, wire, wire_length);
  return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
}

wt_status_t wt_qpack_string_encode(wt_writer_t *w, const uint8_t *bytes, size_t length) {
  return wt_qpack_string_encode_coded(w, bytes, length, 0, NULL, 0U);
}
