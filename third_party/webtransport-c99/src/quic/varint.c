/* QUIC variable-length integers. See webtransport/quic/varint.h. */

#include "webtransport/quic/varint.h"

#include "webtransport/endian.h"

size_t wt_quic_varint_size(uint64_t value) {
  if (value < 64U) return 1U;
  if (value < 16384U) return 2U;
  if (value < 1073741824U) return 4U;
  if (value <= WT_QUIC_VARINT_MAX) return 8U;
  return 0U;
}

size_t wt_quic_varint_encode(uint64_t value, uint8_t *out, size_t capacity) {
  size_t size = wt_quic_varint_size(value);
  if (size == 0U || out == NULL || capacity < size) return 0U;

  switch (size) {
    case 1U:
      out[0] = (uint8_t)(value & 0x3FU);
      break;
    case 2U:
      /* The prefix is the top two bits of the first byte: 01 for two bytes. */
      wt_store_be16(out, (uint16_t)(value | 0x4000U));
      break;
    case 4U:
      wt_store_be32(out, (uint32_t)(value | 0x80000000U));
      break;
    default:
      wt_store_be64(out, value | UINT64_C(0xC000000000000000));
      break;
  }
  return size;
}

size_t wt_quic_writer_varint(wt_writer_t *w, uint64_t value) {
  uint8_t bytes[8];
  size_t size = wt_quic_varint_encode(value, bytes, sizeof(bytes));
  if (size == 0U) {
    /* An unencodable value is a caller's bug rather than a peer's, so it
     * overflows the writer: the writer's own failure flag is the one channel
     * every encoder in this library already checks, and adding a second one
     * here would be the kind of inconsistency that gets ignored. */
    if (w != NULL) w->overflow = 1;
    return 0U;
  }
  wt_writer_bytes(w, bytes, size);
  return size;
}

wt_status_t wt_quic_varint_decode_sized(wt_cursor_t *c, uint64_t *out,
                                        size_t *out_size) {
  uint8_t first;
  size_t size;
  uint64_t value;

  if (c == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (wt_cursor_remaining(c) == 0U) return WT_ERR_TRUNCATED;

  first = wt_cursor_u8(c);
  /* `1 << prefix` is the length in bytes: prefix 0 -> 1, 1 -> 2, 2 -> 4,
   * 3 -> 8. Written as a shift of the two-bit prefix rather than as a table so
   * that the arithmetic in RFC 9000 section 16 is recognizable in the code. */
  size = (size_t)1U << (size_t)(first >> 6);
  value = (uint64_t)(first & 0x3FU);

  if (size > 1U) {
    /* The remaining bytes are read as a view and checked before any of them is
     * used, so a truncated varint consumes nothing beyond the first byte and
     * leaves the cursor failed. */
    const uint8_t *rest = wt_cursor_bytes(c, size - 1U);
    size_t i;
    if (rest == NULL) return WT_ERR_TRUNCATED;
    for (i = 0U; i < size - 1U; i++) {
      value = (value << 8) | (uint64_t)rest[i];
    }
  }

  *out = value;
  if (out_size != NULL) *out_size = size;
  return WT_OK;
}

wt_status_t wt_quic_varint_decode(wt_cursor_t *c, uint64_t *out) {
  return wt_quic_varint_decode_sized(c, out, NULL);
}

int wt_quic_varint_is_minimal(uint64_t value, size_t size) {
  return wt_quic_varint_size(value) == size;
}
