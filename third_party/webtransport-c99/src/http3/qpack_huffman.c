/* QPACK's Huffman decoder (RFC 7541 appendix B, adopted by RFC 9204 section 4.1.2). */

#include "webtransport/http3/qpack.h"

#include <string.h>

#include "qpack_huffman_table.h"

wt_status_t wt_qpack_huffman_decode(const uint8_t *coded, size_t coded_length, uint8_t *out,
                                    size_t capacity, size_t *out_length) {
  uint32_t code = 0U;
  unsigned bits = 0U;
  size_t produced = 0U;
  size_t i;

  if (out_length == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (coded == NULL && coded_length != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (out == NULL && capacity != 0U) return WT_ERR_INVALID_ARGUMENT;
  *out_length = 0U;

  for (i = 0U; i < coded_length; i++) {
    unsigned bit;
    for (bit = 0x80U; bit != 0U; bit >>= 1) {
      const wt_rfc7541_huffman_range_t *range;
      uint32_t offset;

      code = (code << 1) | ((coded[i] & (uint8_t)bit) != 0U ? 1U : 0U);
      bits++;
      if (bits > (unsigned)WT_RFC7541_HUFFMAN_MAX_BITS) {
        /* No code is longer than thirty bits, so a run of bits that has not
         * matched one is a representation this table cannot produce. */
        return WT_ERR_PROTOCOL;
      }
      range = &WT_RFC7541_HUFFMAN_RANGES[bits - 1U];
      if (range->count == 0U || code < range->first_code) continue;
      offset = code - range->first_code;
      if (offset >= (uint32_t)range->count) continue;
      {
        uint16_t symbol = WT_RFC7541_HUFFMAN_BY_CODE[range->offset + (size_t)offset].symbol;
        if (symbol == (uint16_t)WT_RFC7541_HUFFMAN_EOS) {
          /* Section 5.2: "A Huffman-encoded string literal containing the EOS
           * symbol MUST be treated as a decoding error." */
          return WT_ERR_PROTOCOL;
        }
        if (produced == capacity) return WT_ERR_LIMIT;
        out[produced] = (uint8_t)symbol;
        produced++;
        code = 0U;
        bits = 0U;
      }
    }
  }

  /* Section 5.2: the padding is the most significant bits of the EOS code -- all
   * ones -- and is at most seven bits long. Anything else is a decoding error, and
   * accepting it would let a peer's malformed string decode to a different value
   * than it encoded. */
  if (bits > 7U) return WT_ERR_PROTOCOL;
  if (bits != 0U) {
    uint32_t expected = (((uint32_t)1U << bits) - 1U);
    if (code != expected) return WT_ERR_PROTOCOL;
  }
  *out_length = produced;
  return WT_OK;
}

/* The encoder writes the same table the decoder reads, MSB first, and pads the
 * final byte with one-bits -- which is the prefix of the EOS code, so a decoder
 * reads the padding as exactly that (RFC 7541 section 5.2). */
wt_status_t wt_qpack_huffman_encoded_size(const uint8_t *bytes, size_t length, size_t *out_size) {
  size_t bits = 0U;
  size_t i;

  if (out_size == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (bytes == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;
  *out_size = 0U;

  for (i = 0U; i < length; i++) {
    bits += (size_t)WT_RFC7541_HUFFMAN_CODES[bytes[i]].bits;
    if (bits > SIZE_MAX - 7U) return WT_ERR_OVERFLOW;
  }
  /* Rounded up to the byte boundary. */
  *out_size = (bits + 7U) / 8U;
  return WT_OK;
}

wt_status_t wt_qpack_huffman_encode(const uint8_t *bytes, size_t length, uint8_t *out,
                                    size_t capacity, size_t *out_length) {
  size_t used = 0U;
  size_t produced = 0U;
  size_t i;

  if (out_length == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (bytes == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (out == NULL && capacity != 0U) return WT_ERR_INVALID_ARGUMENT;
  *out_length = 0U;
  if (capacity != 0U) memset(out, 0, capacity);

  for (i = 0U; i < length; i++) {
    const wt_rfc7541_huffman_code_t *entry = &WT_RFC7541_HUFFMAN_CODES[bytes[i]];
    unsigned remaining = entry->bits;
    while (remaining != 0U) {
      unsigned free_bits;
      unsigned take;
      uint32_t chunk;

      if (produced == capacity) return WT_ERR_LIMIT;
      free_bits = 8U - (unsigned)(used % 8U);
      take = remaining < free_bits ? remaining : free_bits;
      /* The top `take` bits of the code, shifted down into place and left in the
       * byte's low `take` bits, then moved up under the bits already written. */
      chunk = (entry->code >> (remaining - take)) & (((uint32_t)1U << take) - 1U);
      out[produced] = (uint8_t)(out[produced] | (uint8_t)(chunk << (free_bits - take)));
      used += (size_t)take;
      remaining -= take;
      if (used % 8U == 0U) produced++;
    }
  }

  /* Pad the last partial byte with one-bits: the most significant bits of the EOS
   * code, which is what section 5.2 requires. */
  if (used % 8U != 0U) {
    unsigned free_bits = 8U - (unsigned)(used % 8U);
    uint32_t padding = (((uint32_t)1U << free_bits) - 1U);
    if (produced == capacity) return WT_ERR_LIMIT;
    out[produced] = (uint8_t)(out[produced] | (uint8_t)padding);
    produced++;
  }

  *out_length = produced;
  return WT_OK;
}
