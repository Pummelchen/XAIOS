/* QPACK's field section prefix (RFC 9204 section 4.5.1). */

#include "webtransport/http3/qpack.h"

uint64_t wt_qpack_max_entries(size_t capacity) {
  return (uint64_t)(capacity / (size_t)WT_QPACK_DYNAMIC_ENTRY_OVERHEAD);
}

wt_status_t wt_qpack_header_prefix_encode(wt_writer_t *w, uint64_t required_insert_count,
                                          uint64_t base, uint64_t max_entries) {
  uint64_t full_range = 2U * max_entries;
  uint64_t encoded;

  if (w == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (max_entries > 0U && full_range < max_entries) return WT_ERR_OVERFLOW;
  if (required_insert_count != 0U && max_entries == 0U) {
    /* No table to reference: section 4.5.1 makes a non-zero required count
     * impossible when MaxEntries is zero. */
    return WT_ERR_INVALID_ARGUMENT;
  }

  /* Section 4.5.1: the count is sent modulo twice the table's size in entries, plus
   * one, so a value the decoder can place inside the window it knows about. */
  encoded = required_insert_count == 0U ? 0U
                                        : (required_insert_count % full_range) + 1U;

  /* The Base is a signed delta from the required count: section 4.5.1's figure puts
   * the S bit in the MOST significant bit of the byte, with the seven-bit-prefix
   * delta below it (the figures number their bits left to right from the top). */
  if (base >= required_insert_count) {
    uint64_t delta = base - required_insert_count;
    if (delta > (uint64_t)0x3fffffffffffffffULL) return WT_ERR_INVALID_ARGUMENT;
    if (wt_qpack_integer_encode(w, 8U, 0U, encoded) != WT_OK) return WT_ERR_LIMIT;
    return wt_qpack_integer_encode(w, 7U, 0x00U, delta);
  }
  {
    uint64_t delta = required_insert_count - base - 1U;
    if (delta > (uint64_t)0x3fffffffffffffffULL) return WT_ERR_INVALID_ARGUMENT;
    if (wt_qpack_integer_encode(w, 8U, 0U, encoded) != WT_OK) return WT_ERR_LIMIT;
    return wt_qpack_integer_encode(w, 7U, 0x80U, delta);
  }
}

wt_status_t wt_qpack_header_prefix_decode(wt_cursor_t *c, uint64_t max_entries,
                                          uint64_t known_insert_count,
                                          wt_qpack_header_prefix_t *out,
                                          wt_qpack_error_t *out_error) {
  uint64_t full_range = 2U * max_entries;
  uint64_t encoded;
  uint64_t delta;
  int negative;
  wt_status_t status;

  if (out_error != NULL) *out_error = WT_QPACK_ERROR_NONE;
  if (c == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (max_entries > 0U && full_range < max_entries) {
    if (out_error != NULL) *out_error = WT_QPACK_ERROR_DECOMPRESSION_FAILED;
    return WT_ERR_PROTOCOL;
  }

  status = wt_qpack_integer_decode(c, 8U, &encoded);
  if (status == WT_ERR_TRUNCATED) return WT_ERR_TRUNCATED;
  if (status != WT_OK) {
    if (out_error != NULL) *out_error = WT_QPACK_ERROR_DECOMPRESSION_FAILED;
    return WT_ERR_PROTOCOL;
  }
  {
    size_t available = 0U;
    const uint8_t *rest = wt_cursor_rest(c, &available);
    if (rest == NULL || available == 0U) return WT_ERR_TRUNCATED;
    negative = (rest[0] & 0x80U) != 0U;
  }
  status = wt_qpack_integer_decode(c, 7U, &delta);
  if (status == WT_ERR_TRUNCATED) return WT_ERR_TRUNCATED;
  if (status != WT_OK) {
    if (out_error != NULL) *out_error = WT_QPACK_ERROR_DECOMPRESSION_FAILED;
    return WT_ERR_PROTOCOL;
  }

  /* Section 4.5.1's decoding algorithm, with both of its error exits: an encoded
   * count outside the full range cannot be a wrapped value, and a decoded count
   * that is more than the encoder could have inserted (given the window this
   * decoder knows) is not one either. */
  if (encoded == 0U) {
    out->required_insert_count = 0U;
  } else {
    uint64_t max_value;
    uint64_t max_wrapped;
    uint64_t required;

    if (encoded > full_range) {
      if (out_error != NULL) *out_error = WT_QPACK_ERROR_DECOMPRESSION_FAILED;
      return WT_ERR_PROTOCOL;
    }
    max_value = known_insert_count + max_entries;
    max_wrapped = (max_value / full_range) * full_range;
    required = max_wrapped + encoded - 1U;
    if (required > max_value) {
      if (required <= full_range) {
        if (out_error != NULL) *out_error = WT_QPACK_ERROR_DECOMPRESSION_FAILED;
        return WT_ERR_PROTOCOL;
      }
      required -= full_range;
    }
    if (required == 0U) {
      if (out_error != NULL) *out_error = WT_QPACK_ERROR_DECOMPRESSION_FAILED;
      return WT_ERR_PROTOCOL;
    }
    out->required_insert_count = required;
  }

  /* The Base is relative to the required count, and the negative form has one
   * subtracted from the delta: section 4.5.1's "Base = Required Insert Count -
   * Delta Base - 1". A delta with nothing to subtract from is a decoder error. */
  if (negative) {
    if (delta >= out->required_insert_count) {
      if (out_error != NULL) *out_error = WT_QPACK_ERROR_DECOMPRESSION_FAILED;
      return WT_ERR_PROTOCOL;
    }
    out->base = out->required_insert_count - delta - 1U;
  } else {
    if (delta > UINT64_MAX - out->required_insert_count) {
      if (out_error != NULL) *out_error = WT_QPACK_ERROR_DECOMPRESSION_FAILED;
      return WT_ERR_PROTOCOL;
    }
    out->base = out->required_insert_count + delta;
  }
  return WT_OK;
}
