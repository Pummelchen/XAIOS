/* Decoding one field line of a QPACK field section (RFC 9204 sections 4.5 and 3.2.5). */

#include "webtransport/http3/qpack.h"

/* An inline string may be Huffman-coded, and a resolved field must be plain bytes, so it is decoded into the
 * caller's scratch. `*scratch_used` advances so that a name and a value can share the buffer within one line --
 * AND so that a line cannot overwrite the line before it, which is the defect this cursor exists to prevent
 * (WT-154). */
static wt_status_t materialise(const uint8_t *bytes, size_t length, int huffman, uint8_t *scratch,
                               size_t capacity, size_t *scratch_used, const uint8_t **out,
                               size_t *out_length) {
  size_t decoded = 0U;
  wt_status_t status;

  if (!huffman) {
    *out = bytes;
    *out_length = length;
    return WT_OK;
  }
  /* The cursor is the SECTION's, so it can be past the end of the buffer the caller gave the decoder -- a section
   * with more inline strings than the buffer holds. Subtracting then would wrap to a huge size and the decode
   * would write past the caller's buffer, so this is a bound rather than a formality (WT-154). */
  if (*scratch_used > capacity) return WT_ERR_LIMIT;
  status = wt_qpack_huffman_decode(bytes, length, scratch + *scratch_used, capacity - *scratch_used,
                                  &decoded);
  if (status == WT_ERR_PROTOCOL) return WT_ERR_PROTOCOL;
  if (status != WT_OK) return status;
  *out = scratch + *scratch_used;
  *out_length = decoded;
  *scratch_used += decoded;
  return WT_OK;
}

/* The name and value of the dynamic entry at an absolute index. An index the table
 * no longer (or does not yet) holds is what QPACK_DECOMPRESSION_FAILED is for. */
static wt_status_t dynamic_lookup(const wt_qpack_dynamic_table_t *table, uint64_t absolute,
                                  wt_qpack_error_t *out_error, const uint8_t **out_name,
                                  size_t *out_name_length, const uint8_t **out_value,
                                  size_t *out_value_length) {
  if (table == NULL ||
      wt_qpack_dynamic_entry(table, absolute, out_name, out_name_length, out_value,
                             out_value_length) != WT_OK) {
    if (out_error != NULL) *out_error = WT_QPACK_ERROR_DECOMPRESSION_FAILED;
    return WT_ERR_PROTOCOL;
  }
  return WT_OK;
}

wt_status_t wt_qpack_field_section_next(wt_cursor_t *c, const wt_qpack_header_prefix_t *prefix,
                                        const wt_qpack_dynamic_table_t *table, uint8_t *scratch,
                                        size_t scratch_capacity, size_t *scratch_used,
                                        wt_qpack_resolved_field_t *out,
                                        wt_qpack_error_t *out_error) {
  wt_qpack_field_line_t line;
  const uint8_t *inline_value = NULL;
  size_t inline_value_length = 0U;
  const uint8_t *entry_name = NULL;
  const uint8_t *entry_value = NULL;
  size_t entry_name_length = 0U;
  size_t entry_value_length = 0U;
  wt_status_t status;

  if (out_error != NULL) *out_error = WT_QPACK_ERROR_NONE;
  if (c == NULL || prefix == NULL || out == NULL || scratch_used == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (scratch == NULL && scratch_capacity != 0U) return WT_ERR_INVALID_ARGUMENT;

  /* The end of the section is not an error: the caller asked for the next field and
   * there is none. */
  if (wt_cursor_at_end(c)) return WT_ERR_CLOSED;

  status = wt_qpack_field_line_decode(c, &line);
  if (status == WT_ERR_TRUNCATED) return WT_ERR_TRUNCATED;
  if (status != WT_OK) {
    if (out_error != NULL) *out_error = WT_QPACK_ERROR_DECOMPRESSION_FAILED;
    return WT_ERR_PROTOCOL;
  }

  /* The value is inline for every form except the two indexed ones. Decoding it
   * first keeps the name resolution below free of the scratch arithmetic. */
  if (line.kind != WT_QPACK_FIELD_INDEXED_STATIC && line.kind != WT_QPACK_FIELD_INDEXED_DYNAMIC) {
    status = materialise(line.value, line.value_length, line.value_huffman, scratch,
                         scratch_capacity, scratch_used, &inline_value, &inline_value_length);
    if (status != WT_OK) {
      if (out_error != NULL) {
        *out_error = status == WT_ERR_LIMIT ? WT_QPACK_ERROR_NONE
                                            : WT_QPACK_ERROR_DECOMPRESSION_FAILED;
      }
      return status;
    }
  }

  switch (line.kind) {
    case WT_QPACK_FIELD_INDEXED_STATIC: {
      wt_qpack_static_entry_t entry;
      if (wt_qpack_static_entry(line.index, &entry) != WT_OK) {
        if (out_error != NULL) *out_error = WT_QPACK_ERROR_DECOMPRESSION_FAILED;
        return WT_ERR_PROTOCOL;
      }
      out->name = (const uint8_t *)entry.name;
      out->name_length = entry.name_length;
      out->value = (const uint8_t *)entry.value;
      out->value_length = entry.value_length;
      return WT_OK;
    }
    case WT_QPACK_FIELD_LITERAL_NAME_REF_STATIC: {
      wt_qpack_static_entry_t entry;
      if (wt_qpack_static_entry(line.index, &entry) != WT_OK) {
        if (out_error != NULL) *out_error = WT_QPACK_ERROR_DECOMPRESSION_FAILED;
        return WT_ERR_PROTOCOL;
      }
      /* The name from the table, the value from the line. */
      out->name = (const uint8_t *)entry.name;
      out->name_length = entry.name_length;
      out->value = inline_value;
      out->value_length = inline_value_length;
      return WT_OK;
    }
    case WT_QPACK_FIELD_INDEXED_DYNAMIC:
    case WT_QPACK_FIELD_LITERAL_NAME_REF_DYNAMIC: {
      /* A dynamic index is relative to the Base and counts DOWN from it: an absolute
       * index is `Base - Index - 1` (section 3.2.5). An index at or above the Base
       * names nothing. */
      uint64_t absolute;
      if (line.index >= prefix->base) {
        if (out_error != NULL) *out_error = WT_QPACK_ERROR_DECOMPRESSION_FAILED;
        return WT_ERR_PROTOCOL;
      }
      absolute = prefix->base - line.index - 1U;
      /* RFC 9204 section 2.2.3: "If the absolute index of a dynamic table entry is greater than or equal to the
       * Required Insert Count, the decoder MUST treat this as a connection error of type
       * QPACK_DECOMPRESSION_FAILED." The table bounds check alone is not enough -- the entry can be in the table
       * and still be one this section was never allowed to reference, which tells the decoder the encoder's
       * count and its own have diverged. An audit decoded a section with a Required Insert Count of 1 and a Base
       * of 6 into entry 5 without complaint. */
      if (absolute >= prefix->required_insert_count) {
        if (out_error != NULL) *out_error = WT_QPACK_ERROR_DECOMPRESSION_FAILED;
        return WT_ERR_PROTOCOL;
      }
      status = dynamic_lookup(table, absolute, out_error, &entry_name, &entry_name_length,
                              &entry_value, &entry_value_length);
      if (status != WT_OK) return status;
      out->name = entry_name;
      out->name_length = entry_name_length;
      /* The indexed form takes both halves from the table; the name-reference form
       * takes the name from it and the value from the line. */
      out->value = line.kind == WT_QPACK_FIELD_INDEXED_DYNAMIC ? entry_value : inline_value;
      out->value_length =
          line.kind == WT_QPACK_FIELD_INDEXED_DYNAMIC ? entry_value_length : inline_value_length;
      return WT_OK;
    }
    case WT_QPACK_FIELD_POST_BASE_INDEX:
    case WT_QPACK_FIELD_POST_BASE_NAME_REF: {
      /* A post-base index counts UP from the Base: an absolute index is `Base + Index`
       * (section 3.2.5). */
      uint64_t absolute;
      if (line.index > UINT64_MAX - prefix->base) {
        if (out_error != NULL) *out_error = WT_QPACK_ERROR_DECOMPRESSION_FAILED;
        return WT_ERR_PROTOCOL;
      }
      absolute = prefix->base + line.index;
      /* The same section 2.2.3 rule as the base-relative form above, and it is the form where it matters most: a
       * post-base index counts UP past the Base, so an encoder that has lost the count can name an entry no
       * section was allowed to reference. */
      if (absolute >= prefix->required_insert_count) {
        if (out_error != NULL) *out_error = WT_QPACK_ERROR_DECOMPRESSION_FAILED;
        return WT_ERR_PROTOCOL;
      }
      status = dynamic_lookup(table, absolute, out_error, &entry_name, &entry_name_length,
                              &entry_value, &entry_value_length);
      if (status != WT_OK) return status;
      out->name = entry_name;
      out->name_length = entry_name_length;
      out->value = line.kind == WT_QPACK_FIELD_POST_BASE_INDEX ? entry_value : inline_value;
      out->value_length =
          line.kind == WT_QPACK_FIELD_POST_BASE_INDEX ? entry_value_length : inline_value_length;
      return WT_OK;
    }
    case WT_QPACK_FIELD_LITERAL_LITERAL_NAME: {
      status = materialise(line.name, line.name_length, line.name_huffman, scratch,
                           scratch_capacity, scratch_used, &out->name, &out->name_length);
      if (status != WT_OK) {
        if (out_error != NULL) {
          *out_error = status == WT_ERR_LIMIT ? WT_QPACK_ERROR_NONE
                                              : WT_QPACK_ERROR_DECOMPRESSION_FAILED;
        }
        return status;
      }
      out->value = inline_value;
      out->value_length = inline_value_length;
      return WT_OK;
    }
  }
  /* Not reachable: the switch covers every kind the enum has. */
  if (out_error != NULL) *out_error = WT_QPACK_ERROR_DECOMPRESSION_FAILED;
  return WT_ERR_STATE;
}
