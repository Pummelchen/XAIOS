/* QPACK's field line representations (RFC 9204 section 4.5). */

#include "webtransport/http3/qpack.h"

#include "webtransport/checked.h"

/* The first byte's pattern decides which representation follows: the section's
 * figures are a small prefix code, and reading it in that order is what keeps a
 * decoder from having to try each form in turn. */

wt_status_t wt_qpack_field_line_decode(wt_cursor_t *c, wt_qpack_field_line_t *out) {
  uint8_t first;
  size_t before;

  if (c == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  before = wt_cursor_remaining(c);
  /* The first byte is PEEKED, not read: every form's index -- and the literal
   * form's name length -- is an integer whose prefix lives in that byte, and the
   * integer decoder is what reads it. Consuming it here would need a rewind the
   * cursor does not offer. */
  {
    size_t available = 0U;
    const uint8_t *rest = wt_cursor_rest(c, &available);
    if (rest == NULL || available == 0U) return WT_ERR_TRUNCATED;
    first = rest[0];
  }

  out->never_indexed = 0;
  out->index = 0U;
  out->name_huffman = 0;
  out->name = NULL;
  out->name_length = 0U;
  out->value = NULL;
  out->value_length = 0U;
  out->value_huffman = 0;
  out->bytes_consumed = 0U;

  if ((first & 0x80U) != 0U) {
    /* 1 T index(6+): indexed field line, static when T is set. */
    if (wt_qpack_integer_decode(c, 6U, &out->index) != WT_OK) return WT_ERR_PROTOCOL;
    out->kind = (first & 0x40U) != 0U ? WT_QPACK_FIELD_INDEXED_STATIC
                                      : WT_QPACK_FIELD_INDEXED_DYNAMIC;
  } else if ((first & 0x40U) != 0U) {
    /* 01 N T index(4+) then a value string. */
    if (wt_qpack_integer_decode(c, 4U, &out->index) != WT_OK) return WT_ERR_PROTOCOL;
    out->never_indexed = (first & 0x20U) != 0U;
    out->kind = (first & 0x10U) != 0U ? WT_QPACK_FIELD_LITERAL_NAME_REF_STATIC
                                      : WT_QPACK_FIELD_LITERAL_NAME_REF_DYNAMIC;
    if (wt_qpack_string_decode(c, &out->value, &out->value_length, &out->value_huffman) != WT_OK) {
      return WT_ERR_TRUNCATED;
    }
  } else if ((first & 0x20U) != 0U) {
    /* 001 N H name-length(3+) then the name and the value. */
    uint64_t name_length;
    if (wt_qpack_integer_decode(c, 3U, &name_length) != WT_OK) return WT_ERR_PROTOCOL;
    out->never_indexed = (first & 0x10U) != 0U;
    out->name_huffman = (first & 0x08U) != 0U;
    /* The name length is a peer's varint (up to 2^62-1) and `name_length` here is a size_t, so the narrowing is
     * CHECKED rather than cast, exactly as `wt_qpack_string_decode` checks the value's length. A bare
     * `(size_t)name_length` truncates on a target whose size_t is narrower than 64 bits: a name of 2^32+1 bytes
     * becomes a one-byte name and the value that follows is read from the wrong offset, which mis-parses the whole
     * field line. A length that cannot be represented cannot be present in the cursor either, so it is a malformed
     * line rather than a wait that more bytes would end. */
    if (wt_checked_narrow_u64_to_size(name_length, &out->name_length) != WT_OK) {
      return WT_ERR_PROTOCOL;
    }
    out->name = wt_cursor_bytes(c, out->name_length);
    if (out->name == NULL && out->name_length != 0U) return WT_ERR_TRUNCATED;
    out->kind = WT_QPACK_FIELD_LITERAL_LITERAL_NAME;
    if (wt_qpack_string_decode(c, &out->value, &out->value_length, &out->value_huffman) != WT_OK) {
      return WT_ERR_TRUNCATED;
    }
  } else if ((first & 0x10U) != 0U) {
    /* 0001 index(4+): a dynamic entry counted from the base. */
    if (wt_qpack_integer_decode(c, 4U, &out->index) != WT_OK) return WT_ERR_PROTOCOL;
    out->kind = WT_QPACK_FIELD_POST_BASE_INDEX;
  } else {
    /* 0000 N index(3+) then a value string. */
    if (wt_qpack_integer_decode(c, 3U, &out->index) != WT_OK) return WT_ERR_PROTOCOL;
    out->never_indexed = (first & 0x08U) != 0U;
    out->kind = WT_QPACK_FIELD_POST_BASE_NAME_REF;
    if (wt_qpack_string_decode(c, &out->value, &out->value_length, &out->value_huffman) != WT_OK) {
      return WT_ERR_TRUNCATED;
    }
  }
  out->bytes_consumed = before - wt_cursor_remaining(c);
  return WT_OK;
}

wt_status_t wt_qpack_field_line_encode_coded(wt_writer_t *w, const wt_qpack_field_line_t *line,
                                            uint8_t *scratch, size_t scratch_capacity) {
  if (w == NULL || line == NULL) return WT_ERR_INVALID_ARGUMENT;

  switch (line->kind) {
    case WT_QPACK_FIELD_INDEXED_STATIC:
    case WT_QPACK_FIELD_INDEXED_DYNAMIC:
      return wt_qpack_integer_encode(w, 6U,
                                     line->kind == WT_QPACK_FIELD_INDEXED_STATIC ? 0xc0U : 0x80U,
                                     line->index);
    case WT_QPACK_FIELD_LITERAL_NAME_REF_STATIC:
    case WT_QPACK_FIELD_LITERAL_NAME_REF_DYNAMIC: {
      uint8_t flags = 0x40U;
      if (line->kind == WT_QPACK_FIELD_LITERAL_NAME_REF_STATIC) flags |= 0x10U;
      if (line->never_indexed) flags |= 0x20U;
      if (wt_qpack_integer_encode(w, 4U, flags, line->index) != WT_OK) return WT_ERR_LIMIT;
      return wt_qpack_string_encode_coded(w, line->value, line->value_length, line->value_huffman,
                                          scratch, scratch_capacity);
    }
    case WT_QPACK_FIELD_LITERAL_LITERAL_NAME: {
      uint8_t flags = 0x20U;
      const uint8_t *name_wire = line->name;
      size_t name_wire_length = line->name_length;

      if (line->never_indexed) flags |= 0x10U;
      if (line->name == NULL && line->name_length != 0U) return WT_ERR_INVALID_ARGUMENT;
      if (line->name_huffman) {
        size_t needed = 0U;
        size_t coded_length = 0U;

        /* The name is coded into the scratch first, and written into the writer
         * before the value reuses that buffer: the writer copies what it is given,
         * so the two strings never share live scratch. */
        if (wt_qpack_huffman_encoded_size(line->name, line->name_length, &needed) != WT_OK) {
          return WT_ERR_LIMIT;
        }
        if (needed > scratch_capacity) return WT_ERR_LIMIT;
        if (wt_qpack_huffman_encode(line->name, line->name_length, scratch, scratch_capacity,
                                    &coded_length) != WT_OK) {
          return WT_ERR_LIMIT;
        }
        flags |= 0x08U;
        if (wt_qpack_integer_encode(w, 3U, flags, (uint64_t)coded_length) != WT_OK) {
          return WT_ERR_LIMIT;
        }
        if (coded_length != 0U) wt_writer_bytes(w, scratch, coded_length);
        if (!wt_writer_ok(w)) return WT_ERR_LIMIT;
        return wt_qpack_string_encode_coded(w, line->value, line->value_length,
                                            line->value_huffman, scratch, scratch_capacity);
      }
      if (wt_qpack_integer_encode(w, 3U, flags, (uint64_t)name_wire_length) != WT_OK) {
        return WT_ERR_LIMIT;
      }
      if (name_wire_length != 0U) wt_writer_bytes(w, name_wire, name_wire_length);
      if (!wt_writer_ok(w)) return WT_ERR_LIMIT;
      return wt_qpack_string_encode_coded(w, line->value, line->value_length, line->value_huffman,
                                          scratch, scratch_capacity);
    }
    case WT_QPACK_FIELD_POST_BASE_INDEX:
      return wt_qpack_integer_encode(w, 4U, 0x10U, line->index);
    case WT_QPACK_FIELD_POST_BASE_NAME_REF: {
      uint8_t flags = line->never_indexed ? 0x08U : 0x00U;
      if (wt_qpack_integer_encode(w, 3U, flags, line->index) != WT_OK) return WT_ERR_LIMIT;
      return wt_qpack_string_encode_coded(w, line->value, line->value_length, line->value_huffman,
                                          scratch, scratch_capacity);
    }
  }
  /* Not reachable: the switch covers every kind the enum has. */
  return WT_ERR_INVALID_ARGUMENT;
}

wt_status_t wt_qpack_field_line_encode(wt_writer_t *w, const wt_qpack_field_line_t *line) {
  /* No scratch, so the coded forms are the `_coded` variant's. A line that asks for
   * one is refused HERE rather than written plainly: the flags are part of the
   * representation, and a plain string with the H bit clear is a different line. */
  if (line != NULL && (line->name_huffman || line->value_huffman)) return WT_ERR_STATE;
  return wt_qpack_field_line_encode_coded(w, line, NULL, 0U);
}

wt_status_t wt_qpack_field_line_static_name(const wt_qpack_field_line_t *line, const char **out_name,
                                            size_t *out_length) {
  wt_qpack_static_entry_t entry;

  if (line == NULL || out_name == NULL || out_length == NULL) return WT_ERR_INVALID_ARGUMENT;

  if (line->kind == WT_QPACK_FIELD_LITERAL_LITERAL_NAME) {
    *out_name = (const char *)line->name;
    *out_length = line->name_length;
    return WT_OK;
  }
  if (line->kind == WT_QPACK_FIELD_INDEXED_STATIC ||
      line->kind == WT_QPACK_FIELD_LITERAL_NAME_REF_STATIC) {
    if (wt_qpack_static_entry(line->index, &entry) != WT_OK) return WT_ERR_PROTOCOL;
    *out_name = entry.name;
    *out_length = entry.name_length;
    return WT_OK;
  }
  /* A dynamic index needs the dynamic table, and a post-base one needs the header
   * block's base: neither is this function's to guess. */
  return WT_ERR_STATE;
}
