/* QPACK's encoder stream instructions (RFC 9204 section 4.3). */

#include "webtransport/http3/qpack.h"

void wt_qpack_encoder_stream_init(wt_qpack_encoder_stream_t *stream,
                                  wt_qpack_dynamic_table_t *table, size_t max_capacity) {
  if (stream == NULL) return;
  stream->table = table;
  stream->max_capacity = max_capacity;
}

/* A relative index counts entries inserted after the one it names (section 3.2.3),
 * so it resolves against the CURRENT insert count. Anything outside the live range
 * is an instruction the encoder could not have meant. */
static wt_status_t resolve_relative(const wt_qpack_dynamic_table_t *table, uint64_t relative,
                                    uint64_t *out_absolute) {
  if (table == NULL) return WT_ERR_STATE;
  if (relative >= table->insert_count) return WT_ERR_CLOSED;
  *out_absolute = table->insert_count - 1U - relative;
  if (*out_absolute < table->dropped) return WT_ERR_CLOSED;
  return WT_OK;
}

/* Apply an insertion the peer's encoder stream asked for.
 *
 * Every failure has to be REPORTED rather than returned raw: the cursor has already consumed the instruction, so
 * carrying on would leave this endpoint's insert count -- and therefore every absolute index it can be asked to
 * resolve -- out of step with the peer's, silently. An audit watched the 33rd insert be consumed and vanish
 * (`status=9`, no error code, `insert_count` still 32), which is a table that diverges in silence; RFC 9204
 * section 3.2.2 makes it QPACK_ENCODER_STREAM_ERROR. A failure caused by this endpoint's own table bound keeps
 * that code too, because the peer must be told to stop rather than left believing the entry is there. */
static wt_status_t apply_insert(wt_qpack_encoder_stream_t *stream, const uint8_t *name,
                                size_t name_length, const uint8_t *value, size_t value_length,
                                wt_qpack_error_t *out_error) {
  wt_status_t status =
      wt_qpack_dynamic_insert(stream->table, name, name_length, value, value_length, NULL);

  if (status == WT_OK) return WT_OK;
  if (out_error != NULL) *out_error = WT_QPACK_ERROR_ENCODER_STREAM;
  /* A bound is still a bound: the caller gets WT_ERR_LIMIT for one this endpoint owns and WT_ERR_PROTOCOL for an
   * instruction that could never have been applied. Both carry the code above. */
  return status == WT_ERR_LIMIT ? WT_ERR_LIMIT : WT_ERR_PROTOCOL;
}

wt_status_t wt_qpack_encoder_stream_apply(wt_qpack_encoder_stream_t *stream, wt_cursor_t *c,
                                          wt_qpack_error_t *out_error) {
  uint8_t first;
  size_t available = 0U;
  const uint8_t *rest;

  if (out_error != NULL) *out_error = WT_QPACK_ERROR_NONE;
  if (stream == NULL || c == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (stream->table == NULL) return WT_ERR_STATE;

  rest = wt_cursor_rest(c, &available);
  if (rest == NULL || available == 0U) {
    if (out_error != NULL) *out_error = WT_QPACK_ERROR_ENCODER_STREAM;
    return WT_ERR_TRUNCATED;
  }
  first = rest[0];

  if ((first & 0x80U) != 0U) {
    /* 1 T Index(6+) then a value: an insertion whose name comes from a table. */
    uint64_t index;
    const uint8_t *value = NULL;
    size_t value_length = 0U;
    int value_huffman = 0;
    const wt_qpack_static_entry_t *unused = NULL;
    wt_qpack_static_entry_t entry;

    (void)unused;
    {
      wt_status_t status = wt_qpack_integer_decode(c, 6U, &index);
      if (status == WT_ERR_TRUNCATED) return WT_ERR_TRUNCATED;
      if (status != WT_OK) {
        if (out_error != NULL) *out_error = WT_QPACK_ERROR_ENCODER_STREAM;
        return WT_ERR_PROTOCOL;
      }
    }
    {
      /* A string whose bytes have not all arrived is INCOMPLETE, not malformed: a
       * QPACK stream delivers instructions in pieces (RFC 9204 section 2.2), so the
       * caller waits for more and only a malformed instruction is the peer's error. */
      wt_status_t status = wt_qpack_string_decode(c, &value, &value_length, &value_huffman);
      if (status == WT_ERR_TRUNCATED) return WT_ERR_TRUNCATED;
      if (status != WT_OK) {
        if (out_error != NULL) *out_error = WT_QPACK_ERROR_ENCODER_STREAM;
        return WT_ERR_PROTOCOL;
      }
    }
    if (value_huffman) {
      /* The name may be Huffman-coded and so may the value; the encoder stream
       * stores DECODED bytes, so this build refuses a coded value until the
       * dynamic table's values are decoded on the way in. Recorded as the next
       * part's work rather than decoded here with a buffer this function does not
       * have. */
      if (out_error != NULL) *out_error = WT_QPACK_ERROR_ENCODER_STREAM;
      return WT_ERR_STATE;
    }
    if ((first & 0x40U) != 0U) {
      if (wt_qpack_static_entry(index, &entry) != WT_OK) {
        if (out_error != NULL) *out_error = WT_QPACK_ERROR_ENCODER_STREAM;
        return WT_ERR_PROTOCOL;
      }
      return apply_insert(stream, (const uint8_t *)entry.name, entry.name_length, value,
                          value_length, out_error);
    }
    {
      uint64_t absolute = 0U;
      const uint8_t *name = NULL;
      const uint8_t *stored_value = NULL;
      size_t name_length = 0U;
      size_t stored_length = 0U;

      if (resolve_relative(stream->table, index, &absolute) != WT_OK) {
        if (out_error != NULL) *out_error = WT_QPACK_ERROR_ENCODER_STREAM;
        return WT_ERR_PROTOCOL;
      }
      if (wt_qpack_dynamic_entry(stream->table, absolute, &name, &name_length, &stored_value,
                                 &stored_length) != WT_OK) {
        if (out_error != NULL) *out_error = WT_QPACK_ERROR_ENCODER_STREAM;
        return WT_ERR_PROTOCOL;
      }
      (void)stored_value;
      (void)stored_length;
      return apply_insert(stream, name, name_length, value, value_length, out_error);
    }
  }

  if ((first & 0x40U) != 0U) {
    /* 01 H NameLen(5+) then the name and the value: both written out. */
    uint64_t name_length;
    int name_huffman = (first & 0x20U) != 0U;
    const uint8_t *name;
    const uint8_t *value = NULL;
    size_t value_length = 0U;
    int value_huffman = 0;

    {
      wt_status_t status = wt_qpack_integer_decode(c, 5U, &name_length);
      if (status == WT_ERR_TRUNCATED) return WT_ERR_TRUNCATED;
      if (status != WT_OK) {
        if (out_error != NULL) *out_error = WT_QPACK_ERROR_ENCODER_STREAM;
        return WT_ERR_PROTOCOL;
      }
    }
    if (name_length > (uint64_t)SIZE_MAX) {
      if (out_error != NULL) *out_error = WT_QPACK_ERROR_ENCODER_STREAM;
      return WT_ERR_LIMIT;
    }
    name = wt_cursor_bytes(c, (size_t)name_length);
    if (name == NULL && name_length != 0U) return WT_ERR_TRUNCATED;
    {
      wt_status_t status = wt_qpack_string_decode(c, &value, &value_length, &value_huffman);
      if (status == WT_ERR_TRUNCATED) return WT_ERR_TRUNCATED;
      if (status != WT_OK) {
        if (out_error != NULL) *out_error = WT_QPACK_ERROR_ENCODER_STREAM;
        return WT_ERR_PROTOCOL;
      }
    }
    if (name_huffman || value_huffman) {
      if (out_error != NULL) *out_error = WT_QPACK_ERROR_ENCODER_STREAM;
      return WT_ERR_STATE;
    }
    return apply_insert(stream, name, (size_t)name_length, value, value_length, out_error);
  }

  if ((first & 0x20U) != 0U) {
    /* 001xxxxx: the table's capacity. */
    uint64_t capacity;
    {
      wt_status_t status = wt_qpack_integer_decode(c, 5U, &capacity);
      if (status == WT_ERR_TRUNCATED) return WT_ERR_TRUNCATED;
      if (status != WT_OK) {
        if (out_error != NULL) *out_error = WT_QPACK_ERROR_ENCODER_STREAM;
        return WT_ERR_PROTOCOL;
      }
    }
    if (capacity > (uint64_t)stream->max_capacity) {
      /* Section 4.3.1: a capacity above what this endpoint advertised is an error,
       * because a peer may not use more than it was granted. */
      if (out_error != NULL) *out_error = WT_QPACK_ERROR_ENCODER_STREAM;
      return WT_ERR_PROTOCOL;
    }
    wt_qpack_dynamic_set_capacity(stream->table, (size_t)capacity);
    return WT_OK;
  }

  /* 000 Index(5+): duplicate an entry at the end of the table. */
  {
    uint64_t relative;
    uint64_t absolute = 0U;
    const uint8_t *name = NULL;
    const uint8_t *value = NULL;
    size_t name_length = 0U;
    size_t value_length = 0U;

    {
      wt_status_t status = wt_qpack_integer_decode(c, 5U, &relative);
      if (status == WT_ERR_TRUNCATED) return WT_ERR_TRUNCATED;
      if (status != WT_OK) {
        if (out_error != NULL) *out_error = WT_QPACK_ERROR_ENCODER_STREAM;
        return WT_ERR_PROTOCOL;
      }
    }
    if (resolve_relative(stream->table, relative, &absolute) != WT_OK) {
      if (out_error != NULL) *out_error = WT_QPACK_ERROR_ENCODER_STREAM;
      return WT_ERR_PROTOCOL;
    }
    if (wt_qpack_dynamic_entry(stream->table, absolute, &name, &name_length, &value, &value_length) !=
        WT_OK) {
      if (out_error != NULL) *out_error = WT_QPACK_ERROR_ENCODER_STREAM;
      return WT_ERR_PROTOCOL;
    }
    return apply_insert(stream, name, name_length, value, value_length, out_error);
  }
}

wt_status_t wt_qpack_encoder_stream_write_capacity(wt_writer_t *w, size_t capacity) {
  if (w == NULL) return WT_ERR_INVALID_ARGUMENT;
  return wt_qpack_integer_encode(w, 5U, 0x20U, (uint64_t)capacity);
}

wt_status_t wt_qpack_encoder_stream_write_insert_name_reference(wt_writer_t *w, int from_static,
                                                               uint64_t index, const uint8_t *value,
                                                               size_t value_length) {
  if (w == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (wt_qpack_integer_encode(w, 6U, from_static ? 0xc0U : 0x80U, index) != WT_OK) {
    return WT_ERR_LIMIT;
  }
  return wt_qpack_string_encode(w, value, value_length);
}

wt_status_t wt_qpack_encoder_stream_write_insert_literal(wt_writer_t *w, const uint8_t *name,
                                                        size_t name_length, const uint8_t *value,
                                                        size_t value_length) {
  if (w == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (name == NULL && name_length != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (wt_qpack_integer_encode(w, 5U, 0x40U, (uint64_t)name_length) != WT_OK) return WT_ERR_LIMIT;
  if (name_length != 0U) wt_writer_bytes(w, name, name_length);
  if (!wt_writer_ok(w)) return WT_ERR_LIMIT;
  return wt_qpack_string_encode(w, value, value_length);
}

wt_status_t wt_qpack_encoder_stream_write_duplicate(wt_writer_t *w, uint64_t relative_index) {
  if (w == NULL) return WT_ERR_INVALID_ARGUMENT;
  return wt_qpack_integer_encode(w, 5U, 0x00U, relative_index);
}
