/* QPACK's decoder stream instructions (RFC 9204 section 4.4). */

#include "webtransport/http3/qpack.h"

void wt_qpack_decoder_stream_init(wt_qpack_decoder_stream_t *stream) {
  if (stream == NULL) return;
  stream->acknowledged_insert_count = 0U;
  stream->sections_acknowledged = 0U;
  stream->streams_cancelled = 0U;
}

wt_status_t wt_qpack_decoder_stream_apply(wt_qpack_decoder_stream_t *stream,
                                          const wt_qpack_dynamic_table_t *table, wt_cursor_t *c,
                                          wt_qpack_error_t *out_error) {
  uint8_t first;
  size_t available = 0U;
  const uint8_t *rest;

  if (out_error != NULL) *out_error = WT_QPACK_ERROR_NONE;
  if (stream == NULL || c == NULL) return WT_ERR_INVALID_ARGUMENT;

  rest = wt_cursor_rest(c, &available);
  if (rest == NULL || available == 0U) {
    if (out_error != NULL) *out_error = WT_QPACK_ERROR_DECODER_STREAM;
    return WT_ERR_TRUNCATED;
  }
  first = rest[0];

  if ((first & 0x80U) != 0U) {
    /* 1 SectionID(7+): this field section has been decoded. */
    uint64_t section_id;
    {
      wt_status_t status = wt_qpack_integer_decode(c, 7U, &section_id);
      /* An instruction whose bytes have not all arrived is INCOMPLETE, not
       * malformed: a QPACK stream may deliver it in pieces (RFC 9204 section 2.2),
       * so the caller waits for more. Only a malformed integer -- one past the
       * 62-bit bound -- is the peer's error. */
      if (status == WT_ERR_TRUNCATED) return WT_ERR_TRUNCATED;
      if (status != WT_OK) {
        if (out_error != NULL) *out_error = WT_QPACK_ERROR_DECODER_STREAM;
        return WT_ERR_PROTOCOL;
      }
    }
    (void)section_id;
    stream->sections_acknowledged++;
    return WT_OK;
  }

  if ((first & 0x40U) != 0U) {
    /* 01 StreamID(6+): the decoder will not decode more on that stream. */
    uint64_t stream_id;
    {
      wt_status_t status = wt_qpack_integer_decode(c, 6U, &stream_id);
      if (status == WT_ERR_TRUNCATED) return WT_ERR_TRUNCATED;
      if (status != WT_OK) {
        if (out_error != NULL) *out_error = WT_QPACK_ERROR_DECODER_STREAM;
        return WT_ERR_PROTOCOL;
      }
    }
    (void)stream_id;
    stream->streams_cancelled++;
    return WT_OK;
  }

  /* 00 Increment(6+): this many insertions have been processed. */
  {
    uint64_t increment;
    {
      wt_status_t status = wt_qpack_integer_decode(c, 6U, &increment);
      if (status == WT_ERR_TRUNCATED) return WT_ERR_TRUNCATED;
      if (status != WT_OK) {
        if (out_error != NULL) *out_error = WT_QPACK_ERROR_DECODER_STREAM;
        return WT_ERR_PROTOCOL;
      }
    }
    /* Section 4.4.3: "An encoder that receives an Increment field equal to zero
     * ... MUST treat this as a connection error of type QPACK_DECODER_STREAM_ERROR."
     * Zero is not a no-op: it is an instruction that says nothing, and accepting it
     * would hide a decoder that is confused about what it has processed. */
    if (increment == 0U) {
      if (out_error != NULL) *out_error = WT_QPACK_ERROR_DECODER_STREAM;
      return WT_ERR_PROTOCOL;
    }
    /* And the sum may not pass what was inserted: a decoder cannot have processed
     * more insertions than the encoder made. */
    if (stream->acknowledged_insert_count > UINT64_MAX - increment) {
      if (out_error != NULL) *out_error = WT_QPACK_ERROR_DECODER_STREAM;
      return WT_ERR_PROTOCOL;
    }
    if (table != NULL && stream->acknowledged_insert_count + increment > table->insert_count) {
      if (out_error != NULL) *out_error = WT_QPACK_ERROR_DECODER_STREAM;
      return WT_ERR_PROTOCOL;
    }
    stream->acknowledged_insert_count += increment;
    return WT_OK;
  }
}

wt_status_t wt_qpack_decoder_stream_write_section_acknowledgement(wt_writer_t *w,
                                                                 uint64_t section_id) {
  if (w == NULL) return WT_ERR_INVALID_ARGUMENT;
  return wt_qpack_integer_encode(w, 7U, 0x80U, section_id);
}

wt_status_t wt_qpack_decoder_stream_write_stream_cancellation(wt_writer_t *w, uint64_t stream_id) {
  if (w == NULL) return WT_ERR_INVALID_ARGUMENT;
  return wt_qpack_integer_encode(w, 6U, 0x40U, stream_id);
}

wt_status_t wt_qpack_decoder_stream_write_insert_count_increment(wt_writer_t *w,
                                                                uint64_t increment) {
  if (w == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* Refused at the writer too, so this build cannot produce the instruction its
   * own reader refuses. */
  if (increment == 0U) return WT_ERR_INVALID_ARGUMENT;
  return wt_qpack_integer_encode(w, 6U, 0x00U, increment);
}
