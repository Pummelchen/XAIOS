/* WebTransport stream and datagram framing (draft-ietf-webtrans-http3-16 sections 4.2
 * and 4.3). */

#include "webtransport/webtransport/framing.h"

#include "webtransport/quic/varint.h"

int wt_webtransport_is_session_stream_id(uint64_t stream_id) {
  /* RFC 9000 section 2.1: the low bit selects the initiator (0 is the client) and the
   * next selects the directionality (0 is bidirectional). A session ID is the CONNECT
   * stream's, so it is client-initiated and bidirectional -- both bits clear. */
  return (stream_id & (uint64_t)0x03U) == 0U;
}

uint64_t wt_webtransport_session_id_from_quarter(uint64_t quarter_stream_id) {
  return quarter_stream_id * 4U;
}

uint64_t wt_webtransport_quarter_stream_id(uint64_t session_id) {
  return session_id / 4U;
}

wt_status_t wt_webtransport_stream_prefix_write(wt_writer_t *w, int unidirectional,
                                                uint64_t session_id) {
  if (w == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* A prefix can only name a session, so a caller asking for another ID has a bug
   * rather than a peer. */
  if (!wt_webtransport_is_session_stream_id(session_id)) return WT_ERR_INVALID_ARGUMENT;
  (void)wt_quic_writer_varint(w,
                              unidirectional ? WT_WEBTRANSPORT_STREAM_UNI : WT_WEBTRANSPORT_STREAM_BIDI);
  (void)wt_quic_writer_varint(w, session_id);
  return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
}

wt_status_t wt_webtransport_stream_prefix_parse(wt_cursor_t *c, int *out_unidirectional,
                                                uint64_t *out_session_id,
                                                wt_http3_error_t *out_error) {
  uint64_t type;
  uint64_t session_id;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (c == NULL || out_session_id == NULL) return WT_ERR_INVALID_ARGUMENT;

  /* A prefix whose bytes have not all arrived is INCOMPLETE, not malformed: a stream
   * delivers in pieces, exactly as the capsules and QPACK's instructions do. */
  if (wt_quic_varint_decode(c, &type) != WT_OK) return WT_ERR_TRUNCATED;
  if (type != WT_WEBTRANSPORT_STREAM_BIDI && type != WT_WEBTRANSPORT_STREAM_UNI) {
    if (out_error != NULL) *out_error = WT_HTTP3_FRAME_UNEXPECTED;
    return WT_ERR_PROTOCOL;
  }
  if (wt_quic_varint_decode(c, &session_id) != WT_OK) return WT_ERR_TRUNCATED;
  if (!wt_webtransport_is_session_stream_id(session_id)) {
    /* A session that cannot exist: the ID does not have the shape the CONNECT stream's
     * must have, so this prefix is describing nothing. */
    if (out_error != NULL) *out_error = WT_HTTP3_ID_ERROR;
    return WT_ERR_PROTOCOL;
  }
  if (out_unidirectional != NULL) {
    *out_unidirectional = type == WT_WEBTRANSPORT_STREAM_UNI ? 1 : 0;
  }
  *out_session_id = session_id;
  return WT_OK;
}

wt_status_t wt_webtransport_datagram_write(wt_writer_t *w, uint64_t quarter_stream_id,
                                           const uint8_t *payload, size_t length) {
  if (w == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (payload == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (quarter_stream_id > WT_QUIC_VARINT_MAX) return WT_ERR_INVALID_ARGUMENT;

  (void)wt_quic_writer_varint(w, quarter_stream_id);
  if (length != 0U) wt_writer_bytes(w, payload, length);
  return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
}

wt_status_t wt_webtransport_datagram_parse(const uint8_t *data, size_t length,
                                           uint64_t *out_quarter_stream_id,
                                           const uint8_t **out_payload, size_t *out_payload_length,
                                           wt_http3_error_t *out_error) {
  wt_cursor_t c;
  uint64_t quarter;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (data == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;

  c = wt_cursor_init(data, length);
  if (wt_quic_varint_decode(&c, &quarter) != WT_OK) {
    /* A datagram is a whole unit, so one that does not hold its quarter ID is
     * malformed rather than early -- and the draft names the code for exactly this: H3_DATAGRAM_ERROR. The first
     * version reported H3_MESSAGE_ERROR, which is the code for a field section's problem, so a peer was told the
     * wrong rule. */
    if (out_error != NULL) *out_error = WT_HTTP3_DATAGRAM_ERROR;
    return WT_ERR_PROTOCOL;
  }
  /* And a quarter ID whose session would not fit is the same class of error, refused here rather than handed on:
   * `wt_webtransport_session_id_from_quarter` multiplies by four, and a peer-supplied value above
   * `UINT64_MAX / 4` wraps to an ID that can name a REAL session -- an audit fed quarter 2^62 and got session 0.
   * Checked at the parse boundary because this is where a peer's number enters the library. */
  if (quarter > UINT64_MAX / 4U) {
    if (out_error != NULL) *out_error = WT_HTTP3_DATAGRAM_ERROR;
    return WT_ERR_PROTOCOL;
  }
  if (out_quarter_stream_id != NULL) *out_quarter_stream_id = quarter;
  /* The payload is what is LEFT after the quarter ID, so it is taken as a view rather
   * than as a read: the cursor's remaining region is the session data, whatever its
   * length. */
  if (out_payload_length != NULL) *out_payload_length = wt_cursor_remaining(&c);
  if (out_payload != NULL) {
    size_t available = 0U;
    *out_payload = wt_cursor_rest(&c, &available);
  }
  return WT_OK;
}
