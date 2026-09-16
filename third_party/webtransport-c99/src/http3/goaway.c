/* The HTTP/3 GOAWAY frame. See webtransport/http3/goaway.h. */

#include "webtransport/http3/goaway.h"

#include "webtransport/quic/varint.h"

void wt_http3_goaway_init(wt_http3_goaway_t *goaway) {
  if (goaway == NULL) return;
  goaway->received = 0;
  goaway->identifier = 0U;
  goaway->sender = WT_HTTP3_ROLE_SERVER;
}

uint64_t wt_http3_goaway_maximum_identifier(wt_http3_role_t sender) {
  /* RFC 9114 section 5.2: "An endpoint that is attempting to gracefully shut down
   * a connection can send a GOAWAY frame with a value set to the maximum possible
   * value (2^62-4 for servers, 2^62-1 for clients)." The server's maximum is the
   * largest client-initiated bidirectional stream ID, which is what a server's
   * GOAWAY identifier has to be. */
  return sender == WT_HTTP3_ROLE_SERVER ? WT_HTTP3_GOAWAY_SERVER_MAXIMUM
                                        : WT_HTTP3_GOAWAY_CLIENT_MAXIMUM;
}

wt_status_t wt_http3_goaway_encode_payload(wt_writer_t *w, uint64_t identifier) {
  if (w == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (identifier > WT_QUIC_VARINT_MAX) return WT_ERR_INVALID_ARGUMENT;
  (void)wt_quic_writer_varint(w, identifier);
  return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
}

wt_status_t wt_http3_goaway_decode_payload(const uint8_t *payload, size_t length,
                                           uint64_t *out_identifier, wt_http3_error_t *out_error) {
  wt_cursor_t c;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (out_identifier == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (payload == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;

  c = wt_cursor_init(payload, length);
  if (wt_quic_varint_decode(&c, out_identifier) != WT_OK) {
    /* The payload is one field; a payload that does not hold it is a malformed
     * frame rather than a frame to wait for (section 7.2.6's format). */
    if (out_error != NULL) *out_error = WT_HTTP3_FRAME_ERROR;
    return WT_ERR_TRUNCATED;
  }
  if (!wt_cursor_at_end(&c)) {
    /* And a second field, or trailing bytes, is malformed too: reading the first
     * varint and ignoring the rest would accept a frame this implementation
     * cannot interpret. */
    if (out_error != NULL) *out_error = WT_HTTP3_FRAME_ERROR;
    return WT_ERR_PROTOCOL;
  }
  return WT_OK;
}

wt_status_t wt_http3_goaway_on_received(wt_http3_goaway_t *goaway, wt_http3_role_t sender,
                                        uint64_t identifier, wt_http3_error_t *out_error) {
  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (goaway == NULL) return WT_ERR_INVALID_ARGUMENT;

  /* RFC 9114 section 7.2.6: in the server-to-client direction the identifier is a
   * client-initiated bidirectional stream ID, and "A client MUST treat receipt of
   * a GOAWAY frame containing a stream ID of any other type as a connection error
   * of type H3_ID_ERROR." RFC 9000 section 2.1 puts the initiator in the low bit
   * (0 = client) and the directionality in the next (0 = bidirectional), so the
   * two together are zero exactly for the stream type this identifier must be. */
  if (sender == WT_HTTP3_ROLE_SERVER && (identifier & (uint64_t)0x03) != 0U) {
    if (out_error != NULL) *out_error = WT_HTTP3_ID_ERROR;
    return WT_ERR_PROTOCOL;
  }

  /* RFC 9114 section 5.2: "the identifier in each frame MUST NOT be greater than
   * the identifier in any previous frame ... Receiving a GOAWAY containing a
   * larger identifier than previously received MUST be treated as a connection
   * error of type H3_ID_ERROR." A lower one is the ordinary graceful shutdown:
   * the maximum first, then what was really processed. */
  if (goaway->received && identifier > goaway->identifier) {
    if (out_error != NULL) *out_error = WT_HTTP3_ID_ERROR;
    return WT_ERR_PROTOCOL;
  }

  goaway->received = 1;
  goaway->identifier = identifier;
  goaway->sender = sender;
  return WT_OK;
}

int wt_http3_goaway_rejects_stream(const wt_http3_goaway_t *goaway, uint64_t stream_id) {
  if (goaway == NULL || !goaway->received) return 0;
  /* Section 5.2: "Requests or pushes with the indicated identifier or greater are
   * rejected ... by the sender of the GOAWAY." */
  return stream_id >= goaway->identifier;
}

int wt_http3_goaway_allows_new_requests(const wt_http3_goaway_t *goaway) {
  if (goaway == NULL) return 1;
  /* Section 5.2: "Endpoints MUST NOT initiate new requests or promise new pushes
   * on the connection after receipt of a GOAWAY frame from the peer." */
  return !goaway->received;
}
