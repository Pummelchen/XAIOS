/* How a WebTransport session's streams and datagrams are framed
 * (draft-ietf-webtrans-http3-16 sections 4.2 and 4.3).
 *
 * A WebTransport stream begins with a stream type and the session it belongs to:
 * 0x41 for a bidirectional stream and 0x54 for a unidirectional one, then the session
 * ID as a varint. The session ID is the CONNECT stream's own ID -- a client-initiated
 * bidirectional stream -- so it must have that shape, and a prefix naming anything else
 * is a peer describing a session that cannot exist.
 *
 * A datagram carries a QUARTER stream ID (the CONNECT stream's ID divided by four,
 * because the low two bits of a stream ID are constant for a class of stream) followed
 * by the session data. The quarter ID is what a receiver multiplies back out, and a
 * datagram too short to hold it carries no session to deliver to.
 */

#ifndef WEBTRANSPORT_WEBTRANSPORT_FRAMING_H
#define WEBTRANSPORT_WEBTRANSPORT_FRAMING_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/cursor.h"
#include "webtransport/http3/frame.h"
#include "webtransport/status.h"
#include "webtransport/writer.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The stream types the draft gives a WebTransport stream (section 4.2). */
#define WT_WEBTRANSPORT_STREAM_BIDI ((uint64_t)0x41)
#define WT_WEBTRANSPORT_STREAM_UNI ((uint64_t)0x54)

/* True when this stream ID has the shape a session ID must have: client-initiated
 * (its low bit clear) and bidirectional (the next bit clear), which is RFC 9000
 * section 2.1's numbering. */
int wt_webtransport_is_session_stream_id(uint64_t stream_id);

/* The session ID a quarter stream ID names, and the reverse. */
uint64_t wt_webtransport_session_id_from_quarter(uint64_t quarter_stream_id);
uint64_t wt_webtransport_quarter_stream_id(uint64_t session_id);

/* Write a stream's prefix, and read one. `out_unidirectional` says which type it was,
 * which the caller needs because the two carry different rules. A prefix naming a
 * stream ID that is not a session is H3_ID_ERROR, the code the HTTP/3 layer uses for an
 * identifier that cannot be one. */
wt_status_t wt_webtransport_stream_prefix_write(wt_writer_t *w, int unidirectional,
                                                uint64_t session_id);
wt_status_t wt_webtransport_stream_prefix_parse(wt_cursor_t *c, int *out_unidirectional,
                                                uint64_t *out_session_id,
                                                wt_http3_error_t *out_error);

/* Write and read a datagram: the quarter stream ID, then the payload. */
wt_status_t wt_webtransport_datagram_write(wt_writer_t *w, uint64_t quarter_stream_id,
                                           const uint8_t *payload, size_t length);
wt_status_t wt_webtransport_datagram_parse(const uint8_t *data, size_t length,
                                           uint64_t *out_quarter_stream_id,
                                           const uint8_t **out_payload, size_t *out_payload_length,
                                           wt_http3_error_t *out_error);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_WEBTRANSPORT_FRAMING_H */
