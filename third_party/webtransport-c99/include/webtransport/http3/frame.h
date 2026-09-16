/* HTTP/3 frames and stream type prefixes (RFC 9114 sections 6, 7.2 and 11.2.1).
 *
 * HTTP/3 carries everything as a varint type, a varint length and that many
 * bytes of payload. That is the whole wire format: what a frame MEANS is the
 * stream layer's business (a SETTINGS frame's identifiers are parsed there, a
 * GOAWAY's identifier too), and keeping the codec this narrow is what lets one
 * implementation of "is this frame well formed" be reused by every stream type.
 *
 * Two bounds apply, and neither is a limit this module invented:
 *
 *   - a length that does not fit `size_t` cannot describe a frame this program
 *     can hold, so it is refused rather than narrowed;
 *   - a length larger than the bytes actually present is a frame error, not a
 *     request to wait. HTTP/3 has no partial frame: the stream layer assembles
 *     a frame's bytes before it hands them here, and a shorter buffer than the
 *     frame claims is malformed.
 *
 * Frame types that HTTP/2 reserved for itself (`0x1f * N + 0x21`) are recognised
 * by `wt_http3_frame_type_is_reserved` so the layer that owns the rule can raise
 * H3_FRAME_UNEXPECTED for them (section 7.2.8); the codec parses them like any
 * other unknown type, because a codec that refused them would also refuse the
 * frame types HTTP/3 has not defined yet.
 */

#ifndef WEBTRANSPORT_HTTP3_FRAME_H
#define WEBTRANSPORT_HTTP3_FRAME_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/cursor.h"
#include "webtransport/status.h"
#include "webtransport/writer.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The frame types RFC 9114 section 11.2.1 registers. */
#define WT_HTTP3_FRAME_DATA ((uint64_t)0x00)
#define WT_HTTP3_FRAME_HEADERS ((uint64_t)0x01)
#define WT_HTTP3_FRAME_CANCEL_PUSH ((uint64_t)0x03)
#define WT_HTTP3_FRAME_SETTINGS ((uint64_t)0x04)
#define WT_HTTP3_FRAME_PUSH_PROMISE ((uint64_t)0x05)
#define WT_HTTP3_FRAME_GOAWAY ((uint64_t)0x07)
#define WT_HTTP3_FRAME_MAX_PUSH_ID ((uint64_t)0x0d)

/* The stream types of section 6.2.1: the first varint on a stream says what the
 * stream is for. */
#define WT_HTTP3_STREAM_CONTROL ((uint64_t)0x00)
#define WT_HTTP3_STREAM_PUSH ((uint64_t)0x01)
#define WT_HTTP3_STREAM_QPACK_ENCODER ((uint64_t)0x02)
#define WT_HTTP3_STREAM_QPACK_DECODER ((uint64_t)0x03)

/* The error codes of section 8.1, which travel in a QUIC CONNECTION_CLOSE. */
typedef enum wt_http3_error {
  WT_HTTP3_NO_ERROR = 0x0100,
  WT_HTTP3_GENERAL_PROTOCOL_ERROR = 0x0101,
  WT_HTTP3_INTERNAL_ERROR = 0x0102,
  WT_HTTP3_STREAM_CREATION_ERROR = 0x0103,
  WT_HTTP3_CLOSED_CRITICAL_STREAM = 0x0104,
  WT_HTTP3_FRAME_UNEXPECTED = 0x0105,
  WT_HTTP3_FRAME_ERROR = 0x0106,
  WT_HTTP3_EXCESSIVE_LOAD = 0x0107,
  WT_HTTP3_ID_ERROR = 0x0108,
  WT_HTTP3_SETTINGS_ERROR = 0x0109,
  WT_HTTP3_MISSING_SETTINGS = 0x010a,
  WT_HTTP3_REQUEST_REJECTED = 0x010b,
  WT_HTTP3_REQUEST_CANCELLED = 0x010c,
  WT_HTTP3_REQUEST_INCOMPLETE = 0x010d,
  WT_HTTP3_MESSAGE_ERROR = 0x010e,
  WT_HTTP3_CONNECT_ERROR = 0x010f,
  WT_HTTP3_VERSION_FALLBACK = 0x0110,
  /* NOT from RFC 9114: this is the WebTransport draft's own code, defined for a DATAGRAM whose quarter stream ID
   * is malformed or names a stream that cannot be a session. It travels in the same connection-close code space,
   * which is why it lives in this enum rather than beside the framing helpers -- the values below 0x0100 are the
   * extension range, and this is one. An audit found the framing layer reporting a malformed datagram prefix as
   * H3_MESSAGE_ERROR, which names the wrong rule. */
  WT_HTTP3_DATAGRAM_ERROR = 0x33
} wt_http3_error_t;

/* One frame, as it is on the wire: a type and a view of the payload the caller
 * owns. The codec never copies and never allocates. */
typedef struct wt_http3_frame {
  uint64_t type;
  const uint8_t *payload;
  size_t length;
} wt_http3_frame_t;

/* A frame with no payload. */
wt_http3_frame_t wt_http3_frame_make(uint64_t type);

/* A name for diagnostics, or "unknown". Never NULL, so a log line can use it
 * without a branch, and never a peer-supplied string. */
const char *wt_http3_frame_type_name(uint64_t type);

/* True for the types HTTP/2 reserved for itself: 0x1f * N + 0x21 (section
 * 7.2.8). Receiving one is H3_FRAME_UNEXPECTED, which the stream layer raises;
 * this exists so the rule is stated once. */
int wt_http3_frame_type_is_reserved(uint64_t type);

/* The OTHER reserved family (RFC 9114 section 7.2.8): `0x1f * N + 0x21` are reserved to exercise the rule that
 * unknown types are ignored. A peer MAY send one as padding and this endpoint MUST NOT give it meaning -- so the
 * answer here is IGNORE, and a caller that refused one would refuse a conforming peer. Kept as its own predicate
 * because "reserved" names two rules with opposite outcomes, which is exactly the confusion that had this file
 * refusing the legal family and accepting the forbidden one. */
int wt_http3_frame_type_is_exerciser(uint64_t type);

/* Write one frame. Refuses a type or payload length outside the varint range and
 * a null payload with a non-zero length. */
wt_status_t wt_http3_frame_encode(wt_writer_t *w, const wt_http3_frame_t *frame);

/* The bytes one frame occupies, without writing it. */
wt_status_t wt_http3_frame_encoded_size(const wt_http3_frame_t *frame, size_t *out_size);

/* Read one frame from a cursor, advancing it past the frame. `out->payload`
 * points into the cursor's buffer and lives as long as it does. `out_error` is
 * set to H3_FRAME_ERROR when the frame's own encoding is what failed. */
wt_status_t wt_http3_frame_decode(wt_cursor_t *c, wt_http3_frame_t *out,
                                  wt_http3_error_t *out_error);

/* Read one frame from the front of `data`, reporting how many bytes it used, so
 * a caller holding a complete frame's bytes can hand back the rest. */
wt_status_t wt_http3_frame_decode_prefix(const uint8_t *data, size_t length,
                                         wt_http3_frame_t *out, size_t *out_consumed,
                                         wt_http3_error_t *out_error);

/* Read a stream's type prefix (section 6.2.1), leaving the cursor after it. A
 * truncated varint is H3_STREAM_CREATION_ERROR, because the stream's type has to
 * be there before anything else is. */
wt_status_t wt_http3_stream_type_read(wt_cursor_t *c, uint64_t *out_type,
                                      wt_http3_error_t *out_error);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_HTTP3_FRAME_H */
