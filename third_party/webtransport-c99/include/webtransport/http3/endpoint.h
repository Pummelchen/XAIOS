/* The HTTP/3 endpoint's own streams (Phase 9).
 *
 * Everything below this header is a state machine for one concern: the control stream, the
 * frame rules, QPACK, the request stream. This is the layer that OWNS them for one
 * connection, and its whole job is the lifecycle a consumer never sees:
 *
 *   - our own unidirectional streams, opened once each. The control stream carries the type
 *     prefix `0x00` and then SETTINGS; the QPACK streams carry `0x02` and `0x03`. Sending a
 *     second one of any of them is the caller's error (WT_ERR_STATE), because sections
 *     6.2.1 and 4.2 of QPACK make "one per connection" part of the protocol rather than a
 *     style choice.
 *
 *   - the peer's unidirectional streams, classified by their type prefix. The rules here
 *     are the RFC's and are deliberately asymmetric with the receiving side of a frame
 *     parser: an UNKNOWN type is not an error at all (section 6.2.1 leaves unknown types
 *     for future revisions, and the endpoint simply stops reading that stream), while a
 *     SECOND control stream, a second QPACK stream, or a push stream this endpoint never
 *     asked for commits the connection to an error with the code the RFC names.
 *
 *   - the draft-16 WebTransport unidirectional stream (`0x54`), which is not HTTP/3's to
 *     interpret. It is classified and handed to the layer above; the HTTP/3 core must not
 *     treat it as unknown-and-ignored, or a session's own streams would silently disappear.
 *
 * The peer-stream table is fixed. It is a bound this endpoint published rather than one
 * that grows with a peer's appetite, and running into it is WT_ERR_LIMIT -- this endpoint's
 * own limit -- and not an HTTP/3 error code.
 */

#ifndef WEBTRANSPORT_HTTP3_ENDPOINT_H
#define WEBTRANSPORT_HTTP3_ENDPOINT_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/http3/control.h"
#include "webtransport/http3/frame.h"
#include "webtransport/http3/message.h"
#include "webtransport/http3/request.h"
#include "webtransport/http3/role.h"
#include "webtransport/status.h"
#include "webtransport/writer.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The largest number of peer unidirectional streams one endpoint tracks at once. A
 * connection has three of HTTP/3's own at most, plus the draft's WebTransport streams,
 * which are bounded by the session's own stream table. */
#define WT_HTTP3_ENDPOINT_STREAMS_MAX 32U

/* The largest number of request streams one endpoint tracks at once. A WebTransport
 * session is one request stream, so this is the number of sessions one connection may
 * carry; a client that wants more than its own bound must say so, and a server refuses
 * past what it advertised. */
#define WT_HTTP3_ENDPOINT_REQUESTS_MAX 8U

typedef enum wt_http3_endpoint_stream_kind {
  WT_HTTP3_ENDPOINT_STREAM_CONTROL = 0,
  WT_HTTP3_ENDPOINT_STREAM_PUSH = 1,
  WT_HTTP3_ENDPOINT_STREAM_QPACK_ENCODER = 2,
  WT_HTTP3_ENDPOINT_STREAM_QPACK_DECODER = 3,
  /* The draft-16 WebTransport unidirectional stream (0x54). */
  WT_HTTP3_ENDPOINT_STREAM_WEBTRANSPORT = 4,
  /* A type this build does not know. Section 6.2.1: ignore the stream, do not fail. */
  WT_HTTP3_ENDPOINT_STREAM_UNKNOWN = 5
} wt_http3_endpoint_stream_kind_t;

typedef struct wt_http3_endpoint_stream {
  uint64_t stream_id;
  wt_http3_endpoint_stream_kind_t kind;
  /* The type prefix's wire value, kept so a caller can log what it saw without decoding it
   * again -- and so a test can assert the endpoint classified what was actually sent. */
  uint64_t type;
} wt_http3_endpoint_stream_t;

/* A request stream, with the ordering machine that belongs to it. */
typedef struct wt_http3_endpoint_request {
  uint64_t stream_id;
  /* Whether THIS endpoint opened it, which decides who may send what next: the initiator
   * sends the request, the peer answers with the response. */
  int locally_opened;
  /* Whether the response's HEADERS have arrived. One response per request stream: a second one is not a
   * trailer, it is a peer that lost track of the exchange. */
  int response_seen;
  wt_http3_request_stream_t request;
} wt_http3_endpoint_request_t;

typedef struct wt_http3_endpoint {
  wt_http3_role_t role;
  /* The peer's control stream, with the rules that make a second one an error. */
  wt_http3_control_stream_t peer_control;
  int peer_qpack_encoder_seen;
  int peer_qpack_decoder_seen;
  int peer_webtransport_streams_seen;
  /* Our own streams, sent at most once each. */
  int control_sent;
  int qpack_encoder_sent;
  int qpack_decoder_sent;
  /* The peer's unidirectional streams while they live. */
  wt_http3_endpoint_stream_t streams[WT_HTTP3_ENDPOINT_STREAMS_MAX];
  size_t stream_count;
  /* The request streams while they live, in either direction. */
  wt_http3_endpoint_request_t requests[WT_HTTP3_ENDPOINT_REQUESTS_MAX];
  size_t request_count;
  /* The QPACK DECODER state: the dynamic table the peer's encoder stream fills, and how
   * many insertions have been applied to it. It lives here because a field section cannot
   * be read without it and a connection has exactly one of each. */
  wt_qpack_dynamic_table_t decoder_table;
  uint64_t decoder_insert_count;
  int decoder_capacity_set;
} wt_http3_endpoint_t;

void wt_http3_endpoint_init(wt_http3_endpoint_t *endpoint, wt_http3_role_t role);

/* Write the type prefix of one of OUR unidirectional streams. The caller sends these bytes
 * as the first thing on a newly opened stream. A second call for the same kind is
 * WT_ERR_STATE. The control stream's SETTINGS frame is written by the caller, with
 * `wt_http3_frame_encode` and the SETTINGS encoder, because what this endpoint's settings
 * say is a decision the layer above owns. */
wt_status_t wt_http3_endpoint_write_prefix(wt_http3_endpoint_t *endpoint,
                                           wt_http3_endpoint_stream_kind_t kind, wt_writer_t *w);

/* A peer unidirectional stream's opening bytes: its type prefix, and possibly more. Reads
 * the varint type, classifies the stream, records it, applies the once-only rules, and
 * reports how many bytes the prefix took so the caller continues at the right offset.
 * `out_kind` is always set when the call succeeds, including for UNKNOWN. */
wt_status_t wt_http3_endpoint_on_uni_stream(wt_http3_endpoint_t *endpoint, uint64_t stream_id,
                                            const uint8_t *bytes, size_t length,
                                            size_t *out_consumed,
                                            wt_http3_endpoint_stream_kind_t *out_kind,
                                            wt_http3_error_t *out_error);

/* Write a HEADERS frame carrying a field section, which is how a request, a response and a
 * trailer are sent. The section is encoded into the caller's `scratch` first, because a
 * frame's length prefix is a varint whose width depends on the length: the frame can only be
 * written once the section has been MEASURED, which is the rule this library follows
 * everywhere a length is written. A section that does not fit the scratch is WT_ERR_LIMIT
 * with no error code -- the caller's buffer, not the peer's doing.
 *
 * `peer_max_entries` is the peer's advertised dynamic-table capacity in units of 32, from
 * its SETTINGS; the section's prefix is encoded against that number. Nothing this encoder
 * writes references the dynamic table, so a peer that advertised none can read it. */
wt_status_t wt_http3_endpoint_write_headers(wt_http3_endpoint_t *endpoint,
                                            const wt_http3_message_t *message,
                                            uint64_t peer_max_entries, uint8_t *scratch,
                                            size_t scratch_capacity, wt_writer_t *w,
                                            wt_http3_error_t *out_error);

/* A frame arrived on the peer's control stream: the endpoint forwards it to the control
 * machine, which is where the "SETTINGS first, and only once" rule lives. WT_ERR_STATE when
 * the stream was never opened. */
wt_status_t wt_http3_endpoint_on_control_frame(wt_http3_endpoint_t *endpoint, uint64_t type,
                                               wt_http3_error_t *out_error);

/* A peer unidirectional stream ended. The peer's control stream ending is
 * H3_CLOSED_CRITICAL_STREAM whether or not SETTINGS had arrived; any other stream is
 * simply forgotten. */
wt_status_t wt_http3_endpoint_on_uni_stream_end(wt_http3_endpoint_t *endpoint, uint64_t stream_id,
                                                wt_http3_error_t *out_error);

/* The recorded kind of a peer stream, for a caller routing its data. Returns
 * WT_HTTP3_ENDPOINT_STREAM_UNKNOWN when the stream is not one the endpoint recorded. */
wt_http3_endpoint_stream_kind_t wt_http3_endpoint_stream_kind(
    const wt_http3_endpoint_t *endpoint, uint64_t stream_id);

/* How many peer streams the endpoint is tracking, for a caller that logs occupancy. */
size_t wt_http3_endpoint_stream_count(const wt_http3_endpoint_t *endpoint);

/* ------------------------------------------------ request streams (RFC 9114 section 6.1)

 * A WebTransport session IS a request stream: the client sends an extended CONNECT on a
 * client-initiated bidirectional stream and the server answers on the same one. These four
 * calls are that stream's lifecycle, and the role rules in them are the RFC's rather than
 * this implementation's preferences:
 *
 *   - only a CLIENT opens one. HTTP/3 has no server-initiated request, and section 6.1
 *     makes a client that receives a server-initiated bidirectional stream a connection
 *     error of type H3_STREAM_CREATION_ERROR, so the opening call refuses a server and the
 *     receiving call refuses a client. Refusing here rather than silently tracking either
 *     is what keeps a role mix-up from looking like a protocol error from the peer.
 *
 *   - the request-ordering machine's rules are applied per stream, through
 *     `wt_http3_request_*`, so HEADERS first and H3_REQUEST_INCOMPLETE are decided in one
 *     place and not re-implemented here. */

/* Open a request stream (the client's side). Records it, so its frames have somewhere to
 * be applied. A second call for the same stream, a stream past the table's bound, or a
 * server calling it at all is refused. */
wt_status_t wt_http3_endpoint_open_request(wt_http3_endpoint_t *endpoint, uint64_t stream_id,
                                           wt_http3_error_t *out_error);

/* A peer opened a request stream (the server's side). A client receiving one is
 * H3_STREAM_CREATION_ERROR. */
wt_status_t wt_http3_endpoint_on_request_stream(wt_http3_endpoint_t *endpoint, uint64_t stream_id,
                                                wt_http3_error_t *out_error);

/* A HEADERS frame carrying the RESPONSE on a tracked request stream.
 *
 * It is NOT the request machine's business, and that is the reason this call exists rather than a flag on
 * `wt_http3_endpoint_on_request_headers`: RFC 9114 section 4.1 gives the two directions of one exchange their
 * own HEADERS frames on the same stream, so the response is neither the request line nor a trailer -- it is
 * the other half of the conversation, with its own pseudo-header rules (`:status`) and its own once-only
 * rule. Decoding it with the request rules would refuse a perfectly good `:status` as a pseudo-header in a
 * trailer, which is what this endpoint did before the call existed. */
wt_status_t wt_http3_endpoint_on_response_headers(wt_http3_endpoint_t *endpoint, uint64_t stream_id,
                                                  const uint8_t *payload, size_t length,
                                                  uint8_t *scratch, size_t scratch_capacity,
                                                  wt_http3_message_t *out_message,
                                                  wt_http3_error_t *out_error);

/* One frame arrived on a tracked request stream. */
wt_status_t wt_http3_endpoint_on_request_frame(wt_http3_endpoint_t *endpoint, uint64_t stream_id,
                                               uint64_t type, wt_http3_error_t *out_error);

/* The peer ended or reset a tracked request stream. Ending before HEADERS is
 * H3_REQUEST_INCOMPLETE, which section 4.1 defines for aborting the response rather than
 * for closing the connection. Either way the stream is forgotten afterwards, except when
 * the request is complete: a complete request's state is still readable until the stream
 * itself ends. */
wt_status_t wt_http3_endpoint_on_request_end(wt_http3_endpoint_t *endpoint, uint64_t stream_id,
                                             wt_http3_error_t *out_error);
wt_status_t wt_http3_endpoint_on_request_reset(wt_http3_endpoint_t *endpoint, uint64_t stream_id);

/* The ordering state of a tracked request stream. WT_ERR_STATE for a stream this endpoint
 * is not tracking. */
wt_status_t wt_http3_endpoint_request_state(const wt_http3_endpoint_t *endpoint, uint64_t stream_id,
                                            wt_http3_request_state_t *out_state);

size_t wt_http3_endpoint_request_count(const wt_http3_endpoint_t *endpoint);

/* Set the dynamic table's capacity to what this endpoint advertised, which is what makes
 * a field section's MaxEntries prefix readable: the prefix is encoded against that number,
 * so reading it without saying what was advertised would mean guessing. A capacity below
 * 32 makes MaxEntries zero, and then no field section may reference the dynamic table at
 * all -- which is the correct state for an endpoint that advertised no dynamic table. */
wt_status_t wt_http3_endpoint_set_decoder_capacity(wt_http3_endpoint_t *endpoint, size_t capacity);

/* A HEADERS frame's payload on a tracked request stream: the ordering rule first, then the
 * field section decoded against this endpoint's decoder state. The decoded message is what
 * HEADERS means -- its pseudo-headers are the request line -- and deciding whether it is a
 * WebTransport request is the session layer's judgement, not this one's, so it is left to
 * `wt_webtransport_session_request_validate`.
 *
 * `scratch` is where Huffman-coded strings are decoded, exactly as in the QPACK layer: it
 * belongs to the caller because its size is a policy decision and this struct should not
 * carry a buffer for it. The message's views point into the tables and into `scratch`, so
 * both must outlive the message. */
wt_status_t wt_http3_endpoint_on_request_headers(wt_http3_endpoint_t *endpoint, uint64_t stream_id,
                                                 const uint8_t *payload, size_t length,
                                                 uint8_t *scratch, size_t scratch_capacity,
                                                 wt_http3_message_t *out_message,
                                                 wt_http3_error_t *out_error);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_HTTP3_ENDPOINT_H */
