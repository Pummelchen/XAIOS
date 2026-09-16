/* Driving an HTTP/3 endpoint from a connection (Phase 9).
 *
 * `endpoint.h` owns the per-connection HTTP/3 state but knows nothing about how bytes
 * arrive. This is the seam between the two: it takes stream events the way a connection
 * reports them -- a stream ID, an offset, the bytes, and whether the peer finished -- and
 * turns an opening unidirectional stream into a classified one.
 *
 * The reason it exists rather than a direct call to `wt_http3_endpoint_on_uni_stream` is
 * REASSEMBLY. A stream's type prefix is a varint, and a varint can be split across frames: a
 * peer may open a stream and send one byte of `0xC0 0x00 ...` in its first packet and the
 * rest in the next. The endpoint's classifier wants the whole prefix, and it is right to --
 * deciding a stream's type from half a varint is exactly the mistake that makes an
 * implementation read someone else's stream. So the driver holds at most the first eight
 * bytes of each opening stream (the longest prefix QUIC's varint can make) until they add up
 * to a prefix, and it holds them in a FIXED table, because a buffer that grows with the
 * number of streams a peer opens is a heap exhaustion path with the peer's name on it.
 *
 * A prefix must also arrive at offset zero: a stream whose type prefix is not at its start
 * is not that type, and `WT_ERR_STATE` says the caller's own accounting is wrong rather than
 * blaming the peer.
 */

#ifndef WEBTRANSPORT_HTTP3_DRIVER_H
#define WEBTRANSPORT_HTTP3_DRIVER_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/http3/endpoint.h"
#include "webtransport/http3/settings.h"
#include "webtransport/quic/connection.h"
#include "webtransport/status.h"
#include "webtransport/webtransport/session_request.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The longest stream prefix a peer can send: a draft-16 WebTransport stream's prefix is the TYPE and then the
 * session ID, each a varint of up to eight bytes, so sixteen rather than eight. A table sized for the type alone
 * would refuse a legal prefix. */
#define WT_HTTP3_DRIVER_PREFIX_MAX 16U

/* How many opening streams may be waiting for the rest of their prefix at once. A peer that
 * opens more than this before completing any of them is refused with WT_ERR_LIMIT rather
 * than given more memory. */
#define WT_HTTP3_DRIVER_PENDING_MAX 8U

/* How many WebTransport DATA streams this driver may remember at once. A stream is remembered once its prefix is
 * settled -- either because this endpoint opened it, or because the peer's prefix was classified -- so that the
 * bytes after the prefix are the session's payload rather than something to parse again. A caller past the bound
 * is refused with WT_ERR_LIMIT rather than given more, which is the same rule the endpoint's request table
 * follows. */
#define WT_HTTP3_DRIVER_DATA_STREAMS_MAX 32U

/* One remembered WebTransport data stream. The PREFIX LENGTH is how many bytes of THIS endpoint's prefix are on
 * that stream -- the draft's header that associates it with the session -- and it is 0 for a stream the peer
 * opened, whose prefix is on the peer's own direction. It is here because draft-ietf-webtrans-http3-16 section 4.4
 * requires a reset of a WebTransport stream to commit to at least that many bytes (a Reliable Size), so that the
 * association survives the reset, and a driver that forgot which streams it had written a prefix on could not
 * state it (WT-182). */
typedef struct wt_http3_driver_data_stream {
  uint64_t stream_id;
  uint64_t prefix_length;
  /* The session this stream's prefix named, when it named one (WT-180). A peer's stream carries the ID in its
   * prefix and it is kept here so a caller can apply section 4.6's "buffer until it can be associated" rule;
   * for a stream this endpoint opened, the ID is the one `wt_http3_driver_set_session_id` was given, and
   * `session_id_set` says whether there was one. */
  uint64_t session_id;
  int session_id_set;
} wt_http3_driver_data_stream_t;

/* How many WebTransport CONNECT streams this driver may remember at once. A CONNECT stream is marked when its
 * session is known -- by the client when it sends the CONNECT, by the server when it accepts one -- so that the
 * bytes after its single HEADERS frame are the SESSION's capsules rather than HTTP/3 frames (draft-16 section 5).
 * The bound is smaller than the data-stream table's because one session has many streams but a driver serves a
 * handful of sessions, and a caller past it is refused with WT_ERR_LIMIT rather than given more. */
#define WT_HTTP3_DRIVER_CAPSULE_STREAMS_MAX 8U

typedef struct wt_http3_driver_pending {
  uint64_t stream_id;
  uint8_t bytes[WT_HTTP3_DRIVER_PREFIX_MAX];
  size_t length;
} wt_http3_driver_pending_t;

/* One marked CONNECT stream. `headers_pending` is the ONE frame that is still HTTP/3 on the stream -- the
 * response on a stream this endpoint opened, the request on a peer-initiated one -- and the mark settles when
 * that frame has been delivered. */
typedef struct wt_http3_driver_capsule_stream {
  uint64_t stream_id;
  int headers_pending;
} wt_http3_driver_capsule_stream_t;

/* The longest frame header: two varints, at most eight bytes each. */
#define WT_HTTP3_DRIVER_FRAME_HEADER_MAX 16U

/* How many streams may be mid-frame at once. Each holds only a frame header, so this is a
 * limit on interleaving rather than on memory; a stream past it is WT_ERR_LIMIT. */
#define WT_HTTP3_DRIVER_FRAMES_MAX 8U

typedef struct wt_http3_driver_frame_state {
  uint64_t stream_id;
  uint8_t header[WT_HTTP3_DRIVER_FRAME_HEADER_MAX];
  size_t header_length;
  int in_frame;
  uint64_t type;
  uint64_t payload_length;
  uint64_t payload_received;
} wt_http3_driver_frame_state_t;

/* ---------------------------------------------- sending, without knowing QUIC

 * The endpoint has to open streams and send bytes, and this header deliberately does not name
 * a QUIC connection to do it: the transport is a small table of three calls. That keeps the
 * HTTP/3 layer independent of the connection implementation -- and it makes the outbound half
 * testable against a recording transport, which is how the bytes this layer produces are
 * checked without standing up a handshake.

 * The driver owns one scratch buffer for the bytes it sends, because a frame is measured
 * before it is written (a length prefix's width depends on the length) and the measurement
 * needs somewhere to live. It is a bound like every other one here: a section that does not
 * fit is WT_ERR_LIMIT with no error code, and the caller can raise
 * `WT_HTTP3_DRIVER_SCRATCH` by compiling its own copy or send the section itself. */

#define WT_HTTP3_DRIVER_SCRATCH 1024U

typedef wt_status_t (*wt_http3_open_stream_fn)(void *context, int bidirectional,
                                               uint64_t *out_stream_id, uint64_t now);
typedef wt_status_t (*wt_http3_send_stream_fn)(void *context, uint64_t stream_id,
                                               const uint8_t *data, size_t length, int fin,
                                               uint64_t now);
typedef wt_status_t (*wt_http3_send_datagram_fn)(void *context, const uint8_t *data,
                                                 size_t length);

typedef struct wt_http3_driver_transport {
  /* Open a stream this endpoint initiates, and say what ID it got. */
  wt_http3_open_stream_fn open_stream;
  /* Send bytes on a stream. `fin` ends it. */
  wt_http3_send_stream_fn send_stream;
  wt_http3_send_datagram_fn send_datagram;
  void *context;
} wt_http3_driver_transport_t;

typedef struct wt_http3_driver {
  /* The endpoint whose streams these are. Not owned. */
  wt_http3_endpoint_t *endpoint;
  wt_http3_driver_pending_t pending[WT_HTTP3_DRIVER_PENDING_MAX];
  size_t pending_count;
  /* Streams part way through a frame's header. */
  wt_http3_driver_frame_state_t frames[WT_HTTP3_DRIVER_FRAMES_MAX];
  size_t frame_count;
  /* The bytes of the message being sent, measured before the frame around them is written, and the frame that
   * carries them. TWO buffers, because the two must not overlap: the writer copies the section from where it was
   * measured to just past the frame header, and a single buffer makes that copy overlap itself -- undefined
   * behaviour that produced garbage under a hardened build (an audit caught it with ASan). `start_own_streams`
   * can use two halves of one buffer because a SETTINGS payload is small; a HEADERS section is a caller's, so it
   * gets a buffer of its own. The frame is the retained copy (`request_retained`), exactly as before. */
  uint8_t scratch[WT_HTTP3_DRIVER_SCRATCH];
  uint8_t section[WT_HTTP3_DRIVER_SCRATCH];
  /* The session this endpoint serves. A WebTransport stream's prefix must name it, and until it is set a
   * WebTransport stream is refused rather than delivered to an endpoint that cannot say which session it
   * belongs to. */
  uint64_t session_id;
  int session_id_set;
  /* The `:protocol` token the extended CONNECT of `wt_http3_driver_send_session_request` carries. The draft-16
   * value is the default (see `wt_webtransport_upgrade_token_t`, where zero is that value, and
   * `wt_http3_driver_init` zeroes this whole structure), because draft-ietf-webtrans-http3-16 section 3.2 names
   * `webtransport-h3` and that is what a conforming client sends. The token is not negotiable on the wire: a peer
   * written against an earlier draft knows only `webtransport` and rejects the CONNECT with H3_MESSAGE_ERROR
   * before it reads any setting, so reaching such a peer means being TOLD to send the old value -- which is what
   * `wt_http3_driver_set_upgrade_token` is for, and what the C99 CLI's `--upgrade-token legacy` selects (F-02b). */
  wt_webtransport_upgrade_token_t upgrade_token;
  /* The request this endpoint sent, so it can be sent AGAIN when a probe timeout reports it lost (RFC 9002
   * section 6.2.4). The bytes are the ones `send_message` left in `scratch`, so they stay valid until the
   * driver sends another message -- which for a client's CONNECT is the rest of the handshake, and which the
   * resend function says in its own contract (WT-135). */
  uint64_t request_stream_id;
  size_t request_length;
  int request_retained;
  /* The WebTransport DATA streams whose prefix is SETTLED, by ID: the ones this endpoint opened, and the ones a
   * peer opened whose prefix this driver classified as WebTransport. The draft's prefix (`0x41` for a
   * bidirectional stream, `0x54` for a unidirectional one, then the session ID) is sent ONCE, by the stream's
   * initiator (draft-ietf-webtrans-http3-16 sections 4.2 and 4.3), so everything after it on that stream is the
   * session's payload. Reading the payload as a prefix again closed a connection (WT-135); forgetting the prefix
   * and parsing the payload as HTTP/3 frames did it too, and only a peer that sends the prefix in one STREAM
   * frame and its message in the next could show that -- this tree's own client sends both together (WT-156). */
  wt_http3_driver_data_stream_t data_streams[WT_HTTP3_DRIVER_DATA_STREAMS_MAX];
  size_t data_stream_count;
  /* The WebTransport CONNECT streams whose capsules have begun, by ID, and the ones whose single HEADERS frame is
   * still to come. Draft-16 section 5 puts the session's control messages -- drain, close and the flow-control
   * grants -- on the CONNECT stream as CAPSULES after that one HEADERS frame, and a capsule's type is a varint
   * that this layer would otherwise read as a frame type: a flow-control capsule is an UNKNOWN frame type, so its
   * length field is read as a frame length and the capsule is SKIPPED -- the peer's credit dropped without a
   * word. Marking the stream is what stops the framing (WT-164). */
  wt_http3_driver_capsule_stream_t capsule_streams[WT_HTTP3_DRIVER_CAPSULE_STREAMS_MAX];
  size_t capsule_stream_count;
  /* The HTTP/3 error code of the last refusal this driver made, and the connection it belongs to when one has
   * been bound. RFC 9114 section 8 carries an HTTP/3 error in a CONNECTION_CLOSE of type 0x1d with the HTTP/3
   * code, and a handler that only returns a status closes the TRANSPORT with INTERNAL_ERROR instead -- a
   * different error, in a different frame, that names the wrong rule. The driver knows the code, so the driver
   * states it: a translation done by each caller instead is a translation one of them will forget (WT-158,
   * WT-159). */
  wt_http3_error_t last_error;
  wt_quic_connection_t *connection;
  /* Whether the session's streams have been ended (section 6). Set by `wt_http3_driver_end_session_streams`, and
   * read by the send paths that must refuse a new data stream or datagram afterwards. */
  int session_ended;
} wt_http3_driver_t;

void wt_http3_driver_init(wt_http3_driver_t *driver, wt_http3_endpoint_t *endpoint);

/* Say which session this endpoint serves, so a WebTransport stream's prefix can be checked against it. */
void wt_http3_driver_set_session_id(wt_http3_driver_t *driver, uint64_t session_id);

/* Say which `:protocol` token this endpoint's own CONNECT carries.
 *
 * The default -- and what `wt_http3_driver_init` leaves in place -- is the draft-16 token, `webtransport-h3`
 * (draft-ietf-webtrans-http3-16 section 3.2). `WT_WEBTRANSPORT_UPGRADE_TOKEN_LEGACY` selects the pre-draft
 * `webtransport` for a peer that predates the rename. The selection is explicit rather than negotiated because it
 * cannot be negotiated: the peer refuses the extended CONNECT with H3_MESSAGE_ERROR before any SETTINGS exchange,
 * which is how four of the five third-party peers rejected the draft-16 token (F-02b). Only the two values above
 * are meaningful; any other value sends the draft-16 token (see `wt_webtransport_upgrade_token_value`). */
void wt_http3_driver_set_upgrade_token(wt_http3_driver_t *driver, wt_webtransport_upgrade_token_t token);

/* END THE SESSION'S DATA STREAMS: draft-ietf-webtrans-http3-16 section 6's reset, for every WebTransport stream
 * this driver remembers.
 *
 * "Upon learning that the session has been terminated, the endpoint MUST reset the send side and abort reading on
 * the receive side of all unidirectional and bidirectional streams associated with the session ... using the
 * WT_SESSION_GONE error code; it MUST NOT send any new datagrams or open any new streams." The session object
 * records that a session ended; the DRIVER is what knows which streams belonged to it, so the reset happens here
 * and the two halves meet in one call.
 *
 * What it does, per remembered stream: a RESET_STREAM_AT carrying `WT_WEBTRANSPORT_ERROR_SESSION_GONE`, with the
 * Reliable Size set to this endpoint's prefix capped by the bytes actually sent (section 4.4's rule, and the
 * reason the table above remembers the prefix length), and a STOP_SENDING with the same code for a stream this
 * endpoint can still receive on. The streams are then FORGOTTEN, so a second call does nothing, and the driver
 * refuses a new data stream or datagram (WT_ERR_STATE) from here on: both are the section's MUST NOT.
 *
 * WT_ERR_STATE when no connection is bound (`wt_http3_driver_bind_connection`), because a reset is a frame.
 * `out_streams_ended` reports how many streams were reset, which a caller logs or asserts; a stream the connection
 * refuses (one it no longer has, or a reliable reset the peer did not negotiate) is skipped and counted in the
 * same number only if it was reset -- the return is the first refusal, and WT_OK says every one of them went. */
wt_status_t wt_http3_driver_end_session_streams(wt_http3_driver_t *driver, uint64_t now,
                                                size_t *out_streams_ended);

/* Whether the session's streams have been ended, so a caller can tell "the session is over" from "it never
 * started" without reading the count. */
int wt_http3_driver_session_ended(const wt_http3_driver_t *driver);

/* One unidirectional stream's bytes, as a connection reported them.
 *
 * On the frame that completes the prefix, `out_kind` is set and `out_payload` points at the
 * bytes AFTER the prefix, within the caller's own `data` -- so it lives as long as that
 * buffer, and the driver copies nothing. On an earlier frame `out_kind` is left as UNKNOWN
 * and `*out_payload_length` is zero: the prefix is not yet a prefix, and the caller sends
 * the rest.
 *
 * `out_prefix_consumed` reports how many of THIS frame's bytes went to the prefix, which is
 * what a caller replaying buffered bytes needs. */
wt_status_t wt_http3_driver_on_uni_stream_data(wt_http3_driver_t *driver, uint64_t stream_id,
                                               uint64_t offset, const uint8_t *data, size_t length,
                                               wt_http3_endpoint_stream_kind_t *out_kind,
                                               const uint8_t **out_payload,
                                               size_t *out_payload_length,
                                               size_t *out_prefix_consumed,
                                               wt_http3_error_t *out_error);

/* A peer's unidirectional stream ended: the endpoint is told so its rules apply (a control
 * stream ending is the error itself), and any half-received prefix is dropped -- a stream
 * that ended before its type was complete never had one. */
wt_status_t wt_http3_driver_on_uni_stream_end(wt_http3_driver_t *driver, uint64_t stream_id,
                                              wt_http3_error_t *out_error);

/* How many opening streams are waiting for the rest of their prefix, for a caller that logs
 * occupancy or bounds its own buffering. */
size_t wt_http3_driver_pending_count(const wt_http3_driver_t *driver);

/* ---------------------------------------------- frame boundaries on a stream

 * A stream carries a sequence of HTTP/3 frames, and a frame's own header -- a type varint
 * and a length varint -- can be SPLIT across the STREAM frames a connection hands over, the
 * same way a stream's type prefix can. This part of the driver reassembles the boundary, and
 * it deliberately does NOT buffer the payload: it reports the frame's payload to a sink in
 * whatever pieces arrive, with a `last` flag on the final one.
 *
 * That division is the point. The driver's job is framing, and framing needs sixteen bytes of
 * state per stream; the PAYLOAD is policy -- how much of a HEADERS section this endpoint will
 * hold is a bound, and a bound belongs to whoever owns the memory. A driver that buffered
 * every stream's frames would be carrying that policy silently, with a fixed size nobody
 * chose.
 *
 * The one thing the driver does bound is the frame's declared length, because a length is
 * the peer's to choose and this endpoint has to refuse absurdity before the sink allocates
 * for it: over `max_frame_bytes` it is H3_EXCESSIVE_LOAD. */

/* What a frame's payload is delivered to. Called once per piece that arrives, in order, with
 * `last` set on the piece that completes the frame; a zero-length frame reports one piece of
 * zero bytes with `last` set, so a sink never has to special-case an empty frame. */
typedef wt_status_t (*wt_http3_frame_sink_fn)(void *context, uint64_t stream_id, uint64_t type,
                                              const uint8_t *payload, size_t length, int last);

/* The peer's own stream data, which is NOT HTTP/3 framing: a WebTransport stream's bytes
 * after its prefix are the session's, and a datagram's payload is the session's too. The
 * driver does not interpret them -- it hands them over, because what they mean is the
 * session layer's business and buffering them is a bound that layer owns. */
typedef wt_status_t (*wt_http3_stream_data_fn)(void *context, uint64_t stream_id,
                                              const uint8_t *data, size_t length, int fin);
typedef wt_status_t (*wt_http3_datagram_fn)(void *context, const uint8_t *data, size_t length);

typedef struct wt_http3_driver_sink {
  wt_http3_frame_sink_fn on_frame_payload;
  wt_http3_stream_data_fn on_stream_data;
  wt_http3_datagram_fn on_datagram;
  void *context;
} wt_http3_driver_sink_t;

/* Bytes arriving on a stream that carries HTTP/3 frames (the control stream, the QPACK
 * streams, a request stream). `fin` says the peer ended the stream here.
 *
 * WT_ERR_TRUNCATED means the stream ended in the middle of a frame: an incomplete frame on a
 * stream is not malformed until there is nothing more coming, which is what `fin` decides. */
wt_status_t wt_http3_driver_on_stream_bytes(wt_http3_driver_t *driver, uint64_t stream_id,
                                            const uint8_t *data, size_t length, int fin,
                                            uint64_t max_frame_bytes,
                                            const wt_http3_driver_sink_t *sink,
                                            wt_http3_error_t *out_error);

/* Forget a stream's half-read frame when the stream ends or is reset, and RELEASE the slot it was using.
 * Returns whether a frame was in progress, which is what a caller needs to decide between WT_ERR_TRUNCATED and
 * silence. The driver calls this itself when a unidirectional stream ends and when a bidirectional one is
 * finished, so a caller only needs it for a reset; the table is eight slots, and a stream that is over must not
 * keep one. */
int wt_http3_driver_forget_frame(wt_http3_driver_t *driver, uint64_t stream_id);

/* What a peer's opening bytes on a BIDIRECTIONAL stream make it.
 *
 * A peer-initiated bidirectional stream is either a request stream (an HTTP/3 CONNECT, whose first bytes are a
 * QPACK field-section prefix) or a WebTransport bidirectional stream (the draft's `0x41` type and the session
 * ID). The two are told apart by those first bytes and nothing else, so this is a pure function of them: it
 * reads, it does not route, and the caller decides what to do with the answer. That separation is deliberate --
 * the routing that USES this is where the release-build crash of WT-120 lived, and a pure classifier can be
 * proven in all three build configurations before anything is routed by it. */
typedef enum wt_http3_bidi_start_kind {
  /* Not a WebTransport prefix: an HTTP/3 request stream, or so few bytes that nothing is decided yet. */
  WT_HTTP3_BIDI_START_REQUEST = 0,
  /* The draft's bidirectional WebTransport prefix, whose length is `*out_consumed`. */
  WT_HTTP3_BIDI_START_WEBTRANSPORT = 1
} wt_http3_bidi_start_kind_t;

/* WT_ERR_TRUNCATED means the prefix has not fully arrived, which on a stream is a WAIT rather than a refusal: a
 * peer may open a stream and send its first bytes in the next packet. */
wt_status_t wt_http3_driver_classify_bidi_start(const uint8_t *bytes, size_t length,
                                                wt_http3_bidi_start_kind_t *out_kind,
                                                uint64_t *out_session_id, size_t *out_consumed);

/* One frame the connection handed over, routed to whichever of the sink's callbacks owns it.
 *
 * This is the shape `wt_quic_connection_set_handlers` wants, so a caller installs the driver
 * directly:
 *
 *     wt_quic_connection_set_handlers(&connection, wt_http3_driver_on_quic_frame, &driver, ...);
 *
 * What it routes, and why each has to be here rather than in the connection layer:
 *   - a STREAM frame on a peer-initiated unidirectional stream: the type prefix is
 *     reassembled, and then the bytes are either HTTP/3 frames (control, QPACK) or the
 *     session's own data (the draft's stream type), which is a distinction only the HTTP/3
 *     layer can make;
 *   - a STREAM frame on a peer-initiated bidirectional stream: a request stream, whose frames
 *     are the CONNECT and its response;
 *   - a DATAGRAM frame: the session's datagram payload, handed over uninterpreted.
 *
 * A frame on a stream THIS endpoint initiated is not routed: it is the connection's to track
 * and this layer has nothing to do with the peer's answer on a stream it did not receive.
 * Unhandled frame kinds are ignored, which is what a frame handler is for. */
wt_status_t wt_http3_driver_on_quic_frame(void *context, wt_quic_space_t space,
                                          const wt_quic_frame_t *frame,
                                          const wt_http3_driver_sink_t *sink,
                                          uint64_t max_frame_bytes);

/* Open and start the three streams HTTP/3 requires of an endpoint: the control stream with its
 * SETTINGS, and both QPACK streams. Each is opened once; a second call is WT_ERR_STATE from the
 * endpoint's own rules, and nothing is sent. */
wt_status_t wt_http3_driver_start_own_streams(wt_http3_driver_t *driver,
                                              const wt_http3_driver_transport_t *transport,
                                              const wt_http3_settings_t *settings, uint64_t now);

/* Open a request stream on the CONNECTION and register it with the ENDPOINT, in one call, so the two
 * halves of "this stream is a request" cannot disagree. They are two different machines -- the connection
 * owns the stream ID and its flow control, the endpoint owns the request ordering -- and a caller that
 * opened one without the other gets a refusal from the connection at the first send, which reads as a
 * state error rather than as a missing step. (It did: that is why this function exists.) */
wt_status_t wt_http3_driver_open_request(wt_http3_driver_t *driver,
                                         const wt_http3_driver_transport_t *transport, uint64_t now,
                                         uint64_t *out_stream_id, wt_http3_error_t *out_error);

/* The whole client-side opening sequence in one call: start this endpoint's own streams (control and both
 * QPACK streams), open a request stream, and send an extended CONNECT for `authority` and `path` on it.
 *
 * It exists because the sequence is fixed by the protocol and every WebTransport client performs it in the
 * same order -- and because doing it by hand is where three separate bugs were found in this phase (a grant
 * that did not match the advertised value, a stream opened on one machine and not the other, and a send whose
 * offset was never recorded). A caller that wants a different order can still use the pieces. */
wt_status_t wt_http3_driver_start_session(wt_http3_driver_t *driver,
                                          const wt_http3_driver_transport_t *transport,
                                          const wt_http3_settings_t *settings, const char *authority,
                                          const char *path, uint64_t peer_max_entries, uint64_t now,
                                          uint64_t *out_stream_id, wt_http3_error_t *out_error);

/* Send a request, a response or a trailer on a stream this endpoint owns, as a HEADERS frame.
 * `peer_max_entries` is the peer's advertised QPACK capacity, from its SETTINGS. */
/* Send the retained request again, because its packet was reported lost.
 *
 * The bytes are the driver's own `scratch` at the length it last sent, so this is only valid while nothing else
 * has used the scratch: the caller knows when that is (a client's CONNECT is the only message it sends before the
 * response). WT_ERR_STATE when there is nothing retained, which is a caller that asked at the wrong time rather
 * than a peer that did something. */
wt_status_t wt_http3_driver_resend_request(wt_http3_driver_t *driver,
                                           const wt_http3_driver_transport_t *transport, uint64_t now);

wt_status_t wt_http3_driver_send_message(wt_http3_driver_t *driver,
                                         const wt_http3_driver_transport_t *transport,
                                         uint64_t stream_id, const wt_http3_message_t *message,
                                         uint64_t peer_max_entries, int fin, uint64_t now);

/* Open a WebTransport DATA stream and send `data` on it, prefix and all.
 *
 * The prefix is written HERE rather than by the caller, because this function is also where the stream becomes
 * one this endpoint OWNS: the draft gives the prefix to the stream's initiator, so the responder's bytes on the
 * same stream are payload, and only the owner knows that (WT-135). `unidirectional` chooses the prefix's type
 * and the stream's class; `fin` ends the stream with the bytes. `*out_stream_id` is the stream that was opened,
 * which a caller needs to match the answer to its own stream. */
wt_status_t wt_http3_driver_open_data_stream(wt_http3_driver_t *driver,
                                             const wt_http3_driver_transport_t *transport,
                                             int unidirectional, const uint8_t *data, size_t length,
                                             int fin, uint64_t now, uint64_t *out_stream_id);

/* The HTTP/3 error code of the last refusal this driver made, or WT_HTTP3_NO_ERROR when the last frame was
 * accepted (or refused for a reason that is not an HTTP/3 error, such as a caller's bound). */
wt_http3_error_t wt_http3_driver_last_error(const wt_http3_driver_t *driver);

/* Say which connection this driver's refusals belong to, so that a refusal WITH an HTTP/3 error closes it as an
 * APPLICATION close carrying that code (RFC 9114 section 8) without every caller having to translate. Unbound is
 * the default and is not an error: a driver used without a connection simply reports the status, as before. */
void wt_http3_driver_bind_connection(wt_http3_driver_t *driver, wt_quic_connection_t *connection);

/* Whether `stream_id` is a WebTransport data stream whose prefix is settled, in either direction. The receive
 * path asks FIRST, because the answer decides whether the bytes are the session's payload or something to
 * classify. */
int wt_http3_driver_is_data_stream(const wt_http3_driver_t *driver, uint64_t stream_id);

/* The session a remembered WebTransport data stream's prefix named (draft-16 section 4.2).
 *
 * This is what lets a caller apply section 4.6's buffering rule to a STREAM: a stream can arrive before the
 * session it names is known, and the answer to "may I deliver this yet?" is the ID in its prefix rather than
 * anything about the stream. The driver is where that prefix was parsed, so it is where the number lives -- it
 * used to be discarded at the parse, which left a caller with no way to ask.
 *
 * WT_OK and `*out_session_id` when the stream is remembered and its prefix named a session; WT_ERR_STATE when
 * the stream is remembered but this endpoint wrote the prefix itself and no session ID has been set
 * (`wt_http3_driver_set_session_id`); WT_ERR_CLOSED when the stream is not a remembered data stream at all. */
wt_status_t wt_http3_driver_data_stream_session_id(const wt_http3_driver_t *driver, uint64_t stream_id,
                                                   uint64_t *out_session_id);

/* REJECT one WebTransport data stream with `error_code`: section 4.6's answer to a stream that arrives while its
 * session is unknown and cannot be buffered any longer.
 *
 * "When the number of buffered streams is exceeded, a stream MUST be closed by sending a RESET_STREAM and/or
 * STOP_SENDING with the WT_BUFFERED_STREAM_REJECTED error code." So this is a reset of the send side with that
 * code -- a Reliable Size of this endpoint's prefix capped by the bytes actually sent, the section 4.4 rule
 * `wt_http3_driver_end_session_streams` also follows -- plus a STOP_SENDING for a stream this endpoint can still
 * receive on, because the peer's bytes on it are refused too. The stream is then FORGOTTEN, so the caller cannot
 * park more of it and a second rejection is WT_ERR_CLOSED rather than a second reset.
 *
 * WT_ERR_CLOSED when the stream is not a remembered data stream, and WT_ERR_STATE when no connection is bound (a
 * reset is a frame). A connection that refuses the reset -- a stream it does not have, a peer that did not
 * negotiate the reliable reset -- is reported as its own status with the stream still forgotten: the refusal is
 * the caller's to log, and the stream is over either way. */
wt_status_t wt_http3_driver_reject_data_stream(wt_http3_driver_t *driver, uint64_t stream_id,
                                               uint64_t error_code, uint64_t now);

/* The two halves of starting a session, for a caller that has something to send BETWEEN them (WT-189).
 *
 * `wt_http3_driver_start_session` is both halves in order, and that is what a client normally wants. It is split
 * because the draft says a client's flight may hold more than its CONNECT: "clients can, however, send a SETTINGS
 * frame, multiple WebTransport CONNECT requests, WebTransport data streams, and WebTransport datagrams all within
 * a single flight. As those can arrive out of order, a WebTransport server can receive a stream or a datagram
 * without a corresponding session" (section 4.6). A client that sends a data stream first is therefore
 * CONFORMING, and this tree could not express it: `start_session` opens the request stream and writes the CONNECT
 * in one call, so no stream could precede it and the server's parking path had no way to be reached from the
 * tools.
 *
 * So: open the request stream, which is also where this endpoint learns its SESSION ID (section 3.2) -- after
 * which `wt_http3_driver_open_data_stream` names the right session -- and send the CONNECT on it when the caller
 * is ready. `stream_id` must be the one the first call reported; sending a request on any other stream is the
 * caller's error, and the message would simply be an HTTP/3 request on it. */
wt_status_t wt_http3_driver_open_session_stream(wt_http3_driver_t *driver,
                                                const wt_http3_driver_transport_t *transport,
                                                const wt_http3_settings_t *settings, uint64_t now,
                                                uint64_t *out_stream_id, wt_http3_error_t *out_error);

wt_status_t wt_http3_driver_send_session_request(wt_http3_driver_t *driver,
                                                 const wt_http3_driver_transport_t *transport,
                                                 uint64_t stream_id, const char *authority,
                                                 const char *path, uint64_t peer_max_entries, uint64_t now,
                                                 wt_http3_error_t *out_error);

/* Say that a stream is a WebTransport CONNECT stream, so that once its single HEADERS frame has passed, the rest
 * of what arrives on it is the SESSION's capsules rather than HTTP/3 frames (draft-16 section 5).
 *
 * `headers_pending` says whether that one frame is still to come. A CLIENT marks its request stream when it sends
 * the CONNECT, because the RESPONSE -- the stream's one inbound HEADERS frame -- has not arrived yet; a SERVER
 * marks the peer's stream when it accepts the request, whose HEADERS it has just read. Either way the HEADERS
 * frame is delivered to the frame sink exactly as before, and the bytes after it go to the stream-data sink,
 * because only the session can say what a capsule means. Marking a stream twice is not an error and does not
 * change the mark. WT_ERR_LIMIT when the table is full, which is a caller with more sessions than this driver
 * was built for rather than a peer's doing. */
wt_status_t wt_http3_driver_mark_capsule_stream(wt_http3_driver_t *driver, uint64_t stream_id,
                                                int headers_pending);

/* Whether a stream's CAPSULES have begun: it was marked, and its one HEADERS frame has been delivered. False for
 * a marked stream whose HEADERS frame is still to come, because that frame is still this layer's to frame. */
int wt_http3_driver_is_capsule_stream(const wt_http3_driver_t *driver, uint64_t stream_id);

/* Answer a request with a status: the response's HEADERS on the stream that carried the request. One per
 * stream, because a second response is not a status an HTTP/3 peer can be given. */
wt_status_t wt_http3_driver_send_response(wt_http3_driver_t *driver,
                                          const wt_http3_driver_transport_t *transport,
                                          uint64_t stream_id, uint32_t status, uint64_t peer_max_entries,
                                          int fin, uint64_t now);

/* Send a datagram: the payload is the session's, and this layer passes it through. */
wt_status_t wt_http3_driver_send_datagram(wt_http3_driver_t *driver,
                                          const wt_http3_driver_transport_t *transport,
                                          const uint8_t *data, size_t length);

/* The transport table bound to a QUIC connection: the three adapters that turn this layer's
 * three calls into `wt_quic_connection_open_stream`, `wt_quic_connection_send_stream` and
 * `wt_quic_connection_send_datagram`.
 *
 * The offset a send goes at is read from the connection's own stream state
 * (`stream->send_offset`, advanced by the stream when data is sent), so this adapter keeps no
 * bookkeeping of its own and cannot drift from the connection's idea of where the stream is.
 * A stream the connection does not know, or one it cannot send on yet, is refused by the
 * connection and that refusal is passed through unchanged: congestion and state are the
 * connection's to report, not this layer's to reinterpret. */
void wt_http3_driver_quic_transport(wt_quic_connection_t *connection,
                                    wt_http3_driver_transport_t *out_transport);

/* Start this endpoint's control stream: the type prefix, then the SETTINGS frame built from
 * `settings`. The bytes go into the caller's writer, which is the stream the connection
 * opened for them.
 *
 * The frame can only be written once its length is known, so the SETTINGS payload is
 * measured into `scratch` first -- the same measure-then-write rule every length on this wire
 * follows. A payload that does not fit the scratch is WT_ERR_LIMIT with no error code: it is
 * this endpoint's buffer and its own choice of settings, not anything a peer did.
 *
 * Sending a second control stream is refused by the endpoint's own one-per-connection rule
 * (WT_ERR_STATE), so this is safe to call on a session that may already have started one. */
wt_status_t wt_http3_driver_start_control(wt_http3_driver_t *driver, const wt_http3_settings_t *settings,
                                          uint8_t *scratch, size_t scratch_capacity, wt_writer_t *w);

/* Start one of this endpoint's QPACK streams: the type prefix alone, because what follows on
 * it is the QPACK layer's to write. `encoder` selects the encoder stream (0x02) or the
 * decoder stream (0x03), and a second one of either is WT_ERR_STATE. */
wt_status_t wt_http3_driver_start_qpack_stream(wt_http3_driver_t *driver, int encoder,
                                               wt_writer_t *w);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_HTTP3_DRIVER_H */
