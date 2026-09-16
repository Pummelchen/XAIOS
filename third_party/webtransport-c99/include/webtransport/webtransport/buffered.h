/* What a WebTransport endpoint does with a stream or datagram that arrives BEFORE the
 * session it names is known (draft-ietf-webtrans-http3-16 section 4.6).
 *
 * The draft's own words: a client can send "a SETTINGS frame, multiple WebTransport CONNECT
 * requests, WebTransport data streams, and WebTransport datagrams all within a single flight.
 * As those can arrive out of order, a WebTransport server can receive a stream or a datagram
 * without a corresponding session. ... To handle this case, WebTransport endpoints SHOULD
 * buffer streams and datagrams until they can be associated with an established session. To
 * avoid resource exhaustion, endpoints MUST limit the number of buffered streams and
 * datagrams."
 *
 * "Buffer until they can be associated" is the rule this object owns, and it is one rule for
 * both halves because the reason is the same for both: until the session ID is known there is
 * no way to tell "mine, early" from "not mine", so everything is parked, bounded, and resolved
 * in one place when the ID becomes known. At that point the ones that name this session are
 * delivered IN ARRIVAL ORDER -- a stream's bytes after its prefix, a datagram's payload -- and
 * the rest are dropped, because a stream or datagram that arrived before the reference point
 * existed was never an error. WHICH stream and datagram IDs those are is the caller's; this
 * object compares numbers and holds bytes.
 *
 * The bounds are the section's MUST, and each has the answer the draft gives it:
 *
 *   - More buffered STREAMS than the table holds. The draft names the answer: "When the number
 *     of buffered streams is exceeded, a stream MUST be closed by sending a RESET_STREAM
 *     and/or STOP_SENDING with the WT_BUFFERED_STREAM_REJECTED error code." So a stream over
 *     the bound is REJECTED: `wt_webtransport_buffered_park_stream` returns WT_ERR_LIMIT and
 *     leaves the stream's ID in `last_rejected_stream_id`, and the caller sends that reset.
 *     The rejected stream is not buffered, and the ones already parked keep their order.
 *   - A stream whose OWN bytes do not fit the per-stream hold. The same rejection, because a
 *     stream delivered later with its tail cut off would be a corrupt message rather than a
 *     short one.
 *   - More buffered DATAGRAMS than the table holds, or one longer than the hold. The datagram
 *     is DROPPED and counted. A datagram is unreliable by definition -- RFC 9221 section 5.2
 *     does not retransmit one -- so dropping is the honest answer for the unreliable half, and
 *     section 4.6's MUST is about the count rather than about telling the peer.
 *
 * A second frame of a stream that is already parked APPENDS to it, in order, which is what an
 * endpoint sees when a peer's stream arrives in pieces. A stream that was dropped or rejected
 * is not parked, so the next frame of it starts a new entry: a caller that has rejected a
 * stream must not park the rest of it (the reset ends it), and the object cannot enforce that
 * for the caller -- it can only never claim a stream it does not hold.
 */

#ifndef WEBTRANSPORT_WEBTRANSPORT_BUFFERED_H
#define WEBTRANSPORT_WEBTRANSPORT_BUFFERED_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/quic/datagram.h"
#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The endpoint's bounds. Both are policy rather than protocol -- the section requires a limit and
 * does not name one -- and both are compile-time so that the memory is in the object rather than
 * in an allocator this tree does not have. Four of each is a whole flight's worth for the peers this
 * tree interops with, and the CLI's own loop already parked four datagrams. A datagram's hold is the
 * QUIC datagram bound, because a longer one cannot arrive; a stream's is smaller because a stream
 * that arrives before its session is a handful of bytes in practice, and one over the hold is
 * rejected with the code the section names rather than truncated. */
#define WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX 4U
#define WT_WEBTRANSPORT_BUFFERED_STREAM_BYTES_MAX 1024U
#define WT_WEBTRANSPORT_BUFFERED_DATAGRAMS_MAX 4U
#define WT_WEBTRANSPORT_BUFFERED_DATAGRAM_BYTES_MAX WT_QUIC_DATAGRAM_MAX

/* One parked stream: the prefix's session, whether the prefix said unidirectional, and the bytes
 * that followed it. */
typedef struct wt_webtransport_buffered_stream {
  uint64_t stream_id;
  uint64_t session_id;
  int unidirectional;
  size_t length;
  uint8_t bytes[WT_WEBTRANSPORT_BUFFERED_STREAM_BYTES_MAX];
} wt_webtransport_buffered_stream_t;

/* One parked datagram: the quarter stream ID that names the session, and the payload. */
typedef struct wt_webtransport_buffered_datagram {
  uint64_t quarter_stream_id;
  size_t length;
  uint8_t bytes[WT_WEBTRANSPORT_BUFFERED_DATAGRAM_BYTES_MAX];
} wt_webtransport_buffered_datagram_t;

typedef struct wt_webtransport_buffered {
  wt_webtransport_buffered_stream_t streams[WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX];
  size_t stream_count;
  wt_webtransport_buffered_datagram_t datagrams[WT_WEBTRANSPORT_BUFFERED_DATAGRAMS_MAX];
  size_t datagram_count;
  /* What the bounds refused, so a caller can log or assert it rather than infer it: the rejected
   * streams (each of which the caller reset with WT_BUFFERED_STREAM_REJECTED) and the dropped
   * datagrams. */
  uint64_t streams_rejected;
  uint64_t datagrams_dropped;
  /* The stream the last rejection named, so the caller does not have to be handed it twice. */
  uint64_t last_rejected_stream_id;
} wt_webtransport_buffered_t;

/* A deliver callback, called by the drain functions for each parked item that names the session the
 * caller is resolving. Its return is the drain's: WT_OK continues, anything else stops the drain --
 * the items behind it are not offered to a callback that just refused -- and the status is returned.
 * The drain's delivered count is of the items the callback ACCEPTED, so a refused one is not in it;
 * a NULL callback resolves the items without delivering them anywhere. */
typedef wt_status_t (*wt_webtransport_buffered_stream_fn)(void *context, uint64_t stream_id,
                                                          int unidirectional, const uint8_t *data,
                                                          size_t length);
typedef wt_status_t (*wt_webtransport_buffered_datagram_fn)(void *context, uint64_t quarter_stream_id,
                                                            const uint8_t *payload, size_t length);

void wt_webtransport_buffered_init(wt_webtransport_buffered_t *buffer);

/* Park one piece of a stream that arrived before its session was known.
 *
 * WT_OK means the bytes are held. WT_ERR_LIMIT means the section 4.6 rejection: the stream count is
 * at the bound, or these bytes would not fit the hold, and the caller MUST close the stream with a
 * RESET_STREAM and/or STOP_SENDING carrying WT_WEBTRANSPORT_ERROR_BUFFERED_STREAM_REJECTED.
 * `data` may be NULL only when `length` is 0. */
wt_status_t wt_webtransport_buffered_park_stream(wt_webtransport_buffered_t *buffer, uint64_t stream_id,
                                                 uint64_t session_id, int unidirectional,
                                                 const uint8_t *data, size_t length);

/* Resolve the parked streams against the session ID that is now known: every parked stream that
 * names it is delivered through `deliver` in arrival order, and every one that names another is
 * dropped. The buffer is empty afterwards -- a parked stream is resolved once, and a stream that
 * arrives after this point is the caller's live path, not a parked one. `out_delivered` and
 * `out_dropped` may each be NULL. The return is the first callback error, or WT_OK. */
wt_status_t wt_webtransport_buffered_drain_streams(wt_webtransport_buffered_t *buffer,
                                                   uint64_t session_id,
                                                   wt_webtransport_buffered_stream_fn deliver,
                                                   void *context, size_t *out_delivered,
                                                   size_t *out_dropped);

/* Park a datagram that arrived before its session was known. 1 means it is held, 0 that it was
 * dropped over a bound (counted in `datagrams_dropped`), which is the unreliable half's answer. */
int wt_webtransport_buffered_park_datagram(wt_webtransport_buffered_t *buffer,
                                           uint64_t quarter_stream_id, const uint8_t *payload,
                                           size_t length);

/* The datagram half of the drain above: parked datagrams whose quarter stream ID is this session's
 * are delivered in arrival order, and the rest are dropped. */
wt_status_t wt_webtransport_buffered_drain_datagrams(wt_webtransport_buffered_t *buffer,
                                                     uint64_t quarter_stream_id,
                                                     wt_webtransport_buffered_datagram_fn deliver,
                                                     void *context, size_t *out_delivered,
                                                     size_t *out_dropped);

size_t wt_webtransport_buffered_stream_count(const wt_webtransport_buffered_t *buffer);
size_t wt_webtransport_buffered_datagram_count(const wt_webtransport_buffered_t *buffer);
uint64_t wt_webtransport_buffered_streams_rejected(const wt_webtransport_buffered_t *buffer);
uint64_t wt_webtransport_buffered_datagrams_dropped(const wt_webtransport_buffered_t *buffer);
uint64_t wt_webtransport_buffered_last_rejected_stream_id(const wt_webtransport_buffered_t *buffer);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_WEBTRANSPORT_BUFFERED_H */
