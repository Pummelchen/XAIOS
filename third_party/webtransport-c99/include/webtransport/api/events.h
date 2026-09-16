/* The event-loop seam (Phase 8).
 *
 * A WebTransport endpoint is asynchronous: bytes arrive when the network says so, and the
 * application has to be told what they meant. This header is that telling. It is a
 * callback table with a context, and nothing else -- no thread, no queue, no hidden
 * buffer. The design rules are:
 *
 *   - THE LIBRARY NEVER CALLS A CALLBACK FROM A THREAD OF ITS OWN. Callbacks run inside
 *     the call the application made, on the application's thread, so a caller needs no
 *     synchronization it did not already have for that call.
 *
 *   - A CALLBACK MUST NOT RE-ENTER THE SESSION. Calling a feed function from inside a
 *     callback is undefined; the library does not queue what a callback reports. Deliver
 *     a datagram by returning from the callback and calling the next feed function.
 *
 *     THAT INCLUDES `wt_session_destroy` AND `wt_session_set_callbacks`, and the reason is worth stating rather
 *     than implying: releasing the handle inside a callback is the first pattern a consumer reaches for, and it
 *     cannot be made safe here. The library settles its own state and error surface BEFORE a callback runs and
 *     touches the session nowhere afterwards, so a callback that destroys the session does not corrupt this
 *     library's own write -- but the DRIVER that invoked the feed function still owns the handle when the
 *     callback returns, and it will use it. The discipline is to record the decision in the callback and act on
 *     it after the driver returns: a `closed` flag beside the loop, not `destroy` inside `on_close`.
 *
 *     A callback also reads the error surface of the call it runs inside (`wt_session_last_error`), because
 *     that surface is recorded before the callback is invoked rather than after it.
 *
 *   - NO CALLBACK MEANS THE EVENT IS ACCEPTED AND DISCARDED, not refused. A peer's
 *     datagram is not an error because this endpoint did not ask for one, and turning it
 *     into a connection error would blame the peer for our own configuration. The one
 *     exception is a bound this endpoint published: a value over it is refused, and the
 *     refusal says so.
 *
 *   - A CALLBACK OBSERVES THE STATE ITS EVENT HAS ALREADY PRODUCED. The stream table is
 *     updated before the callback runs, so `wt_session_stream_count` inside the
 *     `on_stream_opened` callback counts the new stream and inside the `end_stream` or
 *     `on_stream_reset` callback does not count the finished one. The rule is uniform on
 *     purpose: it is the same rule for all three, and it is the one that leaves the
 *     library with nothing to write after a callback returns.
 *
 *   - EVERY POINTER PASSED TO A CALLBACK IS A VIEW INTO THE CALLER'S OWN BUFFER and is
 *     valid only for the duration of the callback, exactly like the reader convention the
 *     rest of this library follows. Copy what must outlive the call.
 */

#ifndef WEBTRANSPORT_API_EVENTS_H
#define WEBTRANSPORT_API_EVENTS_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/api/session.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The largest number of concurrent peer streams one handle will track. The table is
 * fixed, because it is a bound the peer must run into rather than a limit that grows
 * with the peer's appetite; a caller that wants more than this must ask for a bigger
 * build, not a bigger allocation at run time. */
#define WT_SESSION_STREAM_MAX 64U

typedef struct wt_session_callbacks {
  /* Passed back to every callback below, untouched. */
  void *context;

  /* A WebTransport stream's prefix was read and named this session. Reported once per
   * stream, before any data from it. */
  void (*on_stream_opened)(void *context, uint64_t stream_id, int unidirectional);

  /* Data arrived on a stream that was opened. `end_stream` says the peer finished it, so
   * this is the last callback for that stream. */
  void (*on_stream_data)(void *context, uint64_t stream_id, const uint8_t *data, size_t length,
                         int end_stream);

  /* The peer reset a stream or asked this endpoint to stop sending on one. `error_code`
   * is the peer's code, carried through unchanged. No further callback arrives for that
   * stream. */
  void (*on_stream_reset)(void *context, uint64_t stream_id, uint64_t error_code);

  /* A datagram arrived, already stripped of its quarter stream ID: what is passed is the
   * session data the peer sent. Datagrams are delivered in the order they were fed. */
  void (*on_datagram)(void *context, const uint8_t *data, size_t length);

  /* The peer is draining or has closed the session. Both are also visible from
   * `wt_session_state`, so a caller that only polls does not have to use them. */
  void (*on_drain)(void *context);
  void (*on_close)(void *context, uint32_t error_code);
} wt_session_callbacks_t;

/* Install the callbacks. They may be installed at any point, replaced, or cleared with
 * NULL. Everything already reported stays reported: this does not replay. */
wt_status_t wt_session_set_callbacks(wt_session_t *session, const wt_session_callbacks_t *callbacks);

/* A WebTransport stream arrived. `session_id` is what the stream's prefix named, and it
 * must be THIS session -- a stream for another session is refused with
 * `WT_HTTP3_ID_ERROR` rather than delivered to the wrong one. */
wt_status_t wt_session_on_stream_opened(wt_session_t *session, uint64_t stream_id,
                                        int unidirectional, uint64_t session_id);

/* Data on an opened stream. Data on a stream that was never opened is `WT_ERR_STATE`:
 * the application's ordering is wrong, not the peer's. */
wt_status_t wt_session_on_stream_data(wt_session_t *session, uint64_t stream_id,
                                      const uint8_t *data, size_t length, int end_stream);

/* A reset or a stop-sending from the peer, with its code. */
wt_status_t wt_session_on_stream_reset(wt_session_t *session, uint64_t stream_id,
                                       uint64_t error_code);

/* A datagram, as it came off the wire: quarter stream ID included. It must name this
 * session, and its payload must be within the session's datagram bound. */
wt_status_t wt_session_on_datagram(wt_session_t *session, const uint8_t *data, size_t length);

/* How many peer streams are open right now, for a caller that wants to log the occupancy
 * or to test. There is no accessor for the entries: a caller that needs to know more
 * about a stream than its ID should keep its own record when it is opened. */
size_t wt_session_stream_count(const wt_session_t *session);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_API_EVENTS_H */
