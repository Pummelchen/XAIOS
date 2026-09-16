/* A WebTransport session's lifecycle (draft-ietf-webtrans-http3-16 sections 3 to 5).
 *
 * A session is created by a CONNECT request that passes the session-request rules,
 * established when the response is sent, and ends in one of two ways: a graceful drain,
 * which says "finish what you have, start nothing new", and a close, which ends it at
 * once with an application error code. The draft lets either endpoint send either, so
 * the state has to remember which direction each came from.
 *
 * Three rules are the whole state machine, and each is a rule about what a session may
 * DO rather than about bytes:
 *
 *   - after a drain, in either direction, no new stream may be started for the session
 *     (existing ones may finish);
 *   - after a close, nothing at all: the session is gone, and the code it was closed
 *     with is what a caller reports;
 *   - the first close wins. A second one, from either side, does not change the code,
 *     because the session ended at the first.
 *
 * The capsules this machine sends are the ones the capsule codec writes; this layer
 * decides WHEN, which is a different question from HOW.
 */

#ifndef WEBTRANSPORT_WEBTRANSPORT_SESSION_H
#define WEBTRANSPORT_WEBTRANSPORT_SESSION_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/cursor.h"
#include "webtransport/http3/frame.h"
#include "webtransport/status.h"
#include "webtransport/webtransport/capsule.h"
#include "webtransport/writer.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum wt_webtransport_session_state {
  /* The request has been accepted; the response has not gone out. */
  WT_WEBTRANSPORT_SESSION_ESTABLISHING = 0,
  /* The response went out: streams and datagrams may flow. */
  WT_WEBTRANSPORT_SESSION_ESTABLISHED = 1,
  /* A drain was sent or received: no new streams, existing ones may finish. */
  WT_WEBTRANSPORT_SESSION_DRAINING = 2,
  /* A close was sent or received: the session is over. */
  WT_WEBTRANSPORT_SESSION_CLOSED = 3
} wt_webtransport_session_state_t;

typedef struct wt_webtransport_session {
  wt_webtransport_session_state_t state;
  /* The code the session was closed with, from whichever direction closed it first. */
  uint32_t close_error_code;
  int close_error_set;
  /* Which directions the drain and the close came from, so a caller can tell "the peer
   * is going away" from "we are". */
  int drain_sent;
  int drain_received;
  int close_sent;
  int close_received;
} wt_webtransport_session_t;

void wt_webtransport_session_init(wt_webtransport_session_t *session);

/* The response went out: the session is established. */
wt_status_t wt_webtransport_session_established(wt_webtransport_session_t *session);

/* A drain was received (the peer is going away) or sent (this endpoint is). Repeating
 * either is not an error: a drain is idempotent, and a peer may send it twice while it
 * is shutting down. */
wt_status_t wt_webtransport_session_on_drain(wt_webtransport_session_t *session, int sent);

/* A close was received, with the code its capsule carried, or sent by this endpoint. The
 * FIRST close's code is what the session ends with (section 5.4), and a close after a
 * close is accepted and ignored for the same reason. */
wt_status_t wt_webtransport_session_on_close(wt_webtransport_session_t *session, int sent,
                                             uint32_t error_code);

/* The CONNECT stream ended without a close capsule: the session is over, with no
 * application code to report (section 4.4). */
wt_status_t wt_webtransport_session_on_stream_end(wt_webtransport_session_t *session);

/* A capsule this layer does not apply, handed over so the caller can. It is called for every capsule that is not
 * the session's own -- the flow-control grants and the blocked signals, whose meaning depends on a stream table
 * and a flow account this lifecycle machine does not have -- and it may set `out_error` to the HTTP/3 code of its
 * refusal, which the walker passes on. */
typedef wt_status_t (*wt_webtransport_capsule_fn)(void *context, const wt_webtransport_capsule_t *capsule,
                                                  wt_http3_error_t *out_error);

/* Walk the capsules a peer sent on the CONNECT stream, applying the ones this layer owns.
 *
 * A session's control messages arrive on the CONNECT stream as capsules once that stream's one HEADERS frame has
 * passed (draft-16 section 5), and they arrive in whatever pieces the connection delivered: the caller keeps the
 * bytes -- a bound belongs to whoever owns the memory -- and this walks as many COMPLETE capsules as the cursor
 * holds. The drain and close capsules are applied here, because they ARE the state machine; everything else is
 * handed to `observe`, or dropped when it is NULL, which RFC 9297 section 2 makes legal for a capsule a receiver
 * does not understand (a caller that keeps no flow account cannot be lied to about one).
 *
 * WT_ERR_TRUNCATED means the bytes left in the cursor are the start of a capsule that has not fully arrived: it is
 * a WAIT, and the cursor has NOT moved past that capsule, so the caller appends the next delivery to the same
 * bytes. `max_capsule_bytes` is what the CALLER will buffer for one capsule -- the bound belongs to whoever owns
 * the memory -- so a peer's length beyond it is WT_ERR_LIMIT with H3_EXCESSIVE_LOAD rather than a wait that could
 * never end, and a capsule that merely has not arrived is the wait it is. A capsule that is malformed is
 * WT_ERR_PROTOCOL with `out_error` saying which rule; the decoder's own contract, passed through rather than
 * restated. */
wt_status_t wt_webtransport_session_on_capsule_bytes(wt_webtransport_session_t *session,
                                                     wt_cursor_t *cursor, size_t max_capsule_bytes,
                                                     wt_webtransport_capsule_fn observe, void *context,
                                                     wt_http3_error_t *out_error);

/* Whether a new stream may be started for this session: not while establishing, and not
 * after a drain or a close in either direction. */
int wt_webtransport_session_allows_new_streams(const wt_webtransport_session_t *session);

/* Write the capsule that goes with a transition. Both refuse when the session is already
 * closed, because a capsule after the end is a message the peer has no state for. */
wt_status_t wt_webtransport_session_write_drain(wt_webtransport_session_t *session, wt_writer_t *w);
wt_status_t wt_webtransport_session_write_close(wt_webtransport_session_t *session, wt_writer_t *w,
                                               uint32_t error_code, const uint8_t *reason,
                                               size_t reason_length);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_WEBTRANSPORT_SESSION_H */
