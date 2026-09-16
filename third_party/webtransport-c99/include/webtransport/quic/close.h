/* Connection close paths (RFC 9000 sections 10.2 and 19.19).
 *
 * THE TWO FORMS OF CONNECTION_CLOSE ARE DIFFERENT MESSAGES, and a connection that sends the wrong one
 * is telling the peer something it cannot act on: the transport form carries a transport error code
 * plus the frame type that caused it, and the application form carries an application error code and
 * nothing else. An application error code read as a transport error names the wrong problem, and a
 * transport error read as an application error loses the frame type that says which frame was
 * refused.
 *
 * THE DRAINING PERIOD IS THREE PROBE TIMEOUTS (RFC 9000 section 10.2.2), which is the time an
 * endpoint that has closed waits before forgetting the connection. It exists because a closing
 * endpoint does not know whether its CONNECTION_CLOSE arrived: it keeps answering retransmissions
 * long enough for the peer to learn the connection is over, and no longer. RFC 9000 section 10.2.1
 * says what may still be processed during it, and the rule is narrow -- a packet that carries only
 * CONNECTION_CLOSE, PADDING or a probe -- because anything else is an endpoint that has not yet
 * heard the connection is closed, and acting on its frames would be acting on a dead connection.
 *
 * WHAT IS NOT HERE: the packet that carries the close. Which encryption level it goes at, and whether
 * it fits, belongs to the connection runtime; this file owns the state, the frame and the timer.
 */

#ifndef WEBTRANSPORT_QUIC_CLOSE_H
#define WEBTRANSPORT_QUIC_CLOSE_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/quic/frame.h"
#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The multiplier on the probe timeout for the draining period (RFC 9000 section 10.2.2). */
#define WT_QUIC_DRAINING_PERIOD_PTO_MULTIPLIER 3U

typedef enum wt_quic_close_kind {
  WT_QUIC_CLOSE_NONE = 0,
  /* The transport failed: an error code from RFC 9000 section 20 plus the frame type that caused it,
   * or 0 for a frame that has no type of its own. */
  WT_QUIC_CLOSE_TRANSPORT,
  /* The application asked to close, with an application error code (RFC 9000 section 20.5 leaves the
   * meaning to the application). */
  WT_QUIC_CLOSE_APPLICATION
} wt_quic_close_kind_t;

typedef struct wt_quic_close_state {
  wt_quic_close_kind_t kind;
  uint64_t error_code;
  uint64_t frame_type;
  /* The reason phrase, a view into the caller's memory: the state does not own it, and RFC 9000
   * section 19.19 makes it a UTF-8 string rather than something to validate here. */
  const uint8_t *reason;
  size_t reason_length;
  /* When the connection closed and when its draining period ends, from the connection's monotonic
   * clock. */
  uint64_t closed_at;
  uint64_t draining_until;
  int has_draining_deadline;
} wt_quic_close_state_t;

void wt_quic_close_state_init(wt_quic_close_state_t *state);

/* Close for a transport error. `frame_type` is the frame that caused it, or 0 when none did -- which
 * is why the frame member carries a flag of its own rather than using 0 to mean "absent". */
wt_status_t wt_quic_close_transport(wt_quic_close_state_t *state, uint64_t error_code,
                                    uint64_t frame_type, const uint8_t *reason,
                                    size_t reason_length, uint64_t now, uint64_t pto);

/* Close at the application's request. */
wt_status_t wt_quic_close_application(wt_quic_close_state_t *state, uint64_t error_code,
                                      const uint8_t *reason, size_t reason_length,
                                      uint64_t now, uint64_t pto);

int wt_quic_close_is_closed(const wt_quic_close_state_t *state);
wt_quic_close_kind_t wt_quic_close_kind(const wt_quic_close_state_t *state);

/* Whether the draining period is over, at which point the connection is forgotten rather than kept
 * for a peer that has stopped listening. */
int wt_quic_close_draining_expired(const wt_quic_close_state_t *state, uint64_t now);

/* The frame to send, filled in for the frame encoder. The reason is not copied: the caller's bytes
 * are the frame's reason. */
wt_status_t wt_quic_close_frame(const wt_quic_close_state_t *state, wt_quic_frame_t *out);

/* Whether a frame type may still be processed once the connection has closed: CONNECTION_CLOSE,
 * PADDING, and the probe frames that a peer's own timeout sends. RFC 9000 section 10.2.1's list, and
 * it is deliberately narrow. */
int wt_quic_close_accepts_frame_type(uint64_t frame_type);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_QUIC_CLOSE_H */
