/* What one packet number space remembers (RFC 9000 section 12.3, RFC 9002 section 5).
 *
 * A QUIC connection has three of these -- Initial, Handshake, Application -- and each one is
 * independent: packet numbers are numbered per space, acknowledged per space, and their round
 * trip time is measured per space until the handshake is confirmed. This file is the
 * bookkeeping, with no I/O and no policy: which packets arrived, what an ACK frame should say,
 * how long a round trip takes, and which packet number to use next.
 *
 * THE RECEIVED SET IS A BOUNDED LIST OF RANGES. Storing the packet numbers that arrived would
 * be a set whose size a peer chooses -- a peer that sends a million packets is a peer that makes
 * this allocate a million entries -- and an ACK frame is a list of ranges anyway, so the ranges
 * are what is stored. When the list is full the OLDEST range is dropped, which is what RFC 9002
 * section 13.2.3 allows ("an endpoint MAY... limit the number of ACK ranges"), and which makes a
 * peer that only sends old packets lose its acknowledgements rather than this connection lose
 * its memory. A gap between two ranges is a packet that has not arrived *yet*: QUIC reorders, so
 * a gap is filled in later or declared lost, and nothing here decides which.
 *
 * THE ROUND TRIP ESTIMATOR IS RFC 9002 SECTION 5 and nothing else. The only subtlety in it is
 * the one that is easy to get wrong: the ACK delay a peer reports is capped at the peer's
 * max_ack_delay, and it is not applied at all until the handshake is confirmed -- because before
 * that, the delay is a peer's timer rather than a network measurement.
 */

#ifndef WEBTRANSPORT_QUIC_PN_SPACE_H
#define WEBTRANSPORT_QUIC_PN_SPACE_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/quic/frame.h"
#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

/* How many ranges the received set holds. RFC 9002 section 13.2.3 suggests acking at least every
 * second packet, which keeps the count small in the common case; this is the bound for the case
 * that is not common. */
#define WT_QUIC_RECEIVED_RANGES_MAX 32U

typedef struct wt_quic_received_range {
  uint64_t smallest; /* inclusive */
  uint64_t largest;  /* inclusive */
} wt_quic_received_range_t;

typedef struct wt_quic_ack_state {
  /* Largest first: the range an ACK frame's first_range describes is [0]. */
  wt_quic_received_range_t ranges[WT_QUIC_RECEIVED_RANGES_MAX];
  size_t count;
  /* Whether anything has been received at all, because packet number zero is a real packet
   * number and cannot double as "none". */
  int has_largest;
  uint64_t largest_received;
  /* How many packets that were not ACK-only have arrived since the last ACK was sent. An
   * endpoint must acknowledge those promptly, and may delay the acknowledgement of the rest
   * (RFC 9000 section 13.2.1). */
  uint64_t ack_eliciting_since_ack;
  /* Whether an acknowledgement is owed at all. */
  int ack_pending;
} wt_quic_ack_state_t;

void wt_quic_ack_state_init(wt_quic_ack_state_t *state);

/* Record that a packet arrived. `ack_eliciting` says whether it carried anything but
 * ACK/PADDING/CONNECTION_CLOSE, which is what decides whether the acknowledgement has to be
 * prompt. A packet number that is already recorded is accepted and changes nothing: a duplicate
 * is not an error and must not create a second range.
 *
 * WT_ERR_INVALID_ARGUMENT for a NULL state. */
wt_status_t wt_quic_ack_record(wt_quic_ack_state_t *state, uint64_t packet_number,
                               int ack_eliciting);

/* Whether a packet number has been recorded. */
int wt_quic_ack_contains(const wt_quic_ack_state_t *state, uint64_t packet_number);

/* Fill an ACK frame describing everything received, with `delay` already scaled into the units
 * RFC 9000 section 19.3 makes it (the caller owns the ack_delay_exponent).
 *
 * `range_bytes` receives the extra ranges in their wire form -- the gap and length varints --
 * because that is what the frame encoder consumes and what a decoded frame holds. The first
 * range's length is `ack.first_range`, and the ranges must fit `range_capacity`: WT_ERR_LIMIT if
 * they do not, rather than an ACK frame that omits what it cannot describe.
 *
 * WT_ERR_STATE when nothing has been received: there is no ACK to send. The frame's other fields
 * are left for the caller to fill in, because `ranges` must point at `range_bytes`, which is the
 * caller's buffer. */
wt_status_t wt_quic_ack_build(const wt_quic_ack_state_t *state, uint64_t delay,
                              uint8_t *range_bytes, size_t range_capacity,
                              size_t *range_len, wt_quic_frame_t *out);

/* Record that an ACK frame has been sent, which clears the debt. */
void wt_quic_ack_sent(wt_quic_ack_state_t *state);

/* Whether an acknowledgement is owed now rather than after a delay: an ACK-eliciting packet has
 * arrived (RFC 9000 section 13.2.1), or the received set is out of order, which a peer may only
 * rely on promptly. */
int wt_quic_ack_should_send(const wt_quic_ack_state_t *state);

/* Whether the received set describes a gap, which is what tells a sender that a packet may have
 * been lost. */
int wt_quic_ack_has_gap(const wt_quic_ack_state_t *state);

/* The number of packet numbers recorded. Used to bound how much work an ACK frame implies and by
 * tests; the connection itself does not need it. */
uint64_t wt_quic_ack_received_count(const wt_quic_ack_state_t *state);

/* ------------------------------------------------------------ round trip time */

typedef struct wt_quic_rtt {
  uint64_t latest;  /* the most recent sample, microseconds */
  uint64_t smoothed; /* RFC 9002 section 5.3's smoothed_rtt */
  uint64_t rttvar;   /* ... and its variation */
  uint64_t min_rtt;  /* the smallest sample seen, which never rises */
  int has_sample;
} wt_quic_rtt_t;

void wt_quic_rtt_init(wt_quic_rtt_t *rtt);

/* Update the estimator with a sample. `ack_delay` is what the peer reported, in microseconds, and
 * `max_ack_delay` is the peer's limit for it; `handshake_confirmed` says whether the delay is
 * allowed to be subtracted at all (RFC 9002 section 5.3).
 *
 * The first sample sets smoothed_rtt and sets rttvar to half of it, which is what section 5.3
 * says and what an estimator that started at zero would get wrong: a connection would begin with
 * a round trip time of zero and a probe timeout to match. */
wt_status_t wt_quic_rtt_update(wt_quic_rtt_t *rtt, uint64_t latest_rtt,
                               uint64_t ack_delay, uint64_t max_ack_delay,
                               int handshake_confirmed);

/* The probe timeout (RFC 9002 section 6.2.1): smoothed_rtt + max(4 * rttvar, 1ms) + max_ack_delay,
 * with the exponential backoff the caller applies itself because that is per-connection state.
 * Meaningless before the first sample, which is why it refuses. */
wt_status_t wt_quic_rtt_pto(const wt_quic_rtt_t *rtt, uint64_t max_ack_delay,
                            uint64_t *out_micros);

/* ------------------------------------------------------------- the space itself */

typedef struct wt_quic_pn_space {
  /* The next packet number to send in this space, and the largest the peer has acknowledged.
   * RFC 9000 section 12.3: numbers are per space and never reused. */
  uint64_t next_send;
  int has_largest_acked;
  uint64_t largest_acked;
  /* Whether any packet has been sent in this space, so that `next_send` of zero can be told from
   * "nothing sent yet". */
  int has_sent;
  wt_quic_ack_state_t received;
  wt_quic_rtt_t rtt;
} wt_quic_pn_space_t;

void wt_quic_pn_space_init(wt_quic_pn_space_t *space);

/* Take the next packet number to send, and advance. WT_ERR_OVERFLOW once the space is exhausted,
 * which RFC 9000 section 12.3 makes a connection error rather than a wrap. */
wt_status_t wt_quic_pn_space_next(wt_quic_pn_space_t *space, uint64_t *out_packet_number);

/* Record that the peer acknowledged up to `largest`: the largest acknowledged never decreases, so
 * an ACK that arrives out of order cannot move it backwards. Returns WT_ERR_STATE for a value
 * below what is already known. */
wt_status_t wt_quic_pn_space_on_ack(wt_quic_pn_space_t *space, uint64_t largest);

/* The smallest packet number still in flight, which is what loss detection measures against
 * (RFC 9002 section 6.1): one past the largest acknowledged, or zero when nothing has been
 * acknowledged. */
uint64_t wt_quic_pn_space_first_in_flight(const wt_quic_pn_space_t *space);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_QUIC_PN_SPACE_H */
