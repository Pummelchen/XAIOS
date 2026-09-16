/* Congestion control (RFC 9002 section 7, the NewReno algorithm the RFC specifies).
 *
 * THE EPOCH IS THE WHOLE IDEA. A loss event halves the window, and a burst of losses -- which is
 * what a single congested queue produces -- must halve it once rather than once per packet. So a
 * loss starts a recovery period, and every packet sent *before* that period began is part of the
 * event that caused it: its loss does not reduce the window again, and its acknowledgement does not
 * grow the window either. Getting this wrong in the permissive direction collapses the window on
 * every packet of a burst; getting it wrong in the other direction grows the window during the
 * recovery it is recovering from. Both are tested by sending a burst and checking that the window
 * moved exactly once.
 *
 * THIS FILE DOES NOT COUNT BYTES. How many bytes are in flight is a property of what has been sent
 * and acknowledged, which is the loss module's bookkeeping; this file reads that number and decides
 * whether another packet may be sent. The alternative -- both files counting -- is two numbers that
 * disagree after the first retransmission.
 *
 * WHAT IS NOT HERE: the pacing rate (RFC 9002 section 7.7) and the HyStart++ slow start exit
 * (section 7.8), neither of which the RFC requires, and the application-limited rule (section 7.8's
 * "cwnd is not increased if the sender is application limited"), which the caller knows and this
 * file does not. Persistent congestion is here as an effect the caller asks for, because the
 * *condition* needs the loss history that the connection has and this file does not.
 */

#ifndef WEBTRANSPORT_QUIC_CONGESTION_H
#define WEBTRANSPORT_QUIC_CONGESTION_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

/* RFC 9002 section 7.2's constants. */
#define WT_QUIC_INITIAL_WINDOW_PACKETS 10U
#define WT_QUIC_MINIMUM_WINDOW_PACKETS 2U
#define WT_QUIC_INITIAL_WINDOW_MAX 14720U /* the 14720 bytes of the RFC's formula */
#define WT_QUIC_LOSS_REDUCTION_NUMERATOR 1U
#define WT_QUIC_LOSS_REDUCTION_DENOMINATOR 2U

/* The window an endpoint starts with: min(10 * max_datagram_size, max(2 * max_datagram_size,
 * 14720)). The 14720 is RFC 6928's initial window, and the max() is what keeps a small datagram
 * size from making the initial window smaller than the congestion controller's minimum. */
uint64_t wt_quic_congestion_initial_window(uint64_t max_datagram_size);

/* The floor the window may never go below: two datagrams, one in each direction (RFC 9002
 * section 7.2). Below it a connection could not send even a probe. */
uint64_t wt_quic_congestion_minimum_window(uint64_t max_datagram_size);

typedef struct wt_quic_congestion {
  uint64_t cwnd;
  uint64_t max_datagram_size;
  /* The slow start threshold. The RFC starts it at infinity, which is what makes a connection begin
   * in slow start; UINT64_MAX is that, and slow start is what a window below it means. */
  uint64_t ssthresh;
  /* The send time at which the current recovery period began, and whether there is one. A packet
   * sent at or before it belongs to the event that started the period. */
  uint64_t recovery_start_time;
  int in_recovery;
} wt_quic_congestion_t;

void wt_quic_congestion_init(wt_quic_congestion_t *congestion,
                             uint64_t max_datagram_size);

uint64_t wt_quic_congestion_window(const wt_quic_congestion_t *congestion);
uint64_t wt_quic_congestion_ssthresh(const wt_quic_congestion_t *congestion);
int wt_quic_congestion_in_recovery(const wt_quic_congestion_t *congestion);

/* Whether a packet sent at `time_sent` belongs to the current recovery period, and so may not move
 * the window in either direction. */
int wt_quic_congestion_in_recovery_at(const wt_quic_congestion_t *congestion,
                                      uint64_t time_sent);

/* An acknowledged packet, by the bytes it carried and the time it was sent.
 *
 * In slow start the window grows by the acknowledged bytes -- which doubles it per round trip --
 * and in congestion avoidance by at most one datagram per round trip, as
 * max_datagram_size * acked / cwnd (RFC 9002 section 7.3.1). The division is integer division, so a
 * small acknowledgement against a large window adds nothing; that is the RFC's formula and section
 * 7.3.3 discusses why it is preferred to growing faster. */
wt_status_t wt_quic_congestion_on_ack(wt_quic_congestion_t *congestion,
                                      uint64_t bytes_acked, uint64_t time_sent);

/* A lost packet, by the time it was sent. The first loss of an event halves the window, sets the
 * slow start threshold to what the window was, and begins a recovery period at `now`; a loss of a
 * packet that belongs to that period changes nothing (RFC 9002 section 7.3.2). */
wt_status_t wt_quic_congestion_on_loss(wt_quic_congestion_t *congestion,
                                       uint64_t time_sent, uint64_t now);

/* Persistent congestion: the connection decides that everything it sent over a long enough period
 * was lost, and collapses the window to the minimum and starts a new recovery period (RFC 9002
 * section 7.6). The condition needs the loss history; the effect is here. */
wt_status_t wt_quic_congestion_on_persistent_congestion(
    wt_quic_congestion_t *congestion, uint64_t now);

/* Whether a packet may be sent: there has to be room in the window (RFC 9002 section 7). A caller
 * with nothing to send is application limited, which this file deliberately does not model. */
int wt_quic_congestion_can_send(const wt_quic_congestion_t *congestion,
                                uint64_t bytes_in_flight);

/* Whether the connection is in slow start, which is what a caller's slow start exit rule (if it has
 * one) needs to know. */
int wt_quic_congestion_in_slow_start(const wt_quic_congestion_t *congestion);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_QUIC_CONGESTION_H */
