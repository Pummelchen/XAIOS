/* Loss detection and probe timeouts (RFC 9002 sections 6.1 and 6.2).
 *
 * THE TWO RULES ARE INDEPENDENT AND BOTH ARE NEEDED. A packet is lost when a packet at least
 * three numbers higher has been acknowledged -- the packet threshold, which catches loss on a
 * path where acknowledgements arrive together -- or when it was sent long enough ago that its
 * acknowledgement should have arrived -- the time threshold, which catches loss at the tail of a
 * flight, where nothing higher has been acknowledged to compare against. A receiver that only
 * implemented one of them loses either the beginning or the end of every flight, and the symptom
 * is a connection that stalls at a particular window size.
 *
 * THIS MODULE OWNS THE SENT PACKETS AND NOT THEIR CONTENTS. What has to be retransmitted is
 * frames, and frames belong to the connection: this file keeps when each packet was sent, how big
 * it was, and whether it was ack-eliciting or in flight, and reports a lost packet's number and
 * the caller's own `tag` back through a visitor. The alternative -- storing the frames here --
 * would mean this file carried a second copy of the connection's send state, and a second copy is
 * a second thing to keep in step.
 *
 * THE LIST IS BOUNDED, AND BEING FULL IS AN ERROR RATHER THAN A DROP. A lost packet that was
 * forgotten is a packet that is never retransmitted, and the connection stalls with no symptom to
 * point at; refusing to record a packet tells the caller to detect losses (which removes packets)
 * before sending more. RFC 9002 section 6.1 leaves the bound to the implementation.
 *
 * BYTES IN FLIGHT ARE COUNTED HERE, not by the congestion controller, because "in flight" is a
 * property of what has been sent and acknowledged -- the controller reads the number rather than
 * maintaining it, so the two cannot disagree about how much of the network is occupied.
 */

#ifndef WEBTRANSPORT_QUIC_LOSS_H
#define WEBTRANSPORT_QUIC_LOSS_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/quic/pn_space.h"
#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

/* How many sent packets one space remembers. A window this size covers any realistic
 * bandwidth-delay product at the packet sizes QUIC uses, and the connection is expected to
 * acknowledge and detect losses within it. */
#define WT_QUIC_SENT_PACKETS_MAX 64U

/* RFC 9002 section 6.1's constants. */
#define WT_QUIC_PACKET_THRESHOLD 3U
#define WT_QUIC_TIME_THRESHOLD_NUMERATOR 9U
#define WT_QUIC_TIME_THRESHOLD_DENOMINATOR 8U

typedef struct wt_quic_sent_packet {
  /* The packet number space this packet belongs to, as the caller numbers them. RFC 9000 section 12.3
   * makes packet numbers per space, so a number is only unique together with its space: a list that
   * keyed on the number alone refused a Handshake packet number zero because an Initial packet number
   * zero had been sent first. The module never interprets the value beyond comparing it, which is why
   * it is a plain byte rather than this layer's enum -- the space type belongs to the connection and
   * this header must not depend on it. */
  uint8_t packet_number_space;
  uint64_t packet_number;
  uint64_t time_sent; /* microseconds, from the connection's monotonic clock */
  uint64_t size;      /* bytes on the wire, which is what congestion control accounts for */
  /* The caller's own identifier for this packet -- an index into its retransmission buffer, say.
   * This file never interprets it and hands it back with a lost packet. */
  uint64_t tag;
  /* Whether the packet needs an acknowledgement (RFC 9000 section 13.2.1) and whether it counts
   * against the congestion window at all (RFC 9002 section 2). A packet of PADDING alone is in
   * flight but not ack-eliciting. */
  int ack_eliciting;
  int in_flight;
} wt_quic_sent_packet_t;

typedef struct wt_quic_loss {
  wt_quic_sent_packet_t sent[WT_QUIC_SENT_PACKETS_MAX];
  size_t count;
  uint64_t bytes_in_flight;
  uint64_t ack_eliciting_in_flight;
  /* RFC 9002 section 6.2.1's backoff: the probe timeout doubles for each consecutive expiry that
   * produces no acknowledgement, and is reset by one. */
  uint64_t pto_count;
  /* The earliest time a packet will be declared lost by the time threshold, or 0 for "none". The
   * connection arms one timer with this and the probe timeout and takes whichever is sooner. */
  uint64_t loss_time;
} wt_quic_loss_t;

void wt_quic_loss_init(wt_quic_loss_t *loss);

/* Record a packet that was sent. WT_ERR_LIMIT when the list is full, which is the caller's signal
 * to detect losses first; nothing is recorded in that case. */
wt_status_t wt_quic_loss_on_sent(wt_quic_loss_t *loss,
                                 const wt_quic_sent_packet_t *packet);

/* Record that a packet was acknowledged and remove it.
 *
 * `rtt` and `max_ack_delay` are used to re-arm the probe timeout; `now` and `handshake_confirmed`
 * likewise. Acknowledging a packet that is not in the list is not an error -- an acknowledgement
 * can arrive for a packet this endpoint has already declared lost, which is the ordinary race
 * between a loss detection and a late acknowledgement -- and reports 0 through `out_newly_acked`
 * so a caller can tell the two apart. */
wt_status_t wt_quic_loss_on_ack(wt_quic_loss_t *loss, uint8_t packet_number_space,
                                uint64_t packet_number, const wt_quic_rtt_t *rtt, uint64_t now,
                                uint64_t max_ack_delay, int *out_newly_acked);

/* A packet that has been declared lost. */
typedef void (*wt_quic_lost_fn)(void *context, const wt_quic_sent_packet_t *packet);

/* Declare packets lost as of `now`, reporting each through `visit`, and re-arm the loss timer.
 *
 * A packet below the largest acknowledged is lost when a packet at least three numbers higher has
 * been acknowledged, or when it was sent more than 9/8 of the larger of the smoothed and latest
 * round trip times ago. The order is the order packets were sent, which is what makes a caller
 * that retransmits in that order retransmit in a useful order.
 *
 * Detection is PER SPACE (RFC 9002 appendix A keeps one sent-packet list per space), so the space is
 * an argument: an acknowledgement in one space must not declare a packet of another lost, and the
 * packet and time thresholds of one space say nothing about the others. */
wt_status_t wt_quic_loss_detect(wt_quic_loss_t *loss, uint8_t packet_number_space,
                                const wt_quic_rtt_t *rtt, uint64_t now, uint64_t largest_acked,
                                wt_quic_lost_fn visit, void *context);

/* The time at which the next packet will be declared lost by the time threshold, or 0 when no
 * packet is below the largest acknowledged. With `now` this is the loss timer. */
uint64_t wt_quic_loss_time(const wt_quic_loss_t *loss, uint8_t packet_number_space,
                           const wt_quic_rtt_t *rtt, uint64_t largest_acked);

/* Forget every packet in one space, reporting each through `visit` BEFORE it goes.
 *
 * RFC 9000 section 17.2.5.3 is what needs this: a Retry invalidates everything a client sent in the
 * Initial space, because those packets were protected with keys the server has thrown away and can never
 * be acknowledged. Leaving them in the list would hold the congestion window against bytes that will
 * never arrive, and a client that instead reset the packet number would violate the section's MUST NOT.
 * The caller's descriptor comes back through `visit`, which is what lets it re-offer what those packets
 * carried -- the same cryptographic handshake message, as the section requires.
 *
 * The packet numbers are untouched (they live in the packet number space, not here) and so is
 * `pto_count`; only the accounting for these bytes changes. Returns the number of packets forgotten. */
size_t wt_quic_loss_discard_space(wt_quic_loss_t *loss, uint8_t packet_number_space,
                                  wt_quic_lost_fn visit, void *context);

/* The probe timeout: the earliest send time among ack-eliciting packets in flight, plus the probe
 * timeout from the estimator doubled `pto_count` times (RFC 9002 sections 6.2.1 and 6.2.2).
 * WT_ERR_STATE when nothing ack-eliciting is in flight, which is when there is nothing to probe
 * for; `max_ack_delay` is the peer's delay for this space, which is zero outside the Application
 * space. */
wt_status_t wt_quic_loss_pto(const wt_quic_loss_t *loss, uint8_t packet_number_space,
                             const wt_quic_rtt_t *rtt, uint64_t max_ack_delay,
                             uint64_t *out_time);

/* Record that the probe timeout fired: the backoff doubles, and the caller is expected to send a
 * probe (RFC 9002 section 6.2.4). The doubling is bounded so that a long-lived connection whose
 * peer has gone away cannot overflow the timer into the past. */
void wt_quic_loss_on_pto(wt_quic_loss_t *loss);

uint64_t wt_quic_loss_bytes_in_flight(const wt_quic_loss_t *loss);
uint64_t wt_quic_loss_ack_eliciting_in_flight(const wt_quic_loss_t *loss);
size_t wt_quic_loss_count(const wt_quic_loss_t *loss);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_QUIC_LOSS_H */
