/* Loss detection and probe timeouts. See webtransport/quic/loss.h. */

#include "webtransport/quic/loss.h"

#include <string.h>

/* The largest backoff exponent. RFC 9002 section 6.2.1 doubles the probe timeout for each
 * consecutive expiry, and an unbounded doubling eventually overflows the clock arithmetic into a
 * timeout that can never fire. Sixteen doublings take a 333 ms timeout past nine hours, which is
 * long past the point where a connection with no reply is dead anyway. */
#define WT_QUIC_PTO_MAX_BACKOFF 16U

void wt_quic_loss_init(wt_quic_loss_t *loss) {
  if (loss == NULL) return;
  memset(loss, 0, sizeof(*loss));
}

static size_t find_packet(const wt_quic_loss_t *loss, uint8_t packet_number_space,
                          uint64_t packet_number) {
  size_t i;
  for (i = 0U; i < loss->count; i++) {
    if (loss->sent[i].packet_number_space == packet_number_space &&
        loss->sent[i].packet_number == packet_number) {
      return i;
    }
  }
  return loss->count;
}

wt_status_t wt_quic_loss_on_sent(wt_quic_loss_t *loss,
                                 const wt_quic_sent_packet_t *packet) {
  if (loss == NULL || packet == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* A packet number is never reused (RFC 9000 section 12.3), so recording one twice is a caller
   * that has lost track of what it sent, and appending it again would double-count its bytes. */
  if (find_packet(loss, packet->packet_number_space, packet->packet_number) != loss->count) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (loss->count == WT_QUIC_SENT_PACKETS_MAX) {
    /* Refused rather than dropped: a forgotten packet is one that is never declared lost and
     * never retransmitted, and the stall it causes names nothing. */
    return WT_ERR_LIMIT;
  }
  loss->sent[loss->count] = *packet;
  loss->count++;
  if (packet->in_flight) loss->bytes_in_flight += packet->size;
  if (packet->ack_eliciting) loss->ack_eliciting_in_flight++;
  return WT_OK;
}

static void remove_packet(wt_quic_loss_t *loss, size_t at) {
  const wt_quic_sent_packet_t *packet = &loss->sent[at];
  if (packet->in_flight) {
    loss->bytes_in_flight -= (loss->bytes_in_flight >= packet->size)
                                 ? packet->size
                                 : loss->bytes_in_flight;
  }
  if (packet->ack_eliciting && loss->ack_eliciting_in_flight > 0U) {
    loss->ack_eliciting_in_flight--;
  }
  if (at + 1U < loss->count) {
    memmove(&loss->sent[at], &loss->sent[at + 1U],
            (loss->count - at - 1U) * sizeof(loss->sent[0]));
  }
  loss->count--;
}

wt_status_t wt_quic_loss_on_ack(wt_quic_loss_t *loss, uint8_t packet_number_space,
                                uint64_t packet_number, const wt_quic_rtt_t *rtt, uint64_t now,
                                uint64_t max_ack_delay, int *out_newly_acked) {
  size_t at;

  if (loss == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (out_newly_acked != NULL) *out_newly_acked = 0;
  at = find_packet(loss, packet_number_space, packet_number);
  if (at == loss->count) {
    /* An acknowledgement for a packet already declared lost is the ordinary race between loss
     * detection and a late acknowledgement, not an error. */
    return WT_OK;
  }
  {
    int was_ack_eliciting = loss->sent[at].ack_eliciting;
    remove_packet(loss, at);
    if (out_newly_acked != NULL) *out_newly_acked = 1;
    /* RFC 9002 section 6.2.1: "A sender computes its PTO ... pto_count is reset to 0 when ... an
     * ack-eliciting packet is acknowledged." Only an ack-eliciting one: acknowledging a packet
     * that needed no acknowledgement says nothing about whether the peer is still there. */
    if (was_ack_eliciting) loss->pto_count = 0U;
  }
  (void)rtt;
  (void)now;
  (void)max_ack_delay;
  return WT_OK;
}

/* 9/8 of the larger of the smoothed and latest round trip times. Computed as
 * (value * 9) / 8 with the multiplication first, which is the order that keeps the precision. */
static uint64_t loss_delay(const wt_quic_rtt_t *rtt) {
  uint64_t base;
  if (rtt == NULL || !rtt->has_sample) return 0U;
  base = (rtt->smoothed > rtt->latest) ? rtt->smoothed : rtt->latest;
  return (base * WT_QUIC_TIME_THRESHOLD_NUMERATOR) / WT_QUIC_TIME_THRESHOLD_DENOMINATOR;
}

uint64_t wt_quic_loss_time(const wt_quic_loss_t *loss, uint8_t packet_number_space,
                           const wt_quic_rtt_t *rtt, uint64_t largest_acked) {
  uint64_t delay;
  uint64_t earliest = 0U;
  size_t i;

  if (loss == NULL) return 0U;
  delay = loss_delay(rtt);
  if (delay == 0U) return 0U;
  for (i = 0U; i < loss->count; i++) {
    const wt_quic_sent_packet_t *packet = &loss->sent[i];
    uint64_t when;
    if (packet->packet_number_space != packet_number_space) continue;
    if (packet->packet_number > largest_acked) continue;
    /* A packet that has already met the packet threshold is lost on the next detection rather
     * than by a timer. */
    if (largest_acked >= packet->packet_number + WT_QUIC_PACKET_THRESHOLD) continue;
    when = packet->time_sent + delay;
    if (earliest == 0U || when < earliest) earliest = when;
  }
  return earliest;
}

wt_status_t wt_quic_loss_detect(wt_quic_loss_t *loss, uint8_t packet_number_space,
                                const wt_quic_rtt_t *rtt, uint64_t now, uint64_t largest_acked,
                                wt_quic_lost_fn visit, void *context) {
  uint64_t delay;
  uint64_t lost_send_time;
  size_t i;

  if (loss == NULL) return WT_ERR_INVALID_ARGUMENT;
  delay = loss_delay(rtt);
  lost_send_time = (now > delay) ? now - delay : 0U;

  /* The list is walked with an index that is not advanced when a packet is removed, so that the
   * packet after it -- which has moved into its place -- is examined too. */
  i = 0U;
  while (i < loss->count) {
    const wt_quic_sent_packet_t *packet = &loss->sent[i];
    int lost = 0;
    if (packet->packet_number_space == packet_number_space &&
        packet->packet_number <= largest_acked) {
      if (largest_acked >= packet->packet_number + WT_QUIC_PACKET_THRESHOLD) {
        lost = 1; /* The packet threshold: three numbers higher has arrived. */
      } else if (delay != 0U && packet->time_sent <= lost_send_time) {
        lost = 1; /* The time threshold: its acknowledgement is overdue. */
      }
    }
    if (!lost) {
      i++;
      continue;
    }
    if (visit != NULL) visit(context, packet);
    remove_packet(loss, i);
  }
  loss->loss_time = wt_quic_loss_time(loss, packet_number_space, rtt, largest_acked);
  return WT_OK;
}

wt_status_t wt_quic_loss_pto(const wt_quic_loss_t *loss, uint8_t packet_number_space,
                             const wt_quic_rtt_t *rtt, uint64_t max_ack_delay,
                             uint64_t *out_time) {
  uint64_t base_pto = 0U;
  uint64_t earliest = 0U;
  size_t i;
  wt_status_t status;

  if (loss == NULL || rtt == NULL || out_time == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (loss->ack_eliciting_in_flight == 0U) {
    /* Nothing outstanding that needs an answer: there is nothing to probe for, and a timer for it
     * would fire forever. */
    return WT_ERR_STATE;
  }
  status = wt_quic_rtt_pto(rtt, max_ack_delay, &base_pto);
  if (status != WT_OK) return status;
  for (i = 0U; i < loss->pto_count && i < WT_QUIC_PTO_MAX_BACKOFF; i++) {
    base_pto *= 2U;
  }
  for (i = 0U; i < loss->count; i++) {
    const wt_quic_sent_packet_t *packet = &loss->sent[i];
    if (packet->packet_number_space != packet_number_space) continue;
    uint64_t when;
    if (!packet->ack_eliciting) continue;
    when = packet->time_sent + base_pto;
    if (earliest == 0U || when < earliest) earliest = when;
  }
  if (earliest == 0U) return WT_ERR_STATE;
  *out_time = earliest;
  return WT_OK;
}

void wt_quic_loss_on_pto(wt_quic_loss_t *loss) {
  if (loss == NULL) return;
  if (loss->pto_count < WT_QUIC_PTO_MAX_BACKOFF) loss->pto_count++;
}

uint64_t wt_quic_loss_bytes_in_flight(const wt_quic_loss_t *loss) {
  return (loss == NULL) ? 0U : loss->bytes_in_flight;
}

uint64_t wt_quic_loss_ack_eliciting_in_flight(const wt_quic_loss_t *loss) {
  return (loss == NULL) ? 0U : loss->ack_eliciting_in_flight;
}

size_t wt_quic_loss_count(const wt_quic_loss_t *loss) {
  return (loss == NULL) ? 0U : loss->count;
}

size_t wt_quic_loss_discard_space(wt_quic_loss_t *loss, uint8_t packet_number_space,
                                  wt_quic_lost_fn visit, void *context) {
  size_t discarded = 0U;
  size_t at = 0U;

  if (loss == NULL) return 0U;
  while (at < loss->count) {
    if (loss->sent[at].packet_number_space != packet_number_space) {
      at++;
      continue;
    }
    /* Told BEFORE it is removed, because the descriptor it names is about to become unreachable and the
     * caller is the only one who can re-offer what the packet carried. */
    if (visit != NULL) visit(context, &loss->sent[at]);
    remove_packet(loss, at);
    discarded++;
  }
  if (discarded > 0U) {
    /* The timer was armed for a packet that may be gone; the next detection recomputes it, and a stale
     * deadline would fire a probe for a space this endpoint has already thrown away. */
    loss->loss_time = 0U;
  }
  return discarded;
}
