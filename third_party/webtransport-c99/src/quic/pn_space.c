/* Packet number space bookkeeping. See webtransport/quic/pn_space.h. */

#include "webtransport/quic/pn_space.h"

#include <string.h>

#include "webtransport/quic/packet_number.h"
#include "webtransport/writer.h"

/* RFC 9002 section 5.3 / 6.2.1's constants, named so the arithmetic below reads as the document
 * does. */
#define WT_QUIC_TIMER_GRANULARITY 1000U      /* 1 ms, in microseconds */
#define WT_QUIC_INITIAL_RTT 333000U          /* 333 ms, in microseconds */

void wt_quic_ack_state_init(wt_quic_ack_state_t *state) {
  if (state == NULL) return;
  memset(state, 0, sizeof(*state));
}

int wt_quic_ack_contains(const wt_quic_ack_state_t *state, uint64_t packet_number) {
  size_t i;
  if (state == NULL) return 0;
  for (i = 0U; i < state->count; i++) {
    if (packet_number >= state->ranges[i].smallest &&
        packet_number <= state->ranges[i].largest) {
      return 1;
    }
  }
  return 0;
}

/* Drop the OLDEST range, which is the last one: the list is kept largest first, so "oldest" is
 * the end of it and not the start. Dropping the wrong end would acknowledge the newest packets and
 * forget the oldest, which is the opposite of what RFC 9002 section 13.2.3 permits -- the point of
 * the bound is that a peer's oldest, least useful ranges are the ones that go. */
static void drop_oldest(wt_quic_ack_state_t *state) {
  if (state->count == 0U) return;
  state->count--;
}

wt_status_t wt_quic_ack_record(wt_quic_ack_state_t *state, uint64_t packet_number,
                               int ack_eliciting) {
  size_t i;
  size_t at;

  if (state == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* A packet number that is already recorded changes nothing: a duplicate arrival is ordinary on
   * a network that reorders, and it must not create a second range or count twice towards the
   * acknowledgement debt. */
  if (wt_quic_ack_contains(state, packet_number)) return WT_OK;

  /* The ranges are kept largest first, so the search stops at the first range whose largest is
   * below the new packet number: that index is where a new range would go, the range above it (if
   * any) is the next larger one, and the range at it (if any) is the next smaller one. */
  at = state->count;
  for (i = 0U; i < state->count; i++) {
    if (packet_number > state->ranges[i].largest) {
      at = i;
      break;
    }
  }

  /* Whether the packet touches the range above it, the range below it, or both. Both cases are
   * checked even when one would do, because a packet that bridges a gap has to merge: extending
   * the upper range downwards without joining the lower one leaves two ranges where the set has
   * one, and an ACK frame built from that would tell a peer about a gap that does not exist. */
  {
    int joins_above = (at > 0U && state->ranges[at - 1U].smallest == packet_number + 1U);
    int joins_below = (at < state->count &&
                       state->ranges[at].largest == packet_number - 1U);

    if (joins_above && joins_below) {
      state->ranges[at - 1U].smallest = state->ranges[at].smallest;
      for (i = at + 1U; i < state->count; i++) {
        state->ranges[i - 1U] = state->ranges[i];
      }
      state->count--;
    } else if (joins_above) {
      state->ranges[at - 1U].smallest = packet_number;
    } else if (joins_below) {
      state->ranges[at].largest = packet_number;
    } else {
      if (state->count == WT_QUIC_RECEIVED_RANGES_MAX) {
        drop_oldest(state);
        /* The oldest range was the last one, which is at or below `at`, so an insertion point at
         * the end has to follow it in. */
        if (at > state->count) at = state->count;
      }
      for (i = state->count; i > at; i--) {
        state->ranges[i] = state->ranges[i - 1U];
      }
      state->ranges[at].smallest = packet_number;
      state->ranges[at].largest = packet_number;
      state->count++;
    }
  }

  if (!state->has_largest || packet_number > state->largest_received) {
    state->largest_received = packet_number;
    state->has_largest = 1;
  }
  state->ack_pending = 1;
  if (ack_eliciting) state->ack_eliciting_since_ack++;
  return WT_OK;
}

wt_status_t wt_quic_ack_build(const wt_quic_ack_state_t *state, uint64_t delay,
                              uint8_t *range_bytes, size_t range_capacity,
                              size_t *range_len, wt_quic_frame_t *out) {
  wt_writer_t w;
  size_t i;
  uint64_t previous_smallest;

  if (state == NULL || range_bytes == NULL || range_len == NULL || out == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  *range_len = 0U;
  if (!state->has_largest || state->count == 0U) return WT_ERR_STATE;

  memset(out, 0, sizeof(*out));
  out->kind = WT_QUIC_FRAME_KIND_ACK;
  out->as.ack.largest = state->ranges[0].largest;
  out->as.ack.delay = delay;
  out->as.ack.first_range = state->ranges[0].largest - state->ranges[0].smallest;
  out->as.ack.range_count = (uint64_t)(state->count - 1U);

  /* The extra ranges are written in their wire form, which is what the frame encoder consumes:
   * a gap from the previous range's smallest, then this range's length. RFC 9000 section 19.3.1
   * defines the gap as "the number of contiguous unacknowledged packets preceding the packet
   * number one smaller than the smallest in the previous range" -- which is why the previous
   * range's smallest, not its largest, is what the subtraction starts from. */
  w = wt_writer_init(range_bytes, range_capacity);
  previous_smallest = state->ranges[0].smallest;
  for (i = 1U; i < state->count; i++) {
    (void)wt_quic_writer_varint(&w, previous_smallest - state->ranges[i].largest - 2U);
    (void)wt_quic_writer_varint(&w, state->ranges[i].largest - state->ranges[i].smallest);
    previous_smallest = state->ranges[i].smallest;
  }
  if (!wt_writer_ok(&w)) {
    /* An ACK frame that cannot describe what it was given is refused rather than truncated: a
     * peer that is told less than arrived would retransmit what it did not need to. */
    memset(out, 0, sizeof(*out));
    return WT_ERR_LIMIT;
  }
  out->as.ack.ranges = range_bytes;
  out->as.ack.ranges_len = wt_writer_offset(&w);
  *range_len = wt_writer_offset(&w);
  return WT_OK;
}

void wt_quic_ack_sent(wt_quic_ack_state_t *state) {
  if (state == NULL) return;
  state->ack_pending = 0;
  state->ack_eliciting_since_ack = 0U;
}

int wt_quic_ack_should_send(const wt_quic_ack_state_t *state) {
  if (state == NULL) return 0;
  if (!state->ack_pending) return 0;
  /* RFC 9000 section 13.2.1: a packet that is not ACK-only has to be acknowledged promptly, and
   * so does one that fills a gap, because a sender waiting for its acknowledgement is waiting to
   * declare something lost. */
  if (state->ack_eliciting_since_ack >= 2U) return 1;
  if (state->count > 1U) return 1;
  return 0;
}

int wt_quic_ack_has_gap(const wt_quic_ack_state_t *state) {
  size_t i;
  if (state == NULL) return 0;
  for (i = 1U; i < state->count; i++) {
    if (state->ranges[i - 1U].smallest > state->ranges[i].largest + 1U) return 1;
  }
  return 0;
}

uint64_t wt_quic_ack_received_count(const wt_quic_ack_state_t *state) {
  uint64_t total = 0U;
  size_t i;
  if (state == NULL) return 0U;
  for (i = 0U; i < state->count; i++) {
    total += state->ranges[i].largest - state->ranges[i].smallest + 1U;
  }
  return total;
}

/* ------------------------------------------------------------------- rtt */

void wt_quic_rtt_init(wt_quic_rtt_t *rtt) {
  if (rtt == NULL) return;
  memset(rtt, 0, sizeof(*rtt));
}

wt_status_t wt_quic_rtt_update(wt_quic_rtt_t *rtt, uint64_t latest_rtt,
                               uint64_t ack_delay, uint64_t max_ack_delay,
                               int handshake_confirmed) {
  uint64_t adjusted;

  if (rtt == NULL) return WT_ERR_INVALID_ARGUMENT;
  rtt->latest = latest_rtt;
  if (!rtt->has_sample || latest_rtt < rtt->min_rtt) rtt->min_rtt = latest_rtt;

  /* RFC 9002 section 5.3: the peer's reported delay is capped at its own max_ack_delay and is
   * only subtracted once the handshake is confirmed. Before that, a long handshake ACK delay is
   * the peer's timer rather than a network measurement, and subtracting it would make this
   * endpoint's estimate of the network smaller than the network is. */
  adjusted = latest_rtt;
  if (handshake_confirmed && latest_rtt >= rtt->min_rtt + ack_delay) {
    uint64_t capped = (ack_delay > max_ack_delay) ? max_ack_delay : ack_delay;
    if (latest_rtt > capped) adjusted = latest_rtt - capped;
  }

  if (!rtt->has_sample) {
    rtt->smoothed = adjusted;
    rtt->rttvar = adjusted / 2U;
    rtt->has_sample = 1;
  } else {
    uint64_t difference = (rtt->smoothed > adjusted) ? rtt->smoothed - adjusted
                                                     : adjusted - rtt->smoothed;
    /* rttvar = 3/4 * rttvar + 1/4 * |smoothed_rtt - adjusted_rtt|, then
     * smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * adjusted_rtt. The order matters: the variation is
     * computed from the previous smoothed value, as section 5.3 writes it. */
    rtt->rttvar = (3U * rtt->rttvar + difference) / 4U;
    rtt->smoothed = (7U * rtt->smoothed + adjusted) / 8U;
  }
  return WT_OK;
}

wt_status_t wt_quic_rtt_pto(const wt_quic_rtt_t *rtt, uint64_t max_ack_delay,
                            uint64_t *out_micros) {
  uint64_t variation;
  uint64_t timeout;

  if (rtt == NULL || out_micros == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (!rtt->has_sample) return WT_ERR_STATE;
  variation = 4U * rtt->rttvar;
  if (variation < WT_QUIC_TIMER_GRANULARITY) variation = WT_QUIC_TIMER_GRANULARITY;
  timeout = rtt->smoothed + variation + max_ack_delay;
  *out_micros = timeout;
  return WT_OK;
}

/* ------------------------------------------------------------- the space */

void wt_quic_pn_space_init(wt_quic_pn_space_t *space) {
  if (space == NULL) return;
  memset(space, 0, sizeof(*space));
  wt_quic_ack_state_init(&space->received);
  wt_quic_rtt_init(&space->rtt);
}

wt_status_t wt_quic_pn_space_next(wt_quic_pn_space_t *space, uint64_t *out_packet_number) {
  if (space == NULL || out_packet_number == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* RFC 9000 section 12.3: a packet number is a 62-bit value and may not wrap. The connection is
   * closed rather than reusing a number, because a reused number is a nonce reused with the same
   * key. */
  if (space->has_sent && space->next_send > WT_QUIC_PACKET_NUMBER_MAX) {
    return WT_ERR_OVERFLOW;
  }
  *out_packet_number = space->next_send;
  space->next_send++;
  space->has_sent = 1;
  return WT_OK;
}

wt_status_t wt_quic_pn_space_on_ack(wt_quic_pn_space_t *space, uint64_t largest) {
  if (space == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* An ACK that arrives out of order must not move the watermark backwards: the largest
   * acknowledged is what everything else is measured against, and a smaller late ACK would make
   * this endpoint believe packets it sent are unacknowledged. */
  if (space->has_largest_acked && largest < space->largest_acked) return WT_ERR_STATE;
  space->largest_acked = largest;
  space->has_largest_acked = 1;
  return WT_OK;
}

uint64_t wt_quic_pn_space_first_in_flight(const wt_quic_pn_space_t *space) {
  if (space == NULL || !space->has_largest_acked) return 0U;
  return space->largest_acked + 1U;
}
