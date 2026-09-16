/* Congestion control. See webtransport/quic/congestion.h. */

#include "webtransport/quic/congestion.h"

#include <string.h>

uint64_t wt_quic_congestion_initial_window(uint64_t max_datagram_size) {
  uint64_t ten_packets = WT_QUIC_INITIAL_WINDOW_PACKETS * max_datagram_size;
  uint64_t floor = WT_QUIC_MINIMUM_WINDOW_PACKETS * max_datagram_size;
  uint64_t bound = (floor > WT_QUIC_INITIAL_WINDOW_MAX) ? floor : WT_QUIC_INITIAL_WINDOW_MAX;
  return (ten_packets < bound) ? ten_packets : bound;
}

uint64_t wt_quic_congestion_minimum_window(uint64_t max_datagram_size) {
  return WT_QUIC_MINIMUM_WINDOW_PACKETS * max_datagram_size;
}

void wt_quic_congestion_init(wt_quic_congestion_t *congestion,
                             uint64_t max_datagram_size) {
  if (congestion == NULL) return;
  memset(congestion, 0, sizeof(*congestion));
  congestion->max_datagram_size = (max_datagram_size == 0U) ? 1200U : max_datagram_size;
  congestion->cwnd = wt_quic_congestion_initial_window(congestion->max_datagram_size);
  /* The threshold starts at infinity, so a new connection begins in slow start. */
  congestion->ssthresh = UINT64_MAX;
  congestion->in_recovery = 0;
  congestion->recovery_start_time = 0U;
}

uint64_t wt_quic_congestion_window(const wt_quic_congestion_t *congestion) {
  return (congestion == NULL) ? 0U : congestion->cwnd;
}

uint64_t wt_quic_congestion_ssthresh(const wt_quic_congestion_t *congestion) {
  return (congestion == NULL) ? 0U : congestion->ssthresh;
}

int wt_quic_congestion_in_recovery(const wt_quic_congestion_t *congestion) {
  return (congestion == NULL) ? 0 : congestion->in_recovery;
}

int wt_quic_congestion_in_slow_start(const wt_quic_congestion_t *congestion) {
  if (congestion == NULL) return 0;
  return congestion->cwnd < congestion->ssthresh;
}

int wt_quic_congestion_in_recovery_at(const wt_quic_congestion_t *congestion,
                                      uint64_t time_sent) {
  if (congestion == NULL || !congestion->in_recovery) return 0;
  /* "At or before": the packet that was sent at the instant the period began is part of the event,
   * because the clock granularity makes "after" and "at" indistinguishable there. */
  return time_sent <= congestion->recovery_start_time;
}

wt_status_t wt_quic_congestion_on_ack(wt_quic_congestion_t *congestion,
                                      uint64_t bytes_acked, uint64_t time_sent) {
  if (congestion == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* An acknowledgement of a packet from before the recovery period says nothing about whether the
   * network has recovered, because it was sent into the congestion that caused the period. Growing
   * the window for it would grow it during the recovery it is recovering from. */
  if (wt_quic_congestion_in_recovery_at(congestion, time_sent)) return WT_OK;

  if (congestion->cwnd < congestion->ssthresh) {
    congestion->cwnd += bytes_acked;
  } else {
    /* RFC 9002 section 7.3.1's increment. It is about one datagram per round trip *in aggregate*:
     * each acknowledgement adds mds * acked / cwnd, and the acknowledgements that make up a window's
     * worth sum to about one datagram. Integer division is what the formula specifies, so a small
     * acknowledgement against a large window adds nothing at all, and section 7.3.3 discusses why
     * that is preferred to growing faster. */
    uint64_t increase = (congestion->max_datagram_size * bytes_acked) / congestion->cwnd;
    /* A guard against the window growing by more than the data that was acknowledged, which cannot
     * happen with the numbers above but costs nothing to state. */
    if (increase > bytes_acked) increase = bytes_acked;
    congestion->cwnd += increase;
  }
  return WT_OK;
}

wt_status_t wt_quic_congestion_on_loss(wt_quic_congestion_t *congestion,
                                       uint64_t time_sent, uint64_t now) {
  uint64_t reduced;
  uint64_t floor;

  if (congestion == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* The loss of a packet from before the current period is the rest of the same burst: the window
   * was already halved for it, and halving it again per packet is what turns one congested queue
   * into a collapsed connection. */
  if (wt_quic_congestion_in_recovery_at(congestion, time_sent)) return WT_OK;

  congestion->ssthresh = (congestion->cwnd / WT_QUIC_LOSS_REDUCTION_DENOMINATOR);
  reduced = congestion->ssthresh;
  floor = wt_quic_congestion_minimum_window(congestion->max_datagram_size);
  if (reduced < floor) reduced = floor;
  /* The window is never raised by a loss: a connection whose window is already at or below the
   * halved value keeps it. */
  if (reduced < congestion->cwnd) congestion->cwnd = reduced;
  congestion->in_recovery = 1;
  congestion->recovery_start_time = now;
  return WT_OK;
}

wt_status_t wt_quic_congestion_on_persistent_congestion(
    wt_quic_congestion_t *congestion, uint64_t now) {
  if (congestion == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* RFC 9002 section 7.6: the window collapses to the minimum and a new recovery period begins, so
   * that the connection has to earn its window back rather than inherit the one it had before the
   * path stopped delivering anything. */
  congestion->cwnd = wt_quic_congestion_minimum_window(congestion->max_datagram_size);
  congestion->ssthresh = congestion->cwnd;
  congestion->in_recovery = 1;
  congestion->recovery_start_time = now;
  return WT_OK;
}

int wt_quic_congestion_can_send(const wt_quic_congestion_t *congestion,
                                uint64_t bytes_in_flight) {
  if (congestion == NULL) return 0;
  return bytes_in_flight < congestion->cwnd;
}
