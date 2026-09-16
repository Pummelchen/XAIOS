/* QUIC DATAGRAM (RFC 9221).
 *
 * A datagram is an unreliable message: it is not retransmitted, it is not flow controlled, and it is
 * not ordered. Those three properties are what make it useful for the traffic WebTransport carries
 * and also what make it easy to get wrong in the two directions:
 *
 *   - ON SENDING, the only requirement is that the frame fits in a packet. There is no flow control
 *     to check and no acknowledgement to wait for, so the interesting question is size: the peer's
 *     `max_datagram_frame_size` bounds the frame and the path's packet size bounds the packet, and a
 *     datagram that satisfies one and not the other is one the peer will refuse or the path will
 *     fragment. `wt_quic_datagram_max_payload` answers that question for both bounds at once.
 *   - ON RECEIVING, the only requirement is a bound. A peer that sends datagrams faster than the
 *     application reads them is a peer that chooses this endpoint's memory if the queue is unbounded,
 *     so the queue is fixed and a datagram that does not fit is discarded -- which RFC 9221 section
 *     5.3 permits, and which is the right loss for a message that was never guaranteed to arrive.
 *
 * THE DISCARD POLICY IS STATED RATHER THAN IMPLIED: the NEWEST datagram is the one discarded. The
 * alternative, dropping the oldest, would throw away a message the application has already been told
 * about, and for the traffic this carries the freshest message is the one that matters least -- a
 * video frame that is late has already been superseded.
 */

#ifndef WEBTRANSPORT_QUIC_DATAGRAM_H
#define WEBTRANSPORT_QUIC_DATAGRAM_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The largest datagram this implementation will hold, which is the largest payload a QUIC packet can
 * carry at the minimum datagram size QUIC requires (RFC 9000 section 14.1). A peer that advertises
 * more than this is not refused: this endpoint simply never sends one that large. */
#define WT_QUIC_DATAGRAM_MAX 1200U

/* How many received datagrams are held for the application. Small on purpose: a queue that is deep
 * enough to hide a slow reader from a fast sender is a queue that turns a latency problem into a
 * memory problem. */
#define WT_QUIC_DATAGRAM_QUEUE_MAX 8U

/* The largest payload that fits both the peer's frame limit and the packet the path will carry.
 *
 * `peer_max_datagram_frame_size` is the peer's transport parameter (zero means it does not accept
 * datagrams at all); `max_packet_size` is the datagram size this endpoint may send; and
 * `packet_overhead` is everything in the packet that is not the payload: the header, the packet
 * number, the length fields and the tag. Returns 0 when no payload fits. */
uint64_t wt_quic_datagram_max_payload(uint64_t peer_max_datagram_frame_size,
                                      uint64_t max_packet_size,
                                      uint64_t packet_overhead);

typedef struct wt_quic_datagram {
  uint8_t data[WT_QUIC_DATAGRAM_MAX];
  size_t length;
  /* When it was received, from the connection's monotonic clock. Kept so that a caller can apply its
   * own policy -- a datagram older than a frame interval is not worth delivering -- without this file
   * having an opinion. */
  uint64_t received_at;
} wt_quic_datagram_t;

typedef struct wt_quic_datagram_queue {
  wt_quic_datagram_t entries[WT_QUIC_DATAGRAM_QUEUE_MAX];
  size_t head;
  size_t count;
  /* Counters for a caller that reports them: how many arrived and how many were discarded because
   * the queue was full. */
  uint64_t received;
  uint64_t discarded;
} wt_quic_datagram_queue_t;

void wt_quic_datagram_queue_init(wt_quic_datagram_queue_t *queue);

/* Take a received datagram into the queue.
 *
 * WT_ERR_LIMIT when the datagram is larger than any datagram this implementation holds, which is a
 * caller error rather than a peer's: the caller should not have read it. A full queue discards the
 * datagram and reports WT_OK with `*out_discarded` set, because a datagram that was never guaranteed
 * to arrive is not an error when it does not. */
wt_status_t wt_quic_datagram_queue_push(wt_quic_datagram_queue_t *queue,
                                        const uint8_t *data, size_t length,
                                        uint64_t received_at, int *out_discarded);

/* Take the oldest datagram out. WT_ERR_AGAIN when there is none, which is the ordinary case for a
 * queue that is read whenever the application asks rather than when something arrives. */
wt_status_t wt_quic_datagram_queue_pop(wt_quic_datagram_queue_t *queue, uint8_t *out,
                                       size_t capacity, size_t *out_length,
                                       uint64_t *out_received_at);

size_t wt_quic_datagram_queue_count(const wt_quic_datagram_queue_t *queue);
uint64_t wt_quic_datagram_queue_received(const wt_quic_datagram_queue_t *queue);
uint64_t wt_quic_datagram_queue_discarded(const wt_quic_datagram_queue_t *queue);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_QUIC_DATAGRAM_H */
