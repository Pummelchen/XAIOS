/* QUIC DATAGRAM. See webtransport/quic/datagram.h. */

#include "webtransport/quic/datagram.h"

#include <string.h>

#include "webtransport/quic/varint.h"

uint64_t wt_quic_datagram_max_payload(uint64_t peer_max_datagram_frame_size,
                                      uint64_t max_packet_size,
                                      uint64_t packet_overhead) {
  uint64_t by_packet;
  uint64_t by_frame;
  uint64_t length;

  if (max_packet_size <= packet_overhead) return 0U;
  /* The packet's bound: everything that is not payload. */
  by_packet = max_packet_size - packet_overhead;
  if (peer_max_datagram_frame_size == 0U) return 0U;

  /* The frame's bound: the type byte and the length field come out of the peer's limit, and the
   * length field's own width depends on the length it describes -- so the answer is the largest
   * length L with 1 + varint_size(L) + L <= limit. Trying the candidates from the largest down is
   * exact and bounded: varint_size takes four distinct values, so at most four attempts. */
  by_frame = (peer_max_datagram_frame_size > 1U) ? peer_max_datagram_frame_size - 1U : 0U;
  length = by_frame;
  for (;;) {
    uint64_t needed = 1U + (uint64_t)wt_quic_varint_size(length) + length;
    if (needed <= peer_max_datagram_frame_size) break;
    /* One byte less is not enough to change the width often, so step back by the difference rather
     * than by one: the loop runs at most a few times either way. */
    if (needed - peer_max_datagram_frame_size > length) return 0U;
    length -= (needed - peer_max_datagram_frame_size);
    if (length == 0U) return 0U;
  }
  return (length < by_packet) ? length : by_packet;
}

void wt_quic_datagram_queue_init(wt_quic_datagram_queue_t *queue) {
  if (queue == NULL) return;
  memset(queue, 0, sizeof(*queue));
}

wt_status_t wt_quic_datagram_queue_push(wt_quic_datagram_queue_t *queue,
                                        const uint8_t *data, size_t length,
                                        uint64_t received_at, int *out_discarded) {
  size_t index;

  if (out_discarded != NULL) *out_discarded = 0;
  if (queue == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (data == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (length > WT_QUIC_DATAGRAM_MAX) return WT_ERR_LIMIT;

  queue->received++;
  /* THE DISCARD IS THE NEWEST, and it is discarded rather than queued: the application has already
   * been told about everything in the queue, and a datagram is a message that was never promised. */
  if (queue->count == WT_QUIC_DATAGRAM_QUEUE_MAX) {
    queue->discarded++;
    if (out_discarded != NULL) *out_discarded = 1;
    return WT_OK;
  }
  index = (queue->head + queue->count) % WT_QUIC_DATAGRAM_QUEUE_MAX;
  if (length != 0U) memcpy(queue->entries[index].data, data, length);
  queue->entries[index].length = length;
  queue->entries[index].received_at = received_at;
  queue->count++;
  return WT_OK;
}

wt_status_t wt_quic_datagram_queue_pop(wt_quic_datagram_queue_t *queue, uint8_t *out,
                                       size_t capacity, size_t *out_length,
                                       uint64_t *out_received_at) {
  const wt_quic_datagram_t *entry;

  if (queue == NULL || out == NULL || out_length == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  *out_length = 0U;
  if (queue->count == 0U) return WT_ERR_AGAIN;
  entry = &queue->entries[queue->head];
  if (entry->length > capacity) {
    /* The caller's buffer is smaller than a datagram this queue holds, which is a caller error: the
     * entry stays queued rather than being dropped, so a caller that grows its buffer can still read
     * it. */
    return WT_ERR_LIMIT;
  }
  if (entry->length != 0U) memcpy(out, entry->data, entry->length);
  *out_length = entry->length;
  if (out_received_at != NULL) *out_received_at = entry->received_at;
  queue->head = (queue->head + 1U) % WT_QUIC_DATAGRAM_QUEUE_MAX;
  queue->count--;
  return WT_OK;
}

size_t wt_quic_datagram_queue_count(const wt_quic_datagram_queue_t *queue) {
  return (queue == NULL) ? 0U : queue->count;
}

uint64_t wt_quic_datagram_queue_received(const wt_quic_datagram_queue_t *queue) {
  return (queue == NULL) ? 0U : queue->received;
}

uint64_t wt_quic_datagram_queue_discarded(const wt_quic_datagram_queue_t *queue) {
  return (queue == NULL) ? 0U : queue->discarded;
}
