/* The CRYPTO stream. See webtransport/quic/crypto_stream.h.
 *
 * The receive half is a window of bytes addressed by offset, with a bitmap saying which of them have
 * arrived. The bitmap is what makes an out-of-order handshake readable without an allocation per gap:
 * delivery stops at the first byte that has not arrived, and everything after it waits, which is
 * exactly what a two-packet ClientHello needs.
 *
 * The window slides when the consumer takes bytes: the indices are relative to the read offset, so a
 * consume moves what is left down. That keeps the "does this frame fit" test a subtraction rather than
 * a growing index, and it is why the peer cannot make the buffer grow by sending far ahead -- the
 * answer is WT_ERR_LIMIT, which the connection turns into CRYPTO_BUFFER_EXCEEDED.
 */

#include "webtransport/quic/crypto_stream.h"

#include <string.h>

#include "webtransport/quic/error.h"

/* RFC 9000 section 19.6 bounds the offset of a CRYPTO frame and the length it adds, so a total beyond
 * this is not a buffer this endpoint is too small for: it is a frame the protocol does not allow. */
#define WT_QUIC_CRYPTO_MAX_OFFSET ((UINT64_C(1) << 62) - 1U)

static int byte_arrived(const wt_quic_crypto_recv_t *recv, size_t index) {
  return (recv->arrived[index / 8U] & (uint8_t)(1U << (index % 8U))) != 0U;
}

static void mark_arrived(wt_quic_crypto_recv_t *recv, size_t index) {
  recv->arrived[index / 8U] |= (uint8_t)(1U << (index % 8U));
}

void wt_quic_crypto_recv_init(wt_quic_crypto_recv_t *recv) {
  if (recv == NULL) return;
  memset(recv, 0, sizeof(*recv));
}

void wt_quic_crypto_send_init(wt_quic_crypto_send_t *send) {
  if (send == NULL) return;
  memset(send, 0, sizeof(*send));
}

wt_status_t wt_quic_crypto_recv_insert(wt_quic_crypto_recv_t *recv, uint64_t offset,
                                       const uint8_t *data, size_t length) {
  uint64_t end;
  size_t start;
  size_t i;

  if (recv == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (data == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (length == 0U) return WT_OK;
  if (offset > WT_QUIC_CRYPTO_MAX_OFFSET - (uint64_t)length) return WT_ERR_OVERFLOW;
  end = offset + (uint64_t)length;

  /* Everything here was delivered already: a peer that repeats itself is ordinary and this is not an
   * error. */
  if (end <= recv->read_offset) return WT_OK;
  if (offset < recv->read_offset) {
    size_t skip = (size_t)(recv->read_offset - offset);
    offset = recv->read_offset;
    data += skip;
    length -= skip;
  }

  /* Where the bytes land is relative to the read offset, so the fit test is about the window and not
   * about the absolute offsets. Nothing is stored when they do not fit, which is what lets the caller
   * close the connection knowing the state is unchanged. */
  if (offset - recv->read_offset >= (uint64_t)WT_QUIC_CRYPTO_BUFFER_MAX) return WT_ERR_LIMIT;
  start = (size_t)(offset - recv->read_offset);
  if (length > (size_t)WT_QUIC_CRYPTO_BUFFER_MAX - start) return WT_ERR_LIMIT;

  for (i = 0U; i < length; i++) {
    recv->data[start + i] = data[i];
    mark_arrived(recv, start + i);
  }
  if (start + length > recv->length) recv->length = start + length;
  recv->has_received = 1;
  return WT_OK;
}

size_t wt_quic_crypto_recv_available(const wt_quic_crypto_recv_t *recv,
                                     const uint8_t **out_data) {
  size_t available = 0U;

  if (out_data != NULL) *out_data = NULL;
  if (recv == NULL) return 0U;
  while (available < recv->length && byte_arrived(recv, available)) available++;
  if (out_data != NULL && available != 0U) *out_data = recv->data;
  return available;
}

wt_status_t wt_quic_crypto_recv_consume(wt_quic_crypto_recv_t *recv, size_t length) {
  uint8_t shifted[WT_QUIC_CRYPTO_BUFFER_WORDS];
  size_t bit;

  if (recv == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (length > recv->length) return WT_ERR_INVALID_ARGUMENT;
  if (length == 0U) return WT_OK;

  /* The window slides: what is left moves down, and so does the bitmap. The bitmap is shifted bit by
   * bit rather than byte by byte because the amount consumed is not a multiple of eight, and a byte
   * shift would claim bytes had arrived that had not. */
  memmove(recv->data, recv->data + length, recv->length - length);
  memset(shifted, 0, sizeof(shifted));
  for (bit = length; bit < recv->length; bit++) {
    if (byte_arrived(recv, bit)) {
      size_t at = bit - length;
      shifted[at / 8U] |= (uint8_t)(1U << (at % 8U));
    }
  }
  memcpy(recv->arrived, shifted, sizeof(shifted));
  recv->length -= length;
  recv->read_offset += (uint64_t)length;
  return WT_OK;
}

int wt_quic_crypto_recv_has_gap(const wt_quic_crypto_recv_t *recv) {
  if (recv == NULL) return 0;
  /* Data beyond the delivered prefix is a gap only if the prefix does not reach the end: bytes that
   * arrived out of order and were then joined to the prefix are not a gap any more. */
  return wt_quic_crypto_recv_available(recv, NULL) < recv->length;
}

uint64_t wt_quic_crypto_recv_read_offset(const wt_quic_crypto_recv_t *recv) {
  return recv == NULL ? 0U : recv->read_offset;
}

wt_status_t wt_quic_crypto_send_append(wt_quic_crypto_send_t *send, const uint8_t *data,
                                       size_t length) {
  if (send == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (data == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (length == 0U) return WT_OK;
  if (length > (size_t)WT_QUIC_CRYPTO_BUFFER_MAX - send->length) return WT_ERR_LIMIT;
  memcpy(send->data + send->length, data, length);
  send->length += length;
  return WT_OK;
}

wt_status_t wt_quic_crypto_send_next(const wt_quic_crypto_send_t *send, size_t max_length,
                                     uint64_t *out_offset, const uint8_t **out_data,
                                     size_t *out_length) {
  size_t unsent;

  if (send == NULL || out_offset == NULL || out_data == NULL || out_length == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (send->next_offset < send->base_offset) return WT_ERR_STATE;
  unsent = (size_t)(send->next_offset - send->base_offset);
  if (unsent >= send->length) return WT_ERR_STATE;

  *out_offset = send->next_offset;
  *out_data = send->data + unsent;
  *out_length = send->length - unsent;
  if (*out_length > max_length) *out_length = max_length;
  return WT_OK;
}

wt_status_t wt_quic_crypto_send_advance(wt_quic_crypto_send_t *send, size_t length) {
  size_t unsent;

  if (send == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (send->next_offset < send->base_offset) return WT_ERR_STATE;
  unsent = (size_t)(send->next_offset - send->base_offset);
  if (length > send->length - unsent) return WT_ERR_INVALID_ARGUMENT;
  send->next_offset += (uint64_t)length;
  return WT_OK;
}

wt_status_t wt_quic_crypto_send_retransmit(const wt_quic_crypto_send_t *send, uint64_t offset,
                                           size_t length, const uint8_t **out_data) {
  size_t start;

  if (send == NULL || out_data == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* A range that was never sent is a caller that has confused the two halves, and a range the buffer
   * no longer holds is a caller that asked for bytes it let go of. */
  if (offset >= send->next_offset) return WT_ERR_INVALID_ARGUMENT;
  if (offset < send->base_offset) return WT_ERR_STATE;
  start = (size_t)(offset - send->base_offset);
  if (start >= send->length || length > send->length - start) return WT_ERR_STATE;
  *out_data = send->data + start;
  return WT_OK;
}

int wt_quic_crypto_send_pending(const wt_quic_crypto_send_t *send) {
  if (send == NULL) return 0;
  if (send->next_offset < send->base_offset) return 0;
  return (size_t)(send->next_offset - send->base_offset) < send->length;
}
