/*
 * The CRYPTO stream: handshake bytes, which arrive as offsets rather than in order.
 *
 * A CRYPTO frame carries an offset and bytes (RFC 9000 section 19.6), so a receiver has to put them
 * back in order before TLS can read them, and it has to do that with memory the PEER chooses how to
 * fill -- which is why both halves here are bounded buffers and a frame that does not fit is refused by
 * name rather than grown into. The name is WT_QUIC_CRYPTO_BUFFER_EXCEEDED: RFC 9000 section 20.1 gives
 * that a transport error code of its own, which is what a connection tells the peer when the peer's
 * handshake does not fit.
 *
 * TWO HALVES, ONE STREAM EACH DIRECTION.
 *
 * The receive half holds the bytes that have arrived, delivered only in order: a gap stops delivery
 * until it is filled, which is what makes a handshake message that was split across two packets
 * readable at all. Bytes behind the read offset are dropped, because the peer re-sending what was
 * already delivered is ordinary and not an error.
 *
 * The send half holds the bytes this endpoint has produced and not yet had acknowledged, with the
 * offset of the next one to hand out. A lost packet is retransmitted from it, which is why the bytes
 * are kept after they are first sent: RFC 9002 section 6.1 declares a packet lost by a time threshold
 * as well as by a packet threshold, so a packet can be lost after a later one was acknowledged, and its
 * bytes are still needed. The buffer is sized for a handshake; a handshake that does not fit it is
 * WT_ERR_LIMIT and a caller that wants more allocates its own and passes the bytes in.
 */

#ifndef WEBTRANSPORT_QUIC_CRYPTO_STREAM_H
#define WEBTRANSPORT_QUIC_CRYPTO_STREAM_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The bytes one direction of one encryption level can hold. A TLS 1.3 handshake flight is a few
 * kilobytes -- RFC 8448's server flight is about 1.5 KB -- and the Initial and Handshake levels each
 * have their own pair of buffers, so this is generous for the data it holds and small enough that a
 * peer cannot make an endpoint hold much. */
#define WT_QUIC_CRYPTO_BUFFER_MAX 4096U

/* The bitmap's words per byte, for a caller that wants to size something. */
#define WT_QUIC_CRYPTO_BUFFER_WORDS (WT_QUIC_CRYPTO_BUFFER_MAX / 8U)

typedef struct wt_quic_crypto_recv {
  /* The offset of the next byte the consumer will take, which is what "delivered up to here" means. */
  uint64_t read_offset;
  /* Bytes held from `read_offset`, and how many of them have arrived. A hole inside the span is a
   * byte the peer has not sent yet, and delivery stops at the first one. */
  size_t length;
  int has_received;
  uint8_t data[WT_QUIC_CRYPTO_BUFFER_MAX];
  uint8_t arrived[WT_QUIC_CRYPTO_BUFFER_WORDS];
} wt_quic_crypto_recv_t;

typedef struct wt_quic_crypto_send {
  /* The offset of the next byte that has never been sent, and the offset of data[0]. */
  uint64_t next_offset;
  uint64_t base_offset;
  size_t length;
  uint8_t data[WT_QUIC_CRYPTO_BUFFER_MAX];
} wt_quic_crypto_send_t;

/* Reset both halves. A receive half with no bytes has received nothing, which is not the same as
 * having received bytes at offset zero. */
void wt_quic_crypto_recv_init(wt_quic_crypto_recv_t *recv);
void wt_quic_crypto_send_init(wt_quic_crypto_send_t *send);

/* Insert `length` bytes that arrived at `offset`. Duplicate and overlapping data is accepted and
 * changes nothing about what is delivered; data below the read offset is dropped, because a peer that
 * repeats what was already delivered is ordinary.
 *
 * WT_ERR_LIMIT when the bytes would not fit the buffer. Nothing is stored in that case, so the caller
 * can close the connection with WT_QUIC_CRYPTO_BUFFER_EXCEEDED and know the state is unchanged.
 * WT_ERR_OVERFLOW when the offset itself cannot be expressed (RFC 9000 section 19.6 bounds a CRYPTO
 * offset), and WT_ERR_INVALID_ARGUMENT for a null pointer or a length that does not match its data. */
wt_status_t wt_quic_crypto_recv_insert(wt_quic_crypto_recv_t *recv, uint64_t offset,
                                       const uint8_t *data, size_t length);

/* The bytes that can be delivered now: a pointer to them and their length, zero when the first byte
 * of the span has not arrived. The pointer is valid until the next insert or consume. */
size_t wt_quic_crypto_recv_available(const wt_quic_crypto_recv_t *recv, const uint8_t **out_data);

/* Consume `length` bytes that were delivered, which must not exceed what `available` reported. */
wt_status_t wt_quic_crypto_recv_consume(wt_quic_crypto_recv_t *recv, size_t length);

/* Whether anything has arrived ahead of the delivered prefix, which is what tells a caller that the
 * handshake is waiting for a gap to be filled rather than for more data. */
int wt_quic_crypto_recv_has_gap(const wt_quic_crypto_recv_t *recv);

/* The next byte the consumer needs, which is what a caller reports when it asks the peer to send
 * again (RFC 9000 section 13.3 leaves that to the transport, and this is the offset it would name). */
uint64_t wt_quic_crypto_recv_read_offset(const wt_quic_crypto_recv_t *recv);

/* Append the bytes of a handshake message the TLS machine produced. WT_ERR_LIMIT when they do not
 * fit. */
wt_status_t wt_quic_crypto_send_append(wt_quic_crypto_send_t *send, const uint8_t *data,
                                       size_t length);

/* The range to hand out next: the bytes from the next never-sent offset to the end of what is held.
 * WT_ERR_STATE when everything has been sent. `*out_length` may be capped by `max_length`, which is how
 * a caller keeps a packet inside its path limit. */
wt_status_t wt_quic_crypto_send_next(const wt_quic_crypto_send_t *send, size_t max_length,
                                     uint64_t *out_offset, const uint8_t **out_data,
                                     size_t *out_length);

/* Record that `length` bytes from the next unsent offset have been sent, so that the next call to
 * `wt_quic_crypto_send_next` starts after them. */
wt_status_t wt_quic_crypto_send_advance(wt_quic_crypto_send_t *send, size_t length);

/* The bytes of a range that has to be sent again after a loss. The bytes are still held because a
 * packet can be declared lost after a later one was acknowledged; a range the buffer no longer holds
 * is WT_ERR_STATE, and a range that has never been sent is WT_ERR_INVALID_ARGUMENT, because a caller
 * that asks for one has confused the two halves. */
wt_status_t wt_quic_crypto_send_retransmit(const wt_quic_crypto_send_t *send, uint64_t offset,
                                           size_t length, const uint8_t **out_data);

/* Whether anything is waiting to be sent for the first time. */
int wt_quic_crypto_send_pending(const wt_quic_crypto_send_t *send);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_QUIC_CRYPTO_STREAM_H */
