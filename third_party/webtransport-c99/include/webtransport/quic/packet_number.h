/* QUIC packet number encoding and reconstruction (RFC 9000 section 17.1 and
 * appendix A.2, RFC 9001 section 5.4).
 *
 * A packet number is sent truncated to one to four bytes, because the full
 * number is implied by the packets already seen and spending eight bytes on it
 * would be the largest field in a small packet. The receiver reconstructs it
 * against the largest number it has received, and RFC 9000 appendix A.2 gives
 * the algorithm. The window is half the truncated range: a sender must not
 * encode a number more than half the range ahead of the largest acknowledged,
 * and a receiver picks the candidate closest to its expectation.
 *
 * BOTH HALVES ARE HERE AND THEY ARE TESTED AGAINST EACH OTHER, which is the
 * point: an encoder and a decoder that are wrong in the same way round-trip
 * perfectly, so the tests also drive the RFC's own boundary cases -- the two
 * ends of the window and the cases where the expected value is near the top of
 * the 62-bit range where a naive `candidate + window` wraps.
 */

#ifndef WEBTRANSPORT_QUIC_PACKET_NUMBER_H
#define WEBTRANSPORT_QUIC_PACKET_NUMBER_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/quic/varint.h"
#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The largest packet number QUIC allows: 2^62 - 1, the same bound as a varint. */
#define WT_QUIC_PACKET_NUMBER_MAX WT_QUIC_VARINT_MAX

/* How many bytes are needed to encode `packet_number` so that a receiver whose
 * expectation is `largest_acknowledged + 1` reconstructs it exactly. Returns
 * 1..4, or 0 when the number cannot be sent: a number below the largest
 * acknowledged is in the past, and a number more than half the window ahead
 * cannot be reconstructed by the peer (RFC 9000 section 17.1).
 *
 * `largest_acknowledged` is the largest packet number the peer has acknowledged;
 * a sender with nothing acknowledged yet passes 0 and a packet number of 1 or
 * more. */
size_t wt_quic_packet_number_size(uint64_t packet_number,
                                  uint64_t largest_acknowledged);

/* Encode the low `byte_count` bytes, big-endian, into `out`. Returns the number
 * of bytes written, or 0 on a bad argument or `byte_count` outside 1..4. */
size_t wt_quic_packet_number_encode(uint64_t packet_number, size_t byte_count,
                                    uint8_t out[4]);

/* Reconstruct a full packet number from its truncated form. `truncated` holds
 * the low `byte_count` bytes as an integer; `largest_received` is the largest
 * packet number received on this packet number space, or 0 when none has been.
 * Returns the reconstructed number.
 *
 * Returns 0 for a `byte_count` outside 1..4, which is a caller's bug: the
 * length comes from a packet header this library has already parsed, and the
 * four-bit field that carries it can express 0 and values above 4 that RFC 9000
 * forbids. A caller that reaches here with one has skipped a check, and 0 is a
 * value no reconstructed packet number can legitimately be (numbers start at
 * 0 for the first packet *sent*, so a *received* number is at least 0 -- which
 * is why the refusal is a status at the call site and not here). */
uint64_t wt_quic_packet_number_decode(uint64_t truncated, size_t byte_count,
                                      uint64_t largest_received);

/* The window a truncated packet number can express, and half of it. Exposed
 * because a sender's limit on how far ahead it may send is half the window, and
 * a caller that computed it separately could get the shift wrong. */
uint64_t wt_quic_packet_number_window(size_t byte_count);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_QUIC_PACKET_NUMBER_H */
