/* QUIC packet protection: header protection, AEAD, and packet number encoding.
 *
 * RFC 9001 sections 5.3, 5.4 and 5.5, plus RFC 9000 section 17.1 for the
 * packet number encoding. This is the layer between the key schedule and the
 * wire: it takes a packet as the sender assembled it, applies header
 * protection and the AEAD, and reverses both at the receiver.
 *
 * WHAT IS VERIFIABLE HERE. Every part of this has published vectors: RFC 9001
 * appendix A gives a complete client Initial, a complete server Initial, a
 * ChaCha20-Poly1305 short header packet and a Retry, each with the sample, the
 * mask and the final bytes. tests/security/test_wt_quic_pkt.c reproduces all
 * of them, and a mistake in the sample offset, the packet number encoding, the
 * nonce construction or the associated-data definition shows up as a mismatch
 * rather than as a packet a peer silently drops. That is unusual for protocol
 * code and it is the reason this layer is worth having first: it can be
 * finished rather than only started.
 *
 * TWO THINGS THAT ARE EASY TO GET WRONG AND ARE THEREFORE EXPLICIT HERE.
 *
 * The associated data depends on whether the packet has a long or a short
 * header, and on the packet number length. For a long header it is the whole
 * header including the unprotected packet number, from the first byte up to
 * and including the packet number. For a short header it is the same, but the
 * header has no length field so the caller must say where it ends. Getting
 * this wrong authenticates the wrong bytes and every packet is discarded with
 * no diagnostic.
 *
 * The receiver's packet number is recovered from a truncated one relative to
 * the largest packet number it has seen (RFC 9000 section 17.1). The algorithm
 * is not "append zeros": it picks the candidate in the window nearest the
 * largest seen, and appending zeros instead produces packet numbers that are
 * wrong by up to half the encoding range -- which fails authentication only
 * when it happens to recover a different number than the sender used.
 */

#ifndef WT_QUIC_PKT_H
#define WT_QUIC_PKT_H

#include <stddef.h>
#include <stdint.h>

#include "wt_tls.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The largest packet number QUIC allows (RFC 9000 section 12.3). */
#define WT_QUIC_MAX_PACKET_NUMBER UINT64_C(4611686018427387903)

/* The longest header this layer will protect. A QUIC long header is at most
 * 1 + 4 + 1 + 20 + 1 + 20 + up to 8 length bytes + up to 4 packet number
 * bytes; 64 is comfortably above that and small enough to keep the header
 * scratch buffer on the stack. */
#define WT_QUIC_MAX_HEADER_LEN 64U

/* How a packet's header is laid out, which decides what the AEAD
 * authenticates and where header protection samples from. */
typedef struct wt_quic_packet_header {
  /* The header bytes with the packet number UNPROTECTED, exactly as the
   * sender wrote them. For a long header this includes the length field. */
  const uint8_t *bytes;
  size_t len;
  /* Offset of the packet number within `bytes`. */
  size_t pn_offset;
  /* How many bytes the packet number is encoded in: 1, 2, 3 or 4. */
  size_t pn_len;
  /* Long (Initial, Handshake, 0-RTT, Retry) or short (1-RTT). Decides which
   * bits header protection masks and what the sample offset is. */
  int long_header;
} wt_quic_packet_header_t;

/* Encode a packet number in the fewest bytes that unambiguously represent it
 * relative to `largest_acked` (RFC 9000 section 17.1).
 *
 * Returns the number of bytes to use, 1 to 4, and writes them to `out` in
 * network byte order. `out` must have room for 4 bytes. Returns 0 on a bad
 * argument or when the packet number is not greater than `largest_acked`. */
size_t wt_quic_packet_number_length(uint64_t packet_number,
                                    uint64_t largest_acked);
size_t wt_quic_encode_packet_number(uint64_t packet_number,
                                    uint64_t largest_acked, uint8_t *out);

/* Recover a full packet number from the truncated one in a received header
 * (RFC 9000 section 17.1).
 *
 * `truncated` is the value read from the `pn_len` bytes, `largest_seen` is the
 * largest packet number the receiver has successfully processed in this packet
 * number space, or 0 if none. Returns 0 on success and -1 on a bad argument.
 * The result is written to `out`. */
int wt_quic_decode_packet_number(uint64_t truncated, size_t pn_len,
                                 uint64_t largest_seen, uint64_t *out);

/* Apply or remove header protection (RFC 9001 sections 5.4.1 to 5.4.4).
 *
 * `packet` is the whole packet: the header followed by the protected payload.
 * `header` describes the header and must have `pn_offset` and `pn_len` set to
 * where the packet number is. `hp_key` is `wt_tls_traffic_keys_t.hp` and
 * `hp_len` its meaningful length (16 for AES-128-GCM, 32 for
 * ChaCha20-Poly1305); `aead` selects the mask construction.
 *
 * The same function does both directions, because header protection is an XOR
 * with a mask derived from the packet: applying it twice removes it. That is
 * worth stating because it means a caller cannot "unprotect" a packet twice by
 * mistake without noticing -- the second call restores the protection.
 *
 * `packet` must be writable and at least `header.len` bytes long. Returns 0 on
 * success, -1 on a bad argument or when the packet is too short to contain the
 * header protection sample. */
int wt_quic_header_protection(wt_tls_aead_t aead, const uint8_t *hp_key,
                              size_t hp_len,
                              const wt_quic_packet_header_t *header,
                              uint8_t *packet, size_t packet_len);

/* Encrypt a packet in place (RFC 9001 section 5.3).
 *
 * `packet` holds the unprotected header followed by the plaintext payload; on
 * success it holds the protected header followed by the ciphertext and the
 * 16-byte tag. `packet_len` is the total length on entry and `out_len` the
 * total length on exit, which is `packet_len + 16`.
 *
 * The nonce is the IV with the full packet number XORed into its rightmost
 * bytes, and the associated data is the header with the packet number in the
 * clear. Both are defined in section 5.3 and both are checked by the vectors.
 *
 * `packet` must have room for `packet_len + 16` bytes. Returns 0 on success. */
int wt_quic_protect_packet(wt_tls_aead_t aead,
                           const wt_tls_traffic_keys_t *keys,
                           const wt_quic_packet_header_t *header,
                           uint64_t packet_number, uint8_t *packet,
                           size_t packet_len, size_t *out_len);

/* Remove protection from a received packet (RFC 9001 section 5.5).
 *
 * `packet` is the protected packet as received and is treated as read-only:
 * the plaintext goes to `plaintext`, which the caller owns and which must have
 * room for `plaintext_capacity` bytes. It is a separate buffer on purpose.
 * Decrypting in place is not possible with the AEAD binding used here -- it
 * copies its input into its output buffer before working, so an overlapping
 * call would feed it its own plaintext from the second block onward -- and
 * writing into the caller's receive buffer before the tag has verified would
 * hand an unauthenticated payload to code that might read it after ignoring
 * the return value. Nothing is written to `plaintext` when the tag fails.
 *
 * `header` must have enough of the header parsed to know `bytes`, `len`,
 * `pn_offset`, `pn_len` and whether it is a long header -- which means header
 * protection has already been removed, because the length and the packet
 * number are unreadable until it has. The usual order is:
 *
 *   1. parse the first byte and the connection IDs (unprotected),
 *   2. call wt_quic_header_protection to unmask the length and packet number,
 *   3. parse the packet number, recover it, and fill in `header`,
 *   4. call this.
 *
 * Note that `header.bytes` must be the header with the packet number in the
 * CLEAR, because that is the associated data the sender authenticated. A
 * caller that passes the still-masked header will fail the tag check on every
 * packet; the vectors in the test show both the masked and unmasked forms so
 * the distinction is visible.
 *
 * Returns 0 on success with `*out_len` the plaintext length, -1 on a bad
 * argument, a tag failure, or a plaintext buffer too small. */
int wt_quic_unprotect_packet(wt_tls_aead_t aead,
                             const wt_tls_traffic_keys_t *keys,
                             const wt_quic_packet_header_t *header,
                             uint64_t packet_number, const uint8_t *packet,
                             size_t packet_len, uint8_t *plaintext,
                             size_t plaintext_capacity, size_t *out_len);

/* The nonce for a packet number: the IV with the packet number XORed into its
 * rightmost bytes, left-padded with zeros (RFC 9001 section 5.3). Exposed
 * because it is easy to write as a truncation instead, and the vectors check
 * it directly. */
int wt_quic_packet_nonce(const uint8_t iv[WT_TLS_IV_LEN],
                         uint64_t packet_number, uint8_t out[WT_TLS_IV_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* WT_QUIC_PKT_H */
