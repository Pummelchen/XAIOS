/* One packet out, one packet in (RFC 9000 section 17, RFC 9001 sections 5.3 and 5.4).
 *
 * This is the wire seam between a connection and the crypto: the headers, the packet numbers, the two
 * protections and the frame bytes, in the order the RFCs put them. It is a separate file from the
 * connection because the order is the part that is easy to get wrong and the part worth testing on its
 * own:
 *
 *   BUILDING: the header is written first, because the AEAD authenticates it; the payload is sealed
 *   with the header as associated data; the tag goes after the ciphertext; and only then is header
 *   protection applied, because its sample comes from the ciphertext. A builder that sealed the
 *   payload before writing the header would have no associated data, and one that protected the header
 *   first would mask the packet number the nonce needs.
 *
 *   READING: the sample comes from the ciphertext, so header protection is removed first; the packet
 *   number length and the low bits of the number are then readable, so the number is reconstructed
 *   against the largest this endpoint has seen; and only then can the payload be authenticated and
 *   decrypted. Each step needs the one before it, which is why a decoder cannot be reordered either.
 *
 * WHAT IS NOT HERE: which frames go in a packet, how many, and whether it may be sent at all. That is
 * flow control, congestion control and acknowledgement policy, and it belongs to the connection. This
 * file takes the frames' bytes and gives back the bytes of the datagram.
 */

#ifndef WEBTRANSPORT_QUIC_PACKET_IO_H
#define WEBTRANSPORT_QUIC_PACKET_IO_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/quic/packet.h"
#include "webtransport/quic/protection.h"
#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The largest packet this implementation builds, which is the smallest maximum datagram size QUIC
 * requires an endpoint to accept (RFC 9000 section 14.1). A caller with a larger path MTU may pass
 * more room; nothing here builds more than this without being told to. */
#define WT_QUIC_MAX_PACKET 1200U

/* The smallest datagram that may carry an Initial packet (RFC 9000 section 14.1). A client MUST
 * expand every UDP datagram carrying an Initial packet to at least this size, and a server MUST
 * discard an Initial packet whose datagram is smaller -- so an unpadded client Initial cannot start
 * a connection against a conformant server at all. */
#define WT_QUIC_MIN_INITIAL_DATAGRAM_SIZE 1200U

/* What building a packet needs. */
typedef struct wt_quic_packet_build {
  /* The encryption level: Initial or Handshake for a long header, and 0-RTT or 1-RTT for a short one.
   * A short header carries no type on the wire, which is why the caller says which it is. */
  wt_quic_packet_type_t type;
  int short_header;
  uint32_t version;
  const uint8_t *destination_connection_id;
  size_t destination_connection_id_len;
  const uint8_t *source_connection_id; /* long headers only */
  size_t source_connection_id_len;
  const uint8_t *token; /* Initial only */
  size_t token_len;
  uint64_t packet_number;
  /* The packet number's encoded length, which the caller chooses from the difference between this
   * number and the largest the peer has acknowledged (RFC 9000 section 17.1). */
  size_t packet_number_length;
  int key_phase; /* short headers */
  /* The frames, already encoded. */
  const uint8_t *payload;
  size_t payload_len;
  const wt_quic_packet_keys_t *keys;
} wt_quic_packet_build_t;

/* Build one protected packet into `out`.
 *
 * WT_ERR_LIMIT when it does not fit, which is the caller's signal that fewer frames have to go in
 * this packet; WT_ERR_INVALID_ARGUMENT for a field the header form does not allow (a token on a
 * Handshake packet, a source connection ID on a short header). */
wt_status_t wt_quic_packet_build(const wt_quic_packet_build_t *params, uint8_t *out,
                                 size_t capacity, size_t *out_len);

/* What reading a packet produced. The views point into the caller's buffer, whose ciphertext is
 * decrypted in place. */
typedef struct wt_quic_received_packet {
  /* The type a long header carries. A short header does not carry one, so this is left zeroed there
   * and `short_header` is what says which form was read. */
  wt_quic_packet_type_t type;
  int short_header;
  uint32_t version;
  const uint8_t *destination_connection_id;
  size_t destination_connection_id_len;
  const uint8_t *source_connection_id;
  size_t source_connection_id_len;
  /* The reconstructed packet number, and how many bytes it was encoded in. */
  uint64_t packet_number;
  size_t packet_number_length;
  /* The header through the packet number, which is what the AEAD authenticated. */
  size_t header_len;
  /* The decrypted frames, in place. */
  const uint8_t *payload;
  size_t payload_len;
  int key_phase;
  /* The total bytes this packet occupied in the datagram, so a caller can walk the packets that were
   * coalesced into it. */
  size_t total_len;
} wt_quic_received_packet_t;

/* Remove header protection and locate the packet number, WITHOUT touching the payload.
 *
 * This is a separate step because the Key Phase bit is one of the bits the mask owns (RFC 9001 section 5.4
 * masks the low five bits of a short header), so the phase -- and therefore which packet protection keys to
 * use -- cannot be known until the mask is off. The header protection KEY is the one thing a key update does
 * not change (section 6.1), so a caller may pass the phase it currently holds and still read a packet of any
 * phase, which is what makes a key update expressible at all.
 *
 * `out_pn_len` is what the unmasked first byte revealed, and `out_total_len` is the packet's own length, not
 * the datagram's. Every out parameter may be NULL. */
wt_status_t wt_quic_packet_unprotect_header(uint8_t *packet, size_t length,
                                            const wt_quic_packet_keys_t *keys,
                                            size_t local_connection_id_len, size_t *out_pn_offset,
                                            size_t *out_total_len, size_t *out_pn_len,
                                            int *out_short_header);

/* Decode and authenticate a packet whose header protection is ALREADY removed, with the keys the caller chose
 * for its phase. `total_len` and `pn_len` come from `wt_quic_packet_unprotect_header`; `local_connection_id_len`
 * is this endpoint's own connection ID length, which a short header does not carry. */
wt_status_t wt_quic_packet_open(uint8_t *packet, size_t total_len, size_t pn_len,
                                const wt_quic_packet_keys_t *keys, uint64_t largest_received,
                                size_t local_connection_id_len, wt_quic_received_packet_t *out);

/* Read one packet: remove header protection, reconstruct the packet number, authenticate and decrypt
 * the payload.
 *
 * `largest_received` is the largest packet number this endpoint has processed in this space, which is
 * what the reconstruction needs (RFC 9000 appendix A.3); pass 0 when none has been.
 *
 * `local_connection_id_len` is this endpoint's own connection ID length, which a short header does
 * not carry: the wire has the ID's bytes and not its length, so a decoder that guessed would look for
 * the packet number in the middle of the ID. A long header carries both lengths, so this is ignored
 * for one -- and it is ignored rather than required to be zero because a caller that does not know
 * which form it is holding is the ordinary case.
 *
 * WT_ERR_AUTHENTICATION when the tag does not verify, which is the ordinary outcome for a packet that
 * is not for this connection or not for this key, and is not the same as a protocol violation: the
 * caller discards the datagram or closes the connection, and this layer does not decide which. The
 * rest: WT_ERR_TRUNCATED when the datagram is too short to hold what its header claims or too short to
 * carry a header protection sample at all, WT_ERR_PROTOCOL for a header this implementation refuses,
 * and WT_ERR_INVALID_ARGUMENT for a Version Negotiation or a Retry, neither of which is protected by
 * the keys this takes and both of which have their own parsers.
 *
 * Nothing of the plaintext survives a failed tag: the buffer holds the unmasked header and zeroed
 * ciphertext, never unauthenticated frames (see wt_quic_unprotect_frames). */
wt_status_t wt_quic_packet_read(uint8_t *packet, size_t length,
                                const wt_quic_packet_keys_t *keys,
                                uint64_t largest_received,
                                size_t local_connection_id_len,
                                wt_quic_received_packet_t *out);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_QUIC_PACKET_IO_H */
