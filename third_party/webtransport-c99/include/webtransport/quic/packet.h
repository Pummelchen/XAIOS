/* QUIC packet headers (RFC 9000 sections 17.2 and 17.3).
 *
 * Two shapes. A LONG header names a version and two connection IDs and comes in
 * four types; a SHORT header has no version, no source connection ID and no
 * type, because by the time it is used both ends know them. The first byte's top
 * bit is the whole of the discrimination, so it is the first thing every decoder
 * here reads.
 *
 * WHAT IS NOT HERE: packet protection. The header is parsed as it appears on the
 * wire, with the packet number truncated and the payload opaque. Removing header
 * protection and decrypting is the next phase's job, and it has to happen before
 * most of these fields can be trusted -- the reserved bits and the packet number
 * length are the two fields that header protection covers, which is why a
 * decoder here checks the reserved bits and reports them rather than relying on
 * them.
 *
 * COALESCING IS WHY THE LENGTH IS RETURNED. A UDP datagram may carry several
 * QUIC packets back to back, and a long header's Length field says where the
 * packet ends, so a decoder reports the total size it consumed and a caller
 * walks the datagram. A short header has no length field and is therefore always
 * last, which is a rule of the protocol and not a limitation of this parser.
 *
 * A SHORT HEADER NEEDS THE CONNECTION ID LENGTH FROM THE CALLER. The wire does
 * not carry it -- the receiver knows which connection the packet belongs to
 * because it just matched the ID, whose length it chose -- so a decoder that
 * guessed would read the packet number out of the middle of the connection ID.
 */

#ifndef WEBTRANSPORT_QUIC_PACKET_H
#define WEBTRANSPORT_QUIC_PACKET_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/cursor.h"
#include "webtransport/quic/error.h"
#include "webtransport/quic/frame.h"
#include "webtransport/quic/varint.h"
#include "webtransport/status.h"
#include "webtransport/writer.h"

#ifdef __cplusplus
extern "C" {
#endif

/* QUIC version 1 (RFC 9000). Version negotiation is a separate exchange and is
 * not implemented; a caller comparing this constant is doing the check the
 * multiplexer would do. */
#define WT_QUIC_VERSION_1 ((uint32_t)0x00000001U)

/* The version in a Version Negotiation packet, which has no version of its own
 * (RFC 9000 section 17.2.1). */
#define WT_QUIC_VERSION_NEGOTIATION ((uint32_t)0x00000000U)

/* A long header's type, from bits 4 and 5 of the first byte. */
typedef enum wt_quic_packet_type {
  WT_QUIC_PACKET_INITIAL = 0,
  WT_QUIC_PACKET_ZERO_RTT = 1,
  WT_QUIC_PACKET_HANDSHAKE = 2,
  WT_QUIC_PACKET_RETRY = 3
} wt_quic_packet_type_t;

/* The fixed bit, RFC 9000 section 17.2: "Packets that have the Fixed Bit set to
 * 0 ... are not valid packets in this version and MUST be discarded." Both
 * header forms carry it. */
#define WT_QUIC_FIXED_BIT 0x40U
/* The long header form bit, and the short header's key phase. */
#define WT_QUIC_LONG_HEADER_BIT 0x80U
#define WT_QUIC_KEY_PHASE_BIT 0x04U
#define WT_QUIC_SPIN_BIT 0x20U

typedef struct wt_quic_long_header {
  wt_quic_packet_type_t type;
  uint32_t version;
  /* Views into the datagram. */
  const uint8_t *destination_connection_id;
  size_t destination_connection_id_len;
  const uint8_t *source_connection_id;
  size_t source_connection_id_len;
  /* The address validation token, Initial packets only. */
  const uint8_t *token;
  size_t token_len;
  /* The packet number as it appeared, and how many bytes that was, so a caller
   * can reconstruct it against the largest it has seen (RFC 9000 appendix A.3). */
  uint64_t packet_number;
  size_t packet_number_len;
  /* The protected payload: the frames plus the authentication tag, still
   * encrypted. `length` is the Length field's value, which covers the packet
   * number and the payload. */
  const uint8_t *payload;
  size_t payload_len;
  /* The whole header, so a caller building the associated data for AEAD has it
   * without re-encoding: RFC 9001 section 5.3 authenticates the header from its
   * first byte through the packet number. */
  const uint8_t *header;
  size_t header_len;
  /* The total number of bytes this packet occupies in the datagram, which is
   * where the next coalesced packet starts. */
  size_t total_len;
  /* Whether the two reserved bits (0x0c of the first byte) were NON-zero once the header protection
   * came off. REPORTED rather than refused, because the rule about them is a rule about an
   * AUTHENTICATED packet: RFC 9000 section 17.2 says "after removing both packet and header
   * protection", and RFC 9001 section 5.3 makes a packet that fails packet protection one to DISCARD.
   * A decoder that refused them here turned every packet from another key epoch -- a Retry's
   * predecessor, an injected datagram -- into a PROTOCOL_VIOLATION against the peer (WT-167). */
  int reserved_bits_set;
} wt_quic_long_header_t;

typedef struct wt_quic_short_header {
  int key_phase;
  int spin;
  /* As above: reported, and checked once the packet has authenticated. */
  int reserved_bits_set;
  const uint8_t *destination_connection_id;
  size_t destination_connection_id_len;
  uint64_t packet_number;
  size_t packet_number_len;
  const uint8_t *payload;
  size_t payload_len;
  const uint8_t *header;
  size_t header_len;
  size_t total_len;
} wt_quic_short_header_t;

/* A Retry packet (RFC 9000 section 17.2.5). It has no Length field: the token
 * runs to the end of the datagram minus the 16-byte integrity tag. */
typedef struct wt_quic_retry_packet {
  uint32_t version;
  const uint8_t *destination_connection_id;
  size_t destination_connection_id_len;
  const uint8_t *source_connection_id;
  size_t source_connection_id_len;
  const uint8_t *token;
  size_t token_len;
  const uint8_t *integrity_tag; /* 16 bytes */
  const uint8_t *header;
  size_t header_len;
  size_t total_len;
} wt_quic_retry_packet_t;

/* What a datagram's first byte says it holds. */
typedef enum wt_quic_packet_kind {
  WT_QUIC_PACKET_KIND_LONG = 0,
  WT_QUIC_PACKET_KIND_SHORT = 1,
  /* A Version Negotiation packet, which is a long header with version zero and
   * no length. Reported rather than parsed: RFC 9000 section 6.2 makes the
   * response to one a matter of the version list, which is the connection's
   * business. */
  WT_QUIC_PACKET_KIND_VERSION_NEGOTIATION = 2
} wt_quic_packet_kind_t;

/* Which kind of packet the datagram at `c` begins with, without parsing it. */
wt_status_t wt_quic_packet_kind(const uint8_t *data, size_t length,
                                wt_quic_packet_kind_t *out);

/* The two connection IDs a LONG header names, and nothing else.
 *
 * A listener needs exactly this and cannot use `wt_quic_long_header_decode` to get it: that function reads the
 * Length field and hands back a view of the payload, so it needs the WHOLE packet, and the datagram a listener
 * peeks is typically 1200 bytes of Initial while the header is under 64. A truncated read here means the header
 * is not all present, which is the same answer the receive path gives a truncated packet.
 *
 * The views point into the caller's own bytes. Both are set only on WT_OK. */
wt_status_t wt_quic_long_header_connection_ids(const uint8_t *data, size_t length,
                                               const uint8_t **out_destination,
                                               size_t *out_destination_length,
                                               const uint8_t **out_source,
                                               size_t *out_source_length);

/* Read an Initial packet's address validation token WITHOUT decoding the packet, from a datagram that may be
 * TRUNCATED after the header.
 *
 * A listener that peeked only the front of a 1200-byte Initial needs exactly this: whether the client is already
 * answering a Retry is the Token Length field and the token, and the full decoder cannot answer it because it
 * wants the payload and the Length field that covers it. `out_token` is NULL and the length zero when the token
 * field is empty, which is the case a server answers with a Retry (WT-168). WT_ERR_TRUNCATED when the buffer ends
 * before the token does, so a caller can never mistake a partial read for an absent token -- the two mean opposite
 * things here. */
wt_status_t wt_quic_initial_token(const uint8_t *data, size_t length, const uint8_t **out_token,
                                  size_t *out_token_length);

/* Parse a long header. `c` is left past the whole packet, so a caller that wants
 * to walk a coalesced datagram can call this repeatedly.
 *
 * `out_error` is set to the transport error code to report on failure.
 *
 * Refuses: a missing fixed bit, non-zero reserved bits, an unknown packet type,
 * a connection ID longer than 20 bytes, a Retry (which has its own parser and a
 * different shape), a token that does not fit, a Length field that does not fit,
 * and a packet number length outside 1..4. RFC 9000 section 17.2 makes the
 * reserved bits a PROTOCOL_VIOLATION and the rest a FRAME_ENCODING_ERROR or a
 * truncation. */
wt_status_t wt_quic_long_header_decode(wt_cursor_t *c,
                                       wt_quic_long_header_t *out,
                                       wt_quic_error_t *out_error);

/* Parse a short header. `destination_connection_id_len` is the local connection
 * ID length, which the wire does not carry. A short header runs to the end of
 * the datagram, so `payload_len` is what remains. */
wt_status_t wt_quic_short_header_decode(wt_cursor_t *c,
                                        size_t destination_connection_id_len,
                                        wt_quic_short_header_t *out,
                                        wt_quic_error_t *out_error);

/* Where the packet number begins in a header that is STILL PROTECTED, and how long the packet is.
 *
 * This exists because neither decoder can answer it for a protected header, and that is not a gap in
 * them: the packet number's own length is the low two bits of the first byte, which the header
 * protection mask owns, and so are the two reserved bits the decoders refuse -- so a header whose mask
 * is still on cannot be decoded, and the offset the mask's sample is measured from (RFC 9001 section
 * 5.4.2) has to come from the layout instead. The walk below is the same layout the decoders use,
 * which is why it lives here beside them: two copies of it would be two answers.
 *
 * `local_connection_id_len` is the endpoint's own connection ID length, which a short header does not
 * carry; it is ignored for a long header. `out_short_header` reports which form was found, so a caller
 * need not ask separately.
 *
 * Refuses what is not protected this way: a Retry (no packet number at all) and a Version Negotiation
 * (no Length field), both WT_ERR_INVALID_ARGUMENT because they have their own parsers.
 * WT_ERR_TRUNCATED when the datagram ends before the walk does. */
wt_status_t wt_quic_protected_pn_offset(const uint8_t *data, size_t length,
                                        size_t local_connection_id_len,
                                        size_t *out_offset, size_t *out_total_len,
                                        int *out_short_header);

/* Parse a Retry packet. It occupies the rest of the datagram, so the caller must
 * pass a cursor over exactly one datagram. */
wt_status_t wt_quic_retry_packet_decode(const uint8_t *data, size_t length,
                                        wt_quic_retry_packet_t *out,
                                        wt_quic_error_t *out_error);

/* Encode a long header through a writer, which writes the header and the
 * protected payload as given. The Length field is computed from the packet
 * number length and the payload length, so a caller cannot disagree with itself
 * about it -- an earlier design had the caller pass the length and the two
 * drifted.
 *
 * Refuses a Retry type (use the Retry encoder), a connection ID above 20 bytes,
 * a packet number length outside 1..4, a token on a non-Initial packet, and a
 * payload whose length does not fit the Length field's varint. */
wt_status_t wt_quic_long_header_encode(wt_writer_t *w,
                                       wt_quic_packet_type_t type,
                                       uint32_t version,
                                       const uint8_t *destination_connection_id,
                                       size_t destination_connection_id_len,
                                       const uint8_t *source_connection_id,
                                       size_t source_connection_id_len,
                                       const uint8_t *token, size_t token_len,
                                       uint64_t packet_number,
                                       size_t packet_number_len,
                                       const uint8_t *payload,
                                       size_t payload_len);

/* Encode a long header WITHOUT its payload, for a caller that will produce the payload itself.
 *
 * A packet builder needs this because of the order the two protections impose: the AEAD's associated
 * data is the header through the packet number, so the header has to exist before the payload can be
 * sealed -- and the payload's length has to be known before the header can be written, because the
 * Length field covers it. This writes the header and the Length field for a payload of `payload_len`
 * bytes that the caller has not produced yet. */
wt_status_t wt_quic_long_header_encode_prefix(
    wt_writer_t *w, wt_quic_packet_type_t type, uint32_t version,
    const uint8_t *destination_connection_id, size_t destination_connection_id_len,
    const uint8_t *source_connection_id, size_t source_connection_id_len,
    const uint8_t *token, size_t token_len, uint64_t packet_number,
    size_t packet_number_len, size_t payload_len);

/* Encode a short header and its protected payload. */
wt_status_t wt_quic_short_header_encode(wt_writer_t *w,
                                        const uint8_t *destination_connection_id,
                                        size_t destination_connection_id_len,
                                        uint64_t packet_number,
                                        size_t packet_number_len, int key_phase,
                                        int spin, const uint8_t *payload,
                                        size_t payload_len);

/* Encode a Retry packet, whose integrity tag the caller supplies: computing it
 * needs the original destination connection ID and the AEAD, which is the
 * crypto layer's job and not the header codec's. */
wt_status_t wt_quic_retry_packet_encode(
    wt_writer_t *w, uint32_t version, const uint8_t *destination_connection_id,
    size_t destination_connection_id_len,
    const uint8_t *source_connection_id, size_t source_connection_id_len,
    const uint8_t *token, size_t token_len, const uint8_t integrity_tag[16]);

/* A short stable name for a packet type: "initial", "0-rtt", "handshake",
 * "retry". Never NULL. */
const char *wt_quic_packet_type_name(wt_quic_packet_type_t type);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_QUIC_PACKET_H */
