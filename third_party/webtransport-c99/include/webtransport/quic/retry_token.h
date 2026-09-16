/* Retry tokens: the opaque value a server hands out to validate a client's address (WT-168).
 *
 * RFC 9000 section 8.1.2 lets a server answer a client's first Initial with a Retry whose token the client must
 * echo in its next Initial. The client's address is then known to be reachable, and the server has done no work
 * and kept no state for a client that never came back -- which is the whole point, and the reason a Retry is the
 * only defence section 21.3 (amplification) accepts.
 *
 * Statelessness is what makes the token's own integrity the server's business: with no table to look a token up
 * in, the token has to CARRY what the server needs to check, protected so that a client cannot forge it.
 * Section 8.1.4 names the construction -- "a token can be constructed with a first part containing the client's
 * address and a timestamp, and a second part containing an HMAC" -- and this is that construction:
 *
 *     format(1) | issued_at(8, big endian) | address(<= WT_QUIC_RETRY_TOKEN_ADDRESS_MAX) | odcid_len(1) | odcid | tag(16)
 *
 * The tag is HMAC-SHA256 over everything before it, truncated to 16 bytes, keyed by a secret the server holds
 * (section 8.1.4: "at least 128 bits"). The timestamp is the SERVER's clock, and validation takes a maximum age,
 * so a token a client has been sitting on cannot be replayed for ever. The original destination connection ID --
 * which is what the server's transport parameters have to name as `original_destination_connection_id` after a
 * Retry (section 7.3) -- is carried rather than remembered, for the same statelessness reason.
 *
 * WHAT IS VALIDATED AND WHAT IS NOT. A token that does not parse, whose tag does not match, or whose address
 * does not match the packet's source is NOT a token this server issued for this client, and all three are one
 * answer (`WT_ERR_AUTHENTICATION`): a server has nothing useful to do with the distinction, and a caller that
 * acted on it would be leaking which half of a forgery attempt succeeded. A token that is authentic but older
 * than the caller's bound is `WT_ERR_STATE`, which is a different thing -- the client is who it says it is, and
 * the server simply wants a fresh round trip before spending state on it.
 */

#ifndef WEBTRANSPORT_QUIC_RETRY_TOKEN_H
#define WEBTRANSPORT_QUIC_RETRY_TOKEN_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/quic/connection_id.h"
#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The key the tag is computed with. 32 bytes is what HMAC-SHA256 takes without hashing the key first, and section
 * 8.1.4's "at least 128 bits" is satisfied several times over; a caller gets it from `wt_random_bytes` and keeps
 * it for the life of the listener, because rotating it invalidates every token in flight (which is a legitimate
 * thing to do, and simply means those clients get another Retry). */
#define WT_QUIC_RETRY_TOKEN_SECRET_LEN 32U

/* The address form this module hashes is the caller's: whatever bytes name the peer, so long as build and
 * validate are given the same form for the same peer. `wt_udp_address_encode` is the canonical one this
 * repository uses (family, sixteen address bytes, port and scope id), and it is 23 bytes. */
#define WT_QUIC_RETRY_TOKEN_ADDRESS_MAX 32U

/* The tag, and the largest token this module builds: 1 + 8 + 32 + 1 + 20 + 16. A client treats the token as
 * opaque and only echoes it, so its size is the server's choice; this bound is the one the layout allows. */
#define WT_QUIC_RETRY_TOKEN_TAG_LEN 16U
#define WT_QUIC_RETRY_TOKEN_MAX 78U

/* Build a token binding `address` to `original_destination_id`, issued at `now`.
 *
 * `original_destination_id` is the destination connection ID of the Initial the client first sent -- the value
 * the server must name in its `original_destination_connection_id` parameter once the connection is established,
 * and the value the Initial keys were derived from before the Retry. It must be 1..20 bytes, which is what a
 * connection ID is (RFC 9000 section 17.2). WT_ERR_LIMIT when `capacity` cannot hold the token. */
wt_status_t wt_quic_retry_token_build(const uint8_t secret[WT_QUIC_RETRY_TOKEN_SECRET_LEN],
                                      const uint8_t *address, size_t address_length,
                                      const uint8_t *original_destination_id, size_t original_length,
                                      uint64_t now, uint8_t *out, size_t capacity, size_t *out_length);

/* Validate a token a client echoed, for the address the packet came from and the server's current `now`.
 *
 * `max_age` is the caller's bound in the same unit as `now`; zero means no expiry check, which a caller that
 * cannot keep a clock may pass but should not. On success the bound original destination connection ID is copied
 * to `out_original` and its length to `out_original_length`, so a server can build its transport parameters
 * without having kept anything.
 *
 * The answers are split by WHOSE fault it is, because that is the only distinction a caller acts on:
 *
 *   - WT_ERR_AUTHENTICATION -- everything about the TOKEN BYTES: a bad format byte, a length the layout cannot
 *     have, an internal length that disagrees with it, a tag that does not match, or an address that does not.
 *     A server answers all of them the same way (another Retry), and a caller that could tell them apart would
 *     be handing a forger a measure of how close it got.
 *   - WT_ERR_STATE -- authentic, and older than `max_age`: the client is who it says it is, and the server wants
 *     a fresh round trip before spending state on it.
 *   - WT_ERR_INVALID_ARGUMENT and WT_ERR_LIMIT -- the CALLER's own mistakes (a null pointer, an address length
 *     outside the form, an output buffer too small), which are bugs rather than attacks. */
wt_status_t wt_quic_retry_token_validate(const uint8_t secret[WT_QUIC_RETRY_TOKEN_SECRET_LEN],
                                         const uint8_t *address, size_t address_length, uint64_t now,
                                         uint64_t max_age, const uint8_t *token, size_t token_length,
                                         uint8_t *out_original, size_t capacity,
                                         size_t *out_original_length);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_QUIC_RETRY_TOKEN_H */
