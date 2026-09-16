/* QUIC packet protection (RFC 9001 sections 5.1 to 5.4).
 *
 * A QUIC packet is protected twice over, and the two are independent:
 *
 *   1. The PAYLOAD is encrypted with an AEAD whose associated data is the packet
 *      header through the packet number, and whose nonce is the IV with the
 *      packet number XORed into its last eight bytes (section 5.3).
 *   2. The HEADER is partly masked with a sample of the protected payload, so
 *      that the packet number length and the low bits of the first byte are not
 *      readable by an observer (section 5.4). The mask is applied after the
 *      payload is encrypted, because the sample comes from it, and nowhere
 *      before.
 *
 * The keys come from two places. The Initial keys are derived from the
 * destination connection ID the client chose and a version-specific salt, with no
 * key exchange at all -- which is why an observer can decrypt an Initial packet,
 * and why everything after it is protected with keys TLS agreed. Handshake and
 * 1-RTT keys come from TLS traffic secrets, and this file derives them from a
 * secret the same way RFC 9001 section 5.1 says.
 *
 * THE ORDER IS THE PART THAT IS EASY TO GET WRONG. Removing header protection
 * needs a sample of the payload as it is on the wire; decrypting the payload
 * needs the packet number, which is inside the masked header. So the receive path
 * is always: unmask the first byte and the packet number, reconstruct the number,
 * then decrypt. A decoder that decrypted first would be decrypting with a packet
 * number it had not read, and the AEAD would reject every packet with a tag
 * failure that names nothing.
 *
 * WHAT IS NOT HERE: any decision about when a key is usable. RFC 9001 sections
 * 4.1.4 and 4.9 make key availability and key discarding connection state, and
 * that belongs to the runtime. This file turns secrets into keys and protects
 * bytes with them.
 */

#ifndef WEBTRANSPORT_QUIC_PROTECTION_H
#define WEBTRANSPORT_QUIC_PROTECTION_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/crypto/crypto.h"
#include "webtransport/quic/error.h"
#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The four values one traffic secret produces (RFC 9001 section 5.1): the
 * packet protection key and IV, the header protection key, and the secret
 * itself, kept because a key update derives the next set from it. */
typedef struct wt_quic_packet_keys {
  uint8_t secret[WT_SHA256_LEN];
  uint8_t key[WT_AEAD_MAX_KEY_LEN];
  uint8_t iv[WT_AEAD_IV_LEN];
  uint8_t hp[WT_AEAD_MAX_KEY_LEN];
  /* How many bytes of `key` and of `hp` are meaningful. RFC 9001 section 5.1
   * derives `quic hp` with the AEAD's own key length, so both are 16 for
   * AES-128-GCM and 32 for ChaCha20-Poly1305 -- and the length is an INPUT to the
   * expansion, not a truncation of a longer one, so a struct that assumed one
   * length would be wrong for the other suite even though its key and IV were
   * right. */
  size_t key_len;
  size_t hp_len;
  wt_aead_t aead;
} wt_quic_packet_keys_t;

/* The QUIC version 1 Initial salt, RFC 9001 section 5.2. Exposed because the
 * derivation takes the salt rather than hard-coding one, so that a version with a
 * different salt is a different constant and not a silent change. */
extern const uint8_t wt_quic_initial_salt_v1[20];

/* initial_secret = HKDF-Extract(initial_salt, destination_connection_id).
 * `dcid` is the destination connection ID of the client's first Initial packet,
 * which is what binds the keys to the connection: two connections with different
 * IDs have different Initial keys. */
wt_status_t wt_quic_initial_secret(const uint8_t *salt, size_t salt_len,
                                   const uint8_t *dcid, size_t dcid_len,
                                   uint8_t out[WT_SHA256_LEN]);

/* The Initial packet keys for one direction. `from_server` selects the "server
 * in" label over "client in"; RFC 9001 section 5.2 derives both from the same
 * initial_secret, and using the wrong one produces keys that decrypt nothing. */
wt_status_t wt_quic_initial_packet_keys(const uint8_t initial_secret[WT_SHA256_LEN],
                                        int from_server, wt_aead_t aead,
                                        wt_quic_packet_keys_t *out);

/* The packet keys a traffic secret produces (RFC 9001 section 5.1). */
wt_status_t wt_quic_packet_keys_from_secret(
    const uint8_t secret[WT_SHA256_LEN], wt_aead_t aead,
    wt_quic_packet_keys_t *out);

/* The next set, for a key update (RFC 9001 section 6):
 *
 *   secret_<n+1> = HKDF-Expand-Label(secret_<n>, "quic ku", "", Hash.length)
 *
 * and the KEY and IV are derived from the new secret as usual -- while the HEADER PROTECTION KEY IS NOT UPDATED
 * ("The header protection key is not updated", section 6.1), so `out->hp` is a copy of `current->hp` rather than
 * a fresh derivation. This comment used to say all three were derived from the new secret, which is what the
 * implementation did and what a caller following it would have got wrong: every protected header after an update
 * would be one the peer cannot unmask. The AEAD does not change across an update either, which is why this takes
 * the current keys rather than a suite. */
wt_status_t wt_quic_packet_keys_update(const wt_quic_packet_keys_t *current,
                                       wt_quic_packet_keys_t *out);

/* The AEAD nonce for a packet (RFC 9001 section 5.3): the IV with the packet
 * number, as a 62-bit big-endian integer, XORed into its LAST eight bytes. The
 * first four bytes of the IV are left alone, which is what makes the construction
 * a per-packet nonce rather than a new IV, and a caller that XORed at the front
 * would reuse a nonce across a whole packet number space. */
wt_status_t wt_quic_packet_nonce(const uint8_t iv[WT_AEAD_IV_LEN],
                                 uint64_t packet_number,
                                 uint8_t out[WT_AEAD_IV_LEN]);

/* The offset of the header protection sample, RFC 9001 section 5.4.2: four bytes
 * past the start of the packet number field. The sample is sixteen bytes from
 * there, so a packet whose payload is shorter than that cannot be protected at
 * all -- which is why QUIC requires a minimum packet size and why this refuses
 * rather than reading past the end.
 *
 * Both numbers are named because the sender needs them too: a packet builder
 * pads its own plaintext with PADDING frames when the payload would leave the
 * packet too short to sample, which is the only way a small frame -- PING, or
 * RETIRE_CONNECTION_ID at two bytes -- can be sent on its own. */
#define WT_QUIC_HP_SAMPLE_OFFSET 4U
#define WT_QUIC_HP_SAMPLE_LENGTH 16U
wt_status_t wt_quic_header_protection_sample(size_t pn_offset,
                                             const uint8_t *packet,
                                             size_t packet_len,
                                             uint8_t sample[16]);

/* The five-byte header protection mask for an AEAD and its header protection
 * key. AES-128-GCM encrypts the sample and takes its first five bytes;
 * ChaCha20-Poly1305 takes the first five bytes of the ChaCha20 keystream over
 * five zero bytes with a counter taken from the sample's first four bytes. The
 * two are not variations of one another, which is why this dispatches. */
wt_status_t wt_quic_header_protection_mask(wt_aead_t aead, const uint8_t *hp,
                                           size_t hp_len,
                                           const uint8_t sample[16],
                                           uint8_t out[5]);

/* Apply header protection in place: mask the low four bits of the first byte and
 * the whole packet number field. `pn_offset` is where the packet number starts,
 * which the caller knows from parsing the unprotected header; `pn_len` is its
 * length, 1 to 4.
 *
 * Applying it twice is not the same as applying it once and then removing it --
 * the mask depends on the payload, which the first application does not change,
 * so a second application would XOR the mask again and produce a header no peer
 * can read. This is a protect, not a toggle. */
wt_status_t wt_quic_protect_header(wt_aead_t aead, const uint8_t *hp,
                                   size_t hp_len, uint8_t *packet,
                                   size_t packet_len, size_t pn_offset,
                                   size_t pn_len);

/* Remove header protection in place, reporting the packet number length that the
 * unmasked first byte revealed. The caller reconstructs the full packet number
 * from those bytes and the largest it has seen (RFC 9000 appendix A.3), and then
 * decrypts the payload -- in that order, because the nonce needs the number. */
wt_status_t wt_quic_unprotect_header(wt_aead_t aead, const uint8_t *hp,
                                     size_t hp_len, uint8_t *packet,
                                     size_t packet_len, size_t pn_offset,
                                     size_t *out_pn_len);

/* Encrypt `frames_len` bytes of `frames` into `out`, which must have room for
 * `frames_len + 16` bytes of ciphertext and tag. `aad` is the packet header
 * through the packet number.
 *
 * The tag is written after the ciphertext, which is where a QUIC packet carries
 * it. A caller assembling a packet writes the header, calls this to append the
 * protected payload, and then calls wt_quic_protect_header. */
wt_status_t wt_quic_protect_frames(const wt_quic_packet_keys_t *keys,
                                   uint64_t packet_number, const uint8_t *aad,
                                   size_t aad_len, const uint8_t *frames,
                                   size_t frames_len, uint8_t *out,
                                   size_t out_capacity, size_t *out_len);

/* Decrypt in place: `packet` holds the ciphertext and `len` bytes of it,
 * excluding the tag, which is passed separately because the caller has already
 * decided that it belongs to this packet.
 *
 * Returns WT_OK when the tag matches and WT_ERR_AUTHENTICATION when it does not, and in
 * the second case the plaintext written to `packet` is cleared before returning.
 * THAT IS THE WHOLE POINT OF THIS FUNCTION'S SHAPE: a caller cannot forget to
 * compare the tag, cannot act on unauthenticated plaintext, and cannot leak what
 * a failed decryption produced. The comparison is constant time.
 *
 * WT_ERR_AUTHENTICATION rather than WT_ERR_PROTOCOL, which status.h reserves for bytes
 * that violate the protocol: a tag that does not verify means the packet was not produced
 * by the holder of the key -- forged or corrupted in transit -- and the caller decides
 * whether that is a discarded datagram or a closed connection (RFC 9001 section 5.3). */
wt_status_t wt_quic_unprotect_frames(const wt_quic_packet_keys_t *keys,
                                     uint64_t packet_number, const uint8_t *aad,
                                     size_t aad_len, uint8_t *packet,
                                     size_t len,
                                     const uint8_t tag[WT_AEAD_TAG_LEN]);

/* RFC 9001 section 5.8's Retry integrity tag: AES-128-GCM with an empty plaintext over
 *
 *   Retry Pseudo-Packet = ODCID Length || Original Destination Connection ID || Retry packet
 *
 * where "Retry packet" is the packet WITHOUT its tag. The key and nonce are the version's own constants,
 * not a negotiated secret: the point of the tag is that a client can tell a Retry the server sent from
 * one an attacker injected, so it must be computable before any handshake has happened. `out` receives
 * the sixteen-byte tag.
 *
 * WT_ERR_LIMIT when the pseudo-packet does not fit the bounded buffer this uses, which cannot happen for
 * a connection ID of twenty bytes or fewer -- the protocol's own bound -- so it means a caller passed a
 * length that is not a connection ID length. */
wt_status_t wt_quic_retry_integrity_tag(const uint8_t *original_destination_connection_id,
                                        size_t original_destination_connection_id_len,
                                        const uint8_t *retry_packet_without_tag, size_t length,
                                        uint8_t out[WT_AEAD_TAG_LEN]);

/* Whether a Retry packet's tag is the one this ODCID and packet produce. WT_OK when it is,
 * WT_ERR_AUTHENTICATION when it is not, which is the ordinary answer for a Retry an attacker sent: the
 * comparison accumulates differences rather than stopping at the first, because the tag's bytes are
 * derived from a secret only in the sense that an attacker does not have the packet -- a fast comparison
 * would tell them how much of a guess was right. */
wt_status_t wt_quic_retry_integrity_verify(const uint8_t *original_destination_connection_id,
                                           size_t original_destination_connection_id_len,
                                           const uint8_t *retry_packet, size_t length);

/* Zero a key set. Called when a connection ends or a key is discarded. */
void wt_quic_packet_keys_clear(wt_quic_packet_keys_t *keys);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_QUIC_PROTECTION_H */
