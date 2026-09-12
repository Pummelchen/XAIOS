/* TLS 1.3 key schedule and QUIC traffic key derivation.
 *
 * RFC 8446 section 7.1 defines the schedule; RFC 9001 section 5.1 defines how
 * QUIC turns a traffic secret into a packet protection key, an IV and a header
 * protection key. For a connection with no pre-shared key and no 0-RTT -- the
 * only kind this module supports -- that is the whole of what QUIC needs from
 * TLS to protect a packet, and it is the part of TLS 1.3 that can be checked
 * against published vectors without a peer.
 *
 * WHAT IS MISSING FROM THE SCHEDULE, so it is not mistaken for complete: the
 * early-secret branches. `binder_key` ("res binder"/"ext binder"),
 * `client_early_traffic_secret` ("c e traffic") and
 * `early_exporter_master_secret` ("e exp master") are not derived, because
 * without a PSK or 0-RTT none of them is used. A connection that wants 0-RTT
 * needs them and needs a session-ticket store to hold the PSK they come from,
 * and neither exists here.
 *
 * WHAT THIS IS NOT. This is not a TLS handshake. It does not parse a
 * ClientHello, build a ServerHello, verify a certificate chain or check a
 * Finished MAC, and no amount of calling it correctly will complete a
 * handshake. Those are the parts that need a peer, or a full transcript
 * assembled from handshake messages that this module does not yet carry. The
 * boundary is stated here rather than discovered by reading the tree: the
 * functions below produce the right keys for the right secrets, and where the
 * secrets come from is the handshake's business.
 *
 * Every function is checked against RFC 8448's printed intermediate values and
 * RFC 9001 appendix A in tests/security/test_wt_tls.c. Nothing here is
 * "obviously right": HKDF-Expand-Label's length prefixes, the empty-transcript
 * hash, and the order of the Derive-Secret chain are all places where a wrong
 * choice produces 32 well-formed bytes.
 */

#ifndef WT_TLS_H
#define WT_TLS_H

#include <stddef.h>
#include <stdint.h>

#include "wt_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The hash TLS_AES_128_GCM_SHA256 uses. All lengths below are for SHA-256. */
#define WT_TLS_HASH_LEN 32U
/* The maximum traffic key length. The real length is the AEAD's key size --
   16 for AES-128-GCM, 32 for ChaCha20-Poly1305 -- and is carried in
   `wt_tls_traffic_keys_t.key_len`. Deriving 16 bytes for ChaCha20 and calling
   it a key produces a value that is not a ChaCha20 key and a connection that
   cannot work, so the length is neither assumed nor truncated. */
#define WT_TLS_KEY_LEN 32U
#define WT_TLS_IV_LEN 12U
/* The header protection key's maximum length.
 *
 * RFC 9001 section 5.1 derives hp with the AEAD's own key length, which is 16
 * bytes for AES-128-GCM and 32 for ChaCha20-Poly1305. It is a maximum rather
 * than a fixed length, and the length actually used is carried in
 * `wt_tls_traffic_keys_t.hp_len`, because the two are not interchangeable: the
 * derivation is
 *
 *   HKDF-Expand-Label(secret, "quic hp", "", hp_len)
 *
 * and the length is an input to the expansion, not a truncation of a longer
 * one. Expanding 32 bytes and taking the first 16 gives a different value --
 * e9c80d02... instead of 9f50449e... for RFC 9001's own Initial -- so a struct
 * that assumed one length was wrong for the other suite even though both key
 * and iv beside it were right. */
#define WT_TLS_HP_LEN 32U

/* The hash of the empty transcript, which is the transcript at the point
 * "derived" is taken from the early secret. RFC 8446 section 7.1 names it
 * explicitly; computing it is cheaper than getting it wrong. */
extern const uint8_t wt_tls_empty_hash[WT_TLS_HASH_LEN];

/* The secrets a connection runs on, in derivation order. Every field is a
 * sensitive value and must be cleared with wt_tls_secrets_clear when the
 * connection ends. */
typedef struct wt_tls_secrets {
  uint8_t early[WT_TLS_HASH_LEN];
  uint8_t handshake[WT_TLS_HASH_LEN];
  uint8_t master[WT_TLS_HASH_LEN];
  uint8_t client_handshake_traffic[WT_TLS_HASH_LEN];
  uint8_t server_handshake_traffic[WT_TLS_HASH_LEN];
  uint8_t client_application_traffic[WT_TLS_HASH_LEN];
  uint8_t server_application_traffic[WT_TLS_HASH_LEN];
  uint8_t exporter_master[WT_TLS_HASH_LEN];
  /* Zero unless the caller supplied the transcript through the client's
     Finished. See `wt_tls_key_schedule`. */
  uint8_t resumption_master[WT_TLS_HASH_LEN];
  int resumption_master_available;
} wt_tls_secrets_t;

/* A traffic secret turned into the four values QUIC protects packets with.
 * `key`, `iv` and `hp` are secret; `secret` is kept so a key update can
 * derive the next set. */
typedef struct wt_tls_traffic_keys {
  uint8_t secret[WT_TLS_HASH_LEN];
  uint8_t key[WT_TLS_KEY_LEN];
  uint8_t iv[WT_TLS_IV_LEN];
  uint8_t hp[WT_TLS_HP_LEN];
  /* How many bytes of `key` and of `hp` are meaningful: 16 and 16 for
     AES-128-GCM, 32 and 32 for ChaCha20-Poly1305. Both must be used at exactly
     these lengths; the fields are sized for the larger suite. */
  size_t key_len;
  size_t hp_len;
} wt_tls_traffic_keys_t;

/* The AEAD a connection negotiated. Only these two are defined for QUIC, and
   AES-128-GCM is mandatory (RFC 9001 section 5.1). */
typedef enum wt_tls_aead {
  WT_TLS_AEAD_AES_128_GCM = 1,
  WT_TLS_AEAD_CHACHA20_POLY1305 = 2
} wt_tls_aead_t;

/* HKDF-Expand-Label (RFC 8446 section 7.1).
 *
 * `label` is the bare label without the "tls13 " prefix, which this adds.
 * `context` may be NULL when `context_len` is 0. Fails when `out_len` exceeds
 * the HKDF bound or when a length prefix would not fit in its byte, rather
 * than truncating the label or the context. */
int wt_tls_expand_label(const uint8_t *secret, size_t secret_len,
                        const char *label, const uint8_t *context,
                        size_t context_len, uint8_t *out, size_t out_len);

/* Derive-Secret(secret, label, transcript_hash) at the SHA-256 length.
 * `transcript_hash` is the hash of the messages so far, not the messages. */
int wt_tls_derive_secret(const uint8_t *secret, size_t secret_len,
                         const char *label,
                         const uint8_t transcript_hash[WT_TLS_HASH_LEN],
                         uint8_t out[WT_TLS_HASH_LEN]);

/* The full schedule, for a connection with ECDHE and no pre-shared key.
 *
 * `ecdh_secret` is the ECDHE shared secret in the length the negotiated group
 * produces; for x25519 that is 32 bytes. It is only read.
 *
 * `transcript_after_server_hello` is the hash of every handshake message
 * through ServerHello, which is where the handshake traffic secrets are taken.
 * `transcript_after_server_finished` is the hash through the server's Finished,
 * which is where the application traffic secrets and the exporter are taken.
 *
 * `transcript_after_client_finished` is the hash through the CLIENT's Finished,
 * and it is a separate argument because RFC 8446 section 7.1 derives the
 * resumption master secret from that point and not from the server's Finished.
 * Passing the server-Finished hash for it -- which is what this function did
 * first, using one transcript for both -- produces a perfectly well-formed
 * 32-byte value that is not the resumption master secret and would fail on the
 * first resumption attempt with no way to tell why. A caller that has not seen
 * the client's Finished yet, which is every caller before the handshake
 * completes, passes NULL: the resumption master secret is then left zero and
 * `resumption_master_available` is 0, because a wrong value is worse than an
 * absent one.
 *
 * The schedule runs in two phases, and a handshake has to run them at two
 * different times: `wt_tls_handshake_key_schedule` as soon as the ServerHello
 * has been seen, because the next packet from the server is protected with the
 * handshake keys it produces, and `wt_tls_application_key_schedule` once the
 * server's Finished has been verified, because its transcript does not exist
 * before then. `wt_tls_key_schedule` runs both at once, for a caller that has
 * the whole transcript -- which is what the RFC 8448 vectors do, and what makes
 * the two phases checkable against one published answer.
 *
 * A caller that has no transcript yet can pass wt_tls_empty_hash for the
 * transcript arguments, which is what the RFC 8448 vectors do at the points
 * they are printed for; that is useful for testing the schedule and wrong for a
 * connection.
 *
 * On failure `out` is cleared rather than partially filled. */
int wt_tls_handshake_key_schedule(
    const uint8_t *ecdh_secret, size_t ecdh_len,
    const uint8_t transcript_after_server_hello[WT_TLS_HASH_LEN],
    wt_tls_secrets_t *out);

/* The second phase. `handshake_phase` is what `wt_tls_handshake_key_schedule`
 * produced, and its early, handshake and handshake-traffic secrets are carried
 * into `out` unchanged -- so `out` holds the whole schedule and not just its
 * second half. `out` and `handshake_phase` may be the same object. */
int wt_tls_application_key_schedule(
    const wt_tls_secrets_t *handshake_phase,
    const uint8_t transcript_after_server_finished[WT_TLS_HASH_LEN],
    wt_tls_secrets_t *out);

/* Both phases, in order, plus the resumption master secret when a transcript
 * through the client's Finished is supplied (NULL for one that has not seen
 * it). Equivalent to calling the two above; this is the form the RFC 8448
 * vectors are checked against. */
int wt_tls_key_schedule(const uint8_t *ecdh_secret, size_t ecdh_len,
                        const uint8_t transcript_after_server_hello[WT_TLS_HASH_LEN],
                        const uint8_t transcript_after_server_finished[WT_TLS_HASH_LEN],
                        const uint8_t *transcript_after_client_finished,
                        wt_tls_secrets_t *out);

/* The traffic keys derived from one traffic secret (RFC 9001 section 5.1).
 * The "quic key", "quic iv" and "quic hp" labels are QUIC's, not TLS's.
 * `aead` selects the header protection key length. */
int wt_tls_traffic_keys(const uint8_t secret[WT_TLS_HASH_LEN],
                        wt_tls_aead_t aead, wt_tls_traffic_keys_t *out);

/* The next set of traffic keys for a key update (RFC 9001 section 6).
 * `next_secret = HKDF-Expand-Label(secret, "quic ku", "", 32)`. */
int wt_tls_key_update(const uint8_t secret[WT_TLS_HASH_LEN],
                      wt_tls_aead_t aead, wt_tls_traffic_keys_t *out);

/* QUIC Initial secrets (RFC 9001 section 5.2).
 *
 * The salt is the version-specific constant; this takes it rather than
 * hard-coding one so that a version that changes it is not silently wrong.
 * `dcid` is the destination connection ID the client chose, which is what
 * binds the Initial keys to the connection. */
int wt_tls_initial_secret(const uint8_t *salt, size_t salt_len,
                          const uint8_t *dcid, size_t dcid_len,
                          uint8_t out[WT_TLS_HASH_LEN]);
int wt_tls_initial_traffic_keys(const uint8_t initial_secret[WT_TLS_HASH_LEN],
                                int from_server, wt_tls_aead_t aead,
                                wt_tls_traffic_keys_t *out);

/* The Retry Integrity Tag (RFC 9001 section 5.8; this is WT-1 in the
 * WebTransport tracker's numbering, where the Swift implementation never
 * computed it).
 *
 * The tag authenticates a Retry against the connection it answers: the
 * pseudo-packet is the original destination connection ID, length-prefixed,
 * followed by the Retry packet with its own tag removed. `retry_without_tag`
 * must therefore NOT include the 16-byte tag, and `out_tag` is that tag.
 *
 * THE CALLER SUPPLIES THE SCRATCH SPACE. The pseudo-packet is
 * `1 + dcid_len + retry_len` bytes and a Retry's token is peer-controlled and
 * may be hundreds of bytes, so there is no fixed-size internal buffer that is
 * both correct and safe: the first version of this used a 256-byte local and
 * copied an unbounded `retry_len` into it, which is a stack buffer overflow
 * reachable from an unauthenticated packet. The caller passes the buffer and
 * its capacity, and a Retry too large for it is refused rather than truncated.
 *
 * `scratch` may be NULL only when `scratch_len` is 0, which is a valid call
 * only for a pseudo-packet that is empty -- it never is, since the one-byte
 * length prefix is always present.
 *
 * `retry_aead_key` and `retry_aead_nonce` are the fixed constants from the
 * RFC, not derived from anything. */
int wt_tls_retry_integrity_tag(const uint8_t retry_aead_key[16],
                               const uint8_t retry_aead_nonce[12],
                               const uint8_t *original_dcid, size_t dcid_len,
                               const uint8_t *retry_without_tag,
                               size_t retry_len, uint8_t *scratch,
                               size_t scratch_len, uint8_t out_tag[16]);

/* Check a received Retry's tag in constant time. Returns 1 when it verifies,
 * 0 when it does not, and -1 on a bad argument or a Retry too large for
 * `scratch`. */
int wt_tls_verify_retry_integrity_tag(const uint8_t retry_aead_key[16],
                                      const uint8_t retry_aead_nonce[12],
                                      const uint8_t *original_dcid,
                                      size_t dcid_len,
                                      const uint8_t *retry_packet,
                                      size_t retry_len, uint8_t *scratch,
                                      size_t scratch_len);

/* Zero a secrets or keys structure. Callers must do this when a connection
 * ends: these values decrypt everything the connection carries. */
void wt_tls_secrets_clear(wt_tls_secrets_t *secrets);
void wt_tls_traffic_keys_clear(wt_tls_traffic_keys_t *keys);

#ifdef __cplusplus
}
#endif

#endif /* WT_TLS_H */
