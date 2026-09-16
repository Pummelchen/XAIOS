/* TLS 1.3's key schedule (RFC 8446 section 7.1) and the transcript it consumes.
 *
 * THE SCHEDULE IS TWO CHAINS, AND THE DIFFERENCE MATTERS.
 *
 * The first chain is built by extraction: the Early Secret is HMAC with a zero
 * salt over the PSK (or over nothing, which RFC 8446 defines as a PSK of Hash.length
 * zero bytes -- not an empty PSK, and the two produce different secrets); the
 * Handshake Secret is HMAC with the Early Secret's derivation over the ECDHE shared
 * secret; the Master Secret is HMAC with the Handshake Secret's derivation over
 * zeroes. Each step absorbs one input and produces one secret, and the "derived"
 * step in between is what makes the chain a chain rather than three independent
 * hashes.
 *
 * The second chain is built by derivation: every other secret is
 * Derive-Secret(parent, label, transcript_hash), which is HKDF-Expand-Label with
 * the transcript hash as the context. That is why this file owns the transcript:
 * the hash at the moment of the derivation is an *input* to the secret, and a
 * handshake that hashes one message too many or one too few produces secrets that
 * match no peer and a Finished that verifies against nothing.
 *
 * WHAT IS NOT HERE. The 0-RTT secrets (`c e traffic`, `e exp master`), the resumption
 * binder keys (`res binder`, `ext binder`) and the exporter interface are absent
 * rather than present and unused: this implementation has no early data and no
 * exporter, and a derivation whose only caller is a future phase is a fact about a
 * draft rather than about this code. The resumption master secret IS here, because
 * RFC 8446 section 7.1 defines it as part of the schedule and it is derived at the
 * same point as the application secrets -- but nothing consumes it yet, which is
 * recorded in the project tracker rather than hidden.
 *
 * SHA-256 is the only hash, because TLS_AES_128_GCM_SHA256 is the only suite this
 * implementation offers (RFC 8446 section 9.1 makes it mandatory and it is what QUIC
 * requires of an implementation that speaks it). Every length below is therefore
 * fixed, and a caller cannot ask for a schedule that does not exist.
 */

#ifndef WEBTRANSPORT_TLS_KEY_SCHEDULE_H
#define WEBTRANSPORT_TLS_KEY_SCHEDULE_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/crypto/crypto.h"
#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Hash.length, and therefore the length of every secret here. */
#define WT_TLS13_SECRET_LEN WT_SHA256_LEN
/* The record protection key and IV lengths for TLS_AES_128_GCM_SHA256. */
#define WT_TLS13_KEY_LEN 16U
#define WT_TLS13_IV_LEN 12U
/* Finished and the ticket nonce's MAC are Hash.length. */
#define WT_TLS13_FINISHED_LEN WT_SHA256_LEN

/* The handshake transcript: a running SHA-256 over the handshake messages, in the
 * order they were sent or received, headers included.
 *
 * The messages are absorbed as they go and never kept. The hash is read as often as
 * the schedule needs it (RFC 8446 section 4.4.1) through `wt_sha256_snapshot`, which
 * copies the hash state instead of consuming it, so a transcript is one SHA-256
 * context (a few hundred bytes) for a handshake of any size -- rather than a buffer
 * whose size a peer's certificate chain decides.
 *
 * A message must be absorbed whole: TLS 1.3 frames every handshake message as a
 * type byte and a three-octet length, and `wt_tls13_transcript_append` refuses
 * anything whose framing disagrees with its size. That check is here rather than
 * only in the parser because the transcript is the one place that remembers which
 * bytes went in: a message absorbed without its header, or in two pieces, still
 * produces a plausible hash, and every secret derived from it is wrong with nothing
 * to point at. */
/* How many handshake messages a transcript records the TYPE of. The list a TLS 1.3 handshake absorbs is short
 * (ClientHello, ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished), so this is a
 * diagnostic bound rather than a protocol one -- and recording the types is what makes "what did this client
 * hash" answerable at all, which is the question a third-party peer forced (WT-135). */
#define WT_TLS13_TRANSCRIPT_TYPES_MAX 16U

typedef struct wt_tls13_transcript {
  wt_sha256_ctx_t hash;
  /* How many messages have been absorbed. Not used by any derivation; it is what
   * makes a transcript state printable in a diagnostic without printing the
   * handshake. */
  unsigned long messages;
  /* The type byte of each message absorbed, in order, up to the bound above. Nothing derives from this; it is
   * what a diagnostic prints so that a transcript can be compared with RFC 8446's list rather than merely
   * trusted. */
  uint8_t types[WT_TLS13_TRANSCRIPT_TYPES_MAX];
} wt_tls13_transcript_t;

wt_status_t wt_tls13_transcript_init(wt_tls13_transcript_t *transcript);

/* Append one complete handshake message, its four-byte header included.
 *
 * WT_ERR_TRUNCATED if the bytes are shorter than a handshake header;
 * WT_ERR_PROTOCOL if the header's length field is not the message's length;
 * WT_ERR_STATE if the transcript was not initialised or has been cleared. */
wt_status_t wt_tls13_transcript_append(wt_tls13_transcript_t *transcript,
                                       const uint8_t *message, size_t len);

/* The transcript hash so far, leaving the transcript usable. */
wt_status_t wt_tls13_transcript_hash(const wt_tls13_transcript_t *transcript,
                                     uint8_t out[WT_TLS13_SECRET_LEN]);

/* Release the transcript's state and clear it. Called when a handshake ends, so
 * that the transcript of a connection is not left in a reusable buffer. */
void wt_tls13_transcript_clear(wt_tls13_transcript_t *transcript);

/* ------------------------------------------------------------- the extract chain */

/* Early Secret = HKDF-Extract(0, PSK). `psk` may be NULL with `psk_len` 0 for a
 * handshake with no pre-shared key, which RFC 8446 section 7.1 defines as a PSK of
 * Hash.length zero bytes. */
wt_status_t wt_tls13_early_secret(const uint8_t *psk, size_t psk_len,
                                  uint8_t out[WT_TLS13_SECRET_LEN]);

/* Handshake Secret = HKDF-Extract(Derive-Secret(Early, "derived", ""), ECDHE).
 *
 * An all-zero `ecdhe` is refused: RFC 8446 section 7.4.2 makes a shared secret of
 * zeroes a handshake failure, and for X25519 -- the only group here -- it is what a
 * low-order public key produces (RFC 7748 section 6.1). Refusing it in the schedule
 * rather than in the caller means no caller can derive secrets from a value the peer
 * chose. */
wt_status_t wt_tls13_handshake_secret(const uint8_t early_secret[WT_TLS13_SECRET_LEN],
                                      const uint8_t *ecdhe, size_t ecdhe_len,
                                      uint8_t out[WT_TLS13_SECRET_LEN]);

/* Master Secret = HKDF-Extract(Derive-Secret(Handshake, "derived", ""), 0). */
wt_status_t wt_tls13_master_secret(
    const uint8_t handshake_secret[WT_TLS13_SECRET_LEN],
    uint8_t out[WT_TLS13_SECRET_LEN]);

/* ------------------------------------------------------------------ derivations */

/* Derive-Secret(secret, label, transcript_hash). The label is passed without the
 * "tls13 " prefix the wire format adds. Exposed because a caller may need a label
 * this file does not name -- and because spelling one wrongly is a mistake a test
 * can only catch if the function takes one. */
wt_status_t wt_tls13_derive_secret(const uint8_t secret[WT_TLS13_SECRET_LEN],
                                   const char *label,
                                   const uint8_t transcript_hash[WT_TLS13_SECRET_LEN],
                                   uint8_t out[WT_TLS13_SECRET_LEN]);

/* Derive-Secret(secret, "derived", ""), the step between the extracts. The context
 * is the hash of the empty transcript, not an empty context. */
wt_status_t wt_tls13_derived(const uint8_t secret[WT_TLS13_SECRET_LEN],
                             uint8_t out[WT_TLS13_SECRET_LEN]);

/* client_handshake_traffic_secret and server_handshake_traffic_secret, both from the
 * transcript through the ServerHello. */
wt_status_t wt_tls13_handshake_traffic_secrets(
    const uint8_t handshake_secret[WT_TLS13_SECRET_LEN],
    const uint8_t transcript_hash[WT_TLS13_SECRET_LEN],
    uint8_t client_out[WT_TLS13_SECRET_LEN],
    uint8_t server_out[WT_TLS13_SECRET_LEN]);

/* client_application_traffic_secret_0 and server_application_traffic_secret_0, both
 * from the transcript through the server's Finished. */
wt_status_t wt_tls13_application_traffic_secrets(
    const uint8_t master_secret[WT_TLS13_SECRET_LEN],
    const uint8_t transcript_hash[WT_TLS13_SECRET_LEN],
    uint8_t client_out[WT_TLS13_SECRET_LEN],
    uint8_t server_out[WT_TLS13_SECRET_LEN]);

/* exporter_master_secret and resumption_master_secret. The first is part of the
 * schedule and is checked by RFC 8448's trace; the second is what a NewSessionTicket
 * would be built from, which this implementation does not yet send or accept. */
wt_status_t wt_tls13_exporter_master_secret(
    const uint8_t master_secret[WT_TLS13_SECRET_LEN],
    const uint8_t transcript_hash[WT_TLS13_SECRET_LEN],
    uint8_t out[WT_TLS13_SECRET_LEN]);
wt_status_t wt_tls13_resumption_master_secret(
    const uint8_t master_secret[WT_TLS13_SECRET_LEN],
    const uint8_t transcript_hash[WT_TLS13_SECRET_LEN],
    uint8_t out[WT_TLS13_SECRET_LEN]);

/* The next application traffic secret after a key update (RFC 8446 section 7.2):
 * HKDF-Expand-Label(secret, "traffic upd", "", Hash.length). */
wt_status_t wt_tls13_next_traffic_secret(const uint8_t secret[WT_TLS13_SECRET_LEN],
                                         uint8_t out[WT_TLS13_SECRET_LEN]);

/* The record protection keys a traffic secret produces, HKDF-Expand-Label(secret,
 * "key", "", 16) and (secret, "iv", "", 12). */
wt_status_t wt_tls13_traffic_keys(const uint8_t secret[WT_TLS13_SECRET_LEN],
                                  uint8_t key[WT_TLS13_KEY_LEN],
                                  uint8_t iv[WT_TLS13_IV_LEN]);

/* --------------------------------------------------------------------- Finished */

/* finished_key = HKDF-Expand-Label(base_key, "finished", "", Hash.length), where
 * `base_key` is the handshake traffic secret of the side whose Finished it is. */
wt_status_t wt_tls13_finished_key(const uint8_t base_key[WT_TLS13_SECRET_LEN],
                                  uint8_t out[WT_TLS13_FINISHED_LEN]);

/* verify_data = HMAC(finished_key, transcript_hash). */
wt_status_t wt_tls13_finished_verify_data(
    const uint8_t base_key[WT_TLS13_SECRET_LEN],
    const uint8_t transcript_hash[WT_TLS13_SECRET_LEN],
    uint8_t out[WT_TLS13_FINISHED_LEN]);

/* Verify a peer's Finished. Returns WT_OK, WT_ERR_AUTHENTICATION when the data does
 * not match, or WT_ERR_INVALID_ARGUMENT for a length that is not Hash.length -- a
 * short comparison that "matched" is the forgery this exists to prevent. The
 * comparison is constant time. */
wt_status_t wt_tls13_finished_check(
    const uint8_t base_key[WT_TLS13_SECRET_LEN],
    const uint8_t transcript_hash[WT_TLS13_SECRET_LEN],
    const uint8_t *verify_data, size_t verify_data_len);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_TLS_KEY_SCHEDULE_H */
