/* TLS 1.3 handshake message framing and the transcript hash.
 *
 * RFC 8446 section 4. Handshake messages are `type || uint24 length || body`,
 * and the transcript is the concatenation of every handshake message in order,
 * hashed. Almost everything in TLS 1.3 that can fail cryptically depends on
 * the transcript, so the framing and the running hash are worth having as their
 * own thing: the key schedule already takes transcript hashes, and this is
 * what produces them.
 *
 * WHAT IS VERIFIABLE HERE, and it is more than usual for handshake code: RFC
 * 8448 prints the ClientHello as a complete 196-byte message and the
 * ServerHello as a complete 90-byte message, and then prints the transcript
 * hash after each. So a message built here can be compared byte for byte, and
 * the hash of the two concatenated can be compared to a published value. A
 * length prefix that is off by one, a missing extension, or a transcript that
 * absorbs a message twice all show up as a mismatch rather than as an
 * authentication failure several round trips later.
 *
 * WHAT THIS IS NOT: it does not implement the handshake state machine. It
 * frames messages, parses the ones whose layout is fixed, and hashes them. It
 * does not decide what to send, validate a certificate, or check a Finished
 * MAC.
 */

#ifndef WT_TLS_HANDSHAKE_H
#define WT_TLS_HANDSHAKE_H

#include <stddef.h>
#include <stdint.h>

#include "wt_crypto.h"
#include "wt_tls.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Handshake message types (RFC 8446 section 4). */
#define WT_TLS_HS_CLIENT_HELLO 1U
#define WT_TLS_HS_SERVER_HELLO 2U
#define WT_TLS_HS_NEW_SESSION_TICKET 4U
#define WT_TLS_HS_ENCRYPTED_EXTENSIONS 8U
#define WT_TLS_HS_CERTIFICATE 11U
#define WT_TLS_HS_CERTIFICATE_VERIFY 15U
#define WT_TLS_HS_FINISHED 20U

/* A 24-bit length, which is the largest a handshake message can be. */
#define WT_TLS_MAX_HANDSHAKE_MESSAGE 0xFFFFFFU

/* The transcript: SHA-256 over the concatenated handshake messages. */
typedef struct wt_tls_transcript {
  wt_sha256_ctx_t hash;
} wt_tls_transcript_t;

/* Start a transcript, which is the hash of the empty string until something is
 * absorbed. */
int wt_tls_transcript_init(wt_tls_transcript_t *transcript);

/* Absorb one handshake message, framing included: callers pass the message as
 * it goes on the wire, `type || length || body`.
 *
 * `is_included` reports whether RFC 8446 says this message goes in the
 * transcript. ClientHello, ServerHello, EncryptedExtensions, Certificate,
 * CertificateVerify and Finished are included; a HelloRetryRequest is included
 * but is preceded by a synthetic message_hash (section 4.4.1), which this
 * function does not synthesise -- a caller that receives one must do that
 * itself, and the message is refused here rather than hashed wrongly. */
int wt_tls_transcript_absorb(wt_tls_transcript_t *transcript,
                             const uint8_t *message, size_t message_len);

/* The hash so far, without ending the transcript. */
int wt_tls_transcript_hash(const wt_tls_transcript_t *transcript,
                           uint8_t out[WT_TLS_HASH_LEN]);

/* Absorb a message and write the resulting hash: the common case, since a
 * transcript is almost always read at a message boundary. */
int wt_tls_transcript_absorb_and_hash(wt_tls_transcript_t *transcript,
                                      const uint8_t *message,
                                      size_t message_len,
                                      uint8_t out[WT_TLS_HASH_LEN]);

/* What was parsed out of a ServerHello, which is all the key schedule needs
 * from it. */
typedef struct wt_tls_server_hello {
  uint16_t cipher_suite;
  uint16_t selected_version;
  /* The server's key share. `key_share` points into the message buffer passed
     to the parse function, so it is valid only while that buffer is. */
  uint16_t group;
  const uint8_t *key_share;
  size_t key_share_len;
  int has_supported_versions;
  int has_key_share;
} wt_tls_server_hello_t;

/* Parse a ServerHello message (RFC 8446 section 4.1.3).
 *
 * `message` is the whole handshake message including the `type || length`
 * header. Fails on a wrong type, a truncated message, or a missing
 * supported_versions or key_share extension -- all of which RFC 9001 requires
 * a QUIC server to send. A legacy_session_id that is not echoed, or a
 * legacy_compression_method that is not zero, is a refusal: the first is a
 * downgrade check and the second is the TLS 1.3 rule.
 *
 * This does not verify the server's signature or its Finished. It extracts
 * what the key schedule needs. */
int wt_tls_parse_server_hello(const uint8_t *message, size_t message_len,
                              const uint8_t *expected_legacy_session_id,
                              size_t legacy_session_id_len,
                              wt_tls_server_hello_t *out);

/* Encode the 4-byte handshake header for `body_len` bytes of `type`. `out`
 * must have room for 4 bytes. Returns 4. */
size_t wt_tls_encode_handshake_header(uint8_t type, size_t body_len,
                                      uint8_t out[4]);

/* Read a handshake header, returning the type, the body length and the offset
 * of the body within `message`. Returns 0 on success and -1 when the buffer is
 * too short or the declared length does not fit. */
int wt_tls_decode_handshake_header(const uint8_t *message, size_t message_len,
                                   uint8_t *out_type, size_t *out_body_len,
                                   size_t *out_body_offset);

#ifdef __cplusplus
}
#endif

#endif /* WT_TLS_HANDSHAKE_H */
