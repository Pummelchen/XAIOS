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

/* ---------------------------------------------------------------------------
 * ClientHello construction
 *
 * The parameters a client chooses. This is not a policy object: it is the list
 * of things that go on the wire, and the caller decides them. The defaults a
 * real client would want -- which groups, which signature algorithms, which
 * ALPN protocol -- are protocol policy and belong to the caller.
 * ------------------------------------------------------------------------- */

/* One key share to offer: a group and a public key the client generated for
   it. The key is copied into the message, so the caller keeps ownership. */
typedef struct wt_tls_key_share {
  uint16_t group;
  const uint8_t *public_key;
  size_t public_key_len;
} wt_tls_key_share_t;

typedef struct wt_tls_client_hello_params {
  /* The 32-byte ClientHello random. Caller-supplied because it must be
     unpredictable: a predictable random is a replay and downgrade weakness,
     and a builder that generated its own would hide where it came from. */
  const uint8_t *random;
  /* RFC 8446 section 4.1.2: required to be empty for QUIC, because TLS 1.3
     middlebox compatibility mode is prohibited (RFC 9001 section 8.4). A
     non-empty value is refused rather than sent. */
  const uint8_t *legacy_session_id;
  size_t legacy_session_id_len;
  /* The cipher suites offered, in preference order. */
  const uint16_t *cipher_suites;
  size_t cipher_suite_count;
  /* The key shares offered. */
  const wt_tls_key_share_t *key_shares;
  size_t key_share_count;
  /* The groups the client supports, for the supported_groups extension. */
  const uint16_t *supported_groups;
  size_t supported_group_count;
  /* The signature algorithms offered, in preference order. */
  const uint16_t *signature_algorithms;
  size_t signature_algorithm_count;
  /* The ALPN protocols, each a length-prefixed byte string in
     `alpn_protocols`. For QUIC this must include "h3" for HTTP/3. */
  const uint8_t *alpn_protocols;
  size_t alpn_protocols_len;
  /* The Server Name Indication, without a length prefix. NULL for none. */
  const char *server_name;
  /* The QUIC transport parameters, already encoded. This module does not build
     them -- they are QUIC's, not TLS's -- but it carries them, because a QUIC
     ClientHello without the extension is rejected (RFC 9001 section 8.2). */
  const uint8_t *quic_transport_parameters;
  size_t quic_transport_parameters_len;
} wt_tls_client_hello_params_t;

/* How large a buffer a ClientHello needs for these parameters, or 0 if the
 * parameters are invalid. Use this to size the buffer: the encoder refuses
 * rather than truncating, so a caller that guessed too small gets an error and
 * not a short message. */
size_t wt_tls_client_hello_size(const wt_tls_client_hello_params_t *params);

/* Encode a ClientHello into `out`, which must have room for
 * wt_tls_client_hello_size(params) bytes. Returns the message length, or 0 on
 * a bad argument or a buffer too small.
 *
 * The extensions are emitted in a fixed order -- server_name, supported_groups,
 * signature_algorithms, ALPN, supported_versions, key_share,
 * quic_transport_parameters -- which RFC 8446 allows and which makes the output
 * comparable to a published message. RFC 8448's ClientHello uses that order
 * with one difference: it interleaves nothing, so a caller reproducing the
 * vector gets the vector's bytes. */
size_t wt_tls_encode_client_hello(const wt_tls_client_hello_params_t *params,
                                  uint8_t *out, size_t out_capacity);

/* ----------------------------------------------------------------- Finished
 *
 * RFC 8446 section 4.4.4. The Finished message is an HMAC over the transcript
 * hash with a key derived from the sender's traffic secret:
 *
 *   finished_key = HKDF-Expand-Label(secret, "finished", "", Hash.length)
 *   verify_data  = HMAC(finished_key, Transcript-Hash(...))
 *
 * The secret is the CLIENT's handshake traffic secret for a client Finished
 * and the SERVER's for a server Finished. Using the wrong one produces a MAC
 * of the right shape that never verifies, which is why the direction is an
 * argument rather than something the caller is expected to remember.
 * ------------------------------------------------------------------------- */

/* The 32-byte verify_data a Finished message must carry. */
#define WT_TLS_FINISHED_LEN 32U

/* Compute the verify_data for a Finished, given the traffic secret for the
 * direction being sent and the transcript hash through the previous message. */
int wt_tls_finished_compute(const uint8_t traffic_secret[WT_TLS_HASH_LEN],
                            const uint8_t transcript_hash[WT_TLS_HASH_LEN],
                            uint8_t out[WT_TLS_FINISHED_LEN]);

/* Verify a received Finished in constant time. Returns 1 when it verifies, 0
 * when it does not, and -1 on a bad argument. `message` is the whole Finished
 * handshake message, framing included, and the transcript hash must be the one
 * through the message BEFORE it -- RFC 8446 hashes a message into the
 * transcript after its own MAC has been checked, so a caller that absorbs the
 * Finished first will never verify.
 *
 * The comparison is constant time because a timing-variable compare on a MAC
 * is a forgery oracle. */
int wt_tls_finished_verify(const uint8_t traffic_secret[WT_TLS_HASH_LEN],
                           const uint8_t transcript_hash[WT_TLS_HASH_LEN],
                           const uint8_t *message, size_t message_len);

#ifdef __cplusplus
}
#endif

#endif /* WT_TLS_HANDSHAKE_H */
