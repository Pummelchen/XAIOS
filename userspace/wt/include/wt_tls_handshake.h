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
/* RFC 8446 section 4.3.2. A server may send one before its Certificate; this
   client holds no certificate, so it answers with an empty one. */
#define WT_TLS_HS_CERTIFICATE_REQUEST 13U
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
 * EncryptedExtensions
 *
 * RFC 8446 section 4.3.1 and RFC 9001 section 8.2. The first message under
 * handshake keys, and the one that carries ALPN's answer and the server's QUIC
 * transport parameters.
 *
 * The message is a bare extension list, which makes it the one handshake
 * message whose content is almost entirely peer-chosen. Two rules decide
 * whether it is acceptable, and they are different rules:
 *
 *   - RFC 8446 section 4.3.1: an extension that is not allowed in
 *     EncryptedExtensions at all is `illegal_parameter`.
 *   - RFC 8446 section 4.2: an extension the client did not offer is
 *     `unsupported_extension`. This one needs the ClientHello, so the parser
 *     reports which types arrived and `wt_tls_client_hello_offers` answers
 *     whether each was asked for.
 * ------------------------------------------------------------------------- */

/* Extension types, named so a caller does not compare magic numbers. These are
 * the TLS 1.3 registry entries (RFC 8446 section 4.2), not a subset: the
 * parser's job includes recognising the ones that must NOT appear here. */
#define WT_TLS_EXT_SERVER_NAME 0x0000U
#define WT_TLS_EXT_MAX_FRAGMENT_LENGTH 0x0001U
#define WT_TLS_EXT_STATUS_REQUEST 0x0005U
#define WT_TLS_EXT_SUPPORTED_GROUPS 0x000AU
#define WT_TLS_EXT_SIGNATURE_ALGORITHMS 0x000DU
#define WT_TLS_EXT_USE_SRTP 0x000EU
#define WT_TLS_EXT_HEARTBEAT 0x000FU
#define WT_TLS_EXT_ALPN 0x0010U
#define WT_TLS_EXT_SIGNED_CERTIFICATE_TIMESTAMP 0x0012U
#define WT_TLS_EXT_CLIENT_CERTIFICATE_TYPE 0x0013U
#define WT_TLS_EXT_SERVER_CERTIFICATE_TYPE 0x0014U
#define WT_TLS_EXT_PADDING 0x0015U
/* RFC 8449. Not in RFC 8446's table, because RFC 8446 predates it, but it is
 * legal in EncryptedExtensions and RFC 8448's trace carries one -- which is a
 * useful reminder that "valid in EncryptedExtensions" is not a closed set. */
#define WT_TLS_EXT_RECORD_SIZE_LIMIT 0x001CU
#define WT_TLS_EXT_PRE_SHARED_KEY 0x0029U
#define WT_TLS_EXT_EARLY_DATA 0x002AU
#define WT_TLS_EXT_SUPPORTED_VERSIONS 0x002BU
#define WT_TLS_EXT_COOKIE 0x002CU
#define WT_TLS_EXT_PSK_KEY_EXCHANGE_MODES 0x002DU
#define WT_TLS_EXT_CERTIFICATE_AUTHORITIES 0x002FU
#define WT_TLS_EXT_OID_FILTERS 0x0030U
#define WT_TLS_EXT_POST_HANDSHAKE_AUTH 0x0031U
#define WT_TLS_EXT_SIGNATURE_ALGORITHMS_CERT 0x0032U
#define WT_TLS_EXT_KEY_SHARE 0x0033U
/* RFC 9001 section 8.2. Mandatory in a ClientHello and in EncryptedExtensions
   for QUIC, and forbidden in TLS over any other transport. */
#define WT_TLS_EXT_QUIC_TRANSPORT_PARAMETERS 0x0039U

/* The most extensions a single EncryptedExtensions may carry before this
 * refuses. Sixteen is far above any real server's list, and the alternative --
 * a growing array -- is an allocation on a peer-controlled count. */
#define WT_TLS_MAX_ENCRYPTED_EXTENSIONS 16U

/* Why an EncryptedExtensions was refused. The value selects the TLS alert a
 * QUIC stack reports, so it is returned rather than logged and dropped:
 * "refused" and "refused for this reason" are different to a peer and to
 * whoever reads the connection close.
 *
 * The first five come from the parse; the last two come from
 * `wt_tls_encrypted_extensions_check`, which is the one that needs the
 * ClientHello. */
typedef enum wt_tls_ee_reject {
  WT_TLS_EE_OK = 0,
  /* Not an EncryptedExtensions, truncated, a length that does not fit, or a
     body that is not exactly one extension list -> decode_error. */
  WT_TLS_EE_MALFORMED,
  /* The same extension type twice in one list (RFC 8446 section 4.2) ->
     illegal_parameter. */
  WT_TLS_EE_DUPLICATE_EXTENSION,
  /* A recognised extension whose body is invalid: an ALPN list that is not one
     protocol, a server_name that is not empty, a bad max_fragment_length ->
     decode_error. */
  WT_TLS_EE_BAD_EXTENSION,
  /* More extensions than this parser holds -> decode_error. */
  WT_TLS_EE_TOO_MANY_EXTENSIONS,
  /* An extension the ClientHello offered, in a message RFC 8446 section 4.2
     says it may not appear in (key_share, supported_versions,
     signature_algorithms, ...) -> illegal_parameter. */
  WT_TLS_EE_FORBIDDEN_EXTENSION,
  /* An extension the ClientHello did not offer (RFC 8446 section 4.2: a server
     MUST NOT send an extension response the client did not request) ->
     unsupported_extension. */
  WT_TLS_EE_UNSOLICITED_EXTENSION
} wt_tls_ee_reject_t;

typedef struct wt_tls_encrypted_extensions {
  /* The selected ALPN protocol, as a view into the message. RFC 7301 requires
     exactly one name in the server's answer, so this is one protocol and not a
     list; `has_alpn` distinguishes "no ALPN" from "an empty one", which is
     otherwise the same pointer and length. */
  const uint8_t *alpn;
  size_t alpn_len;
  int has_alpn;

  /* The server's QUIC transport parameters, still encoded: their layout is
     RFC 9000's, not TLS's. Absent for a QUIC connection is fatal
     (RFC 9001 section 8.2), and this parser does not enforce that because it
     is not a QUIC implementation -- the driver does. */
  const uint8_t *transport_parameters;
  size_t transport_parameters_len;
  int has_transport_parameters;

  /* Present-and-well-formed flags for the rest of the extensions that may
     appear here. None of them changes what this module does; they are recorded
     so a caller is not left guessing what the server sent. */
  int has_server_name;
  int has_early_data;
  int has_max_fragment_length;
  uint8_t max_fragment_length;
  int has_supported_groups;
  int has_client_certificate_type;
  uint8_t client_certificate_type;
  int has_server_certificate_type;
  uint8_t server_certificate_type;
  int has_use_srtp;
  int has_heartbeat;

  /* Every extension type in the message, in the order it appeared, so a caller
     can apply RFC 8446 section 4.2's "the client must have offered it" rule.
     Duplicates are refused, so these are distinct. */
  uint16_t types[WT_TLS_MAX_ENCRYPTED_EXTENSIONS];
  size_t type_count;

  /* Valid only when the parse returned -1: which refusal this was, and for the
     two extension-specific reasons, which extension caused it. */
  wt_tls_ee_reject_t reject;
  uint16_t reject_extension;
} wt_tls_encrypted_extensions_t;

/* Parse an EncryptedExtensions message. `message` is the whole handshake
 * message including its `type || length` header.
 *
 * Returns 0 on success and -1 on any refusal, in which case `out` is cleared
 * and only `reject` and `reject_extension` are meaningful -- a caller that
 * wants the alert code reads them; a caller that only wants to fail does not
 * have to. Views point into `message`, which must outlive the structure.
 *
 * This checks the message's SHAPE: that it is an EncryptedExtensions, that the
 * body is exactly one extension list, that no type repeats, and that the
 * extensions this module understands are well formed. It deliberately does NOT
 * decide whether an extension was allowed to be there, because that answer
 * depends on the ClientHello and RFC 8446 gives two different alerts for the
 * two ways it can be wrong. That decision is
 * `wt_tls_encrypted_extensions_check`, declared after the ClientHello
 * parameters because that is what it reads. */
int wt_tls_parse_encrypted_extensions(const uint8_t *message, size_t message_len,
                                      wt_tls_encrypted_extensions_t *out);

/* The remaining rule -- an extension the client did not offer is
 * `unsupported_extension` (RFC 8446 section 4.2) -- needs the ClientHello, so
 * `wt_tls_client_hello_offers` answers it. It is declared after the
 * ClientHello parameters, because that is what it reads. */

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

/* Whether the ClientHello these parameters describe offered `type`
 * (RFC 8446 section 4.2: a server MUST NOT send an extension response the
 * client did not request, and a client that receives one MUST abort with
 * `unsupported_extension`).
 *
 * This is derived from the parameters rather than from a list recorded at
 * encode time, because those parameters ARE the ClientHello: the builder emits
 * an extension for a field exactly when that field is set, so asking the
 * parameters is asking the message. The test asserts the two agree by encoding
 * a ClientHello and reading its extension list back, so a builder that starts
 * emitting an extension this does not know about is a test failure rather than
 * a silent difference.
 *
 * Returns 1 when the extension was offered, 0 when it was not, and -1 on a
 * NULL `params`. */
int wt_tls_client_hello_offers(const wt_tls_client_hello_params_t *params,
                               uint16_t type);

/* Apply RFC 8446's two acceptance rules to a parsed EncryptedExtensions,
 * against the ClientHello this client sent, in the order the RFC states them:
 *
 *   1. An extension that was not offered -> `unsupported_extension`
 *      (section 4.2: "Implementations MUST NOT send extension responses if the
 *      remote endpoint did not send the corresponding extension requests").
 *   2. An extension that was offered but whose TLS 1.3 location is not
 *      EncryptedExtensions -> `illegal_parameter`
 *      (section 4.3.1: "The client MUST check EncryptedExtensions for the
 *      presence of any forbidden extensions").
 *
 * The order matters and is not arbitrary. Rule 1 is decidable from the
 * ClientHello alone and covers every extension this client does not speak,
 * including ones registered after RFC 8446; rule 2 only ever sees types the
 * client offered, which is a set of seven this module knows in full. That is
 * what keeps the check correct without a complete copy of the IANA registry --
 * a whitelist of "extensions valid in EncryptedExtensions" would refuse a
 * server that used a newer RFC's extension, and RFC 8448's own trace already
 * carries `record_size_limit`, which RFC 8446 predates.
 *
 * Returns 0 when the message may be accepted and -1 otherwise, writing the
 * reject reason and the offending extension type through `out_reject` and
 * `out_extension` (both may be NULL). */
int wt_tls_encrypted_extensions_check(
    const wt_tls_encrypted_extensions_t *ee,
    const wt_tls_client_hello_params_t *offered, wt_tls_ee_reject_t *out_reject,
    uint16_t *out_extension);

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
