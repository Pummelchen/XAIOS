/* TLS 1.3 handshake messages (RFC 8446 section 4).
 *
 * THE FRAMING IS FOUR BYTES AND IT IS CHECKED IN BOTH DIRECTIONS. Every handshake
 * message is a one-byte type and a three-octet length, and the transcript hashes
 * those four bytes along with the body. A message that is parsed from a body without
 * its header, or encoded with a length that is not its body's, produces a transcript
 * that matches no peer -- so `wt_tls_handshake_header_parse` insists that the declared
 * length is exactly what the caller's buffer holds, and the encoders write the length
 * they measured rather than one they were given.
 *
 * PARSED MESSAGES ARE VIEWS. `wt_tls_client_hello_t` and `wt_tls_server_hello_t` hold
 * pointers into the buffer they were parsed from and no copies of it, which is what
 * makes parsing a handshake allocation-free. The buffer must therefore outlive the
 * structure, and the encoder can re-encode a parsed message byte for byte -- including
 * extensions this implementation does not understand, which is what a server needs to
 * echo a ClientHello's shape rather than its meaning.
 *
 * WHAT A MESSAGE REQUIRES IS PART OF THE PARSE. A ClientHello whose
 * `legacy_compression_methods` is not exactly one zero byte, or whose cipher suite
 * list is empty or odd, or whose `legacy_session_id` is longer than 32 bytes, is
 * refused here rather than carried along for a later layer to notice. That is a
 * deliberate reading of RFC 8446 section 4.1.2: for TLS 1.3 those fields have exactly
 * one legal value each, and a parser that accepted others would be accepting a
 * handshake it cannot complete.
 *
 * NOT HERE: the certificate messages, CertificateVerify and Finished, which need the
 * key share and the signature layer to mean anything, and NewSessionTicket, which
 * needs the resumption machinery this implementation does not have.
 */

#ifndef WEBTRANSPORT_TLS_HANDSHAKE_H
#define WEBTRANSPORT_TLS_HANDSHAKE_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/cursor.h"
#include "webtransport/status.h"
#include "webtransport/tls/extension.h"
#include "webtransport/tls/keyschedule.h"
#include "webtransport/writer.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Handshake message types (RFC 8446 section 4, and RFC 9001 section 8.4 for the
 * extension to KeyUpdate that QUIC does not use). */
#define WT_TLS_HANDSHAKE_CLIENT_HELLO 1U
#define WT_TLS_HANDSHAKE_SERVER_HELLO 2U
#define WT_TLS_HANDSHAKE_NEW_SESSION_TICKET 4U
#define WT_TLS_HANDSHAKE_END_OF_EARLY_DATA 5U
#define WT_TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS 8U
#define WT_TLS_HANDSHAKE_CERTIFICATE 11U
#define WT_TLS_HANDSHAKE_CERTIFICATE_REQUEST 13U
#define WT_TLS_HANDSHAKE_CERTIFICATE_VERIFY 15U
#define WT_TLS_HANDSHAKE_FINISHED 20U
#define WT_TLS_HANDSHAKE_KEY_UPDATE 24U
#define WT_TLS_HANDSHAKE_MESSAGE_HASH 254U

#define WT_TLS_HANDSHAKE_HEADER_LEN 4U
/* The length field is three octets, so this is the largest body that can be framed. */
#define WT_TLS_HANDSHAKE_MAX_BODY 0xFFFFFFU
#define WT_TLS_RANDOM_LEN 32U
#define WT_TLS_SESSION_ID_MAX 32U
#define WT_TLS_CIPHER_SUITES_MAX 16U
#define WT_TLS_COMPRESSION_METHODS_MAX 4U

/* The four-byte framing. */
typedef struct wt_tls_handshake_header {
  uint8_t type;
  size_t length;
} wt_tls_handshake_header_t;

/* Parse a header at the cursor, refusing a length that is not exactly what remains
 * after it: a header whose length disagrees with the buffer is a fabricated frame, and
 * a caller that wanted to walk several messages in one buffer has to slice them
 * itself. On success the cursor is positioned at the body. */
wt_status_t wt_tls_handshake_header_parse(wt_cursor_t *cursor,
                                          wt_tls_handshake_header_t *out);

/* Write a header. `body_len` must fit three octets. */
wt_status_t wt_tls_handshake_header_encode(wt_writer_t *w, uint8_t type,
                                           size_t body_len);

/* The length of the handshake message at the start of `buffer`, header included, or 0 when the
 * buffer does not hold a whole one.
 *
 * THIS IS HOW A CRYPTO STREAM IS WALKED. A QUIC CRYPTO stream is a concatenation of handshake
 * messages, and `wt_tls_handshake_header_parse` deliberately refuses a buffer longer than the
 * message it describes -- which is what stops a parse from reading the next message's bytes as
 * this one's body. So the walker reads the four bytes itself, and a caller slices the message
 * out before handing it to a parser. */
size_t wt_tls_handshake_message_len(const uint8_t *buffer, size_t len);

/* The name of a handshake type, for a diagnostic. Not for logs that carry size: a
 * name is three to twenty characters and says nothing a peer chose. */
const char *wt_tls_handshake_type_name(uint8_t type);

/* ---------------------------------------------------------------- ClientHello */

typedef struct wt_tls_client_hello {
  uint16_t legacy_version;
  uint8_t random[WT_TLS_RANDOM_LEN];
  const uint8_t *session_id;
  size_t session_id_len;
  uint16_t cipher_suites[WT_TLS_CIPHER_SUITES_MAX];
  size_t cipher_suite_count;
  uint8_t compression_methods[WT_TLS_COMPRESSION_METHODS_MAX];
  size_t compression_method_count;
  wt_tls_extension_list_t extensions;
} wt_tls_client_hello_t;

/* Parse a complete ClientHello, header included. */
wt_status_t wt_tls_client_hello_parse(const uint8_t *message, size_t len,
                                      wt_tls_client_hello_t *out);

/* Re-encode a parsed ClientHello, header included. Byte for byte, including
 * extensions this implementation does not know. */
wt_status_t wt_tls_client_hello_encode(const wt_tls_client_hello_t *hello,
                                       wt_writer_t *w);

/* What our client offers. The extensions are the ones a QUIC client must send, in the
 * order RFC 8446 and RFC 9001 expect them, with `transport_parameters` the encoded
 * QUIC parameters the caller has already built (this layer does not know their
 * grammar) and `key_share` the public key from the key agreement. */
typedef struct wt_tls_client_hello_params {
  const uint8_t *random; /* WT_TLS_RANDOM_LEN bytes */
  const uint8_t *session_id;
  size_t session_id_len;
  const uint16_t *cipher_suites;
  size_t cipher_suite_count;
  const char *host_name; /* NULL to send no server_name */
  const uint16_t *supported_groups;
  size_t supported_group_count;
  const uint16_t *signature_schemes;
  size_t signature_scheme_count;
  const wt_tls_key_share_t *key_shares;
  size_t key_share_count;
  const char *const *alpn;
  size_t alpn_count;
  const uint8_t *transport_parameters;
  size_t transport_parameters_len;
} wt_tls_client_hello_params_t;

/* Build a ClientHello into `out`, reporting how many bytes it took.
 *
 * WT_ERR_LIMIT if it does not fit, WT_ERR_INVALID_ARGUMENT for a NULL or out-of-range
 * parameter. The whole message is measured before anything is written, so a refusal
 * leaves no partial message behind. */
wt_status_t wt_tls_client_hello_build(const wt_tls_client_hello_params_t *params,
                                      uint8_t *out, size_t capacity,
                                      size_t *out_len);

/* ----------------------------------------------------- EncryptedExtensions
 *
 * EncryptedExtensions is a body of nothing but an extension list (RFC 8446 section 4.3.1),
 * which is why it has a parser and a builder and no structure of its own: everything it
 * says is in the extensions, and every rule about them belongs to the layer that knows what
 * the extensions mean.
 */
wt_status_t wt_tls_encrypted_extensions_parse(const uint8_t *message, size_t len,
                                              wt_tls_extension_list_t *out);
wt_status_t wt_tls_encrypted_extensions_encode(
    const wt_tls_extension_list_t *extensions, wt_writer_t *w);
wt_status_t wt_tls_encrypted_extensions_build(
    const wt_tls_extension_list_t *extensions, uint8_t *out, size_t capacity,
    size_t *out_len);

/* ------------------------------------------- Certificate, CertificateVerify, Finished
 *
 * The three messages that carry a peer's identity and prove it holds the key. Nothing
 * here validates anything: the certificate entries are DER views and the signature is a
 * byte string, and what checks them is the trust layer above. That split is what lets
 * this file be tested against a document, and it is also why a Certificate whose DER is
 * garbage parses: "well framed" and "trustworthy" are different questions and this layer
 * answers only the first.
 */

/* How many certificates a chain may hold. A server sends one to three in practice; eight
 * is a bound on a peer's message rather than a statement about certificate chains. */
#define WT_TLS_CERTIFICATE_MAX_ENTRIES 8U

typedef struct wt_tls_certificate_entry {
  /* The DER encoding of one X.509 certificate, as a view. */
  const uint8_t *der;
  size_t der_len;
  /* The entry's own extension block, which is empty for every certificate TLS 1.3
   * defines (RFC 8446 section 4.4.2). */
  const uint8_t *extensions;
  size_t extensions_len;
} wt_tls_certificate_entry_t;

typedef struct wt_tls_certificate {
  /* The CertificateRequest context: empty in a server's Certificate, and the echo of the
   * request in a client's (RFC 8446 section 4.4.2). */
  const uint8_t *request_context;
  size_t request_context_len;
  wt_tls_certificate_entry_t entries[WT_TLS_CERTIFICATE_MAX_ENTRIES];
  size_t count;
} wt_tls_certificate_t;

wt_status_t wt_tls_certificate_parse(const uint8_t *message, size_t len,
                                     wt_tls_certificate_t *out);
wt_status_t wt_tls_certificate_encode(const wt_tls_certificate_t *certificate,
                                      wt_writer_t *w);

/* What our side sends. A client with no certificate to offer sends an empty chain with an
 * empty context, which is what RFC 8446 section 4.4.2 requires rather than an omission. */
typedef struct wt_tls_certificate_params {
  const uint8_t *request_context;
  size_t request_context_len;
  const wt_tls_certificate_entry_t *entries;
  size_t count;
} wt_tls_certificate_params_t;

wt_status_t wt_tls_certificate_build(const wt_tls_certificate_params_t *params,
                                     uint8_t *out, size_t capacity, size_t *out_len);

/* CertificateVerify: the signature over the transcript, and the scheme that produced it
 * (RFC 8446 section 4.4.3). The signature is checked against the transcript and the
 * certificate's public key by the trust layer; this carries the bytes. */
typedef struct wt_tls_certificate_verify {
  uint16_t scheme;
  const uint8_t *signature;
  size_t signature_len;
} wt_tls_certificate_verify_t;

wt_status_t wt_tls_certificate_verify_parse(
    const uint8_t *message, size_t len, wt_tls_certificate_verify_t *out);
wt_status_t wt_tls_certificate_verify_encode(
    const wt_tls_certificate_verify_t *certificate_verify, wt_writer_t *w);
wt_status_t wt_tls_certificate_verify_build(uint16_t scheme,
                                            const uint8_t *signature,
                                            size_t signature_len, uint8_t *out,
                                            size_t capacity, size_t *out_len);

/* Finished: a body of exactly Hash.length bytes, with nothing else in it (RFC 8446
 * section 4.4.4). */
wt_status_t wt_tls_finished_parse(const uint8_t *message, size_t len,
                                  uint8_t out[WT_TLS13_FINISHED_LEN]);
wt_status_t wt_tls_finished_build(const uint8_t verify_data[WT_TLS13_FINISHED_LEN],
                                  uint8_t *out, size_t capacity, size_t *out_len);

/* ---------------------------------------------------------------- ServerHello */

typedef struct wt_tls_server_hello {
  uint16_t legacy_version;
  uint8_t random[WT_TLS_RANDOM_LEN];
  const uint8_t *session_id;
  size_t session_id_len;
  uint16_t cipher_suite;
  uint8_t compression_method;
  wt_tls_extension_list_t extensions;
} wt_tls_server_hello_t;

wt_status_t wt_tls_server_hello_parse(const uint8_t *message, size_t len,
                                      wt_tls_server_hello_t *out);
wt_status_t wt_tls_server_hello_encode(const wt_tls_server_hello_t *hello,
                                       wt_writer_t *w);

typedef struct wt_tls_server_hello_params {
  const uint8_t *random; /* WT_TLS_RANDOM_LEN bytes */
  /* The client's session id, echoed back (RFC 8446 section 4.1.3). */
  const uint8_t *session_id;
  size_t session_id_len;
  uint16_t cipher_suite;
  const wt_tls_key_share_t *key_share;
  uint16_t supported_version;
} wt_tls_server_hello_params_t;

wt_status_t wt_tls_server_hello_build(const wt_tls_server_hello_params_t *params,
                                      uint8_t *out, size_t capacity,
                                      size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_TLS_HANDSHAKE_H */
