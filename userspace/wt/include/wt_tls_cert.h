/* TLS 1.3 Certificate and CertificateVerify (RFC 8446 sections 4.4.2, 4.4.3).
 *
 * Two messages, and the signature check that ties the server's identity to the
 * transcript.
 *
 *   Certificate        the server's chain, in DER, one to many entries
 *   CertificateVerify  a signature over the transcript with a context string
 *
 * The signature is the part that makes the handshake authenticated: without it
 * anyone can send a ServerHello and a certificate, and the key schedule will
 * happily derive keys from a connection to an attacker. So the check is the
 * one thing in this file that must not be gotten wrong, and the test verifies
 * RFC 8448's own CertificateVerify signature with RFC 8448's own certificate --
 * a real signature over a real transcript, not a fixture built to match the
 * verifier.
 *
 * TRUST IS NOT DECIDED HERE. This module answers "is this message signed by the
 * key in this certificate", which is a question with a yes or no answer. It
 * does not answer "should this certificate be trusted", which is a policy, and
 * on XAIOS the policy is a pinned operator key. That decision belongs to the
 * caller, and keeping it out of the signature check is what lets the check be
 * tested against a published vector without a trust store existing.
 */

#ifndef WT_TLS_CERT_H
#define WT_TLS_CERT_H

#include <stddef.h>
#include <stdint.h>

#include "wt_crypto.h"
#include "wt_tls.h"
#include "wt_tls_handshake.h"

/* BearSSL types are needed for the public keys this module produces. The
   include is inside the guard and outside the extern "C" pair, because BearSSL
   declares its own linkage. */
#include "bearssl.h"

#ifdef __cplusplus
extern "C" {
#endif

/* A signature scheme from the TLS registry, RFC 8446 section 4.2.3. Only the
 * ones a QUIC server may use for CertificateVerify and that this module can
 * check are listed; anything else is a refusal rather than a silent skip. */
#define WT_TLS_SIG_RSA_PSS_RSAE_SHA256 0x0804U
#define WT_TLS_SIG_RSA_PSS_RSAE_SHA384 0x0805U
#define WT_TLS_SIG_RSA_PSS_RSAE_SHA512 0x0806U
#define WT_TLS_SIG_ECDSA_SECP256R1_SHA256 0x0403U
#define WT_TLS_SIG_ECDSA_SECP384R1_SHA384 0x0503U
#define WT_TLS_SIG_ECDSA_SECP521R1_SHA512 0x0603U

/* The context string for a server CertificateVerify, verbatim per RFC 8446
 * section 4.4.3. The client's is "TLS 1.3, client CertificateVerify"; getting
 * one byte wrong produces a signature that never verifies and no hint why. */
extern const char wt_tls_server_certificate_verify_context[];

/* A certificate chain, with each entry a view into the message buffer. */
#define WT_TLS_MAX_CERTIFICATES 8U

typedef struct wt_tls_certificate_chain {
  const uint8_t *entries[WT_TLS_MAX_CERTIFICATES];
  size_t lengths[WT_TLS_MAX_CERTIFICATES];
  size_t count;
  /* The extensions block of the Certificate message, which a TLS 1.3 client
     must parse or refuse: RFC 8446 requires the whole message to be well
     formed even when the extensions are empty. */
  const uint8_t *extensions;
  size_t extensions_len;
} wt_tls_certificate_chain_t;

/* Parse a Certificate message. `message` is the whole handshake message with
 * its `type || length` header. The chain views point into it, so the buffer
 * must outlive the structure.
 *
 * Refuses a message that is not a Certificate, more entries than the structure
 * holds, a truncated entry, an entry longer than the rest of the message, or
 * extensions that do not fit -- each of which is reachable from the wire. */
int wt_tls_parse_certificate(const uint8_t *message, size_t message_len,
                             wt_tls_certificate_chain_t *out);

/* What was parsed out of a CertificateVerify. */
typedef struct wt_tls_certificate_verify {
  uint16_t scheme;
  const uint8_t *signature;
  size_t signature_len;
} wt_tls_certificate_verify_t;

/* Parse a CertificateVerify message. The signature is a view into `message`. */
int wt_tls_parse_certificate_verify(const uint8_t *message, size_t message_len,
                                    wt_tls_certificate_verify_t *out);

/* The bytes a CertificateVerify signs (RFC 8446 section 4.4.3):
 *
 *   64 spaces || context string || 0x00 || Transcript-Hash
 *
 * `context` is passed in so a client CertificateVerify can use its own string
 * without this function having to know which side is talking. The transcript
 * hash is the one through the message BEFORE the CertificateVerify. */
int wt_tls_certificate_verify_content(const char *context,
                                      const uint8_t transcript_hash[WT_TLS_HASH_LEN],
                                      uint8_t *out, size_t out_capacity,
                                      size_t *out_len);

/* Verify a CertificateVerify against a certificate's public key.
 *
 * The public key comes from the certificate the peer sent; this does NOT check
 * that the certificate is trusted, only that the signature is the peer's. That
 * split is deliberate and is the caller's to complete with its pinning policy.
 *
 * `certificate_der` is one DER certificate from the chain. `content` is what
 * `wt_tls_certificate_verify_content` produced.
 *
 * Returns 1 when the signature verifies, 0 when it does not, and -1 on a bad
 * argument, an unsupported scheme, or a certificate whose key cannot be read.
 * A -1 is a refusal, never a pass. */
int wt_tls_certificate_verify_signature(
    const uint8_t *certificate_der, size_t certificate_len,
    const wt_tls_certificate_verify_t *verify, const uint8_t *content,
    size_t content_len);

/* Read the public key out of a DER certificate, for a caller that wants to
 * compare it against a pinned key rather than verify a signature with it.
 *
 * Exactly one of `rsa` and `ec` is filled, according to the key type.
 * `is_rsa` is 1 when the key is RSA and 0 when it is EC. Returns 0 on success,
 * -1 when the certificate cannot be parsed or its key type is unsupported. */
int wt_tls_certificate_public_key(const uint8_t *certificate_der,
                                  size_t certificate_len, int *is_rsa,
                                  br_rsa_public_key *rsa, br_ec_public_key *ec);

/* Whether two RSA public keys are the same key, in constant time.
 *
 * This is the pinned-key comparison: the operator's key is configured at build
 * or boot time and the peer's certificate must carry exactly it. Comparing
 * only the modulus is deliberate -- the exponent is checked too, but a key is
 * identified by its modulus, and a comparison that stopped at the first
 * difference would be a timing oracle for the modulus. */
int wt_tls_rsa_public_key_equal(const br_rsa_public_key *a,
                                const br_rsa_public_key *b);

#ifdef __cplusplus
}
#endif

#endif /* WT_TLS_CERT_H */
