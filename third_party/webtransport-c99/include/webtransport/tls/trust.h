/* TLS 1.3 peer authentication: certificate validation and the CertificateVerify check.
 *
 * TWO QUESTIONS, ASKED IN ORDER. A Certificate message says what the peer claims to be;
 * CertificateVerify says it holds the key. This file answers both, and the second answer
 * is only worth anything if the first one passed -- a signature verified against a
 * certificate nobody trusted proves that the peer holds a key, not that the key is the
 * one it claimed. The handshake layer is therefore required to call `wt_tls_trust_verify`
 * for every certificate message and only then `wt_tls_signature_verify`, with the public
 * key that validation returned.
 *
 * THE POLICY IS PROMPT-FREE, WHICH IS A PROPERTY AND NOT AN OMISSION. There is no
 * callback and no interaction: a mode is configured before the handshake starts, every
 * failure is a status, and the same inputs give the same answer every time. The plan's
 * completion criterion for this phase is that application keys are unavailable until
 * every security condition holds and that all trust failures are deterministic and
 * non-interactive, and a policy that consulted a user would fail both.
 *
 * THE MODES MIRROR THE SWIFT LIBRARY:
 *
 *   - `WT_TLS_TRUST_SYSTEM` validates against the platform's own trust store, which is
 *     what the Swift client's `systemTrust` policy does through Network.framework.
 *   - `WT_TLS_TRUST_STORE` validates against certificates the caller supplies. A portable
 *     library cannot assume a platform store exists -- this one cross-compiles to targets
 *     whose store is a directory of PEMs or nothing at all -- so the store is data rather
 *     than a platform feature.
 *   - `WT_TLS_TRUST_PINNED_CERTIFICATE` accepts one of a small set of leaf certificates by
 *     SHA-256 fingerprint, which is the Swift library's `TLSPinnedCertificateTrustPolicy`
 *     and the model the XAIOS port uses: an operator pins the key they expect.
 *   - `WT_TLS_TRUST_LOCAL_DEVELOPMENT` skips validation entirely and is restricted to
 *     loopback host names, exactly as the Swift client's `localDevelopmentSelfSigned`
 *     policy is. The restriction travels with the mode rather than being advice, so a
 *     caller cannot accidentally use a development bypass against a real endpoint.
 */

#ifndef WEBTRANSPORT_TLS_TRUST_H
#define WEBTRANSPORT_TLS_TRUST_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/status.h"
#include "webtransport/tls/handshake.h"
#include "webtransport/tls/keyschedule.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The largest SubjectPublicKeyInfo this implementation extracts, which is what a peer's
 * certificate has to fit its public key into. An RSA-4096 key's DER is around 550 bytes
 * and a P-256 key's is 91, so this is generous by a factor of two and still bounded. */
#define WT_TLS_SPKI_MAX 1024U

/* How many fingerprints a pinned policy may hold. A deployment pins one key and rotates to
 * two; four is room to rotate without an outage. */
#define WT_TLS_PINNED_MAX 4U

typedef enum wt_tls_trust_mode {
  WT_TLS_TRUST_SYSTEM = 1,
  WT_TLS_TRUST_STORE = 2,
  WT_TLS_TRUST_PINNED_CERTIFICATE = 3,
  WT_TLS_TRUST_LOCAL_DEVELOPMENT = 4
} wt_tls_trust_mode_t;

typedef struct wt_tls_trust_policy {
  wt_tls_trust_mode_t mode;

  /* The name the peer must be reachable at, checked against the leaf's subject
   * alternative names (RFC 6125) by SYSTEM and STORE. NULL skips the check, which is
   * documented rather than offered as a convenience: a caller who does not know what name
   * they are connecting to cannot validate a certificate for it, and the pinned and
   * development modes are the ones that do not need a name. */
  const char *host_name;

  /* STORE: a bundle of PEM certificates, concatenated. */
  const uint8_t *ca_bundle;
  size_t ca_bundle_len;

  /* PINNED_CERTIFICATE: the SHA-256 digests of acceptable leaf certificates. */
  uint8_t fingerprints[WT_TLS_PINNED_MAX][WT_SHA256_LEN];
  size_t fingerprint_count;
} wt_tls_trust_policy_t;

/* Whether a host name is one the LOCAL_DEVELOPMENT bypass is allowed for. Exported
 * because two layers need the same answer -- this policy at the handshake, and the public
 * API when it checks a configuration before a connection is even attempted -- and a rule
 * with two implementations is a rule that will disagree with itself. Exact comparison: a
 * name that merely contains a loopback name is not one. */
int wt_tls_trust_host_is_loopback(const char *host_name);

/* Validate a peer's certificate chain and hand back the leaf's public key.
 *
 * `spki_out` receives the leaf's SubjectPublicKeyInfo in DER, which is what
 * `wt_tls_signature_verify` takes; `*spki_len` is set to what was written. The key is
 * returned rather than an opaque handle so that this call owns nothing and a caller needs
 * no cleanup path.
 *
 * WT_ERR_TRUST when the policy refuses the chain -- an unknown issuer, an expired
 * certificate, a name that does not match, a fingerprint that is not pinned, or a
 * development bypass asked for against a non-loopback name;
 * WT_ERR_UNSUPPORTED when the platform has no trust store for SYSTEM;
 * WT_ERR_LIMIT when the leaf's key does not fit `WT_TLS_SPKI_MAX`;
 * WT_ERR_PROTOCOL for a chain that is not well formed DER. */
wt_status_t wt_tls_trust_verify(const wt_tls_trust_policy_t *policy,
                                const wt_tls_certificate_t *certificate,
                                uint8_t spki_out[WT_TLS_SPKI_MAX],
                                size_t *spki_len);

/* The content a CertificateVerify signs (RFC 8446 section 4.4.3):
 *
 *   64 spaces || context_string || 0x00 || Transcript-Hash
 *
 * where the context string is "TLS 1.3, server CertificateVerify" for a server's message
 * and "TLS 1.3, client CertificateVerify" for a client's. `out` needs 130 bytes: 64 + 33 +
 * 1 + 32. The construction is here rather than in the handshake layer because a wrong
 * context string produces a signature that verifies against nothing and names no cause. */
#define WT_TLS_CERTIFICATE_VERIFY_CONTENT_LEN 130U
wt_status_t wt_tls_certificate_verify_content(
    int from_server, const uint8_t transcript_hash[WT_TLS13_SECRET_LEN],
    uint8_t out[WT_TLS_CERTIFICATE_VERIFY_CONTENT_LEN]);

/* Verify a CertificateVerify signature over `content` with the peer's public key.
 *
 * The scheme is the one the peer named in its message, and the hash it implies is taken
 * from the scheme rather than from the message: RFC 8446 section 4.4.3 defines each scheme
 * as a signature algorithm over the content, so a caller cannot choose a hash separately
 * from the scheme and cannot get the two out of step.
 *
 * WT_ERR_AUTHENTICATION when the signature does not verify, WT_ERR_UNSUPPORTED for a
 * scheme this implementation does not carry, WT_ERR_PROTOCOL for a key or signature that
 * is not well formed. */
wt_status_t wt_tls_signature_verify(const uint8_t *spki, size_t spki_len,
                                    uint16_t scheme, const uint8_t *content,
                                    size_t content_len, const uint8_t *signature,
                                    size_t signature_len);

/* Sign `content` with a private key, for the server's CertificateVerify. The mirror of
 * `wt_tls_signature_verify`, and the reason a client and a server here cannot disagree about
 * what a scheme means: both take the digest from the scheme and both set RSA-PSS's parameters
 * the same way.
 *
 * `private_key` is a DER private key (PKCS#8 or PKCS#1, which OpenSSL tells apart itself).
 * WT_ERR_LIMIT when the signature does not fit, WT_ERR_UNSUPPORTED for a scheme this
 * implementation does not carry or a key that does not match it, WT_ERR_PROTOCOL for a key
 * that is not a key. */
wt_status_t wt_tls_signature_sign(const uint8_t *private_key, size_t private_key_len,
                                  uint16_t scheme, const uint8_t *content,
                                  size_t content_len, uint8_t *signature_out,
                                  size_t capacity, size_t *signature_len);

/* Whether a scheme is one this implementation can verify, for a caller assembling the
 * signature_algorithms extension from the same list. */
int wt_tls_signature_scheme_supported(uint16_t scheme);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_TLS_TRUST_H */
