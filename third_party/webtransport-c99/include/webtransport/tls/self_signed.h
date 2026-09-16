/* A self-signed identity for local development (Phase 9).
 *
 * The plan's `--trust local-development` mode is only useful if a tool can SERVE something without a
 * certificate file, and a test that wants a loopback session should not have to borrow one from the
 * repository's fixtures either. This generates the pair in memory: an ECDSA P-256 key and a certificate for
 * the loopback names, signed by itself.
 *
 * The pin is the point of the design. A self-signed certificate is not trusted by anything -- that is what
 * "self-signed" means -- so a CLIENT reaches it only through `WT_TLS_TRUST_PINNED_CERTIFICATE` with the
 * fingerprint this call returns, or through the development bypass, which the trust layer restricts to loopback
 * names. One call therefore produces BOTH halves of a local development setup, and the fingerprint is a value
 * the caller can print, compare or hand to a peer.
 *
 * It is deliberately not a general certificate authority: no extensions beyond the subject alternative names,
 * one key, one signature, and a lifetime measured in days. Anything that needs more should use a real
 * certificate, which is what the SYSTEM and STORE trust modes are for.
 */

#ifndef WEBTRANSPORT_TLS_SELF_SIGNED_H
#define WEBTRANSPORT_TLS_SELF_SIGNED_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/status.h"
#include "webtransport/tls/handshake.h"
#include "webtransport/tls/keyschedule.h"
#include "webtransport/tls/session.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The buffers, sized from what a P-256 key and a one-name certificate actually take: a PKCS#8 P-256 key is
 * around 140 bytes and the certificate around 600, so these are generous by a factor of three and still
 * bounded. */
#define WT_TLS_SELF_SIGNED_KEY_MAX 512U
#define WT_TLS_SELF_SIGNED_CERT_MAX 2048U

typedef struct wt_tls_self_signed {
  uint8_t private_key[WT_TLS_SELF_SIGNED_KEY_MAX];
  size_t private_key_len;
  uint8_t certificate[WT_TLS_SELF_SIGNED_CERT_MAX];
  size_t certificate_len;
  /* The SHA-256 of the certificate, which is what a pinning client compares. */
  uint8_t fingerprint[WT_SHA256_LEN];
} wt_tls_self_signed_t;

/* Generate the pair. `common_name` is the subject and the first subject alternative name; the loopback
 * addresses are always included. Returns WT_ERR_UNSUPPORTED when this build has no TLS backend, which is the
 * honest answer for a build without OpenSSL rather than a certificate nobody can verify. */
wt_status_t wt_tls_self_signed_generate(wt_tls_self_signed_t *out, const char *common_name);

/* Fill a server identity that points INTO `self`, for the handshake to use. Kept separate from the generation
 * so that the structure holds no pointers to itself: a self-referential struct is one `memcpy` away from
 * pointing at somebody else's stack. */
void wt_tls_self_signed_identity(const wt_tls_self_signed_t *self, wt_tls_server_identity_t *out);

/* The certificate as the chain a trust check takes, built the same way and for the same reason. */
void wt_tls_self_signed_certificate(const wt_tls_self_signed_t *self, wt_tls_certificate_t *out);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_TLS_SELF_SIGNED_H */
