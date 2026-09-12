/* The XAIOS trust policy for a QUIC server: one pinned operator key.
 *
 * `wt_tls_cert.c` answers "did the peer sign this transcript with the key in
 * the certificate it sent?" and stops there, because a yes-or-no answer about a
 * signature is not a decision about trust. This file is the decision, and it is
 * deliberately small: it holds one key and says whether a peer's key is that
 * key.
 *
 * WHY A PIN AND NOT A STORE. XAIOS already made this choice for `xapt`: a
 * private deployment reaches its server by address, its key is long-lived, and
 * there is no public chain to validate. A trust store on a machine rebuilt from
 * an image would mean baking roots into the image and trusting every authority
 * that ever issues for the name, and validating a chain needs a clock and a
 * revocation story this system does not have. Pinning the operator's own key
 * makes the question answerable from the image alone: the peer either holds the
 * key the operator put in the image or the connection does not proceed.
 *
 * WHAT A PIN DOES NOT DO, and this has to be said out loud: it does not
 * authenticate a name. A pin answers "is this the machine this image was built
 * to talk to", not "is this the host that DNS named". Every deployment that
 * pins gives up being redirected, and that is the trade rather than an
 * oversight.
 *
 * THE FAILURE THAT MATTERS. An unset pin must never accept anything. A policy
 * object whose default is "trust everything" is one that will eventually be
 * constructed, not configured, and then used -- so an unset pin answers
 * WT_TLS_PIN_NO_PIN, which is a refusal, and there is no state of this
 * structure that means "accept any key".
 */

#ifndef WT_TLS_PIN_H
#define WT_TLS_PIN_H

#include <stddef.h>
#include <stdint.h>

#include "bearssl.h"
#include "wt_tls_cert.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Why an acceptance check came out the way it did. The distinct values are for
 * the caller's log: "the peer is not who we pinned" and "we never pinned
 * anyone" are different operational problems with the same consequence. */
typedef enum wt_tls_pin_result {
  /* The peer's key is the pinned key. The only accepting value. */
  WT_TLS_PIN_ACCEPTED = 0,
  /* The peer's key was read and it is not the pinned one. */
  WT_TLS_PIN_KEY_MISMATCH,
  /* No pin is set. A refusal, and deliberately not an acceptance. */
  WT_TLS_PIN_NO_PIN,
  /* The pin is set for the other key type, so this certificate cannot satisfy
     it. Never an acceptance. */
  WT_TLS_PIN_WRONG_KEY_TYPE,
  /* The certificate did not parse, or is empty. */
  WT_TLS_PIN_BAD_CERTIFICATE
} wt_tls_pin_result_t;

/* One pinned operator key. The key material is owned, not borrowed: see
 * wt_tls_public_key_t for why a key that outlives its decoder must be copied. */
typedef struct wt_tls_pinned_key {
  int pin_is_set;
  wt_tls_public_key_t key;
} wt_tls_pinned_key_t;

/* Zero a pin, which also unsets it: a zeroed pin refuses everything. */
void wt_tls_pinned_key_clear(wt_tls_pinned_key_t *pin);

/* Whether a pin is configured. A caller that forgets to check is still
 * refusing, because the acceptance functions answer WT_TLS_PIN_NO_PIN. */
int wt_tls_pinned_key_is_set(const wt_tls_pinned_key_t *pin);

/* Set the pin. The argument rules are `wt_tls_public_key_set_*`'s; a refusal
 * leaves the pin unset rather than half configured. */
int wt_tls_pinned_key_set_rsa(wt_tls_pinned_key_t *pin, const uint8_t *modulus,
                              size_t modulus_len, const uint8_t *exponent,
                              size_t exponent_len);
int wt_tls_pinned_key_set_rsa_hex(wt_tls_pinned_key_t *pin, const char *modulus,
                                  uint32_t exponent);
int wt_tls_pinned_key_set_ec(wt_tls_pinned_key_t *pin, int curve,
                             const uint8_t *point, size_t point_len);

/* Whether a peer's already-read public key is the pinned one. */
wt_tls_pin_result_t wt_tls_pinned_key_accepts_public_key(
    const wt_tls_pinned_key_t *pin, const wt_tls_public_key_t *peer);

/* Whether a DER certificate carries the pinned key.
 *
 * This does NOT check the certificate's signature, its dates, its issuer or its
 * extensions, and it does not need to: it answers one question, and
 * `wt_tls_certificate_verify_signature` answers the other. A certificate that
 * carries the pinned key but whose signature is not the peer's is refused
 * there; a certificate that carries a different key is refused here. Both have
 * to pass, and neither check is sufficient alone -- a pin by itself would
 * accept a certificate anyone could copy, and a signature check by itself would
 * accept any self-signed key an attacker generated. */
wt_tls_pin_result_t wt_tls_pinned_key_accepts_certificate(
    const wt_tls_pinned_key_t *pin, const uint8_t *certificate_der,
    size_t certificate_len);

#ifdef __cplusplus
}
#endif

#endif /* WT_TLS_PIN_H */
