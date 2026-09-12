/* The pinned-operator-key trust policy. See wt_tls_pin.h for why.
 *
 * Almost nothing happens here, and that is the design: the key comparison is
 * `wt_tls_public_key_equal` in `wt_tls_cert.c`, tested on its own, and this
 * file only adds the one piece of state that comparison cannot express -- the
 * difference between "this is not the pinned key" and "nothing is pinned".
 */

#include "wt_tls_pin.h"

#include "wt_crypto.h"

#include <string.h>

void wt_tls_pinned_key_clear(wt_tls_pinned_key_t *pin) {
  if (pin == NULL) return;
  /* wt_secure_zero rather than memset: a clear the compiler may remove is a
     clear that cannot be relied on, and this function's whole purpose is that
     the pin afterwards refuses everything. */
  wt_secure_zero(pin, sizeof(*pin));
}

int wt_tls_pinned_key_is_set(const wt_tls_pinned_key_t *pin) {
  if (pin == NULL) return 0;
  if (!pin->pin_is_set) return 0;
  /* A pin flagged as set whose key is empty is a contradiction, and the safe
     reading of a contradiction is "not set". */
  return pin->key.storage_len > 0U ? 1 : 0;
}

int wt_tls_pinned_key_set_rsa(wt_tls_pinned_key_t *pin, const uint8_t *modulus,
                              size_t modulus_len, const uint8_t *exponent,
                              size_t exponent_len) {
  if (pin == NULL) return -1;
  wt_tls_pinned_key_clear(pin);
  if (wt_tls_public_key_set_rsa(&pin->key, modulus, modulus_len, exponent,
                                exponent_len) != 0) {
    wt_tls_pinned_key_clear(pin);
    return -1;
  }
  pin->pin_is_set = 1;
  return 0;
}

int wt_tls_pinned_key_set_rsa_hex(wt_tls_pinned_key_t *pin, const char *modulus,
                                  uint32_t exponent) {
  if (pin == NULL) return -1;
  wt_tls_pinned_key_clear(pin);
  if (wt_tls_public_key_set_rsa_hex(&pin->key, modulus, exponent) != 0) {
    wt_tls_pinned_key_clear(pin);
    return -1;
  }
  pin->pin_is_set = 1;
  return 0;
}

int wt_tls_pinned_key_set_ec(wt_tls_pinned_key_t *pin, int curve,
                             const uint8_t *point, size_t point_len) {
  if (pin == NULL) return -1;
  wt_tls_pinned_key_clear(pin);
  if (wt_tls_public_key_set_ec(&pin->key, curve, point, point_len) != 0) {
    wt_tls_pinned_key_clear(pin);
    return -1;
  }
  pin->pin_is_set = 1;
  return 0;
}

wt_tls_pin_result_t wt_tls_pinned_key_accepts_public_key(
    const wt_tls_pinned_key_t *pin, const wt_tls_public_key_t *peer) {
  if (!wt_tls_pinned_key_is_set(pin)) return WT_TLS_PIN_NO_PIN;
  if (peer == NULL || peer->storage_len == 0U) {
    return WT_TLS_PIN_BAD_CERTIFICATE;
  }
  /* A pin for one key type cannot be satisfied by a certificate that carries
     the other. This is not a mismatch of key material; it is a pin that does
     not apply, and an operator who pinned an RSA key and got an EC certificate
     needs to be told that rather than told the keys differ. */
  if (pin->key.is_rsa != peer->is_rsa) return WT_TLS_PIN_WRONG_KEY_TYPE;
  return wt_tls_public_key_equal(&pin->key, peer) ? WT_TLS_PIN_ACCEPTED
                                                  : WT_TLS_PIN_KEY_MISMATCH;
}

wt_tls_pin_result_t wt_tls_pinned_key_accepts_certificate(
    const wt_tls_pinned_key_t *pin, const uint8_t *certificate_der,
    size_t certificate_len) {
  wt_tls_public_key_t peer;

  if (!wt_tls_pinned_key_is_set(pin)) return WT_TLS_PIN_NO_PIN;
  if (certificate_der == NULL || certificate_len == 0U) {
    return WT_TLS_PIN_BAD_CERTIFICATE;
  }
  if (wt_tls_certificate_public_key(certificate_der, certificate_len, &peer) !=
      0) {
    return WT_TLS_PIN_BAD_CERTIFICATE;
  }
  {
    wt_tls_pin_result_t result =
        wt_tls_pinned_key_accepts_public_key(pin, &peer);
    wt_tls_public_key_clear(&peer);
    return result;
  }
}
