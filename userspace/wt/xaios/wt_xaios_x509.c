/*
 * The bridge between the vendored WebTransport port and this repository's
 * certificate code (B-131). `wt_xaios_x509.h` says why the two cannot share a
 * translation unit; this file is the one side that names both, and it does
 * nothing but cast the opaque key buffer and forward three calls.
 */

#include "wt_xaios_x509.h"

#include "wt_tls_cert.h"

/* The opaque buffer has to hold a real key structure. If a future key type
   grows past it, this build fails rather than a caller's key being truncated
   at run time. */
typedef char wt_xaios_key_fits[sizeof(wt_tls_public_key_t) <=
                                       WT_XAIOS_KEY_STORAGE
                                   ? 1
                                   : -1];

static wt_tls_public_key_t *key_of(const wt_xaios_public_key_t *key) {
  return (wt_tls_public_key_t *)(void *)key->storage;
}

static wt_tls_public_key_t *key_of_mutable(wt_xaios_public_key_t *key) {
  return (wt_tls_public_key_t *)(void *)key->storage;
}

int wt_xaios_spki_from_certificate(const uint8_t *der, size_t der_len,
                                   const uint8_t **spki, size_t *spki_len) {
  return wt_tls_certificate_spki(der, der_len, spki, spki_len);
}

int wt_xaios_public_key_load(const uint8_t *spki, size_t spki_len,
                             wt_xaios_public_key_t *out) {
  if (out == NULL) return -1;
  return wt_tls_public_key_from_spki(spki, spki_len, key_of_mutable(out));
}

int wt_xaios_signature_verify(const wt_xaios_public_key_t *key, uint16_t scheme,
                              const uint8_t *signature, size_t signature_len,
                              const uint8_t *content, size_t content_len) {
  wt_tls_public_key_t *parsed;
  if (key == NULL) return -1;
  parsed = key_of(key);
  return wt_tls_verify_signature_components(
      parsed->is_rsa ? BR_KEYTYPE_RSA : BR_KEYTYPE_EC, &parsed->rsa,
      &parsed->ec, scheme, signature, signature_len, content, content_len);
}
