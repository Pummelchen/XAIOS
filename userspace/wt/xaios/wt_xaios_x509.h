/*
 * A key the vendored WebTransport port can hold without naming this
 * repository's crypto headers (B-131).
 *
 * The port's `webtransport/crypto/crypto.h` and this repository's
 * `wt_crypto.h` declare the same identifiers for different types --
 * `wt_sha256_ctx_t`, `WT_SHA256_CTX_MAX`, `wt_sha256_init` and the rest -- so
 * one translation unit cannot include both, and the port's trust file needs a
 * public key while the code that parses one lives on this side. The two meet
 * here: an opaque, sufficiently large, sufficiently aligned buffer, and three
 * operations over it.
 *
 * The size is fixed rather than measured because the port's translation unit
 * cannot see the structure it stands for; `wt_xaios_x509.c` carries a
 * build-time assertion that it is large enough and fails its own build if a
 * future key structure outgrows it.
 */

#ifndef XAIOS_WT_XAIOS_X509_H
#define XAIOS_WT_XAIOS_X509_H

#include <stddef.h>
#include <stdint.h>

/* Room for one `wt_tls_public_key_t`: a 520-byte key buffer plus the two
   BearSSL views and their lengths. 640 is that with margin, and the assertion
   in the implementation is what keeps the margin honest. */
#define WT_XAIOS_KEY_STORAGE 640U

typedef struct wt_xaios_public_key {
  /* Present only to give the structure the alignment a key containing
     pointers needs. */
  uint64_t alignment;
  unsigned char storage[WT_XAIOS_KEY_STORAGE];
} wt_xaios_public_key_t;

/* Locate the SubjectPublicKeyInfo inside a DER certificate. The view points
   into `der`, which must outlive it. Returns 0 on success, -1 otherwise. */
int wt_xaios_spki_from_certificate(const uint8_t *der, size_t der_len,
                                   const uint8_t **spki, size_t *spki_len);

/* Parse a SubjectPublicKeyInfo into `out`. Returns 0 on success, -1 when the
   key algorithm is not one this port can verify. */
int wt_xaios_public_key_load(const uint8_t *spki, size_t spki_len,
                             wt_xaios_public_key_t *out);

/* Verify a signature over `content` with the key `load` produced.
 *
 * Returns 1 when the signature verifies, 0 when it does not, and -1 on a bad
 * argument, an unsupported scheme, or a key that does not match the scheme. */
int wt_xaios_signature_verify(const wt_xaios_public_key_t *key, uint16_t scheme,
                              const uint8_t *signature, size_t signature_len,
                              const uint8_t *content, size_t content_len);

/* Room for one RSA private key's eight components, or one EC private scalar.
   The assertion in the implementation is what keeps this honest; an RSA-4096
   key is 6 x 512 bytes plus the two small exponents, so 4096 is the same
   generous-by-a-bit shape the public key buffer has. */
#define WT_XAIOS_SKEY_STORAGE 4608U

typedef struct wt_xaios_private_key {
  uint64_t alignment;
  unsigned char storage[WT_XAIOS_SKEY_STORAGE];
} wt_xaios_private_key_t;

/* Parse a DER private key (PKCS#8 or PKCS#1) into `out`. Returns 0 on success,
   -1 for a key this backend does not carry. */
int wt_xaios_private_key_load(const uint8_t *der, size_t der_len,
                              wt_xaios_private_key_t *out);

/* The largest signature this key can produce, so a caller with a fixed buffer
   can tell "the signature does not fit" from "the key does not match". */
size_t wt_xaios_signature_size(const wt_xaios_private_key_t *key);

/* Sign `content` with the key `load` produced, under `scheme`.
 *
 * The digest is taken from the scheme, as RFC 8446 section 4.4.3 requires, so
 * a caller cannot choose a hash separately from the scheme and cannot get the
 * two out of step. RSA-PSS uses a salt as long as the hash and a fresh one per
 * signature, drawn from the platform's entropy.
 *
 * Returns 0 on success, -1 on a bad argument, an unsupported scheme, a key that
 * does not match the scheme, or an output buffer too small. */
int wt_xaios_signature_sign(const wt_xaios_private_key_t *key, uint16_t scheme,
                            const uint8_t *content, size_t content_len,
                            uint8_t *out, size_t capacity, size_t *out_len);

#endif
