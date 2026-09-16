/*
 * The bridge between the vendored WebTransport port and this repository's
 * certificate code (B-131). `wt_xaios_x509.h` says why the two cannot share a
 * translation unit; this file is the one side that names both, and it does
 * nothing but cast the opaque key buffer and forward three calls.
 */

#include "wt_xaios_x509.h"

#include "inner.h"

#include "wt_tls_cert.h"

#include <string.h>

#include <xaios_user.h>

/* The opaque buffer has to hold a real key structure. If a future key type
   grows past it, this build fails rather than a caller's key being truncated
   at run time. */
typedef char wt_xaios_key_fits[sizeof(wt_tls_public_key_t) <=
                                       WT_XAIOS_KEY_STORAGE
                                   ? 1
                                   : -1];

/* The private key's components, copied out of the decoder for the same reason
   the public key's are: `br_skey_decoder_get_rsa` hands out views into a
   decoder context that is a local in the loading function. */
#define WT_XAIOS_SKEY_BYTES 4096U

/* BearSSL's HMAC-DRBG refuses a seed shorter than 32 bytes, and 32 is also the
   SHA-256 output it is seeded for. */
#define WT_XAIOS_DRBG_SEED 32U

typedef struct wt_xaios_private {
  int is_rsa;
  size_t storage_len;
  unsigned char storage[WT_XAIOS_SKEY_BYTES];
  br_rsa_private_key rsa;
  br_ec_private_key ec;
} wt_xaios_private_t;

typedef char wt_xaios_skey_fits[sizeof(wt_xaios_private_t) <=
                                      WT_XAIOS_SKEY_STORAGE
                                  ? 1
                                  : -1];

static wt_xaios_private_t *private_of(const wt_xaios_private_key_t *key) {
  return (wt_xaios_private_t *)(void *)key->storage;
}

static wt_xaios_private_t *private_of_mutable(wt_xaios_private_key_t *key) {
  return (wt_xaios_private_t *)(void *)key->storage;
}

/* Append `length` bytes to the key's own storage at `*used` and return where
   they went, so a component's view points into the structure rather than into
   the decoder. */
static unsigned char *take_bytes(wt_xaios_private_t *key, const unsigned char *source,
                                 size_t length, size_t *used) {
  unsigned char *at;
  if (source == NULL || length == 0U) return NULL;
  if (*used + length > sizeof(key->storage)) return NULL;
  at = key->storage + *used;
  memcpy(at, source, length);
  *used += length;
  return at;
}

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

int wt_xaios_private_key_load(const uint8_t *der, size_t der_len,
                              wt_xaios_private_key_t *out) {
  br_skey_decoder_context decoder;
  const br_rsa_private_key *rsa;
  const br_ec_private_key *ec;
  wt_xaios_private_t *key;
  size_t used = 0U;

  if (out == NULL) return -1;
  memset(out, 0, sizeof(*out));
  if (der == NULL || der_len == 0U) return -1;
  key = private_of_mutable(out);

  br_skey_decoder_init(&decoder);
  br_skey_decoder_push(&decoder, der, der_len);
  if (br_skey_decoder_last_error(&decoder) != 0) return -1;

  rsa = br_skey_decoder_get_rsa(&decoder);
  if (rsa != NULL) {
/* The field's name is paired with its length member by token pasting -- `p`
   with `plen` -- so the two cannot drift apart in a hand-written list. */
#define WT_TAKE(field, size)                                                    \
  do {                                                                          \
    key->rsa.field = take_bytes(key, rsa->field, (size), &used);                \
    if (key->rsa.field == NULL) return -1;                                      \
    key->rsa.field##len = (size);                                               \
  } while (0)
    /* BearSSL's private key carries the CRT factors and the modulus's bit
       length, not the modulus itself: the length is what sizes a signature,
       and the factors are what signs it. */
    WT_TAKE(p, rsa->plen);
    WT_TAKE(q, rsa->qlen);
    WT_TAKE(dp, rsa->dplen);
    WT_TAKE(dq, rsa->dqlen);
    WT_TAKE(iq, rsa->iqlen);
#undef WT_TAKE
    key->rsa.n_bitlen = rsa->n_bitlen;
    key->is_rsa = 1;
    key->storage_len = used;
    return 0;
  }

  ec = br_skey_decoder_get_ec(&decoder);
  if (ec != NULL) {
    key->ec.x = take_bytes(key, ec->x, ec->xlen, &used);
    if (key->ec.x == NULL) return -1;
    key->ec.xlen = ec->xlen;
    key->ec.curve = ec->curve;
    key->is_rsa = 0;
    key->storage_len = used;
    return 0;
  }
  /* A key type this backend cannot sign with. A refusal, because a caller told
     "success" would have no signature. */
  return -1;
}

/* The hash function and digest length a scheme signs with, or NULL when the
   scheme is not one this backend carries. The two are returned together
   because a scheme IS a hash and a key type, and separating them is how a
   caller gets a P-256 key checked against a SHA-384 digest. */
static const br_hash_class *scheme_hash(uint16_t scheme, size_t *out_length,
                                        int *out_is_rsa, int *out_curve) {
  *out_is_rsa = 0;
  *out_curve = -1;
  switch (scheme) {
    case 0x0804U: /* rsa_pss_rsae_sha256 */
      *out_length = 32U;
      *out_is_rsa = 1;
      return &br_sha256_vtable;
    case 0x0805U: /* rsa_pss_rsae_sha384 */
      *out_length = 48U;
      *out_is_rsa = 1;
      return &br_sha384_vtable;
    case 0x0806U: /* rsa_pss_rsae_sha512 */
      *out_length = 64U;
      *out_is_rsa = 1;
      return &br_sha512_vtable;
    case 0x0403U: /* ecdsa_secp256r1_sha256 */
      *out_length = 32U;
      *out_curve = BR_EC_secp256r1;
      return &br_sha256_vtable;
    case 0x0503U: /* ecdsa_secp384r1_sha384 */
      *out_length = 48U;
      *out_curve = BR_EC_secp384r1;
      return &br_sha384_vtable;
    default:
      return NULL;
  }
}

size_t wt_xaios_signature_size(const wt_xaios_private_key_t *key) {
  wt_xaios_private_t *private_key;
  if (key == NULL) return 0U;
  private_key = private_of(key);
  if (private_key->is_rsa) {
    return ((size_t)private_key->rsa.n_bitlen + 7U) / 8U;
  }
  /* An ECDSA-Sig-Value is at most two integers of the curve's byte length plus
     the DER framing. */
  if (private_key->ec.curve == BR_EC_secp521r1) return 141U;
  if (private_key->ec.curve == BR_EC_secp384r1) return 104U;
  return 72U;
}

int wt_xaios_signature_sign(const wt_xaios_private_key_t *key, uint16_t scheme,
                            const uint8_t *content, size_t content_len,
                            uint8_t *out, size_t capacity, size_t *out_len) {
  const br_hash_class *hash;
  size_t hash_length = 0U;
  int want_rsa = 0;
  int want_curve = -1;
  uint8_t digest[64];
  size_t signature_length = 0U;
  br_hash_compat_context context;
  wt_xaios_private_t *private_key;

  if (key == NULL || content == NULL || out == NULL || out_len == NULL) {
    return -1;
  }
  if (content_len == 0U) return -1;
  *out_len = 0U;
  hash = scheme_hash(scheme, &hash_length, &want_rsa, &want_curve);
  if (hash == NULL || hash_length == 0U || hash_length > sizeof(digest)) {
    return -1;
  }
  private_key = private_of(key);
  if (private_key->is_rsa != want_rsa) return -1;
  if (!want_rsa && private_key->ec.curve != want_curve) return -1;

  hash->init(&context.vtable);
  hash->update(&context.vtable, content, content_len);
  hash->out(&context.vtable, digest);

  if (want_rsa) {
    /* RFC 8446 section 4.2.3: RSA-PSS with a salt as long as the hash. The
       salt must not repeat, so it comes from the platform's entropy rather
       than from anything this file could count. */
    br_hmac_drbg_context rng;
    uint8_t seed[WT_XAIOS_DRBG_SEED];
    uint32_t ok;
    /* An RSA signature is exactly as long as the modulus, which BearSSL keeps
       as an exact bit length rather than as bytes. */
    signature_length = ((size_t)private_key->rsa.n_bitlen + 7U) / 8U;
    if (signature_length == 0U || capacity < signature_length) return -1;
    if (xaios_random(seed, (u64)sizeof(seed)) != 0) return -1;
    br_hmac_drbg_init(&rng, &br_sha256_vtable, seed, sizeof(seed));
    ok = br_rsa_i31_pss_sign(&rng.vtable, hash, hash, digest, hash_length,
                             &private_key->rsa, out);
    if (ok != 1U) return -1;
    *out_len = signature_length;
  } else {
    size_t written = br_ecdsa_i31_sign_asn1(&br_ec_prime_i31, hash, digest,
                                            &private_key->ec, out);
    if (written == 0U || written > capacity) return -1;
    *out_len = written;
  }
  return 0;
}
