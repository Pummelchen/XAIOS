/* Signature verification over BearSSL, shared by the in-tree certificate
 * module and the vendored WebTransport port's trust backend (B-131).
 *
 * The scheme dispatch lives here rather than in either caller because a scheme
 * means the same thing to both: one hash function, one padding rule, and one
 * curve-consistency check. The in-tree module keeps its certificate and key
 * wrappers; the port's backend parses an SPKI itself and calls this.
 */

#include "wt_tls_cert.h"

#include "inner.h"

#include <string.h>

/* Reduce a big-endian integer by stripping leading zeros, which is the form
 * BearSSL's verifiers expect for a signature and for a key component. */
static void strip_leading_zeros(const uint8_t **p, size_t *len) {
  while (*len > 0U && **p == 0U) {
    (*p)++;
    (*len)--;
  }
}

/* The check itself, over key components rather than over a certificate or a
 * key structure.
 *
 * Split out because the callers arrive holding the key differently. The
 * in-tree module has either a certificate to decode or a key it owns; the
 * vendored WebTransport port reaches this with the SubjectPublicKeyInfo it
 * parsed in `wt_x509_spki.c`. Doing the decoding inside would force each
 * caller to keep whatever the key came from, which is the thing B-92 is
 * about: the key is bounded and the certificate is not. */
int wt_tls_verify_signature_components(
    int key_type, const br_rsa_public_key *key_rsa,
    const br_ec_public_key *key_ec, uint16_t scheme,
    const uint8_t *signature, size_t signature_len, const uint8_t *content,
    size_t content_len) {
  uint8_t digest[WT_TLS_MAX_HASH_LEN];
  const uint8_t *sig;
  size_t sig_len;
  uint32_t ok = 0U;

  if (key_rsa == NULL || key_ec == NULL) return -1;
  if (signature == NULL || signature_len == 0U) return -1;
  if (content == NULL) return -1;
  if (signature_len > 0xFFFFU) return -1;

  /* The signature and the key components are unsigned big-endian integers and
     may carry leading zero bytes; the verifiers expect them stripped. The
     signature is a view into the peer's message, so the stripped pointer is a
     local rather than a modification of that buffer. */
  sig = signature;
  sig_len = signature_len;
  strip_leading_zeros(&sig, &sig_len);
  if (sig_len == 0U) return -1;

  switch (scheme) {
    case WT_TLS_SIG_RSA_PSS_RSAE_SHA256:
    case WT_TLS_SIG_RSA_PSS_RSAE_SHA384:
    case WT_TLS_SIG_RSA_PSS_RSAE_SHA512: {
      const br_hash_class *hf = (scheme == WT_TLS_SIG_RSA_PSS_RSAE_SHA256)
                                    ? &br_sha256_vtable
                                : (scheme == WT_TLS_SIG_RSA_PSS_RSAE_SHA384)
                                    ? &br_sha384_vtable
                                    : &br_sha512_vtable;
      size_t hash_len = (scheme == WT_TLS_SIG_RSA_PSS_RSAE_SHA256) ? 32U
                       : (scheme == WT_TLS_SIG_RSA_PSS_RSAE_SHA384) ? 48U
                                                                            : 64U;
      const uint8_t *n;
      size_t nlen;
      br_rsa_public_key rsa_key;

      if (key_type != BR_KEYTYPE_RSA) return -1;
      if (content_len == 0U) return -1;
      /* Belt as well as braces: the buffer above is the bound, and this makes
         a scheme added later fail loudly rather than write past it. */
      if (hash_len == 0U || hash_len > sizeof(digest)) return -1;
      /* TLS 1.3 uses RSA-PSS with a salt as long as the hash, which is what
         RFC 8446 section 4.2.3 says and what makes this different from a
         PKCS#1 v1.5 check. */
      {
        br_hash_compat_context hc;
        hf->init(&hc.vtable);
        hf->update(&hc.vtable, content, content_len);
        hf->out(&hc.vtable, digest);
      }
      /* The modulus must be long enough for the hash plus the PSS overhead;
         the verifier checks the rest. */
      n = key_rsa->n;
      nlen = key_rsa->nlen;
      strip_leading_zeros(&n, &nlen);
      if (nlen == 0U) return -1;
      /* BearSSL's `br_rsa_public_key` takes non-const pointers although the
         verifier only reads them. The key is a view into the peer's
         certificate, which this function does not modify; the cast is the
         interface's shape and not a permission to write. */
      rsa_key.n = (unsigned char *)(uintptr_t)n;
      rsa_key.nlen = nlen;
      rsa_key.e = key_rsa->e;
      rsa_key.elen = key_rsa->elen;
      ok = br_rsa_i31_pss_vrfy(sig, sig_len, hf, hf, digest, hash_len,
                               &rsa_key);
      break;
    }
    case WT_TLS_SIG_ECDSA_SECP256R1_SHA256:
    case WT_TLS_SIG_ECDSA_SECP384R1_SHA384:
    case WT_TLS_SIG_ECDSA_SECP521R1_SHA512: {
      const br_hash_class *hf = (scheme == WT_TLS_SIG_ECDSA_SECP256R1_SHA256)
                                    ? &br_sha256_vtable
                                : (scheme == WT_TLS_SIG_ECDSA_SECP384R1_SHA384)
                                    ? &br_sha384_vtable
                                    : &br_sha512_vtable;
      int expected_curve =
          (scheme == WT_TLS_SIG_ECDSA_SECP256R1_SHA256) ? BR_EC_secp256r1
          : (scheme == WT_TLS_SIG_ECDSA_SECP384R1_SHA384)
              ? BR_EC_secp384r1
              : BR_EC_secp521r1;
      if (key_type != BR_KEYTYPE_EC) return -1;
      if (content_len == 0U) return -1;
      /* RFC 8446 section 4.4.3: the scheme must be consistent with the key in
         the certificate. A P-384 scheme answered by a P-256 key is not a
         signature that failed to verify; it is a message that does not make
         sense, and saying so is the difference between "the peer made a
         mistake" and "the peer forged something". Without this check the
         verifier runs a P-256 multiplication with a 48-byte digest and returns
         0 -- the right answer by accident, and a -1 that an audit can point at
         is better than an accident. */
      if (key_ec->curve != expected_curve) return -1;
      {
        br_hash_compat_context hc;
        size_t hash_len = hf->desc >> BR_HASHDESC_OUT_OFF & BR_HASHDESC_OUT_MASK;
        if (hash_len == 0U || hash_len > sizeof(digest)) return -1;
        hf->init(&hc.vtable);
        hf->update(&hc.vtable, content, content_len);
        hf->out(&hc.vtable, digest);
        /* The implementation is the constant-time prime-field one, and the key
           it is given is the one the certificate carried. */
        ok = br_ecdsa_i31_vrfy_asn1(&br_ec_prime_i31, digest, hash_len,
                                    key_ec, sig, sig_len);
      }
      break;
    }
    default:
      /* An unsupported scheme is a refusal. Falling through to "0" would say
         the signature was checked and failed, which is a different and more
         misleading answer than "this cannot be checked". */
      return -1;
  }

  wt_secure_zero(digest, sizeof(digest));
  return ok == 1U ? 1 : 0;
}
