/* Peer authentication. See webtransport/tls/trust.h.
 *
 * OpenSSL does the X.509 work and the signature arithmetic; what this file owns is the
 * policy -- which modes exist, what each one accepts, and which failures are trust
 * failures rather than protocol errors. The chain is parsed, validated and discarded
 * inside one call, so no X.509 object outlives the function that needed it and the public
 * header mentions no OpenSSL type.
 */

#include "webtransport/tls/trust.h"

#include "webtransport/crypto/crypto.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <string.h>

int wt_tls_signature_scheme_supported(uint16_t scheme) {
  switch (scheme) {
    case WT_TLS_SIGNATURE_ECDSA_SECP256R1_SHA256:
    case WT_TLS_SIGNATURE_ECDSA_SECP384R1_SHA384:
    case WT_TLS_SIGNATURE_RSA_PSS_RSAE_SHA256:
    case WT_TLS_SIGNATURE_RSA_PSS_RSAE_SHA384:
    case WT_TLS_SIGNATURE_RSA_PSS_RSAE_SHA512:
    case WT_TLS_SIGNATURE_ED25519:
      return 1;
    default:
      return 0;
  }
}

/* The digest a scheme signs with, or NULL for Ed25519, which hashes internally and takes
 * no separate digest at all (RFC 8446 section 4.2.3). The digest is a function of the
 * scheme, which is why this is one function and not two parameters. */
static const EVP_MD *scheme_digest(uint16_t scheme) {
  switch (scheme) {
    case WT_TLS_SIGNATURE_ECDSA_SECP256R1_SHA256:
    case WT_TLS_SIGNATURE_RSA_PSS_RSAE_SHA256:
      return EVP_sha256();
    case WT_TLS_SIGNATURE_ECDSA_SECP384R1_SHA384:
    case WT_TLS_SIGNATURE_RSA_PSS_RSAE_SHA384:
      return EVP_sha384();
    case WT_TLS_SIGNATURE_RSA_PSS_RSAE_SHA512:
      return EVP_sha512();
    case WT_TLS_SIGNATURE_ED25519:
      return NULL;
    default:
      return NULL;
  }
}

/* Whether a scheme is one of the RSA-PSS family, which needs its padding parameters set
 * rather than the key's default. */
static int scheme_is_rsa_pss(uint16_t scheme) {
  return scheme == WT_TLS_SIGNATURE_RSA_PSS_RSAE_SHA256 ||
         scheme == WT_TLS_SIGNATURE_RSA_PSS_RSAE_SHA384 ||
         scheme == WT_TLS_SIGNATURE_RSA_PSS_RSAE_SHA512;
}

/* The loopback names the development bypass is restricted to, which is the same set the
 * Swift client's `localDevelopmentSelfSigned` policy allows. Compared exactly: a name that
 * merely contains one of these is not one of them. Public because the API checks the same
 * rule before a connection is attempted. */
int wt_tls_trust_host_is_loopback(const char *host_name) {
  if (host_name == NULL) return 0;
  return strcmp(host_name, "localhost") == 0 || strcmp(host_name, "127.0.0.1") == 0 ||
         strcmp(host_name, "::1") == 0 || strcmp(host_name, "[::1]") == 0;
}

/* The leaf of a parsed chain, or NULL. */
static X509 *parse_first(const wt_tls_certificate_t *certificate,
                         STACK_OF(X509) * rest) {
  size_t i;
  X509 *leaf = NULL;

  for (i = 0U; i < certificate->count; i++) {
    const unsigned char *cursor = certificate->entries[i].der;
    X509 *parsed = d2i_X509(NULL, &cursor, (long)certificate->entries[i].der_len);
    if (parsed == NULL) {
      /* A chain entry that is not DER is a malformed message rather than an untrusted one,
       * and the caller gets a protocol error for it. Nothing is freed here: the caller owns
       * the stack and releases it on every path, so a failure that freed it too would free
       * it twice. */
      return NULL;
    }
    if (leaf == NULL) {
      leaf = parsed;
    } else if (sk_X509_push(rest, parsed) == 0) {
      X509_free(parsed);
      return NULL;
    }
  }
  return leaf;
}

/* The leaf's SubjectPublicKeyInfo, in DER. */
static wt_status_t leaf_spki(X509 *leaf, uint8_t *out, size_t capacity,
                             size_t *out_len) {
  unsigned char *cursor = out;
  int measured;
  int written;

  *out_len = 0U;
  /* Measured with a NULL output first: i2d_X509_PUBKEY writes before it reports how much
   * it wrote, so a key larger than the buffer would be an overflow rather than a refusal. */
  measured = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(leaf), NULL);
  if (measured <= 0) return WT_ERR_PROTOCOL;
  if ((size_t)measured > capacity) return WT_ERR_LIMIT;
  written = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(leaf), &cursor);
  if (written != measured) {
    memset(out, 0, capacity);
    return WT_ERR_PROTOCOL;
  }
  *out_len = (size_t)written;
  return WT_OK;
}

/* SHA-256 over a DER certificate, which is what a pinned fingerprint is. */
static wt_status_t certificate_fingerprint(const uint8_t *der, size_t len,
                                           uint8_t out[WT_SHA256_LEN]) {
  return wt_sha256(der, len, out);
}

wt_status_t wt_tls_trust_verify(const wt_tls_trust_policy_t *policy,
                                const wt_tls_certificate_t *certificate,
                                uint8_t spki_out[WT_TLS_SPKI_MAX],
                                size_t *spki_len) {
  STACK_OF(X509) *rest = NULL;
  X509 *leaf = NULL;
  X509_STORE *store = NULL;
  X509_STORE_CTX *ctx = NULL;
  wt_status_t status = WT_ERR_TRUST;

  if (policy == NULL || certificate == NULL || spki_out == NULL ||
      spki_len == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  *spki_len = 0U;

  /* The pin is checked before anything is parsed: it is a property of the bytes, and a
   * pinned mode that parsed first would be doing work whose result it ignores. */
  if (policy->mode == WT_TLS_TRUST_PINNED_CERTIFICATE) {
    uint8_t fingerprint[WT_SHA256_LEN];
    size_t i;
    int matched = 0;

    if (policy->fingerprint_count == 0U ||
        policy->fingerprint_count > WT_TLS_PINNED_MAX) {
      return WT_ERR_INVALID_ARGUMENT;
    }
    if (certificate->count == 0U) return WT_ERR_TRUST;
    status = certificate_fingerprint(certificate->entries[0].der,
                                     certificate->entries[0].der_len, fingerprint);
    if (status != WT_OK) return status;
    /* Every pin is compared, in constant time, and the loop does not stop at the first
     * match: how many fingerprints a policy holds is a deployment fact, and a comparison
     * that returned early would report which one matched through its timing. */
    for (i = 0U; i < policy->fingerprint_count; i++) {
      matched |= wt_ct_equal(fingerprint, policy->fingerprints[i], WT_SHA256_LEN);
    }
    wt_secure_zero(fingerprint, sizeof(fingerprint));
    if (!matched) return WT_ERR_TRUST;
    /* The key still has to be extracted, because the caller needs it for
     * CertificateVerify. */
    rest = sk_X509_new_null();
    if (rest == NULL) return WT_ERR_OUT_OF_MEMORY;
    leaf = parse_first(certificate, rest);
    if (leaf == NULL) {
      status = WT_ERR_PROTOCOL;
      goto done;
    }
    status = leaf_spki(leaf, spki_out, WT_TLS_SPKI_MAX, spki_len);
    goto done;
  }

  if (policy->mode == WT_TLS_TRUST_LOCAL_DEVELOPMENT) {
    /* The bypass is restricted to loopback names, and the restriction is part of the
     * mode: a caller that reached for the development policy against a real endpoint
     * gets a trust failure rather than a connection that is authenticated by nothing. */
    if (!wt_tls_trust_host_is_loopback(policy->host_name)) return WT_ERR_TRUST;
    rest = sk_X509_new_null();
    if (rest == NULL) return WT_ERR_OUT_OF_MEMORY;
    leaf = parse_first(certificate, rest);
    if (leaf == NULL) {
      status = WT_ERR_PROTOCOL;
      goto done;
    }
    status = leaf_spki(leaf, spki_out, WT_TLS_SPKI_MAX, spki_len);
    goto done;
  }

  if (policy->mode != WT_TLS_TRUST_SYSTEM && policy->mode != WT_TLS_TRUST_STORE) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (certificate->count == 0U) return WT_ERR_TRUST;

  rest = sk_X509_new_null();
  if (rest == NULL) return WT_ERR_OUT_OF_MEMORY;
  leaf = parse_first(certificate, rest);
  if (leaf == NULL) {
    status = WT_ERR_PROTOCOL;
    goto done;
  }

  store = X509_STORE_new();
  if (store == NULL) {
    status = WT_ERR_OUT_OF_MEMORY;
    goto done;
  }
  if (policy->mode == WT_TLS_TRUST_SYSTEM) {
    if (X509_STORE_set_default_paths(store) != 1) {
      /* A platform with no trust store configured cannot validate anything, and saying so
       * is more useful than reporting every certificate as untrusted. */
      status = WT_ERR_UNSUPPORTED;
      goto done;
    }
  } else {
    BIO *bundle;
    if (policy->ca_bundle == NULL || policy->ca_bundle_len == 0U) {
      status = WT_ERR_TRUST;
      goto done;
    }
    bundle = BIO_new_mem_buf(policy->ca_bundle, (int)policy->ca_bundle_len);
    if (bundle == NULL) {
      status = WT_ERR_OUT_OF_MEMORY;
      goto done;
    }
    for (;;) {
      X509 *trusted = PEM_read_bio_X509_AUX(bundle, NULL, NULL, NULL);
      if (trusted == NULL) break;
      if (X509_STORE_add_cert(store, trusted) != 1) {
        /* A certificate the store already holds is not an error: the same bundle may
         * legitimately contain a certificate twice. Any other failure means the bundle is
         * unusable, and a trust store that silently dropped an anchor would refuse
         * certificates the caller meant to trust. */
        unsigned long error = ERR_peek_last_error();
        if (ERR_GET_REASON(error) != X509_R_CERT_ALREADY_IN_HASH_TABLE) {
          X509_free(trusted);
          BIO_free(bundle);
          status = WT_ERR_TRUST;
          goto done;
        }
        ERR_clear_error();
      }
      X509_free(trusted);
    }
    BIO_free(bundle);
    ERR_clear_error();
  }

  ctx = X509_STORE_CTX_new();
  if (ctx == NULL) {
    status = WT_ERR_OUT_OF_MEMORY;
    goto done;
  }
  if (X509_STORE_CTX_init(ctx, store, leaf, rest) != 1) {
    status = WT_ERR_TRUST;
    goto done;
  }
  if (policy->host_name != NULL) {
    /* The name check is part of validation rather than a second step, so a chain that is
     * valid but for the wrong name cannot be mistaken for a valid one. */
    X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(ctx);
    if (X509_VERIFY_PARAM_set1_host(param, policy->host_name, 0U) != 1) {
      status = WT_ERR_INVALID_ARGUMENT;
      goto done;
    }
  }
  if (X509_verify_cert(ctx) != 1) {
    /* Every reason a chain can be refused is a trust failure from the caller's side: an
     * unknown issuer, an expired certificate, a name that does not match. The specific
     * OpenSSL reason is not propagated into the status, because a status is what a caller
     * branches on and the reason is a diagnostic the log owns. */
    status = WT_ERR_TRUST;
    goto done;
  }
  status = leaf_spki(leaf, spki_out, WT_TLS_SPKI_MAX, spki_len);

done:
  X509_STORE_CTX_free(ctx);
  X509_STORE_free(store);
  X509_free(leaf);
  sk_X509_pop_free(rest, X509_free);
  if (status != WT_OK) memset(spki_out, 0, WT_TLS_SPKI_MAX);
  return status;
}

wt_status_t wt_tls_certificate_verify_content(
    int from_server, const uint8_t transcript_hash[WT_TLS13_SECRET_LEN],
    uint8_t out[WT_TLS_CERTIFICATE_VERIFY_CONTENT_LEN]) {
  static const char server_context[] = "TLS 1.3, server CertificateVerify";
  static const char client_context[] = "TLS 1.3, client CertificateVerify";
  const char *context = from_server ? server_context : client_context;
  size_t context_len = strlen(context);

  if (transcript_hash == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* The 64 spaces are a deliberate prefix: they put the context string past the point a
   * signature algorithm's internal padding can reach (RFC 8446 section 4.4.3). */
  memset(out, 0x20, 64U);
  memcpy(out + 64U, context, context_len);
  out[64U + context_len] = 0U;
  memcpy(out + 64U + context_len + 1U, transcript_hash, WT_TLS13_SECRET_LEN);
  return WT_OK;
}

wt_status_t wt_tls_signature_verify(const uint8_t *spki, size_t spki_len,
                                    uint16_t scheme, const uint8_t *content,
                                    size_t content_len, const uint8_t *signature,
                                    size_t signature_len) {
  const unsigned char *cursor;
  EVP_PKEY *key = NULL;
  EVP_MD_CTX *ctx = NULL;
  EVP_PKEY_CTX *pkey_ctx = NULL;
  const EVP_MD *digest;
  wt_status_t status = WT_ERR_UNSUPPORTED;
  int ok;

  if (spki == NULL || content == NULL || signature == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (!wt_tls_signature_scheme_supported(scheme)) return WT_ERR_UNSUPPORTED;
  digest = scheme_digest(scheme);

  cursor = spki;
  key = d2i_PUBKEY(NULL, &cursor, (long)spki_len);
  if (key == NULL) return WT_ERR_PROTOCOL;
  /* The DER must be exactly the key: trailing bytes mean the caller handed over something
   * other than one SubjectPublicKeyInfo. */
  if ((size_t)(cursor - spki) != spki_len) {
    EVP_PKEY_free(key);
    return WT_ERR_PROTOCOL;
  }

  /* RFC 8446 section 4.2.3 binds each signature scheme to a KEY TYPE, and TLS 1.3 removed PKCS#1 v1.5 from
   * CertificateVerify entirely. Verifying without that binding let an RSA key answer a claim of
   * `ecdsa_secp256r1_sha256`: the signature DID verify -- under the leaf's own RSA key, with OpenSSL's default
   * PKCS#1 v1.5 padding, because no RSA-PSS parameters were set for a scheme this code did not recognise as
   * PSS. An audit proved it with the fixture's RSA leaf. The key's type is checked here rather than the
   * scheme's digest, because it is the key that selects the padding. */
  {
    int key_type = EVP_PKEY_base_id(key);
    int matches = 0;
    if (scheme == WT_TLS_SIGNATURE_ECDSA_SECP256R1_SHA256 ||
        scheme == WT_TLS_SIGNATURE_ECDSA_SECP384R1_SHA384) {
      matches = key_type == EVP_PKEY_EC;
    } else if (scheme == WT_TLS_SIGNATURE_ED25519) {
      matches = key_type == EVP_PKEY_ED25519;
    } else if (scheme_is_rsa_pss(scheme)) {
      matches = key_type == EVP_PKEY_RSA;
    }
    if (!matches) {
      /* A scheme the peer's key cannot produce is a protocol violation, not a bad signature: the peer named an
       * algorithm that does not go with the key it sent. */
      EVP_PKEY_free(key);
      return WT_ERR_PROTOCOL;
    }
  }

  ctx = EVP_MD_CTX_new();
  if (ctx == NULL) {
    EVP_PKEY_free(key);
    return WT_ERR_OUT_OF_MEMORY;
  }
  if (EVP_DigestVerifyInit(ctx, &pkey_ctx, digest, NULL, key) != 1) goto done;
  if (scheme_is_rsa_pss(scheme)) {
    /* RFC 8446 section 4.2.3: rsa_pss_rsae_* means PSS with the scheme's own digest as the
     * MGF1 digest and a salt as long as that digest. OpenSSL's defaults are not those, so
     * they are set rather than assumed. */
    if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) != 1) goto done;
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, RSA_PSS_SALTLEN_DIGEST) != 1) {
      goto done;
    }
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, digest) != 1) goto done;
  }
  ok = EVP_DigestVerify(ctx, signature, signature_len, content, content_len);
  /* One means verified, zero means the signature is wrong, and anything else is an error
   * in the key or the scheme rather than a verdict on the signature. */
  status = (ok == 1) ? WT_OK : ((ok == 0) ? WT_ERR_AUTHENTICATION : WT_ERR_UNSUPPORTED);

done:
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(key);
  return status;
}

wt_status_t wt_tls_signature_sign(const uint8_t *private_key, size_t private_key_len,
                                  uint16_t scheme, const uint8_t *content,
                                  size_t content_len, uint8_t *signature_out,
                                  size_t capacity, size_t *signature_len) {
  const unsigned char *cursor;
  EVP_PKEY *key = NULL;
  EVP_MD_CTX *ctx = NULL;
  EVP_PKEY_CTX *pkey_ctx = NULL;
  const EVP_MD *digest;
  wt_status_t status = WT_ERR_UNSUPPORTED;
  size_t needed = 0U;
  int ok;

  if (private_key == NULL || content == NULL || signature_out == NULL ||
      signature_len == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  *signature_len = 0U;
  if (!wt_tls_signature_scheme_supported(scheme)) return WT_ERR_UNSUPPORTED;
  digest = scheme_digest(scheme);

  cursor = private_key;
  key = d2i_AutoPrivateKey(NULL, &cursor, (long)private_key_len);
  if (key == NULL) return WT_ERR_PROTOCOL;
  if ((size_t)(cursor - private_key) != private_key_len) {
    EVP_PKEY_free(key);
    return WT_ERR_PROTOCOL;
  }

  ctx = EVP_MD_CTX_new();
  if (ctx == NULL) {
    EVP_PKEY_free(key);
    return WT_ERR_OUT_OF_MEMORY;
  }
  if (EVP_DigestSignInit(ctx, &pkey_ctx, digest, NULL, key) != 1) goto done;
  if (scheme_is_rsa_pss(scheme)) {
    if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) != 1) goto done;
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, RSA_PSS_SALTLEN_DIGEST) != 1) {
      goto done;
    }
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, digest) != 1) goto done;
  }
  /* Measured before anything is written, so a signature larger than the caller's buffer is a
   * refusal rather than an overflow. */
  if (EVP_DigestSign(ctx, NULL, &needed, content, content_len) != 1) goto done;
  if (needed > capacity) {
    status = WT_ERR_LIMIT;
    goto done;
  }
  ok = EVP_DigestSign(ctx, signature_out, &needed, content, content_len);
  if (ok == 1) {
    *signature_len = needed;
    status = WT_OK;
  }

done:
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(key);
  if (status != WT_OK) memset(signature_out, 0, capacity);
  return status;
}
