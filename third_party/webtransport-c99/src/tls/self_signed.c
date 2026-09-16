/* A self-signed identity for local development (Phase 9). */

#include "webtransport/tls/self_signed.h"

#include <stdio.h>
#include <string.h>

#include "webtransport/crypto/crypto.h"

/* OpenSSL is this build's TLS backend, exactly as it is for the trust layer: there is no second backend to
 * guard against yet, and a generator that compiled as a stub beside a trust layer that does not would be a
 * promise the build cannot keep. */
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

wt_status_t wt_tls_self_signed_generate(wt_tls_self_signed_t *out, const char *common_name) {
  EVP_PKEY_CTX *key_context = NULL;
  EVP_PKEY *key = NULL;
  X509 *certificate = NULL;
  X509_NAME *name = NULL;
  unsigned char *cursor;
  int written;

  if (out == NULL || common_name == NULL || common_name[0] == '\0') return WT_ERR_INVALID_ARGUMENT;
  memset(out, 0, sizeof(*out));

  /* A P-256 key: small enough to keep the whole identity in a few hundred bytes, and the scheme TLS 1.3
   * pairs with it is the one the identity advertises. */
  key_context = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
  if (key_context == NULL) return WT_ERR_OUT_OF_MEMORY;
  if (EVP_PKEY_keygen_init(key_context) <= 0 ||
      EVP_PKEY_CTX_set_ec_paramgen_curve_nid(key_context, NID_X9_62_prime256v1) <= 0 ||
      EVP_PKEY_keygen(key_context, &key) <= 0) {
    EVP_PKEY_CTX_free(key_context);
    return WT_ERR_UNSUPPORTED;
  }
  EVP_PKEY_CTX_free(key_context);

  certificate = X509_new();
  if (certificate == NULL) {
    EVP_PKEY_free(key);
    return WT_ERR_OUT_OF_MEMORY;
  }

  /* Version 3, because that is what carries the subject alternative names a client validates a name against,
   * and a serial number -- self-signed or not, a certificate without one is not a certificate. */
  if (X509_set_version(certificate, 2L) != 1) goto fail;
  if (ASN1_INTEGER_set(X509_get_serialNumber(certificate), 1L) != 1) goto fail;
  if (X509_gmtime_adj(X509_getm_notBefore(certificate), 0L) == NULL) goto fail;
  /* Seven days: long enough for a development session, short enough that a forgotten certificate expires. */
  if (X509_gmtime_adj(X509_getm_notAfter(certificate), 60L * 60L * 24L * 7L) == NULL) goto fail;
  if (X509_set_pubkey(certificate, key) != 1) goto fail;

  name = X509_get_subject_name(certificate);
  if (name == NULL) goto fail;
  if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                 (const unsigned char *)common_name, -1, -1, 0) != 1) {
    goto fail;
  }
  /* Self-signed: the issuer is the subject, which is what makes the pin the only thing to trust. */
  if (X509_set_issuer_name(certificate, name) != 1) goto fail;

  {
    X509V3_CTX context;
    X509_EXTENSION *extension;
    char alternative_names[256];

    X509V3_set_ctx_nodb(&context);
    X509V3_set_ctx(&context, certificate, certificate, NULL, NULL, 0);
    /* The loopback names always, and the caller's name when it is a different one -- a certificate is
     * validated against the name the client used, so the two must agree. */
    if (strcmp(common_name, "localhost") == 0) {
      (void)snprintf(alternative_names, sizeof(alternative_names),
                     "DNS:localhost,IP:127.0.0.1,IP:::1");
    } else {
      (void)snprintf(alternative_names, sizeof(alternative_names),
                     "DNS:localhost,DNS:%s,IP:127.0.0.1,IP:::1", common_name);
    }
    extension = X509V3_EXT_conf_nid(NULL, &context, NID_subject_alt_name, alternative_names);
    if (extension == NULL) goto fail;
    if (X509_add_ext(certificate, extension, -1) != 1) {
      X509_EXTENSION_free(extension);
      goto fail;
    }
    X509_EXTENSION_free(extension);
  }
  if (X509_sign(certificate, key, EVP_sha256()) == 0) goto fail;

  cursor = out->certificate;
  written = i2d_X509(certificate, &cursor);
  if (written <= 0 || (size_t)written > sizeof(out->certificate)) goto fail;
  out->certificate_len = (size_t)written;

  cursor = out->private_key;
  written = i2d_PrivateKey(key, &cursor);
  if (written <= 0 || (size_t)written > sizeof(out->private_key)) goto fail;
  out->private_key_len = (size_t)written;

  X509_free(certificate);
  EVP_PKEY_free(key);

  if (wt_sha256(out->certificate, out->certificate_len, out->fingerprint) != WT_OK) {
    memset(out, 0, sizeof(*out));
    return WT_ERR_PROTOCOL;
  }
  return WT_OK;

fail:
  X509_free(certificate);
  EVP_PKEY_free(key);
  memset(out, 0, sizeof(*out));
  return WT_ERR_PROTOCOL;
}

void wt_tls_self_signed_identity(const wt_tls_self_signed_t *self, wt_tls_server_identity_t *out) {
  if (self == NULL || out == NULL) return;
  memset(out, 0, sizeof(*out));
  out->certificate[0] = self->certificate;
  out->certificate_len[0] = self->certificate_len;
  out->certificate_count = 1U;
  out->private_key = self->private_key;
  out->private_key_len = self->private_key_len;
  /* The scheme an ECDSA P-256 key signs with, which is what the certificate's own signature uses too. */
  out->signature_scheme = WT_TLS_SIGNATURE_ECDSA_SECP256R1_SHA256;
}

void wt_tls_self_signed_certificate(const wt_tls_self_signed_t *self, wt_tls_certificate_t *out) {
  if (self == NULL || out == NULL) return;
  memset(out, 0, sizeof(*out));
  out->request_context = NULL;
  out->request_context_len = 0U;
  out->entries[0].der = self->certificate;
  out->entries[0].der_len = self->certificate_len;
  out->entries[0].extensions = NULL;
  out->entries[0].extensions_len = 0U;
  out->count = 1U;
}
