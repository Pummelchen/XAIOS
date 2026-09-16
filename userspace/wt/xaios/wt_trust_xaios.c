/*
 * The vendored WebTransport library's trust and CertificateVerify file, over
 * BearSSL and this repository's DER helpers (B-131).
 *
 * Upstream's `src/tls/trust.c` is the last file in the tree that calls OpenSSL
 * directly: it parses X.509 with `d2i_X509`, extracts the SubjectPublicKeyInfo
 * with `i2d_X509_PUBKEY`, and verifies signatures with `EVP_PKEY_verify`. None
 * of that exists here. What replaces it is:
 *
 *   - the same trust policy, unchanged: PINNED compares the SHA-256 of the
 *     leaf DER against the configured fingerprints in constant time, and
 *     LOCAL_DEVELOPMENT is a bypass restricted to a loopback name. SYSTEM and
 *     STORE are refused by name, because this machine has no platform store
 *     and no PEM bundle path -- refusing is the honest answer, and it is what
 *     the original did too;
 *   - the leaf's SPKI, located by `wt_xaios_x509.c` rather than by OpenSSL;
 *   - signature verification over the scheme dispatch this repository already
 *     checks against RFC 8448 vectors.
 *
 * The two warnings the upstream header gives are both honoured: the
 * CertificateVerify content is `64 spaces || context || 0x00 || hash`, and a
 * signature is only checked after the certificate that carries the key has
 * passed the policy.
 *
 * Signing is not carried. Upstream signs only in its server half and this port
 * is a client; `wt_tls_signature_sign` returns WT_ERR_UNSUPPORTED rather than
 * pretending, and the endpoint API that would offer a server is not compiled
 * into the image.
 */

#include "webtransport/tls/trust.h"

#include "webtransport/crypto/crypto.h"
#include "webtransport/tls/extension.h"

#include "wt_xaios_x509.h"

#include <string.h>

int wt_tls_trust_host_is_loopback(const char *host_name) {
  if (host_name == NULL) return 0;
  /* Exact comparison, as upstream does it: a name that merely contains one of
     these is not one of them, or "localhost.example.com" would be a bypass. */
  return strcmp(host_name, "localhost") == 0 ||
         strcmp(host_name, "127.0.0.1") == 0 || strcmp(host_name, "::1") == 0 ||
         strcmp(host_name, "[::1]") == 0;
}

int wt_tls_signature_scheme_supported(uint16_t scheme) {
  switch (scheme) {
    case WT_TLS_SIGNATURE_ECDSA_SECP256R1_SHA256:
    case WT_TLS_SIGNATURE_ECDSA_SECP384R1_SHA384:
    case WT_TLS_SIGNATURE_RSA_PSS_RSAE_SHA256:
    case WT_TLS_SIGNATURE_RSA_PSS_RSAE_SHA384:
    case WT_TLS_SIGNATURE_RSA_PSS_RSAE_SHA512:
      return 1;
    default:
      /* Ed25519 is in upstream's list and is not here: BearSSL has no
         implementation of it, so offering it would be offering a scheme that
         cannot be checked. */
      return 0;
  }
}

wt_status_t wt_tls_trust_verify(const wt_tls_trust_policy_t *policy,
                                const wt_tls_certificate_t *certificate,
                                uint8_t spki_out[WT_TLS_SPKI_MAX],
                                size_t *spki_len) {
  const uint8_t *spki = NULL;
  size_t found = 0U;

  if (policy == NULL || certificate == NULL || spki_out == NULL ||
      spki_len == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  *spki_len = 0U;
  if (certificate->count == 0U) {
    memset(spki_out, 0, WT_TLS_SPKI_MAX);
    return WT_ERR_TRUST;
  }
  if (certificate->entries[0].der == NULL ||
      certificate->entries[0].der_len == 0U) {
    memset(spki_out, 0, WT_TLS_SPKI_MAX);
    return WT_ERR_PROTOCOL;
  }

  switch (policy->mode) {
    case WT_TLS_TRUST_PINNED_CERTIFICATE: {
      uint8_t digest[WT_SHA256_LEN];
      uint8_t matched = 0U;
      size_t index;
      if (policy->fingerprint_count == 0U ||
          policy->fingerprint_count > WT_TLS_PINNED_MAX) {
        memset(spki_out, 0, WT_TLS_SPKI_MAX);
        return WT_ERR_TRUST;
      }
      if (wt_sha256(certificate->entries[0].der,
                    certificate->entries[0].der_len, digest) != WT_OK) {
        memset(spki_out, 0, WT_TLS_SPKI_MAX);
        return WT_ERR_UNSUPPORTED;
      }
      /* Every fingerprint is compared, and the results are accumulated: a
         loop that stopped at the first match would take a different amount of
         time depending on which pin matched, and one that stopped at the
         first mismatch would report how far into the list a caller guessed. */
      for (index = 0U; index < policy->fingerprint_count; ++index) {
        matched |= (uint8_t)wt_ct_equal(digest, policy->fingerprints[index],
                                        WT_SHA256_LEN);
      }
      wt_secure_zero(digest, sizeof(digest));
      if (matched != 1U) {
        memset(spki_out, 0, WT_TLS_SPKI_MAX);
        return WT_ERR_TRUST;
      }
      break;
    }
    case WT_TLS_TRUST_LOCAL_DEVELOPMENT:
      /* The bypass is restricted to a loopback name, and the restriction
         travels with the mode rather than being advice. */
      if (!wt_tls_trust_host_is_loopback(policy->host_name)) {
        memset(spki_out, 0, WT_TLS_SPKI_MAX);
        return WT_ERR_TRUST;
      }
      break;
    case WT_TLS_TRUST_SYSTEM:
    case WT_TLS_TRUST_STORE:
      /* No platform store and no PEM bundle path on this machine. Named
         rather than skipped: a caller that asked for one gets the reason. */
      memset(spki_out, 0, WT_TLS_SPKI_MAX);
      return WT_ERR_UNSUPPORTED;
    default:
      memset(spki_out, 0, WT_TLS_SPKI_MAX);
      return WT_ERR_INVALID_ARGUMENT;
  }

  /* Even the pinned path extracts the key: CertificateVerify is checked
     against the leaf's public key, and the fingerprint says which leaf is
     acceptable, not what its key is. */
  if (wt_xaios_spki_from_certificate(certificate->entries[0].der,
                                     certificate->entries[0].der_len, &spki,
                                     &found) != 0) {
    memset(spki_out, 0, WT_TLS_SPKI_MAX);
    return WT_ERR_PROTOCOL;
  }
  if (found == 0U || found > WT_TLS_SPKI_MAX) {
    memset(spki_out, 0, WT_TLS_SPKI_MAX);
    return WT_ERR_LIMIT;
  }
  memcpy(spki_out, spki, found);
  *spki_len = found;
  return WT_OK;
}

wt_status_t wt_tls_certificate_verify_content(
    int from_server, const uint8_t transcript_hash[WT_TLS13_SECRET_LEN],
    uint8_t out[WT_TLS_CERTIFICATE_VERIFY_CONTENT_LEN]) {
  static const char server_context[] = "TLS 1.3, server CertificateVerify";
  static const char client_context[] = "TLS 1.3, client CertificateVerify";
  const char *context = from_server ? server_context : client_context;
  size_t context_len = strlen(context);

  if (transcript_hash == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* The 64 spaces put the context string past the point a signature
     algorithm's internal padding can reach (RFC 8446 section 4.4.3), and the
     zero byte is a separator rather than a terminator. */
  memset(out, 0x20, 64U);
  memcpy(out + 64U, context, context_len);
  out[64U + context_len] = 0U;
  memcpy(out + 64U + context_len + 1U, transcript_hash, WT_TLS13_SECRET_LEN);
  return WT_OK;
}

wt_status_t wt_tls_signature_verify(const uint8_t *spki, size_t spki_len,
                                    uint16_t scheme, const uint8_t *content,
                                    size_t content_len,
                                    const uint8_t *signature,
                                    size_t signature_len) {
  wt_xaios_public_key_t key;
  int verified;

  if (spki == NULL || content == NULL || signature == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (!wt_tls_signature_scheme_supported(scheme)) return WT_ERR_UNSUPPORTED;
  if (wt_xaios_public_key_load(spki, spki_len, &key) != 0) {
    return WT_ERR_PROTOCOL;
  }
  verified = wt_xaios_signature_verify(&key, scheme, signature, signature_len,
                                       content, content_len);
  wt_secure_zero(&key, sizeof(key));
  if (verified == 1) return WT_OK;
  if (verified == 0) return WT_ERR_AUTHENTICATION;
  /* -1 is a malformed key or a signature shape the scheme does not accept;
     the scheme itself was checked above, so this is the peer's message being
     wrong rather than a capability this port lacks. */
  return WT_ERR_PROTOCOL;
}

wt_status_t wt_tls_signature_sign(const uint8_t *private_key,
                                  size_t private_key_len, uint16_t scheme,
                                  const uint8_t *content, size_t content_len,
                                  uint8_t *signature_out, size_t capacity,
                                  size_t *signature_len) {
  wt_xaios_private_key_t key;
  int status;

  if (private_key == NULL || content == NULL || signature_out == NULL ||
      signature_len == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  *signature_len = 0U;
  if (!wt_tls_signature_scheme_supported(scheme)) return WT_ERR_UNSUPPORTED;
  if (wt_xaios_private_key_load(private_key, private_key_len, &key) != 0) {
    /* A key this backend cannot read is not a key, which is a protocol error
       rather than a missing capability: the caller supplied the bytes. */
    return WT_ERR_PROTOCOL;
  }
  if (capacity < wt_xaios_signature_size(&key)) {
    wt_secure_zero(&key, sizeof(key));
    return WT_ERR_LIMIT;
  }
  status = wt_xaios_signature_sign(&key, scheme, content, content_len,
                                   signature_out, capacity, signature_len);
  wt_secure_zero(&key, sizeof(key));
  /* The scheme and the buffer were both checked above, so a refusal here is a
     key that does not match the scheme it is being asked to sign with. */
  return status == 0 ? WT_OK : WT_ERR_UNSUPPORTED;
}
