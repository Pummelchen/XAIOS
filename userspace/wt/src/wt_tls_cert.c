/* TLS 1.3 Certificate and CertificateVerify.
 *
 * RFC 8446 sections 4.4.2 and 4.4.3. BearSSL supplies the X.509 parser
 * (`br_x509_decoder`) and the signature checks (`br_rsa_i31_pss_vrfy`,
 * `br_ecdsa_i31_vrfy_asn1`); this file supplies the message framing, the
 * signed-content construction and the scheme dispatch that TLS 1.3 asks for.
 *
 * The X.509 parsing is deliberately minimal. A pinned-key trust model does not
 * need chain building, path validation or a store: it needs the public key out
 * of the leaf certificate, and the leaf's signature checked against it. The
 * decoder is run over the DER with a callback that captures the key and
 * nothing else, which is also the smallest amount of code that can be wrong.
 */

#include "wt_tls_cert.h"

#include "inner.h"

#include <string.h>

const char wt_tls_server_certificate_verify_context[] =
    "TLS 1.3, server CertificateVerify";

/* RFC 8446 section 4.4.3: the signed content begins with 64 space bytes.
 *
 * The spaces are not decoration. They exist so that the signed content cannot
 * be confused with a TLS 1.2 structure that a server might be talked into
 * signing -- a length-prefixed handshake message begins with a byte that is
 * never 0x20 -- and dropping or short-counting them produces a signature that
 * never verifies. */
#define WT_TLS_CV_SPACES 64U

int wt_tls_parse_certificate(const uint8_t *message, size_t message_len,
                             wt_tls_certificate_chain_t *out) {
  uint8_t type = 0U;
  size_t body_len = 0U;
  size_t offset = 4U;
  uint32_t list_len;
  size_t list_end;

  if (message == NULL || out == NULL) return -1;
  memset(out, 0, sizeof(*out));

  if (message_len < 4U) return -1;
  type = message[0];
  body_len = ((size_t)message[1] << 16) | ((size_t)message[2] << 8) |
             (size_t)message[3];
  if (type != WT_TLS_HS_CERTIFICATE) return -1;
  if (body_len > message_len - 4U) return -1;
  if (body_len < 4U) return -1;

  /* certificate_request_context: one byte of length, then that many bytes.
     For a server's Certificate it is always empty (RFC 8446 section 4.4.2);
     the same structure carries a non-empty one for a client's, so it is
     parsed rather than assumed. */
  {
    uint8_t context_len = message[offset];
    offset += 1U;
    if ((size_t)context_len > 4U + body_len - offset) return -1;
    offset += context_len;
  }

  /* certificate_list<0..2^24-1>: a three-byte length then the entries. */
  if (4U + body_len - offset < 3U) return -1;
  list_len = ((uint32_t)message[offset] << 16) |
             ((uint32_t)message[offset + 1U] << 8) |
             (uint32_t)message[offset + 2U];
  offset += 3U;
  if ((size_t)list_len > 4U + body_len - offset) return -1;
  list_end = offset + list_len;

  while (offset < list_end) {
    uint32_t cert_len;
    if (list_end - offset < 3U) return -1;
    cert_len = ((uint32_t)message[offset] << 16) |
               ((uint32_t)message[offset + 1U] << 8) |
               (uint32_t)message[offset + 2U];
    offset += 3U;
    if ((size_t)cert_len > list_end - offset) return -1;
    if (out->count >= WT_TLS_MAX_CERTIFICATES) {
      /* More entries than the structure holds is a refusal rather than a
         silent truncation: a chain a caller cannot see is a chain it cannot
         validate. */
      memset(out, 0, sizeof(*out));
      return -1;
    }
    out->entries[out->count] = message + offset;
    out->lengths[out->count] = cert_len;
    out->count++;
    offset += cert_len;

    /* certificate_entry extensions: a two-byte length then that many bytes.
       RFC 8446 requires these to be well formed even when empty. */
    if (list_end - offset < 2U) return -1;
    {
      uint16_t ext_len = (uint16_t)(((uint16_t)message[offset] << 8) |
                                    (uint16_t)message[offset + 1U]);
      offset += 2U;
      if ((size_t)ext_len > list_end - offset) return -1;
      if (out->count == 1U) {
        out->extensions = message + offset;
        out->extensions_len = ext_len;
      }
      offset += ext_len;
    }
  }
  if (offset != list_end) return -1;
  if (out->count == 0U) return -1;
  return 0;
}

int wt_tls_parse_certificate_verify(const uint8_t *message, size_t message_len,
                                    wt_tls_certificate_verify_t *out) {
  uint8_t type = 0U;
  size_t body_len = 0U;

  if (message == NULL || out == NULL) return -1;
  memset(out, 0, sizeof(*out));

  if (message_len < 4U) return -1;
  type = message[0];
  body_len = ((size_t)message[1] << 16) | ((size_t)message[2] << 8) |
             (size_t)message[3];
  if (type != WT_TLS_HS_CERTIFICATE_VERIFY) return -1;
  if (body_len > message_len - 4U) return -1;
  /* scheme (2) || signature length (2) || signature */
  if (body_len < 4U) return -1;

  out->scheme = (uint16_t)(((uint16_t)message[4] << 8) | message[5]);
  {
    uint16_t sig_len = (uint16_t)(((uint16_t)message[6] << 8) | message[7]);
    if (body_len != 4U + (size_t)sig_len) return -1;
    if (sig_len == 0U) return -1;
    out->signature = message + 8U;
    out->signature_len = sig_len;
  }
  return 0;
}

int wt_tls_certificate_verify_content(const char *context,
                                      const uint8_t transcript_hash[WT_TLS_HASH_LEN],
                                      uint8_t *out, size_t out_capacity,
                                      size_t *out_len) {
  size_t context_len;
  size_t total;
  size_t i;

  if (context == NULL || transcript_hash == NULL || out == NULL) return -1;
  context_len = strlen(context);
  /* 64 spaces || context || 0x00 || Hash */
  total = WT_TLS_CV_SPACES + context_len + 1U + WT_TLS_HASH_LEN;
  if (total > out_capacity) {
    if (out_len != NULL) *out_len = total;
    return -1;
  }
  for (i = 0U; i < WT_TLS_CV_SPACES; i++) out[i] = 0x20U;
  memcpy(out + WT_TLS_CV_SPACES, context, context_len);
  out[WT_TLS_CV_SPACES + context_len] = 0x00U;
  memcpy(out + WT_TLS_CV_SPACES + context_len + 1U, transcript_hash,
         WT_TLS_HASH_LEN);
  if (out_len != NULL) *out_len = total;
  return 0;
}

/* Read one DER certificate's public key.
 *
 * `br_x509_decoder` is a streaming parser that checks the certificate's own
 * internal structure -- the algorithm identifiers, the length encodings, the
 * validity fields -- and leaves the decoded public key in its context. It does
 * NOT check who issued the certificate, which is exactly what a pinned-key
 * model needs: the leaf's key, and nothing about a chain.
 *
 * The DN callback is required by the constructor and unused here: a pinned key
 * is a public key, not a name. */
static void ignore_dn(void *context, const void *buf, size_t len) {
  (void)context;
  (void)buf;
  (void)len;
}

int wt_tls_certificate_public_key(const uint8_t *certificate_der,
                                  size_t certificate_len, int *is_rsa,
                                  br_rsa_public_key *rsa, br_ec_public_key *ec) {
  br_x509_decoder_context decoder;
  br_x509_pkey *pk;

  if (certificate_der == NULL || is_rsa == NULL || rsa == NULL || ec == NULL) {
    return -1;
  }
  if (certificate_len == 0U) return -1;
  memset(rsa, 0, sizeof(*rsa));
  memset(ec, 0, sizeof(*ec));

  br_x509_decoder_init(&decoder, &ignore_dn, NULL);
  br_x509_decoder_push(&decoder, certificate_der, certificate_len);

  /* Non-zero when the certificate is malformed or truncated. */
  if (br_x509_decoder_last_error(&decoder) != 0) return -1;
  pk = br_x509_decoder_get_pkey(&decoder);
  if (pk == NULL) return -1;

  /* Only the two key types a TLS 1.3 server may present for the schemes this
     module checks. Anything else is a refusal, because a caller that got a key
     it cannot use should not be told the parse succeeded. */
  if (pk->key_type == BR_KEYTYPE_RSA) {
    *is_rsa = 1;
    *rsa = pk->key.rsa;
    return 0;
  }
  if (pk->key_type == BR_KEYTYPE_EC) {
    *is_rsa = 0;
    *ec = pk->key.ec;
    return 0;
  }
  return -1;
}

int wt_tls_rsa_public_key_equal(const br_rsa_public_key *a,
                                const br_rsa_public_key *b) {
  int equal;
  if (a == NULL || b == NULL) return 0;
  if (a->n == NULL || b->n == NULL || a->e == NULL || b->e == NULL) return 0;
  /* The modulus identifies the key and is compared in constant time. */
  if (a->nlen != b->nlen) return 0;
  equal = wt_ct_equal(a->n, b->n, a->nlen);
  /* The exponent is not secret but is part of the key, so it is compared too;
     a mismatched exponent with a matching modulus is a different key. */
  if (a->elen != b->elen) return 0;
  return equal && wt_ct_equal(a->e, b->e, a->elen);
}

/* Reduce a big-endian integer by stripping leading zeros, which is the form
 * BearSSL's verifiers expect for a signature and for a key component. */
static void strip_leading_zeros(const uint8_t **p, size_t *len) {
  while (*len > 0U && **p == 0U) {
    (*p)++;
    (*len)--;
  }
}

int wt_tls_certificate_verify_signature(
    const uint8_t *certificate_der, size_t certificate_len,
    const wt_tls_certificate_verify_t *verify, const uint8_t *content,
    size_t content_len) {
  br_x509_decoder_context decoder;
  br_x509_pkey *pk;
  uint8_t digest[WT_TLS_HASH_LEN];
  const uint8_t *sig;
  size_t sig_len;
  uint32_t ok = 0U;

  if (certificate_der == NULL || verify == NULL || content == NULL) return -1;
  if (verify->signature == NULL || verify->signature_len == 0U) return -1;
  if (verify->signature_len > 0xFFFFU) return -1;
  if (certificate_len == 0U) return -1;

  br_x509_decoder_init(&decoder, &ignore_dn, NULL);
  br_x509_decoder_push(&decoder, certificate_der, certificate_len);
  if (br_x509_decoder_last_error(&decoder) != 0) return -1;
  pk = br_x509_decoder_get_pkey(&decoder);
  if (pk == NULL) return -1;

  /* The signature and the key components are unsigned big-endian integers and
     may carry leading zero bytes; the verifiers expect them stripped. The
     signature is a view into the peer's message, so the stripped pointer is a
     local rather than a modification of that buffer. */
  sig = verify->signature;
  sig_len = verify->signature_len;
  strip_leading_zeros(&sig, &sig_len);
  if (sig_len == 0U) return -1;

  switch (verify->scheme) {
    case WT_TLS_SIG_RSA_PSS_RSAE_SHA256:
    case WT_TLS_SIG_RSA_PSS_RSAE_SHA384:
    case WT_TLS_SIG_RSA_PSS_RSAE_SHA512: {
      const br_hash_class *hf = (verify->scheme == WT_TLS_SIG_RSA_PSS_RSAE_SHA256)
                                    ? &br_sha256_vtable
                                : (verify->scheme == WT_TLS_SIG_RSA_PSS_RSAE_SHA384)
                                    ? &br_sha384_vtable
                                    : &br_sha512_vtable;
      size_t hash_len = (verify->scheme == WT_TLS_SIG_RSA_PSS_RSAE_SHA256) ? 32U
                       : (verify->scheme == WT_TLS_SIG_RSA_PSS_RSAE_SHA384) ? 48U
                                                                            : 64U;
      const uint8_t *n;
      size_t nlen;
      br_rsa_public_key rsa_key;

      if (pk->key_type != BR_KEYTYPE_RSA) return -1;
      if (content_len == 0U) return -1;
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
      n = pk->key.rsa.n;
      nlen = pk->key.rsa.nlen;
      strip_leading_zeros(&n, &nlen);
      if (nlen == 0U) return -1;
      /* BearSSL's `br_rsa_public_key` takes non-const pointers although the
         verifier only reads them. The key is a view into the peer's
         certificate, which this function does not modify; the cast is the
         interface's shape and not a permission to write. */
      rsa_key.n = (unsigned char *)(uintptr_t)n;
      rsa_key.nlen = nlen;
      rsa_key.e = pk->key.rsa.e;
      rsa_key.elen = pk->key.rsa.elen;
      ok = br_rsa_i31_pss_vrfy(sig, sig_len, hf, hf, digest, hash_len,
                               &rsa_key);
      break;
    }
    case WT_TLS_SIG_ECDSA_SECP256R1_SHA256:
    case WT_TLS_SIG_ECDSA_SECP384R1_SHA384:
    case WT_TLS_SIG_ECDSA_SECP521R1_SHA512: {
      const br_hash_class *hf = (verify->scheme == WT_TLS_SIG_ECDSA_SECP256R1_SHA256)
                                    ? &br_sha256_vtable
                                : (verify->scheme == WT_TLS_SIG_ECDSA_SECP384R1_SHA384)
                                    ? &br_sha384_vtable
                                    : &br_sha512_vtable;
      if (pk->key_type != BR_KEYTYPE_EC) return -1;
      if (content_len == 0U) return -1;
      {
        br_hash_compat_context hc;
        size_t hash_len = hf->desc >> BR_HASHDESC_OUT_OFF & BR_HASHDESC_OUT_MASK;
        hf->init(&hc.vtable);
        hf->update(&hc.vtable, content, content_len);
        hf->out(&hc.vtable, digest);
        /* The EC implementation must be the one the key's curve belongs to;
           the decoder records the curve in the public key. */
        ok = br_ecdsa_i31_vrfy_asn1(&br_ec_prime_i31, digest, hash_len,
                                    &pk->key.ec, sig, sig_len);
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
