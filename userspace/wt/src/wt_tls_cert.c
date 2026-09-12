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

/* The CertificateVerify dispatcher hashes the signed content with a hash that
 * depends on the SCHEME, and the schemes this module checks use SHA-256,
 * SHA-384 and SHA-512. The digest buffer is therefore sized for the largest of
 * them and not for WT_TLS_HASH_LEN, which is the SHA-256 length and the length
 * of everything in the key schedule.
 *
 * This was a stack buffer overflow, reachable from the wire: a server that
 * answered a CertificateVerify with scheme 0x0805 or 0x0806 made
 * sha384/sha512 write 48 or 64 bytes into a 32-byte local. It is the same class
 * of defect as the Retry integrity tag's unbounded copy earlier in this port,
 * and it was found the same way -- by asking what the length actually is rather
 * than what it is called. The tests now drive both longer schemes under
 * AddressSanitizer, which is what would have caught it. */
#define WT_TLS_MAX_HASH_LEN 64U

/* A build-time bound, so a future scheme whose hash does not fit fails to
 * compile rather than at the first packet from a hostile peer. */
typedef char wt_tls_max_hash_fits[WT_TLS_MAX_HASH_LEN >= 64U ? 1 : -1];

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
                                  size_t certificate_len,
                                  wt_tls_public_key_t *out) {
  br_x509_decoder_context decoder;
  br_x509_pkey *pk;
  size_t need;

  if (out == NULL) return -1;
  memset(out, 0, sizeof(*out));
  if (certificate_der == NULL || certificate_len == 0U) return -1;

  br_x509_decoder_init(&decoder, &ignore_dn, NULL);
  br_x509_decoder_push(&decoder, certificate_der, certificate_len);

  /* Non-zero when the certificate is malformed or truncated. */
  if (br_x509_decoder_last_error(&decoder) != 0) return -1;
  pk = br_x509_decoder_get_pkey(&decoder);
  if (pk == NULL) return -1;

  /* Everything the decoder produced lives in `decoder`, which is about to go
     out of scope. Copying is the whole point of this function: see
     WT_TLS_PUBLIC_KEY_MAX in the header for what happened when it did not. */
  if (pk->key_type == BR_KEYTYPE_RSA) {
    const br_rsa_public_key *src = &pk->key.rsa;
    if (src->n == NULL || src->e == NULL) return -1;
    if (src->nlen == 0U || src->elen == 0U) return -1;
    need = src->nlen + src->elen;
    if (need > sizeof(out->storage)) return -1;
    memcpy(out->storage, src->n, src->nlen);
    memcpy(out->storage + src->nlen, src->e, src->elen);
    out->is_rsa = 1;
    out->storage_len = need;
    out->rsa.n = out->storage;
    out->rsa.nlen = src->nlen;
    out->rsa.e = out->storage + src->nlen;
    out->rsa.elen = src->elen;
    return 0;
  }
  if (pk->key_type == BR_KEYTYPE_EC) {
    const br_ec_public_key *src = &pk->key.ec;
    if (src->q == NULL || src->qlen == 0U) return -1;
    if (src->qlen > sizeof(out->storage)) return -1;
    if (src->curve < 0) return -1;
    memcpy(out->storage, src->q, src->qlen);
    out->is_rsa = 0;
    out->storage_len = src->qlen;
    out->ec.curve = src->curve;
    out->ec.q = out->storage;
    out->ec.qlen = src->qlen;
    return 0;
  }
  /* A key type a TLS 1.3 server may present that this module cannot check.
     A refusal, because a caller told "success" would have nothing to compare. */
  return -1;
}

/* A big-endian integer that begins with a zero byte is the same number as the
 * string without it, and DER never emits the padded form. Refusing the padded
 * form is what makes "the operator's key and the certificate's key are the same
 * bytes" checkable. */
static int public_key_leading_zero(const uint8_t *bytes, size_t len) {
  return len > 1U && bytes[0] == 0x00U;
}

int wt_tls_public_key_set_rsa(wt_tls_public_key_t *out, const uint8_t *modulus,
                              size_t modulus_len, const uint8_t *exponent,
                              size_t exponent_len) {
  size_t need;

  if (out == NULL) return -1;
  memset(out, 0, sizeof(*out));
  if (modulus == NULL || exponent == NULL) return -1;
  if (modulus_len == 0U || exponent_len == 0U) return -1;
  if (public_key_leading_zero(modulus, modulus_len)) return -1;
  if (public_key_leading_zero(exponent, exponent_len)) return -1;
  need = modulus_len + exponent_len;
  if (need > sizeof(out->storage)) return -1;

  memcpy(out->storage, modulus, modulus_len);
  memcpy(out->storage + modulus_len, exponent, exponent_len);
  out->is_rsa = 1;
  out->storage_len = need;
  out->rsa.n = out->storage;
  out->rsa.nlen = modulus_len;
  out->rsa.e = out->storage + modulus_len;
  out->rsa.elen = exponent_len;
  return 0;
}

static int public_key_hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

int wt_tls_public_key_set_rsa_hex(wt_tls_public_key_t *out, const char *modulus,
                                  uint32_t exponent) {
  size_t hex_len;
  size_t modulus_len;
  uint8_t exponent_bytes[4];
  size_t exponent_len = 0U;
  size_t i;

  if (out == NULL) return -1;
  memset(out, 0, sizeof(*out));
  if (modulus == NULL) return -1;
  if (exponent == 0U) return -1;
  hex_len = strlen(modulus);
  if (hex_len == 0U) return -1;
  /* An odd number of digits is not a byte string, and choosing where to pad
     would be guessing which end the operator meant. */
  if ((hex_len % 2U) != 0U) return -1;
  modulus_len = hex_len / 2U;
  if (modulus_len == 0U) return -1;
  if (modulus_len + 1U > sizeof(out->storage)) return -1;

  /* Every digit is checked before any is written, so one bad character cannot
     leave half a modulus behind for a later comparison. */
  for (i = 0U; i < hex_len; i++) {
    if (public_key_hex_nibble(modulus[i]) < 0) return -1;
  }
  {
    uint32_t value = exponent;
    while (value != 0U) {
      exponent_bytes[exponent_len++] = (uint8_t)(value & 0xFFU);
      value >>= 8;
    }
    for (i = 0U; i < exponent_len / 2U; i++) {
      uint8_t swap = exponent_bytes[i];
      exponent_bytes[i] = exponent_bytes[exponent_len - 1U - i];
      exponent_bytes[exponent_len - 1U - i] = swap;
    }
  }
  {
    uint8_t decoded[WT_TLS_PUBLIC_KEY_MAX];
    if (modulus_len > sizeof(decoded)) return -1;
    for (i = 0U; i < modulus_len; i++) {
      int hi = public_key_hex_nibble(modulus[2U * i]);
      int lo = public_key_hex_nibble(modulus[2U * i + 1U]);
      decoded[i] = (uint8_t)((hi << 4) | lo);
    }
    if (wt_tls_public_key_set_rsa(out, decoded, modulus_len, exponent_bytes,
                                  exponent_len) != 0) {
      memset(out, 0, sizeof(*out));
      return -1;
    }
  }
  return 0;
}

int wt_tls_public_key_set_ec(wt_tls_public_key_t *out, int curve,
                             const uint8_t *point, size_t point_len) {
  if (out == NULL) return -1;
  memset(out, 0, sizeof(*out));
  if (point == NULL || point_len == 0U) return -1;
  if (curve < 0) return -1;
  if (point_len > sizeof(out->storage)) return -1;
  memcpy(out->storage, point, point_len);
  out->is_rsa = 0;
  out->storage_len = point_len;
  out->ec.curve = curve;
  out->ec.q = out->storage;
  out->ec.qlen = point_len;
  return 0;
}

void wt_tls_public_key_clear(wt_tls_public_key_t *key) {
  if (key == NULL) return;
  memset(key, 0, sizeof(*key));
}

int wt_tls_public_key_equal(const wt_tls_public_key_t *a,
                            const wt_tls_public_key_t *b) {
  if (a == NULL || b == NULL) return 0;
  if (a->storage_len == 0U || b->storage_len == 0U) return 0;
  if (a->is_rsa != b->is_rsa) return 0;
  if (a->is_rsa) {
    return wt_tls_rsa_public_key_equal(&a->rsa, &b->rsa);
  }
  return wt_tls_ec_public_key_equal(&a->ec, &b->ec);
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

int wt_tls_ec_public_key_equal(const br_ec_public_key *a,
                               const br_ec_public_key *b) {
  if (a == NULL || b == NULL) return 0;
  if (a->q == NULL || b->q == NULL) return 0;
  if (a->qlen == 0U || b->qlen == 0U) return 0;
  /* The same point on a different curve is a different key: the curve is an
     input to every operation on it, so the bytes alone do not name a key. */
  if (a->curve != b->curve) return 0;
  if (a->qlen != b->qlen) return 0;
  return wt_ct_equal(a->q, b->q, a->qlen);
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
  uint8_t digest[WT_TLS_MAX_HASH_LEN];
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
      int expected_curve =
          (verify->scheme == WT_TLS_SIG_ECDSA_SECP256R1_SHA256) ? BR_EC_secp256r1
          : (verify->scheme == WT_TLS_SIG_ECDSA_SECP384R1_SHA384)
              ? BR_EC_secp384r1
              : BR_EC_secp521r1;
      if (pk->key_type != BR_KEYTYPE_EC) return -1;
      if (content_len == 0U) return -1;
      /* RFC 8446 section 4.4.3: the scheme must be consistent with the key in
         the certificate. A P-384 scheme answered by a P-256 key is not a
         signature that failed to verify; it is a message that does not make
         sense, and saying so is the difference between "the peer made a
         mistake" and "the peer forged something". Without this check the
         verifier runs a P-256 multiplication with a 48-byte digest and returns
         0 -- the right answer by accident, and a -1 that an audit can point at
         is better than an accident. */
      if (pk->key.ec.curve != expected_curve) return -1;
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
