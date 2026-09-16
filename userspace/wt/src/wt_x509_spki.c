/* SubjectPublicKeyInfo, out of a certificate and into a public key.
 *
 * The in-tree certificate module reads the key with BearSSL's X.509 decoder
 * over a whole certificate. The vendored WebTransport port's trust backend
 * cannot: the interface it implements hands the peer's SubjectPublicKeyInfo
 * forward as DER -- RFC 8446's CertificateVerify is checked against exactly
 * those bytes -- and by the time the signature is verified the certificate
 * itself is gone. So this file does the two things that need:
 *
 *   `wt_tls_certificate_spki`  locates the SPKI inside a certificate, as a
 *                              view, without decoding anything else.
 *   `wt_tls_public_key_from_spki` parses that DER into the key structure the
 *                              shared scheme dispatch takes.
 *
 * It is a definite-length DER reader and nothing more: X.509 uses DER, so an
 * indefinite length is refused rather than guessed at, and every length is
 * checked against the bytes that remain before a pointer moves. Only the two
 * key algorithms this port can verify are carried -- RSA and the three NIST
 * curves -- and anything else is a refusal, because a caller told "success"
 * would have no key to check a signature with.
 *
 * The tests compare this parser's output with BearSSL's decoder on the same
 * certificates, which is what makes a second implementation of a delicate
 * encoding defensible rather than a second place to be wrong.
 */

#include "wt_tls_cert.h"

#include <string.h>

/* DER tags named once. */
#define WT_DER_SEQUENCE 0x30U
#define WT_DER_INTEGER 0x02U
#define WT_DER_BIT_STRING 0x03U
#define WT_DER_OID 0x06U
#define WT_DER_CONTEXT_0 0xA0U

/* The algorithms, by the DER contents of their OIDs. */
static const uint8_t wt_oid_rsa[] = {0x2aU, 0x86U, 0x48U, 0x86U, 0xf7U,
                                     0x0dU, 0x01U, 0x01U, 0x01U};
static const uint8_t wt_oid_ec_public_key[] = {0x2aU, 0x86U, 0x48U, 0xceU,
                                               0x3dU, 0x02U, 0x01U};
static const uint8_t wt_oid_prime256v1[] = {0x2aU, 0x86U, 0x48U, 0xceU,
                                            0x3dU, 0x03U, 0x01U, 0x07U};
static const uint8_t wt_oid_secp384r1[] = {0x2bU, 0x81U, 0x04U, 0x00U, 0x22U};
static const uint8_t wt_oid_secp521r1[] = {0x2bU, 0x81U, 0x04U, 0x00U, 0x23U};

/* A bounded view of the bytes a DER reader is walking. */
typedef struct wt_der {
  const uint8_t *bytes;
  size_t length;
} wt_der_t;

/* Read one tag-length-value. The length is definite DER only, and it is
   checked against what remains before the view moves, so a length that
   overruns its parent is a refusal rather than a read past the end. */
static int wt_der_read(wt_der_t *in, uint8_t *out_tag, wt_der_t *out_value) {
  /* Tag plus the first length octet: two bytes in the short form, and the
     long form adds the octets that first one announces. Counting the length
     octet itself is what the first version of this got wrong -- it advanced
     three bytes past a four-byte header, so every certificate walked two
     bytes short and no SPKI was ever found. */
  size_t header = 2U;
  size_t length;
  if (in == NULL || in->bytes == 0 || in->length < 2U) return -1;
  *out_tag = in->bytes[0];
  if ((in->bytes[1] & 0x80U) == 0U) {
    length = (size_t)in->bytes[1];
  } else {
    size_t count = (size_t)(in->bytes[1] & 0x7fU);
    size_t index;
    /* 0x80 is the indefinite form, which DER forbids; more than four length
       bytes describes more than any buffer here could hold. */
    if (count == 0U || count > 4U || in->length < 2U + count) return -1;
    length = 0U;
    for (index = 0U; index < count; ++index) {
      length = (length << 8U) | (size_t)in->bytes[2U + index];
    }
    header = 2U + count;
  }
  if (length > in->length - header) return -1;
  out_value->bytes = in->bytes + header;
  out_value->length = length;
  in->bytes += header + length;
  in->length -= header + length;
  return 0;
}

static int wt_der_expect(wt_der_t *in, uint8_t tag, wt_der_t *out_value) {
  uint8_t seen = 0U;
  if (wt_der_read(in, &seen, out_value) != 0) return -1;
  return seen == tag ? 0 : -1;
}

static int wt_der_is(const wt_der_t *value, const uint8_t *contents,
                     size_t length) {
  return value->length == length &&
         memcmp(value->bytes, contents, length) == 0;
}

/* Copy an INTEGER's contents, minus DER's leading zero byte, which exists only
   to keep a positive number from being read as negative. A component that is
   all zero after stripping is not a key. */
static int wt_der_integer(const wt_der_t *value, uint8_t *out, size_t capacity,
                          size_t *out_length) {
  const uint8_t *bytes = value->bytes;
  size_t length = value->length;
  while (length > 1U && *bytes == 0U) {
    ++bytes;
    --length;
  }
  if (length == 0U || length > capacity) return -1;
  memcpy(out, bytes, length);
  *out_length = length;
  return 0;
}

int wt_tls_certificate_spki(const uint8_t *certificate_der,
                            size_t certificate_len, const uint8_t **spki,
                            size_t *spki_len) {
  wt_der_t certificate;
  wt_der_t tbs;
  wt_der_t field;
  size_t index;

  if (certificate_der == NULL || spki == NULL || spki_len == NULL) return -1;
  if (certificate_len == 0U) return -1;
  certificate.bytes = certificate_der;
  certificate.length = certificate_len;

  /* Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
     signatureValue }. Only the first is walked. */
  if (wt_der_expect(&certificate, WT_DER_SEQUENCE, &tbs) != 0) return -1;
  if (wt_der_expect(&tbs, WT_DER_SEQUENCE, &field) != 0) return -1;

  /* TBSCertificate ::= SEQUENCE { [0] version OPTIONAL, serialNumber,
     signature, issuer, validity, subject, subjectPublicKeyInfo, ... }. The
     version is the only optional leading element, and it is the only one with
     a context tag. */
  {
    wt_der_t probe = field;
    uint8_t tag = 0U;
    wt_der_t value;
    if (wt_der_read(&probe, &tag, &value) == 0 && tag == WT_DER_CONTEXT_0) {
      field = probe;
    }
  }
  for (index = 0U; index < 5U; ++index) {
    uint8_t tag = 0U;
    wt_der_t value;
    if (wt_der_read(&field, &tag, &value) != 0) return -1;
  }

  /* What is left begins with the SPKI, and it is handed back as the bytes it
     occupies -- header included, because that is what a CertificateVerify
     check is given and what a caller compares. */
  {
    const uint8_t *start = field.bytes;
    wt_der_t value;
    if (wt_der_expect(&field, WT_DER_SEQUENCE, &value) != 0) return -1;
    *spki = start;
    *spki_len = (size_t)(field.bytes - start);
  }
  return 0;
}

int wt_tls_public_key_from_spki(const uint8_t *spki, size_t spki_len,
                                wt_tls_public_key_t *out) {
  wt_der_t input;
  wt_der_t sequence;
  wt_der_t algorithm;
  wt_der_t identifier;
  wt_der_t parameters;
  wt_der_t bit_string;
  const uint8_t *point;
  size_t point_length;
  int curve = -1;

  if (out == NULL) return -1;
  memset(out, 0, sizeof(*out));
  if (spki == NULL || spki_len == 0U) return -1;
  input.bytes = spki;
  input.length = spki_len;

  /* SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey }. */
  if (wt_der_expect(&input, WT_DER_SEQUENCE, &sequence) != 0) return -1;
  if (wt_der_expect(&sequence, WT_DER_SEQUENCE, &algorithm) != 0) return -1;
  if (wt_der_expect(&algorithm, WT_DER_OID, &identifier) != 0) return -1;
  if (wt_der_expect(&sequence, WT_DER_BIT_STRING, &bit_string) != 0) return -1;
  /* A BIT STRING with unused bits is not a key encoding; DER requires zero
     here, and accepting a partial byte would shift everything after it. */
  if (bit_string.length == 0U || bit_string.bytes[0] != 0U) return -1;
  point = bit_string.bytes + 1U;
  point_length = bit_string.length - 1U;

  if (wt_der_is(&identifier, wt_oid_rsa, sizeof(wt_oid_rsa))) {
    /* RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER },
       and the exponent is small enough to live beside the modulus in the
       key's own storage. */
    wt_der_t rsa;
    wt_der_t modulus;
    wt_der_t exponent;
    wt_der_t rest = {point, point_length};
    size_t modulus_len = 0U;
    size_t exponent_len = 0U;
    if (wt_der_expect(&rest, WT_DER_SEQUENCE, &rsa) != 0) return -1;
    if (wt_der_expect(&rsa, WT_DER_INTEGER, &modulus) != 0) return -1;
    if (wt_der_expect(&rsa, WT_DER_INTEGER, &exponent) != 0) return -1;
    if (modulus.length > sizeof(out->storage)) return -1;
    if (wt_der_integer(&modulus, out->storage, sizeof(out->storage),
                       &modulus_len) != 0) {
      return -1;
    }
    if (wt_der_integer(&exponent, out->storage + modulus_len,
                       sizeof(out->storage) - modulus_len,
                       &exponent_len) != 0) {
      return -1;
    }
    out->is_rsa = 1;
    out->storage_len = modulus_len + exponent_len;
    out->rsa.n = out->storage;
    out->rsa.nlen = modulus_len;
    out->rsa.e = out->storage + modulus_len;
    out->rsa.elen = exponent_len;
    return 0;
  }

  if (wt_der_is(&identifier, wt_oid_ec_public_key, sizeof(wt_oid_ec_public_key))) {
    /* The curve is the algorithm's parameter, and it is not optional for the
       only key type this branch accepts. */
    if (wt_der_expect(&algorithm, WT_DER_OID, &parameters) != 0) return -1;
    if (wt_der_is(&parameters, wt_oid_prime256v1, sizeof(wt_oid_prime256v1))) {
      curve = BR_EC_secp256r1;
    } else if (wt_der_is(&parameters, wt_oid_secp384r1,
                         sizeof(wt_oid_secp384r1))) {
      curve = BR_EC_secp384r1;
    } else if (wt_der_is(&parameters, wt_oid_secp521r1,
                         sizeof(wt_oid_secp521r1))) {
      curve = BR_EC_secp521r1;
    } else {
      return -1;
    }
    /* The uncompressed point: one 0x04 byte and two field elements. A
       compressed point is a shape this verifier does not carry, and it has to
       be refused here rather than by the multiplication. */
    if (point_length == 0U || point[0] != 0x04U) return -1;
    if (curve == BR_EC_secp256r1 && point_length != 65U) return -1;
    if (curve == BR_EC_secp384r1 && point_length != 97U) return -1;
    if (curve == BR_EC_secp521r1 && point_length != 133U) return -1;
    if (point_length > sizeof(out->storage)) return -1;
    memcpy(out->storage, point, point_length);
    out->is_rsa = 0;
    out->storage_len = point_length;
    out->ec.curve = curve;
    out->ec.q = out->storage;
    out->ec.qlen = point_length;
    return 0;
  }

  /* A key algorithm this port cannot verify. A refusal, because a caller told
     "success" would have nothing to check a signature with. */
  return -1;
}
