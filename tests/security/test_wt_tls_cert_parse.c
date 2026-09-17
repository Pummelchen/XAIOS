/* The Certificate and CertificateVerify parsers, the check helpers the whole
 * suite asserts with, and the ECDSA curves the verifier advertises.
 *
 * This was the top and the middle of `test_wt_tls_cert.c`. The opening comment,
 * `main`, the signed-content and structural tests stayed in the driver; the
 * RSA-PSS signature, the long-hash schemes and the SubjectPublicKeyInfo
 * comparison moved to `test_wt_tls_cert_signature.c`. The two check helpers and
 * the transcript helper are defined here because they were defined in the
 * one-file suite where they were first used, and every translation unit
 * includes `test_wt_tls_cert_support.h` for their declarations.
 */
#include "test_wt_tls_cert_support.h"

#include "wt_ecdsa_vectors.h"
#include "wt_rfc8448_vectors.h"
#include "wt_tls_pin.h"

#include <stdio.h>
#include <string.h>

/* The two counters the whole suite asserts through. Defined here and declared
 * `extern` in `test_wt_tls_cert_support.h`, because `main` reads them. */
int wtcert_failures;
int wtcert_checks;

/* The transcript hash through Certificate, which is what the CertificateVerify
 * signs. Rebuilt here from the RFC's messages rather than taken from a vector:
 * the RFC prints the signature and not this hash, and deriving it from the
 * messages is the check that the messages were framed right. */
int wtcert_transcript_through_certificate(uint8_t out[WT_TLS_HASH_LEN]) {
  wt_tls_transcript_t transcript;
  if (wt_tls_transcript_init(&transcript) != 0) return -1;
  if (wt_tls_transcript_absorb(&transcript, WT_RFC8448_CLIENT_HELLO,
                               sizeof(WT_RFC8448_CLIENT_HELLO)) != 0) return -1;
  if (wt_tls_transcript_absorb(&transcript, WT_RFC8448_SERVER_HELLO,
                               sizeof(WT_RFC8448_SERVER_HELLO)) != 0) return -1;
  if (wt_tls_transcript_absorb(&transcript, WT_RFC8448_ENCRYPTED_EXTENSIONS,
                               sizeof(WT_RFC8448_ENCRYPTED_EXTENSIONS)) != 0) {
    return -1;
  }
  if (wt_tls_transcript_absorb(&transcript, WT_RFC8448_CERTIFICATE,
                               sizeof(WT_RFC8448_CERTIFICATE)) != 0) return -1;
  return wt_tls_transcript_hash(&transcript, out);
}

/* ------------------------------------------------------------ parsing */

void wtcert_test_parse_certificate(void) {
  wt_tls_certificate_chain_t chain;

  wtcert_expect_int("parse the RFC's Certificate", 0,
             wt_tls_parse_certificate(WT_RFC8448_CERTIFICATE,
                                      sizeof(WT_RFC8448_CERTIFICATE), &chain));
  wtcert_expect_int("one entry", 1, (long)chain.count);
  /* RFC 8448's certificate is 432 bytes of DER; the message body's own length
     fields say so and the parse must agree. */
  wtcert_expect_int("the entry is 432 bytes", 432, (long)chain.lengths[0]);
  wtcert_expect_int("the entry starts where the message says", 1,
             (long)(chain.entries[0] > WT_RFC8448_CERTIFICATE));
  wtcert_expect_int("no certificate extensions", 0, (long)chain.extensions_len);

  /* The DER must start with a SEQUENCE, which is the only thing a caller can
     check cheaply before handing it to a parser. */
  wtcert_expect_int("the entry is a DER SEQUENCE", 0x30, chain.entries[0][0]);

  /* Refusals. Each of these is reachable from the wire. */
  wtcert_expect_int("a ClientHello is not a Certificate", -1,
             wt_tls_parse_certificate(WT_RFC8448_CLIENT_HELLO,
                                      sizeof(WT_RFC8448_CLIENT_HELLO), &chain));
  wtcert_expect_int("a NULL message is refused", -1,
             wt_tls_parse_certificate(NULL, 100U, &chain));
  wtcert_expect_int("a NULL output is refused", -1,
             wt_tls_parse_certificate(WT_RFC8448_CERTIFICATE,
                                      sizeof(WT_RFC8448_CERTIFICATE), NULL));
  wtcert_expect_int("a truncated header is refused", -1,
             wt_tls_parse_certificate(WT_RFC8448_CERTIFICATE, 3U, &chain));

  /* Every truncation of the message must be refused rather than reading past
     the end. This is the loop that catches an off-by-one in the length
     arithmetic. */
  {
    int accepted = 0;
    for (size_t cut = 0U; cut < sizeof(WT_RFC8448_CERTIFICATE); cut++) {
      wt_tls_certificate_chain_t partial;
      if (wt_tls_parse_certificate(WT_RFC8448_CERTIFICATE, cut, &partial) == 0) {
        accepted++;
      }
    }
    wtcert_expect_int("no truncated Certificate is accepted", 0, accepted);
  }

  /* A declared body length that overruns the buffer is a refusal. */
  {
    uint8_t forged[64];
    memcpy(forged, WT_RFC8448_CERTIFICATE, sizeof(forged));
    forged[1] = 0xffU;
    forged[2] = 0xffU;
    forged[3] = 0xffU;
    wtcert_expect_int("a body length past the buffer is refused", -1,
               wt_tls_parse_certificate(forged, sizeof(forged), &chain));
  }
}
void wtcert_test_parse_certificate_verify(void) {
  wt_tls_certificate_verify_t verify;

  wtcert_expect_int("parse the RFC's CertificateVerify", 0,
             wt_tls_parse_certificate_verify(WT_RFC8448_CERTIFICATE_VERIFY,
                                             sizeof(WT_RFC8448_CERTIFICATE_VERIFY),
                                             &verify));
  wtcert_expect_int("the scheme is rsa_pss_rsae_sha256", 0x0804,
             (long)verify.scheme);
  wtcert_expect_int("the signature is 128 bytes", 128, (long)verify.signature_len);

  {
    int accepted = 0;
    for (size_t cut = 0U; cut < sizeof(WT_RFC8448_CERTIFICATE_VERIFY); cut++) {
      wt_tls_certificate_verify_t partial;
      if (wt_tls_parse_certificate_verify(WT_RFC8448_CERTIFICATE_VERIFY, cut,
                                          &partial) == 0) {
        accepted++;
      }
    }
    wtcert_expect_int("no truncated CertificateVerify is accepted", 0, accepted);
  }

  wtcert_expect_int("a Certificate is not a CertificateVerify", -1,
             wt_tls_parse_certificate_verify(WT_RFC8448_CERTIFICATE,
                                             sizeof(WT_RFC8448_CERTIFICATE),
                                             &verify));
  /* A signature length that does not match the body is a refusal, not a
     shorter signature silently compared. */
  {
    uint8_t forged[sizeof(WT_RFC8448_CERTIFICATE_VERIFY)];
    memcpy(forged, WT_RFC8448_CERTIFICATE_VERIFY, sizeof(forged));
    forged[7] = 0x40U; /* claim 64 bytes instead of 128 */
    wtcert_expect_int("a signature length that disagrees with the body is refused", -1,
               wt_tls_parse_certificate_verify(forged, sizeof(forged), &verify));
  }
}
/* The client's Certificate handler relies on the parser refusing an empty
 * certificate_list, so it does not repeat the check. That makes the refusal a
 * documented guarantee rather than an incidental one, and this is where it is
 * asserted: a Certificate with no entries is a malformed message (RFC 8446
 * section 4.4.2 -- a server authenticates with a certificate), and a change
 * that let one through would leave the handler reading a leaf that does not
 * exist. */
void wtcert_test_empty_certificate_list(void) {
  static const uint8_t empty[10] = {0x0bU, 0x00U, 0x00U, 0x07U, 0x00U,
                                    0x00U, 0x00U, 0x00U, 0x00U, 0x00U};
  wt_tls_certificate_chain_t chain;

  wtcert_expect_int("an empty certificate_list is refused", -1,
             wt_tls_parse_certificate(empty, sizeof(empty), &chain));
  wtcert_expect_int("  and the chain is cleared", 0, (long)chain.count);

  /* One entry: framed the way the parser expects, so the structure is
     accepted and the count is one. Built here byte by byte rather than
     transcribed, because the three lengths have to agree with each other and a
     hand-written array gets that wrong -- which is how the first version of
     this test failed. */
  {
    uint8_t message[64];
    size_t offset = 0U;
    size_t i;
    const size_t der_len = 18U;
    const size_t list_len = 3U + der_len + 2U;
    const size_t body_len = 1U + 3U + list_len;

    message[offset++] = 0x0bU;
    message[offset++] = (uint8_t)((body_len >> 16) & 0xFFU);
    message[offset++] = (uint8_t)((body_len >> 8) & 0xFFU);
    message[offset++] = (uint8_t)(body_len & 0xFFU);
    message[offset++] = 0x00U; /* empty certificate_request_context */
    message[offset++] = (uint8_t)((list_len >> 16) & 0xFFU);
    message[offset++] = (uint8_t)((list_len >> 8) & 0xFFU);
    message[offset++] = (uint8_t)(list_len & 0xFFU);
    message[offset++] = (uint8_t)((der_len >> 16) & 0xFFU);
    message[offset++] = (uint8_t)((der_len >> 8) & 0xFFU);
    message[offset++] = (uint8_t)(der_len & 0xFFU);
    message[offset++] = 0x30U; /* something that begins like DER */
    for (i = 1U; i < der_len; i++) message[offset++] = 0x00U;
    message[offset++] = 0x00U; /* the entry's empty extension block */
    message[offset++] = 0x00U;

    wtcert_expect_int("a one-entry list is accepted", 0,
               wt_tls_parse_certificate(message, offset, &chain));
    wtcert_expect_int("  with one entry", 1, (long)chain.count);
    wtcert_expect_int("  of eighteen bytes", (long)der_len, (long)chain.lengths[0]);
    wtcert_expect_int("  pointing at the DER", 0x30, (long)chain.entries[0][0]);
  }
}
/* --------------------------------------------------------- the ECDSA path
 *
 * RFC 8448's traces carry RSA certificates, so the ECDSA scheme this module
 * advertises -- `WT_TLS_SIG_ECDSA_SECP256R1_SHA256`, the second-most likely
 * scheme a QUIC server will pick -- would otherwise be code that has never run.
 * The fixture is generated by `tests/security/generate_wt_ecdsa_vectors.py`
 * with the Python `cryptography` package and re-verified by it, so the
 * signature the test checks is a real ECDSA signature over real content,
 * produced by an implementation independent of BearSSL.
 *
 * What this catches that the RSA path cannot: the ASN.1 DER decoding of an
 * ECDSA-Sig-Value, the curve lookup, the point length, and the dispatch on the
 * scheme value rather than on the key type.
 */
void wtcert_test_ecdsa(void) {
  wt_tls_certificate_verify_t verify;
  wt_tls_public_key_t key;

  wtcert_expect_int("the fixture's certificate has a readable key", 0,
             wt_tls_certificate_public_key(WT_ECDSA_CERT, WT_ECDSA_CERT_LEN,
                                           &key));
  wtcert_expect_int("it is not RSA", 0, key.is_rsa);
  wtcert_expect_int("it is on secp256r1", BR_EC_secp256r1, key.ec.curve);
  wtcert_expect_int("with a 65-byte uncompressed point", 65, (long)key.ec.qlen);
  wtcert_expect_bytes("and the point is the one the generator computed",
               WT_ECDSA_POINT, key.ec.q, WT_ECDSA_POINT_LEN);
  wtcert_expect_int("the DER signature is a SEQUENCE", 0x30,
             (long)WT_ECDSA_SIGNATURE[0]);

  verify.scheme = WT_TLS_SIG_ECDSA_SECP256R1_SHA256;
  verify.signature = WT_ECDSA_SIGNATURE;
  verify.signature_len = WT_ECDSA_SIGNATURE_LEN;

  /* THE CHECK: a real P-256 signature over real content. */
  wtcert_expect_int("the ECDSA signature verifies", 1,
             wt_tls_certificate_verify_signature(
                 WT_ECDSA_CERT, WT_ECDSA_CERT_LEN, &verify, WT_ECDSA_CONTENT,
                 WT_ECDSA_CONTENT_LEN));

  /* NEGATIVE: every byte of the signature changed, and every byte of the
     content changed, must fail. A verifier that accepted a mangled signature
     would pass the check above and nothing else. */
  {
    uint8_t forged[WT_ECDSA_SIGNATURE_LEN];
    size_t i;
    for (i = 0U; i < WT_ECDSA_SIGNATURE_LEN; i++) {
      wt_tls_certificate_verify_t mangled = verify;
      memcpy(forged, WT_ECDSA_SIGNATURE, sizeof(forged));
      forged[i] ^= 0xFFU;
      mangled.signature = forged;
      wtcert_expect_int("a mangled ECDSA signature is refused", 0,
                 wt_tls_certificate_verify_signature(
                     WT_ECDSA_CERT, WT_ECDSA_CERT_LEN, &mangled,
                     WT_ECDSA_CONTENT, WT_ECDSA_CONTENT_LEN));
    }
    for (i = 0U; i < WT_ECDSA_CONTENT_LEN; i += 7U) {
      uint8_t content[WT_ECDSA_CONTENT_LEN];
      memcpy(content, WT_ECDSA_CONTENT, sizeof(content));
      content[i] ^= 0x01U;
      wtcert_expect_int("a changed content byte is refused", 0,
                 wt_tls_certificate_verify_signature(
                     WT_ECDSA_CERT, WT_ECDSA_CERT_LEN, &verify, content,
                     WT_ECDSA_CONTENT_LEN));
    }
  }

  /* The scheme must match the key. A P-256 certificate cannot answer a P-384
     scheme, and an EC certificate cannot answer an RSA one: the dispatcher
     looks up a verifier by scheme, and a scheme whose curve does not match the
     certificate would otherwise reach a multiplication on the wrong curve. */
  {
    wt_tls_certificate_verify_t wrong = verify;
    wrong.scheme = WT_TLS_SIG_ECDSA_SECP384R1_SHA384;
    wtcert_expect_int("a P-384 scheme against a P-256 certificate is refused", -1,
               wt_tls_certificate_verify_signature(
                   WT_ECDSA_CERT, WT_ECDSA_CERT_LEN, &wrong, WT_ECDSA_CONTENT,
                   WT_ECDSA_CONTENT_LEN));
    wrong.scheme = WT_TLS_SIG_ECDSA_SECP521R1_SHA512;
    wtcert_expect_int("a P-521 scheme against a P-256 certificate is refused", -1,
               wt_tls_certificate_verify_signature(
                   WT_ECDSA_CERT, WT_ECDSA_CERT_LEN, &wrong, WT_ECDSA_CONTENT,
                   WT_ECDSA_CONTENT_LEN));
    wrong.scheme = WT_TLS_SIG_RSA_PSS_RSAE_SHA256;
    wtcert_expect_int("an RSA-PSS scheme against an EC certificate is refused", -1,
               wt_tls_certificate_verify_signature(
                   WT_ECDSA_CERT, WT_ECDSA_CERT_LEN, &wrong, WT_ECDSA_CONTENT,
                   WT_ECDSA_CONTENT_LEN));
  }

  /* An EC key equals itself and not another EC key, on the same path the RSA
     comparison takes. */
  {
    wt_tls_public_key_t same;
    wtcert_expect_int("an EC key equals itself", 1, wt_tls_public_key_equal(&key, &key));
    memcpy(&same, &key, sizeof(same));
    same.ec.q = same.storage;
    wtcert_expect_int("and equals a copy of itself", 1,
               wt_tls_public_key_equal(&key, &same));
    same.storage[20] ^= 0x01U;
    wtcert_expect_int("but not a copy with one bit changed", 0,
               wt_tls_public_key_equal(&key, &same));
    same.storage[20] ^= 0x01U;
    same.ec.curve = BR_EC_secp384r1;
    wtcert_expect_int("and not the same point on another curve", 0,
               wt_tls_public_key_equal(&key, &same));
  }

  /* The pin, on an EC certificate: this is the path an operator pinning an EC
     deployment takes, and it is the only place a real EC certificate meets the
     pinned-key comparison. */
  {
    wt_tls_pinned_key_t pin;
    wt_tls_pinned_key_t other;
    uint8_t point[WT_ECDSA_POINT_LEN];
    wtcert_expect_int("pin the fixture's EC key", 0,
               wt_tls_pinned_key_set_ec(&pin, BR_EC_secp256r1, WT_ECDSA_POINT,
                                        WT_ECDSA_POINT_LEN));
    wtcert_expect_int("the EC certificate is accepted", (long)WT_TLS_PIN_ACCEPTED,
               (long)wt_tls_pinned_key_accepts_certificate(
                   &pin, WT_ECDSA_CERT, WT_ECDSA_CERT_LEN));
    memcpy(point, WT_ECDSA_POINT, sizeof(point));
    point[40] ^= 0x01U;
    wtcert_expect_int("pin a different point", 0,
               wt_tls_pinned_key_set_ec(&other, BR_EC_secp256r1, point,
                                        sizeof(point)));
    wtcert_expect_int("a different point is a mismatch",
               (long)WT_TLS_PIN_KEY_MISMATCH,
               (long)wt_tls_pinned_key_accepts_certificate(
                   &other, WT_ECDSA_CERT, WT_ECDSA_CERT_LEN));
  }
}
void wtcert_test_ecdsa_long_curves(void) {
  typedef struct long_case {
    const char *label;
    const uint8_t *cert;
    size_t cert_len;
    const uint8_t *point;
    size_t point_len;
    const uint8_t *signature;
    size_t signature_len;
    int curve;
    uint16_t scheme;
    size_t coordinate; /* bytes per coordinate; the point is 1 + 2 of them */
  } long_case_t;
  static const long_case_t cases[] = {
    {"P-384", WT_ECDSA_P384_CERT, WT_ECDSA_P384_CERT_LEN,
     WT_ECDSA_P384_POINT, WT_ECDSA_P384_POINT_LEN,
     WT_ECDSA_P384_SIGNATURE, WT_ECDSA_P384_SIGNATURE_LEN,
     BR_EC_secp384r1, WT_TLS_SIG_ECDSA_SECP384R1_SHA384, 48U},
    {"P-521", WT_ECDSA_P521_CERT, WT_ECDSA_P521_CERT_LEN,
     WT_ECDSA_P521_POINT, WT_ECDSA_P521_POINT_LEN,
     WT_ECDSA_P521_SIGNATURE, WT_ECDSA_P521_SIGNATURE_LEN,
     BR_EC_secp521r1, WT_TLS_SIG_ECDSA_SECP521R1_SHA512, 66U},
  };
  size_t c;
  for (c = 0U; c < sizeof(cases) / sizeof(cases[0]); c++) {
    wt_tls_certificate_verify_t verify;
    wt_tls_public_key_t key;
    wtcert_expect_int("the certificate has a readable key", 0,
               wt_tls_certificate_public_key(cases[c].cert, cases[c].cert_len,
                                             &key));
    wtcert_expect_int("it is not RSA", 0, key.is_rsa);
    wtcert_expect_int("it is on the curve the scheme names", cases[c].curve,
               key.ec.curve);
    wtcert_expect_int("with the uncompressed point length that curve needs",
               (long)(1U + (2U * cases[c].coordinate)), (long)key.ec.qlen);
    wtcert_expect_bytes("and the point is the one the generator computed",
                 cases[c].point, key.ec.q, cases[c].point_len);
    wtcert_expect_int("the DER signature is a SEQUENCE", 0x30,
               (long)cases[c].signature[0]);

    verify.scheme = cases[c].scheme;
    verify.signature = cases[c].signature;
    verify.signature_len = cases[c].signature_len;

    /* THE CHECK: a real signature on this curve. This is the multiplication
       that had never run. */
    wtcert_expect_int("the signature verifies on this curve", 1,
               wt_tls_certificate_verify_signature(
                   cases[c].cert, cases[c].cert_len, &verify, WT_ECDSA_CONTENT,
                   WT_ECDSA_CONTENT_LEN));

    /* NEGATIVE: a mangled signature must still be refused here. A verifier
       that returned success for the longer curves without doing the
       arithmetic would pass the check above and nothing else. */
    {
      uint8_t forged[WT_ECDSA_P521_SIGNATURE_LEN];
      size_t i;
      for (i = 0U; i < cases[c].signature_len; i++) {
        wt_tls_certificate_verify_t mangled = verify;
        memcpy(forged, cases[c].signature, cases[c].signature_len);
        forged[i] ^= 0xFFU;
        mangled.signature = forged;
        wtcert_expect_int("a mangled signature is refused on this curve", 0,
                   wt_tls_certificate_verify_signature(
                       cases[c].cert, cases[c].cert_len, &mangled,
                       WT_ECDSA_CONTENT, WT_ECDSA_CONTENT_LEN));
      }
    }

    /* And the curves must not answer for each other: the same certificate
       answering a different curve's scheme is the mismatch the curve check
       exists for, now exercised from the other side as well. */
    {
      wt_tls_certificate_verify_t wrong = verify;
      wrong.scheme = cases[c].scheme == WT_TLS_SIG_ECDSA_SECP384R1_SHA384
                         ? WT_TLS_SIG_ECDSA_SECP256R1_SHA256
                         : WT_TLS_SIG_ECDSA_SECP384R1_SHA384;
      wtcert_expect_int("another curve's scheme is refused", -1,
                 wt_tls_certificate_verify_signature(
                     cases[c].cert, cases[c].cert_len, &wrong,
                     WT_ECDSA_CONTENT, WT_ECDSA_CONTENT_LEN));
    }
  }
}
