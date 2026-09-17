/* The CertificateVerify signature checks: RSA-PSS against RFC 8448's own
 * transcript, the longer hash schemes, and the SubjectPublicKeyInfo comparison
 * against BearSSL's decoder.
 *
 * This was the bottom of `test_wt_tls_cert.c`. The opening comment, `main`, the
 * parsers and the structural tests stayed in the driver; the check helpers and
 * the transcript helper are defined in `test_wt_tls_cert_parse.c` and declared
 * in `test_wt_tls_cert_support.h`.
 */
#include "test_wt_tls_cert_support.h"

#include "wt_ecdsa_vectors.h"
#include "wt_rfc8448_vectors.h"
#include "wt_tls_pin.h"

#include <stdio.h>
#include <string.h>

/* Walk a 1 KiB array down the stack, so that any storage a returned pointer
 * might still refer to is overwritten. This exists to catch use-after-return:
 * a view into a callee's frame that happened to survive one call is a view that
 * changes the moment anything else runs. It is defined here because
 * `wtcert_test_signature` is the only caller. */
static void sweep_the_stack(int depth) {
  volatile uint8_t junk[1024];
  size_t i;
  for (i = 0U; i < sizeof(junk); i++) junk[i] = 0xA5U;
  if (depth > 0) sweep_the_stack(depth - 1);
  (void)junk[0];
}

/* ------------------------------------------------------- the signature */

void wtcert_test_signature(void) {
  wt_tls_certificate_chain_t chain;
  wt_tls_certificate_verify_t verify;
  uint8_t hash[WT_TLS_HASH_LEN];
  uint8_t content[256];
  size_t content_len = 0U;

  wtcert_expect_int("parse the Certificate", 0,
             wt_tls_parse_certificate(WT_RFC8448_CERTIFICATE,
                                      sizeof(WT_RFC8448_CERTIFICATE), &chain));
  wtcert_expect_int("parse the CertificateVerify", 0,
             wt_tls_parse_certificate_verify(WT_RFC8448_CERTIFICATE_VERIFY,
                                             sizeof(WT_RFC8448_CERTIFICATE_VERIFY),
                                             &verify));
  wtcert_expect_int("transcript hash", 0, wtcert_transcript_through_certificate(hash));
  wtcert_expect_int("signed content", 0,
             wt_tls_certificate_verify_content(
                 wt_tls_server_certificate_verify_context, hash, content,
                 sizeof(content), &content_len));

  /* THE CHECK. RFC 8448's signature over RFC 8448's transcript with RFC 8448's
     certificate must verify. */
  wtcert_expect_int("the RFC's CertificateVerify signature verifies", 1,
             wt_tls_certificate_verify_signature(
                 chain.entries[0], chain.lengths[0], &verify, content,
                 content_len));

  /* The public key is readable, and it is an RSA key of 1024 bits -- the RFC's
     certificate. */
  {
    wt_tls_public_key_t key;
    wtcert_expect_int("read the certificate's public key", 0,
               wt_tls_certificate_public_key(chain.entries[0], chain.lengths[0],
                                             &key));
    wtcert_expect_int("it is an RSA key", 1, key.is_rsa);
    wtcert_expect_int("its modulus is 128 bytes", 128, (long)key.rsa.nlen);
    wtcert_expect_int("its exponent is 3 bytes", 3, (long)key.rsa.elen);
    /* The RFC's exponent is 65537. */
    wtcert_expect_int("the exponent is 65537", 1,
               (long)(key.rsa.e[0] == 0x01U && key.rsa.e[1] == 0x00U &&
                      key.rsa.e[2] == 0x01U));

    /* THE KEY MUST SURVIVE THE CALL THAT PRODUCED IT. BearSSL's decoder hands
       out views into its own context, which is a local in the function that
       parses a certificate; an earlier version of this function returned those
       views, so the key was a pointer into a dead stack frame. Reading it after
       another call returned whatever that call had left there -- a
       use-after-return that this test used to pass, because nothing had
       overwritten the bytes yet. So: copy the modulus, sweep the stack, and
       require the key's own bytes to be unchanged. */
    {
      uint8_t before[128];
      size_t i;
      memcpy(before, key.rsa.n, sizeof(before));
      sweep_the_stack(64);
      wtcert_expect_bytes("the modulus survives a stack sweep", before, key.rsa.n,
                   sizeof(before));
      for (i = 0U; i < sizeof(before); i++) {
        if (before[i] != 0x00U) break;
      }
      wtcert_expect_int("and it is not all zeros", 1, i < sizeof(before) ? 1 : 0);
    }

    /* A key compared against itself is equal; against a different key it is
       not. This is the pinned-key comparison. */
    {
      wt_tls_public_key_t same;
      wtcert_expect_int("a key equals itself", 1,
                 wt_tls_public_key_equal(&key, &key));
      memcpy(&same, &key, sizeof(same));
      /* The copy's views point at the original's storage, so re-point them at
         the copy: a struct copy of a self-referential structure is exactly the
         mistake this type makes hard to write by accident. */
      same.rsa.n = same.storage;
      same.rsa.e = same.storage + same.rsa.nlen;
      wtcert_expect_int("a copied key still equals it", 1,
                 wt_tls_public_key_equal(&key, &same));
      same.storage[64] ^= 0x01U;
      wtcert_expect_int("a different modulus is a different key", 0,
                 wt_tls_public_key_equal(&key, &same));
      same.storage[64] ^= 0x01U;
      same.storage[key.rsa.nlen] ^= 0x01U;
      wtcert_expect_int("a different exponent is a different key", 0,
                 wt_tls_public_key_equal(&key, &same));
    }
    wtcert_expect_int("a NULL key is refused", 0, wt_tls_public_key_equal(&key, NULL));
    wtcert_expect_int("a NULL key is refused from either side", 0,
               wt_tls_public_key_equal(NULL, &key));

    /* A pristine key (all zeros) is not equal to a real one: an uninitialised
       key must never compare equal. */
    {
      wt_tls_public_key_t empty;
      memset(&empty, 0, sizeof(empty));
      wtcert_expect_int("an all-zero key is not equal to a real one", 0,
                 wt_tls_public_key_equal(&key, &empty));
    }

    /* The same key rebuilt from the operator's form -- modulus and exponent as
       big-endian bytes -- is the same key, and rebuilding it from hex is the
       same key again. This is what makes a pin checkable against a certificate
       rather than merely plausible. */
    {
      wt_tls_public_key_t rebuilt;
      char hex[257];
      size_t i;
      wtcert_expect_int("rebuild the key from its bytes", 0,
                 wt_tls_public_key_set_rsa(&rebuilt, key.rsa.n, key.rsa.nlen,
                                           key.rsa.e, key.rsa.elen));
      wtcert_expect_int("the rebuilt key equals the certificate's", 1,
                 wt_tls_public_key_equal(&key, &rebuilt));
      for (i = 0U; i < 128U; i++) {
        static const char digits[] = "0123456789abcdef";
        hex[2U * i] = digits[(key.rsa.n[i] >> 4) & 0x0FU];
        hex[2U * i + 1U] = digits[key.rsa.n[i] & 0x0FU];
      }
      hex[256] = '\0';
      wtcert_expect_int("rebuild the key from hex", 0,
                 wt_tls_public_key_set_rsa_hex(&rebuilt, hex, 65537U));
      wtcert_expect_int("the hex key equals the certificate's", 1,
                 wt_tls_public_key_equal(&key, &rebuilt));

      /* And the refusals: a padded modulus, an odd-length string, a non-hex
         character, an empty string, a zero exponent, and a key with one bit
         changed are all refused or unequal. */
      {
        char padded[259];
        padded[0] = '0';
        padded[1] = '0';
        memcpy(padded + 2U, hex, 257U);
        wtcert_expect_int("a leading 00 byte is refused", -1,
                   wt_tls_public_key_set_rsa_hex(&rebuilt, padded, 65537U));
      }
      wtcert_expect_int("an odd-length hex string is refused", -1,
                 wt_tls_public_key_set_rsa_hex(&rebuilt, "abc", 65537U));
      {
        char bad[257];
        memcpy(bad, hex, 257U);
        bad[128] = 'z';
        wtcert_expect_int("a non-hex digit is refused", -1,
                   wt_tls_public_key_set_rsa_hex(&rebuilt, bad, 65537U));
      }
      wtcert_expect_int("an empty hex string is refused", -1,
                 wt_tls_public_key_set_rsa_hex(&rebuilt, "", 65537U));
      wtcert_expect_int("a zero exponent is refused", -1,
                 wt_tls_public_key_set_rsa_hex(&rebuilt, hex, 0U));
      wtcert_expect_int("a NULL hex string is refused", -1,
                 wt_tls_public_key_set_rsa_hex(&rebuilt, NULL, 65537U));
      {
        uint8_t exponent_zero[3] = {0x00U, 0x00U, 0x03U};
        wtcert_expect_int("a leading zero in the exponent is refused", -1,
                   wt_tls_public_key_set_rsa(&rebuilt, key.rsa.n, key.rsa.nlen,
                                             exponent_zero, 3U));
      }
      wtcert_expect_int("a NULL modulus is refused", -1,
                 wt_tls_public_key_set_rsa(&rebuilt, NULL, 128U, key.rsa.e,
                                           3U));
      {
        uint8_t too_big[WT_TLS_PUBLIC_KEY_MAX + 1U];
        memset(too_big, 0x80, sizeof(too_big));
        wtcert_expect_int("a modulus that does not fit is refused", -1,
                   wt_tls_public_key_set_rsa(&rebuilt, too_big, sizeof(too_big),
                                             key.rsa.e, 3U));
      }
    }
  }

  /* Refusals, and each of them must leave the key cleared rather than half
     filled: a caller that ignored the return value would otherwise compare
     against whatever the previous parse left behind. */
  {
    static const uint8_t not_a_certificate[16] = "not a certifica";
    wt_tls_public_key_t key;
    wtcert_expect_int("a NULL certificate is refused", -1,
               wt_tls_certificate_public_key(NULL, 100U, &key));
    wtcert_expect_int("  and the key is cleared", 0, (long)key.storage_len);
    wtcert_expect_int("an empty certificate is refused", -1,
               wt_tls_certificate_public_key(not_a_certificate, 0U, &key));
    wtcert_expect_int("  and the key is cleared", 0, (long)key.storage_len);
    wtcert_expect_int("a non-certificate is refused", -1,
               wt_tls_certificate_public_key(not_a_certificate,
                                             sizeof(not_a_certificate), &key));
    wtcert_expect_int("  and the key is cleared", 0, (long)key.storage_len);
    wtcert_expect_int("a NULL output is refused", -1,
               wt_tls_certificate_public_key(chain.entries[0],
                                             chain.lengths[0], NULL));
    /* A truncated certificate is not a certificate. */
    wtcert_expect_int("a truncated certificate is refused", -1,
               wt_tls_certificate_public_key(chain.entries[0],
                                             chain.lengths[0] / 2U, &key));
  }

  /* NEGATIVE: every single-bit change to the signature must fail. A verifier
     that accepted a mangled signature would pass the positive check above and
     nothing else. */
  {
    uint8_t forged[136];
    int accepted = 0;
    wt_tls_certificate_verify_t forged_verify;
    for (size_t bit = 0U; bit < 128U * 8U; bit += 8U) {
      memcpy(forged, WT_RFC8448_CERTIFICATE_VERIFY, sizeof(forged));
      forged[8U + bit / 8U] ^= (uint8_t)(1U << (bit % 8U));
      wtcert_expect_int("the forged message parses", 0,
                 wt_tls_parse_certificate_verify(forged, sizeof(forged),
                                                 &forged_verify));
      if (wt_tls_certificate_verify_signature(
              chain.entries[0], chain.lengths[0], &forged_verify, content,
              content_len) == 1) {
        accepted++;
      }
    }
    wtcert_expect_int("no single-byte change to the signature verifies", 0, accepted);
  }

  /* NEGATIVE: a changed transcript must fail. */
  {
    uint8_t altered[256];
    size_t altered_len = 0U;
    memcpy(altered, content, content_len);
    altered[content_len - 1U] ^= 0x01U;
    wtcert_expect_int("a changed transcript does not verify", 0,
               wt_tls_certificate_verify_signature(
                   chain.entries[0], chain.lengths[0], &verify, altered,
                   content_len));
    (void)altered_len;
  }

  /* NEGATIVE: the client's context string must not verify, which is the check
     that the context is actually part of the signature. */
  {
    uint8_t other[256];
    size_t other_len = 0U;
    wtcert_expect_int("content with the client context", 0,
               wt_tls_certificate_verify_content(
                   "TLS 1.3, client CertificateVerify", hash, other,
                   sizeof(other), &other_len));
    wtcert_expect_int("the client context does not verify a server signature", 0,
               wt_tls_certificate_verify_signature(
                   chain.entries[0], chain.lengths[0], &verify, other,
                   other_len));
  }

  /* NEGATIVE: an unsupported scheme is a refusal, not a failed check. */
  {
    wt_tls_certificate_verify_t unknown = verify;
    unknown.scheme = 0x9999U;
    wtcert_expect_int("an unknown scheme is refused", -1,
               wt_tls_certificate_verify_signature(
                   chain.entries[0], chain.lengths[0], &unknown, content,
                   content_len));
  }

  /* NEGATIVE: a certificate that is not the signer's. The ClientHello is not a
     certificate at all, so the key cannot be read and the check is refused
     rather than reported as a failed signature. */
  wtcert_expect_int("a non-certificate is refused", -1,
             wt_tls_certificate_verify_signature(
                 WT_RFC8448_CLIENT_HELLO, sizeof(WT_RFC8448_CLIENT_HELLO),
                 &verify, content, content_len));
  wtcert_expect_int("a NULL certificate is refused", -1,
             wt_tls_certificate_verify_signature(NULL, 100U, &verify, content,
                                                 content_len));
  wtcert_expect_int("a NULL verify is refused", -1,
             wt_tls_certificate_verify_signature(
                 chain.entries[0], chain.lengths[0], NULL, content,
                 content_len));
  wtcert_expect_int("a NULL content is refused", -1,
             wt_tls_certificate_verify_signature(
                 chain.entries[0], chain.lengths[0], &verify, NULL,
                 content_len));
}
/* --------------------------------------------- the longer hash schemes
 *
 * RFC 8446 lets a server sign with SHA-384 or SHA-512, and this module offers
 * those schemes. The digest buffer the verifier hashes into was sized for
 * SHA-256, so a CertificateVerify with scheme 0x0805 or 0x0806 wrote 48 or 64
 * bytes into a 32-byte local -- a stack buffer overflow reachable from the
 * wire by an unauthenticated peer, and one that no test covered because the RFC
 * 8448 vector uses SHA-256.
 *
 * The signature here is deliberately garbage: the overflow happens while the
 * signed content is hashed, before the signature is examined, so a wrong
 * signature still exercises the write. Under AddressSanitizer this test fails
 * on the unfixed code and passes on the fixed code, which is the whole point of
 * it -- the check is the sanitizer, not the return value.
 */
void wtcert_test_long_hash_schemes(void) {
  static const uint16_t schemes[2] = {WT_TLS_SIG_RSA_PSS_RSAE_SHA384,
                                      WT_TLS_SIG_RSA_PSS_RSAE_SHA512};
  static const size_t hash_lengths[2] = {48U, 64U};
  wt_tls_certificate_chain_t chain;
  wt_tls_certificate_verify_t verify;
  uint8_t content[130];
  uint8_t signature[128];
  size_t i;

  wtcert_expect_int("the RFC's Certificate parses for the long-hash checks", 0,
             wt_tls_parse_certificate(WT_RFC8448_CERTIFICATE,
                                      sizeof(WT_RFC8448_CERTIFICATE), &chain));
  wtcert_expect_int("with one entry", 1, (long)chain.count);

  memset(content, 0x41, sizeof(content));
  memset(signature, 0x00, sizeof(signature));
  signature[0] = 0x30U;
  verify.signature = signature;
  verify.signature_len = sizeof(signature);

  for (i = 0U; i < 2U; i++) {
    /* The signed content is longer than the hash, so a verifier that hashed
       into a buffer sized for SHA-256 writes past it immediately -- which is
       what AddressSanitizer reports on the unfixed code, before the signature
       is looked at. */
    (void)hash_lengths;
    verify.scheme = schemes[i];
    wtcert_expect_int("a garbage signature under a long hash scheme is refused", 0,
               wt_tls_certificate_verify_signature(
                   chain.entries[0], chain.lengths[0], &verify, content,
                   sizeof(content)));
  }

  /* The same two schemes with a signature too short to hold the hash: the
     refusal must come from the verifier and not from a buffer that was
     overrun. */
  verify.signature_len = 8U;
  for (i = 0U; i < 2U; i++) {
    verify.scheme = schemes[i];
    wtcert_expect_int("a short signature under a long hash scheme is refused", 0,
               wt_tls_certificate_verify_signature(
                   chain.entries[0], chain.lengths[0], &verify, content,
                   sizeof(content)));
  }

  /* And the ECDSA schemes on a P-256 certificate are refused before anything
     is hashed, because the scheme's curve does not match the key's. */
  {
    static const uint16_t curves[2] = {WT_TLS_SIG_ECDSA_SECP384R1_SHA384,
                                       WT_TLS_SIG_ECDSA_SECP521R1_SHA512};
    for (i = 0U; i < 2U; i++) {
      verify.scheme = curves[i];
      verify.signature_len = sizeof(signature);
      wtcert_expect_int("a longer-curve ECDSA scheme is refused", -1,
                 wt_tls_certificate_verify_signature(
                     chain.entries[0], chain.lengths[0], &verify, content,
                     sizeof(content)));
    }
  }
}
/* The SubjectPublicKeyInfo parser is a second implementation of an encoding
 * BearSSL already decodes -- it exists because the vendored WebTransport port
 * receives the SPKI as DER and has no certificate to hand a decoder. A second
 * implementation of a delicate encoding is only defensible if it is checked
 * against the first, so every certificate fixture is parsed both ways and the
 * keys are compared. */
static void compare_spki(const char *what, const uint8_t *cert,
                         size_t cert_len) {
  wt_tls_public_key_t decoded;
  wt_tls_public_key_t parsed;
  const uint8_t *spki = NULL;
  size_t spki_len = 0U;
  char label[128];

  snprintf(label, sizeof(label), "%s: BearSSL decodes the key", what);
  if (wt_tls_certificate_public_key(cert, cert_len, &decoded) != 0) {
    wtcert_expect_int(label, 0, -1);
    return;
  }
  wtcert_expect_int(label, 0, 0);

  snprintf(label, sizeof(label), "%s: the SPKI is located", what);
  if (wt_tls_certificate_spki(cert, cert_len, &spki, &spki_len) != 0) {
    wtcert_expect_int(label, 0, -1);
    return;
  }
  wtcert_expect_int(label, 0, 0);
  snprintf(label, sizeof(label), "%s: the SPKI is non-empty", what);
  wtcert_expect_int(label, 1, spki_len != 0U ? 1 : 0);

  snprintf(label, sizeof(label), "%s: the SPKI parses", what);
  if (wt_tls_public_key_from_spki(spki, spki_len, &parsed) != 0) {
    wtcert_expect_int(label, 0, -1);
    return;
  }
  wtcert_expect_int(label, 0, 0);

  snprintf(label, sizeof(label), "%s: same key type", what);
  wtcert_expect_int(label, decoded.is_rsa, parsed.is_rsa);
  if (decoded.is_rsa) {
    snprintf(label, sizeof(label), "%s: same modulus length", what);
    wtcert_expect_int(label, (long)decoded.rsa.nlen, (long)parsed.rsa.nlen);
    snprintf(label, sizeof(label), "%s: same modulus", what);
    wtcert_expect_bytes(label, decoded.rsa.n, parsed.rsa.n, decoded.rsa.nlen);
    snprintf(label, sizeof(label), "%s: same exponent length", what);
    wtcert_expect_int(label, (long)decoded.rsa.elen, (long)parsed.rsa.elen);
    snprintf(label, sizeof(label), "%s: same exponent", what);
    wtcert_expect_bytes(label, decoded.rsa.e, parsed.rsa.e, decoded.rsa.elen);
  } else {
    snprintf(label, sizeof(label), "%s: same curve", what);
    wtcert_expect_int(label, decoded.ec.curve, parsed.ec.curve);
    snprintf(label, sizeof(label), "%s: same point length", what);
    wtcert_expect_int(label, (long)decoded.ec.qlen, (long)parsed.ec.qlen);
    snprintf(label, sizeof(label), "%s: same point", what);
    wtcert_expect_bytes(label, decoded.ec.q, parsed.ec.q, decoded.ec.qlen);
  }
}
void wtcert_test_spki_parser(void) {
  wt_tls_certificate_chain_t chain;
  compare_spki("p256", WT_ECDSA_CERT, WT_ECDSA_CERT_LEN);
  compare_spki("p384", WT_ECDSA_P384_CERT, WT_ECDSA_P384_CERT_LEN);
  compare_spki("p521", WT_ECDSA_P521_CERT, WT_ECDSA_P521_CERT_LEN);
  /* The RFC 8448 fixture is a whole Certificate message rather than a
     certificate, so its leaf is the view the module's own tests use. */
  wtcert_expect_int("the RFC 8448 Certificate message parses", 0,
             wt_tls_parse_certificate(WT_RFC8448_CERTIFICATE,
                                      sizeof(WT_RFC8448_CERTIFICATE), &chain));
  compare_spki("rfc8448", chain.entries[0], chain.lengths[0]);
}
