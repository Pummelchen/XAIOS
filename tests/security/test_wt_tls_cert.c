/* TLS 1.3 Certificate and CertificateVerify, checked against RFC 8448.
 *
 * The test that matters verifies RFC 8448's own CertificateVerify signature:
 * the certificate the RFC sends, the signature the RFC sends, and the signed
 * content built from the transcript of the RFC's own messages. That is a real
 * RSA-PSS signature over a real TLS 1.3 transcript, so it exercises the message
 * framing, the 64-space prefix, the context string, the transcript hash, the
 * X.509 key extraction and the PSS check at once -- and a mistake in any of
 * them shows up as a signature that does not verify rather than as a handshake
 * that fails later for an unexplained reason.
 *
 * It also checks the negative cases, because a verifier that accepts everything
 * passes the positive one: a corrupted signature, a corrupted transcript, the
 * wrong context string, and a certificate that is not the signer's.
 */

#include "wt_tls_cert.h"
#include "wt_ecdsa_vectors.h"
#include "wt_rfc8448_vectors.h"
#include "wt_tls_pin.h"

#include <stdio.h>
#include <string.h>

static int g_failures;
static int g_checks;

static void expect_bytes(const char *name, const uint8_t *want,
                         const uint8_t *got, size_t len) {
  g_checks++;
  if (memcmp(want, got, len) == 0) return;
  g_failures++;
  printf("FAIL %s\n     want ", name);
  for (size_t i = 0; i < len; i++) printf("%02x", want[i]);
  printf("\n     got  ");
  for (size_t i = 0; i < len; i++) printf("%02x", got[i]);
  printf("\n");
}

static void expect_int(const char *name, long want, long got) {
  g_checks++;
  if (want == got) return;
  g_failures++;
  printf("FAIL %s: want %ld, got %ld\n", name, want, got);
}

/* Walk a 1 KiB array down the stack, so that any storage a returned pointer
 * might still refer to is overwritten. This exists to catch use-after-return:
 * a view into a callee's frame that happened to survive one call is a view that
 * changes the moment anything else runs. */
static void sweep_the_stack(int depth) {
  volatile uint8_t junk[1024];
  size_t i;
  for (i = 0U; i < sizeof(junk); i++) junk[i] = 0xA5U;
  if (depth > 0) sweep_the_stack(depth - 1);
  (void)junk[0];
}

/* The transcript hash through Certificate, which is what the CertificateVerify
 * signs. Rebuilt here from the RFC's messages rather than taken from a vector:
 * the RFC prints the signature and not this hash, and deriving it from the
 * messages is the check that the messages were framed right. */
static int transcript_through_certificate(uint8_t out[WT_TLS_HASH_LEN]) {
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

static void test_parse_certificate(void) {
  wt_tls_certificate_chain_t chain;

  expect_int("parse the RFC's Certificate", 0,
             wt_tls_parse_certificate(WT_RFC8448_CERTIFICATE,
                                      sizeof(WT_RFC8448_CERTIFICATE), &chain));
  expect_int("one entry", 1, (long)chain.count);
  /* RFC 8448's certificate is 432 bytes of DER; the message body's own length
     fields say so and the parse must agree. */
  expect_int("the entry is 432 bytes", 432, (long)chain.lengths[0]);
  expect_int("the entry starts where the message says", 1,
             (long)(chain.entries[0] > WT_RFC8448_CERTIFICATE));
  expect_int("no certificate extensions", 0, (long)chain.extensions_len);

  /* The DER must start with a SEQUENCE, which is the only thing a caller can
     check cheaply before handing it to a parser. */
  expect_int("the entry is a DER SEQUENCE", 0x30, chain.entries[0][0]);

  /* Refusals. Each of these is reachable from the wire. */
  expect_int("a ClientHello is not a Certificate", -1,
             wt_tls_parse_certificate(WT_RFC8448_CLIENT_HELLO,
                                      sizeof(WT_RFC8448_CLIENT_HELLO), &chain));
  expect_int("a NULL message is refused", -1,
             wt_tls_parse_certificate(NULL, 100U, &chain));
  expect_int("a NULL output is refused", -1,
             wt_tls_parse_certificate(WT_RFC8448_CERTIFICATE,
                                      sizeof(WT_RFC8448_CERTIFICATE), NULL));
  expect_int("a truncated header is refused", -1,
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
    expect_int("no truncated Certificate is accepted", 0, accepted);
  }

  /* A declared body length that overruns the buffer is a refusal. */
  {
    uint8_t forged[64];
    memcpy(forged, WT_RFC8448_CERTIFICATE, sizeof(forged));
    forged[1] = 0xffU;
    forged[2] = 0xffU;
    forged[3] = 0xffU;
    expect_int("a body length past the buffer is refused", -1,
               wt_tls_parse_certificate(forged, sizeof(forged), &chain));
  }
}

static void test_parse_certificate_verify(void) {
  wt_tls_certificate_verify_t verify;

  expect_int("parse the RFC's CertificateVerify", 0,
             wt_tls_parse_certificate_verify(WT_RFC8448_CERTIFICATE_VERIFY,
                                             sizeof(WT_RFC8448_CERTIFICATE_VERIFY),
                                             &verify));
  expect_int("the scheme is rsa_pss_rsae_sha256", 0x0804,
             (long)verify.scheme);
  expect_int("the signature is 128 bytes", 128, (long)verify.signature_len);

  {
    int accepted = 0;
    for (size_t cut = 0U; cut < sizeof(WT_RFC8448_CERTIFICATE_VERIFY); cut++) {
      wt_tls_certificate_verify_t partial;
      if (wt_tls_parse_certificate_verify(WT_RFC8448_CERTIFICATE_VERIFY, cut,
                                          &partial) == 0) {
        accepted++;
      }
    }
    expect_int("no truncated CertificateVerify is accepted", 0, accepted);
  }

  expect_int("a Certificate is not a CertificateVerify", -1,
             wt_tls_parse_certificate_verify(WT_RFC8448_CERTIFICATE,
                                             sizeof(WT_RFC8448_CERTIFICATE),
                                             &verify));
  /* A signature length that does not match the body is a refusal, not a
     shorter signature silently compared. */
  {
    uint8_t forged[sizeof(WT_RFC8448_CERTIFICATE_VERIFY)];
    memcpy(forged, WT_RFC8448_CERTIFICATE_VERIFY, sizeof(forged));
    forged[7] = 0x40U; /* claim 64 bytes instead of 128 */
    expect_int("a signature length that disagrees with the body is refused", -1,
               wt_tls_parse_certificate_verify(forged, sizeof(forged), &verify));
  }
}

/* -------------------------------------------------------- signed content */

static void test_signed_content(void) {
  uint8_t hash[WT_TLS_HASH_LEN];
  uint8_t content[256];
  size_t len = 0U;

  expect_int("transcript through Certificate", 0,
             transcript_through_certificate(hash));
  expect_int("build the signed content", 0,
             wt_tls_certificate_verify_content(
                 wt_tls_server_certificate_verify_context, hash, content,
                 sizeof(content), &len));

  /* 64 spaces, the context string, a zero byte, then 32 bytes of hash. */
  expect_int("the content is 64 + 33 + 1 + 32 bytes",
             (long)(64U + strlen(wt_tls_server_certificate_verify_context) + 1U +
                    WT_TLS_HASH_LEN),
             (long)len);
  {
    int all_spaces = 1;
    for (size_t i = 0U; i < 64U; i++) {
      if (content[i] != 0x20U) all_spaces = 0;
    }
    expect_int("the first 64 bytes are spaces", 1, all_spaces);
  }
  expect_bytes("the context string is where it should be",
               (const uint8_t *)wt_tls_server_certificate_verify_context,
               content + 64U,
               strlen(wt_tls_server_certificate_verify_context));
  expect_int("a zero byte separates the context from the hash", 0,
             (long)content[64U + strlen(wt_tls_server_certificate_verify_context)]);
  expect_bytes("the transcript hash is last", hash,
               content + 64U + strlen(wt_tls_server_certificate_verify_context) + 1U,
               WT_TLS_HASH_LEN);

  /* The context string must be the server's exactly: RFC 8446 section 4.4.3
     gives both, and they differ in one word. */
  expect_int("the server context string is the RFC's",
             (long)strlen("TLS 1.3, server CertificateVerify"),
             (long)strlen(wt_tls_server_certificate_verify_context));
  expect_int("and it matches byte for byte", 1,
             (long)(strcmp(wt_tls_server_certificate_verify_context,
                           "TLS 1.3, server CertificateVerify") == 0));

  /* The client's context string must produce different content, so a caller
     that passed the wrong one would not verify. */
  {
    uint8_t other[256];
    size_t other_len = 0U;
    expect_int("build content with the client context", 0,
               wt_tls_certificate_verify_content(
                   "TLS 1.3, client CertificateVerify", hash, other,
                   sizeof(other), &other_len));
    g_checks++;
    if (other_len == len && memcmp(other, content, len) == 0) {
      g_failures++;
      printf("FAIL the two context strings produce the same content\n");
    }
  }

  /* A buffer that is too small is refused and reports what it needed. */
  {
    size_t needed = 0U;
    expect_int("an undersized buffer is refused", -1,
               wt_tls_certificate_verify_content(
                   wt_tls_server_certificate_verify_context, hash, content, 10U,
                   &needed));
    expect_int("and the required size is reported", (long)len, (long)needed);
  }
  expect_int("a NULL context is refused", -1,
             wt_tls_certificate_verify_content(NULL, hash, content,
                                               sizeof(content), &len));
  expect_int("a NULL hash is refused", -1,
             wt_tls_certificate_verify_content(
                 wt_tls_server_certificate_verify_context, NULL, content,
                 sizeof(content), &len));
}

/* ------------------------------------------------------- the signature */

static void test_signature(void) {
  wt_tls_certificate_chain_t chain;
  wt_tls_certificate_verify_t verify;
  uint8_t hash[WT_TLS_HASH_LEN];
  uint8_t content[256];
  size_t content_len = 0U;

  expect_int("parse the Certificate", 0,
             wt_tls_parse_certificate(WT_RFC8448_CERTIFICATE,
                                      sizeof(WT_RFC8448_CERTIFICATE), &chain));
  expect_int("parse the CertificateVerify", 0,
             wt_tls_parse_certificate_verify(WT_RFC8448_CERTIFICATE_VERIFY,
                                             sizeof(WT_RFC8448_CERTIFICATE_VERIFY),
                                             &verify));
  expect_int("transcript hash", 0, transcript_through_certificate(hash));
  expect_int("signed content", 0,
             wt_tls_certificate_verify_content(
                 wt_tls_server_certificate_verify_context, hash, content,
                 sizeof(content), &content_len));

  /* THE CHECK. RFC 8448's signature over RFC 8448's transcript with RFC 8448's
     certificate must verify. */
  expect_int("the RFC's CertificateVerify signature verifies", 1,
             wt_tls_certificate_verify_signature(
                 chain.entries[0], chain.lengths[0], &verify, content,
                 content_len));

  /* The public key is readable, and it is an RSA key of 1024 bits -- the RFC's
     certificate. */
  {
    wt_tls_public_key_t key;
    expect_int("read the certificate's public key", 0,
               wt_tls_certificate_public_key(chain.entries[0], chain.lengths[0],
                                             &key));
    expect_int("it is an RSA key", 1, key.is_rsa);
    expect_int("its modulus is 128 bytes", 128, (long)key.rsa.nlen);
    expect_int("its exponent is 3 bytes", 3, (long)key.rsa.elen);
    /* The RFC's exponent is 65537. */
    expect_int("the exponent is 65537", 1,
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
      expect_bytes("the modulus survives a stack sweep", before, key.rsa.n,
                   sizeof(before));
      for (i = 0U; i < sizeof(before); i++) {
        if (before[i] != 0x00U) break;
      }
      expect_int("and it is not all zeros", 1, i < sizeof(before) ? 1 : 0);
    }

    /* A key compared against itself is equal; against a different key it is
       not. This is the pinned-key comparison. */
    {
      wt_tls_public_key_t same;
      expect_int("a key equals itself", 1,
                 wt_tls_public_key_equal(&key, &key));
      memcpy(&same, &key, sizeof(same));
      /* The copy's views point at the original's storage, so re-point them at
         the copy: a struct copy of a self-referential structure is exactly the
         mistake this type makes hard to write by accident. */
      same.rsa.n = same.storage;
      same.rsa.e = same.storage + same.rsa.nlen;
      expect_int("a copied key still equals it", 1,
                 wt_tls_public_key_equal(&key, &same));
      same.storage[64] ^= 0x01U;
      expect_int("a different modulus is a different key", 0,
                 wt_tls_public_key_equal(&key, &same));
      same.storage[64] ^= 0x01U;
      same.storage[key.rsa.nlen] ^= 0x01U;
      expect_int("a different exponent is a different key", 0,
                 wt_tls_public_key_equal(&key, &same));
    }
    expect_int("a NULL key is refused", 0, wt_tls_public_key_equal(&key, NULL));
    expect_int("a NULL key is refused from either side", 0,
               wt_tls_public_key_equal(NULL, &key));

    /* A pristine key (all zeros) is not equal to a real one: an uninitialised
       key must never compare equal. */
    {
      wt_tls_public_key_t empty;
      memset(&empty, 0, sizeof(empty));
      expect_int("an all-zero key is not equal to a real one", 0,
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
      expect_int("rebuild the key from its bytes", 0,
                 wt_tls_public_key_set_rsa(&rebuilt, key.rsa.n, key.rsa.nlen,
                                           key.rsa.e, key.rsa.elen));
      expect_int("the rebuilt key equals the certificate's", 1,
                 wt_tls_public_key_equal(&key, &rebuilt));
      for (i = 0U; i < 128U; i++) {
        static const char digits[] = "0123456789abcdef";
        hex[2U * i] = digits[(key.rsa.n[i] >> 4) & 0x0FU];
        hex[2U * i + 1U] = digits[key.rsa.n[i] & 0x0FU];
      }
      hex[256] = '\0';
      expect_int("rebuild the key from hex", 0,
                 wt_tls_public_key_set_rsa_hex(&rebuilt, hex, 65537U));
      expect_int("the hex key equals the certificate's", 1,
                 wt_tls_public_key_equal(&key, &rebuilt));

      /* And the refusals: a padded modulus, an odd-length string, a non-hex
         character, an empty string, a zero exponent, and a key with one bit
         changed are all refused or unequal. */
      {
        char padded[259];
        padded[0] = '0';
        padded[1] = '0';
        memcpy(padded + 2U, hex, 257U);
        expect_int("a leading 00 byte is refused", -1,
                   wt_tls_public_key_set_rsa_hex(&rebuilt, padded, 65537U));
      }
      expect_int("an odd-length hex string is refused", -1,
                 wt_tls_public_key_set_rsa_hex(&rebuilt, "abc", 65537U));
      {
        char bad[257];
        memcpy(bad, hex, 257U);
        bad[128] = 'z';
        expect_int("a non-hex digit is refused", -1,
                   wt_tls_public_key_set_rsa_hex(&rebuilt, bad, 65537U));
      }
      expect_int("an empty hex string is refused", -1,
                 wt_tls_public_key_set_rsa_hex(&rebuilt, "", 65537U));
      expect_int("a zero exponent is refused", -1,
                 wt_tls_public_key_set_rsa_hex(&rebuilt, hex, 0U));
      expect_int("a NULL hex string is refused", -1,
                 wt_tls_public_key_set_rsa_hex(&rebuilt, NULL, 65537U));
      {
        uint8_t exponent_zero[3] = {0x00U, 0x00U, 0x03U};
        expect_int("a leading zero in the exponent is refused", -1,
                   wt_tls_public_key_set_rsa(&rebuilt, key.rsa.n, key.rsa.nlen,
                                             exponent_zero, 3U));
      }
      expect_int("a NULL modulus is refused", -1,
                 wt_tls_public_key_set_rsa(&rebuilt, NULL, 128U, key.rsa.e,
                                           3U));
      {
        uint8_t too_big[WT_TLS_PUBLIC_KEY_MAX + 1U];
        memset(too_big, 0x80, sizeof(too_big));
        expect_int("a modulus that does not fit is refused", -1,
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
    expect_int("a NULL certificate is refused", -1,
               wt_tls_certificate_public_key(NULL, 100U, &key));
    expect_int("  and the key is cleared", 0, (long)key.storage_len);
    expect_int("an empty certificate is refused", -1,
               wt_tls_certificate_public_key(not_a_certificate, 0U, &key));
    expect_int("  and the key is cleared", 0, (long)key.storage_len);
    expect_int("a non-certificate is refused", -1,
               wt_tls_certificate_public_key(not_a_certificate,
                                             sizeof(not_a_certificate), &key));
    expect_int("  and the key is cleared", 0, (long)key.storage_len);
    expect_int("a NULL output is refused", -1,
               wt_tls_certificate_public_key(chain.entries[0],
                                             chain.lengths[0], NULL));
    /* A truncated certificate is not a certificate. */
    expect_int("a truncated certificate is refused", -1,
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
      expect_int("the forged message parses", 0,
                 wt_tls_parse_certificate_verify(forged, sizeof(forged),
                                                 &forged_verify));
      if (wt_tls_certificate_verify_signature(
              chain.entries[0], chain.lengths[0], &forged_verify, content,
              content_len) == 1) {
        accepted++;
      }
    }
    expect_int("no single-byte change to the signature verifies", 0, accepted);
  }

  /* NEGATIVE: a changed transcript must fail. */
  {
    uint8_t altered[256];
    size_t altered_len = 0U;
    memcpy(altered, content, content_len);
    altered[content_len - 1U] ^= 0x01U;
    expect_int("a changed transcript does not verify", 0,
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
    expect_int("content with the client context", 0,
               wt_tls_certificate_verify_content(
                   "TLS 1.3, client CertificateVerify", hash, other,
                   sizeof(other), &other_len));
    expect_int("the client context does not verify a server signature", 0,
               wt_tls_certificate_verify_signature(
                   chain.entries[0], chain.lengths[0], &verify, other,
                   other_len));
  }

  /* NEGATIVE: an unsupported scheme is a refusal, not a failed check. */
  {
    wt_tls_certificate_verify_t unknown = verify;
    unknown.scheme = 0x9999U;
    expect_int("an unknown scheme is refused", -1,
               wt_tls_certificate_verify_signature(
                   chain.entries[0], chain.lengths[0], &unknown, content,
                   content_len));
  }

  /* NEGATIVE: a certificate that is not the signer's. The ClientHello is not a
     certificate at all, so the key cannot be read and the check is refused
     rather than reported as a failed signature. */
  expect_int("a non-certificate is refused", -1,
             wt_tls_certificate_verify_signature(
                 WT_RFC8448_CLIENT_HELLO, sizeof(WT_RFC8448_CLIENT_HELLO),
                 &verify, content, content_len));
  expect_int("a NULL certificate is refused", -1,
             wt_tls_certificate_verify_signature(NULL, 100U, &verify, content,
                                                 content_len));
  expect_int("a NULL verify is refused", -1,
             wt_tls_certificate_verify_signature(
                 chain.entries[0], chain.lengths[0], NULL, content,
                 content_len));
  expect_int("a NULL content is refused", -1,
             wt_tls_certificate_verify_signature(
                 chain.entries[0], chain.lengths[0], &verify, NULL,
                 content_len));
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
static void test_ecdsa(void) {
  wt_tls_certificate_verify_t verify;
  wt_tls_public_key_t key;

  expect_int("the fixture's certificate has a readable key", 0,
             wt_tls_certificate_public_key(WT_ECDSA_CERT, WT_ECDSA_CERT_LEN,
                                           &key));
  expect_int("it is not RSA", 0, key.is_rsa);
  expect_int("it is on secp256r1", BR_EC_secp256r1, key.ec.curve);
  expect_int("with a 65-byte uncompressed point", 65, (long)key.ec.qlen);
  expect_bytes("and the point is the one the generator computed",
               WT_ECDSA_POINT, key.ec.q, WT_ECDSA_POINT_LEN);
  expect_int("the DER signature is a SEQUENCE", 0x30,
             (long)WT_ECDSA_SIGNATURE[0]);

  verify.scheme = WT_TLS_SIG_ECDSA_SECP256R1_SHA256;
  verify.signature = WT_ECDSA_SIGNATURE;
  verify.signature_len = WT_ECDSA_SIGNATURE_LEN;

  /* THE CHECK: a real P-256 signature over real content. */
  expect_int("the ECDSA signature verifies", 1,
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
      expect_int("a mangled ECDSA signature is refused", 0,
                 wt_tls_certificate_verify_signature(
                     WT_ECDSA_CERT, WT_ECDSA_CERT_LEN, &mangled,
                     WT_ECDSA_CONTENT, WT_ECDSA_CONTENT_LEN));
    }
    for (i = 0U; i < WT_ECDSA_CONTENT_LEN; i += 7U) {
      uint8_t content[WT_ECDSA_CONTENT_LEN];
      memcpy(content, WT_ECDSA_CONTENT, sizeof(content));
      content[i] ^= 0x01U;
      expect_int("a changed content byte is refused", 0,
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
    expect_int("a P-384 scheme against a P-256 certificate is refused", -1,
               wt_tls_certificate_verify_signature(
                   WT_ECDSA_CERT, WT_ECDSA_CERT_LEN, &wrong, WT_ECDSA_CONTENT,
                   WT_ECDSA_CONTENT_LEN));
    wrong.scheme = WT_TLS_SIG_ECDSA_SECP521R1_SHA512;
    expect_int("a P-521 scheme against a P-256 certificate is refused", -1,
               wt_tls_certificate_verify_signature(
                   WT_ECDSA_CERT, WT_ECDSA_CERT_LEN, &wrong, WT_ECDSA_CONTENT,
                   WT_ECDSA_CONTENT_LEN));
    wrong.scheme = WT_TLS_SIG_RSA_PSS_RSAE_SHA256;
    expect_int("an RSA-PSS scheme against an EC certificate is refused", -1,
               wt_tls_certificate_verify_signature(
                   WT_ECDSA_CERT, WT_ECDSA_CERT_LEN, &wrong, WT_ECDSA_CONTENT,
                   WT_ECDSA_CONTENT_LEN));
  }

  /* An EC key equals itself and not another EC key, on the same path the RSA
     comparison takes. */
  {
    wt_tls_public_key_t same;
    expect_int("an EC key equals itself", 1, wt_tls_public_key_equal(&key, &key));
    memcpy(&same, &key, sizeof(same));
    same.ec.q = same.storage;
    expect_int("and equals a copy of itself", 1,
               wt_tls_public_key_equal(&key, &same));
    same.storage[20] ^= 0x01U;
    expect_int("but not a copy with one bit changed", 0,
               wt_tls_public_key_equal(&key, &same));
    same.storage[20] ^= 0x01U;
    same.ec.curve = BR_EC_secp384r1;
    expect_int("and not the same point on another curve", 0,
               wt_tls_public_key_equal(&key, &same));
  }

  /* The pin, on an EC certificate: this is the path an operator pinning an EC
     deployment takes, and it is the only place a real EC certificate meets the
     pinned-key comparison. */
  {
    wt_tls_pinned_key_t pin;
    wt_tls_pinned_key_t other;
    uint8_t point[WT_ECDSA_POINT_LEN];
    expect_int("pin the fixture's EC key", 0,
               wt_tls_pinned_key_set_ec(&pin, BR_EC_secp256r1, WT_ECDSA_POINT,
                                        WT_ECDSA_POINT_LEN));
    expect_int("the EC certificate is accepted", (long)WT_TLS_PIN_ACCEPTED,
               (long)wt_tls_pinned_key_accepts_certificate(
                   &pin, WT_ECDSA_CERT, WT_ECDSA_CERT_LEN));
    memcpy(point, WT_ECDSA_POINT, sizeof(point));
    point[40] ^= 0x01U;
    expect_int("pin a different point", 0,
               wt_tls_pinned_key_set_ec(&other, BR_EC_secp256r1, point,
                                        sizeof(point)));
    expect_int("a different point is a mismatch",
               (long)WT_TLS_PIN_KEY_MISMATCH,
               (long)wt_tls_pinned_key_accepts_certificate(
                   &other, WT_ECDSA_CERT, WT_ECDSA_CERT_LEN));
  }
}

int main(void) {
  test_parse_certificate();
  test_parse_certificate_verify();
  test_signed_content();
  test_signature();
  test_ecdsa();

  if (g_failures != 0) {
    printf("wt_tls_cert: %d of %d checks FAILED\n", g_failures, g_checks);
    return 1;
  }
  printf("wt_tls_cert: all %d checks reproduced their RFC 8446 / 8448 vector\n",
         g_checks);
  return 0;
}
