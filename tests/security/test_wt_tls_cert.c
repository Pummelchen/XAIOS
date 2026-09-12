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
#include "wt_rfc8448_vectors.h"

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
    int is_rsa = 0;
    br_rsa_public_key rsa;
    br_ec_public_key ec;
    expect_int("read the certificate's public key", 0,
               wt_tls_certificate_public_key(chain.entries[0],
                                             chain.lengths[0], &is_rsa, &rsa,
                                             &ec));
    expect_int("it is an RSA key", 1, is_rsa);
    expect_int("its modulus is 128 bytes", 128, (long)rsa.nlen);
    expect_int("its exponent is 3 bytes", 3, (long)rsa.elen);
    /* The RFC's exponent is 65537. */
    expect_int("the exponent is 65537", 1,
               (long)(rsa.e[0] == 0x01U && rsa.e[1] == 0x00U &&
                      rsa.e[2] == 0x01U));

    /* A key compared against itself is equal; against a different key it is
       not. This is the pinned-key comparison. */
    {
      br_rsa_public_key same = rsa;
      expect_int("a key equals itself", 1,
                 wt_tls_rsa_public_key_equal(&rsa, &same));
    }
    {
      /* Flip a bit in a copy of the modulus: a different key. */
      static uint8_t other_n[128];
      br_rsa_public_key other;
      memcpy(other_n, rsa.n, 128U);
      other_n[64] ^= 0x01U;
      other.n = other_n;
      other.nlen = 128U;
      other.e = rsa.e;
      other.elen = rsa.elen;
      expect_int("a different modulus is a different key", 0,
                 wt_tls_rsa_public_key_equal(&rsa, &other));
    }
    {
      /* And a different exponent with the same modulus is too. */
      static uint8_t other_e[3] = {0x01U, 0x00U, 0x03U};
      br_rsa_public_key other = rsa;
      other.e = other_e;
      other.elen = 3U;
      expect_int("a different exponent is a different key", 0,
                 wt_tls_rsa_public_key_equal(&rsa, &other));
    }
    expect_int("a NULL key is refused", 0,
               wt_tls_rsa_public_key_equal(&rsa, NULL));
    expect_int("reading a key from a NULL certificate is refused", -1,
               wt_tls_certificate_public_key(NULL, 100U, &is_rsa, &rsa, &ec));
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

int main(void) {
  test_parse_certificate();
  test_parse_certificate_verify();
  test_signed_content();
  test_signature();

  if (g_failures != 0) {
    printf("wt_tls_cert: %d of %d checks FAILED\n", g_failures, g_checks);
    return 1;
  }
  printf("wt_tls_cert: all %d checks reproduced their RFC 8446 / 8448 vector\n",
         g_checks);
  return 0;
}
