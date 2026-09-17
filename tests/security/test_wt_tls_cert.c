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
 *
 * The suite is three translation units: this driver, which keeps `main` and the
 * tests that need no fixture, `test_wt_tls_cert_parse.c` and
 * `test_wt_tls_cert_signature.c`. The runner must compile all three.
 */

#include "test_wt_tls_cert_support.h"

#include "wt_ecdsa_vectors.h"
#include "wt_rfc8448_vectors.h"
#include "wt_tls_pin.h"

#include <stdio.h>
#include <string.h>


/* -------------------------------------------------------- signed content */

static void test_signed_content(void) {
  uint8_t hash[WT_TLS_HASH_LEN];
  uint8_t content[256];
  size_t len = 0U;

  wtcert_expect_int("transcript through Certificate", 0,
             wtcert_transcript_through_certificate(hash));
  wtcert_expect_int("build the signed content", 0,
             wt_tls_certificate_verify_content(
                 wt_tls_server_certificate_verify_context, hash, content,
                 sizeof(content), &len));

  /* 64 spaces, the context string, a zero byte, then 32 bytes of hash. */
  wtcert_expect_int("the content is 64 + 33 + 1 + 32 bytes",
             (long)(64U + strlen(wt_tls_server_certificate_verify_context) + 1U +
                    WT_TLS_HASH_LEN),
             (long)len);
  {
    int all_spaces = 1;
    for (size_t i = 0U; i < 64U; i++) {
      if (content[i] != 0x20U) all_spaces = 0;
    }
    wtcert_expect_int("the first 64 bytes are spaces", 1, all_spaces);
  }
  wtcert_expect_bytes("the context string is where it should be",
               (const uint8_t *)wt_tls_server_certificate_verify_context,
               content + 64U,
               strlen(wt_tls_server_certificate_verify_context));
  wtcert_expect_int("a zero byte separates the context from the hash", 0,
             (long)content[64U + strlen(wt_tls_server_certificate_verify_context)]);
  wtcert_expect_bytes("the transcript hash is last", hash,
               content + 64U + strlen(wt_tls_server_certificate_verify_context) + 1U,
               WT_TLS_HASH_LEN);

  /* The context string must be the server's exactly: RFC 8446 section 4.4.3
     gives both, and they differ in one word. */
  wtcert_expect_int("the server context string is the RFC's",
             (long)strlen("TLS 1.3, server CertificateVerify"),
             (long)strlen(wt_tls_server_certificate_verify_context));
  wtcert_expect_int("and it matches byte for byte", 1,
             (long)(strcmp(wt_tls_server_certificate_verify_context,
                           "TLS 1.3, server CertificateVerify") == 0));

  /* The client's context string must produce different content, so a caller
     that passed the wrong one would not verify. */
  {
    uint8_t other[256];
    size_t other_len = 0U;
    wtcert_expect_int("build content with the client context", 0,
               wt_tls_certificate_verify_content(
                   "TLS 1.3, client CertificateVerify", hash, other,
                   sizeof(other), &other_len));
    wtcert_checks++;
    if (other_len == len && memcmp(other, content, len) == 0) {
      wtcert_failures++;
      printf("FAIL the two context strings produce the same content\n");
    }
  }

  /* A buffer that is too small is refused and reports what it needed. */
  {
    size_t needed = 0U;
    wtcert_expect_int("an undersized buffer is refused", -1,
               wt_tls_certificate_verify_content(
                   wt_tls_server_certificate_verify_context, hash, content, 10U,
                   &needed));
    wtcert_expect_int("and the required size is reported", (long)len, (long)needed);
  }
  wtcert_expect_int("a NULL context is refused", -1,
             wt_tls_certificate_verify_content(NULL, hash, content,
                                               sizeof(content), &len));
  wtcert_expect_int("a NULL hash is refused", -1,
             wt_tls_certificate_verify_content(
                 wt_tls_server_certificate_verify_context, NULL, content,
                 sizeof(content), &len));
}

int main(void) {
  wtcert_test_parse_certificate();
  wtcert_test_empty_certificate_list();
  wtcert_test_parse_certificate_verify();
  test_signed_content();
  wtcert_test_signature();
  wtcert_test_long_hash_schemes();
  wtcert_test_ecdsa();
  wtcert_test_ecdsa_long_curves();
  wtcert_test_spki_parser();

  if (wtcert_failures != 0) {
    printf("wt_tls_cert: %d of %d checks FAILED\n", wtcert_failures, wtcert_checks);
    return 1;
  }
  printf("wt_tls_cert: all %d checks reproduced their RFC 8446 / 8448 vector\n",
         wtcert_checks);
  return 0;
}
