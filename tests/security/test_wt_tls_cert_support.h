#ifndef XAIOS_TESTS_SECURITY_TEST_WT_TLS_CERT_SUPPORT_H
#define XAIOS_TESTS_SECURITY_TEST_WT_TLS_CERT_SUPPORT_H

/* Declarations shared by the three translation units of the TLS 1.3
 * Certificate and CertificateVerify test.
 *
 * `test_wt_tls_cert.c` was one 979-line file. It is now the driver and entry
 * point plus two modules: `test_wt_tls_cert_parse.c` holds the check helpers,
 * the transcript helper and the Certificate and CertificateVerify parser
 * tests; `test_wt_tls_cert_signature.c` holds the signature checks -- RSA-PSS
 * against RFC 8448, the ECDSA paths on three curves, the long-hash schemes and
 * the SubjectPublicKeyInfo comparison. Everything that crosses a translation
 * unit is declared here; the counters are defined exactly once, in the parse
 * module.
 *
 * Every symbol that leaves its own translation unit carries the `wtcert_`
 * prefix. The host runner links the modules of a split WebTransport test
 * together with the ones it already shares, so `expect_int` and `test_ecdsa`
 * unprefixed would collide with a sibling suite's own helpers; the sibling
 * suites use `wtc_` and `twth_`, so the third prefix keeps the three apart.
 * The two check helpers moved here are `static inline` for the same reason the
 * handshake suite's are: each translation unit includes this header and each
 * unit uses both, but two external definitions of one name would not link.
 * Their counters are `extern` because `main` reads them for the exit status
 * and the final line.
 *
 * Nothing here is for anyone outside this test.
 */

#include "wt_tls_cert.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* The two counters, owned by the parse module. A test increments them through
 * the helpers below; the driver's `main` reads them to decide the exit status
 * and to print the total. */
extern int wtcert_failures;
extern int wtcert_checks;

static inline void wtcert_expect_bytes(const char *name, const uint8_t *want,
                                       const uint8_t *got, size_t len) {
  wtcert_checks++;
  if (memcmp(want, got, len) == 0) return;
  wtcert_failures++;
  printf("FAIL %s\n     want ", name);
  for (size_t i = 0; i < len; i++) printf("%02x", want[i]);
  printf("\n     got  ");
  for (size_t i = 0; i < len; i++) printf("%02x", got[i]);
  printf("\n");
}

static inline void wtcert_expect_int(const char *name, long want, long got) {
  wtcert_checks++;
  if (want == got) return;
  wtcert_failures++;
  printf("FAIL %s: want %ld, got %ld\n", name, want, got);
}

/* The transcript hash through Certificate, which is what the CertificateVerify
 * signs. Defined in the parse module; used by the driver's signed-content test
 * and by the signature module's RSA and long-hash tests. */
int wtcert_transcript_through_certificate(uint8_t out[WT_TLS_HASH_LEN]);

/* The tests that live outside the driver, declared in the order `main` calls
 * them. The parse module owns the parser and ECDSA tests, the signature module
 * the RSA-PSS, long-hash and SPKI tests. */
void wtcert_test_parse_certificate(void);
void wtcert_test_empty_certificate_list(void);
void wtcert_test_parse_certificate_verify(void);
void wtcert_test_signature(void);
void wtcert_test_long_hash_schemes(void);
void wtcert_test_ecdsa(void);
void wtcert_test_ecdsa_long_curves(void);
void wtcert_test_spki_parser(void);

#endif
