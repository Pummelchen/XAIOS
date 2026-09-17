#ifndef XAIOS_TESTS_SECURITY_TEST_WT_CRYPTO_SUPPORT_H
#define XAIOS_TESTS_SECURITY_TEST_WT_CRYPTO_SUPPORT_H

/* Assertion helpers and counters shared by the split WebTransport crypto test.
 *
 * `test_wt_crypto.c` was one 688-line file. It is now the driver and entry
 * point plus two modules: `test_wt_crypto_primitives.c` holds the SHA-256,
 * HKDF, AES-GCM round-trip, x25519 and helper checks;
 * `test_wt_crypto_packet.c` holds the ChaCha20 block and header-protection
 * check, the HKDF-Expand-Label construction the QUIC labels need, and the whole
 * RFC 9001 Initial packet, header protection and Retry integrity tag check.
 * Everything that crosses a translation unit is declared here and defined
 * exactly once.
 *
 * The five helpers are `static inline` because both modules include this
 * header and use them: an external definition would be emitted twice, and a
 * plain `static` one would be flagged as unused -- with the runner's -Werror --
 * in whichever module did not happen to call it. The two counters they
 * increment are `extern` here because `main` reads them for the exit status and
 * the summary line, and they are defined once, in
 * `test_wt_crypto_primitives.c`.
 *
 * Every symbol that leaves its own translation unit carries the `wtcrypto_`
 * prefix. The host runner links the modules of a split WebTransport test
 * together with the ones it already shares, so an unprefixed `expect_int`
 * would collide with a sibling suite's own helper.
 *
 * Nothing here is for anyone outside this test.
 */

#include "wt_crypto.h"
#include "wt_rfc9001_vectors.h"
#include "wt_rfc8448_vectors.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* The two counters, owned by the primitives module. A test increments them
 * through the helpers below; the driver's `main` reads them to decide the exit
 * status and to print the total. */
extern int wtcrypto_failures;
extern int wtcrypto_checks;

static inline size_t wtcrypto_unhex(const char *hex, uint8_t *out,
                                    size_t out_size) {
  size_t written = 0;
  int high = -1;
  for (const char *p = hex; *p != '\0'; p++) {
    int value;
    if (*p == ' ' || *p == '\n' || *p == '\t') continue;
    if (*p >= '0' && *p <= '9') value = *p - '0';
    else if (*p >= 'a' && *p <= 'f') value = *p - 'a' + 10;
    else if (*p >= 'A' && *p <= 'F') value = *p - 'A' + 10;
    else return (size_t)-1;
    if (high < 0) high = value;
    else {
      if (written >= out_size) return (size_t)-1;
      out[written++] = (uint8_t)((high << 4) | value);
      high = -1;
    }
  }
  return high < 0 ? written : (size_t)-1;
}

/* Decode a vector, failing loudly rather than silently truncating it. */
static inline void wtcrypto_vector(const char *name, const char *hex,
                                   uint8_t *out, size_t out_size,
                                   size_t want_len) {
  size_t n = wtcrypto_unhex(hex, out, out_size);
  wtcrypto_checks++;
  if (n == want_len) return;
  wtcrypto_failures++;
  printf("FAIL %s: vector decoded to %ld bytes, expected %ld\n", name, (long)n,
         (long)want_len);
}

static inline void wtcrypto_expect(const char *name, const uint8_t *want,
                                   const uint8_t *got, size_t len) {
  wtcrypto_checks++;
  if (memcmp(want, got, len) == 0) return;
  wtcrypto_failures++;
  printf("FAIL %s\n     want ", name);
  for (size_t i = 0; i < len; i++) printf("%02x", want[i]);
  printf("\n     got  ");
  for (size_t i = 0; i < len; i++) printf("%02x", got[i]);
  printf("\n");
}

static inline void wtcrypto_expect_int(const char *name, long want, long got) {
  wtcrypto_checks++;
  if (want == got) return;
  wtcrypto_failures++;
  printf("FAIL %s: want %ld, got %ld\n", name, want, got);
}

/* Compare against a hex literal, so the vectors read as the RFC prints them. */
static inline void wtcrypto_expect_hex(const char *name, const char *want_hex,
                                       const uint8_t *got, size_t len) {
  uint8_t want[128];
  size_t n = wtcrypto_unhex(want_hex, want, sizeof(want));
  wtcrypto_checks++;
  if (n == len) {
    if (memcmp(want, got, len) == 0) return;
  } else {
    wtcrypto_failures++;
    printf("FAIL %s: vector decoded to %ld bytes, expected %ld\n", name,
           (long)n, (long)len);
    return;
  }
  wtcrypto_failures++;
  printf("FAIL %s\n     want ", name);
  for (size_t i = 0; i < len; i++) printf("%02x", want[i]);
  printf("\n     got  ");
  for (size_t i = 0; i < len; i++) printf("%02x", got[i]);
  printf("\n");
}

/* The tests that live outside the driver, declared in the order `main` calls
 * them. The primitives module owns the first, second, fifth, sixth and seventh;
 * the packet module owns the third and fourth. */
void wtcrypto_test_sha256(void);
void wtcrypto_test_hkdf(void);
void wtcrypto_test_chacha20(void);
void wtcrypto_test_initial_packet(void);
void wtcrypto_test_gcm_round_trip(void);
void wtcrypto_test_x25519(void);
void wtcrypto_test_helpers(void);

#endif
