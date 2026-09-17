/* Fixtures and assertion helpers shared by the split TLS key-schedule test.
 *
 * `test_wt_tls.c` was one 749-line file. It is now the driver and entry point
 * plus two modules: `test_wt_tls_schedule.c` holds the empty-transcript check,
 * HKDF-Expand-Label, the whole TLS 1.3 key schedule and its two-phase form;
 * `test_wt_tls_quic_keys.c` holds the QUIC traffic keys, the Initial keys and
 * the Retry integrity tag. Everything that crosses a translation unit is
 * declared here and defined exactly once.
 *
 * The three check helpers are `static inline` because both modules include
 * this header and use them: an external definition would be emitted twice.
 * The two counters they increment are `extern` here because `main` reads them
 * for the exit status and the summary line, and they are defined once, in
 * `test_wt_tls_schedule.c`.
 *
 * Every symbol that leaves its own translation unit carries the `wttls_`
 * prefix. The host runner links the modules of a split WebTransport test
 * together with the ones it already shares, so an unprefixed `expect_int`
 * would collide with a sibling suite's own helper.
 *
 * Nothing here is for anyone outside this test.
 */

#ifndef XAIOS_TESTS_SECURITY_TEST_WT_TLS_SUPPORT_H
#define XAIOS_TESTS_SECURITY_TEST_WT_TLS_SUPPORT_H

#include "wt_tls.h"
#include "wt_rfc8448_vectors.h"
#include "wt_rfc9001_vectors.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* The two counters, owned by the schedule module. A test increments them
 * directly or through the helpers below; the driver's `main` reads them to
 * decide the exit status and to print the total. */
extern int wttls_failures;
extern int wttls_checks;

static inline void wttls_expect_hex(const char *name, const char *want_hex,
                                    const uint8_t *got, size_t len) {
  uint8_t want[128];
  size_t n = 0;
  int high = -1;
  if (len > sizeof(want)) {
    wttls_checks++; wttls_failures++;
    printf("FAIL %s: oversized comparison\n", name);
    return;
  }
  for (const char *p = want_hex; *p != '\0'; p++) {
    int value;
    if (*p == ' ') continue;
    value = (*p >= '0' && *p <= '9') ? *p - '0'
          : (*p >= 'a' && *p <= 'f') ? *p - 'a' + 10
          : (*p >= 'A' && *p <= 'F') ? *p - 'A' + 10 : -1;
    if (value < 0) { wttls_checks++; wttls_failures++; printf("FAIL %s: bad hex\n", name); return; }
    if (high < 0) high = value;
    else { want[n++] = (uint8_t)((high << 4) | value); high = -1; }
  }
  wttls_checks++;
  if (n == len && memcmp(want, got, len) == 0) return;
  wttls_failures++;
  printf("FAIL %s\n     want ", name);
  for (size_t i = 0; i < n; i++) printf("%02x", want[i]);
  printf("\n     got  ");
  for (size_t i = 0; i < len; i++) printf("%02x", got[i]);
  printf("\n");
}

static inline void wttls_expect_bytes(const char *name, const uint8_t *want,
                                      const uint8_t *got, size_t len) {
  wttls_checks++;
  if (memcmp(want, got, len) == 0) return;
  wttls_failures++;
  printf("FAIL %s\n     want ", name);
  for (size_t i = 0; i < len; i++) printf("%02x", want[i]);
  printf("\n     got  ");
  for (size_t i = 0; i < len; i++) printf("%02x", got[i]);
  printf("\n");
}

static inline void wttls_expect_int(const char *name, long want, long got) {
  wttls_checks++;
  if (want == got) return;
  wttls_failures++;
  printf("FAIL %s: want %ld, got %ld\n", name, want, got);
}

/* The tests that live outside the driver, declared in the order `main` calls
 * them. The schedule module owns the first four, the QUIC key module the last
 * three. */
void wttls_test_empty_hash(void);
void wttls_test_expand_label(void);
void wttls_test_key_schedule(void);
void wttls_test_key_schedule_phases(void);
void wttls_test_traffic_keys(void);
void wttls_test_initial_keys(void);
void wttls_test_retry_tag(void);

#endif /* XAIOS_TESTS_SECURITY_TEST_WT_TLS_SUPPORT_H */
