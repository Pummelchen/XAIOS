#ifndef XAIOS_TESTS_SECURITY_TEST_WT_QUIC_PKT_SUPPORT_H
#define XAIOS_TESTS_SECURITY_TEST_WT_QUIC_PKT_SUPPORT_H

/* Assertion helpers and counters shared by the split WebTransport QUIC
 * packet-protection test.
 *
 * `test_wt_quic_pkt.c` was one 604-line file. It is now the driver and entry
 * point plus two modules: `test_wt_quic_pkt_number.c` holds the RFC 9000
 * packet-number encoding and decoding checks and the RFC 9001 A.5 nonce check;
 * `test_wt_quic_pkt_protect.c` holds the header-protection, whole-packet and
 * ChaCha20 header-protection checks. Everything that crosses a translation
 * unit is declared here and defined exactly once.
 *
 * The two helpers are `static inline` because both modules include this header
 * and use them: an external definition would be emitted twice, and a plain
 * `static` one would be flagged as unused -- with the runner's -Werror -- in
 * whichever module did not happen to call it. The two counters they increment
 * are `extern` here because `main` reads them for the exit status and the
 * summary line, and they are defined once, in `test_wt_quic_pkt_number.c`.
 *
 * Every symbol that leaves its own translation unit carries the `wtqpkt_`
 * prefix. The host runner links the modules of a split WebTransport test
 * together with the ones it already shares, so an unprefixed `expect_int`
 * would collide with a sibling suite's own helper.
 *
 * Nothing here is for anyone outside this test.
 */

#include "wt_quic_pkt.h"
#include "wt_rfc9001_vectors.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* The two counters, owned by the packet-number module. A test increments them
 * through the helpers below; the driver's `main` reads them to decide the exit
 * status and to print the total. */
extern int wtqpkt_failures;
extern int wtqpkt_checks;

static inline void wtqpkt_expect_bytes(const char *name, const uint8_t *want,
                                       const uint8_t *got, size_t len) {
  wtqpkt_checks++;
  if (memcmp(want, got, len) == 0) return;
  wtqpkt_failures++;
  printf("FAIL %s\n     want ", name);
  for (size_t i = 0; i < len; i++) printf("%02x", want[i]);
  printf("\n     got  ");
  for (size_t i = 0; i < len; i++) printf("%02x", got[i]);
  printf("\n");
}

static inline void wtqpkt_expect_int(const char *name, long want, long got) {
  wtqpkt_checks++;
  if (want == got) return;
  wtqpkt_failures++;
  printf("FAIL %s: want %ld, got %ld\n", name, want, got);
}

/* The tests that live outside the driver, declared in the order `main` calls
 * them. The packet-number module owns the first three; the protect module owns
 * the last five. */
void wtqpkt_test_packet_number_encoding(void);
void wtqpkt_test_packet_number_decoding(void);
void wtqpkt_test_nonce(void);
void wtqpkt_test_header_protection_client_initial(void);
void wtqpkt_test_client_initial_end_to_end(void);
void wtqpkt_test_server_initial_end_to_end(void);
void wtqpkt_test_chacha20_header_protection(void);
void wtqpkt_test_header_protection_argument_checks(void);

#endif
