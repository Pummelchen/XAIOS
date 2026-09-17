/* QUIC packet protection checked against RFC 9001 appendix A.
 *
 * The vectors are complete input/output pairs: a client Initial, a server
 * Initial, a ChaCha20-Poly1305 short header packet and a Retry, each with the
 * header protection sample and mask the RFC prints. Reproducing them exercises
 * the packet number encoding, the nonce construction, the associated-data
 * definition, the sample offset and the mask application together -- which is
 * the only way to test them, because each is individually plausible when
 * wrong.
 *
 * This file is the driver and entry point. The tests themselves were split
 * across two translation units for the file-size budget:
 * test_wt_quic_pkt_number.c owns the packet-number encoding and decoding checks
 * and the A.5 nonce check; test_wt_quic_pkt_protect.c owns the header
 * protection, whole-packet and ChaCha20 header-protection checks. `main` calls
 * their entry points in the order the one-file suite did and prints the same
 * summary, so every assertion and every byte of output is unchanged. The runner
 * must compile all three translation units -- see the `quic_pkt` case in
 * tests/security/run-wt-host-tests.sh.
 */

#include "test_wt_quic_pkt_support.h"

int main(void) {
  wtqpkt_test_packet_number_encoding();
  wtqpkt_test_packet_number_decoding();
  wtqpkt_test_nonce();
  wtqpkt_test_header_protection_client_initial();
  wtqpkt_test_client_initial_end_to_end();
  wtqpkt_test_server_initial_end_to_end();
  wtqpkt_test_chacha20_header_protection();
  wtqpkt_test_header_protection_argument_checks();

  if (wtqpkt_failures != 0) {
    printf("wt_quic_pkt: %d of %d checks FAILED\n", wtqpkt_failures,
           wtqpkt_checks);
    return 1;
  }
  printf("wt_quic_pkt: all %d checks reproduced their RFC 9001 / 9000 vector\n",
         wtqpkt_checks);
  return 0;
}
