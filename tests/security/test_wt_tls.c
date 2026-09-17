/* TLS 1.3 key schedule and QUIC key derivation, checked against RFC 8448 and
 * RFC 9001.
 *
 * The schedule is the part of TLS 1.3 that can be verified without a peer:
 * every intermediate value is published, so a wrong label, a wrong length
 * prefix, a wrong order in the Derive-Secret chain or a wrong notion of "empty
 * transcript" shows up as a mismatch rather than as a connection that fails
 * later for an unexplained reason.
 *
 * The vectors come from wt_rfc8448_vectors.h, generated from the RFC text by
 * generate_wt_rfc8448_vectors.py, and the same values are recomputed
 * independently in Python by verify_wt_rfc8448_key_schedule.py.
 *
 * This file is the driver and entry point. The tests themselves were split
 * across two translation units for the file-size budget:
 * test_wt_tls_schedule.c owns the TLS 1.3 schedule and
 * test_wt_tls_quic_keys.c owns the QUIC key derivation. `main` calls their
 * entry points in the order the one-file suite did and prints the same
 * summary, so every assertion and every byte of output is unchanged.
 */

#include "test_wt_tls_support.h"

int main(void) {
  wttls_test_empty_hash();
  wttls_test_expand_label();
  wttls_test_key_schedule();
  wttls_test_key_schedule_phases();
  wttls_test_traffic_keys();
  wttls_test_initial_keys();
  wttls_test_retry_tag();

  if (wttls_failures != 0) {
    printf("wt_tls: %d of %d checks FAILED\n", wttls_failures, wttls_checks);
    return 1;
  }
  printf("wt_tls: all %d checks reproduced their RFC 8448 / 9001 vector\n",
         wttls_checks);
  return 0;
}
