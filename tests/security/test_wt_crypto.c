/* wt_crypto.h checked against published RFC vectors.
 *
 * Every value here is printed in an RFC. The point is not that the code runs;
 * it is that the layer is bound to BearSSL in exactly the shape TLS 1.3 and
 * QUIC require, and that the shapes where a wrong binding still produces
 * well-formed output are pinned to a published answer.
 *
 * Sources:
 *   RFC 5869 appendix A       HKDF-SHA256 test cases 1 and 3
 *   RFC 8439 section 2.4.2    ChaCha20 block function
 *   RFC 9001 appendix A.1-A.5 QUIC Initial secrets, AES-128-GCM, header
 *                             protection, ChaCha20 header protection, Retry tag
 *
 * The long RFC 9001 blocks come from wt_rfc9001_vectors.h, which is generated
 * from the RFC text rather than typed -- see generate_wt_rfc9001_vectors.py.
 *
 * This file is the driver and entry point. The tests themselves were split
 * across two translation units for the file-size budget:
 * test_wt_crypto_primitives.c owns the SHA-256, HKDF, AES-GCM round-trip,
 * x25519 and helper checks; test_wt_crypto_packet.c owns the ChaCha20
 * header-protection check and the whole RFC 9001 Initial packet, header
 * protection and Retry integrity tag check. `main` calls their entry points in
 * the order the one-file suite did and prints the same summary, so every
 * assertion and every byte of output is unchanged. The runner must compile all
 * three translation units -- see the `crypto` case in
 * tests/security/run-wt-host-tests.sh.
 */

#include "test_wt_crypto_support.h"

int main(void) {
  wtcrypto_test_sha256();
  wtcrypto_test_hkdf();
  wtcrypto_test_chacha20();
  wtcrypto_test_initial_packet();
  wtcrypto_test_gcm_round_trip();
  wtcrypto_test_x25519();
  wtcrypto_test_helpers();

  if (wtcrypto_failures != 0) {
    printf("wt_crypto: %d of %d checks FAILED\n", wtcrypto_failures,
           wtcrypto_checks);
    return 1;
  }
  printf("wt_crypto: all %d checks reproduced their RFC vector\n",
         wtcrypto_checks);
  return 0;
}
