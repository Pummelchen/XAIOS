/* X25519 (RFC 7748), the key exchange TLS 1.3 uses by default.
 *
 * Split out of `wt_crypto_bearssl.c` when the vendored WebTransport library
 * needed the same ladder (B-131): there is one BearSSL byte-order rule to get
 * right here, and two copies of it would be one copy and one future bug. The
 * rule and how it was found are in the comment below, which moved with the
 * code.
 *
 * This file is compiled into both the in-tree module and the upstream port's
 * backend.
 */

#include "wt_crypto.h"

#include "inner.h"

#include <string.h>



/* BearSSL's Curve25519 is an `br_ec_impl` rather than a named primitive, and it
 * does NOT use RFC 7748's byte order.
 *
 * RFC 7748 encodes both the scalar and the u-coordinate as LITTLE-endian, and
 * clamps the scalar by clearing the low three bits of the FIRST byte and
 * setting the second-highest bit of the LAST. BearSSL's implementations do the
 * opposite: `ec_c25519_m15.c` clears `k[31]` and sets bit 6 of `k[0]`, and
 * byteswaps the point before the ladder. That is the same mathematics over
 * byte-reversed operands, and it means a caller that passes RFC 7748's bytes
 * straight through gets a wrong answer that is indistinguishable from a wrong
 * key.
 *
 * This was found by the test, not by reading: BearSSL's output agreed with
 * itself, with a second BearSSL implementation (`i15` and `m15` produce
 * identical results), and with a Montgomery ladder written independently here
 * from the RFC's pseudocode -- and all three disagreed with RFC 7748's own
 * published vectors. Reversing the scalar alone reproduced Alice's public key
 * exactly.
 *
 * The rule, established by experiment rather than by reading, is ASYMMETRIC:
 * the SCALAR is big-endian and the u-COORDINATE and the RESULT are
 * little-endian. So this reverses the scalar on the way in and leaves the
 * point and the result alone. Reversing the point as well, which is the
 * symmetric guess, produces a different wrong answer.
 *
 * Reversing the scalar is not merely a convention: it is what makes the clamp
 * operate on the bits the RFC intends to clamp. Passing RFC 7748's scalar
 * straight through clears the wrong three bits and sets the wrong one, so the
 * ladder runs on a scalar the RFC never specified.
 *
 * WHICH IMPLEMENTATION. `br_ec_c25519_m15` needs a 64x64->128 multiply, which
 * clang provides as `unsigned __int128` on aarch64, x86_64 and riscv64. The
 * `i15` variant needs none and is the fallback if that ever stops being true;
 * both are verified to produce the RFC's vectors, so switching is a one-line
 * change with a test that will say whether it worked.
 */

static void reverse32(uint8_t out[32], const uint8_t in[32]) {
  size_t i;
  for (i = 0U; i < 32U; i++) out[i] = in[31U - i];
}

int wt_x25519_public_key_is_valid(const uint8_t peer_public[32]) {
  uint8_t accumulated = 0U;
  size_t i;
  if (peer_public == NULL) return 0;
  /* All zeros is the low-order point's result and the only key that produces a
     secret independent of the private key. */
  for (i = 0U; i < 32U; i++) accumulated |= peer_public[i];
  return accumulated != 0U;
}

int wt_x25519_public_key(const uint8_t private_key[32], uint8_t out[32]) {
  const br_ec_impl *ec = &br_ec_c25519_m15;
  uint8_t scalar[32];
  uint8_t result[32];
  size_t produced;

  if (private_key == NULL || out == NULL) return -1;

  reverse32(scalar, private_key);
  produced = ec->mulgen(result, scalar, 32U, BR_EC_curve25519);
  wt_secure_zero(scalar, sizeof(scalar));
  if (produced != 32U) {
    wt_secure_zero(out, 32U);
    return -1;
  }
  /* The result is little-endian as the RFC has it, so it is copied and not
     reversed. Reversing it as well was the symmetric guess and it produced a
     public key that is its own mirror image. */
  memcpy(out, result, 32U);
  wt_secure_zero(result, sizeof(result));
  return 0;
}

int wt_x25519_shared_secret(const uint8_t private_key[32],
                            const uint8_t peer_public[32], uint8_t out[32]) {
  const br_ec_impl *ec = &br_ec_c25519_m15;
  uint8_t scalar[32];
  uint8_t point[32];
  size_t produced;
  int valid;

  if (private_key == NULL || peer_public == NULL || out == NULL) return -1;
  if (!wt_x25519_public_key_is_valid(peer_public)) {
    memset(out, 0, 32U);
    return -1;
  }

  reverse32(scalar, private_key);
  /* The point is little-endian, as the RFC has it, and is copied rather than
     modified: it is the caller's buffer and, in a handshake, the message the
     transcript hashes. */
  memcpy(point, peer_public, 32U);
  /* `mul` modifies its point in place and returns 0 on refusal and a non-zero
     success flag otherwise -- NOT a byte count, although `mulgen` returns the
     generator's length (32) from the same vtable. Comparing its result to 32
     is what made this refuse every shared secret, and the value it returns
     happens to be 1, so the comparison failed all the time rather than
     sometimes. The point buffer is the result, and the all-zero test below is
     the real check. */
  produced = ec->mul(point, 32U, scalar, 32U, BR_EC_curve25519);
  wt_secure_zero(scalar, sizeof(scalar));
  if (produced == 0U) {
    wt_secure_zero(point, sizeof(point));
    wt_secure_zero(out, 32U);
    return -1;
  }
  memcpy(out, point, 32U);
  wt_secure_zero(point, sizeof(point));

  /* The ladder refuses a low-order point by producing all zeros. Check it,
     because the value is not distinguishable from a legitimate secret by
     inspection and a peer that can choose it can force a known one. */
  valid = 0;
  for (size_t i = 0U; i < 32U; i++) valid |= out[i];
  if (valid == 0) {
    wt_secure_zero(out, 32U);
    return -1;
  }
  return 0;
}
