/* wt_crypto.h implemented over BearSSL.
 *
 * Everything here is a binding, not a construction: BearSSL supplies SHA-256,
 * HMAC, AES and GHASH, and this file supplies the shapes TLS 1.3 and QUIC ask
 * for. The two places where a binding could quietly be wrong are called out
 * below and are covered by RFC vectors in tests/security/test_wt_crypto.c.
 *
 * Build note: BearSSL compiles as a single translation unit with `inner.h`,
 * exactly as scripts/build-bearssl.sh does it, so this file is compiled the
 * same way for the host test and for the target.
 */

#include "wt_crypto.h"

#include "inner.h"

#include <string.h>

/* ------------------------------------------------------------------ SHA-256 */

/* The concrete context, over the caller's opaque storage. `br_sha256_context`
   is a fixed-size structure (a vtable pointer, a 64-byte block buffer, a
   64-bit count and eight 32-bit state words). The assertion ties the public
   reservation to it, so a BearSSL upgrade that grows the context fails this
   build rather than overflowing a caller's struct at run time.

   The cast is alignment-safe for the same reason: br_sha256_context is an
   ordinary struct of uint32_t and uint64_t members, and the storage it is
   overlaid on is a byte array inside a caller's object, which has at least
   the alignment of any member it could hold. */
typedef char wt_sha256_ctx_fits[sizeof(br_sha256_context) <=
                                     WT_SHA256_CTX_MAX ? 1 : -1];

static br_sha256_context *inner_of(wt_sha256_ctx_t *ctx) {
  return (br_sha256_context *)(void *)ctx->storage;
}

size_t wt_sha256_size(void) { return sizeof(br_sha256_context); }

int wt_sha256_init(wt_sha256_ctx_t *ctx) {
  if (ctx == NULL) return -1;
  br_sha256_init(inner_of(ctx));
  return 0;
}

int wt_sha256_update(wt_sha256_ctx_t *ctx, const void *data, size_t len) {
  if (ctx == NULL) return -1;
  if (data == NULL && len != 0U) return -1;
  br_sha256_update(inner_of(ctx), data, len);
  return 0;
}

int wt_sha256_final(wt_sha256_ctx_t *ctx, uint8_t out[WT_SHA256_LEN]) {
  if (ctx == NULL || out == NULL) return -1;
  br_sha256_out(inner_of(ctx), out);
  return 0;
}

int wt_sha256(const void *data, size_t len, uint8_t out[WT_SHA256_LEN]) {
  wt_sha256_ctx_t ctx;
  if ((data == NULL && len != 0U) || out == NULL) return -1;
  br_sha256_init(inner_of(&ctx));
  br_sha256_update(inner_of(&ctx), data, len);
  br_sha256_out(inner_of(&ctx), out);
  wt_secure_zero(&ctx, sizeof(ctx));
  return 0;
}

/* ---------------------------------------------------------------- HMAC-SHA256 */

int wt_hmac_sha256(const uint8_t *key, size_t key_len,
                   const uint8_t *data, size_t data_len,
                   uint8_t out[WT_SHA256_LEN]) {
  br_hmac_key_context key_ctx;
  br_hmac_context ctx;
  if (out == NULL) return -1;
  if (key == NULL && key_len != 0U) return -1;
  if (data == NULL && data_len != 0U) return -1;
  /* A NULL or empty key is legal for HMAC: it is padded with zeros to the
     block size. BearSSL takes the pointer and the length as given, so a
     zero-length key is passed through rather than special-cased. */
  br_hmac_key_init(&key_ctx, &br_sha256_vtable, key, key_len);
  br_hmac_init(&ctx, &key_ctx, 0);
  br_hmac_update(&ctx, data, data_len);
  br_hmac_out(&ctx, out);
  return 0;
}

/* --------------------------------------------------------------------- HKDF */

int wt_hkdf_extract_sha256(const uint8_t *salt, size_t salt_len,
                           const uint8_t *ikm, size_t ikm_len,
                           uint8_t out[WT_SHA256_LEN]) {
  /* HKDF-Extract(salt, IKM) is HMAC(key = salt, data = IKM). A NULL salt with
     length 0 means an all-zero salt of HashLen bytes (RFC 5869 section 2.2),
     which is HMAC with a 32-byte zero key -- not HMAC with an empty key, which
     pads differently and gives a different PRK. Doing it here rather than
     making every caller remember is the point. */
  static const uint8_t zero_salt[WT_SHA256_LEN] = {0};
  if (out == NULL) return -1;
  if (salt == NULL && salt_len != 0U) return -1;
  if (ikm == NULL && ikm_len != 0U) return -1;
  if (salt == NULL) {
    salt = zero_salt;
    salt_len = sizeof(zero_salt);
  }
  return wt_hmac_sha256(salt, salt_len, ikm, ikm_len, out);
}

int wt_hkdf_expand_sha256(const uint8_t *prk, size_t prk_len,
                          const uint8_t *info, size_t info_len,
                          uint8_t *out, size_t out_len) {
  /* HKDF-Expand: T(1) = HMAC(PRK, info || 0x01), T(n) = HMAC(PRK, T(n-1) ||
     info || n), output = T(1) || T(2) || ... truncated to out_len. The counter
     is one byte and starts at 1, so the bound is 255*HashLen; the check is an
     error rather than a wrap, because a wrapped counter returns bytes that are
     not the RFC's (WT-30 in the WebTransport tracker was exactly this in the
     Swift implementation). */
  uint8_t block[WT_SHA256_LEN];
  uint8_t previous[WT_SHA256_LEN];
  size_t previous_len = 0U;
  size_t written = 0U;
  uint32_t counter = 1U;

  if (prk == NULL || (info == NULL && info_len != 0U) || out == NULL) {
    return -1;
  }
  if (out_len > 255U * WT_SHA256_LEN) return -1;

  while (written < out_len) {
    br_hmac_key_context key_ctx;
    br_hmac_context ctx;
    br_hmac_key_init(&key_ctx, &br_sha256_vtable, prk, prk_len);
    br_hmac_init(&ctx, &key_ctx, 0);
    if (previous_len != 0U) br_hmac_update(&ctx, previous, previous_len);
    if (info_len != 0U) br_hmac_update(&ctx, info, info_len);
    {
      uint8_t counter_byte = (uint8_t)counter;
      br_hmac_update(&ctx, &counter_byte, 1U);
    }
    br_hmac_out(&ctx, block);

    {
      size_t take = out_len - written;
      if (take > WT_SHA256_LEN) take = WT_SHA256_LEN;
      memcpy(out + written, block, take);
      written += take;
    }
    memcpy(previous, block, WT_SHA256_LEN);
    previous_len = WT_SHA256_LEN;
    counter++;
  }
  wt_secure_zero(block, sizeof(block));
  wt_secure_zero(previous, sizeof(previous));
  return 0;
}

/* ------------------------------------------------------------------- AES-GCM */

/* AES-128 block encryption lives in wt_aes128.c: BearSSL has no ECB entry
   point and reaching its bitslice block function means private API. */

/* The AES-128-GCM core, shared by both directions.
 *
 * On the decrypting side the tag is written to `tag` rather than compared: see
 * the note in wt_crypto.h for why that is the shape, and in particular why
 * "check the tag, then decrypt" cannot work with this backend -- the tag is
 * not known until the ciphertext has been run. */
static int gcm_run(int decrypt, const uint8_t key[16], const uint8_t iv[12],
                   const uint8_t *aad, size_t aad_len,
                   const uint8_t *in, size_t len,
                   uint8_t *out, uint8_t tag[16]) {
  br_aes_ct64_ctr_keys keys;
  br_gcm_context ctx;

  if (key == NULL || iv == NULL || in == NULL || out == NULL || tag == NULL) {
    return -1;
  }
  if (aad == NULL && aad_len != 0U) return -1;

  br_aes_ct64_ctr_init(&keys, key, 16U);
  /* BearSSL's GCM keeps the block-cipher context, not its vtable, and asks for
     it as a `const br_block_ctr_class **` because the context's first field is
     that pointer. */
  br_gcm_init(&ctx, &keys.vtable, br_ghash_ctmul64);
  br_gcm_reset(&ctx, iv, 12U);
  if (aad_len != 0U) br_gcm_aad_inject(&ctx, aad, aad_len);
  br_gcm_flip(&ctx);

  /* The caller's buffers must not overlap: this copies the input into the
     output and then works in place, so an overlapping call would feed the
     cipher its own output from the second block onward. That is documented in
     the header and is why the QUIC layer keeps its plaintext in a separate
     buffer. */
  memcpy(out, in, len);
  br_gcm_run(&ctx, decrypt ? 0 : 1, out, len);
  br_gcm_get_tag(&ctx, tag);

  wt_secure_zero(&ctx, sizeof(ctx));
  wt_secure_zero(&keys, sizeof(keys));
  return 0;
}

int wt_aes128_gcm_encrypt(const uint8_t key[16], const uint8_t iv[12],
                          const uint8_t *aad, size_t aad_len,
                          const uint8_t *plain, size_t len,
                          uint8_t *out, uint8_t tag[16]) {
  return gcm_run(0, key, iv, aad, aad_len, plain, len, out, tag);
}

int wt_aes128_gcm_decrypt(const uint8_t key[16], const uint8_t iv[12],
                          const uint8_t *aad, size_t aad_len,
                          const uint8_t *cipher, size_t len,
                          uint8_t *out, uint8_t computed_tag[16]) {
  return gcm_run(1, key, iv, aad, aad_len, cipher, len, out, computed_tag);
}

/* ---------------------------------------------------------------- ChaCha20 */

/* RFC 8439 section 2.3. Written out rather than bound, because BearSSL's
   ChaCha20 (`br_chacha20_ct_run`) exists but its counter and nonce layout is
   not the one QUIC's header protection uses, and the difference is silent.
   The block function here is checked against RFC 8439's own test vector. */
static uint32_t rotl32(uint32_t x, int n) {
  return (x << n) | (x >> (32 - n));
}

#define QR(a, b, c, d)                     \
  do {                                     \
    a += b; d ^= a; d = rotl32(d, 16);     \
    c += d; b ^= c; b = rotl32(b, 12);     \
    a += b; d ^= a; d = rotl32(d, 8);      \
    c += d; b ^= c; b = rotl32(b, 7);      \
  } while (0)

static void chacha20_block(const uint8_t key[32], uint32_t counter,
                           const uint8_t nonce[12], uint8_t out[64]) {
  static const char sigma[17] = "expand 32-byte k";
  uint32_t state[16];
  uint32_t working[16];
  size_t i;
  int round;

  for (i = 0U; i < 4U; i++) {
    state[i] = ((uint32_t)(uint8_t)sigma[i * 4] << 0)
             | ((uint32_t)(uint8_t)sigma[i * 4 + 1] << 8)
             | ((uint32_t)(uint8_t)sigma[i * 4 + 2] << 16)
             | ((uint32_t)(uint8_t)sigma[i * 4 + 3] << 24);
  }
  for (i = 0U; i < 8U; i++) {
    state[4U + i] = ((uint32_t)key[i * 4U] << 0)
                  | ((uint32_t)key[i * 4U + 1] << 8)
                  | ((uint32_t)key[i * 4U + 2] << 16)
                  | ((uint32_t)key[i * 4U + 3] << 24);
  }
  state[12] = counter;
  for (i = 0U; i < 3U; i++) {
    state[13U + i] = ((uint32_t)nonce[i * 4U] << 0)
                   | ((uint32_t)nonce[i * 4U + 1] << 8)
                   | ((uint32_t)nonce[i * 4U + 2] << 16)
                   | ((uint32_t)nonce[i * 4U + 3] << 24);
  }
  memcpy(working, state, sizeof(state));
  for (round = 0; round < 10; round++) {
    QR(working[0], working[4], working[8], working[12]);
    QR(working[1], working[5], working[9], working[13]);
    QR(working[2], working[6], working[10], working[14]);
    QR(working[3], working[7], working[11], working[15]);
    QR(working[0], working[5], working[10], working[15]);
    QR(working[1], working[6], working[11], working[12]);
    QR(working[2], working[7], working[8], working[13]);
    QR(working[3], working[4], working[9], working[14]);
  }
  for (i = 0U; i < 16U; i++) {
    uint32_t word = working[i] + state[i];
    out[i * 4U] = (uint8_t)(word & 0xFFU);
    out[i * 4U + 1] = (uint8_t)((word >> 8) & 0xFFU);
    out[i * 4U + 2] = (uint8_t)((word >> 16) & 0xFFU);
    out[i * 4U + 3] = (uint8_t)((word >> 24) & 0xFFU);
  }
  wt_secure_zero(state, sizeof(state));
  wt_secure_zero(working, sizeof(working));
}

int wt_chacha20_xor(const uint8_t key[32], const uint8_t nonce[12],
                    uint32_t counter, const uint8_t *in, size_t len,
                    uint8_t *out) {
  uint8_t keystream[64];
  size_t done = 0U;

  if (key == NULL || nonce == NULL || (in == NULL && len != 0U) ||
      out == NULL) {
    return -1;
  }
  while (done < len) {
    size_t take = len - done;
    size_t i;
    if (take > sizeof(keystream)) take = sizeof(keystream);
    chacha20_block(key, counter, nonce, keystream);
    for (i = 0U; i < take; i++) out[done + i] = (uint8_t)(in[done + i] ^ keystream[i]);
    done += take;
    counter++;
  }
  wt_secure_zero(keystream, sizeof(keystream));
  return 0;
}

/* ------------------------------------------------------------------ helpers */

int wt_ct_equal(const uint8_t *a, const uint8_t *b, size_t len) {
  uint8_t difference = 0U;
  size_t i;
  if (a == NULL || b == NULL) return 0;
  for (i = 0U; i < len; i++) difference |= (uint8_t)(a[i] ^ b[i]);
  /* Collapse to 0 or 1 without branching on the value. */
  return (int)((((uint32_t)difference - 1U) >> 8) & 1U);
}

void wt_secure_zero(void *buffer, size_t len) {
  /* A plain memset over a dead local is removable, so the write goes through
     a volatile pointer. */
  volatile uint8_t *p = (volatile uint8_t *)buffer;
  if (buffer == NULL) return;
  while (len-- != 0U) *p++ = 0U;
}

/* ----------------------------------------------------------------- x25519 */

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
