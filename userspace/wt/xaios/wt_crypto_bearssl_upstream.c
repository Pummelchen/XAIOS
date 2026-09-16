/*
 * `webtransport/crypto/crypto.h` over BearSSL (B-131).
 *
 * This is the backend the vendored library's own header names as what a
 * freestanding XAIOS port needs. It replaces `src/crypto/crypto_openssl.c`,
 * which cannot compile here at all, and it borrows the shapes this repository
 * already worked out in `userspace/wt/src/wt_crypto_bearssl.c`: SHA-256 and
 * HMAC straight from BearSSL, HKDF built from HMAC, AES-128-GCM through
 * `br_gcm_*`, and ChaCha20 written out because BearSSL's counter/nonce layout
 * is not the one QUIC uses.
 *
 * Three differences from the in-tree backend are worth naming, because they
 * are where the upstream seam is not the same shape.
 *
 * `wt_sha256_snapshot` is new. The TLS 1.3 transcript hash is read at several
 * points without ending the transcript, and BearSSL's context is a plain
 * struct, so the snapshot is a copy of it that is then finalised -- the
 * original is untouched.
 *
 * `wt_aead_open` returns one status and no tag. The upstream header explains
 * why at length: a caller that has to compare the tag itself holds
 * unauthenticated plaintext between the decrypt and the compare. So this file
 * computes the tag, compares it in constant time, and clears the plaintext
 * when it differs -- which is the opposite of the in-tree shape, where the
 * caller compares.
 *
 * ChaCha20-Poly1305 is refused, not silently wrong. The library only reaches
 * it when a connection negotiates that suite, and the TLS key schedule this
 * port carries is AES-128-GCM's alone; the header is explicit that the AEAD is
 * optional for QUIC. `wt_aead_key_len` and friends still answer for it, so a
 * caller that asks the size of a suite it cannot use gets the right number
 * rather than a zero.
 *
 * AES-128 block encryption is not here: `userspace/wt/src/wt_aes128.c` already
 * implements exactly the symbol upstream declares, is checked against
 * FIPS-197's vectors, and is compiled beside this file.
 */

#include "webtransport/crypto/crypto.h"

#include "inner.h"

#include <string.h>

#include <xaios_user.h>

/* The public context is a uint64_t array large enough for any backend; this
   asserts that BearSSL's is actually one of them, so a BearSSL upgrade that
   grows it fails this build rather than a caller's frame. */
typedef char wt_sha256_ctx_fits[sizeof(br_sha256_context) <= WT_SHA256_CTX_MAX
                                    ? 1
                                    : -1];

/* `xaios_random` refuses more than 4096 bytes in one call; a longer request is
   chunked rather than refused, because the caller is a protocol that asked for
   unpredictability and not for a limit. */
#define WT_XAIOS_RANDOM_MAX 4096U

static br_sha256_context *inner_of(wt_sha256_ctx_t *ctx) {
  return (br_sha256_context *)(void *)ctx->storage;
}

static const br_sha256_context *inner_of_const(const wt_sha256_ctx_t *ctx) {
  return (const br_sha256_context *)(const void *)ctx->storage;
}

/* Whether a context is one `init` produced and `final` has not consumed.
   `final` zeroes the storage, and an all-zero `br_sha256_context` is not one
   any initialisation produces, so this is the whole test -- and it is what
   lets `final` and `snapshot` refuse a context the contract calls unusable
   rather than hashing a run of zeros into a plausible-looking digest. */
static int context_is_live(const wt_sha256_ctx_t *ctx) {
  const uint8_t *bytes = (const uint8_t *)(const void *)ctx->storage;
  uint8_t accumulated = 0U;
  size_t index;
  for (index = 0U; index < sizeof(ctx->storage); ++index) {
    accumulated |= bytes[index];
  }
  return accumulated != 0U;
}

/* --------------------------------------------------------------- SHA-256 */

wt_status_t wt_sha256_init(wt_sha256_ctx_t *ctx) {
  if (ctx == NULL) return WT_ERR_INVALID_ARGUMENT;
  br_sha256_init(inner_of(ctx));
  return WT_OK;
}

wt_status_t wt_sha256_update(wt_sha256_ctx_t *ctx, const void *data,
                             size_t len) {
  if (ctx == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (data == NULL && len != 0U) return WT_ERR_INVALID_ARGUMENT;
  br_sha256_update(inner_of(ctx), data, len);
  return WT_OK;
}

wt_status_t wt_sha256_final(wt_sha256_ctx_t *ctx,
                            uint8_t out[WT_SHA256_LEN]) {
  if (ctx == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (!context_is_live(ctx)) return WT_ERR_STATE;
  br_sha256_out(inner_of(ctx), out);
  /* The contract says final leaves the context unusable and zeroes its state,
     so a caller cannot mistake a finished transcript for a live one -- and a
     second final gets a status rather than a digest of zeros. */
  wt_secure_zero(ctx, sizeof(*ctx));
  return WT_OK;
}

wt_status_t wt_sha256(const void *data, size_t len,
                      uint8_t out[WT_SHA256_LEN]) {
  wt_sha256_ctx_t ctx;
  wt_status_t status;
  if ((data == NULL && len != 0U) || out == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  status = wt_sha256_init(&ctx);
  if (status != WT_OK) return status;
  status = wt_sha256_update(&ctx, data, len);
  if (status != WT_OK) return status;
  return wt_sha256_final(&ctx, out);
}

wt_status_t wt_sha256_snapshot(const wt_sha256_ctx_t *ctx,
                               uint8_t out[WT_SHA256_LEN]) {
  br_sha256_context copy;
  if (ctx == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* The header promises WT_ERR_STATE for a context that was never
     initialised or has already been finalised. */
  if (!context_is_live(ctx)) return WT_ERR_STATE;
  /* A copy, finalised, so the caller's transcript keeps absorbing. The
     alternative -- re-hashing every absorbed message -- would hold a
     peer-controlled amount of memory for the length of a handshake. */
  copy = *inner_of_const(ctx);
  br_sha256_out(&copy, out);
  wt_secure_zero(&copy, sizeof(copy));
  return WT_OK;
}

/* ---------------------------------------------------------- HMAC and HKDF */

wt_status_t wt_hmac_sha256(const uint8_t *key, size_t key_len,
                           const uint8_t *data, size_t data_len,
                           uint8_t out[WT_SHA256_LEN]) {
  static const uint8_t empty = 0U;
  br_hmac_key_context key_ctx;
  br_hmac_context ctx;
  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (key == NULL && key_len != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (data == NULL && data_len != 0U) return WT_ERR_INVALID_ARGUMENT;
  /* A NULL key is legal for HMAC and means a zero-length key, which is padded
     to the block size. BearSSL copies the bytes it is given, so a NULL pointer
     with a zero length would be a pointer it might still touch; the address of
     a byte it will never read is passed instead. */
  br_hmac_key_init(&key_ctx, &br_sha256_vtable, key != NULL ? key : &empty,
                   key_len);
  br_hmac_init(&ctx, &key_ctx, 0);
  br_hmac_update(&ctx, data, data_len);
  br_hmac_out(&ctx, out);
  wt_secure_zero(&key_ctx, sizeof(key_ctx));
  wt_secure_zero(&ctx, sizeof(ctx));
  return WT_OK;
}

wt_status_t wt_hkdf_extract_sha256(const uint8_t *salt, size_t salt_len,
                                   const uint8_t *ikm, size_t ikm_len,
                                   uint8_t out[WT_SHA256_LEN]) {
  static const uint8_t zero_salt[WT_SHA256_LEN] = {0};
  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (salt == NULL && salt_len != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (ikm == NULL && ikm_len != 0U) return WT_ERR_INVALID_ARGUMENT;
  /* A NULL salt is an all-zero salt of HashLen bytes (RFC 5869 section 2.2),
     NOT an empty key: the two pad differently and give different PRKs, and the
     TLS 1.3 schedule depends on the difference. */
  if (salt == NULL) {
    salt = zero_salt;
    salt_len = sizeof(zero_salt);
  }
  return wt_hmac_sha256(salt, salt_len, ikm, ikm_len, out);
}

wt_status_t wt_hkdf_expand_sha256(const uint8_t *prk, size_t prk_len,
                                  const uint8_t *info, size_t info_len,
                                  uint8_t *out, size_t out_len) {
  uint8_t block[WT_SHA256_LEN];
  uint8_t previous[WT_SHA256_LEN];
  size_t previous_len = 0U;
  size_t written = 0U;
  uint32_t counter = 1U;
  if (prk == NULL || (info == NULL && info_len != 0U) || out == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  /* The counter is one byte, so 255 blocks is the RFC's bound; a longer output
     would wrap it and return bytes that are not the RFC 5869 stream. */
  if (out_len > 255U * WT_SHA256_LEN) return WT_ERR_LIMIT;
  while (written < out_len) {
    br_hmac_key_context key_ctx;
    br_hmac_context ctx;
    uint8_t counter_byte = (uint8_t)counter;
    size_t take;
    br_hmac_key_init(&key_ctx, &br_sha256_vtable, prk, prk_len);
    br_hmac_init(&ctx, &key_ctx, 0);
    if (previous_len != 0U) br_hmac_update(&ctx, previous, previous_len);
    if (info_len != 0U) br_hmac_update(&ctx, info, info_len);
    br_hmac_update(&ctx, &counter_byte, 1U);
    br_hmac_out(&ctx, block);
    take = out_len - written;
    if (take > WT_SHA256_LEN) take = WT_SHA256_LEN;
    memcpy(out + written, block, take);
    written += take;
    memcpy(previous, block, WT_SHA256_LEN);
    previous_len = WT_SHA256_LEN;
    counter++;
    wt_secure_zero(&key_ctx, sizeof(key_ctx));
    wt_secure_zero(&ctx, sizeof(ctx));
  }
  wt_secure_zero(block, sizeof(block));
  wt_secure_zero(previous, sizeof(previous));
  return WT_OK;
}

wt_status_t wt_hkdf_expand_label_sha256(const uint8_t *secret,
                                        size_t secret_len, const char *label,
                                        const uint8_t *context,
                                        size_t context_len, uint8_t *out,
                                        size_t out_len) {
  /* HkdfLabel from RFC 8446 section 7.1:
       uint16 length; opaque label<7..255>; opaque context<0..255>;
     with the label carried as "tls13 " followed by the caller's name. Both
     prefixes are places where a wrong choice still produces well-formed
     bytes, so they are spelled out rather than assembled by feel. */
  static const char prefix[] = "tls13 ";
  uint8_t info[2U + 1U + (sizeof(prefix) - 1U) + 249U + 1U + 255U];
  size_t label_len;
  size_t qualified;
  size_t cursor = 0U;
  wt_status_t status;

  if (secret == NULL || label == NULL || out == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (context == NULL && context_len != 0U) return WT_ERR_INVALID_ARGUMENT;
  label_len = strlen(label);
  qualified = sizeof(prefix) - 1U + label_len;
  if (qualified > 255U || context_len > 255U || out_len > 0xffffU) {
    return WT_ERR_LIMIT;
  }
  info[cursor++] = (uint8_t)(out_len >> 8U);
  info[cursor++] = (uint8_t)(out_len & 0xffU);
  info[cursor++] = (uint8_t)qualified;
  memcpy(info + cursor, prefix, sizeof(prefix) - 1U);
  cursor += sizeof(prefix) - 1U;
  memcpy(info + cursor, label, label_len);
  cursor += label_len;
  info[cursor++] = (uint8_t)context_len;
  if (context_len != 0U) {
    memcpy(info + cursor, context, context_len);
    cursor += context_len;
  }
  status = wt_hkdf_expand_sha256(secret, secret_len, info, cursor, out,
                                 out_len);
  wt_secure_zero(info, sizeof(info));
  return status;
}

/* ------------------------------------------------------------------- AEAD */

const char *wt_aead_name(wt_aead_t aead) {
  switch (aead) {
    case WT_AEAD_AES_128_GCM:
      return "aes-128-gcm";
    case WT_AEAD_CHACHA20_POLY1305:
      return "chacha20-poly1305";
  }
  return "unknown";
}

size_t wt_aead_key_len(wt_aead_t aead) {
  return aead == WT_AEAD_CHACHA20_POLY1305 ? 32U : 16U;
}

size_t wt_aead_iv_len(wt_aead_t aead) {
  (void)aead;
  return WT_AEAD_IV_LEN;
}

size_t wt_aead_tag_len(wt_aead_t aead) {
  (void)aead;
  return WT_AEAD_TAG_LEN;
}

/* AES-128-GCM, shared by both directions. The tag is always produced; the
   sealing path writes it out, the opening path compares it. */
static wt_status_t gcm_run(int decrypt, const uint8_t key[16],
                           const uint8_t iv[12], const uint8_t *aad,
                           size_t aad_len, const uint8_t *in, size_t len,
                           uint8_t *out, uint8_t tag[WT_AEAD_TAG_LEN]) {
  br_aes_ct64_ctr_keys keys;
  br_gcm_context ctx;
  uint8_t unused = 0U;
  uint8_t *destination = len != 0U ? out : &unused;
  if (key == NULL || iv == NULL || tag == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  /* A zero-length message needs no output buffer: GCM over nothing is a tag
     over the AAD, and a caller that passes NULL for an empty plaintext is
     asking exactly that. */
  if (len != 0U && (out == NULL || in == NULL)) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (aad == NULL && aad_len != 0U) return WT_ERR_INVALID_ARGUMENT;
  br_aes_ct64_ctr_init(&keys, key, 16U);
  br_gcm_init(&ctx, &keys.vtable, br_ghash_ctmul64);
  br_gcm_reset(&ctx, iv, 12U);
  if (aad_len != 0U) br_gcm_aad_inject(&ctx, aad, aad_len);
  br_gcm_flip(&ctx);
  /* The caller's buffers are documented not to overlap: the input is copied
     into the output and then worked in place, so an overlapping call would
     feed the cipher its own output from the second block on. */
  if (len != 0U) memcpy(destination, in, len);
  br_gcm_run(&ctx, decrypt ? 0 : 1, destination, len);
  br_gcm_get_tag(&ctx, tag);
  wt_secure_zero(&ctx, sizeof(ctx));
  wt_secure_zero(&keys, sizeof(keys));
  return WT_OK;
}

wt_status_t wt_aead_seal(wt_aead_t aead, const uint8_t *key, const uint8_t *iv,
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *plain, size_t len, uint8_t *out,
                         uint8_t tag[WT_AEAD_TAG_LEN]) {
  if (aead != WT_AEAD_AES_128_GCM) return WT_ERR_UNSUPPORTED;
  return gcm_run(0, key, iv, aad, aad_len, plain, len, out, tag);
}

wt_status_t wt_aead_open(wt_aead_t aead, const uint8_t *key, const uint8_t *iv,
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *cipher, size_t len,
                         const uint8_t tag[WT_AEAD_TAG_LEN], uint8_t *out) {
  uint8_t computed[WT_AEAD_TAG_LEN];
  wt_status_t status;
  if (aead != WT_AEAD_AES_128_GCM) return WT_ERR_UNSUPPORTED;
  if (tag == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (len != 0U && out == NULL) return WT_ERR_INVALID_ARGUMENT;
  status = gcm_run(1, key, iv, aad, aad_len, cipher, len, out, computed);
  if (status != WT_OK) return status;
  if (wt_ct_equal(computed, tag, WT_AEAD_TAG_LEN) != 1) {
    /* The return value has to be the only usable output, which is why the
       plaintext is cleared before returning rather than left for a caller
       that might parse it. */
    if (len != 0U) wt_secure_zero(out, len);
    wt_secure_zero(computed, sizeof(computed));
    return WT_ERR_AUTHENTICATION;
  }
  wt_secure_zero(computed, sizeof(computed));
  return WT_OK;
}

/* ---------------------------------------------------------------- ChaCha20 */

/* RFC 8439 section 2.3, written out because BearSSL's ChaCha20 has a
   different counter/nonce layout and the difference is silent. Same
   implementation as the in-tree backend, checked against RFC 8439's vector
   there. */
static uint32_t rotl32(uint32_t value, int count) {
  return (value << count) | (value >> (32 - count));
}

#define WT_QR(a, b, c, d)                          \
  do {                                             \
    a += b; d ^= a; d = rotl32(d, 16);             \
    c += d; b ^= c; b = rotl32(b, 12);             \
    a += b; d ^= a; d = rotl32(d, 8);              \
    c += d; b ^= c; b = rotl32(b, 7);              \
  } while (0)

static void chacha20_block(const uint8_t key[32], uint32_t counter,
                           const uint8_t nonce[12], uint8_t out[64]) {
  static const char sigma[17] = "expand 32-byte k";
  uint32_t state[16];
  uint32_t working[16];
  size_t index;
  int round;
  for (index = 0U; index < 4U; index++) {
    state[index] = ((uint32_t)(uint8_t)sigma[index * 4U]) |
                   ((uint32_t)(uint8_t)sigma[index * 4U + 1U] << 8) |
                   ((uint32_t)(uint8_t)sigma[index * 4U + 2U] << 16) |
                   ((uint32_t)(uint8_t)sigma[index * 4U + 3U] << 24);
  }
  for (index = 0U; index < 8U; index++) {
    state[4U + index] = ((uint32_t)key[index * 4U]) |
                        ((uint32_t)key[index * 4U + 1U] << 8) |
                        ((uint32_t)key[index * 4U + 2U] << 16) |
                        ((uint32_t)key[index * 4U + 3U] << 24);
  }
  state[12] = counter;
  for (index = 0U; index < 3U; index++) {
    state[13U + index] = ((uint32_t)nonce[index * 4U]) |
                         ((uint32_t)nonce[index * 4U + 1U] << 8) |
                         ((uint32_t)nonce[index * 4U + 2U] << 16) |
                         ((uint32_t)nonce[index * 4U + 3U] << 24);
  }
  memcpy(working, state, sizeof(state));
  for (round = 0; round < 10; round++) {
    WT_QR(working[0], working[4], working[8], working[12]);
    WT_QR(working[1], working[5], working[9], working[13]);
    WT_QR(working[2], working[6], working[10], working[14]);
    WT_QR(working[3], working[7], working[11], working[15]);
    WT_QR(working[0], working[5], working[10], working[15]);
    WT_QR(working[1], working[6], working[11], working[12]);
    WT_QR(working[2], working[7], working[8], working[13]);
    WT_QR(working[3], working[4], working[9], working[14]);
  }
  for (index = 0U; index < 16U; index++) {
    uint32_t word = working[index] + state[index];
    out[index * 4U] = (uint8_t)(word & 0xffU);
    out[index * 4U + 1U] = (uint8_t)((word >> 8) & 0xffU);
    out[index * 4U + 2U] = (uint8_t)((word >> 16) & 0xffU);
    out[index * 4U + 3U] = (uint8_t)((word >> 24) & 0xffU);
  }
  wt_secure_zero(state, sizeof(state));
  wt_secure_zero(working, sizeof(working));
}

wt_status_t wt_chacha20_xor(const uint8_t key[32], const uint8_t nonce[12],
                            uint32_t counter, const uint8_t *in, size_t len,
                            uint8_t *out) {
  uint8_t keystream[64];
  size_t done = 0U;
  if (key == NULL || nonce == NULL || out == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (in == NULL && len != 0U) return WT_ERR_INVALID_ARGUMENT;
  while (done < len) {
    size_t take = len - done;
    size_t index;
    if (take > sizeof(keystream)) take = sizeof(keystream);
    chacha20_block(key, counter, nonce, keystream);
    for (index = 0U; index < take; index++) {
      out[done + index] = (uint8_t)(in[done + index] ^ keystream[index]);
    }
    done += take;
    counter++;
  }
  wt_secure_zero(keystream, sizeof(keystream));
  return WT_OK;
}

/* --------------------------------------------------------------- helpers */

int wt_ct_equal(const uint8_t *a, const uint8_t *b, size_t len) {
  uint8_t difference = 0U;
  size_t index;
  if (a == NULL || b == NULL) return 0;
  for (index = 0U; index < len; index++) {
    difference |= (uint8_t)(a[index] ^ b[index]);
  }
  /* Collapsed to 0 or 1 without branching on the value. */
  return (int)((((uint32_t)difference - 1U) >> 8) & 1U);
}

void wt_secure_zero(void *buffer, size_t len) {
  volatile uint8_t *bytes = (volatile uint8_t *)buffer;
  if (buffer == NULL) return;
  while (len-- != 0U) *bytes++ = 0U;
}

wt_status_t wt_random_bytes(uint8_t *out, size_t len) {
  size_t done = 0U;
  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  while (done < len) {
    size_t take = len - done;
    if (take > WT_XAIOS_RANDOM_MAX) take = WT_XAIOS_RANDOM_MAX;
    /* The kernel's RNG is the only source here, and its failure is not
       something a protocol can work around: a connection with predictable
       randomness is a connection an observer can follow. */
    if (xaios_random(out + done, (u64)take) != 0) return WT_ERR_UNSUPPORTED;
    done += take;
  }
  return WT_OK;
}

wt_status_t wt_crypto_init(void) {
  /* BearSSL needs no start-up: there is no provider to fetch and no global
     state to initialise. The call exists so a caller can ask, and the answer
     here is that the backend is always available. */
  return WT_OK;
}
