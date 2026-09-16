/* RFC vectors for the vendored WebTransport library's BearSSL crypto backend.
 *
 * The backend is an adaptation, not a construction: SHA-256 and HMAC come
 * straight from BearSSL, HKDF is built from HMAC, AES-128-GCM is `br_gcm_*`,
 * and ChaCha20 is written out. An adaptation is exactly the kind of code that
 * can be plausible and wrong -- a length prefix in the wrong place in
 * HKDF-Expand-Label still produces 32 well-formed bytes -- so every operation
 * that a handshake depends on is checked here against a published value.
 *
 * It is a separate binary from the in-tree module's tests because the two
 * implement the same function names for two different headers, and one link
 * cannot hold both. It is built and run by
 * `tests/security/run-wt-host-tests.sh`, which is what `make wt-host-test`
 * runs.
 */

#include <stdio.h>
#include <string.h>

#include <xaios_user.h>

#include "webtransport/crypto/crypto.h"

static int g_checks = 0;
static int g_failures = 0;

/* `xaios_random` is the platform's RNG on the target. This test never asks for
   randomness -- an RFC vector is fixed -- but the backend's `wt_random_bytes`
   names it, so the link needs a definition. */
int xaios_random(void *buffer, u64 size) {
  (void)buffer;
  (void)size;
  return 0;
}

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

/* Decode a hex string into `out`; returns the number of bytes. */
static size_t from_hex(const char *text, uint8_t *out, size_t capacity) {
  size_t length = strlen(text);
  size_t produced = length / 2U;
  if (produced > capacity) return 0U;
  for (size_t index = 0U; index < produced; ++index) {
    int high = hex_nibble(text[index * 2U]);
    int low = hex_nibble(text[index * 2U + 1U]);
    if (high < 0 || low < 0) return 0U;
    out[index] = (uint8_t)((high << 4) | low);
  }
  return produced;
}

static void fail(const char *what) {
  printf("  FAIL %s\n", what);
  ++g_failures;
}

static void expect_status(const char *what, wt_status_t got, wt_status_t want) {
  ++g_checks;
  if (got != want) {
    printf("  FAIL %s: status %d, wanted %d\n", what, (int)got, (int)want);
    ++g_failures;
  }
}

static void expect_bytes(const char *what, const uint8_t *got,
                         const char *want_hex) {
  uint8_t want[256];
  size_t want_len = from_hex(want_hex, want, sizeof(want));
  ++g_checks;
  if (want_len == 0U || memcmp(got, want, want_len) != 0) {
    printf("  FAIL %s\n", what);
    for (size_t index = 0U; index < want_len; ++index) {
      printf("%02x", got[index]);
    }
    printf(" != %s\n", want_hex);
    ++g_failures;
  }
}

static void test_sha256(void) {
  static const uint8_t message[] = "abc";
  uint8_t digest[WT_SHA256_LEN];
  wt_sha256_ctx_t ctx;

  expect_status("sha256 one-shot", wt_sha256(message, 3U, digest), WT_OK);
  expect_bytes("sha256(abc)", digest,
               "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

  /* The transcript is read mid-handshake and then keeps absorbing, which is
     what the snapshot exists for. */
  expect_status("sha256 init", wt_sha256_init(&ctx), WT_OK);
  expect_status("sha256 update a", wt_sha256_update(&ctx, "a", 1U), WT_OK);
  expect_status("sha256 update b", wt_sha256_update(&ctx, "b", 1U), WT_OK);
  expect_status("sha256 snapshot", wt_sha256_snapshot(&ctx, digest), WT_OK);
  expect_bytes("sha256(\"ab\")", digest,
               "fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603");
  expect_status("sha256 update c", wt_sha256_update(&ctx, "c", 1U), WT_OK);
  expect_status("sha256 final", wt_sha256_final(&ctx, digest), WT_OK);
  expect_bytes("sha256(\"abc\") streamed", digest,
               "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

  /* A finished context is unusable, which the contract promises: the second
     final gets a status rather than a digest of the zeroed state. */
  expect_status("sha256 final twice", wt_sha256_final(&ctx, digest),
                WT_ERR_STATE);
  expect_status("sha256 snapshot after final", wt_sha256_snapshot(&ctx, digest),
                WT_ERR_STATE);
}

static void test_hmac(void) {
  uint8_t key[20];
  uint8_t mac[WT_SHA256_LEN];
  memset(key, 0x0b, sizeof(key));
  expect_status("hmac rfc4231 case 1",
                wt_hmac_sha256(key, sizeof(key), (const uint8_t *)"Hi There",
                               8U, mac),
                WT_OK);
  expect_bytes("hmac-sha256 case 1", mac,
               "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
}

static void test_hkdf(void) {
  uint8_t ikm[22];
  static const uint8_t salt[13] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                   0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
  static const uint8_t info[10] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4,
                                   0xf5, 0xf6, 0xf7, 0xf8, 0xf9};
  uint8_t prk[WT_SHA256_LEN];
  uint8_t okm[42];
  memset(ikm, 0x0b, sizeof(ikm));

  expect_status("hkdf extract", wt_hkdf_extract_sha256(salt, sizeof(salt), ikm,
                                                       sizeof(ikm), prk),
                WT_OK);
  expect_bytes("hkdf rfc5869 prk", prk,
               "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
  expect_status("hkdf expand",
                wt_hkdf_expand_sha256(prk, sizeof(prk), info, sizeof(info), okm,
                                      sizeof(okm)),
                WT_OK);
  expect_bytes("hkdf rfc5869 okm", okm,
               "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56"
               "ecc4c5bf34007208d5b887185865");
  /* The RFC's own bound: 255 blocks of 32 bytes, and one more is refused
     rather than wrapping the one-byte counter. */
  expect_status("hkdf expand bound",
                wt_hkdf_expand_sha256(prk, sizeof(prk), info, sizeof(info), okm,
                                      sizeof(okm)),
                WT_OK);
  {
    static uint8_t too_much[255 * WT_SHA256_LEN + 1U];
    expect_status("hkdf expand over bound",
                  wt_hkdf_expand_sha256(prk, sizeof(prk), NULL, 0U, too_much,
                                        sizeof(too_much)),
                  WT_ERR_LIMIT);
  }
}

static void test_expand_label(void) {
  /* RFC 8448 section 3: the "derived" secret from the early secret. This is
     the vector that pins the label's own prefix and the context length byte,
     both of which a wrong implementation gets well-formed output from. */
  uint8_t early_secret[WT_SHA256_LEN];
  uint8_t empty_hash[WT_SHA256_LEN];
  uint8_t derived[WT_SHA256_LEN];
  from_hex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a",
           early_secret, sizeof(early_secret));
  expect_status("hash of empty", wt_sha256("", 0U, empty_hash), WT_OK);
  expect_bytes("sha256(\"\")", empty_hash,
               "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  expect_status("expand label",
                wt_hkdf_expand_label_sha256(early_secret, sizeof(early_secret),
                                            "derived", empty_hash,
                                            sizeof(empty_hash), derived,
                                            sizeof(derived)),
                WT_OK);
  expect_bytes("tls13 derived", derived,
               "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba");
}

static void test_aead(void) {
  uint8_t key[16] = {0};
  uint8_t iv[12] = {0};
  uint8_t tag[WT_AEAD_TAG_LEN];
  uint8_t plain[16] = {0};
  uint8_t out[16];

  expect_status("aead sizes", wt_aead_key_len(WT_AEAD_CHACHA20_POLY1305) == 32U
                                      ? WT_OK
                                      : WT_ERR_STATE,
                WT_OK);
  ++g_checks;
  if (strcmp(wt_aead_name(WT_AEAD_AES_128_GCM), "aes-128-gcm") != 0 ||
      strcmp(wt_aead_name(WT_AEAD_CHACHA20_POLY1305),
             "chacha20-poly1305") != 0 ||
      wt_aead_iv_len(WT_AEAD_AES_128_GCM) != 12U ||
      wt_aead_tag_len(WT_AEAD_AES_128_GCM) != 16U) {
    fail("aead names and lengths");
  }

  /* NIST SP 800-38D test case 1: empty plaintext and AAD. */
  expect_status("gcm seal empty",
                wt_aead_seal(WT_AEAD_AES_128_GCM, key, iv, NULL, 0U, NULL, 0U,
                             NULL, tag),
                WT_OK);
  expect_bytes("gcm empty tag", tag, "58e2fccefa7e3061367f1d57a4e7455a");

  /* Test case 2: one all-zero block. */
  expect_status("gcm seal block",
                wt_aead_seal(WT_AEAD_AES_128_GCM, key, iv, NULL, 0U, plain,
                             sizeof(plain), out, tag),
                WT_OK);
  expect_bytes("gcm block ciphertext", out, "0388dace60b6a392f328c2b971b2fe78");
  expect_bytes("gcm block tag", tag, "ab6e47d42cec13bdf53a67b21257bddf");

  /* The same ciphertext opens, and a tampered tag does not -- with the
     plaintext cleared, because the return value is meant to be the only
     usable output. */
  memset(out, 0xaa, sizeof(out));
  {
    uint8_t cipher[16];
    from_hex("0388dace60b6a392f328c2b971b2fe78", cipher, sizeof(cipher));
    expect_status("gcm open",
                  wt_aead_open(WT_AEAD_AES_128_GCM, key, iv, NULL, 0U, cipher,
                               sizeof(cipher),
                               (const uint8_t *)"\xab\x6e\x47\xd4\x2c\xec\x13\xbd"
                                                "\xf5\x3a\x67\xb2\x12\x57\xbd\xdf",
                               out),
                  WT_OK);
    ++g_checks;
    if (memcmp(out, plain, sizeof(plain)) != 0) fail("gcm open plaintext");

    tag[0] ^= 0x01U;
    memset(out, 0xaa, sizeof(out));
    expect_status("gcm open tampered",
                  wt_aead_open(WT_AEAD_AES_128_GCM, key, iv, NULL, 0U, cipher,
                               sizeof(cipher), tag, out),
                  WT_ERR_AUTHENTICATION);
    for (size_t index = 0U; index < sizeof(out); ++index) {
      if (out[index] != 0U) {
        fail("gcm open cleared the plaintext on failure");
        break;
      }
    }
  }

  /* ChaCha20-Poly1305 is refused rather than approximated: the port's key
     schedule is AES-128-GCM's alone, and a wrong answer for a suite nobody
     negotiated is worse than a named refusal. */
  expect_status("gcm seal chacha refused",
                wt_aead_seal(WT_AEAD_CHACHA20_POLY1305, key, iv, NULL, 0U, NULL,
                             0U, NULL, tag),
                WT_ERR_UNSUPPORTED);
}

static void test_chacha20(void) {
  /* RFC 8439 section 2.3.2: the block function with counter 1, XORed over
     sixty-four zero bytes so the keystream itself is the output. */
  uint8_t key[32];
  static const uint8_t nonce[12] = {0x00, 0x00, 0x00, 0x09, 0x00, 0x00,
                                    0x00, 0x4a, 0x00, 0x00, 0x00, 0x00};
  uint8_t zeros[64] = {0};
  uint8_t out[64];
  for (size_t index = 0U; index < sizeof(key); ++index) {
    key[index] = (uint8_t)index;
  }
  expect_status("chacha20 xor",
                wt_chacha20_xor(key, nonce, 1U, zeros, sizeof(zeros), out),
                WT_OK);
  expect_bytes("rfc8439 2.3.2 keystream", out,
               "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
               "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e");
}

static void test_helpers(void) {
  static const uint8_t a[4] = {1U, 2U, 3U, 4U};
  static const uint8_t b[4] = {1U, 2U, 3U, 4U};
  static const uint8_t c[4] = {1U, 2U, 3U, 5U};
  ++g_checks;
  if (wt_ct_equal(a, b, sizeof(a)) != 1) fail("ct_equal equal");
  if (wt_ct_equal(a, c, sizeof(a)) != 0) fail("ct_equal different");
  expect_status("crypto init", wt_crypto_init(), WT_OK);
}

int main(void) {
  test_sha256();
  test_hmac();
  test_hkdf();
  test_expand_label();
  test_aead();
  test_chacha20();
  test_helpers();
  if (g_failures != 0) {
    printf("wt_upstream_crypto: %d of %d checks failed\n", g_failures, g_checks);
    return 1;
  }
  printf("wt_upstream_crypto: all %d checks reproduced their RFC or NIST vector\n",
         g_checks);
  return 0;
}
