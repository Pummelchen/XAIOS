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
 */

#include "wt_crypto.h"
#include "wt_rfc9001_vectors.h"

#include <stdio.h>
#include <string.h>

static int g_failures;
static int g_checks;

static size_t unhex(const char *hex, uint8_t *out, size_t out_size) {
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
static void vector(const char *name, const char *hex, uint8_t *out,
                   size_t out_size, size_t want_len) {
  size_t n = unhex(hex, out, out_size);
  g_checks++;
  if (n == want_len) return;
  g_failures++;
  printf("FAIL %s: vector decoded to %ld bytes, expected %ld\n", name, (long)n,
         (long)want_len);
}

static void expect(const char *name, const uint8_t *want, const uint8_t *got,
                   size_t len) {
  g_checks++;
  if (memcmp(want, got, len) == 0) return;
  g_failures++;
  printf("FAIL %s\n     want ", name);
  for (size_t i = 0; i < len; i++) printf("%02x", want[i]);
  printf("\n     got  ");
  for (size_t i = 0; i < len; i++) printf("%02x", got[i]);
  printf("\n");
}

static void expect_int(const char *name, long want, long got) {
  g_checks++;
  if (want == got) return;
  g_failures++;
  printf("FAIL %s: want %ld, got %ld\n", name, want, got);
}

/* Compare against a hex literal, so the vectors read as the RFC prints them. */
static void expect_hex(const char *name, const char *want_hex,
                       const uint8_t *got, size_t len) {
  uint8_t want[128];
  size_t n = unhex(want_hex, want, sizeof(want));
  g_checks++;
  if (n == len) {
    if (memcmp(want, got, len) == 0) return;
  } else {
    g_failures++;
    printf("FAIL %s: vector decoded to %ld bytes, expected %ld\n", name,
           (long)n, (long)len);
    return;
  }
  g_failures++;
  printf("FAIL %s\n     want ", name);
  for (size_t i = 0; i < len; i++) printf("%02x", want[i]);
  printf("\n     got  ");
  for (size_t i = 0; i < len; i++) printf("%02x", got[i]);
  printf("\n");
}

/* ------------------------------------------------------------------ SHA-256 */

static void test_sha256(void) {
  uint8_t digest[32], want[32];

  expect_int("sha256(abc)", 0, wt_sha256("abc", 3, digest));
  vector("sha256(abc)", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
         want, sizeof(want), 32);
  expect("sha256(abc) value", want, digest, 32);

  expect_int("sha256(empty)", 0, wt_sha256("", 0, digest));
  vector("sha256(empty)",
         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", want,
         sizeof(want), 32);
  expect("sha256(empty) value", want, digest, 32);

  /* The streaming interface must agree with the one-shot, including across a
     call boundary that is not a block multiple. */
  {
    wt_sha256_ctx_t ctx;
    expect_int("sha256_init", 0, wt_sha256_init(&ctx));
    expect_int("sha256_update a", 0, wt_sha256_update(&ctx, "a", 1));
    expect_int("sha256_update bc", 0, wt_sha256_update(&ctx, "bc", 2));
    expect_int("sha256_final", 0, wt_sha256_final(&ctx, digest));
    vector("sha256 streaming abc",
           "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
           want, sizeof(want), 32);
    expect("sha256 streaming abc value", want, digest, 32);
  }

  /* A multi-block input. The expected digest is SHA-256 of 10000 'a'
     characters, computed rather than recalled -- the first version of this
     test carried a wrong expected value and reported a correct
     implementation as broken. A vector is only evidence if it is right. */
  {
    wt_sha256_ctx_t ctx;
    uint8_t block[100];
    uint8_t streamed[32];
    int i;
    memset(block, 'a', sizeof(block));
    expect_int("sha256_init for the streamed case", 0, wt_sha256_init(&ctx));
    for (i = 0; i < 100; i++) {
      expect_int("sha256_update chunk", 0,
                 wt_sha256_update(&ctx, block, sizeof(block)));
    }
    expect_int("sha256_final streamed", 0, wt_sha256_final(&ctx, streamed));
    vector("sha256(10000 x a)",
           "27dd1f61b867b6a0f6e9d8a41c43231de52107e53ae424de8f847b821db4b711",
           want, sizeof(want), 32);
    expect("sha256(10000 x a) streamed", want, streamed, 32);

    /* The one-shot call over the same bytes must agree, which is what makes
       the streaming test meaningful rather than a second guess. */
    {
      static uint8_t whole[10000];
      memset(whole, 'a', sizeof(whole));
      expect_int("sha256 one-shot over 10000", 0,
                 wt_sha256(whole, sizeof(whole), digest));
      expect("sha256(10000 x a) one-shot", want, digest, 32);
    }
  }
}

/* --------------------------------------------------------------------- HKDF */

static void test_hkdf(void) {
  uint8_t ikm[22], salt[13], info[10], prk[32], okm[42], want[32], want_okm[42];
  uint8_t ikm3[22], prk3[32];
  static uint8_t big[255 * 32 + 1];

  vector("A.1 ikm", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", ikm,
         sizeof(ikm), 22);
  vector("A.1 salt", "000102030405060708090a0b0c", salt, sizeof(salt), 13);
  vector("A.1 info", "f0f1f2f3f4f5f6f7f8f9", info, sizeof(info), 10);
  vector("A.1 prk",
         "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
         want, sizeof(want), 32);
  vector("A.1 okm",
         "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
         "34007208d5b887185865",
         want_okm, sizeof(want_okm), 42);

  expect_int("extract A.1", 0,
             wt_hkdf_extract_sha256(salt, sizeof(salt), ikm, sizeof(ikm), prk));
  expect("extract A.1 prk", want, prk, 32);
  expect_int("expand A.1", 0,
             wt_hkdf_expand_sha256(prk, 32, info, sizeof(info), okm,
                                   sizeof(okm)));
  expect("expand A.1 okm", want_okm, okm, sizeof(okm));

  /* RFC 5869 appendix A.3: zero-length salt and info. This separates "no
     salt" (an all-zero HashLen salt) from "an empty salt", which HMAC pads
     differently and which yields a different PRK. */
  vector("A.3 ikm", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", ikm3,
         sizeof(ikm3), 22);
  vector("A.3 prk",
         "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
         want, sizeof(want), 32);
  vector("A.3 okm",
         "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
         "9d201395faa4b61a96c8",
         want_okm, sizeof(want_okm), 42);
  expect_int("extract A.3 (NULL salt)", 0,
             wt_hkdf_extract_sha256(NULL, 0, ikm3, sizeof(ikm3), prk3));
  expect("extract A.3 prk", want, prk3, 32);
  expect_int("expand A.3 (NULL info)", 0,
             wt_hkdf_expand_sha256(prk3, 32, NULL, 0, okm, sizeof(okm)));
  expect("expand A.3 okm", want_okm, okm, sizeof(okm));

  /* The RFC's bound. 255*HashLen is the most HKDF-Expand can produce; one
     byte more must be refused rather than wrapped, because a wrapped counter
     returns bytes that are not the RFC's answer with no other symptom. WT-30
     in the WebTransport tracker was exactly this in the Swift implementation. */
  expect_int("expand 255 blocks is allowed", 0,
             wt_hkdf_expand_sha256(prk3, 32, NULL, 0, big, 255 * 32));
  expect_int("expand over 255 blocks is refused", -1,
             wt_hkdf_expand_sha256(prk3, 32, NULL, 0, big, 255 * 32 + 1));
}

/* ---------------------------------------------------------------- ChaCha20 */

static void test_chacha20(void) {
  uint8_t key[32], nonce[12], keystream[64], zeros[64];
  uint8_t mask[5], zero5[5];
  uint32_t counter;

  memset(key, 0, sizeof(key));
  memset(nonce, 0, sizeof(nonce));
  memset(zeros, 0, sizeof(zeros));
  expect_int("chacha20 block call", 0,
             wt_chacha20_xor(key, nonce, 0, zeros, 32, keystream));
  {
    uint8_t want[32];
    vector("rfc8439 block",
           "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7",
           want, sizeof(want), 32);
    expect("chacha20 rfc8439 block", want, keystream, 32);
  }

  /* RFC 9001 A.5: QUIC's ChaCha20 header-protection mask is the keystream
     over five zero bytes, with the counter from the sample's first four bytes
     little-endian and the nonce from the remaining twelve. Getting the split
     or the endianness wrong still yields five plausible bytes. */
  counter = (uint32_t)WT_RFC9001_CHACHA_SAMPLE[0]
          | ((uint32_t)WT_RFC9001_CHACHA_SAMPLE[1] << 8)
          | ((uint32_t)WT_RFC9001_CHACHA_SAMPLE[2] << 16)
          | ((uint32_t)WT_RFC9001_CHACHA_SAMPLE[3] << 24);
  memset(zero5, 0, sizeof(zero5));
  expect_int("chacha20 hp mask call", 0,
             wt_chacha20_xor(WT_RFC9001_CHACHA_HP, WT_RFC9001_CHACHA_SAMPLE + 4,
                             counter, zero5, 5, mask));
  expect("chacha20 hp mask aefefe7d03", WT_RFC9001_CHACHA_MASK, mask, 5);
}

/* ------------------------------------------------- RFC 9001 packet protection */

/* HKDF-Expand-Label (RFC 8446 section 7.1) as QUIC uses it, with an empty
   context. Built here rather than taken from wt_tls so that this test checks
   the crypto binding on its own; wt_tls's test checks the label construction
   against RFC 8448. */
static void derive_label(const uint8_t secret[32], const char *label,
                         size_t out_len, uint8_t *out) {
  uint8_t info[64];
  size_t label_len = strlen(label);
  size_t full_len = 6U + label_len;
  size_t info_len;

  info[0] = (uint8_t)(out_len >> 8);
  info[1] = (uint8_t)(out_len & 0xFFU);
  info[2] = (uint8_t)full_len;
  memcpy(info + 3, "tls13 ", 6);
  memcpy(info + 9, label, label_len);
  info[3U + full_len] = 0U; /* empty context */
  info_len = 4U + full_len;

  if (wt_hkdf_expand_sha256(secret, 32, info, info_len, out, out_len) != 0) {
    g_checks++;
    g_failures++;
    printf("FAIL derive_label(%s) refused\n", label);
  }
}

static void test_initial_packet(void) {
  uint8_t initial_secret[32], client_secret[32], server_secret[32];
  /* `iv` is padded to 16 bytes because derive_label writes its full output
     length, and the sequence "key then iv" in one frame means a 16-byte write
     into a 12-byte iv overruns. That is what made the server's iv and hp check
     fail while the client's passed: the client's iv was derived last before
     use, the server's was clobbered by the following write. */
  uint8_t key[16], iv[16], hp[16], nonce[12];
  static uint8_t plaintext[1162];
  static uint8_t ciphertext[1162];
  uint8_t tag[16], ecb[16], protected_header[22];
  uint8_t retry_pseudo[1U + sizeof(WT_RFC9001_DCID) +
                       sizeof(WT_RFC9001_RETRY_WITHOUT_TAG)];
  uint8_t retry_tag[16];
  uint8_t zero_aad = 0U;

  /* A.1: initial_secret = HKDF-Extract(initial_salt, dcid) */
  expect_int("initial_secret", 0,
             wt_hkdf_extract_sha256(WT_RFC9001_INITIAL_SALT,
                                    sizeof(WT_RFC9001_INITIAL_SALT),
                                    WT_RFC9001_DCID, sizeof(WT_RFC9001_DCID),
                                    initial_secret));
  expect_hex("initial_secret value",
             "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44",
             initial_secret, 32);

  derive_label(initial_secret, "client in", 32, client_secret);
  expect_hex("client_initial_secret",
             "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
             client_secret, 32);
  derive_label(initial_secret, "server in", 32, server_secret);
  expect_hex("server_initial_secret",
             "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b",
             server_secret, 32);

  derive_label(client_secret, "quic key", 16, key);
  derive_label(client_secret, "quic iv", 12, iv);
  derive_label(client_secret, "quic hp", 16, hp);
  expect_hex("client initial key", "1f369613dd76d5467730efcbe3b1a22d", key, 16);
  expect_hex("client initial iv", "fa044b2f42a3fd3b46fb255c", iv, 12);
  expect_hex("client initial hp", "9f50449e04a0e810283a1e9933adedd2", hp, 16);

  /* A.2: the AEAD over the real packet. The plaintext is the CRYPTO frame the
     RFC prints, padded with zeros to the 1162-byte payload it states. */
  {
    /* The payload the RFC protects is the printed CRYPTO frame followed by
       PADDING to 1162 bytes. PADDING is a zero byte, so the tail is zeros. The
       assertion is the AEAD tag, so getting the frame or the padding length
       wrong fails it -- which is what makes this a check and not a formality. */
    memset(plaintext, 0, sizeof(plaintext));
    memcpy(plaintext, WT_RFC9001_CLIENT_FRAME, sizeof(WT_RFC9001_CLIENT_FRAME));
  }

  memcpy(nonce, iv, sizeof(nonce));
  nonce[11] ^= 0x02U; /* packet number 2, right-aligned */
  expect_int("A.2 gcm encrypt", 0,
             wt_aes128_gcm_encrypt(key, nonce, WT_RFC9001_CLIENT_HEADER, 22,
                                   plaintext, sizeof(plaintext), ciphertext,
                                   tag));

  /* The tag, over the payload the RFC actually protected. */
  /* The tag, over the payload the RFC actually protected. The expected value
     is the last 16 bytes of the RFC's protected packet, extracted by the
     generator rather than typed. */
  expect("A.2 AEAD tag", WT_RFC9001_CLIENT_TAG, tag, 16);
  expect("A.2 ciphertext matches the RFC's protected payload",
         WT_RFC9001_CLIENT_PACKET + 22, ciphertext, 1162);

  /* Header protection: the sample is the first 16 bytes of the protected
     payload, and the mask is AES-ECB(hp, sample)[0..4]. */
  expect("A.2 header protection sample", WT_RFC9001_CLIENT_PACKET + 22,
         ciphertext, 16);
  /* The mask is AES-ECB(hp, sample)[0..4]. `wt_aes128_ecb_encrypt_block` is
     E(sample); the first version of this test compared the *keystream* E(0)
     against it, which is a different value that also looks like a mask. */
  {
    uint8_t zero_block[16];
    memset(zero_block, 0, sizeof(zero_block));
    expect_int("A.2 aes-ecb of sample", 0,
               wt_aes128_ecb_encrypt_block(hp, ciphertext, ecb));
    /* The block function is a block cipher, not a keystream: the RFC's mask is
       E(sample) = 437b9aec36..., and E(0) is a different value that also looks
       like a mask. Both are asserted so the distinction cannot regress
       silently. */
    {
      uint8_t e_zero[16];
      expect_int("A.2 aes-ecb of zeros", 0,
                 wt_aes128_ecb_encrypt_block(hp, zero_block, e_zero));
      expect_hex("A.2 AES-ECB(hp, 0) is the block encryption of zero",
                 "3c84e0abe1ade2049cf3770c8eefd2f4", e_zero, 16);
    }
    expect_hex("A.2 mask from AES-ECB(hp, sample)", "437b9aec36", ecb, 5);
  }

  memcpy(protected_header, WT_RFC9001_CLIENT_HEADER, 22);
  protected_header[0] ^= (uint8_t)(ecb[0] & 0x0FU);
  protected_header[18] ^= ecb[1];
  protected_header[19] ^= ecb[2];
  protected_header[20] ^= ecb[3];
  protected_header[21] ^= ecb[4];
  expect("A.2 protected header", WT_RFC9001_CLIENT_PACKET, protected_header, 22);

  /* The server's Initial, same procedure, so the test is not passing because
     one hard-coded direction happens to line up. The second version of this
     derived from `client_initial` in place of `server_initial`, which fails
     all three values and looks like a derivation bug. */
  derive_label(server_secret, "quic key", 16, key);
  derive_label(server_secret, "quic iv", 12, iv);
  derive_label(server_secret, "quic hp", 16, hp);
  expect_hex("server initial key", "cf3a5331653c364c88f0f379b6067e37", key, 16);
  expect_hex("server initial iv", "0ac1493ca1905853b0bba03e", iv, 12);
  expect_hex("server initial hp", "c206b8d9b9f0f37644430b490eeaa314", hp, 16);

  /* A.4: the Retry integrity tag. The key and nonce are fixed constants in
     RFC 9001 section 5.8 rather than derived, and the pseudo-packet is the
     original DCID, length-prefixed, followed by the Retry without its tag. */
  {
    static const uint8_t retry_key[16] = {
        0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
        0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
    };
    static const uint8_t retry_nonce[12] = {
        0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2,
        0x23, 0x98, 0x25, 0xbb,
    };
    retry_pseudo[0] = (uint8_t)sizeof(WT_RFC9001_DCID);
    memcpy(retry_pseudo + 1, WT_RFC9001_DCID, sizeof(WT_RFC9001_DCID));
    memcpy(retry_pseudo + 1 + sizeof(WT_RFC9001_DCID),
           WT_RFC9001_RETRY_WITHOUT_TAG, sizeof(WT_RFC9001_RETRY_WITHOUT_TAG));
    expect_int("A.4 retry tag", 0,
               wt_aes128_gcm_encrypt(retry_key, retry_nonce, retry_pseudo,
                                     sizeof(retry_pseudo), &zero_aad, 0, &zero_aad,
                                     retry_tag));
    expect("A.4 retry integrity tag", WT_RFC9001_RETRY_TAG, retry_tag, 16);
  }

}

/* ------------------------------------------------------------------ helpers */

static void test_helpers(void) {
  uint8_t a[4] = {1, 2, 3, 4};
  uint8_t b[4] = {1, 2, 3, 4};
  uint8_t c[4] = {1, 2, 3, 5};
  uint8_t secret[8];

  expect_int("ct_equal equal", 1, wt_ct_equal(a, b, 4));
  expect_int("ct_equal differing", 0, wt_ct_equal(a, c, 4));
  expect_int("ct_equal length 0", 1, wt_ct_equal(a, b, 0));

  memset(secret, 0xAA, sizeof(secret));
  wt_secure_zero(secret, sizeof(secret));
  expect_int("wt_secure_zero cleared everything", 1,
             (secret[0] | secret[1] | secret[2] | secret[3] | secret[4] |
              secret[5] | secret[6] | secret[7]) == 0);
}

int main(void) {
  test_sha256();
  test_hkdf();
  test_chacha20();
  test_initial_packet();
  test_helpers();

  if (g_failures != 0) {
    printf("wt_crypto: %d of %d checks FAILED\n", g_failures, g_checks);
    return 1;
  }
  printf("wt_crypto: all %d checks reproduced their RFC vector\n", g_checks);
  return 0;
}
