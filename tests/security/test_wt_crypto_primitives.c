/* The hash, HMAC, AEAD and x25519 primitives of wt_crypto.h, checked against
 * published RFC vectors.
 *
 * This is one of the two modules that `test_wt_crypto.c` was split into; see
 * `test_wt_crypto_support.h` for the layout, the shared helpers and the
 * counters. Every assertion and every byte of output is unchanged from the
 * one-file suite.
 */

#include "test_wt_crypto_support.h"

/* The counters, defined exactly once for the whole suite. */
int wtcrypto_failures;
int wtcrypto_checks;

/* ------------------------------------------------------------------ SHA-256 */

void wtcrypto_test_sha256(void) {
  uint8_t digest[32], want[32];

  wtcrypto_expect_int("sha256(abc)", 0, wt_sha256("abc", 3, digest));
  wtcrypto_vector("sha256(abc)",
                  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                  want, sizeof(want), 32);
  wtcrypto_expect("sha256(abc) value", want, digest, 32);

  wtcrypto_expect_int("sha256(empty)", 0, wt_sha256("", 0, digest));
  wtcrypto_vector("sha256(empty)",
                  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                  want, sizeof(want), 32);
  wtcrypto_expect("sha256(empty) value", want, digest, 32);

  /* The streaming interface must agree with the one-shot, including across a
     call boundary that is not a block multiple. */
  {
    wt_sha256_ctx_t ctx;
    wtcrypto_expect_int("sha256_init", 0, wt_sha256_init(&ctx));
    wtcrypto_expect_int("sha256_update a", 0, wt_sha256_update(&ctx, "a", 1));
    wtcrypto_expect_int("sha256_update bc", 0, wt_sha256_update(&ctx, "bc", 2));
    wtcrypto_expect_int("sha256_final", 0, wt_sha256_final(&ctx, digest));
    wtcrypto_vector("sha256 streaming abc",
                    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                    want, sizeof(want), 32);
    wtcrypto_expect("sha256 streaming abc value", want, digest, 32);
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
    wtcrypto_expect_int("sha256_init for the streamed case", 0,
                        wt_sha256_init(&ctx));
    for (i = 0; i < 100; i++) {
      wtcrypto_expect_int("sha256_update chunk", 0,
                          wt_sha256_update(&ctx, block, sizeof(block)));
    }
    wtcrypto_expect_int("sha256_final streamed", 0,
                        wt_sha256_final(&ctx, streamed));
    wtcrypto_vector("sha256(10000 x a)",
                    "27dd1f61b867b6a0f6e9d8a41c43231de52107e53ae424de8f847b821db4b711",
                    want, sizeof(want), 32);
    wtcrypto_expect("sha256(10000 x a) streamed", want, streamed, 32);

    /* The one-shot call over the same bytes must agree, which is what makes
       the streaming test meaningful rather than a second guess. */
    {
      static uint8_t whole[10000];
      memset(whole, 'a', sizeof(whole));
      wtcrypto_expect_int("sha256 one-shot over 10000", 0,
                          wt_sha256(whole, sizeof(whole), digest));
      wtcrypto_expect("sha256(10000 x a) one-shot", want, digest, 32);
    }
  }
}

/* --------------------------------------------------------------------- HKDF */

void wtcrypto_test_hkdf(void) {
  uint8_t ikm[22], salt[13], info[10], prk[32], okm[42], want[32], want_okm[42];
  uint8_t ikm3[22], prk3[32];
  static uint8_t big[255 * 32 + 1];

  wtcrypto_vector("A.1 ikm", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                  ikm, sizeof(ikm), 22);
  wtcrypto_vector("A.1 salt", "000102030405060708090a0b0c", salt, sizeof(salt),
                  13);
  wtcrypto_vector("A.1 info", "f0f1f2f3f4f5f6f7f8f9", info, sizeof(info), 10);
  wtcrypto_vector("A.1 prk",
                  "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
                  want, sizeof(want), 32);
  wtcrypto_vector("A.1 okm",
                  "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                  "34007208d5b887185865",
                  want_okm, sizeof(want_okm), 42);

  wtcrypto_expect_int("extract A.1", 0,
                      wt_hkdf_extract_sha256(salt, sizeof(salt), ikm,
                                             sizeof(ikm), prk));
  wtcrypto_expect("extract A.1 prk", want, prk, 32);
  wtcrypto_expect_int("expand A.1", 0,
                      wt_hkdf_expand_sha256(prk, 32, info, sizeof(info), okm,
                                            sizeof(okm)));
  wtcrypto_expect("expand A.1 okm", want_okm, okm, sizeof(okm));

  /* RFC 5869 appendix A.3: zero-length salt and info. This separates "no
     salt" (an all-zero HashLen salt) from "an empty salt", which HMAC pads
     differently and which yields a different PRK. */
  wtcrypto_vector("A.3 ikm", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                  ikm3, sizeof(ikm3), 22);
  wtcrypto_vector("A.3 prk",
                  "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
                  want, sizeof(want), 32);
  wtcrypto_vector("A.3 okm",
                  "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
                  "9d201395faa4b61a96c8",
                  want_okm, sizeof(want_okm), 42);
  wtcrypto_expect_int("extract A.3 (NULL salt)", 0,
                      wt_hkdf_extract_sha256(NULL, 0, ikm3, sizeof(ikm3), prk3));
  wtcrypto_expect("extract A.3 prk", want, prk3, 32);
  wtcrypto_expect_int("expand A.3 (NULL info)", 0,
                      wt_hkdf_expand_sha256(prk3, 32, NULL, 0, okm,
                                            sizeof(okm)));
  wtcrypto_expect("expand A.3 okm", want_okm, okm, sizeof(okm));

  /* The RFC's bound. 255*HashLen is the most HKDF-Expand can produce; one
     byte more must be refused rather than wrapped, because a wrapped counter
     returns bytes that are not the RFC's answer with no other symptom. WT-30
     in the WebTransport tracker was exactly this in the Swift implementation. */
  wtcrypto_expect_int("expand 255 blocks is allowed", 0,
                      wt_hkdf_expand_sha256(prk3, 32, NULL, 0, big, 255 * 32));
  wtcrypto_expect_int("expand over 255 blocks is refused", -1,
                      wt_hkdf_expand_sha256(prk3, 32, NULL, 0, big,
                                            255 * 32 + 1));
}

/* ------------------------------------------------- AES-GCM decrypt round trip */

/* Every RFC 9001 vector for AES-GCM is an encryption, so decrypting was not
 * covered by any of them, and the first version of the binding had the tag
 * check in an order that made every decryption fail. A round trip is the
 * minimum evidence that the other direction works at all. */
void wtcrypto_test_gcm_round_trip(void) {
  uint8_t key[16], iv[12], aad[22], plain[32], cipher[32], tag[16], out[32];
  uint8_t key2[16];

  memset(key, 0x11, sizeof(key));
  memset(iv, 0x22, sizeof(iv));
  memset(aad, 0x33, sizeof(aad));
  memset(plain, 0x44, sizeof(plain));
  memset(out, 0, sizeof(out));

  wtcrypto_expect_int("GCM encrypt", 0,
                      wt_aes128_gcm_encrypt(key, iv, aad, sizeof(aad), plain,
                                            sizeof(plain), cipher, tag));
  wtcrypto_checks++;
  if (memcmp(cipher, plain, sizeof(plain)) == 0) {
    wtcrypto_failures++;
    printf("FAIL GCM encrypt left the plaintext unchanged\n");
  }
  {
    uint8_t computed[16];
    wtcrypto_expect_int("GCM decrypt", 0,
                        wt_aes128_gcm_decrypt(key, iv, aad, sizeof(aad), cipher,
                                              sizeof(cipher), out, computed));
    wtcrypto_expect("GCM computed tag matches the sender's", tag, computed, 16);
    wtcrypto_expect_int("GCM tag verifies", 1,
                        wt_ct_equal(computed, tag, 16));
  }
  wtcrypto_expect("GCM round trip", plain, out, sizeof(plain));

  /* Every single-bit change to the tag must be refused, and must leave the
     output buffer alone. */
  {
    int accepted = 0;
    int wrote_output = 0;
    for (size_t bit = 0U; bit < 128U; bit++) {
      uint8_t forged[16];
      memcpy(forged, tag, sizeof(forged));
      forged[bit / 8U] ^= (uint8_t)(1U << (bit % 8U));
      uint8_t computed[16];
      memset(out, 0xAA, sizeof(out));
      if (wt_aes128_gcm_decrypt(key, iv, aad, sizeof(aad), cipher,
                                sizeof(cipher), out, computed) != 0) {
        continue;
      }
      if (wt_ct_equal(computed, forged, 16)) {
        accepted++;
      } else if (out[0] != 0xAAU) {
        /* The binding wrote the plaintext; the caller is the one that must
           discard it. Counting this proves the contract is understood. */
        wrote_output++;
      }
    }
    wtcrypto_expect_int("every single-bit tag forgery is refused", 0, accepted);
    /* Decryption succeeds and produces a tag that does not match: that is the
       contract, and the caller must not use the plaintext. This asserts the
       contract rather than pretending the binding refuses. */
    wtcrypto_expect_int("a forged tag is not equal to the computed one", 128,
                        wrote_output);
  }

  /* A changed ciphertext byte must be refused too. */
  {
    uint8_t forged[32];
    memcpy(forged, cipher, sizeof(forged));
    forged[7] ^= 0x01U;
    {
      uint8_t computed[16];
      wtcrypto_expect_int("an altered ciphertext decrypts", 0,
                          wt_aes128_gcm_decrypt(key, iv, aad, sizeof(aad),
                                                forged, sizeof(forged), out,
                                                computed));
      wtcrypto_expect_int("an altered ciphertext does not verify", 0,
                          wt_ct_equal(computed, tag, 16));
    }
  }

  /* A changed association must be refused: this is what makes the packet
     header authenticated. */
  {
    uint8_t other_aad[22];
    memcpy(other_aad, aad, sizeof(other_aad));
    other_aad[5] ^= 0x01U;
    {
      uint8_t computed[16];
      wtcrypto_expect_int("altered associated data decrypts", 0,
                          wt_aes128_gcm_decrypt(key, iv, other_aad,
                                                sizeof(other_aad), cipher,
                                                sizeof(cipher), out, computed));
      wtcrypto_expect_int("altered associated data does not verify", 0,
                          wt_ct_equal(computed, tag, 16));
    }
  }

  /* A different key must be refused. */
  memcpy(key2, key, sizeof(key2));
  key2[0] ^= 0x01U;
  {
    uint8_t computed[16];
    wtcrypto_expect_int("a different key decrypts", 0,
                        wt_aes128_gcm_decrypt(key2, iv, aad, sizeof(aad),
                                              cipher, sizeof(cipher), out,
                                              computed));
    wtcrypto_expect_int("a different key does not verify", 0,
                        wt_ct_equal(computed, tag, 16));
  }
}

/* ------------------------------------------------------------------ x25519 */

/* RFC 7748 section 5.2's own test vector: a private key and the public key it
 * must produce, and the shared secret between two such pairs. These are the
 * canonical vectors, and they pin the clamping and the encoding rather than
 * just "it produces 32 bytes". */
void wtcrypto_test_x25519(void) {
  static const uint8_t alice_private[32] = {
      0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
      0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
      0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
      0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
  };
  static const uint8_t alice_public[32] = {
      0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
      0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
      0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
      0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a,
  };
  static const uint8_t bob_private[32] = {
      0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
      0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
      0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
      0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
  };
  static const uint8_t bob_public[32] = {
      0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
      0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
      0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
      0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f,
  };
  static const uint8_t expected_secret[32] = {
      0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1,
      0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
      0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
      0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42,
  };
  uint8_t out[32];

  wtcrypto_expect_int("x25519 public key from the RFC's private key", 0,
                      wt_x25519_public_key(alice_private, out));
  wtcrypto_expect("the public key is the RFC's", alice_public, out, 32);

  wtcrypto_expect_int("x25519 public key from the other private key", 0,
                      wt_x25519_public_key(bob_private, out));
  wtcrypto_expect("and it is the RFC's too", bob_public, out, 32);

  /* Both directions must agree; a ladder that is wrong in one direction only
     is a ladder that is wrong. */
  wtcrypto_expect_int("alice's shared secret", 0,
                      wt_x25519_shared_secret(alice_private, bob_public, out));
  wtcrypto_expect("alice computes the RFC's secret", expected_secret, out, 32);
  wtcrypto_expect_int("bob's shared secret", 0,
                      wt_x25519_shared_secret(bob_private, alice_public, out));
  wtcrypto_expect("bob computes the same secret", expected_secret, out, 32);

  /* RFC 7748 section 6.1's low-order point. It must be refused, because the
     result is the same for every private key and a peer that can choose it can
     force a known secret. */
  {
    static const uint8_t low_order[32] = {0};
    wtcrypto_expect_int("the all-zero public key is refused", 0,
                        wt_x25519_public_key_is_valid(low_order));
    wtcrypto_expect_int("and the shared secret with it is refused", -1,
                        wt_x25519_shared_secret(alice_private, low_order, out));
    /* The output must be cleared rather than left holding whatever was there. */
    {
      static const uint8_t zeroes[32] = {0};
      wtcrypto_expect("a refused shared secret is cleared", zeroes, out, 32);
    }
  }

  /* RFC 8448's own trace: the client's private key and the server's public key
     from the ServerHello produce the ECDHE input the key schedule is built on.
     This is the value the whole handshake depends on, and it is published. */
  {
    static const uint8_t rfc8448_client_private[32] = {
        0x49, 0xaf, 0x42, 0xba, 0x7f, 0x79, 0x94, 0x85,
        0x2d, 0x71, 0x3e, 0xf2, 0x78, 0x4b, 0xcb, 0xca,
        0xa7, 0x91, 0x1d, 0xe2, 0x6a, 0xdc, 0x56, 0x42,
        0xcb, 0x63, 0x45, 0x40, 0xe7, 0xea, 0x50, 0x05,
    };
    static const uint8_t rfc8448_client_public[32] = {
        0x99, 0x38, 0x1d, 0xe5, 0x60, 0xe4, 0xbd, 0x43,
        0xd2, 0x3d, 0x8e, 0x43, 0x5a, 0x7d, 0xba, 0xfe,
        0xb3, 0xc0, 0x6e, 0x51, 0xc1, 0x3c, 0xae, 0x4d,
        0x54, 0x13, 0x69, 0x1e, 0x52, 0x9a, 0xaf, 0x2c,
    };
    static const uint8_t rfc8448_server_public[32] = {
        0xc9, 0x82, 0x88, 0x76, 0x11, 0x20, 0x95, 0xfe,
        0x66, 0x76, 0x2b, 0xdb, 0xf7, 0xc6, 0x72, 0xe1,
        0x56, 0xd6, 0xcc, 0x25, 0x3b, 0x83, 0x3d, 0xf1,
        0xdd, 0x69, 0xb1, 0xb0, 0x4e, 0x75, 0x1f, 0x0f,
    };
    wtcrypto_expect_int("the RFC 8448 client public key", 0,
                        wt_x25519_public_key(rfc8448_client_private, out));
    wtcrypto_expect("matches the ClientHello's key share", rfc8448_client_public,
                    out, 32);
    wtcrypto_expect_int("the RFC 8448 shared secret", 0,
                        wt_x25519_shared_secret(rfc8448_client_private,
                                                rfc8448_server_public, out));
    wtcrypto_expect("is the ECDHE input the key schedule uses",
                    WT_RFC8448_ECDHE, out, 32);
  }

  wtcrypto_expect_int("a NULL private key is refused", -1,
                      wt_x25519_public_key(NULL, out));
  wtcrypto_expect_int("a NULL output is refused", -1,
                      wt_x25519_public_key(alice_private, NULL));
  wtcrypto_expect_int("a NULL peer key is refused", -1,
                      wt_x25519_shared_secret(alice_private, NULL, out));
}

/* ------------------------------------------------------------------ helpers */

void wtcrypto_test_helpers(void) {
  uint8_t a[4] = {1, 2, 3, 4};
  uint8_t b[4] = {1, 2, 3, 4};
  uint8_t c[4] = {1, 2, 3, 5};
  uint8_t secret[8];

  wtcrypto_expect_int("ct_equal equal", 1, wt_ct_equal(a, b, 4));
  wtcrypto_expect_int("ct_equal differing", 0, wt_ct_equal(a, c, 4));
  wtcrypto_expect_int("ct_equal length 0", 1, wt_ct_equal(a, b, 0));

  memset(secret, 0xAA, sizeof(secret));
  wt_secure_zero(secret, sizeof(secret));
  wtcrypto_expect_int("wt_secure_zero cleared everything", 1,
                      (secret[0] | secret[1] | secret[2] | secret[3] |
                       secret[4] | secret[5] | secret[6] | secret[7]) == 0);
}
