/* The ChaCha20 header-protection and RFC 9001 Initial-packet checks of
 * wt_crypto.h.
 *
 * This is one of the two modules that `test_wt_crypto.c` was split into; see
 * `test_wt_crypto_support.h` for the layout, the shared helpers and the
 * counters. Every assertion and every byte of output is unchanged from the
 * one-file suite.
 */

#include "test_wt_crypto_support.h"

/* ---------------------------------------------------------------- ChaCha20 */

void wtcrypto_test_chacha20(void) {
  uint8_t key[32], nonce[12], keystream[64], zeros[64];
  uint8_t mask[5], zero5[5];
  uint32_t counter;

  memset(key, 0, sizeof(key));
  memset(nonce, 0, sizeof(nonce));
  memset(zeros, 0, sizeof(zeros));
  wtcrypto_expect_int("chacha20 block call", 0,
                      wt_chacha20_xor(key, nonce, 0, zeros, 32, keystream));
  {
    uint8_t want[32];
    wtcrypto_vector("rfc8439 block",
                    "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7",
                    want, sizeof(want), 32);
    wtcrypto_expect("chacha20 rfc8439 block", want, keystream, 32);
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
  wtcrypto_expect_int("chacha20 hp mask call", 0,
                      wt_chacha20_xor(WT_RFC9001_CHACHA_HP,
                                      WT_RFC9001_CHACHA_SAMPLE + 4, counter,
                                      zero5, 5, mask));
  wtcrypto_expect("chacha20 hp mask aefefe7d03", WT_RFC9001_CHACHA_MASK, mask,
                  5);
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
  size_t full_len;
  size_t info_len;

  /* Bounded rather than assumed: `info` is 64 bytes and `label_len` comes from
     the caller. Every label in this file is short, so this is a latent
     overflow rather than a live one -- which is the same class of defect the
     comments here warn about, so it is closed. */
  if (label_len > 255U - 6U || 4U + 6U + label_len > sizeof(info)) {
    wtcrypto_checks++;
    wtcrypto_failures++;
    printf("FAIL derive_label: label too long for the info buffer\n");
    return;
  }
  full_len = 6U + label_len;

  info[0] = (uint8_t)(out_len >> 8);
  info[1] = (uint8_t)(out_len & 0xFFU);
  info[2] = (uint8_t)full_len;
  memcpy(info + 3, "tls13 ", 6);
  memcpy(info + 9, label, label_len);
  info[3U + full_len] = 0U; /* empty context */
  info_len = 4U + full_len;

  if (wt_hkdf_expand_sha256(secret, 32, info, info_len, out, out_len) != 0) {
    wtcrypto_checks++;
    wtcrypto_failures++;
    printf("FAIL derive_label(%s) refused\n", label);
  }
}

void wtcrypto_test_initial_packet(void) {
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
  wtcrypto_expect_int("initial_secret", 0,
                      wt_hkdf_extract_sha256(
                          WT_RFC9001_INITIAL_SALT,
                          sizeof(WT_RFC9001_INITIAL_SALT), WT_RFC9001_DCID,
                          sizeof(WT_RFC9001_DCID), initial_secret));
  wtcrypto_expect_hex(
      "initial_secret value",
      "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44",
      initial_secret, 32);

  derive_label(initial_secret, "client in", 32, client_secret);
  wtcrypto_expect_hex(
      "client_initial_secret",
      "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
      client_secret, 32);
  derive_label(initial_secret, "server in", 32, server_secret);
  wtcrypto_expect_hex(
      "server_initial_secret",
      "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b",
      server_secret, 32);

  derive_label(client_secret, "quic key", 16, key);
  derive_label(client_secret, "quic iv", 12, iv);
  derive_label(client_secret, "quic hp", 16, hp);
  wtcrypto_expect_hex("client initial key", "1f369613dd76d5467730efcbe3b1a22d",
                      key, 16);
  wtcrypto_expect_hex("client initial iv", "fa044b2f42a3fd3b46fb255c", iv, 12);
  wtcrypto_expect_hex("client initial hp", "9f50449e04a0e810283a1e9933adedd2",
                      hp, 16);

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
  wtcrypto_expect_int(
      "A.2 gcm encrypt", 0,
      wt_aes128_gcm_encrypt(key, nonce, WT_RFC9001_CLIENT_HEADER, 22, plaintext,
                            sizeof(plaintext), ciphertext, tag));

  /* The tag, over the payload the RFC actually protected. */
  /* The tag, over the payload the RFC actually protected. The expected value
     is the last 16 bytes of the RFC's protected packet, extracted by the
     generator rather than typed. */
  wtcrypto_expect("A.2 AEAD tag", WT_RFC9001_CLIENT_TAG, tag, 16);
  wtcrypto_expect("A.2 ciphertext matches the RFC's protected payload",
                  WT_RFC9001_CLIENT_PACKET + 22, ciphertext, 1162);

  /* Header protection: the sample is the first 16 bytes of the protected
     payload, and the mask is AES-ECB(hp, sample)[0..4]. */
  wtcrypto_expect("A.2 header protection sample", WT_RFC9001_CLIENT_PACKET + 22,
                  ciphertext, 16);
  /* The mask is AES-ECB(hp, sample)[0..4]. `wt_aes128_ecb_encrypt_block` is
     E(sample); the first version of this test compared the *keystream* E(0)
     against it, which is a different value that also looks like a mask. */
  {
    uint8_t zero_block[16];
    memset(zero_block, 0, sizeof(zero_block));
    wtcrypto_expect_int("A.2 aes-ecb of sample", 0,
                        wt_aes128_ecb_encrypt_block(hp, ciphertext, ecb));
    /* The block function is a block cipher, not a keystream: the RFC's mask is
       E(sample) = 437b9aec36..., and E(0) is a different value that also looks
       like a mask. Both are asserted so the distinction cannot regress
       silently. */
    {
      uint8_t e_zero[16];
      wtcrypto_expect_int("A.2 aes-ecb of zeros", 0,
                          wt_aes128_ecb_encrypt_block(hp, zero_block, e_zero));
      wtcrypto_expect_hex("A.2 AES-ECB(hp, 0) is the block encryption of zero",
                          "3c84e0abe1ade2049cf3770c8eefd2f4", e_zero, 16);
    }
    wtcrypto_expect_hex("A.2 mask from AES-ECB(hp, sample)", "437b9aec36", ecb,
                        5);
  }

  memcpy(protected_header, WT_RFC9001_CLIENT_HEADER, 22);
  protected_header[0] ^= (uint8_t)(ecb[0] & 0x0FU);
  protected_header[18] ^= ecb[1];
  protected_header[19] ^= ecb[2];
  protected_header[20] ^= ecb[3];
  protected_header[21] ^= ecb[4];
  wtcrypto_expect("A.2 protected header", WT_RFC9001_CLIENT_PACKET,
                  protected_header, 22);

  /* The server's Initial, same procedure, so the test is not passing because
     one hard-coded direction happens to line up. The second version of this
     derived from `client_initial` in place of `server_initial`, which fails
     all three values and looks like a derivation bug. */
  derive_label(server_secret, "quic key", 16, key);
  derive_label(server_secret, "quic iv", 12, iv);
  derive_label(server_secret, "quic hp", 16, hp);
  wtcrypto_expect_hex("server initial key", "cf3a5331653c364c88f0f379b6067e37",
                      key, 16);
  wtcrypto_expect_hex("server initial iv", "0ac1493ca1905853b0bba03e", iv, 12);
  wtcrypto_expect_hex("server initial hp", "c206b8d9b9f0f37644430b490eeaa314",
                      hp, 16);

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
    wtcrypto_expect_int("A.4 retry tag", 0,
                        wt_aes128_gcm_encrypt(retry_key, retry_nonce,
                                              retry_pseudo,
                                              sizeof(retry_pseudo), &zero_aad,
                                              0, &zero_aad, retry_tag));
    wtcrypto_expect("A.4 retry integrity tag", WT_RFC9001_RETRY_TAG, retry_tag,
                    16);
  }
}
