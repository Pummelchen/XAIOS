/* QUIC key derivation, checked against RFC 9001.
 *
 * This is one translation unit of the split TLS key-schedule test.
 * test_wt_tls.c is the driver and entry point and test_wt_tls_schedule.c owns
 * the TLS 1.3 schedule; this module owns the traffic keys, the Initial keys
 * and the Retry integrity tag. The check counters are defined in the schedule
 * module and declared `extern` in test_wt_tls_support.h.
 *
 * Every symbol that leaves this file carries the `wttls_` prefix.
 */

#include "test_wt_tls_support.h"

/* ---------------------------------------------------------- traffic keys */

void wttls_test_traffic_keys(void) {
  wt_tls_traffic_keys_t keys;

  /* RFC 9001 appendix A.5 prints all four values a traffic secret produces,
     including the key-update secret, so this checks the QUIC labels and the
     key update in one place. */
  wttls_expect_int("traffic keys", 0,
             wt_tls_traffic_keys(WT_RFC9001_CHACHA_SECRET,
                                 WT_TLS_AEAD_CHACHA20_POLY1305, &keys));
  /* The key is the AEAD's own length, so 32 here. The RFC prints it in A.5. */
  wttls_expect_hex("quic key (ChaCha20, 32 bytes)",
             "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8",
             keys.key, 32);
  wttls_expect_int("ChaCha20 key length", 32, (long)keys.key_len);
  wttls_expect_hex("quic iv", "e0459b3474bdd0e44a41c144", keys.iv, 12);
  wttls_expect_hex("quic hp",
             "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4",
             keys.hp, 32);
  wttls_expect_int("ChaCha20 hp length", 32, (long)keys.hp_len);
  wttls_expect_bytes("the secret is carried alongside its keys",
               WT_RFC9001_CHACHA_SECRET, keys.secret, 32);

  /* Key update: RFC 9001 section 6 and the "quic ku" value in A.5. The next
     keys come from the next secret, not from the current keys. */
  {
    wt_tls_traffic_keys_t next;
    wttls_expect_int("key update", 0, wt_tls_key_update(WT_RFC9001_CHACHA_SECRET,
                              WT_TLS_AEAD_CHACHA20_POLY1305, &next));
    wttls_expect_hex("quic ku",
               "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9",
               next.secret, 32);
    wttls_expect_int("the updated key is the same length as the original", 32,
               (long)next.key_len);
    wttls_checks++;
    if (memcmp(next.key, keys.key, 32) == 0) {
      wttls_failures++;
      printf("FAIL the key update produced the same key\n");
    }
    wt_tls_traffic_keys_clear(&next);
  }

  wttls_expect_int("traffic keys refuse NULL", -1,
             wt_tls_traffic_keys(NULL, WT_TLS_AEAD_AES_128_GCM, &keys));
  wttls_expect_int("traffic keys refuse an unknown AEAD", -1,
             wt_tls_traffic_keys(WT_RFC9001_CHACHA_SECRET, (wt_tls_aead_t)99,
                                 &keys));

  /* The handshake traffic secret from RFC 8448 produces QUIC keys that the RFC
     does not print (it prints TLS records, not QUIC packets). That the call
     succeeds and the three values differ from each other is all that can be
     said without a vector; the labels themselves are pinned by A.5 above. */
  {
    wt_tls_traffic_keys_t handshake_keys;
    wttls_expect_int("traffic keys from the handshake secret", 0,
               wt_tls_traffic_keys(WT_RFC8448_SERVER_HANDSHAKE_TRAFFIC,
                                   WT_TLS_AEAD_AES_128_GCM, &handshake_keys));
    wttls_checks++;
    if (memcmp(handshake_keys.key, handshake_keys.hp, 16) == 0) {
      wttls_failures++;
      printf("FAIL the key and the header protection key are identical\n");
    }
    wt_tls_traffic_keys_clear(&handshake_keys);
  }

  wt_tls_traffic_keys_clear(&keys);
  {
    /* Clearing must actually clear. */
    static const uint8_t zeroes[32] = {0};
    wt_tls_traffic_keys_t cleared;
    memset(&cleared, 0xAA, sizeof(cleared));
    wt_tls_traffic_keys_clear(&cleared);
    wttls_expect_bytes("traffic keys clear", zeroes, cleared.secret, 32);
  }
}

/* ----------------------------------------------------- QUIC Initial keys */

void wttls_test_initial_keys(void) {
  uint8_t initial_secret[WT_TLS_HASH_LEN];
  wt_tls_traffic_keys_t client;
  wt_tls_traffic_keys_t server;

  wttls_expect_int("initial secret", 0,
             wt_tls_initial_secret(WT_RFC9001_INITIAL_SALT,
                                   sizeof(WT_RFC9001_INITIAL_SALT),
                                   WT_RFC9001_DCID, sizeof(WT_RFC9001_DCID),
                                   initial_secret));
  wttls_expect_hex("initial_secret",
             "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44",
             initial_secret, 32);
  wttls_expect_bytes("the initial secret pin matches the RFC's printed key",
               WT_RFC9001_CLIENT_KEY, (const uint8_t *)"", 0);

  wttls_expect_int("client initial keys", 0,
             wt_tls_initial_traffic_keys(initial_secret, 0,
                                        WT_TLS_AEAD_AES_128_GCM, &client));
  wttls_expect_bytes("client initial key", WT_RFC9001_CLIENT_KEY, client.key, 16);
  wttls_expect_bytes("client initial iv", WT_RFC9001_CLIENT_IV, client.iv, 12);
  wttls_expect_bytes("client initial hp", WT_RFC9001_CLIENT_HP, client.hp, 16);
  wttls_expect_int("client initial hp length", 16, (long)client.hp_len);

  wttls_expect_int("server initial keys", 0,
             wt_tls_initial_traffic_keys(initial_secret, 1,
                                        WT_TLS_AEAD_AES_128_GCM, &server));
  wttls_expect_bytes("server initial key", WT_RFC9001_SERVER_KEY, server.key, 16);
  wttls_expect_bytes("server initial iv", WT_RFC9001_SERVER_IV, server.iv, 12);
  wttls_expect_bytes("server initial hp", WT_RFC9001_SERVER_HP, server.hp, 16);

  /* The two directions must differ. A function that ignored `from_server`
     would pass both sets only if the labels were also swapped, which is
     exactly the confusion this check exists for. */
  wttls_checks++;
  if (memcmp(client.key, server.key, 16) == 0) {
    wttls_failures++;
    printf("FAIL the client and server Initial keys are identical\n");
  }

  wt_tls_traffic_keys_clear(&client);
  wt_tls_traffic_keys_clear(&server);
}

/* ------------------------------------------------------- Retry integrity tag */

void wttls_test_retry_tag(void) {
  /* RFC 9001 section 5.8's fixed constants, not derived from anything. */
  static const uint8_t retry_key[16] = {
      0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
      0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
  };
  static const uint8_t retry_nonce[12] = {
      0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2,
      0x23, 0x98, 0x25, 0xbb,
  };
  uint8_t tag[16];
  /* The pseudo-packet is 1 + dcid_len + retry_len bytes and is built in the
     caller's buffer: see wt_tls.h for why there is no internal one. */
  static uint8_t scratch[600];

  wttls_expect_int("retry integrity tag", 0,
             wt_tls_retry_integrity_tag(retry_key, retry_nonce,
                                        WT_RFC9001_DCID, sizeof(WT_RFC9001_DCID),
                                        WT_RFC9001_RETRY_WITHOUT_TAG,
                                        sizeof(WT_RFC9001_RETRY_WITHOUT_TAG),
                                        scratch, sizeof(scratch), tag));
  wttls_expect_bytes("retry integrity tag", WT_RFC9001_RETRY_TAG, tag, 16);

  /* The whole Retry as it appears on the wire is the body plus the tag, and
     that is what appendix A.4 prints. */
  {
    uint8_t packet[sizeof(WT_RFC9001_RETRY_WITHOUT_TAG) + 16];
    memcpy(packet, WT_RFC9001_RETRY_WITHOUT_TAG,
           sizeof(WT_RFC9001_RETRY_WITHOUT_TAG));
    memcpy(packet + sizeof(WT_RFC9001_RETRY_WITHOUT_TAG), tag, 16);
    wttls_expect_bytes("the Retry on the wire", WT_RFC9001_RETRY_PACKET, packet,
                 sizeof(packet));
  }

  /* Verification, which is the half WT-1 was missing: the Swift
     implementation computed no tag at all, so it accepted a forged Retry. */
  wttls_expect_int("a valid Retry verifies", 1,
             wt_tls_verify_retry_integrity_tag(
                 retry_key, retry_nonce, WT_RFC9001_DCID,
                 sizeof(WT_RFC9001_DCID), WT_RFC9001_RETRY_PACKET,
                 sizeof(WT_RFC9001_RETRY_PACKET), scratch, sizeof(scratch)));

  {
    /* Every single-bit change to the tag must be refused. A comparison that
       checked only the first byte would accept 15 of these. */
    uint8_t forged[sizeof(WT_RFC9001_RETRY_PACKET)];
    int accepted = 0;
    memcpy(forged, WT_RFC9001_RETRY_PACKET, sizeof(forged));
    for (size_t bit = 0U; bit < 16U * 8U; bit++) {
      memcpy(forged, WT_RFC9001_RETRY_PACKET, sizeof(forged));
      forged[sizeof(forged) - 1U - bit / 8U] ^= (uint8_t)(1U << (bit % 8U));
      if (wt_tls_verify_retry_integrity_tag(retry_key, retry_nonce,
                                            WT_RFC9001_DCID,
                                            sizeof(WT_RFC9001_DCID), forged,
                                            sizeof(forged), scratch,
                                            sizeof(scratch)) != 0) {
        accepted++;
      }
    }
    wttls_expect_int("all 128 single-bit tag forgeries are refused", 0, accepted);
  }

  {
    /* A Retry answered to a different original connection ID must not verify:
       that is the whole reason the pseudo-packet carries the ODCID. */
    uint8_t other_dcid[8];
    memcpy(other_dcid, WT_RFC9001_DCID, 8);
    other_dcid[7] ^= 0x01U;
    wttls_expect_int("a Retry for another connection is refused", 0,
               wt_tls_verify_retry_integrity_tag(
                   retry_key, retry_nonce, other_dcid, sizeof(other_dcid),
                   WT_RFC9001_RETRY_PACKET, sizeof(WT_RFC9001_RETRY_PACKET),
                   scratch, sizeof(scratch)));
  }

  {
    /* A modified Server Connection ID is inside the pseudo-packet, so it must
       be refused too. */
    uint8_t forged[sizeof(WT_RFC9001_RETRY_PACKET)];
    memcpy(forged, WT_RFC9001_RETRY_PACKET, sizeof(forged));
    forged[11] ^= 0x01U; /* a byte of the SCID */
    wttls_expect_int("a Retry with a modified body is refused", 0,
               wt_tls_verify_retry_integrity_tag(
                   retry_key, retry_nonce, WT_RFC9001_DCID,
                   sizeof(WT_RFC9001_DCID), forged, sizeof(forged), scratch,
                   sizeof(scratch)));
  }

  wttls_expect_int("verify refuses a short packet", -1,
             wt_tls_verify_retry_integrity_tag(retry_key, retry_nonce,
                                               WT_RFC9001_DCID, 8,
                                               WT_RFC9001_RETRY_PACKET, 8,
                                               scratch, sizeof(scratch)));
  wttls_expect_int("tag refuses NULL key", -1,
             wt_tls_retry_integrity_tag(NULL, retry_nonce, WT_RFC9001_DCID, 8,
                                        WT_RFC9001_RETRY_WITHOUT_TAG,
                                        sizeof(WT_RFC9001_RETRY_WITHOUT_TAG),
                                        scratch, sizeof(scratch), tag));

  /* THE OVERFLOW REGRESSION. A Retry whose token makes the pseudo-packet
     larger than the caller's buffer must be refused, not written past the end.
     The first version of this function had a 256-byte local buffer and copied
     an unbounded `retry_len` into it, which a peer could drive from an
     unauthenticated Retry -- QUIC tokens are routinely hundreds of bytes. Under
     ASan this test is what catches that; without it, the failure is a stack
     smash in the packet receive path. */
  {
    static uint8_t huge_retry[600];
    static uint8_t small_scratch[64];
    memset(huge_retry, 0x5A, sizeof(huge_retry));
    wttls_expect_int("a Retry larger than the caller's buffer is refused", -1,
               wt_tls_verify_retry_integrity_tag(
                   retry_key, retry_nonce, WT_RFC9001_DCID,
                   sizeof(WT_RFC9001_DCID), huge_retry, sizeof(huge_retry),
                   small_scratch, sizeof(small_scratch)));
    wttls_expect_int("a pseudo-packet larger than the caller's buffer is refused", -1,
               wt_tls_retry_integrity_tag(
                   retry_key, retry_nonce, WT_RFC9001_DCID,
                   sizeof(WT_RFC9001_DCID), huge_retry, sizeof(huge_retry),
                   small_scratch, sizeof(small_scratch), tag));
  }
  {
    /* A connection ID longer than 20 bytes cannot occur on the wire, and the
       length byte cannot hold it. */
    static uint8_t long_dcid[21];
    wttls_expect_int("tag refuses an over-long connection ID", -1,
               wt_tls_retry_integrity_tag(retry_key, retry_nonce, long_dcid, 21,
                                          WT_RFC9001_RETRY_WITHOUT_TAG,
                                          sizeof(WT_RFC9001_RETRY_WITHOUT_TAG),
                                          scratch, sizeof(scratch), tag));
    wttls_expect_int("tag refuses a NULL scratch with a non-zero length", -1,
               wt_tls_retry_integrity_tag(retry_key, retry_nonce,
                                          WT_RFC9001_DCID, 8,
                                          WT_RFC9001_RETRY_WITHOUT_TAG,
                                          sizeof(WT_RFC9001_RETRY_WITHOUT_TAG),
                                          NULL, 64U, tag));
  }
}
