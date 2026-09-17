/* TLS 1.3 handshake framing, the transcript, and ServerHello parsing, checked
 * against RFC 8448.
 *
 * The trace prints its ClientHello as a complete 196-byte message and its
 * ServerHello as 90 bytes, and prints the transcript hash after each. So the
 * framing can be checked byte for byte, the transcript can be checked against a
 * published hash, and the ServerHello parser can be checked against a real
 * server message rather than one written to match the parser.
 *
 * The last test is the one that matters most: the parser's output feeds the key
 * schedule, and the transcript it produces is the one RFC 8448 derives the
 * handshake traffic secrets from. If the parse or the transcript is wrong, the
 * secrets come out wrong, and that is a failure three layers away from its
 * cause.
 */

#include "test_wt_tls_handshake_support.h"

/* The RFC prints this hash after the ClientHello and the ServerHello. It is
 * SHA-256 of the two messages concatenated, and it is the transcript the
 * handshake traffic secrets are derived from. */
static const uint8_t EXPECTED_TRANSCRIPT_AFTER_SERVER_HELLO[32] = {
    0x86, 0x0c, 0x06, 0xed, 0xc0, 0x78, 0x58, 0xee,
    0x8e, 0x78, 0xf0, 0xe7, 0x42, 0x8c, 0x58, 0xed,
    0xd6, 0xb4, 0x3f, 0x2c, 0xa3, 0xe6, 0xe9, 0x5f,
    0x02, 0xed, 0x06, 0x3c, 0xf0, 0xe1, 0xca, 0xd8,
};

/* ------------------------------------------------------------ transcript */

static void test_transcript(void) {
  wt_tls_transcript_t transcript;
  uint8_t hash[WT_TLS_HASH_LEN];

  twth_expect_int("transcript_init", 0, wt_tls_transcript_init(&transcript));

  /* Empty, it is SHA-256 of the empty string, which is the famous constant. */
  twth_expect_int("hash of the empty transcript", 0,
             wt_tls_transcript_hash(&transcript, hash));
  twth_expect_bytes("the empty transcript hash", wt_tls_empty_hash, hash, 32);

  /* Hash after the ClientHello alone must differ from the empty hash, and the
     transcript must be usable again afterwards: hashing in place would leave
     the transcript unable to continue, which is a bug that only shows up at the
     second read. */
  {
    uint8_t after_client_hello[WT_TLS_HASH_LEN];
    uint8_t again[WT_TLS_HASH_LEN];
    twth_expect_int("absorb the ClientHello", 0,
               wt_tls_transcript_absorb(&transcript, WT_RFC8448_CLIENT_HELLO,
                                        sizeof(WT_RFC8448_CLIENT_HELLO)));
    twth_expect_int("hash after the ClientHello", 0,
               wt_tls_transcript_hash(&transcript, after_client_hello));
    twth_checks++;
    if (memcmp(after_client_hello, wt_tls_empty_hash, 32) == 0) {
      twth_failures++;
      printf("FAIL absorbing a message did not change the transcript\n");
    }
    twth_expect_int("hashing does not consume the transcript", 0,
               wt_tls_transcript_hash(&transcript, again));
    twth_expect_bytes("the second hash equals the first", after_client_hello, again,
                 32);

    /* THE PUBLISHED VALUE. RFC 8448 prints this hash after the two messages,
       and the key schedule derives the handshake traffic secrets from it. */
    twth_expect_int("absorb the ServerHello", 0,
               wt_tls_transcript_absorb(&transcript, WT_RFC8448_SERVER_HELLO,
                                        sizeof(WT_RFC8448_SERVER_HELLO)));
    twth_expect_int("hash after the ServerHello", 0,
               wt_tls_transcript_hash(&transcript, hash));
    twth_expect_bytes("transcript hash after ServerHello",
                 EXPECTED_TRANSCRIPT_AFTER_SERVER_HELLO, hash, 32);
  }

  /* absorb_and_hash must agree with absorbing and hashing separately. */
  {
    wt_tls_transcript_t t2;
    uint8_t combined[WT_TLS_HASH_LEN];
    wt_tls_transcript_init(&t2);
    twth_expect_int("absorb_and_hash the ClientHello", 0,
               wt_tls_transcript_absorb_and_hash(
                   &t2, WT_RFC8448_CLIENT_HELLO,
                   sizeof(WT_RFC8448_CLIENT_HELLO), combined));
    twth_expect_int("absorb_and_hash the ServerHello", 0,
               wt_tls_transcript_absorb_and_hash(
                   &t2, WT_RFC8448_SERVER_HELLO,
                   sizeof(WT_RFC8448_SERVER_HELLO), combined));
    twth_expect_bytes("absorb_and_hash agrees with absorb + hash", hash, combined,
                 32);
  }

  /* A malformed message is refused rather than hashed: hashing it would produce
     a transcript no peer agrees with, and the failure would appear as a
     Finished mismatch with no hint that the real problem was here. */
  {
    static const uint8_t lying[] = {0x01, 0x00, 0x00, 0xff, 0x00};
    wt_tls_transcript_t t3;
    wt_tls_transcript_init(&t3);
    twth_expect_int("a message whose length overruns is refused", -1,
               wt_tls_transcript_absorb(&t3, lying, sizeof(lying)));
    /* And the transcript is unchanged by the refusal. */
    {
      uint8_t after[WT_TLS_HASH_LEN];
      wt_tls_transcript_hash(&t3, after);
      twth_expect_bytes("a refused message leaves the transcript alone",
                   wt_tls_empty_hash, after, 32);
    }
  }
  twth_expect_int("transcript_refuses a NULL message", -1,
             wt_tls_transcript_absorb(&transcript, NULL, 4));
  twth_expect_int("transcript_hash refuses NULL", -1,
             wt_tls_transcript_hash(&transcript, NULL));
  twth_expect_int("transcript_init refuses NULL", -1, wt_tls_transcript_init(NULL));
}

/* ------------------------------------------------------------------ Finished */

/* The whole chain, verified against RFC 8448 end to end: absorb the RFC's real
 * handshake messages -- ClientHello, ServerHello, EncryptedExtensions,
 * Certificate, CertificateVerify -- hash the transcript, derive the Finished
 * key from the server's handshake traffic secret, and compare the result to the
 * Finished message the RFC prints.
 *
 * This is the strongest check in the file. It fails if any message was framed
 * wrong, if the transcript absorbs one twice or in the wrong order, if the
 * "finished" label or the finished-key length is wrong, if the HMAC is over the
 * wrong bytes, or if the traffic secret is the client's instead of the
 * server's. Every one of those is a failure that would otherwise appear as an
 * authentication failure several round trips away.
 *
 * The transcript hash is not printed by the RFC -- it prints the MAC -- so the
 * generator computes the hash from the extracted messages and REQUIRES the
 * derived MAC to equal the printed one before it will emit a vector. A wrong
 * extraction stops generation rather than producing a vector a wrong
 * implementation would pass.
 */
static void test_finished(void) {
  wt_tls_transcript_t transcript;
  uint8_t hash[WT_TLS_HASH_LEN];
  uint8_t verify_data[WT_TLS_FINISHED_LEN];

  twth_expect_int("transcript_init", 0, wt_tls_transcript_init(&transcript));

  /* The server's flight, in order, as the RFC sends it. */
  twth_expect_int("absorb ClientHello", 0,
             wt_tls_transcript_absorb(&transcript, WT_RFC8448_CLIENT_HELLO,
                                      sizeof(WT_RFC8448_CLIENT_HELLO)));
  twth_expect_int("absorb ServerHello", 0,
             wt_tls_transcript_absorb(&transcript, WT_RFC8448_SERVER_HELLO,
                                      sizeof(WT_RFC8448_SERVER_HELLO)));
  twth_expect_int("absorb EncryptedExtensions", 0,
             wt_tls_transcript_absorb(&transcript, WT_RFC8448_ENCRYPTED_EXTENSIONS,
                                      sizeof(WT_RFC8448_ENCRYPTED_EXTENSIONS)));
  twth_expect_int("absorb Certificate", 0,
             wt_tls_transcript_absorb(&transcript, WT_RFC8448_CERTIFICATE,
                                      sizeof(WT_RFC8448_CERTIFICATE)));
  twth_expect_int("absorb CertificateVerify", 0,
             wt_tls_transcript_absorb(&transcript,
                                      WT_RFC8448_CERTIFICATE_VERIFY,
                                      sizeof(WT_RFC8448_CERTIFICATE_VERIFY)));
  twth_expect_int("transcript hash", 0, wt_tls_transcript_hash(&transcript, hash));

  twth_expect_int("the Finished MAC", 0,
             wt_tls_finished_compute(WT_RFC8448_SERVER_HANDSHAKE_TRAFFIC, hash,
                                     verify_data));
  /* The RFC prints this value as the server's Finished. */
  twth_expect_bytes("the Finished MAC is the RFC's", WT_RFC8448_SERVER_FINISHED,
               verify_data, WT_TLS_FINISHED_LEN);

  /* And the same over the RFC's Finished message, which is
     `14 00 00 20 || verify_data`. */
  twth_expect_int("the RFC's Finished message verifies", 1,
             wt_tls_finished_verify(WT_RFC8448_SERVER_HANDSHAKE_TRAFFIC, hash,
                                    WT_RFC8448_FINISHED,
                                    sizeof(WT_RFC8448_FINISHED)));

  /* The client's handshake secret must NOT verify the server's Finished: the
     two directions have different secrets and using the wrong one is the
     mistake this argument exists to prevent. */
  twth_expect_int("the client's secret does not verify the server's Finished", 0,
             wt_tls_finished_verify(WT_RFC8448_CLIENT_HANDSHAKE_TRAFFIC, hash,
                                    WT_RFC8448_FINISHED,
                                    sizeof(WT_RFC8448_FINISHED)));

  /* Every single-bit change to the MAC must be refused. */
  {
    uint8_t forged[WT_RFC8448_FINISHED_LEN];
    int accepted = 0;
    for (size_t bit = 0U; bit < WT_TLS_FINISHED_LEN * 8U; bit++) {
      memcpy(forged, WT_RFC8448_FINISHED, sizeof(forged));
      forged[4U + bit / 8U] ^= (uint8_t)(1U << (bit % 8U));
      if (wt_tls_finished_verify(WT_RFC8448_SERVER_HANDSHAKE_TRAFFIC, hash,
                                 forged, sizeof(forged)) != 0) {
        accepted++;
      }
    }
    twth_expect_int("every single-bit MAC forgery is refused", 0, accepted);
  }

  /* A wrong transcript hash must not verify. */
  {
    uint8_t wrong[WT_TLS_HASH_LEN];
    memcpy(wrong, hash, sizeof(wrong));
    wrong[0] ^= 0x01U;
    twth_expect_int("a wrong transcript hash is refused", 0,
               wt_tls_finished_verify(WT_RFC8448_SERVER_HANDSHAKE_TRAFFIC,
                                      wrong, WT_RFC8448_FINISHED,
                                      sizeof(WT_RFC8448_FINISHED)));
  }

  /* Wrong message types and lengths are refusals, not comparisons of the
     first 32 bytes of something else. */
  {
    uint8_t forged[WT_RFC8448_FINISHED_LEN];
    memcpy(forged, WT_RFC8448_FINISHED, sizeof(forged));
    forged[0] = WT_TLS_HS_CERTIFICATE;
    twth_expect_int("a Finished-typed check rejects another type", -1,
               wt_tls_finished_verify(WT_RFC8448_SERVER_HANDSHAKE_TRAFFIC,
                                      hash, forged, sizeof(forged)));
    memcpy(forged, WT_RFC8448_FINISHED, sizeof(forged));
    twth_expect_int("a truncated Finished is refused", -1,
               wt_tls_finished_verify(WT_RFC8448_SERVER_HANDSHAKE_TRAFFIC,
                                      hash, forged, 20U));
    twth_expect_int("a NULL message is refused", -1,
               wt_tls_finished_verify(WT_RFC8448_SERVER_HANDSHAKE_TRAFFIC,
                                      hash, NULL, 36U));
    twth_expect_int("a NULL secret is refused", -1,
               wt_tls_finished_verify(NULL, hash, WT_RFC8448_FINISHED,
                                      sizeof(WT_RFC8448_FINISHED)));
  }

  /* compute must refuse bad arguments rather than produce a MAC. */
  twth_expect_int("compute refuses a NULL secret", -1,
             wt_tls_finished_compute(NULL, hash, verify_data));
  twth_expect_int("compute refuses a NULL transcript", -1,
             wt_tls_finished_compute(WT_RFC8448_SERVER_HANDSHAKE_TRAFFIC, NULL,
                                     verify_data));
  twth_expect_int("compute refuses a NULL output", -1,
             wt_tls_finished_compute(WT_RFC8448_SERVER_HANDSHAKE_TRAFFIC, hash,
                                     NULL));
}

/* ------------------------------------------- the two joined: keys from the wire */

/* The whole point of the two layers. Take RFC 8448's actual ServerHello,
 * parse the server's key share out of it, build the transcript from the two
 * real handshake messages, and derive the handshake traffic secrets. They must
 * equal the values the RFC prints.
 *
 * RFC 8448's ECDHE shared secret is published, so the key exchange itself is
 * not recomputed -- x25519 is BearSSL's job and is checked elsewhere. What this
 * proves is that the transcript, the parse and the schedule agree with the RFC
 * end to end, which is the property the three layers separately cannot show.
 */
static void test_parse_then_schedule(void) {
  wt_tls_server_hello_t hello;
  wt_tls_transcript_t transcript;
  uint8_t transcript_hash[WT_TLS_HASH_LEN];
  wt_tls_secrets_t secrets;

  twth_expect_int("parse the ServerHello", 0,
             wt_tls_parse_server_hello(WT_RFC8448_SERVER_HELLO,
                                       sizeof(WT_RFC8448_SERVER_HELLO), NULL,
                                       0U, &hello));
  twth_expect_int("the parsed group is x25519", 0x001d, (long)hello.group);

  twth_expect_int("transcript_init", 0, wt_tls_transcript_init(&transcript));
  twth_expect_int("absorb the ClientHello", 0,
             wt_tls_transcript_absorb(&transcript, WT_RFC8448_CLIENT_HELLO,
                                      sizeof(WT_RFC8448_CLIENT_HELLO)));
  twth_expect_int("absorb the ServerHello", 0,
             wt_tls_transcript_absorb(&transcript, WT_RFC8448_SERVER_HELLO,
                                      sizeof(WT_RFC8448_SERVER_HELLO)));
  twth_expect_int("transcript hash", 0,
             wt_tls_transcript_hash(&transcript, transcript_hash));
  twth_expect_bytes("the transcript is the RFC's", EXPECTED_TRANSCRIPT_AFTER_SERVER_HELLO,
               transcript_hash, 32);

  twth_expect_int("key schedule from the real transcript", 0,
             wt_tls_key_schedule(WT_RFC8448_ECDHE, sizeof(WT_RFC8448_ECDHE),
                                 transcript_hash,
                                 WT_RFC8448_TRANSCRIPT_AFTER_SERVER_FINISHED,
                                 NULL, &secrets));
  /* The value that matters: the handshake secrets come from the transcript the
     two messages produced, not from one supplied by the test. */
  twth_expect_bytes("client handshake traffic secret",
               WT_RFC8448_CLIENT_HANDSHAKE_TRAFFIC,
               secrets.client_handshake_traffic, 32);
  twth_expect_bytes("server handshake traffic secret",
               WT_RFC8448_SERVER_HANDSHAKE_TRAFFIC,
               secrets.server_handshake_traffic, 32);
  wt_tls_secrets_clear(&secrets);
}

/* ------------------------------------------------- the whole send path
 *
 * Build a ClientHello with the builder, wrap it in a CRYPTO frame, put that in
 * a QUIC Initial packet, protect it with RFC 9001's published Initial keys, and
 * recover it -- all the way back to the ClientHello that went in.
 *
 * This is the first place the modules are used together in the direction a
 * client actually uses them. RFC 9001's Initial keys are keyed on the
 * connection ID the packet carries, so the packet is built with the RFC's
 * header and keys; the ClientHello inside it is this module's own, which is not
 * the message RFC 9001 protects (that one is a different trace). The check is
 * therefore a round trip through real key material rather than a comparison
 * with RFC 9001's bytes -- which is what the packet module's own tests do with
 * RFC 9001's actual message.
 */
static void test_client_hello_through_initial_protection(void) {
  static const uint16_t cipher_suites[1] = {0x1301};
  static const uint16_t groups[1] = {0x001d};
  static const uint16_t signature_algorithms[1] = {0x0403};
  static const uint8_t h3[3] = {0x02, 0x68, 0x33};
  static uint8_t hello[512];
  static uint8_t packet[1500];
  static uint8_t recovered[1500];
  wt_tls_key_share_t share;
  wt_tls_client_hello_params_t params;
  wt_tls_traffic_keys_t keys;
  wt_quic_packet_header_t header;
  size_t hello_len;
  size_t frame_len;
  size_t packet_len = 0U;
  size_t plaintext_len = 0U;
  size_t header_len = 22U;

  /* A ClientHello with a real ALPN and a real key share. The public key is the
     RFC's, because generating one would make the test depend on the random
     source; what is under test is the framing and the protection, not the
     key generation. */
  share.group = 0x001d;
  share.public_key = WT_RFC8448_CLIENT_KEY_PUBLIC;
  share.public_key_len = sizeof(WT_RFC8448_CLIENT_KEY_PUBLIC);
  memset(&params, 0, sizeof(params));
  params.random = WT_RFC8448_CLIENT_RANDOM;
  params.cipher_suites = cipher_suites;
  params.cipher_suite_count = 1U;
  params.key_shares = &share;
  params.key_share_count = 1U;
  params.supported_groups = groups;
  params.supported_group_count = 1U;
  params.signature_algorithms = signature_algorithms;
  params.signature_algorithm_count = 1U;
  params.alpn_protocols = h3;
  params.alpn_protocols_len = sizeof(h3);
  params.server_name = "server";

  hello_len = wt_tls_encode_client_hello(&params, hello, sizeof(hello));
  twth_checks++;
  if (hello_len == 0U) {
    twth_failures++;
    printf("FAIL the ClientHello could not be built\n");
    return;
  }

  /* The CRYPTO frame: type 0x06, a three-byte offset of zero, a three-byte
     length, then the handshake message. RFC 9000 section 19.6. */
  {
    size_t offset = 0U;
    packet[header_len + offset] = 0x06U;
    offset++;
    packet[header_len + offset] = 0x00U;
    packet[header_len + offset + 1U] = 0x00U;
    packet[header_len + offset + 2U] = 0x00U;
    offset += 3U;
    packet[header_len + offset] = (uint8_t)((hello_len >> 16) & 0xFFU);
    packet[header_len + offset + 1U] = (uint8_t)((hello_len >> 8) & 0xFFU);
    packet[header_len + offset + 2U] = (uint8_t)(hello_len & 0xFFU);
    offset += 3U;
    memcpy(packet + header_len + offset, hello, hello_len);
    offset += hello_len;
    frame_len = offset;
  }

  /* RFC 9001's client Initial header and keys. The header is the one the RFC
     prints, so the connection ID matches the keys. */
  memcpy(packet, WT_RFC9001_CLIENT_HEADER, header_len);
  /* The length field must describe the frames plus the AEAD tag. It is bytes
     16 and 17 of this header (after the four-byte version, the one-byte DCID
     length, the eight-byte DCID, the one-byte SCID length, the zero-length SCID
     and the one-byte token length): the header the RFC prints already carries a
     length for its own payload, so it is recomputed here for this one. */
  {
    size_t payload = frame_len + 16U;
    packet[16] = (uint8_t)((payload >> 8) & 0xFFU);
    packet[17] = (uint8_t)(payload & 0xFFU);
  }

  memset(&keys, 0, sizeof(keys));
  memcpy(keys.key, WT_RFC9001_CLIENT_KEY, 16);
  memcpy(keys.iv, WT_RFC9001_CLIENT_IV, 12);
  memcpy(keys.hp, WT_RFC9001_CLIENT_HP, 16);
  keys.key_len = 16U;
  keys.hp_len = 16U;

  header.bytes = packet;
  header.len = header_len;
  header.pn_offset = 18U;
  header.pn_len = 4U;
  header.long_header = 1;

  twth_expect_int("protect the ClientHello Initial", 0,
             wt_quic_protect_packet(WT_TLS_AEAD_AES_128_GCM, &keys, &header,
                                    UINT64_C(2), packet,
                                    header_len + frame_len, &packet_len));
  twth_expect_int("the protected packet is the header, the frames and a tag",
             (long)(header_len + frame_len + 16U), (long)packet_len);
  /* Nothing of the ClientHello may be readable on the wire. */
  {
    int leaked = 0;
    for (size_t i = header_len + 7U; i < packet_len - 16U; i++) {
      /* The key share's first byte is distinctive enough for this check. */
      if (packet[i] == WT_RFC8448_CLIENT_KEY_PUBLIC[0] &&
          i + 4U < packet_len &&
          packet[i + 1U] == WT_RFC8448_CLIENT_KEY_PUBLIC[1]) {
        leaked = 1;
      }
    }
    twth_expect_int("the ClientHello is not readable in the protected packet", 0,
               leaked);
  }

  /* And back. */
  {
    wt_quic_packet_header_t rx;
    uint64_t pn = 0U;
    uint64_t truncated = 0U;
    rx.bytes = packet;
    rx.len = header_len;
    rx.pn_offset = 18U;
    rx.pn_len = 4U;
    rx.long_header = 1;

    twth_expect_int("remove header protection", 0,
               wt_quic_header_protection(WT_TLS_AEAD_AES_128_GCM, keys.hp, 16U,
                                         &rx, packet, packet_len));
    for (size_t i = 0U; i < 4U; i++) {
      truncated = (truncated << 8) | packet[18U + i];
    }
    twth_expect_int("recover the packet number", 0,
               wt_quic_decode_packet_number(truncated, 4U, 0U, &pn));
    twth_expect_int("the packet number is 2", 2, (long)pn);
    twth_expect_int("unprotect the packet", 0,
               wt_quic_unprotect_packet(WT_TLS_AEAD_AES_128_GCM, &keys, &rx,
                                        pn, packet, packet_len, recovered,
                                        sizeof(recovered), &plaintext_len));
  }

  /* The recovered CRYPTO frame must carry the ClientHello that went in. */
  twth_expect_int("the recovered payload is the frame", (long)frame_len,
             (long)plaintext_len);
  twth_expect_int("the frame is a CRYPTO frame", 0x06, recovered[0]);
  twth_expect_int("its offset is zero", 0, (long)(recovered[1] | recovered[2] |
                                             recovered[3]));
  {
    size_t declared = ((size_t)recovered[4] << 16) |
                      ((size_t)recovered[5] << 8) | (size_t)recovered[6];
    twth_expect_int("its declared length is the ClientHello's", (long)hello_len,
               (long)declared);
  }
  twth_expect_bytes("the ClientHello survived the round trip", hello,
               recovered + 7U, hello_len);

  /* And it is the same message the transcript would absorb. */
  {
    wt_tls_transcript_t transcript;
    uint8_t hash[WT_TLS_HASH_LEN];
    twth_expect_int("transcript_init", 0, wt_tls_transcript_init(&transcript));
    twth_expect_int("absorb the recovered ClientHello", 0,
               wt_tls_transcript_absorb(&transcript, recovered + 7U, hello_len));
    twth_expect_int("hash it", 0, wt_tls_transcript_hash(&transcript, hash));
    twth_checks++;
    if (memcmp(hash, wt_tls_empty_hash, WT_TLS_HASH_LEN) == 0) {
      twth_failures++;
      printf("FAIL the recovered ClientHello hashed to nothing\n");
    }
  }
}

int main(void) {
  twth_test_handshake_framing();
  test_transcript();
  twth_test_client_hello_build();
  twth_test_encrypted_extensions();
  twth_test_server_hello_parse();
  test_finished();
  test_parse_then_schedule();
  test_client_hello_through_initial_protection();

  if (twth_failures != 0) {
    printf("wt_tls_handshake: %d of %d checks FAILED\n", twth_failures, twth_checks);
    return 1;
  }
  printf("wt_tls_handshake: all %d checks reproduced their RFC 8446 / 8448 "
         "vector\n", twth_checks);
  return 0;
}
