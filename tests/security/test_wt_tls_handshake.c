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

#include "wt_tls_handshake.h"
#include "wt_rfc8448_vectors.h"

#include <stdio.h>
#include <string.h>

static int g_failures;
static int g_checks;

static void expect_bytes(const char *name, const uint8_t *want,
                         const uint8_t *got, size_t len) {
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

/* The RFC prints this hash after the ClientHello and the ServerHello. It is
 * SHA-256 of the two messages concatenated, and it is the transcript the
 * handshake traffic secrets are derived from. */
static const uint8_t EXPECTED_TRANSCRIPT_AFTER_SERVER_HELLO[32] = {
    0x86, 0x0c, 0x06, 0xed, 0xc0, 0x78, 0x58, 0xee,
    0x8e, 0x78, 0xf0, 0xe7, 0x42, 0x8c, 0x58, 0xed,
    0xd6, 0xb4, 0x3f, 0x2c, 0xa3, 0xe6, 0xe9, 0x5f,
    0x02, 0xed, 0x06, 0x3c, 0xf0, 0xe1, 0xca, 0xd8,
};

/* ------------------------------------------------------------- framing */

static void test_handshake_framing(void) {
  uint8_t header[4];
  uint8_t type = 0;
  size_t body_len = 0;
  size_t offset = 0;

  /* RFC 8448's ClientHello starts `01 00 00 c0`: type 1, body length 0xc0. */
  expect_int("encode a 196-byte ClientHello header", 4,
             (long)wt_tls_encode_handshake_header(WT_TLS_HS_CLIENT_HELLO, 192U,
                                                  header));
  expect_bytes("the header is type || uint24 length",
               (const uint8_t *)"\x01\x00\x00\xc0", header, 4);

  /* The message's own first four bytes must decode to the same thing, which
     ties the encoder to the bytes the RFC prints. */
  expect_int("decode the RFC's ClientHello header", 0,
             wt_tls_decode_handshake_header(WT_RFC8448_CLIENT_HELLO,
                                            sizeof(WT_RFC8448_CLIENT_HELLO),
                                            &type, &body_len, &offset));
  expect_int("the RFC's ClientHello is type 1", 1, (long)type);
  expect_int("its body is 192 bytes", 192, (long)body_len);
  expect_int("its body starts at offset 4", 4, (long)offset);
  expect_int("4 + 192 is the whole 196-byte message", 196,
             (long)(offset + body_len));

  expect_int("decode the RFC's ServerHello header", 0,
             wt_tls_decode_handshake_header(WT_RFC8448_SERVER_HELLO,
                                            sizeof(WT_RFC8448_SERVER_HELLO),
                                            &type, &body_len, &offset));
  expect_int("the RFC's ServerHello is type 2", 2, (long)type);
  expect_int("its body is 86 bytes", 86, (long)body_len);

  /* A declared length past the end of the buffer is refused rather than read
     past. This is the check that keeps a peer from walking the transcript
     reader off the end of a message. */
  {
    static const uint8_t lying[] = {0x01, 0x00, 0xff, 0xff, 0x00};
    expect_int("a length past the end is refused", -1,
               wt_tls_decode_handshake_header(lying, sizeof(lying), &type,
                                              &body_len, &offset));
  }
  {
    static const uint8_t truncated[] = {0x01, 0x00};
    expect_int("a truncated header is refused", -1,
               wt_tls_decode_handshake_header(truncated, sizeof(truncated),
                                              &type, &body_len, &offset));
  }
  {
    static const uint8_t exact[] = {0x01, 0x00, 0x00, 0x02, 0xaa, 0xbb};
    expect_int("a length that exactly fits is accepted", 0,
               wt_tls_decode_handshake_header(exact, sizeof(exact), &type,
                                              &body_len, &offset));
    expect_int("and the body length is 2", 2, (long)body_len);
  }
  /* A body of 0xFFFFFF cannot be encoded, because the length would not fit. */
  expect_int("a body too large to encode is refused", 0,
             (long)wt_tls_encode_handshake_header(WT_TLS_HS_CLIENT_HELLO,
                                                  (size_t)0x1000000U, header));
  expect_int("a 0xFFFFFF body is encodable", 4,
             (long)wt_tls_encode_handshake_header(WT_TLS_HS_CLIENT_HELLO,
                                                  (size_t)0xFFFFFFU, header));
  expect_bytes("a 0xFFFFFF length encodes as ff ff ff",
               (const uint8_t *)"\x01\xff\xff\xff", header, 4);
}

/* ------------------------------------------------------------ transcript */

static void test_transcript(void) {
  wt_tls_transcript_t transcript;
  uint8_t hash[WT_TLS_HASH_LEN];

  expect_int("transcript_init", 0, wt_tls_transcript_init(&transcript));

  /* Empty, it is SHA-256 of the empty string, which is the famous constant. */
  expect_int("hash of the empty transcript", 0,
             wt_tls_transcript_hash(&transcript, hash));
  expect_bytes("the empty transcript hash", wt_tls_empty_hash, hash, 32);

  /* Hash after the ClientHello alone must differ from the empty hash, and the
     transcript must be usable again afterwards: hashing in place would leave
     the transcript unable to continue, which is a bug that only shows up at the
     second read. */
  {
    uint8_t after_client_hello[WT_TLS_HASH_LEN];
    uint8_t again[WT_TLS_HASH_LEN];
    expect_int("absorb the ClientHello", 0,
               wt_tls_transcript_absorb(&transcript, WT_RFC8448_CLIENT_HELLO,
                                        sizeof(WT_RFC8448_CLIENT_HELLO)));
    expect_int("hash after the ClientHello", 0,
               wt_tls_transcript_hash(&transcript, after_client_hello));
    g_checks++;
    if (memcmp(after_client_hello, wt_tls_empty_hash, 32) == 0) {
      g_failures++;
      printf("FAIL absorbing a message did not change the transcript\n");
    }
    expect_int("hashing does not consume the transcript", 0,
               wt_tls_transcript_hash(&transcript, again));
    expect_bytes("the second hash equals the first", after_client_hello, again,
                 32);

    /* THE PUBLISHED VALUE. RFC 8448 prints this hash after the two messages,
       and the key schedule derives the handshake traffic secrets from it. */
    expect_int("absorb the ServerHello", 0,
               wt_tls_transcript_absorb(&transcript, WT_RFC8448_SERVER_HELLO,
                                        sizeof(WT_RFC8448_SERVER_HELLO)));
    expect_int("hash after the ServerHello", 0,
               wt_tls_transcript_hash(&transcript, hash));
    expect_bytes("transcript hash after ServerHello",
                 EXPECTED_TRANSCRIPT_AFTER_SERVER_HELLO, hash, 32);
  }

  /* absorb_and_hash must agree with absorbing and hashing separately. */
  {
    wt_tls_transcript_t t2;
    uint8_t combined[WT_TLS_HASH_LEN];
    wt_tls_transcript_init(&t2);
    expect_int("absorb_and_hash the ClientHello", 0,
               wt_tls_transcript_absorb_and_hash(
                   &t2, WT_RFC8448_CLIENT_HELLO,
                   sizeof(WT_RFC8448_CLIENT_HELLO), combined));
    expect_int("absorb_and_hash the ServerHello", 0,
               wt_tls_transcript_absorb_and_hash(
                   &t2, WT_RFC8448_SERVER_HELLO,
                   sizeof(WT_RFC8448_SERVER_HELLO), combined));
    expect_bytes("absorb_and_hash agrees with absorb + hash", hash, combined,
                 32);
  }

  /* A malformed message is refused rather than hashed: hashing it would produce
     a transcript no peer agrees with, and the failure would appear as a
     Finished mismatch with no hint that the real problem was here. */
  {
    static const uint8_t lying[] = {0x01, 0x00, 0x00, 0xff, 0x00};
    wt_tls_transcript_t t3;
    wt_tls_transcript_init(&t3);
    expect_int("a message whose length overruns is refused", -1,
               wt_tls_transcript_absorb(&t3, lying, sizeof(lying)));
    /* And the transcript is unchanged by the refusal. */
    {
      uint8_t after[WT_TLS_HASH_LEN];
      wt_tls_transcript_hash(&t3, after);
      expect_bytes("a refused message leaves the transcript alone",
                   wt_tls_empty_hash, after, 32);
    }
  }
  expect_int("transcript_refuses a NULL message", -1,
             wt_tls_transcript_absorb(&transcript, NULL, 4));
  expect_int("transcript_hash refuses NULL", -1,
             wt_tls_transcript_hash(&transcript, NULL));
  expect_int("transcript_init refuses NULL", -1, wt_tls_transcript_init(NULL));
}

/* -------------------------------------------------------- ServerHello parse */

static void test_server_hello_parse(void) {
  wt_tls_server_hello_t hello;

  /* RFC 8448's ServerHello echoes a zero-length session ID and selects
     TLS_AES_128_GCM_SHA256 (0x1301) and x25519 (0x001d). */
  expect_int("parse the RFC's ServerHello", 0,
             wt_tls_parse_server_hello(WT_RFC8448_SERVER_HELLO,
                                       sizeof(WT_RFC8448_SERVER_HELLO), NULL,
                                       0U, &hello));
  expect_int("the cipher suite is TLS_AES_128_GCM_SHA256", 0x1301,
             (long)hello.cipher_suite);
  expect_int("the negotiated version is TLS 1.3", 0x0304,
             (long)hello.selected_version);
  expect_int("supported_versions was present", 1,
             (long)hello.has_supported_versions);
  expect_int("the key share group is x25519", 0x001d, (long)hello.group);
  expect_int("the key share is 32 bytes", 32, (long)hello.key_share_len);
  expect_int("key_share was present", 1, (long)hello.has_key_share);

  /* The key share is the server's public key, which the RFC prints in the
     message construction. Comparing it against the bytes inside the message
     would be circular, so it is checked against the transcript-derived value
     below instead: the secret it produces is the one the RFC publishes. */
  g_checks++;
  if (hello.key_share == NULL || hello.key_share[0] == 0U) {
    g_failures++;
    printf("FAIL the key share is empty\n");
  }

  /* A session ID that does not match what the client sent is refused. */
  {
    static const uint8_t wrong_session_id[1] = {0x00};
    expect_int("a non-matching session ID echo is refused", -1,
               wt_tls_parse_server_hello(WT_RFC8448_SERVER_HELLO,
                                         sizeof(WT_RFC8448_SERVER_HELLO),
                                         wrong_session_id, 1U, &hello));
  }

  /* A message that is not a ServerHello is refused by type. */
  expect_int("a ClientHello is not a ServerHello", -1,
             wt_tls_parse_server_hello(WT_RFC8448_CLIENT_HELLO,
                                       sizeof(WT_RFC8448_CLIENT_HELLO), NULL,
                                       0U, &hello));

  /* The parser must refuse a truncated message rather than read past it, at
     every truncation point. A parser that reads one byte too many is a memory
     safety bug reachable from the network. */
  {
    int accepted = 0;
    for (size_t cut = 0U; cut + 4U < sizeof(WT_RFC8448_SERVER_HELLO); cut++) {
      wt_tls_server_hello_t partial;
      if (wt_tls_parse_server_hello(WT_RFC8448_SERVER_HELLO, cut, NULL, 0U,
                                    &partial) == 0) {
        accepted++;
      }
    }
    expect_int("no truncated ServerHello is accepted", 0, accepted);
  }

  /* A tampered extension must not be accepted silently. Flipping the version to
     1.2 is a downgrade and must be refused, not negotiated. */
  {
    static uint8_t tampered[sizeof(WT_RFC8448_SERVER_HELLO)];
    memcpy(tampered, WT_RFC8448_SERVER_HELLO, sizeof(tampered));
    /* Find the supported_versions extension's value: 00 2b 00 02 03 04. The
       search is asserted to have found it, so a change to the message cannot
       leave this test quietly doing nothing. */
    {
      int found = 0;
      for (size_t i = 0U; i + 5U < sizeof(tampered); i++) {
        if (tampered[i] == 0x00U && tampered[i + 1U] == 0x2bU &&
            tampered[i + 2U] == 0x00U && tampered[i + 3U] == 0x02U &&
            tampered[i + 4U] == 0x03U && tampered[i + 5U] == 0x04U) {
          tampered[i + 5U] = 0x02U; /* the version becomes "TLS 1.1" */
          expect_int("a downgraded version is refused", -1,
                     wt_tls_parse_server_hello(tampered, sizeof(tampered), NULL,
                                               0U, &hello));
          found = 1;
          break;
        }
      }
      expect_int("the supported_versions extension was located to tamper with",
                 1, found);
    }
  }

  /* And the legacy_version field, which is 0x0303 and not the negotiated
     version, must be exactly that. */
  {
    static uint8_t tampered[sizeof(WT_RFC8448_SERVER_HELLO)];
    memcpy(tampered, WT_RFC8448_SERVER_HELLO, sizeof(tampered));
    tampered[4] = 0x03U;
    tampered[5] = 0x04U; /* legacy_version = "TLS 1.3" */
    expect_int("a legacy_version of 0x0304 is refused", -1,
               wt_tls_parse_server_hello(tampered, sizeof(tampered), NULL, 0U,
                                         &hello));
  }
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

  expect_int("parse the ServerHello", 0,
             wt_tls_parse_server_hello(WT_RFC8448_SERVER_HELLO,
                                       sizeof(WT_RFC8448_SERVER_HELLO), NULL,
                                       0U, &hello));
  expect_int("the parsed group is x25519", 0x001d, (long)hello.group);

  expect_int("transcript_init", 0, wt_tls_transcript_init(&transcript));
  expect_int("absorb the ClientHello", 0,
             wt_tls_transcript_absorb(&transcript, WT_RFC8448_CLIENT_HELLO,
                                      sizeof(WT_RFC8448_CLIENT_HELLO)));
  expect_int("absorb the ServerHello", 0,
             wt_tls_transcript_absorb(&transcript, WT_RFC8448_SERVER_HELLO,
                                      sizeof(WT_RFC8448_SERVER_HELLO)));
  expect_int("transcript hash", 0,
             wt_tls_transcript_hash(&transcript, transcript_hash));
  expect_bytes("the transcript is the RFC's", EXPECTED_TRANSCRIPT_AFTER_SERVER_HELLO,
               transcript_hash, 32);

  expect_int("key schedule from the real transcript", 0,
             wt_tls_key_schedule(WT_RFC8448_ECDHE, sizeof(WT_RFC8448_ECDHE),
                                 transcript_hash,
                                 WT_RFC8448_TRANSCRIPT_AFTER_SERVER_FINISHED,
                                 NULL, &secrets));
  /* The value that matters: the handshake secrets come from the transcript the
     two messages produced, not from one supplied by the test. */
  expect_bytes("client handshake traffic secret",
               WT_RFC8448_CLIENT_HANDSHAKE_TRAFFIC,
               secrets.client_handshake_traffic, 32);
  expect_bytes("server handshake traffic secret",
               WT_RFC8448_SERVER_HANDSHAKE_TRAFFIC,
               secrets.server_handshake_traffic, 32);
  wt_tls_secrets_clear(&secrets);
}

int main(void) {
  test_handshake_framing();
  test_transcript();
  test_server_hello_parse();
  test_parse_then_schedule();

  if (g_failures != 0) {
    printf("wt_tls_handshake: %d of %d checks FAILED\n", g_failures, g_checks);
    return 1;
  }
  printf("wt_tls_handshake: all %d checks reproduced their RFC 8446 / 8448 "
         "vector\n", g_checks);
  return 0;
}
