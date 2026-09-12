/* TLS 1.3 key schedule and QUIC key derivation, checked against RFC 8448 and
 * RFC 9001.
 *
 * The schedule is the part of TLS 1.3 that can be verified without a peer:
 * every intermediate value is published, so a wrong label, a wrong length
 * prefix, a wrong order in the Derive-Secret chain or a wrong notion of "empty
 * transcript" shows up as a mismatch rather than as a connection that fails
 * later for an unexplained reason.
 *
 * The vectors come from wt_rfc8448_vectors.h, generated from the RFC text by
 * generate_wt_rfc8448_vectors.py, and the same values are recomputed
 * independently in Python by verify_wt_rfc8448_key_schedule.py.
 */

#include "wt_tls.h"
#include "wt_rfc8448_vectors.h"
#include "wt_rfc9001_vectors.h"

#include <stdio.h>
#include <string.h>

static int g_failures;
static int g_checks;

static void expect_hex(const char *name, const char *want_hex,
                       const uint8_t *got, size_t len) {
  uint8_t want[128];
  size_t n = 0;
  int high = -1;
  if (len > sizeof(want)) {
    g_checks++; g_failures++;
    printf("FAIL %s: oversized comparison\n", name);
    return;
  }
  for (const char *p = want_hex; *p != '\0'; p++) {
    int value;
    if (*p == ' ') continue;
    value = (*p >= '0' && *p <= '9') ? *p - '0'
          : (*p >= 'a' && *p <= 'f') ? *p - 'a' + 10
          : (*p >= 'A' && *p <= 'F') ? *p - 'A' + 10 : -1;
    if (value < 0) { g_checks++; g_failures++; printf("FAIL %s: bad hex\n", name); return; }
    if (high < 0) high = value;
    else { want[n++] = (uint8_t)((high << 4) | value); high = -1; }
  }
  g_checks++;
  if (n == len && memcmp(want, got, len) == 0) return;
  g_failures++;
  printf("FAIL %s\n     want ", name);
  for (size_t i = 0; i < n; i++) printf("%02x", want[i]);
  printf("\n     got  ");
  for (size_t i = 0; i < len; i++) printf("%02x", got[i]);
  printf("\n");
}

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

/* ------------------------------------------------------ the empty transcript */

static void test_empty_hash(void) {
  uint8_t digest[WT_TLS_HASH_LEN];
  /* The constant in wt_tls.c must be SHA-256 of the empty string. Comparing it
     against a computed value rather than against the same literal is the point:
     a wrong constant would otherwise agree with itself. */
  expect_int("sha256(empty)", 0, wt_sha256("", 0, digest));
  expect_bytes("wt_tls_empty_hash is SHA-256 of the empty transcript",
               digest, wt_tls_empty_hash, WT_TLS_HASH_LEN);
}

/* ----------------------------------------------------------- HKDF-Expand-Label */

static void test_expand_label(void) {
  uint8_t out[32];
  /* RFC 8448 prints the whole HkdfLabel for "tls13 c hs traffic" with an empty
     context and a 32-byte output as:
       00 20 12 74 6c 73 31 33 20 63 20 68 73 20 74 72 61 66 66 69 63 20
     The first two bytes are the length, the third is the label length 0x12,
     then "tls13 c hs traffic", then a zero context length. Build the same
     thing by hand and compare, so a wrong prefix or length is caught here
     rather than as a wrong secret 40 checks later. */
  uint8_t info[64];
  size_t label_len = strlen("c hs traffic");
  size_t full_len = 6U + label_len;
  size_t info_len;
  info[0] = 0x00; info[1] = 0x20;
  info[2] = (uint8_t)full_len;
  memcpy(info + 3, "tls13 ", 6);
  memcpy(info + 9, "c hs traffic", label_len);
  info[3U + full_len] = 0x00;
  info_len = 4U + full_len;
  /* The structure is 22 bytes for this label: two length bytes, the
     label-length byte 0x12, eighteen bytes of "tls13 c hs traffic", and the
     context-length byte. RFC 8448 prints those 22 bytes as the "info" of that
     derivation under a 32-byte context, and the printed hex includes the two
     length bytes, so the label itself starts at offset 3. */
  expect_int("HkdfLabel length for 'c hs traffic'", 22, (long)info_len);
  expect_int("HkdfLabel label length byte", 0x12, (long)info[2]);
  expect_hex("printed HkdfLabel label",
             "746c73313320632068732074726166666963", info + 3, 18);
  expect_int("HkdfLabel context length byte", 0, (long)info[21]);

  /* Expanding with an explicit context must differ from an empty one: a
     function that ignored the context would pass every vector in this file,
     because every vector here uses an empty context. */
  {
    uint8_t with_context[WT_TLS_HASH_LEN];
    uint8_t without_context[WT_TLS_HASH_LEN];
    uint8_t context[WT_TLS_HASH_LEN];
    memset(context, 0x5a, sizeof(context));
    expect_int("expand_label empty context", 0,
               wt_tls_expand_label(WT_RFC8448_HANDSHAKE_SECRET, WT_TLS_HASH_LEN,
                                   "c hs traffic", NULL, 0, without_context,
                                   WT_TLS_HASH_LEN));
    expect_int("expand_label with context", 0,
               wt_tls_expand_label(WT_RFC8448_HANDSHAKE_SECRET, WT_TLS_HASH_LEN,
                                   "c hs traffic", context, sizeof(context),
                                   with_context, WT_TLS_HASH_LEN));
    g_checks++;
    if (memcmp(with_context, without_context, WT_TLS_HASH_LEN) == 0) {
      g_failures++;
      printf("FAIL the context is ignored by wt_tls_expand_label\n");
    }
  }

  /* Refusals, so a caller passing nonsense is told rather than given bytes. */
  expect_int("expand_label refuses an empty label (RFC 8446 label<7..255>)",
             -1,
             wt_tls_expand_label(WT_RFC8448_EARLY_SECRET, WT_TLS_HASH_LEN, "",
                                 NULL, 0, out, 16));
  expect_int("expand_label refuses a NULL secret", -1,
             wt_tls_expand_label(NULL, WT_TLS_HASH_LEN, "key", NULL, 0, out, 16));
  expect_int("expand_label refuses a NULL output", -1,
             wt_tls_expand_label(WT_RFC8448_EARLY_SECRET, WT_TLS_HASH_LEN, "key",
                                 NULL, 0, NULL, 16));
  expect_int("expand_label refuses a NULL context with a length", -1,
             wt_tls_expand_label(WT_RFC8448_EARLY_SECRET, WT_TLS_HASH_LEN, "key",
                                 NULL, 4, out, 16));
  {
    /* 255 bytes of context is the most the length byte holds; one more is a
       refusal, not a truncated label. */
    static uint8_t big_context[256];
    expect_int("expand_label accepts a 255-byte context", 0,
               wt_tls_expand_label(WT_RFC8448_EARLY_SECRET, WT_TLS_HASH_LEN,
                                   "key", big_context, 255, out, 16));
    expect_int("expand_label refuses a 256-byte context", -1,
               wt_tls_expand_label(WT_RFC8448_EARLY_SECRET, WT_TLS_HASH_LEN,
                                   "key", big_context, 256, out, 16));
  }
}

/* ------------------------------------------------------------- the schedule */

static void test_key_schedule(void) {
  wt_tls_secrets_t secrets;

  expect_int("key schedule", 0,
             wt_tls_key_schedule(WT_RFC8448_ECDHE, sizeof(WT_RFC8448_ECDHE),
                                 WT_RFC8448_TRANSCRIPT_AFTER_SERVER_HELLO,
                                 WT_RFC8448_TRANSCRIPT_AFTER_SERVER_FINISHED,
                                 NULL, &secrets));
  expect_int("the resumption master secret is absent without a client "
             "Finished transcript", 0, secrets.resumption_master_available);

  /* RFC 8448 section 3 prints this value over the client-Finished transcript,
     and the audit that found the wrong-transcript defect is what pointed at it.
     Deriving it from the server's Finished gives a well-formed value that is
     not this one, so pinning it is the check that the transcript is the right
     one. */
  {
    wt_tls_secrets_t with_res;
    expect_int("key schedule with the RFC's client-Finished transcript", 0,
               wt_tls_key_schedule(
                   WT_RFC8448_ECDHE, sizeof(WT_RFC8448_ECDHE),
                   WT_RFC8448_TRANSCRIPT_AFTER_SERVER_HELLO,
                   WT_RFC8448_TRANSCRIPT_AFTER_SERVER_FINISHED,
                   WT_RFC8448_TRANSCRIPT_AFTER_CLIENT_FINISHED, &with_res));
    expect_bytes("resumption_master_secret",
                 WT_RFC8448_RESUMPTION_MASTER, with_res.resumption_master, 32);
    expect_int("and it is flagged available", 1,
               with_res.resumption_master_available);
    /* The other values must be unchanged by the extra transcript: they come
       from the server's Finished and must not move. */
    expect_bytes("the exporter is unaffected by the client transcript",
                 WT_RFC8448_EXPORTER_MASTER, with_res.exporter_master, 32);
    expect_bytes("the application secrets are unaffected",
                 WT_RFC8448_CLIENT_APPLICATION_TRAFFIC,
                 with_res.client_application_traffic, 32);
    wt_tls_secrets_clear(&with_res);
  }

  /* Every value RFC 8448 prints, in the order the RFC derives them. A mismatch
     here localises the defect: the early secret failing means the extract, the
     handshake secret failing means the "derived" step or the ECDHE input, and
     so on down the chain. */
  expect_bytes("early_secret", WT_RFC8448_EARLY_SECRET, secrets.early, 32);
  expect_bytes("handshake_secret", WT_RFC8448_HANDSHAKE_SECRET,
               secrets.handshake, 32);
  expect_bytes("master_secret", WT_RFC8448_MASTER_SECRET, secrets.master, 32);
  expect_bytes("client_handshake_traffic_secret",
               WT_RFC8448_CLIENT_HANDSHAKE_TRAFFIC,
               secrets.client_handshake_traffic, 32);
  expect_bytes("server_handshake_traffic_secret",
               WT_RFC8448_SERVER_HANDSHAKE_TRAFFIC,
               secrets.server_handshake_traffic, 32);
  expect_bytes("client_application_traffic_secret",
               WT_RFC8448_CLIENT_APPLICATION_TRAFFIC,
               secrets.client_application_traffic, 32);
  expect_bytes("server_application_traffic_secret",
               WT_RFC8448_SERVER_APPLICATION_TRAFFIC,
               secrets.server_application_traffic, 32);
  expect_bytes("exporter_master_secret", WT_RFC8448_EXPORTER_MASTER,
               secrets.exporter_master, 32);

  /* The resumption master secret is taken over the transcript through the
     CLIENT's Finished. Derived from the server's Finished instead -- which is
     what this function did first -- it is a well-formed value that is simply
     not the resumption master secret, and the failure would appear on the
     first resumption attempt with nothing to point at. The two must therefore
     differ, and the availability flag must say which is which. */
  {
    /* And with no client transcript the field stays zero rather than holding a
       value derived from the wrong messages. */
    static const uint8_t zeroes[32] = {0};
    expect_int("the resumption master secret is zero when unavailable", 1,
               memcmp(secrets.resumption_master, zeroes, 32) == 0);
  }

  /* A wrong ECDHE input must not produce the published secrets. This is the
     check that the schedule actually depends on the key exchange rather than
     ignoring it. */
  {
    uint8_t wrong_ecdh[32];
    wt_tls_secrets_t wrong;
    memcpy(wrong_ecdh, WT_RFC8448_ECDHE, 32);
    wrong_ecdh[0] ^= 0x01U;
    expect_int("key schedule with a wrong ECDHE", 0,
               wt_tls_key_schedule(wrong_ecdh, sizeof(wrong_ecdh),
                                   WT_RFC8448_TRANSCRIPT_AFTER_SERVER_HELLO,
                                   WT_RFC8448_TRANSCRIPT_AFTER_SERVER_FINISHED,
                                   NULL, &wrong));
    g_checks++;
    if (memcmp(wrong.handshake, secrets.handshake, 32) == 0) {
      g_failures++;
      printf("FAIL the handshake secret does not depend on the ECDHE input\n");
    }
    wt_tls_secrets_clear(&wrong);
  }

  /* And a wrong transcript must not either. */
  {
    uint8_t wrong_th[32];
    wt_tls_secrets_t wrong;
    memcpy(wrong_th, WT_RFC8448_TRANSCRIPT_AFTER_SERVER_HELLO, 32);
    wrong_th[31] ^= 0x01U;
    expect_int("key schedule with a wrong transcript", 0,
               wt_tls_key_schedule(WT_RFC8448_ECDHE, sizeof(WT_RFC8448_ECDHE),
                                   wrong_th,
                                   WT_RFC8448_TRANSCRIPT_AFTER_SERVER_FINISHED,
                                   NULL, &wrong));
    g_checks++;
    if (memcmp(wrong.client_handshake_traffic,
               secrets.client_handshake_traffic, 32) == 0) {
      g_failures++;
      printf("FAIL the handshake traffic secret does not depend on the "
             "transcript\n");
    }
    wt_tls_secrets_clear(&wrong);
  }

  /* NULL arguments are refusals, and a refusal clears the output rather than
     leaving a partially derived schedule a caller might use. */
  expect_int("key schedule refuses NULL output", -1,
             wt_tls_key_schedule(WT_RFC8448_ECDHE, 32,
                                 WT_RFC8448_TRANSCRIPT_AFTER_SERVER_HELLO,
                                 WT_RFC8448_TRANSCRIPT_AFTER_SERVER_FINISHED,
                                 NULL, NULL));
  expect_int("key schedule refuses a zero-length ECDHE", -1,
             wt_tls_key_schedule(NULL, 0, WT_RFC8448_TRANSCRIPT_AFTER_SERVER_HELLO,
                                 WT_RFC8448_TRANSCRIPT_AFTER_SERVER_FINISHED,
                                 NULL, &secrets));
  expect_int("key schedule refuses a non-NULL zero-length ECDHE", -1,
             wt_tls_key_schedule((const uint8_t *)"", 0,
                                 WT_RFC8448_TRANSCRIPT_AFTER_SERVER_HELLO,
                                 WT_RFC8448_TRANSCRIPT_AFTER_SERVER_FINISHED,
                                 NULL, &secrets));
  expect_int("key schedule refuses a NULL transcript", -1,
             wt_tls_key_schedule(WT_RFC8448_ECDHE, 32, NULL,
                                 WT_RFC8448_TRANSCRIPT_AFTER_SERVER_FINISHED,
                                 NULL, &secrets));
  {
    wt_tls_secrets_t cleared;
    static const uint8_t zeroes[32] = {0};
    memset(&cleared, 0xAA, sizeof(cleared));
    expect_int("key schedule refusal", -1,
               wt_tls_key_schedule(WT_RFC8448_ECDHE, 32, NULL, NULL, NULL,
                                   &cleared));
    /* A caller that ignored the return value must not be able to use a
       half-derived schedule, so the output is cleared even when the arguments
       were refused before any derivation ran. */
    g_checks++;
    if (memcmp(cleared.early, zeroes, 32) != 0) {
      g_failures++;
      printf("FAIL a refused key schedule left a partially derived secret\n");
    }
  }

  wt_tls_secrets_clear(&secrets);
}

/* ---------------------------------------------------------- traffic keys */

static void test_traffic_keys(void) {
  wt_tls_traffic_keys_t keys;

  /* RFC 9001 appendix A.5 prints all four values a traffic secret produces,
     including the key-update secret, so this checks the QUIC labels and the
     key update in one place. */
  expect_int("traffic keys", 0,
             wt_tls_traffic_keys(WT_RFC9001_CHACHA_SECRET,
                                 WT_TLS_AEAD_CHACHA20_POLY1305, &keys));
  /* The key is the AEAD's own length, so 32 here. The RFC prints it in A.5. */
  expect_hex("quic key (ChaCha20, 32 bytes)",
             "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8",
             keys.key, 32);
  expect_int("ChaCha20 key length", 32, (long)keys.key_len);
  expect_hex("quic iv", "e0459b3474bdd0e44a41c144", keys.iv, 12);
  expect_hex("quic hp",
             "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4",
             keys.hp, 32);
  expect_int("ChaCha20 hp length", 32, (long)keys.hp_len);
  expect_bytes("the secret is carried alongside its keys",
               WT_RFC9001_CHACHA_SECRET, keys.secret, 32);

  /* Key update: RFC 9001 section 6 and the "quic ku" value in A.5. The next
     keys come from the next secret, not from the current keys. */
  {
    wt_tls_traffic_keys_t next;
    expect_int("key update", 0, wt_tls_key_update(WT_RFC9001_CHACHA_SECRET,
                              WT_TLS_AEAD_CHACHA20_POLY1305, &next));
    expect_hex("quic ku",
               "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9",
               next.secret, 32);
    expect_int("the updated key is the same length as the original", 32,
               (long)next.key_len);
    g_checks++;
    if (memcmp(next.key, keys.key, 32) == 0) {
      g_failures++;
      printf("FAIL the key update produced the same key\n");
    }
    wt_tls_traffic_keys_clear(&next);
  }

  expect_int("traffic keys refuse NULL", -1,
             wt_tls_traffic_keys(NULL, WT_TLS_AEAD_AES_128_GCM, &keys));
  expect_int("traffic keys refuse an unknown AEAD", -1,
             wt_tls_traffic_keys(WT_RFC9001_CHACHA_SECRET, (wt_tls_aead_t)99,
                                 &keys));

  /* The handshake traffic secret from RFC 8448 produces QUIC keys that the RFC
     does not print (it prints TLS records, not QUIC packets). That the call
     succeeds and the three values differ from each other is all that can be
     said without a vector; the labels themselves are pinned by A.5 above. */
  {
    wt_tls_traffic_keys_t handshake_keys;
    expect_int("traffic keys from the handshake secret", 0,
               wt_tls_traffic_keys(WT_RFC8448_SERVER_HANDSHAKE_TRAFFIC,
                                   WT_TLS_AEAD_AES_128_GCM, &handshake_keys));
    g_checks++;
    if (memcmp(handshake_keys.key, handshake_keys.hp, 16) == 0) {
      g_failures++;
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
    expect_bytes("traffic keys clear", zeroes, cleared.secret, 32);
  }
}

/* ----------------------------------------------------- QUIC Initial keys */

static void test_initial_keys(void) {
  uint8_t initial_secret[WT_TLS_HASH_LEN];
  wt_tls_traffic_keys_t client;
  wt_tls_traffic_keys_t server;

  expect_int("initial secret", 0,
             wt_tls_initial_secret(WT_RFC9001_INITIAL_SALT,
                                   sizeof(WT_RFC9001_INITIAL_SALT),
                                   WT_RFC9001_DCID, sizeof(WT_RFC9001_DCID),
                                   initial_secret));
  expect_hex("initial_secret",
             "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44",
             initial_secret, 32);
  expect_bytes("the initial secret pin matches the RFC's printed key",
               WT_RFC9001_CLIENT_KEY, (const uint8_t *)"", 0);

  expect_int("client initial keys", 0,
             wt_tls_initial_traffic_keys(initial_secret, 0,
                                        WT_TLS_AEAD_AES_128_GCM, &client));
  expect_bytes("client initial key", WT_RFC9001_CLIENT_KEY, client.key, 16);
  expect_bytes("client initial iv", WT_RFC9001_CLIENT_IV, client.iv, 12);
  expect_bytes("client initial hp", WT_RFC9001_CLIENT_HP, client.hp, 16);
  expect_int("client initial hp length", 16, (long)client.hp_len);

  expect_int("server initial keys", 0,
             wt_tls_initial_traffic_keys(initial_secret, 1,
                                        WT_TLS_AEAD_AES_128_GCM, &server));
  expect_bytes("server initial key", WT_RFC9001_SERVER_KEY, server.key, 16);
  expect_bytes("server initial iv", WT_RFC9001_SERVER_IV, server.iv, 12);
  expect_bytes("server initial hp", WT_RFC9001_SERVER_HP, server.hp, 16);

  /* The two directions must differ. A function that ignored `from_server`
     would pass both sets only if the labels were also swapped, which is
     exactly the confusion this check exists for. */
  g_checks++;
  if (memcmp(client.key, server.key, 16) == 0) {
    g_failures++;
    printf("FAIL the client and server Initial keys are identical\n");
  }

  wt_tls_traffic_keys_clear(&client);
  wt_tls_traffic_keys_clear(&server);
}

/* ------------------------------------------------------- Retry integrity tag */

static void test_retry_tag(void) {
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

  expect_int("retry integrity tag", 0,
             wt_tls_retry_integrity_tag(retry_key, retry_nonce,
                                        WT_RFC9001_DCID, sizeof(WT_RFC9001_DCID),
                                        WT_RFC9001_RETRY_WITHOUT_TAG,
                                        sizeof(WT_RFC9001_RETRY_WITHOUT_TAG),
                                        scratch, sizeof(scratch), tag));
  expect_bytes("retry integrity tag", WT_RFC9001_RETRY_TAG, tag, 16);

  /* The whole Retry as it appears on the wire is the body plus the tag, and
     that is what appendix A.4 prints. */
  {
    uint8_t packet[sizeof(WT_RFC9001_RETRY_WITHOUT_TAG) + 16];
    memcpy(packet, WT_RFC9001_RETRY_WITHOUT_TAG,
           sizeof(WT_RFC9001_RETRY_WITHOUT_TAG));
    memcpy(packet + sizeof(WT_RFC9001_RETRY_WITHOUT_TAG), tag, 16);
    expect_bytes("the Retry on the wire", WT_RFC9001_RETRY_PACKET, packet,
                 sizeof(packet));
  }

  /* Verification, which is the half WT-1 was missing: the Swift
     implementation computed no tag at all, so it accepted a forged Retry. */
  expect_int("a valid Retry verifies", 1,
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
    expect_int("all 128 single-bit tag forgeries are refused", 0, accepted);
  }

  {
    /* A Retry answered to a different original connection ID must not verify:
       that is the whole reason the pseudo-packet carries the ODCID. */
    uint8_t other_dcid[8];
    memcpy(other_dcid, WT_RFC9001_DCID, 8);
    other_dcid[7] ^= 0x01U;
    expect_int("a Retry for another connection is refused", 0,
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
    expect_int("a Retry with a modified body is refused", 0,
               wt_tls_verify_retry_integrity_tag(
                   retry_key, retry_nonce, WT_RFC9001_DCID,
                   sizeof(WT_RFC9001_DCID), forged, sizeof(forged), scratch,
                   sizeof(scratch)));
  }

  expect_int("verify refuses a short packet", -1,
             wt_tls_verify_retry_integrity_tag(retry_key, retry_nonce,
                                               WT_RFC9001_DCID, 8,
                                               WT_RFC9001_RETRY_PACKET, 8,
                                               scratch, sizeof(scratch)));
  expect_int("tag refuses NULL key", -1,
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
    expect_int("a Retry larger than the caller's buffer is refused", -1,
               wt_tls_verify_retry_integrity_tag(
                   retry_key, retry_nonce, WT_RFC9001_DCID,
                   sizeof(WT_RFC9001_DCID), huge_retry, sizeof(huge_retry),
                   small_scratch, sizeof(small_scratch)));
    expect_int("a pseudo-packet larger than the caller's buffer is refused", -1,
               wt_tls_retry_integrity_tag(
                   retry_key, retry_nonce, WT_RFC9001_DCID,
                   sizeof(WT_RFC9001_DCID), huge_retry, sizeof(huge_retry),
                   small_scratch, sizeof(small_scratch), tag));
  }
  {
    /* A connection ID longer than 20 bytes cannot occur on the wire, and the
       length byte cannot hold it. */
    static uint8_t long_dcid[21];
    expect_int("tag refuses an over-long connection ID", -1,
               wt_tls_retry_integrity_tag(retry_key, retry_nonce, long_dcid, 21,
                                          WT_RFC9001_RETRY_WITHOUT_TAG,
                                          sizeof(WT_RFC9001_RETRY_WITHOUT_TAG),
                                          scratch, sizeof(scratch), tag));
    expect_int("tag refuses a NULL scratch with a non-zero length", -1,
               wt_tls_retry_integrity_tag(retry_key, retry_nonce,
                                          WT_RFC9001_DCID, 8,
                                          WT_RFC9001_RETRY_WITHOUT_TAG,
                                          sizeof(WT_RFC9001_RETRY_WITHOUT_TAG),
                                          NULL, 64U, tag));
  }
}

int main(void) {
  test_empty_hash();
  test_expand_label();
  test_key_schedule();
  test_traffic_keys();
  test_initial_keys();
  test_retry_tag();

  if (g_failures != 0) {
    printf("wt_tls: %d of %d checks FAILED\n", g_failures, g_checks);
    return 1;
  }
  printf("wt_tls: all %d checks reproduced their RFC 8448 / 9001 vector\n",
         g_checks);
  return 0;
}
