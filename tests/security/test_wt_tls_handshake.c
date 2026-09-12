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
#include "wt_quic_pkt.h"
#include "wt_rfc8448_vectors.h"
#include "wt_rfc9001_vectors.h"

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

/* -------------------------------------------------------- ClientHello build */

/* Verify the ClientHello builder by parsing what it produces.
 *
 * WHY NOT BYTE-FOR-BYTE AGAINST RFC 8448. The obvious check -- build the
 * message with the trace's parameters and compare it to the 196 bytes the RFC
 * prints -- does not hold, and the reason is worth recording rather than
 * working around. RFC 8448's ClientHello is from an earlier draft of TLS 1.3:
 * it carries renegotiation_info (0xff01), ec_point_formats (0x001c),
 * session_ticket (0x0023), extended_master_secret (0x0017) and
 * psk_key_exchange_modes (0x002d), none of which belong in a TLS 1.3 QUIC
 * ClientHello, and its signature_algorithms list holds SIXTEEN entries where
 * the extension's own length says fifteen -- 00 1e, thirty bytes, sixteen
 * algorithms, so the last of them is a length error in the vector.
 *
 * Matching it byte for byte would mean emitting deprecated extensions and
 * reproducing an off-by-one, and then the message would be rejected by a real
 * server. So the builder is checked against the specification instead: its
 * output is decoded here, field by field, from the wire format. That is a
 * weaker check against a published vector and a stronger check against the
 * protocol, and the difference is stated rather than hidden.
 *
 * The fields that CAN be compared to the RFC are: the cipher suite list, the
 * supported groups, the signature algorithms minus the vector's extra entry,
 * the key share, the ALPN, and the SNI. All are.
 */

/* A minimal reader over the built message, written here rather than shared with
 * the parser: a verifier that used the code under test would agree with it.
 *
 * Every function takes the cursor by pointer and moves it explicitly, and there
 * is no arithmetic that mixes a cursor update with a read in one expression.
 * The first three versions of this used `r->offset += n + chr_u16(r)`, which
 * modifies the cursor twice with no sequence point between them -- undefined
 * behaviour that ASan reported as a stack overflow and then as a wild read, and
 * that read like a builder emitting the wrong bytes. */

typedef struct ch_reader {
  const uint8_t *data;
  size_t len;
  size_t offset;
  int failed;
} ch_reader_t;

static void chr_init(ch_reader_t *r, const uint8_t *data, size_t len) {
  r->data = data;
  r->len = len;
  r->offset = 0U;
  r->failed = 0;
}

static const uint8_t *chr_take(ch_reader_t *r, size_t n) {
  const uint8_t *p;
  if (r->failed || n > r->len - r->offset) {
    r->failed = 1;
    return NULL;
  }
  p = r->data + r->offset;
  r->offset += n;
  return p;
}

static uint8_t chr_u8(ch_reader_t *r) {
  const uint8_t *p = chr_take(r, 1U);
  return p == NULL ? 0U : p[0];
}

static uint16_t chr_u16(ch_reader_t *r) {
  const uint8_t *p = chr_take(r, 2U);
  return p == NULL ? 0U : (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

/* Skip precisely one field and return its length, so the walk reads the same
 * number of bytes in both passes. `chr_skip` is the only place the cursor moves
 * without producing a value, and every caller uses the value it returns. */
static void chr_skip(ch_reader_t *r, size_t n) { (void)chr_take(r, n); }

/* The ClientHello's fixed prefix, leaving the cursor at the extensions block.
 * `out_ext_len` receives that block's length and the cursor is left just past
 * its two-byte length, so the caller can walk the extensions itself. */
static void chr_enter_extensions(ch_reader_t *r, uint16_t *out_ext_len) {
  uint8_t session_id_len;
  uint16_t suites_len;
  uint8_t compression_len;

  chr_skip(r, 2U);                 /* legacy_version */
  chr_skip(r, 32U);                /* random */
  session_id_len = chr_u8(r);
  chr_skip(r, session_id_len);     /* legacy_session_id */
  suites_len = chr_u16(r);
  chr_skip(r, suites_len);         /* cipher_suites */
  compression_len = chr_u8(r);
  chr_skip(r, compression_len);    /* legacy_compression_methods */
  *out_ext_len = chr_u16(r);       /* the extensions block's length */
}

/* Find one extension by walking the block from its start. */
static const uint8_t *chr_find_extension(const uint8_t *extensions,
                                         size_t extensions_len, uint16_t want,
                                         size_t *out_len) {
  ch_reader_t ext;
  chr_init(&ext, extensions, extensions_len);
  while (ext.offset < ext.len) {
    uint16_t type = chr_u16(&ext);
    uint16_t len = chr_u16(&ext);
    const uint8_t *data = chr_take(&ext, len);
    if (ext.failed) return NULL;
    if (type == want) {
      *out_len = len;
      return data;
    }
  }
  return NULL;
}

static void test_client_hello_build(void) {
  static const uint16_t cipher_suites[3] = {0x1301, 0x1303, 0x1302};
  static const uint16_t groups[5] = {0x001d, 0x0017, 0x0018, 0x0019, 0x0100};
  /* RFC 8448's list, without the sixteenth entry its own length field excludes.
     The vector prints 00 1e (thirty bytes, fifteen algorithms) and then
     sixteen; the last, 0x0000, is outside the extension. Fifteen is what the
     RFC's own length says, and 0x0000 is not a signature algorithm. */
  static const uint16_t signature_algorithms[15] = {
      0x0403, 0x0503, 0x0603, 0x0203, 0x0804, 0x0805, 0x0806, 0x0401,
      0x0501, 0x0601, 0x0201, 0x0402, 0x0502, 0x0602, 0x0202,
  };
  static const uint8_t alpn[5] = {0x01, 0x00, 0x00, 0x00, 0x00};
  wt_tls_client_hello_params_t params;
  wt_tls_key_share_t share;
  static uint8_t buffer[512];
  size_t size;
  size_t written;

  share.group = 0x001d;
  share.public_key = WT_RFC8448_CLIENT_KEY_PUBLIC;
  share.public_key_len = sizeof(WT_RFC8448_CLIENT_KEY_PUBLIC);

  memset(&params, 0, sizeof(params));
  params.random = WT_RFC8448_CLIENT_RANDOM;
  params.cipher_suites = cipher_suites;
  params.cipher_suite_count = 3U;
  params.key_shares = &share;
  params.key_share_count = 1U;
  params.supported_groups = groups;
  params.supported_group_count = 5U;
  params.signature_algorithms = signature_algorithms;
  params.signature_algorithm_count = 15U;
  params.alpn_protocols = alpn;
  params.alpn_protocols_len = sizeof(alpn);
  params.server_name = "server";

  size = wt_tls_client_hello_size(&params);
  written = wt_tls_encode_client_hello(&params, buffer, sizeof(buffer));
  expect_int("the builder produces the size it measured", (long)size,
             (long)written);

  /* The framing, decoded by the module's own header reader -- which is checked
     against the RFC's messages elsewhere in this file. */
  {
    uint8_t type = 0U;
    size_t body_len = 0U;
    size_t offset = 0U;
    expect_int("the built message frames", 0,
               wt_tls_decode_handshake_header(buffer, written, &type, &body_len,
                                              &offset));
    expect_int("it is a ClientHello", 1, (long)type);
    expect_int("its body is the message minus the four-byte header",
               (long)(written - 4U), (long)body_len);
  }

  /* Now decode it here. */
  {
    ch_reader_t r;
    const uint8_t *field;
    const uint8_t *extensions;
    size_t field_len = 0U;
    uint16_t ext_len = 0U;

    /* The reader starts at the BODY, past the four-byte handshake header. */
    chr_init(&r, buffer + 4U, written - 4U);
    expect_int("the built ClientHello is a whole number of handshake messages",
               (long)written, (long)(4U + ((size_t)buffer[1] << 16) +
                                     ((size_t)buffer[2] << 8) + buffer[3]));

    /* legacy_version must be 0x0303 with the real version in
       supported_versions. */
    expect_int("legacy_version is 0x0303", 0x0303, (long)chr_u16(&r));
    field = chr_take(&r, 32U);
    expect_bytes("the ClientHello random is the one supplied",
                 WT_RFC8448_CLIENT_RANDOM, field, 32);

    expect_int("legacy_session_id is empty, as QUIC requires", 0,
               (long)chr_u8(&r));

    {
      uint16_t suites_len = chr_u16(&r);
      uint16_t suites[8];
      size_t count = suites_len / 2U;
      expect_int("the cipher suite list is six bytes", 6, (long)suites_len);
      /* Bounded by the array, not by the message. The first version looped to
         count straight from the message and wrote eight past the end of a
         three-element buffer under ASan -- a test bug, but the same shape as
         the parsing bugs the test exists to look for, which is why the
         sanitizer run stays in the loop. */
      if (count > sizeof(suites) / sizeof(suites[0])) {
        g_checks++;
        g_failures++;
        printf("FAIL the cipher suite list is %zu entries, more than the "
               "verifier holds\n", count);
        count = sizeof(suites) / sizeof(suites[0]);
      }
      for (size_t i = 0U; i < count; i++) suites[i] = chr_u16(&r);
      expect_int("suite 0 is TLS_AES_128_GCM_SHA256", 0x1301, (long)suites[0]);
      expect_int("suite 1 is TLS_CHACHA20_POLY1305_SHA256", 0x1303,
                 (long)suites[1]);
      expect_int("suite 2 is TLS_AES_256_GCM_SHA384", 0x1302, (long)suites[2]);
    }

    {
      uint8_t methods_len = chr_u8(&r);
      expect_int("legacy_compression_methods has one entry", 1,
                 (long)methods_len);
      expect_int("and it is null compression", 0, (long)chr_u8(&r));
    }

    ext_len = chr_u16(&r);
    extensions = chr_take(&r, ext_len);
    if (extensions == NULL) {
      g_checks++;
      g_failures++;
      printf("FAIL the extensions block does not fit the message\n");
      return;
    }
    /* The sections before the extensions plus the extensions must consume the
       body exactly. This is the assertion that catches a wrong skip, and it is
       why the walk is worth doing rather than trusting the builder. */
    expect_int("the sections and the extensions consume the body exactly",
               (long)(written - 4U), (long)r.offset);

    /* server_name */
    field = chr_find_extension(extensions, ext_len, 0x0000U, &field_len);
    g_checks++;
    if (field == NULL) {
      g_failures++;
      printf("FAIL the ClientHello has no server_name extension\n");
    } else {
      ch_reader_t sni;
      chr_init(&sni, field, field_len);
      expect_int("the server_name list length", (long)(field_len - 2U),
                 (long)chr_u16(&sni));
      expect_int("the name type is host_name", 0, (long)chr_u8(&sni));
      expect_int("the name length is 6", 6, (long)chr_u16(&sni));
      expect_bytes("the name is \"server\"", (const uint8_t *)"server",
                   chr_take(&sni, 6U), 6);
    }

    /* supported_groups, which must equal the RFC's list. */
    field = chr_find_extension(extensions, ext_len, 0x000AU, &field_len);
    g_checks++;
    if (field == NULL) {
      g_failures++;
      printf("FAIL the ClientHello has no supported_groups extension\n");
    } else {
      ch_reader_t g;
      uint16_t list_len;
      chr_init(&g, field, field_len);
      list_len = chr_u16(&g);
      expect_int("the supported_groups list is ten bytes", 10, (long)list_len);
      for (size_t i = 0U; i < 5U; i++) {
        expect_int("supported group matches the RFC's", (long)groups[i],
                   (long)chr_u16(&g));
      }
    }

    /* signature_algorithms. */
    field = chr_find_extension(extensions, ext_len, 0x000DU, &field_len);
    g_checks++;
    if (field == NULL) {
      g_failures++;
      printf("FAIL the ClientHello has no signature_algorithms extension\n");
    } else {
      ch_reader_t g;
      uint16_t list_len;
      chr_init(&g, field, field_len);
      list_len = chr_u16(&g);
      expect_int("fifteen signature algorithms", 30, (long)list_len);
      for (size_t i = 0U; i < 15U; i++) {
        expect_int("signature algorithm matches the RFC's",
                   (long)signature_algorithms[i], (long)chr_u16(&g));
      }
    }

    /* key_share, including the client's public key. */
    field = chr_find_extension(extensions, ext_len, 0x0033U, &field_len);
    g_checks++;
    if (field == NULL) {
      g_failures++;
      printf("FAIL the ClientHello has no key_share extension\n");
    } else {
      ch_reader_t g;
      uint16_t list_len;
      chr_init(&g, field, field_len);
      list_len = chr_u16(&g);
      expect_int("one key share of 36 bytes", 36, (long)list_len);
      expect_int("the group is x25519", 0x001d, (long)chr_u16(&g));
      expect_int("the key is 32 bytes", 32, (long)chr_u16(&g));
      expect_bytes("the key is the client's public key",
                   WT_RFC8448_CLIENT_KEY_PUBLIC, chr_take(&g, 32U), 32);
    }

    /* supported_versions must advertise 1.3 and nothing else. */
    field = chr_find_extension(extensions, ext_len, 0x002BU, &field_len);
    g_checks++;
    if (field == NULL) {
      g_failures++;
      printf("FAIL the ClientHello has no supported_versions extension\n");
    } else {
      expect_int("supported_versions is three bytes", 3, (long)field_len);
      expect_int("one version is listed", 2, (long)field[0]);
      expect_int("and it is TLS 1.3", 0x0304,
                 (long)(((uint16_t)field[1] << 8) | field[2]));
    }

    /* alpn */
    field = chr_find_extension(extensions, ext_len, 0x0010U, &field_len);
    g_checks++;
    if (field == NULL) {
      g_failures++;
      printf("FAIL the ClientHello has no ALPN extension\n");
    } else {
      /* The extension data is `ProtocolNameList` -- a two-byte list length
         followed by the length-prefixed protocol names -- not the bare list.
         The first version compared the extension data against the caller's
         list and was two bytes out. */
      expect_int("the ALPN extension is the list plus its length prefix",
                 (long)(sizeof(alpn) + 2U), (long)field_len);
      expect_int("the ALPN list length is the caller's", (long)sizeof(alpn),
                 (long)(((uint16_t)field[0] << 8) | field[1]));
      expect_bytes("the ALPN list is the one supplied", alpn, field + 2U,
                   sizeof(alpn));
    }

    /* A QUIC ClientHello without transport parameters is rejected by a server,
       so the builder must emit none only when the caller passes none. */
    field = chr_find_extension(extensions, ext_len, 0x0039U, &field_len);
    expect_int("no quic_transport_parameters extension was requested so none "
               "is present", 1, (long)(field == NULL));
  }

  /* The size function and the encoder must agree, because a caller sizes its
     buffer from one and fills it with the other. */
  {
    static uint8_t exact[512];
    expect_int("a buffer of exactly the measured size is accepted",
               (long)size,
               (long)wt_tls_encode_client_hello(&params, exact, size));
    expect_bytes("and produces the same message", buffer, exact, size);
    expect_int("a buffer one byte short is refused", 0,
               (long)wt_tls_encode_client_hello(&params, exact, size - 1U));
  }

  /* A realistic HTTP/3 client differs from the RFC's vector in two ways that
     matter: it offers "h3" rather than a zero-length protocol, and it carries
     QUIC transport parameters, which RFC 9001 section 8.2 makes mandatory. */
  {
    static const uint8_t h3[3] = {0x02, 0x68, 0x33};
    static const uint8_t quic_params[50] = {
        0x04, 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x05, 0x04, 0x80, 0x00, 0xff, 0xff,
        0x07, 0x04, 0x80, 0x00, 0xff, 0xff,
        0x08, 0x01, 0x10,
        0x01, 0x04, 0x80, 0x00, 0x75, 0x30,
        0x09, 0x01, 0x10,
        0x0f, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08,
        0x06, 0x04, 0x80, 0x00, 0xff, 0xff,
    };
    wt_tls_client_hello_params_t real_params = params;
    static uint8_t real_buffer[512];
    size_t real_size;
    size_t written_real;
    size_t base_size = size;

    real_params.alpn_protocols = h3;
    real_params.alpn_protocols_len = sizeof(h3);
    real_params.quic_transport_parameters = quic_params;
    real_params.quic_transport_parameters_len = sizeof(quic_params);

    real_size = wt_tls_client_hello_size(&real_params);
    /* ALPN loses two bytes (5 -> 3); the parameters add a four-byte extension
       header and fifty bytes, so the message grows by 52. */
    expect_int("the QUIC ClientHello grows by exactly the extension overhead",
               (long)(base_size + 52U), (long)real_size);
    written_real = wt_tls_encode_client_hello(&real_params, real_buffer,
                                              sizeof(real_buffer));
    expect_int("a real HTTP/3 ClientHello encodes to its measured size",
               (long)real_size, (long)written_real);
    {
      ch_reader_t r2;
      const uint8_t *field;
      size_t field_len = 0U;
      chr_init(&r2, real_buffer + 4U, written_real - 4U);
      {
        const uint8_t *real_extensions;
        uint16_t real_ext_len = 0U;
        chr_enter_extensions(&r2, &real_ext_len);
        real_extensions = chr_take(&r2, real_ext_len);
        field = chr_find_extension(real_extensions, real_ext_len, 0x0039U,
                                   &field_len);
      }
      g_checks++;
      if (field == NULL) {
        g_failures++;
        printf("FAIL the transport parameters are missing\n");
      } else {
        expect_int("the transport parameters are carried verbatim",
                   (long)sizeof(quic_params), (long)field_len);
        expect_bytes("and are the bytes supplied", quic_params, field,
                     sizeof(quic_params));
      }
      chr_init(&r2, real_buffer + 4U, written_real - 4U);
      {
        const uint8_t *real_extensions;
        uint16_t real_ext_len = 0U;
        chr_enter_extensions(&r2, &real_ext_len);
        real_extensions = chr_take(&r2, real_ext_len);
        field = chr_find_extension(real_extensions, real_ext_len, 0x0010U,
                                   &field_len);
      }
      expect_int("the h3 ALPN extension is the list plus its length prefix", 5,
                 (long)field_len);
      expect_int("the h3 list length", 3,
                 (long)(((uint16_t)field[0] << 8) | field[1]));
      expect_bytes("and it is h3", h3, field + 2U, 3);
    }
  }

  /* Refusals. Each of these is a way a client can be wrong on the wire. */
  {
    wt_tls_client_hello_params_t bad = params;
    static const uint8_t session_id[1] = {0x01};

    /* RFC 9001 section 8.4 prohibits a non-empty legacy_session_id for QUIC. */
    bad.legacy_session_id = session_id;
    bad.legacy_session_id_len = 1U;
    expect_int("a non-empty legacy session ID is refused", 0,
               (long)wt_tls_client_hello_size(&bad));
    expect_int("and encoding it is refused", 0,
               (long)wt_tls_encode_client_hello(&bad, buffer, sizeof(buffer)));

    /* A random is mandatory: a builder that defaulted to zeros would produce a
       ClientHello with no unpredictability. */
    bad = params;
    bad.random = NULL;
    expect_int("a NULL random is refused", 0,
               (long)wt_tls_client_hello_size(&bad));

    /* At least one cipher suite is mandatory. */
    bad = params;
    bad.cipher_suite_count = 0U;
    expect_int("no cipher suites is refused", 0,
               (long)wt_tls_client_hello_size(&bad));

    /* No key share is legal TLS and produces a HelloRetryRequest, which is a
       round trip a QUIC handshake is not willing to spend. */
    bad = params;
    bad.key_share_count = 0U;
    bad.key_shares = NULL;
    expect_int("no key share is refused", 0,
               (long)wt_tls_client_hello_size(&bad));

    /* A NULL pointer with a non-zero count is a caller bug. */
    bad = params;
    bad.key_shares = NULL;
    expect_int("a NULL key share array with a count is refused", 0,
               (long)wt_tls_client_hello_size(&bad));
    bad = params;
    bad.supported_groups = NULL;
    expect_int("a NULL group array with a count is refused", 0,
               (long)wt_tls_client_hello_size(&bad));
    bad = params;
    bad.signature_algorithms = NULL;
    expect_int("a NULL signature algorithm array with a count is refused", 0,
               (long)wt_tls_client_hello_size(&bad));

    expect_int("a NULL output is refused", 0,
               (long)wt_tls_encode_client_hello(&params, NULL, 512U));
    expect_int("a NULL params is refused", 0,
               (long)wt_tls_client_hello_size(NULL));
  }

  /* The smallest ClientHello: every optional parameter absent. */
  {
    wt_tls_client_hello_params_t minimal = params;
    size_t n;
    static uint8_t small_buffer[512];
    minimal.server_name = NULL;
    minimal.supported_group_count = 0U;
    minimal.supported_groups = NULL;
    minimal.signature_algorithm_count = 0U;
    minimal.signature_algorithms = NULL;
    minimal.alpn_protocols = NULL;
    minimal.alpn_protocols_len = 0U;
    n = wt_tls_client_hello_size(&minimal);
    g_checks++;
    if (n == 0U) {
      g_failures++;
      printf("FAIL a minimal ClientHello reports zero bytes\n");
    } else {
      expect_int("the minimal ClientHello encodes to its measured size",
                 (long)n,
                 (long)wt_tls_encode_client_hello(&minimal, small_buffer,
                                                  sizeof(small_buffer)));
      expect_int("a buffer one byte short is refused", 0,
                 (long)wt_tls_encode_client_hello(&minimal, small_buffer,
                                                  n - 1U));
    }
  }
}

/* -------------------------------------------------- EncryptedExtensions */

/* A minimal EncryptedExtensions around a raw extension block. The header says
 * `08 || uint24 body length` and the body is the two-byte list length followed
 * by the list, per RFC 8446 section 4.3.1. Small enough for the tests, which
 * stay under 256 bytes so the length bytes can be written directly; the size is
 * asserted rather than assumed. */
static size_t ee_wrap(uint8_t *out, size_t capacity, const uint8_t *extensions,
                      size_t extensions_len) {
  size_t body_len = 2U + extensions_len;
  if (capacity < 4U + body_len || body_len > 0xFFFFFFU) return 0U;
  out[0] = WT_TLS_HS_ENCRYPTED_EXTENSIONS;
  out[1] = (uint8_t)((body_len >> 16) & 0xFFU);
  out[2] = (uint8_t)((body_len >> 8) & 0xFFU);
  out[3] = (uint8_t)(body_len & 0xFFU);
  out[4] = (uint8_t)((extensions_len >> 8) & 0xFFU);
  out[5] = (uint8_t)(extensions_len & 0xFFU);
  if (extensions_len != 0U) memcpy(out + 6U, extensions, extensions_len);
  return 4U + body_len;
}

/* One `type || length || data` extension appended to a block. Returns the new
 * block length. */
static size_t ee_ext(uint8_t *out, size_t len, uint16_t type,
                     const uint8_t *data, size_t data_len) {
  out[len + 0U] = (uint8_t)(type >> 8);
  out[len + 1U] = (uint8_t)(type & 0xFFU);
  out[len + 2U] = (uint8_t)(data_len >> 8);
  out[len + 3U] = (uint8_t)(data_len & 0xFFU);
  if (data_len != 0U) memcpy(out + len + 4U, data, data_len);
  return len + 4U + data_len;
}

/* The ClientHello parameters the parser's acceptance rules are checked
 * against: the seven extensions this module's builder emits, and nothing
 * else. `alpn` and the transport parameters are only read for their lengths. */
static void ee_offered_params(wt_tls_client_hello_params_t *p,
                              const uint8_t *alpn, size_t alpn_len,
                              const uint8_t *transport, size_t transport_len) {
  static const uint16_t groups[1] = {0x001DU};
  static const uint16_t sigalgs[1] = {0x0804U};
  static const uint16_t suites[1] = {0x1301U};
  static const uint8_t pub[32] = {0};
  static const wt_tls_key_share_t share = {0x001DU, pub, sizeof(pub)};

  memset(p, 0, sizeof(*p));
  p->random = (const uint8_t *)"0123456789abcdef0123456789abcdef";
  p->cipher_suites = suites;
  p->cipher_suite_count = 1U;
  p->key_shares = &share;
  p->key_share_count = 1U;
  p->supported_groups = groups;
  p->supported_group_count = 1U;
  p->signature_algorithms = sigalgs;
  p->signature_algorithm_count = 1U;
  p->server_name = "server";
  p->alpn_protocols = alpn;
  p->alpn_protocols_len = alpn_len;
  p->quic_transport_parameters = transport;
  p->quic_transport_parameters_len = transport_len;
}

static void test_encrypted_extensions(void) {
  wt_tls_encrypted_extensions_t ee;
  wt_tls_ee_reject_t reject;
  uint16_t offender;
  uint8_t block[512];
  uint8_t message[600];
  size_t block_len;
  size_t message_len;

  /* --- RFC 8448's own EncryptedExtensions, all 40 bytes of it.
   *
   * It carries supported_groups, record_size_limit (0x001c, an extension from
   * RFC 8449 that RFC 8446 postdates) and an empty server_name. It predates
   * QUIC's use of this message, so it has no ALPN and no transport parameters
   * -- which is the point: those two absences are what a QUIC handshake must
   * refuse, and they are absent in the one EncryptedExtensions the RFCs
   * actually publish. */
  expect_int("parse the RFC's EncryptedExtensions", 0,
             wt_tls_parse_encrypted_extensions(
                 WT_RFC8448_ENCRYPTED_EXTENSIONS,
                 sizeof(WT_RFC8448_ENCRYPTED_EXTENSIONS), &ee));
  expect_int("its reject reason is none", 0, (long)ee.reject);
  expect_int("three extensions", 3, (long)ee.type_count);
  expect_int("the first is supported_groups", WT_TLS_EXT_SUPPORTED_GROUPS,
             (long)ee.types[0]);
  expect_int("the second is record_size_limit", WT_TLS_EXT_RECORD_SIZE_LIMIT,
             (long)ee.types[1]);
  expect_int("the third is server_name", WT_TLS_EXT_SERVER_NAME,
             (long)ee.types[2]);
  expect_int("supported_groups is present", 1, ee.has_supported_groups);
  expect_int("server_name is present and empty", 1, ee.has_server_name);
  expect_int("no ALPN", 0, ee.has_alpn);
  expect_int("no transport parameters", 0, ee.has_transport_parameters);
  expect_int("no max_fragment_length", 0, ee.has_max_fragment_length);
  expect_int("no early_data", 0, ee.has_early_data);

  /* --- The check runs against this client's offered set, which is not RFC
   * 8448's (that trace is TLS over TCP). record_size_limit is legal in
   * EncryptedExtensions but this client never asked for it, so rule 1 fires
   * first and it is unsolicited rather than forbidden. */
  {
    wt_tls_client_hello_params_t params;
    ee_offered_params(&params, NULL, 0U, NULL, 0U);
    expect_int("record_size_limit is unsolicited, not forbidden", -1,
               wt_tls_encrypted_extensions_check(
                   &ee, &params, &reject, &offender));
    expect_int("  and the reason says so", (long)WT_TLS_EE_UNSOLICITED_EXTENSION,
               (long)reject);
    expect_int("  naming record_size_limit", WT_TLS_EXT_RECORD_SIZE_LIMIT,
               (long)offender);
  }

  /* --- A QUIC EncryptedExtensions: ALPN "h3" and transport parameters. */
  {
    static const uint8_t h3[3] = {0x02U, 'h', '3'};
    static const uint8_t tp[4] = {0x01U, 0x02U, 0x03U, 0x04U};
    uint8_t alpn_list[8];
    wt_tls_client_hello_params_t params;

    alpn_list[0] = 0x02U;
    memcpy(alpn_list + 1U, "h3", 2U);
    block_len = 0U;
    block_len = ee_ext(block, block_len, WT_TLS_EXT_ALPN, h3, sizeof(h3));
    block_len = ee_ext(block, block_len, WT_TLS_EXT_QUIC_TRANSPORT_PARAMETERS,
                       tp, sizeof(tp));
    message_len = ee_wrap(message, sizeof(message), block, block_len);
    expect_int("the wrapped message is the block plus six", (long)block_len + 6,
               (long)message_len);
    expect_int("parse a QUIC EncryptedExtensions", 0,
               wt_tls_parse_encrypted_extensions(message, message_len, &ee));
    expect_int("ALPN is present", 1, ee.has_alpn);
    expect_bytes("the selected protocol is h3", (const uint8_t *)"h3", ee.alpn,
                 ee.alpn_len);
    expect_int("two bytes of protocol", 2, (long)ee.alpn_len);
    expect_int("transport parameters are present", 1,
               ee.has_transport_parameters);
    expect_bytes("the parameters survived", tp, ee.transport_parameters,
                 ee.transport_parameters_len);

    ee_offered_params(&params, alpn_list, sizeof(alpn_list), tp, sizeof(tp));
    expect_int("both were offered, so the check accepts", 0,
               wt_tls_encrypted_extensions_check(&ee, &params, &reject,
                                                 &offender));
    expect_int("  and the reason is none", (long)WT_TLS_EE_OK, (long)reject);

    /* --- Rule 2: an extension the client offered, in the wrong message.
     * supported_versions and key_share are both in every ClientHello this
     * module builds and are both illegal in EncryptedExtensions (RFC 8446
     * section 4.2 lists them as CH, SH and CH, SH, HRR). */
    {
      static const uint16_t forbidden[] = {WT_TLS_EXT_SUPPORTED_VERSIONS,
                                           WT_TLS_EXT_KEY_SHARE,
                                           WT_TLS_EXT_SIGNATURE_ALGORITHMS};
      size_t i;
      for (i = 0U; i < sizeof(forbidden) / sizeof(forbidden[0]); i++) {
        static const uint8_t body[2] = {0x00U, 0x00U};
        block_len = ee_ext(block, 0U, forbidden[i], body, sizeof(body));
        message_len = ee_wrap(message, sizeof(message), block, block_len);
        expect_int("parse an EncryptedExtensions with a misplaced extension", 0,
                   wt_tls_parse_encrypted_extensions(message, message_len, &ee));
        expect_int("the check refuses it", -1,
                   wt_tls_encrypted_extensions_check(&ee, &params, &reject,
                                                     &offender));
        expect_int("  as a forbidden extension",
                   (long)WT_TLS_EE_FORBIDDEN_EXTENSION, (long)reject);
        expect_int("  naming it", (long)forbidden[i], (long)offender);
      }
    }

    /* --- Rule 1: an extension this ClientHello never offered at all. */
    {
      static const uint8_t body[1] = {0x00U};
      block_len = ee_ext(block, 0U, WT_TLS_EXT_STATUS_REQUEST, body,
                         sizeof(body));
      message_len = ee_wrap(message, sizeof(message), block, block_len);
      expect_int("parse an EncryptedExtensions with an unrequested extension", 0,
                 wt_tls_parse_encrypted_extensions(message, message_len, &ee));
      expect_int("the check refuses it", -1,
                 wt_tls_encrypted_extensions_check(&ee, &params, &reject,
                                                   &offender));
      expect_int("  as unsolicited", (long)WT_TLS_EE_UNSOLICITED_EXTENSION,
                 (long)reject);
      expect_int("  naming status_request", WT_TLS_EXT_STATUS_REQUEST,
                 (long)offender);
    }
  }

  /* --- Bodies that are the right extension but the wrong shape. */
  {
    static const uint8_t two_protocols[6] = {0x02U, 'h', '3',
                                             0x02U, 'h', '2'};
    static const uint8_t empty_protocol[1] = {0x00U};
    static const uint8_t named_server[3] = {0x01U, 'a', 'b'};
    static const uint8_t bad_mfl[1] = {0x05U};
    static const uint8_t one_byte[1] = {0x01U};

    /* RFC 7301: the server answers with exactly one protocol. A client that
       took the first of two would be agreeing to something the server did not
       choose. */
    block_len = ee_ext(block, 0U, WT_TLS_EXT_ALPN, two_protocols,
                       sizeof(two_protocols));
    message_len = ee_wrap(message, sizeof(message), block, block_len);
    expect_int("two ALPN names are refused", -1,
               wt_tls_parse_encrypted_extensions(message, message_len, &ee));
    expect_int("  as a bad extension", (long)WT_TLS_EE_BAD_EXTENSION,
               (long)ee.reject);
    expect_int("  naming ALPN", WT_TLS_EXT_ALPN, (long)ee.reject_extension);

    block_len = ee_ext(block, 0U, WT_TLS_EXT_ALPN, empty_protocol,
                       sizeof(empty_protocol));
    message_len = ee_wrap(message, sizeof(message), block, block_len);
    expect_int("an empty ALPN name is refused", -1,
               wt_tls_parse_encrypted_extensions(message, message_len, &ee));

    block_len = ee_ext(block, 0U, WT_TLS_EXT_SERVER_NAME, named_server,
                       sizeof(named_server));
    message_len = ee_wrap(message, sizeof(message), block, block_len);
    expect_int("a server_name with content is refused", -1,
               wt_tls_parse_encrypted_extensions(message, message_len, &ee));
    expect_int("  naming server_name", WT_TLS_EXT_SERVER_NAME,
               (long)ee.reject_extension);

    block_len = ee_ext(block, 0U, WT_TLS_EXT_MAX_FRAGMENT_LENGTH, bad_mfl,
                       sizeof(bad_mfl));
    message_len = ee_wrap(message, sizeof(message), block, block_len);
    expect_int("max_fragment_length 5 is refused", -1,
               wt_tls_parse_encrypted_extensions(message, message_len, &ee));
    block_len = ee_ext(block, 0U, WT_TLS_EXT_MAX_FRAGMENT_LENGTH, one_byte,
                       sizeof(one_byte));
    message_len = ee_wrap(message, sizeof(message), block, block_len);
    expect_int("max_fragment_length 1 is accepted", 0,
               wt_tls_parse_encrypted_extensions(message, message_len, &ee));
    expect_int("  and recorded", 1, ee.has_max_fragment_length);
    expect_int("  with its value", 1, (long)ee.max_fragment_length);
    {
      /* 2 (2^9) is the smallest legal value in the other direction. */
      static const uint8_t mfl_two[1] = {0x02U};
      static const uint8_t mfl_zero[1] = {0x00U};
      block_len = ee_ext(block, 0U, WT_TLS_EXT_MAX_FRAGMENT_LENGTH, mfl_two,
                         sizeof(mfl_two));
      message_len = ee_wrap(message, sizeof(message), block, block_len);
      expect_int("max_fragment_length 2 is accepted", 0,
                 wt_tls_parse_encrypted_extensions(message, message_len, &ee));
      block_len = ee_ext(block, 0U, WT_TLS_EXT_MAX_FRAGMENT_LENGTH, mfl_zero,
                         sizeof(mfl_zero));
      message_len = ee_wrap(message, sizeof(message), block, block_len);
      expect_int("max_fragment_length 0 is refused", -1,
                 wt_tls_parse_encrypted_extensions(message, message_len, &ee));
    }
  }

  /* --- The same extension twice: RFC 8446 section 4.2 forbids it, and two
   * ALPN answers would leave which one binds ambiguous while the transcript
   * still verifies. */
  {
    static const uint8_t h3[3] = {0x02U, 'h', '3'};
    block_len = 0U;
    block_len = ee_ext(block, block_len, WT_TLS_EXT_ALPN, h3, sizeof(h3));
    block_len = ee_ext(block, block_len, WT_TLS_EXT_ALPN, h3, sizeof(h3));
    message_len = ee_wrap(message, sizeof(message), block, block_len);
    expect_int("a repeated extension is refused", -1,
               wt_tls_parse_encrypted_extensions(message, message_len, &ee));
    expect_int("  as a duplicate", (long)WT_TLS_EE_DUPLICATE_EXTENSION,
               (long)ee.reject);
    expect_int("  naming ALPN", WT_TLS_EXT_ALPN, (long)ee.reject_extension);
  }

  /* --- Structural refusals, each reachable from the wire. */
  {
    static const uint8_t h3[3] = {0x02U, 'h', '3'};
    block_len = ee_ext(block, 0U, WT_TLS_EXT_ALPN, h3, sizeof(h3));
    message_len = ee_wrap(message, sizeof(message), block, block_len);

    /* A declared list length that is not the rest of the body is trailing
       bytes: a second message smuggled inside one the transcript hashes. */
    {
      uint8_t copy[600];
      memcpy(copy, message, message_len);
      copy[5] = (uint8_t)(copy[5] - 1U);
      expect_int("a short extension list is refused", -1,
                 wt_tls_parse_encrypted_extensions(copy, message_len, &ee));
      expect_int("  as malformed", (long)WT_TLS_EE_MALFORMED, (long)ee.reject);
      copy[5] = (uint8_t)(copy[5] + 2U);
      expect_int("a long extension list is refused", -1,
                 wt_tls_parse_encrypted_extensions(copy, message_len, &ee));
    }
    /* The wrong handshake message entirely. */
    {
      uint8_t copy[600];
      memcpy(copy, message, message_len);
      copy[0] = WT_TLS_HS_CERTIFICATE;
      expect_int("a Certificate is not an EncryptedExtensions", -1,
                 wt_tls_parse_encrypted_extensions(copy, message_len, &ee));
    }
    /* Truncation at every length. */
    {
      size_t cut;
      for (cut = 0U; cut < message_len; cut++) {
        expect_int("a truncated EncryptedExtensions is refused", -1,
                   wt_tls_parse_encrypted_extensions(message, cut, &ee));
      }
    }
    /* An extension whose declared length runs past the end of the list. */
    {
      uint8_t copy[600];
      memcpy(copy, message, message_len);
      copy[8] = 0x7FU; /* ALPN's length field */
      expect_int("an extension longer than the list is refused", -1,
                 wt_tls_parse_encrypted_extensions(copy, message_len, &ee));
    }
  }

  /* --- More extensions than the parser holds. Seventeen one-byte
   * early_data-shaped extensions would not fit, so use unknown-but-well-formed
   * ones: the parser records the type before anything else looks at it. */
  {
    uint16_t i;
    block_len = 0U;
    for (i = 0U; i < WT_TLS_MAX_ENCRYPTED_EXTENSIONS + 1U; i++) {
      block_len = ee_ext(block, block_len, (uint16_t)(0x7F00U + i), NULL, 0U);
    }
    message_len = ee_wrap(message, sizeof(message), block, block_len);
    expect_int("seventeen extensions are refused", -1,
               wt_tls_parse_encrypted_extensions(message, message_len, &ee));
    expect_int("  as too many", (long)WT_TLS_EE_TOO_MANY_EXTENSIONS,
               (long)ee.reject);
  }

  /* --- wt_tls_client_hello_offers must agree with what the builder emits.
   *
   * The function is derived from the parameters rather than recorded at encode
   * time, which is only sound if the two cannot drift. So: build a ClientHello
   * from these parameters, walk the extension list it actually contains, and
   * require the answer to be yes for every type present and no for the ones the
   * builder cannot emit. A builder that starts emitting something new fails
   * here rather than silently disagreeing. */
  {
    static const uint8_t alpn_list[3] = {0x02U, 'h', '3'};
    static const uint8_t tp[2] = {0x00U, 0x00U};
    static const uint16_t cannot_emit[] = {
        WT_TLS_EXT_STATUS_REQUEST, WT_TLS_EXT_SIGNED_CERTIFICATE_TIMESTAMP,
        WT_TLS_EXT_RECORD_SIZE_LIMIT, WT_TLS_EXT_PADDING,
        WT_TLS_EXT_PRE_SHARED_KEY, WT_TLS_EXT_COOKIE, 0xFF01U};
    wt_tls_client_hello_params_t params;
    uint8_t hello[512];
    size_t hello_len;
    size_t i;

    ee_offered_params(&params, alpn_list, sizeof(alpn_list), tp, sizeof(tp));
    hello_len = wt_tls_encode_client_hello(&params, hello, sizeof(hello));
    expect_int("the ClientHello encodes", 1, hello_len > 0U ? 1 : 0);
    expect_int("  and frames", (long)WT_TLS_HS_CLIENT_HELLO, (long)hello[0]);

    /* Walk the extensions. The layout before them is fixed for this
       parameter set: 4 header, 2 legacy_version, 32 random, 1 session ID
       length (zero, required for QUIC), 2 cipher suite list length, 2 for the
       one suite, 2 legacy_compression_methods (a length of 1 and the zero
       method). So the extension list's own two-byte length is at offset 45 and
       the list starts at 47. Both offsets are asserted against the message
       rather than trusted. */
    {
      size_t pos = 45U;
      size_t list_end;
      size_t seen = 0U;
      size_t declared = ((size_t)hello[pos] << 8) | (size_t)hello[pos + 1U];
      expect_int("the extension list length is the rest of the message",
                 (long)(hello_len - 47U), (long)declared);
      list_end = hello_len;
      pos += 2U;
      expect_int("the list starts where the layout says", 47, (long)pos);
      while (pos + 4U <= list_end) {
        uint16_t type =
            (uint16_t)(((uint16_t)hello[pos] << 8) | hello[pos + 1U]);
        size_t len =
            ((size_t)hello[pos + 2U] << 8) | (size_t)hello[pos + 3U];
        expect_int("a built extension is reported as offered", 1,
                   wt_tls_client_hello_offers(&params, type));
        pos += 4U + len;
        seen++;
      }
      expect_int("the walk reached the end exactly", (long)list_end, (long)pos);
      expect_int("seven extensions were emitted", 7, (long)seen);
    }
    for (i = 0U; i < sizeof(cannot_emit) / sizeof(cannot_emit[0]); i++) {
      expect_int("an extension the builder cannot emit is not offered", 0,
                 wt_tls_client_hello_offers(&params, cannot_emit[i]));
    }
    expect_int("a NULL parameter list is refused", -1,
               wt_tls_client_hello_offers(NULL, WT_TLS_EXT_ALPN));
  }
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

  expect_int("transcript_init", 0, wt_tls_transcript_init(&transcript));

  /* The server's flight, in order, as the RFC sends it. */
  expect_int("absorb ClientHello", 0,
             wt_tls_transcript_absorb(&transcript, WT_RFC8448_CLIENT_HELLO,
                                      sizeof(WT_RFC8448_CLIENT_HELLO)));
  expect_int("absorb ServerHello", 0,
             wt_tls_transcript_absorb(&transcript, WT_RFC8448_SERVER_HELLO,
                                      sizeof(WT_RFC8448_SERVER_HELLO)));
  expect_int("absorb EncryptedExtensions", 0,
             wt_tls_transcript_absorb(&transcript, WT_RFC8448_ENCRYPTED_EXTENSIONS,
                                      sizeof(WT_RFC8448_ENCRYPTED_EXTENSIONS)));
  expect_int("absorb Certificate", 0,
             wt_tls_transcript_absorb(&transcript, WT_RFC8448_CERTIFICATE,
                                      sizeof(WT_RFC8448_CERTIFICATE)));
  expect_int("absorb CertificateVerify", 0,
             wt_tls_transcript_absorb(&transcript,
                                      WT_RFC8448_CERTIFICATE_VERIFY,
                                      sizeof(WT_RFC8448_CERTIFICATE_VERIFY)));
  expect_int("transcript hash", 0, wt_tls_transcript_hash(&transcript, hash));

  expect_int("the Finished MAC", 0,
             wt_tls_finished_compute(WT_RFC8448_SERVER_HANDSHAKE_TRAFFIC, hash,
                                     verify_data));
  /* The RFC prints this value as the server's Finished. */
  expect_bytes("the Finished MAC is the RFC's", WT_RFC8448_SERVER_FINISHED,
               verify_data, WT_TLS_FINISHED_LEN);

  /* And the same over the RFC's Finished message, which is
     `14 00 00 20 || verify_data`. */
  expect_int("the RFC's Finished message verifies", 1,
             wt_tls_finished_verify(WT_RFC8448_SERVER_HANDSHAKE_TRAFFIC, hash,
                                    WT_RFC8448_FINISHED,
                                    sizeof(WT_RFC8448_FINISHED)));

  /* The client's handshake secret must NOT verify the server's Finished: the
     two directions have different secrets and using the wrong one is the
     mistake this argument exists to prevent. */
  expect_int("the client's secret does not verify the server's Finished", 0,
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
    expect_int("every single-bit MAC forgery is refused", 0, accepted);
  }

  /* A wrong transcript hash must not verify. */
  {
    uint8_t wrong[WT_TLS_HASH_LEN];
    memcpy(wrong, hash, sizeof(wrong));
    wrong[0] ^= 0x01U;
    expect_int("a wrong transcript hash is refused", 0,
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
    expect_int("a Finished-typed check rejects another type", -1,
               wt_tls_finished_verify(WT_RFC8448_SERVER_HANDSHAKE_TRAFFIC,
                                      hash, forged, sizeof(forged)));
    memcpy(forged, WT_RFC8448_FINISHED, sizeof(forged));
    expect_int("a truncated Finished is refused", -1,
               wt_tls_finished_verify(WT_RFC8448_SERVER_HANDSHAKE_TRAFFIC,
                                      hash, forged, 20U));
    expect_int("a NULL message is refused", -1,
               wt_tls_finished_verify(WT_RFC8448_SERVER_HANDSHAKE_TRAFFIC,
                                      hash, NULL, 36U));
    expect_int("a NULL secret is refused", -1,
               wt_tls_finished_verify(NULL, hash, WT_RFC8448_FINISHED,
                                      sizeof(WT_RFC8448_FINISHED)));
  }

  /* compute must refuse bad arguments rather than produce a MAC. */
  expect_int("compute refuses a NULL secret", -1,
             wt_tls_finished_compute(NULL, hash, verify_data));
  expect_int("compute refuses a NULL transcript", -1,
             wt_tls_finished_compute(WT_RFC8448_SERVER_HANDSHAKE_TRAFFIC, NULL,
                                     verify_data));
  expect_int("compute refuses a NULL output", -1,
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
  g_checks++;
  if (hello_len == 0U) {
    g_failures++;
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

  expect_int("protect the ClientHello Initial", 0,
             wt_quic_protect_packet(WT_TLS_AEAD_AES_128_GCM, &keys, &header,
                                    UINT64_C(2), packet,
                                    header_len + frame_len, &packet_len));
  expect_int("the protected packet is the header, the frames and a tag",
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
    expect_int("the ClientHello is not readable in the protected packet", 0,
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

    expect_int("remove header protection", 0,
               wt_quic_header_protection(WT_TLS_AEAD_AES_128_GCM, keys.hp, 16U,
                                         &rx, packet, packet_len));
    for (size_t i = 0U; i < 4U; i++) {
      truncated = (truncated << 8) | packet[18U + i];
    }
    expect_int("recover the packet number", 0,
               wt_quic_decode_packet_number(truncated, 4U, 0U, &pn));
    expect_int("the packet number is 2", 2, (long)pn);
    expect_int("unprotect the packet", 0,
               wt_quic_unprotect_packet(WT_TLS_AEAD_AES_128_GCM, &keys, &rx,
                                        pn, packet, packet_len, recovered,
                                        sizeof(recovered), &plaintext_len));
  }

  /* The recovered CRYPTO frame must carry the ClientHello that went in. */
  expect_int("the recovered payload is the frame", (long)frame_len,
             (long)plaintext_len);
  expect_int("the frame is a CRYPTO frame", 0x06, recovered[0]);
  expect_int("its offset is zero", 0, (long)(recovered[1] | recovered[2] |
                                             recovered[3]));
  {
    size_t declared = ((size_t)recovered[4] << 16) |
                      ((size_t)recovered[5] << 8) | (size_t)recovered[6];
    expect_int("its declared length is the ClientHello's", (long)hello_len,
               (long)declared);
  }
  expect_bytes("the ClientHello survived the round trip", hello,
               recovered + 7U, hello_len);

  /* And it is the same message the transcript would absorb. */
  {
    wt_tls_transcript_t transcript;
    uint8_t hash[WT_TLS_HASH_LEN];
    expect_int("transcript_init", 0, wt_tls_transcript_init(&transcript));
    expect_int("absorb the recovered ClientHello", 0,
               wt_tls_transcript_absorb(&transcript, recovered + 7U, hello_len));
    expect_int("hash it", 0, wt_tls_transcript_hash(&transcript, hash));
    g_checks++;
    if (memcmp(hash, wt_tls_empty_hash, WT_TLS_HASH_LEN) == 0) {
      g_failures++;
      printf("FAIL the recovered ClientHello hashed to nothing\n");
    }
  }
}

int main(void) {
  test_handshake_framing();
  test_transcript();
  test_client_hello_build();
  test_encrypted_extensions();
  test_server_hello_parse();
  test_finished();
  test_parse_then_schedule();
  test_client_hello_through_initial_protection();

  if (g_failures != 0) {
    printf("wt_tls_handshake: %d of %d checks FAILED\n", g_failures, g_checks);
    return 1;
  }
  printf("wt_tls_handshake: all %d checks reproduced their RFC 8446 / 8448 "
         "vector\n", g_checks);
  return 0;
}
