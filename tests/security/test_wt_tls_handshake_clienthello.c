#include "test_wt_tls_handshake_support.h"

/* ------------------------------------------------------------- framing */

void twth_test_handshake_framing(void) {
  uint8_t header[4];
  uint8_t type = 0;
  size_t body_len = 0;
  size_t offset = 0;

  /* RFC 8448's ClientHello starts `01 00 00 c0`: type 1, body length 0xc0. */
  twth_expect_int("encode a 196-byte ClientHello header", 4,
             (long)wt_tls_encode_handshake_header(WT_TLS_HS_CLIENT_HELLO, 192U,
                                                  header));
  twth_expect_bytes("the header is type || uint24 length",
               (const uint8_t *)"\x01\x00\x00\xc0", header, 4);

  /* The message's own first four bytes must decode to the same thing, which
     ties the encoder to the bytes the RFC prints. */
  twth_expect_int("decode the RFC's ClientHello header", 0,
             wt_tls_decode_handshake_header(WT_RFC8448_CLIENT_HELLO,
                                            sizeof(WT_RFC8448_CLIENT_HELLO),
                                            &type, &body_len, &offset));
  twth_expect_int("the RFC's ClientHello is type 1", 1, (long)type);
  twth_expect_int("its body is 192 bytes", 192, (long)body_len);
  twth_expect_int("its body starts at offset 4", 4, (long)offset);
  twth_expect_int("4 + 192 is the whole 196-byte message", 196,
             (long)(offset + body_len));

  twth_expect_int("decode the RFC's ServerHello header", 0,
             wt_tls_decode_handshake_header(WT_RFC8448_SERVER_HELLO,
                                            sizeof(WT_RFC8448_SERVER_HELLO),
                                            &type, &body_len, &offset));
  twth_expect_int("the RFC's ServerHello is type 2", 2, (long)type);
  twth_expect_int("its body is 86 bytes", 86, (long)body_len);

  /* A declared length past the end of the buffer is refused rather than read
     past. This is the check that keeps a peer from walking the transcript
     reader off the end of a message. */
  {
    static const uint8_t lying[] = {0x01, 0x00, 0xff, 0xff, 0x00};
    twth_expect_int("a length past the end is refused", -1,
               wt_tls_decode_handshake_header(lying, sizeof(lying), &type,
                                              &body_len, &offset));
  }
  {
    static const uint8_t truncated[] = {0x01, 0x00};
    twth_expect_int("a truncated header is refused", -1,
               wt_tls_decode_handshake_header(truncated, sizeof(truncated),
                                              &type, &body_len, &offset));
  }
  {
    static const uint8_t exact[] = {0x01, 0x00, 0x00, 0x02, 0xaa, 0xbb};
    twth_expect_int("a length that exactly fits is accepted", 0,
               wt_tls_decode_handshake_header(exact, sizeof(exact), &type,
                                              &body_len, &offset));
    twth_expect_int("and the body length is 2", 2, (long)body_len);
  }
  /* A body of 0xFFFFFF cannot be encoded, because the length would not fit. */
  twth_expect_int("a body too large to encode is refused", 0,
             (long)wt_tls_encode_handshake_header(WT_TLS_HS_CLIENT_HELLO,
                                                  (size_t)0x1000000U, header));
  twth_expect_int("a 0xFFFFFF body is encodable", 4,
             (long)wt_tls_encode_handshake_header(WT_TLS_HS_CLIENT_HELLO,
                                                  (size_t)0xFFFFFFU, header));
  twth_expect_bytes("a 0xFFFFFF length encodes as ff ff ff",
               (const uint8_t *)"\x01\xff\xff\xff", header, 4);
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

void twth_test_client_hello_build(void) {
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
  twth_expect_int("the builder produces the size it measured", (long)size,
             (long)written);

  /* The framing, decoded by the module's own header reader -- which is checked
     against the RFC's messages elsewhere in this file. */
  {
    uint8_t type = 0U;
    size_t body_len = 0U;
    size_t offset = 0U;
    twth_expect_int("the built message frames", 0,
               wt_tls_decode_handshake_header(buffer, written, &type, &body_len,
                                              &offset));
    twth_expect_int("it is a ClientHello", 1, (long)type);
    twth_expect_int("its body is the message minus the four-byte header",
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
    twth_expect_int("the built ClientHello is a whole number of handshake messages",
               (long)written, (long)(4U + ((size_t)buffer[1] << 16) +
                                     ((size_t)buffer[2] << 8) + buffer[3]));

    /* legacy_version must be 0x0303 with the real version in
       supported_versions. */
    twth_expect_int("legacy_version is 0x0303", 0x0303, (long)chr_u16(&r));
    field = chr_take(&r, 32U);
    twth_expect_bytes("the ClientHello random is the one supplied",
                 WT_RFC8448_CLIENT_RANDOM, field, 32);

    twth_expect_int("legacy_session_id is empty, as QUIC requires", 0,
               (long)chr_u8(&r));

    {
      uint16_t suites_len = chr_u16(&r);
      uint16_t suites[8];
      size_t count = suites_len / 2U;
      twth_expect_int("the cipher suite list is six bytes", 6, (long)suites_len);
      /* Bounded by the array, not by the message. The first version looped to
         count straight from the message and wrote eight past the end of a
         three-element buffer under ASan -- a test bug, but the same shape as
         the parsing bugs the test exists to look for, which is why the
         sanitizer run stays in the loop. */
      if (count > sizeof(suites) / sizeof(suites[0])) {
        twth_checks++;
        twth_failures++;
        printf("FAIL the cipher suite list is %zu entries, more than the "
               "verifier holds\n", count);
        count = sizeof(suites) / sizeof(suites[0]);
      }
      for (size_t i = 0U; i < count; i++) suites[i] = chr_u16(&r);
      twth_expect_int("suite 0 is TLS_AES_128_GCM_SHA256", 0x1301, (long)suites[0]);
      twth_expect_int("suite 1 is TLS_CHACHA20_POLY1305_SHA256", 0x1303,
                 (long)suites[1]);
      twth_expect_int("suite 2 is TLS_AES_256_GCM_SHA384", 0x1302, (long)suites[2]);
    }

    {
      uint8_t methods_len = chr_u8(&r);
      twth_expect_int("legacy_compression_methods has one entry", 1,
                 (long)methods_len);
      twth_expect_int("and it is null compression", 0, (long)chr_u8(&r));
    }

    ext_len = chr_u16(&r);
    extensions = chr_take(&r, ext_len);
    if (extensions == NULL) {
      twth_checks++;
      twth_failures++;
      printf("FAIL the extensions block does not fit the message\n");
      return;
    }
    /* The sections before the extensions plus the extensions must consume the
       body exactly. This is the assertion that catches a wrong skip, and it is
       why the walk is worth doing rather than trusting the builder. */
    twth_expect_int("the sections and the extensions consume the body exactly",
               (long)(written - 4U), (long)r.offset);

    /* server_name */
    field = chr_find_extension(extensions, ext_len, 0x0000U, &field_len);
    twth_checks++;
    if (field == NULL) {
      twth_failures++;
      printf("FAIL the ClientHello has no server_name extension\n");
    } else {
      ch_reader_t sni;
      chr_init(&sni, field, field_len);
      twth_expect_int("the server_name list length", (long)(field_len - 2U),
                 (long)chr_u16(&sni));
      twth_expect_int("the name type is host_name", 0, (long)chr_u8(&sni));
      twth_expect_int("the name length is 6", 6, (long)chr_u16(&sni));
      twth_expect_bytes("the name is \"server\"", (const uint8_t *)"server",
                   chr_take(&sni, 6U), 6);
    }

    /* supported_groups, which must equal the RFC's list. */
    field = chr_find_extension(extensions, ext_len, 0x000AU, &field_len);
    twth_checks++;
    if (field == NULL) {
      twth_failures++;
      printf("FAIL the ClientHello has no supported_groups extension\n");
    } else {
      ch_reader_t g;
      uint16_t list_len;
      chr_init(&g, field, field_len);
      list_len = chr_u16(&g);
      twth_expect_int("the supported_groups list is ten bytes", 10, (long)list_len);
      for (size_t i = 0U; i < 5U; i++) {
        twth_expect_int("supported group matches the RFC's", (long)groups[i],
                   (long)chr_u16(&g));
      }
    }

    /* signature_algorithms. */
    field = chr_find_extension(extensions, ext_len, 0x000DU, &field_len);
    twth_checks++;
    if (field == NULL) {
      twth_failures++;
      printf("FAIL the ClientHello has no signature_algorithms extension\n");
    } else {
      ch_reader_t g;
      uint16_t list_len;
      chr_init(&g, field, field_len);
      list_len = chr_u16(&g);
      twth_expect_int("fifteen signature algorithms", 30, (long)list_len);
      for (size_t i = 0U; i < 15U; i++) {
        twth_expect_int("signature algorithm matches the RFC's",
                   (long)signature_algorithms[i], (long)chr_u16(&g));
      }
    }

    /* key_share, including the client's public key. */
    field = chr_find_extension(extensions, ext_len, 0x0033U, &field_len);
    twth_checks++;
    if (field == NULL) {
      twth_failures++;
      printf("FAIL the ClientHello has no key_share extension\n");
    } else {
      ch_reader_t g;
      uint16_t list_len;
      chr_init(&g, field, field_len);
      list_len = chr_u16(&g);
      twth_expect_int("one key share of 36 bytes", 36, (long)list_len);
      twth_expect_int("the group is x25519", 0x001d, (long)chr_u16(&g));
      twth_expect_int("the key is 32 bytes", 32, (long)chr_u16(&g));
      twth_expect_bytes("the key is the client's public key",
                   WT_RFC8448_CLIENT_KEY_PUBLIC, chr_take(&g, 32U), 32);
    }

    /* supported_versions must advertise 1.3 and nothing else. */
    field = chr_find_extension(extensions, ext_len, 0x002BU, &field_len);
    twth_checks++;
    if (field == NULL) {
      twth_failures++;
      printf("FAIL the ClientHello has no supported_versions extension\n");
    } else {
      twth_expect_int("supported_versions is three bytes", 3, (long)field_len);
      twth_expect_int("one version is listed", 2, (long)field[0]);
      twth_expect_int("and it is TLS 1.3", 0x0304,
                 (long)(((uint16_t)field[1] << 8) | field[2]));
    }

    /* alpn */
    field = chr_find_extension(extensions, ext_len, 0x0010U, &field_len);
    twth_checks++;
    if (field == NULL) {
      twth_failures++;
      printf("FAIL the ClientHello has no ALPN extension\n");
    } else {
      /* The extension data is `ProtocolNameList` -- a two-byte list length
         followed by the length-prefixed protocol names -- not the bare list.
         The first version compared the extension data against the caller's
         list and was two bytes out. */
      twth_expect_int("the ALPN extension is the list plus its length prefix",
                 (long)(sizeof(alpn) + 2U), (long)field_len);
      twth_expect_int("the ALPN list length is the caller's", (long)sizeof(alpn),
                 (long)(((uint16_t)field[0] << 8) | field[1]));
      twth_expect_bytes("the ALPN list is the one supplied", alpn, field + 2U,
                   sizeof(alpn));
    }

    /* A QUIC ClientHello without transport parameters is rejected by a server,
       so the builder must emit none only when the caller passes none. */
    field = chr_find_extension(extensions, ext_len, 0x0039U, &field_len);
    twth_expect_int("no quic_transport_parameters extension was requested so none "
               "is present", 1, (long)(field == NULL));
  }

  /* The size function and the encoder must agree, because a caller sizes its
     buffer from one and fills it with the other. */
  {
    static uint8_t exact[512];
    twth_expect_int("a buffer of exactly the measured size is accepted",
               (long)size,
               (long)wt_tls_encode_client_hello(&params, exact, size));
    twth_expect_bytes("and produces the same message", buffer, exact, size);
    twth_expect_int("a buffer one byte short is refused", 0,
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
    twth_expect_int("the QUIC ClientHello grows by exactly the extension overhead",
               (long)(base_size + 52U), (long)real_size);
    written_real = wt_tls_encode_client_hello(&real_params, real_buffer,
                                              sizeof(real_buffer));
    twth_expect_int("a real HTTP/3 ClientHello encodes to its measured size",
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
      twth_checks++;
      if (field == NULL) {
        twth_failures++;
        printf("FAIL the transport parameters are missing\n");
      } else {
        twth_expect_int("the transport parameters are carried verbatim",
                   (long)sizeof(quic_params), (long)field_len);
        twth_expect_bytes("and are the bytes supplied", quic_params, field,
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
      twth_expect_int("the h3 ALPN extension is the list plus its length prefix", 5,
                 (long)field_len);
      twth_expect_int("the h3 list length", 3,
                 (long)(((uint16_t)field[0] << 8) | field[1]));
      twth_expect_bytes("and it is h3", h3, field + 2U, 3);
    }
  }

  /* Refusals. Each of these is a way a client can be wrong on the wire. */
  {
    wt_tls_client_hello_params_t bad = params;
    static const uint8_t session_id[1] = {0x01};

    /* RFC 9001 section 8.4 prohibits a non-empty legacy_session_id for QUIC. */
    bad.legacy_session_id = session_id;
    bad.legacy_session_id_len = 1U;
    twth_expect_int("a non-empty legacy session ID is refused", 0,
               (long)wt_tls_client_hello_size(&bad));
    twth_expect_int("and encoding it is refused", 0,
               (long)wt_tls_encode_client_hello(&bad, buffer, sizeof(buffer)));

    /* A random is mandatory: a builder that defaulted to zeros would produce a
       ClientHello with no unpredictability. */
    bad = params;
    bad.random = NULL;
    twth_expect_int("a NULL random is refused", 0,
               (long)wt_tls_client_hello_size(&bad));

    /* At least one cipher suite is mandatory. */
    bad = params;
    bad.cipher_suite_count = 0U;
    twth_expect_int("no cipher suites is refused", 0,
               (long)wt_tls_client_hello_size(&bad));

    /* No key share is legal TLS and produces a HelloRetryRequest, which is a
       round trip a QUIC handshake is not willing to spend. */
    bad = params;
    bad.key_share_count = 0U;
    bad.key_shares = NULL;
    twth_expect_int("no key share is refused", 0,
               (long)wt_tls_client_hello_size(&bad));

    /* A NULL pointer with a non-zero count is a caller bug. */
    bad = params;
    bad.key_shares = NULL;
    twth_expect_int("a NULL key share array with a count is refused", 0,
               (long)wt_tls_client_hello_size(&bad));
    bad = params;
    bad.supported_groups = NULL;
    twth_expect_int("a NULL group array with a count is refused", 0,
               (long)wt_tls_client_hello_size(&bad));
    bad = params;
    bad.signature_algorithms = NULL;
    twth_expect_int("a NULL signature algorithm array with a count is refused", 0,
               (long)wt_tls_client_hello_size(&bad));

    twth_expect_int("a NULL output is refused", 0,
               (long)wt_tls_encode_client_hello(&params, NULL, 512U));
    twth_expect_int("a NULL params is refused", 0,
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
    twth_checks++;
    if (n == 0U) {
      twth_failures++;
      printf("FAIL a minimal ClientHello reports zero bytes\n");
    } else {
      twth_expect_int("the minimal ClientHello encodes to its measured size",
                 (long)n,
                 (long)wt_tls_encode_client_hello(&minimal, small_buffer,
                                                  sizeof(small_buffer)));
      twth_expect_int("a buffer one byte short is refused", 0,
                 (long)wt_tls_encode_client_hello(&minimal, small_buffer,
                                                  n - 1U));
    }
  }
}
