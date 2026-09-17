#include "test_wt_tls_handshake_support.h"

/* The shared check counters: one definition for the three translation units. */
int twth_failures;
int twth_checks;

void twth_test_encrypted_extensions(void) {
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
  twth_expect_int("parse the RFC's EncryptedExtensions", 0,
             wt_tls_parse_encrypted_extensions(
                 WT_RFC8448_ENCRYPTED_EXTENSIONS,
                 sizeof(WT_RFC8448_ENCRYPTED_EXTENSIONS), &ee));
  twth_expect_int("its reject reason is none", 0, (long)ee.reject);
  twth_expect_int("three extensions", 3, (long)ee.type_count);
  twth_expect_int("the first is supported_groups", WT_TLS_EXT_SUPPORTED_GROUPS,
             (long)ee.types[0]);
  twth_expect_int("the second is record_size_limit", WT_TLS_EXT_RECORD_SIZE_LIMIT,
             (long)ee.types[1]);
  twth_expect_int("the third is server_name", WT_TLS_EXT_SERVER_NAME,
             (long)ee.types[2]);
  twth_expect_int("supported_groups is present", 1, ee.has_supported_groups);
  twth_expect_int("server_name is present and empty", 1, ee.has_server_name);
  twth_expect_int("no ALPN", 0, ee.has_alpn);
  twth_expect_int("no transport parameters", 0, ee.has_transport_parameters);
  twth_expect_int("no max_fragment_length", 0, ee.has_max_fragment_length);
  twth_expect_int("no early_data", 0, ee.has_early_data);

  /* --- The check runs against this client's offered set, which is not RFC
   * 8448's (that trace is TLS over TCP). record_size_limit is legal in
   * EncryptedExtensions but this client never asked for it, so rule 1 fires
   * first and it is unsolicited rather than forbidden. */
  {
    wt_tls_client_hello_params_t params;
    ee_offered_params(&params, NULL, 0U, NULL, 0U);
    twth_expect_int("record_size_limit is unsolicited, not forbidden", -1,
               wt_tls_encrypted_extensions_check(
                   &ee, &params, &reject, &offender));
    twth_expect_int("  and the reason says so", (long)WT_TLS_EE_UNSOLICITED_EXTENSION,
               (long)reject);
    twth_expect_int("  naming record_size_limit", WT_TLS_EXT_RECORD_SIZE_LIMIT,
               (long)offender);
  }

  /* --- A QUIC EncryptedExtensions: ALPN "h3" and transport parameters. */
  {
    /* RFC 7301: the server's extension_data is a ProtocolNameList of
       exactly one name, so two bytes of list length come first. */
    static const uint8_t h3[5] = {0x00U, 0x03U, 0x02U, 'h', '3'};
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
    twth_expect_int("the wrapped message is the block plus six", (long)block_len + 6,
               (long)message_len);
    twth_expect_int("parse a QUIC EncryptedExtensions", 0,
               wt_tls_parse_encrypted_extensions(message, message_len, &ee));
    twth_expect_int("ALPN is present", 1, ee.has_alpn);
    twth_expect_bytes("the selected protocol is h3", (const uint8_t *)"h3", ee.alpn,
                 ee.alpn_len);
    twth_expect_int("two bytes of protocol", 2, (long)ee.alpn_len);
    twth_expect_int("transport parameters are present", 1,
               ee.has_transport_parameters);
    twth_expect_bytes("the parameters survived", tp, ee.transport_parameters,
                 ee.transport_parameters_len);

    ee_offered_params(&params, alpn_list, sizeof(alpn_list), tp, sizeof(tp));
    twth_expect_int("both were offered, so the check accepts", 0,
               wt_tls_encrypted_extensions_check(&ee, &params, &reject,
                                                 &offender));
    twth_expect_int("  and the reason is none", (long)WT_TLS_EE_OK, (long)reject);

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
        twth_expect_int("parse an EncryptedExtensions with a misplaced extension", 0,
                   wt_tls_parse_encrypted_extensions(message, message_len, &ee));
        twth_expect_int("the check refuses it", -1,
                   wt_tls_encrypted_extensions_check(&ee, &params, &reject,
                                                     &offender));
        twth_expect_int("  as a forbidden extension",
                   (long)WT_TLS_EE_FORBIDDEN_EXTENSION, (long)reject);
        twth_expect_int("  naming it", (long)forbidden[i], (long)offender);
      }
    }

    /* --- Rule 1: an extension this ClientHello never offered at all. */
    {
      static const uint8_t body[1] = {0x00U};
      block_len = ee_ext(block, 0U, WT_TLS_EXT_STATUS_REQUEST, body,
                         sizeof(body));
      message_len = ee_wrap(message, sizeof(message), block, block_len);
      twth_expect_int("parse an EncryptedExtensions with an unrequested extension", 0,
                 wt_tls_parse_encrypted_extensions(message, message_len, &ee));
      twth_expect_int("the check refuses it", -1,
                 wt_tls_encrypted_extensions_check(&ee, &params, &reject,
                                                   &offender));
      twth_expect_int("  as unsolicited", (long)WT_TLS_EE_UNSOLICITED_EXTENSION,
                 (long)reject);
      twth_expect_int("  naming status_request", WT_TLS_EXT_STATUS_REQUEST,
                 (long)offender);
    }
  }

  /* --- Bodies that are the right extension but the wrong shape. */
  {
    static const uint8_t two_protocols[8] = {0x00U, 0x06U, 0x02U, 'h',
                                              '3',   0x02U, 'h',    '2'};
    static const uint8_t empty_protocol[3] = {0x00U, 0x01U, 0x00U};
    static const uint8_t named_server[3] = {0x01U, 'a', 'b'};
    static const uint8_t bad_mfl[1] = {0x05U};
    static const uint8_t one_byte[1] = {0x01U};

    /* RFC 7301: the server answers with exactly one protocol. A client that
       took the first of two would be agreeing to something the server did not
       choose. */
    block_len = ee_ext(block, 0U, WT_TLS_EXT_ALPN, two_protocols,
                       sizeof(two_protocols));
    message_len = ee_wrap(message, sizeof(message), block, block_len);
    twth_expect_int("two ALPN names are refused", -1,
               wt_tls_parse_encrypted_extensions(message, message_len, &ee));
    twth_expect_int("  as a bad extension", (long)WT_TLS_EE_BAD_EXTENSION,
               (long)ee.reject);
    twth_expect_int("  naming ALPN", WT_TLS_EXT_ALPN, (long)ee.reject_extension);

    block_len = ee_ext(block, 0U, WT_TLS_EXT_ALPN, empty_protocol,
                       sizeof(empty_protocol));
    message_len = ee_wrap(message, sizeof(message), block, block_len);
    twth_expect_int("an empty ALPN name is refused", -1,
               wt_tls_parse_encrypted_extensions(message, message_len, &ee));

    /* THE BARE-NAME FORM IS NOT THE WIRE FORMAT. The parser first read the
       server's answer as `protocol_name<1..255>` -- one length byte then the
       name -- which is what the structure looks like it wants and is not what
       RFC 7301 says is carried: the server's extension_data is a
       ProtocolNameList of exactly one name, so a two-byte list length comes
       first. The flattened form is refused, and this is the check that would
       have caught it: nothing else in the repository carries ALPN, because RFC
       8448's EncryptedExtensions has none. */
    {
      static const uint8_t bare_name[3] = {0x02U, 'h', '3'};
      static const uint8_t list_too_long[5] = {0x00U, 0x04U, 0x02U, 'h', '3'};
      static const uint8_t list_too_short[5] = {0x00U, 0x02U, 0x02U, 'h',
                                                '3'};
      block_len = ee_ext(block, 0U, WT_TLS_EXT_ALPN, bare_name,
                         sizeof(bare_name));
      message_len = ee_wrap(message, sizeof(message), block, block_len);
      twth_expect_int("a bare protocol name is refused", -1,
                 wt_tls_parse_encrypted_extensions(message, message_len, &ee));
      twth_expect_int("  as a bad extension", (long)WT_TLS_EE_BAD_EXTENSION,
                 (long)ee.reject);
      block_len = ee_ext(block, 0U, WT_TLS_EXT_ALPN, list_too_long,
                         sizeof(list_too_long));
      message_len = ee_wrap(message, sizeof(message), block, block_len);
      twth_expect_int("an ALPN list length that overruns the extension is refused",
                 -1,
                 wt_tls_parse_encrypted_extensions(message, message_len, &ee));
      block_len = ee_ext(block, 0U, WT_TLS_EXT_ALPN, list_too_short,
                         sizeof(list_too_short));
      message_len = ee_wrap(message, sizeof(message), block, block_len);
      twth_expect_int("an ALPN list length that underruns it is refused", -1,
                 wt_tls_parse_encrypted_extensions(message, message_len, &ee));
    }

    block_len = ee_ext(block, 0U, WT_TLS_EXT_SERVER_NAME, named_server,
                       sizeof(named_server));
    message_len = ee_wrap(message, sizeof(message), block, block_len);
    twth_expect_int("a server_name with content is refused", -1,
               wt_tls_parse_encrypted_extensions(message, message_len, &ee));
    twth_expect_int("  naming server_name", WT_TLS_EXT_SERVER_NAME,
               (long)ee.reject_extension);

    block_len = ee_ext(block, 0U, WT_TLS_EXT_MAX_FRAGMENT_LENGTH, bad_mfl,
                       sizeof(bad_mfl));
    message_len = ee_wrap(message, sizeof(message), block, block_len);
    twth_expect_int("max_fragment_length 5 is refused", -1,
               wt_tls_parse_encrypted_extensions(message, message_len, &ee));
    block_len = ee_ext(block, 0U, WT_TLS_EXT_MAX_FRAGMENT_LENGTH, one_byte,
                       sizeof(one_byte));
    message_len = ee_wrap(message, sizeof(message), block, block_len);
    twth_expect_int("max_fragment_length 1 is accepted", 0,
               wt_tls_parse_encrypted_extensions(message, message_len, &ee));
    twth_expect_int("  and recorded", 1, ee.has_max_fragment_length);
    twth_expect_int("  with its value", 1, (long)ee.max_fragment_length);
    {
      /* 2 (2^9) is the smallest legal value in the other direction. */
      static const uint8_t mfl_two[1] = {0x02U};
      static const uint8_t mfl_zero[1] = {0x00U};
      block_len = ee_ext(block, 0U, WT_TLS_EXT_MAX_FRAGMENT_LENGTH, mfl_two,
                         sizeof(mfl_two));
      message_len = ee_wrap(message, sizeof(message), block, block_len);
      twth_expect_int("max_fragment_length 2 is accepted", 0,
                 wt_tls_parse_encrypted_extensions(message, message_len, &ee));
      block_len = ee_ext(block, 0U, WT_TLS_EXT_MAX_FRAGMENT_LENGTH, mfl_zero,
                         sizeof(mfl_zero));
      message_len = ee_wrap(message, sizeof(message), block, block_len);
      twth_expect_int("max_fragment_length 0 is refused", -1,
                 wt_tls_parse_encrypted_extensions(message, message_len, &ee));
    }
  }

  /* --- The same extension twice: RFC 8446 section 4.2 forbids it, and two
   * ALPN answers would leave which one binds ambiguous while the transcript
   * still verifies. */
  {
    /* RFC 7301: the server's extension_data is a ProtocolNameList of
       exactly one name, so two bytes of list length come first. */
    static const uint8_t h3[5] = {0x00U, 0x03U, 0x02U, 'h', '3'};
    block_len = 0U;
    block_len = ee_ext(block, block_len, WT_TLS_EXT_ALPN, h3, sizeof(h3));
    block_len = ee_ext(block, block_len, WT_TLS_EXT_ALPN, h3, sizeof(h3));
    message_len = ee_wrap(message, sizeof(message), block, block_len);
    twth_expect_int("a repeated extension is refused", -1,
               wt_tls_parse_encrypted_extensions(message, message_len, &ee));
    twth_expect_int("  as a duplicate", (long)WT_TLS_EE_DUPLICATE_EXTENSION,
               (long)ee.reject);
    twth_expect_int("  naming ALPN", WT_TLS_EXT_ALPN, (long)ee.reject_extension);
  }

  /* --- Structural refusals, each reachable from the wire. */
  {
    /* RFC 7301: the server's extension_data is a ProtocolNameList of
       exactly one name, so two bytes of list length come first. */
    static const uint8_t h3[5] = {0x00U, 0x03U, 0x02U, 'h', '3'};
    block_len = ee_ext(block, 0U, WT_TLS_EXT_ALPN, h3, sizeof(h3));
    message_len = ee_wrap(message, sizeof(message), block, block_len);

    /* A declared list length that is not the rest of the body is trailing
       bytes: a second message smuggled inside one the transcript hashes. */
    {
      uint8_t copy[600];
      memcpy(copy, message, message_len);
      copy[5] = (uint8_t)(copy[5] - 1U);
      twth_expect_int("a short extension list is refused", -1,
                 wt_tls_parse_encrypted_extensions(copy, message_len, &ee));
      twth_expect_int("  as malformed", (long)WT_TLS_EE_MALFORMED, (long)ee.reject);
      copy[5] = (uint8_t)(copy[5] + 2U);
      twth_expect_int("a long extension list is refused", -1,
                 wt_tls_parse_encrypted_extensions(copy, message_len, &ee));
    }
    /* The wrong handshake message entirely. */
    {
      uint8_t copy[600];
      memcpy(copy, message, message_len);
      copy[0] = WT_TLS_HS_CERTIFICATE;
      twth_expect_int("a Certificate is not an EncryptedExtensions", -1,
                 wt_tls_parse_encrypted_extensions(copy, message_len, &ee));
    }
    /* Truncation at every length. */
    {
      size_t cut;
      for (cut = 0U; cut < message_len; cut++) {
        twth_expect_int("a truncated EncryptedExtensions is refused", -1,
                   wt_tls_parse_encrypted_extensions(message, cut, &ee));
      }
    }
    /* An extension whose declared length runs past the end of the list. */
    {
      uint8_t copy[600];
      memcpy(copy, message, message_len);
      copy[8] = 0x7FU; /* ALPN's length field */
      twth_expect_int("an extension longer than the list is refused", -1,
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
    twth_expect_int("seventeen extensions are refused", -1,
               wt_tls_parse_encrypted_extensions(message, message_len, &ee));
    twth_expect_int("  as too many", (long)WT_TLS_EE_TOO_MANY_EXTENSIONS,
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
    twth_expect_int("the ClientHello encodes", 1, hello_len > 0U ? 1 : 0);
    twth_expect_int("  and frames", (long)WT_TLS_HS_CLIENT_HELLO, (long)hello[0]);

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
      twth_expect_int("the extension list length is the rest of the message",
                 (long)(hello_len - 47U), (long)declared);
      list_end = hello_len;
      pos += 2U;
      twth_expect_int("the list starts where the layout says", 47, (long)pos);
      while (pos + 4U <= list_end) {
        uint16_t type =
            (uint16_t)(((uint16_t)hello[pos] << 8) | hello[pos + 1U]);
        size_t len =
            ((size_t)hello[pos + 2U] << 8) | (size_t)hello[pos + 3U];
        twth_expect_int("a built extension is reported as offered", 1,
                   wt_tls_client_hello_offers(&params, type));
        pos += 4U + len;
        seen++;
      }
      twth_expect_int("the walk reached the end exactly", (long)list_end, (long)pos);
      twth_expect_int("seven extensions were emitted", 7, (long)seen);
    }
    for (i = 0U; i < sizeof(cannot_emit) / sizeof(cannot_emit[0]); i++) {
      twth_expect_int("an extension the builder cannot emit is not offered", 0,
                 wt_tls_client_hello_offers(&params, cannot_emit[i]));
    }
    twth_expect_int("a NULL parameter list is refused", -1,
               wt_tls_client_hello_offers(NULL, WT_TLS_EXT_ALPN));
  }
}

/* -------------------------------------------------------- ServerHello parse */

void twth_test_server_hello_parse(void) {
  wt_tls_server_hello_t hello;

  /* RFC 8448's ServerHello echoes a zero-length session ID and selects
     TLS_AES_128_GCM_SHA256 (0x1301) and x25519 (0x001d). */
  twth_expect_int("parse the RFC's ServerHello", 0,
             wt_tls_parse_server_hello(WT_RFC8448_SERVER_HELLO,
                                       sizeof(WT_RFC8448_SERVER_HELLO), NULL,
                                       0U, &hello));
  twth_expect_int("the cipher suite is TLS_AES_128_GCM_SHA256", 0x1301,
             (long)hello.cipher_suite);
  twth_expect_int("the negotiated version is TLS 1.3", 0x0304,
             (long)hello.selected_version);
  twth_expect_int("supported_versions was present", 1,
             (long)hello.has_supported_versions);
  twth_expect_int("the key share group is x25519", 0x001d, (long)hello.group);
  twth_expect_int("the key share is 32 bytes", 32, (long)hello.key_share_len);
  twth_expect_int("key_share was present", 1, (long)hello.has_key_share);

  /* The key share is the server's public key, which the RFC prints in the
     message construction. Comparing it against the bytes inside the message
     would be circular, so it is checked against the transcript-derived value
     below instead: the secret it produces is the one the RFC publishes. */
  twth_checks++;
  if (hello.key_share == NULL || hello.key_share[0] == 0U) {
    twth_failures++;
    printf("FAIL the key share is empty\n");
  }

  /* A session ID that does not match what the client sent is refused. */
  {
    static const uint8_t wrong_session_id[1] = {0x00};
    twth_expect_int("a non-matching session ID echo is refused", -1,
               wt_tls_parse_server_hello(WT_RFC8448_SERVER_HELLO,
                                         sizeof(WT_RFC8448_SERVER_HELLO),
                                         wrong_session_id, 1U, &hello));
  }

  /* A message that is not a ServerHello is refused by type. */
  twth_expect_int("a ClientHello is not a ServerHello", -1,
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
    twth_expect_int("no truncated ServerHello is accepted", 0, accepted);
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
          twth_expect_int("a downgraded version is refused", -1,
                     wt_tls_parse_server_hello(tampered, sizeof(tampered), NULL,
                                               0U, &hello));
          found = 1;
          break;
        }
      }
      twth_expect_int("the supported_versions extension was located to tamper with",
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
    twth_expect_int("a legacy_version of 0x0304 is refused", -1,
               wt_tls_parse_server_hello(tampered, sizeof(tampered), NULL, 0U,
                                         &hello));
  }
}

