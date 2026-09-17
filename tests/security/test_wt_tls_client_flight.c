/* The Certificate step and the flights that run to completion.
 *
 * The second module cut from `test_wt_tls_client.c`: reaching the point where
 * EncryptedExtensions is expected, the Certificate refusals, the finished
 * flight, the client-auth variant and the two checks that the client owns what
 * it keeps and that the flight outlives the call that produced it. The fixture
 * and builders they share are declared in `test_wt_tls_client_support.h`, and
 * the order of the tests matches the order `main` calls them in.
 *
 * Transport parameters stay function-scope: the client keeps a view of the
 * server's parameters inside the buffer they arrived in, so a good
 * EncryptedExtensions must outlive the call that read it.
 */
#include "test_wt_tls_client_support.h"

#include "wt_rfc8448_vectors.h"
#include "wt_quic_flight_vectors.h"

#include <stdio.h>
#include <string.h>

/* Drive a handshake to the point where EncryptedExtensions is expected. */
int wtc_reach_wait_encrypted_extensions(wt_tls_client_t *handshake) {
  if (wtc_start_client(handshake) != 0) return -1;
  if (wtc_feed(handshake, WT_TLS_LEVEL_INITIAL, WT_QUIC_FLIGHT_SERVER_HELLO,
           sizeof(WT_QUIC_FLIGHT_SERVER_HELLO)) != 0) {
    return -1;
  }
  return 0;
}

/* ------------------------------------------------- the Certificate step */

void wtc_test_certificate(void) {
  wt_tls_client_t handshake;
  wt_tls_pinned_key_t other_pin;
  wt_tls_public_key_t key;
  /* Function scope: see test_encrypted_extensions. */
  uint8_t ee[256];
  uint8_t message[1024];

  wtc_setup_params();
  wtc_setup_pin();

  /* --- an empty chain: a server that cannot authenticate --- */
  if (wtc_reach_wait_encrypted_extensions(&handshake) != 0) return;
  {
    size_t len = wtc_good_encrypted_extensions(ee, sizeof(ee));
    if (wtc_feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, ee, len) != 0) return;
  }
  /* A Certificate with an empty certificate_list. */
  message[0] = WT_TLS_HS_CERTIFICATE;
  message[1] = 0x00U;
  message[2] = 0x00U;
  message[3] = 0x07U;
  message[4] = 0x00U; /* empty context */
  message[5] = 0x00U;
  message[6] = 0x00U;
  message[7] = 0x00U; /* empty list */
  message[8] = 0x00U;
  message[9] = 0x00U; /* empty extensions */
  /* RFC 8446 section 4.4.2: a server authenticates with a certificate, so an
     empty certificate_list is a malformed message rather than a server that
     declined to authenticate, and `wt_tls_parse_certificate` refuses it. The
     alert is therefore the parser's decode_error and not the handler's
     bad_certificate -- the handler never sees it. */
  wtc_expect_int("an empty certificate chain is refused", -1,
             wtc_feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, message, 10U));
  wtc_expect_int("  as a decode error", WT_TLS_ALERT_DECODE_ERROR,
             (long)wt_tls_client_alert(&handshake));

  /* --- a certificate that is not the pinned one --- */
  if (wtc_reach_wait_encrypted_extensions(&handshake) != 0) return;
  {
    size_t len = wtc_good_encrypted_extensions(ee, sizeof(ee));
    if (wtc_feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, ee, len) != 0) return;
  }
  wtc_expect_int("the fixture's key is readable", 0,
             wt_tls_certificate_public_key(wtc_certificate_der,
                                           wtc_certificate_der_len, &key));
  {
    /* The same key with one bit of the modulus flipped: a real key of the
       right shape that is not the pinned one. */
    uint8_t modulus[WT_TLS_PUBLIC_KEY_MAX];
    memcpy(modulus, key.rsa.n, key.rsa.nlen);
    modulus[64] ^= 0x01U;
    wtc_expect_int("the other pin is set", 0,
               wt_tls_pinned_key_set_rsa(&other_pin, modulus, key.rsa.nlen,
                                         key.rsa.e, key.rsa.elen));
  }
  {
    wt_tls_client_config_t config;
    wt_tls_client_t pinned_elsewhere;
    uint8_t hello[512];
    memset(&config, 0, sizeof(config));
    config.params = &wtc_params;
    config.pin = &other_pin;
    config.client_key_private = WT_QUIC_FLIGHT_CLIENT_PRIVATE;
    config.client_key_private_len = sizeof(WT_QUIC_FLIGHT_CLIENT_PRIVATE);
    if (wt_tls_client_start(&pinned_elsewhere, &config, hello,
                            sizeof(hello)) == 0U) {
      printf("FATAL the second handshake could not be built\n");
      wtc_failures++;
      return;
    }
    if (wtc_feed(&pinned_elsewhere, WT_TLS_LEVEL_INITIAL,
             WT_QUIC_FLIGHT_SERVER_HELLO,
             sizeof(WT_QUIC_FLIGHT_SERVER_HELLO)) != 0) {
      return;
    }
    {
      size_t len = wtc_good_encrypted_extensions(ee, sizeof(ee));
      if (wtc_feed(&pinned_elsewhere, WT_TLS_LEVEL_HANDSHAKE, ee, len) != 0) return;
    }
    wtc_expect_int("a certificate that is not the pinned key is refused", -1,
               wtc_feed(&pinned_elsewhere, WT_TLS_LEVEL_HANDSHAKE,
                    WT_QUIC_FLIGHT_CERTIFICATE,
                    sizeof(WT_QUIC_FLIGHT_CERTIFICATE)));
    wtc_expect_int("  as an unknown CA", WT_TLS_ALERT_UNKNOWN_CA,
               (long)wt_tls_client_alert(&pinned_elsewhere));
  }

  /* --- a certificate that is not a certificate --- */
  if (wtc_reach_wait_encrypted_extensions(&handshake) != 0) return;
  {
    size_t len = wtc_good_encrypted_extensions(ee, sizeof(ee));
    if (wtc_feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, ee, len) != 0) return;
  }
  {
    /* A well-framed Certificate whose single entry is not DER. The pin reader
       cannot read a key from it, so the refusal is bad_certificate rather than
       unknown_ca: the client did not learn that the key is wrong, it learned
       that there is no key. */
    /* A well-framed Certificate whose single entry is 24 bytes of not-DER:
       type, body length, empty context, a certificate_list of one entry, the
       entry's own three-byte length, the rubbish, and an empty extension
       block. The framing has to be right for the refusal to be about the key
       rather than about the message. */
    uint8_t garbage[64];
    size_t offset;
    size_t i;
    garbage[0] = WT_TLS_HS_CERTIFICATE;
    garbage[1] = 0x00U;
    garbage[2] = 0x00U;
    garbage[3] = 33U; /* 1 + 3 + 3 + 24 + 2 */
    garbage[4] = 0x00U; /* empty certificate_request_context */
    garbage[5] = 0x00U;
    garbage[6] = 0x00U;
    /* certificate_list holds the entry's three-byte length, the DER, and the
       entry's own two-byte extension block: 3 + 24 + 2 = 29. Counting only the
       length and the DER makes the parser refuse the message for its framing,
       which is a decode error and not the bad_certificate this check is
       about. */
    garbage[7] = 29U;
    garbage[8] = 0x00U;
    garbage[9] = 0x00U;
    garbage[10] = 24U; /* the entry's length */
    offset = 11U;
    for (i = 0U; i < 24U; i++) garbage[offset++] = (uint8_t)(0xA5U + i);
    garbage[offset++] = 0x00U;
    garbage[offset++] = 0x00U;
    wtc_expect_int("a Certificate whose entry is not DER is refused", -1,
               wtc_feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, garbage, offset));
    wtc_expect_int("  as a bad certificate", WT_TLS_ALERT_BAD_CERTIFICATE,
               (long)wt_tls_client_alert(&handshake));
  }

  /* --- the pinned certificate --- */
  if (wtc_reach_wait_encrypted_extensions(&handshake) != 0) return;
  {
    size_t len = wtc_good_encrypted_extensions(ee, sizeof(ee));
    if (wtc_feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, ee, len) != 0) return;
  }
  wtc_expect_int("the pinned certificate is accepted", 0,
             wtc_feed(&handshake, WT_TLS_LEVEL_HANDSHAKE,
                  WT_QUIC_FLIGHT_CERTIFICATE,
                  sizeof(WT_QUIC_FLIGHT_CERTIFICATE)));
  wtc_expect_int("the handshake now waits for CertificateVerify",
             (long)WT_TLS_STATE_WAIT_CERTIFICATE_VERIFY,
             (long)wt_tls_client_state(&handshake));
  wtc_expect_int("transport parameters are still withheld", 0,
             wt_tls_client_peer_transport_parameters(&handshake, NULL) == NULL
                 ? 0
                 : 1);
}

/* -------------------------------------------------------- the whole flight */

void wtc_test_full_handshake(void) {
  wt_tls_client_t handshake;
  wt_tls_traffic_keys_t keys;
  /* Function scope: see test_encrypted_extensions. */
  uint8_t ee[256];
  const uint8_t *out = NULL;
  const uint8_t *parameters = NULL;
  size_t parameters_len = 0U;
  size_t out_len = 0U;
  wt_tls_level_t out_level = WT_TLS_LEVEL_INITIAL;

  wtc_setup_params();
  wtc_setup_pin();

  if (wtc_reach_wait_encrypted_extensions(&handshake) != 0) {
    printf("FATAL could not start the full handshake\n");
    wtc_failures++;
    return;
  }
  {
    size_t len = wtc_good_encrypted_extensions(ee, sizeof(ee));
    if (wtc_feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, ee, len) != 0) return;
  }
  if (wtc_feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, WT_QUIC_FLIGHT_CERTIFICATE,
           sizeof(WT_QUIC_FLIGHT_CERTIFICATE)) != 0) {
    return;
  }
  if (wtc_feed(&handshake, WT_TLS_LEVEL_HANDSHAKE,
           WT_QUIC_FLIGHT_CERTIFICATE_VERIFY,
           sizeof(WT_QUIC_FLIGHT_CERTIFICATE_VERIFY)) != 0) {
    return;
  }
  wtc_expect_int("the handshake now waits for Finished",
             (long)WT_TLS_STATE_WAIT_FINISHED,
             (long)wt_tls_client_state(&handshake));

  /* --- the server's Finished, and the client's own --- */
  wtc_expect_int("the server's Finished is accepted", 0,
             wt_tls_client_receive(&handshake, WT_TLS_LEVEL_HANDSHAKE,
                                   WT_QUIC_FLIGHT_FINISHED,
                                   sizeof(WT_QUIC_FLIGHT_FINISHED), &out,
                                   &out_len, &out_level));
  wtc_expect_int("the handshake is complete", (long)WT_TLS_STATE_CONNECTED,
             (long)wt_tls_client_state(&handshake));
  wtc_expect_int("the client's flight goes out at the Handshake level",
             (long)WT_TLS_LEVEL_HANDSHAKE, (long)out_level);
  wtc_expect_int("the flight is exactly a Finished", (long)(4U + 32U),
             (long)out_len);
  wtc_expect_int("and it was reported", 1, out != NULL ? 1 : 0);
  wtc_checks++;
  if (out == NULL || out_len < 36U) {
    wtc_failures++;
    printf("FAIL no client flight was produced\n");
  } else {
    wtc_expect_int("it is a Finished message", WT_TLS_HS_FINISHED, (long)out[0]);
    wtc_expect_int("of 32 bytes", 32, (long)out[3]);
    /* THE CHECK THAT MATTERS: the client's Finished MAC, computed over the
       transcript through the server's Finished with the client handshake
       traffic secret, must equal the value the independent Python
       implementation computed for the same flight. A transcript that absorbed
       a message twice, or in the wrong order, or took the hash before absorbing
       the server's Finished, produces a different MAC here. */
    wtc_expect_bytes("the client's Finished MAC is the oracle's",
                 WT_QUIC_FLIGHT_CLIENT_FINISHED, out + 4U, 32U);
  }

  /* --- the client's client-authentication flight would come first if the
     server had asked; it did not, so the flight is just the Finished --- */

  /* --- the application keys, against the oracle's own derivation --- */
  wtc_expect_int("application keys are available for reading", 1,
             wt_tls_client_keys_available(&handshake, WT_TLS_LEVEL_APPLICATION,
                                          1));
  wtc_expect_int("and for writing", 1,
             wt_tls_client_keys_available(&handshake, WT_TLS_LEVEL_APPLICATION,
                                          0));
  wtc_expect_int("the server's application keys are readable", 0,
             wt_tls_client_keys(&handshake, WT_TLS_LEVEL_APPLICATION, 1, &keys));
  wtc_expect_bytes("the server application secret is the oracle's",
               WT_QUIC_FLIGHT_SERVER_APPLICATION_SECRET, keys.secret, 32U);
  wtc_expect_int("the client's application keys are readable", 0,
             wt_tls_client_keys(&handshake, WT_TLS_LEVEL_APPLICATION, 0, &keys));
  wtc_expect_bytes("the client application secret is the oracle's",
               WT_QUIC_FLIGHT_CLIENT_APPLICATION_SECRET, keys.secret, 32U);

  /* --- the transport parameters, now that they are authenticated --- */
  parameters = wt_tls_client_peer_transport_parameters(&handshake,
                                                       &parameters_len);
  wtc_expect_int("the transport parameters are released once the handshake "
             "completes",
             1, parameters != NULL ? 1 : 0);
  wtc_expect_bytes("and they are the ones the server sent",
               WT_QUIC_FLIGHT_SERVER_TRANSPORT_PARAMETERS, parameters,
               sizeof(WT_QUIC_FLIGHT_SERVER_TRANSPORT_PARAMETERS));
  wtc_expect_int("with the right length",
             (long)sizeof(WT_QUIC_FLIGHT_SERVER_TRANSPORT_PARAMETERS),
             (long)parameters_len);
  {
    size_t alpn_len = 0U;
    const uint8_t *alpn = wt_tls_client_alpn(&handshake, &alpn_len);
    wtc_expect_int("and the negotiated ALPN is still h3", 1,
               (alpn != NULL && alpn_len == 2U && memcmp(alpn, "h3", 2U) == 0)
                   ? 1
                   : 0);
  }

  /* --- the handshake is passive afterwards --- */
  wtc_expect_int("a message after completion is refused", -1,
             wtc_feed(&handshake, WT_TLS_LEVEL_APPLICATION,
                  WT_QUIC_FLIGHT_FINISHED, sizeof(WT_QUIC_FLIGHT_FINISHED)));
  wtc_expect_int("  as an unexpected message", WT_TLS_ALERT_UNEXPECTED_MESSAGE,
             (long)wt_tls_client_alert(&handshake));

  /* --- clearing wipes the keys --- */
  wt_tls_client_clear(&handshake);
  wtc_expect_int("cleared keys are not available", 0,
             wt_tls_client_keys_available(&handshake, WT_TLS_LEVEL_APPLICATION,
                                          1));
  wtc_expect_int("and not readable", -1,
             wt_tls_client_keys(&handshake, WT_TLS_LEVEL_APPLICATION, 1, &keys));
}

/* ------------------------------------------------------- a client auth ask */

/* RFC 8446 section 4.4.2: a client with no suitable certificate must send an
 * empty Certificate message rather than nothing, and must echo the
 * certificate_request_context. The flight is therefore longer than the
 * no-client-auth one, and -- this is the part worth testing -- the Finished MAC
 * covers the Certificate, so it is a different MAC. The oracle computed the
 * whole client flight for this variant, so it is compared byte for byte. */
void wtc_test_client_auth_request(void) {
  wt_tls_client_t handshake;
  /* Function scope: see test_encrypted_extensions. */
  uint8_t ee[256];
  const uint8_t *out = NULL;
  size_t out_len = 0U;
  wt_tls_level_t out_level = WT_TLS_LEVEL_INITIAL;

  wtc_setup_params();
  wtc_setup_pin();

  if (wtc_reach_wait_encrypted_extensions(&handshake) != 0) return;
  {
    size_t len = wtc_good_encrypted_extensions(ee, sizeof(ee));
    if (wtc_feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, ee, len) != 0) return;
  }

  wtc_expect_int("a CertificateRequest is accepted", 0,
             wtc_feed(&handshake, WT_TLS_LEVEL_HANDSHAKE,
                  WT_QUIC_FLIGHT_CLIENT_AUTH_REQUEST,
                  sizeof(WT_QUIC_FLIGHT_CLIENT_AUTH_REQUEST)));
  wtc_expect_int("and the handshake still wants a Certificate",
             (long)WT_TLS_STATE_WAIT_CERTIFICATE,
             (long)wt_tls_client_state(&handshake));

  if (wtc_feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, WT_QUIC_FLIGHT_CERTIFICATE,
           sizeof(WT_QUIC_FLIGHT_CERTIFICATE)) != 0) {
    return;
  }
  if (wtc_feed(&handshake, WT_TLS_LEVEL_HANDSHAKE,
           WT_QUIC_FLIGHT_CLIENT_AUTH_CERTIFICATE_VERIFY,
           sizeof(WT_QUIC_FLIGHT_CLIENT_AUTH_CERTIFICATE_VERIFY)) != 0) {
    return;
  }
  wtc_expect_int("the server's Finished for this transcript is accepted", 0,
             wt_tls_client_receive(&handshake, WT_TLS_LEVEL_HANDSHAKE,
                                   WT_QUIC_FLIGHT_CLIENT_AUTH_FINISHED,
                                   sizeof(WT_QUIC_FLIGHT_CLIENT_AUTH_FINISHED),
                                   &out, &out_len, &out_level));
  wtc_expect_int("the handshake is complete", (long)WT_TLS_STATE_CONNECTED,
             (long)wt_tls_client_state(&handshake));
  wtc_expect_int("the client's flight is 46 bytes", 46, (long)out_len);
  wtc_checks++;
  if (out == NULL || out_len != 46U) {
    wtc_failures++;
    printf("FAIL the client auth flight is not 46 bytes\n");
    return;
  }
  /* Byte for byte against the independent implementation: the empty
     Certificate, the echoed (empty) context, the empty list, the empty
     extension block, and a Finished whose MAC covers all of it. */
  wtc_expect_bytes("the client auth flight is the oracle's",
               WT_QUIC_FLIGHT_CLIENT_AUTH_FLIGHT, out, 46U);
  wtc_expect_int("it starts with a Certificate", WT_TLS_HS_CERTIFICATE,
             (long)out[0]);
  wtc_expect_int("with a six-byte body", 6, (long)out[3]);
  wtc_expect_int("an empty context", 0, (long)out[4]);
  wtc_expect_int("an empty certificate list", 0, (long)(out[5] | out[6] | out[7]));
  wtc_expect_int("an empty extension block", 0, (long)(out[8] | out[9]));
  wtc_expect_int("then a Finished", WT_TLS_HS_FINISHED, (long)out[10]);
  wtc_expect_int("of 32 bytes", 32, (long)out[13]);
  /* And the MAC is not the one from the flight without a Certificate: the
     Certificate is in the transcript the MAC is taken over. */
  wtc_checks++;
  if (memcmp(out + 14U, WT_QUIC_FLIGHT_CLIENT_FINISHED, 32U) == 0) {
    wtc_failures++;
    printf("FAIL the client auth Finished MAC ignores the Certificate\n");
  }
  wtc_expect_bytes("the client auth MAC is the oracle's",
               WT_QUIC_FLIGHT_CLIENT_AUTH_FINISHED_VALUE, out + 14U, 32U);
}

/* ------------------------------------------------------------- entry point */

/* B-92: the client owns the bytes it keeps, by construction rather than by
 * contract.
 *
 * Every message of this flight is delivered out of one scratch buffer that is
 * overwritten the moment the call returns -- which is what a caller reading
 * into a single buffer does, and the shape the header used to warn against.
 * Nothing downstream may depend on those bytes surviving: the CertificateVerify
 * is checked two messages after the Certificate it takes the key from, and the
 * transport parameters are read after the handshake has completed.
 *
 * The scratch is filled with a byte the flight cannot contain, so a view that
 * dangles reads back as something wrong rather than as something that happens
 * to still be right. That is the difference between this check and one that
 * passes because the stack was left alone. */
void wtc_test_client_owns_what_it_keeps(void) {
  wt_tls_client_t handshake;
  uint8_t scratch[1024];
  const uint8_t *parameters = NULL;
  size_t parameters_len = 0U;
  size_t len;

  wtc_setup_params();
  wtc_setup_pin();

  if (wtc_reach_wait_encrypted_extensions(&handshake) != 0) {
    printf("FATAL could not start the ownership handshake\n");
    wtc_failures++;
    return;
  }

  /* EncryptedExtensions, and then the buffer it came from is destroyed. */
  len = wtc_good_encrypted_extensions(scratch, sizeof(scratch));
  if (wtc_feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, scratch, len) != 0) return;
  memset(scratch, 0xA5, sizeof(scratch));

  /* Certificate, and then the buffer is destroyed before the message that
     needs the key out of it has even been delivered. */
  memcpy(scratch, WT_QUIC_FLIGHT_CERTIFICATE,
         sizeof(WT_QUIC_FLIGHT_CERTIFICATE));
  if (wtc_feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, scratch,
           sizeof(WT_QUIC_FLIGHT_CERTIFICATE)) != 0) {
    return;
  }
  memset(scratch, 0x5A, sizeof(scratch));
  /* The premise of this whole check, asserted rather than assumed: if the
     buffer were still intact the rest would pass for the wrong reason. */
  wtc_expect_int("the test's own message buffer really was destroyed", 1,
             (scratch[0] == 0x5AU &&
              scratch[sizeof(scratch) - 1U] == 0x5AU) ? 1 : 0);

  wtc_expect_int("the CertificateVerify verifies against a key the client kept", 0,
             wtc_feed(&handshake, WT_TLS_LEVEL_HANDSHAKE,
                  WT_QUIC_FLIGHT_CERTIFICATE_VERIFY,
                  sizeof(WT_QUIC_FLIGHT_CERTIFICATE_VERIFY)));
  wtc_expect_int("the server's Finished is accepted", 0,
             wtc_feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, WT_QUIC_FLIGHT_FINISHED,
                  sizeof(WT_QUIC_FLIGHT_FINISHED)));
  wtc_expect_int("the handshake completes with every message buffer destroyed",
             (long)WT_TLS_STATE_CONNECTED,
             (long)wt_tls_client_state(&handshake));

  parameters = wt_tls_client_peer_transport_parameters(&handshake,
                                                       &parameters_len);
  wtc_expect_int("the transport parameters outlived their buffer", 1,
             parameters != NULL ? 1 : 0);
  wtc_expect_int("and kept the peer's length", 6, (long)parameters_len);
  if (parameters != NULL && parameters_len == 6U) {
    wtc_expect_int("and the peer's bytes, not the caller's", 1,
               (parameters[0] == wtc_server_parameters[0] &&
                parameters[5] == wtc_server_parameters[5]) ? 1 : 0);
  }
  wt_tls_client_clear(&handshake);
}
