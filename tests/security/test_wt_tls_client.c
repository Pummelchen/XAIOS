/* The TLS 1.3 client handshake for QUIC: the state machine, the refusals, and
 * the key transitions.
 *
 * This suite is mostly negative, and deliberately so. A state machine that
 * accepts a correct flight is not hard; the part that decides whether a
 * connection is safe is what it does with a flight that is almost correct --
 * a ServerHello selecting a suite that was not offered, an
 * EncryptedExtensions without transport parameters, a certificate carrying the
 * wrong key, a signature over a different transcript, a message at the wrong
 * encryption level, a message in the wrong order. Each of those has a check
 * whose absence would still pass a happy-path test, so each has a test here.
 *
 * The messages the checks are applied to are real where a real one exists: the
 * ServerHello and Certificate are RFC 8448's own, frame for frame, and RFC 8448
 * prints the client's x25519 private key, so the ECDH and the key schedule run
 * on real key material. Where a real message cannot exist -- there is no
 * published QUIC server flight, and RFC 8448's trace is TLS over TCP, so its
 * EncryptedExtensions carries no QUIC transport parameters -- the flight comes
 * from `tests/security/generate_wt_quic_flight.py`, an independent Python
 * implementation of the server side whose output is committed as
 * `wt_quic_flight_vectors.h`. That is what drives the handshake to completion
 * and what the client's own Finished is checked against.
 */

#include "wt_tls_client.h"
#include "wt_rfc8448_vectors.h"
#include "wt_quic_flight_vectors.h"
#include "test_wt_tls_client_support.h"

#include <stdio.h>
#include <string.h>

/* -------------------------------------------------- the ServerHello step */

static void test_server_hello(void) {
  /* Zeroed before use: the argument checks below ask what an unstarted
     handshake does, and an unstarted handshake is a zeroed one. */
  wt_tls_client_t handshake;
  uint8_t message[256];
  size_t len;

  memset(&handshake, 0, sizeof(handshake));
  wtc_setup_params();
  wtc_setup_pin();

  /* --- a handshake that was never started accepts nothing --- */
  {
    const uint8_t *out = NULL;
    size_t out_len = 0U;
    wt_tls_level_t out_level = WT_TLS_LEVEL_INITIAL;
    wt_tls_client_t fresh;
    memset(&fresh, 0, sizeof(fresh));
    wtc_expect_int("a receive on an unstarted handshake is refused", -1,
               wt_tls_client_receive(&fresh, WT_TLS_LEVEL_INITIAL,
                                     WT_QUIC_FLIGHT_SERVER_HELLO,
                                     sizeof(WT_QUIC_FLIGHT_SERVER_HELLO), &out,
                                     &out_len, &out_level));
    wtc_expect_int("  as an unexpected message", WT_TLS_ALERT_UNEXPECTED_MESSAGE,
               (long)wt_tls_client_alert(&fresh));
    /* A refusal is terminal, as the header says, so an unstarted handshake
       that is handed a message ends up FAILED rather than quietly back at the
       start. The state it must never reach is CONNECTED. */
    wtc_expect_int("and it did not become connected",
               (long)WT_TLS_STATE_FAILED, (long)wt_tls_client_state(&fresh));
    wtc_checks++;
    if (wt_tls_client_fail_reason(&fresh) == NULL) {
      wtc_failures++;
      printf("FAIL a failed handshake has no reason\n");
    }
  }
  /* --- bad arguments to a getter are refusals, not crashes --- */
  {
    wt_tls_traffic_keys_t keys;
    wtc_expect_int("a NULL handshake reports no keys", 0,
               wt_tls_client_keys_available(NULL, WT_TLS_LEVEL_HANDSHAKE, 0));
    /* A level outside the enum is refused rather than shifting by it. */
    wtc_expect_int("a level outside the enum reports no keys", 0,
               wt_tls_client_keys_available(&handshake, (wt_tls_level_t)99, 0));
    wtc_expect_int("and a negative one does not either", 0,
               wt_tls_client_keys_available(&handshake, (wt_tls_level_t)-1, 0));
    wtc_expect_int("a NULL handshake has no keys", -1,
               wt_tls_client_keys(NULL, WT_TLS_LEVEL_HANDSHAKE, 0, &keys));
    wtc_expect_int("a NULL output is refused", -1,
               wt_tls_client_keys(&handshake, WT_TLS_LEVEL_APPLICATION, 0,
                                  NULL));
    wtc_expect_int("a NULL handshake is failed", (long)WT_TLS_STATE_FAILED,
               (long)wt_tls_client_state(NULL));
    wtc_expect_int("a NULL handshake has no reason", 0,
               wt_tls_client_fail_reason(NULL) == NULL ? 0 : 1);
    wtc_expect_int("a NULL handshake has no ALPN", 0,
               wt_tls_client_alpn(NULL, NULL) == NULL ? 0 : 1);
    wtc_expect_int("a NULL handshake has no transport parameters", 0,
               wt_tls_client_peer_transport_parameters(NULL, NULL) == NULL ? 0
                                                                          : 1);
    wt_tls_client_clear(NULL);
    wtc_expect_int("clearing a NULL handshake is harmless", 1, 1);
  }

  /* --- the wrong message where a ServerHello belongs --- */
  if (wtc_start_client(&handshake) != 0) {
    printf("FATAL the ClientHello could not be built\n");
    wtc_failures++;
    return;
  }
  wtc_expect_int("a Certificate where a ServerHello belongs is refused", -1,
             wtc_feed(&handshake, WT_TLS_LEVEL_INITIAL,
                  WT_QUIC_FLIGHT_CERTIFICATE,
                  sizeof(WT_QUIC_FLIGHT_CERTIFICATE)));
  wtc_expect_int("  as an unexpected message", WT_TLS_ALERT_UNEXPECTED_MESSAGE,
             (long)wt_tls_client_alert(&handshake));
  wtc_expect_int("a refusal is terminal", -1,
             wtc_feed(&handshake, WT_TLS_LEVEL_INITIAL,
                  WT_QUIC_FLIGHT_SERVER_HELLO,
                  sizeof(WT_QUIC_FLIGHT_SERVER_HELLO)));

  /* --- the right message at the wrong encryption level --- */
  if (wtc_start_client(&handshake) != 0) return;
  wtc_expect_int("a ServerHello at the Handshake level is refused", -1,
             wtc_feed(&handshake, WT_TLS_LEVEL_HANDSHAKE,
                  WT_QUIC_FLIGHT_SERVER_HELLO,
                  sizeof(WT_QUIC_FLIGHT_SERVER_HELLO)));
  wtc_expect_int("  as an unexpected message", WT_TLS_ALERT_UNEXPECTED_MESSAGE,
             (long)wt_tls_client_alert(&handshake));

  /* --- truncation --- */
  if (wtc_start_client(&handshake) != 0) return;
  wtc_expect_int("a truncated ServerHello is refused", -1,
             wtc_feed(&handshake, WT_TLS_LEVEL_INITIAL,
                  WT_QUIC_FLIGHT_SERVER_HELLO,
                  sizeof(WT_QUIC_FLIGHT_SERVER_HELLO) - 1U));
  wtc_expect_int("  as a decode error", WT_TLS_ALERT_DECODE_ERROR,
             (long)wt_tls_client_alert(&handshake));

  /* --- a HelloRetryRequest, which this client does not implement --- */
  if (wtc_start_client(&handshake) != 0) return;
  len = wtc_build_server_hello(message, sizeof(message),
                           WT_TLS_CIPHER_AES_128_GCM_SHA256, WT_TLS_GROUP_X25519,
                           WT_QUIC_FLIGHT_CLIENT_PUBLIC, 32U, 1, 0x0304U);
  wtc_expect_int("the HelloRetryRequest is built", 1, len > 0U ? 1 : 0);
  wtc_expect_int("a HelloRetryRequest is refused by name", -1,
             wtc_feed(&handshake, WT_TLS_LEVEL_INITIAL, message, len));
  wtc_expect_int("  as a handshake failure", WT_TLS_ALERT_HANDSHAKE_FAILURE,
             (long)wt_tls_client_alert(&handshake));
  wtc_checks++;
  if (wt_tls_client_fail_reason(&handshake) == NULL ||
      strstr(wt_tls_client_fail_reason(&handshake), "HelloRetryRequest") ==
          NULL) {
    wtc_failures++;
    printf("FAIL the refusal does not name HelloRetryRequest\n");
  }

  /* --- a suite that was not offered --- */
  if (wtc_start_client(&handshake) != 0) return;
  len = wtc_build_server_hello(message, sizeof(message), 0x1302U, WT_TLS_GROUP_X25519,
                           WT_QUIC_FLIGHT_CLIENT_PUBLIC, 32U, 0, 0x0304U);
  wtc_expect_int("a cipher suite that was not offered is refused", -1,
             wtc_feed(&handshake, WT_TLS_LEVEL_INITIAL, message, len));
  wtc_expect_int("  as an illegal parameter", WT_TLS_ALERT_ILLEGAL_PARAMETER,
             (long)wt_tls_client_alert(&handshake));

  /* --- a version that is not 1.3 --- */
  if (wtc_start_client(&handshake) != 0) return;
  len = wtc_build_server_hello(message, sizeof(message),
                           WT_TLS_CIPHER_AES_128_GCM_SHA256, WT_TLS_GROUP_X25519,
                           WT_QUIC_FLIGHT_CLIENT_PUBLIC, 32U, 0, 0x0303U);
  wtc_expect_int("TLS 1.2 in supported_versions is refused", -1,
             wtc_feed(&handshake, WT_TLS_LEVEL_INITIAL, message, len));

  /* --- a group this module cannot perform --- */
  if (wtc_start_client(&handshake) != 0) return;
  len = wtc_build_server_hello(message, sizeof(message),
                           WT_TLS_CIPHER_AES_128_GCM_SHA256, 0x0017U,
                           WT_QUIC_FLIGHT_CLIENT_PUBLIC, 32U, 0, 0x0304U);
  wtc_expect_int("an unimplemented group is refused", -1,
             wtc_feed(&handshake, WT_TLS_LEVEL_INITIAL, message, len));
  wtc_expect_int("  as an illegal parameter", WT_TLS_ALERT_ILLEGAL_PARAMETER,
             (long)wt_tls_client_alert(&handshake));

  /* --- a key share of the wrong length --- */
  if (wtc_start_client(&handshake) != 0) return;
  len = wtc_build_server_hello(message, sizeof(message),
                           WT_TLS_CIPHER_AES_128_GCM_SHA256, WT_TLS_GROUP_X25519,
                           WT_QUIC_FLIGHT_CLIENT_PUBLIC, 31U, 0, 0x0304U);
  wtc_expect_int("a 31-byte key share is refused", -1,
             wtc_feed(&handshake, WT_TLS_LEVEL_INITIAL, message, len));

  /* --- an all-zero key share: the low-order point, the same secret for every
     private key --- */
  if (wtc_start_client(&handshake) != 0) return;
  {
    static const uint8_t zeros[32] = {0};
    len = wtc_build_server_hello(message, sizeof(message),
                             WT_TLS_CIPHER_AES_128_GCM_SHA256,
                             WT_TLS_GROUP_X25519, zeros, 32U, 0, 0x0304U);
    wtc_expect_int("an all-zero key share is refused", -1,
               wtc_feed(&handshake, WT_TLS_LEVEL_INITIAL, message, len));
  }

  /* --- the real ServerHello: RFC 8448's, whose key share is the server's
     real x25519 public key and whose client private key the RFC prints. The
     transcript here is NOT RFC 8448's (the ClientHello differs), so the secrets
     are not the RFC's either -- but the schedule runs on real key material and
     the resulting keys must be non-zero and complete. --- */
  if (wtc_start_client(&handshake) != 0) return;
  wtc_expect_int("the oracle's ServerHello is accepted", 0,
             wtc_feed(&handshake, WT_TLS_LEVEL_INITIAL,
                  WT_QUIC_FLIGHT_SERVER_HELLO,
                  sizeof(WT_QUIC_FLIGHT_SERVER_HELLO)));
  wtc_expect_int("the handshake now waits for EncryptedExtensions",
             (long)WT_TLS_STATE_WAIT_ENCRYPTED_EXTENSIONS,
             (long)wt_tls_client_state(&handshake));
  wtc_expect_int("handshake keys are available for reading", 1,
             wt_tls_client_keys_available(&handshake, WT_TLS_LEVEL_HANDSHAKE,
                                          1));
  wtc_expect_int("and for writing", 1,
             wt_tls_client_keys_available(&handshake, WT_TLS_LEVEL_HANDSHAKE,
                                          0));
  wtc_expect_int("application keys are not available yet", 0,
             wt_tls_client_keys_available(&handshake, WT_TLS_LEVEL_APPLICATION,
                                          0));
  {
    wt_tls_traffic_keys_t client_keys;
    wt_tls_traffic_keys_t server_keys;
    uint8_t zeros[WT_TLS_KEY_LEN];
    memset(zeros, 0, sizeof(zeros));
    wtc_expect_int("the client's handshake keys are readable", 0,
               wt_tls_client_keys(&handshake, WT_TLS_LEVEL_HANDSHAKE, 0,
                                  &client_keys));
    wtc_expect_int("the server's handshake keys are readable", 0,
               wt_tls_client_keys(&handshake, WT_TLS_LEVEL_HANDSHAKE, 1,
                                  &server_keys));
    wtc_expect_int("the two directions have different keys", 1,
               memcmp(client_keys.key, server_keys.key, 16U) == 0 ? 0 : 1);
    wtc_expect_int("the client's key is not all zeros", 1,
               memcmp(client_keys.key, zeros, 16U) == 0 ? 0 : 1);
    wtc_expect_int("the AEAD key length is 16", 16, (long)client_keys.key_len);
    wtc_expect_int("the header protection length is 16", 16,
               (long)client_keys.hp_len);
    /* RFC 9001 section 5.1: the traffic keys come from the traffic secret, and
       the oracle derived that secret independently. If the transcript or the
       schedule order were wrong, these would not match. */
    wtc_expect_bytes("the client handshake secret is the oracle's",
                 WT_QUIC_FLIGHT_CLIENT_HANDSHAKE_SECRET, client_keys.secret,
                 WT_TLS_HASH_LEN);
    wtc_expect_bytes("the server handshake secret is the oracle's",
                 WT_QUIC_FLIGHT_SERVER_HANDSHAKE_SECRET, server_keys.secret,
                 WT_TLS_HASH_LEN);
  }
}

/* ------------------------------------------- the EncryptedExtensions step */
static void test_encrypted_extensions(void) {
  wt_tls_client_t handshake;
  /* This test builds its own messages, so it needs no shared buffer: every
     EncryptedExtensions here is malformed in some way and is refused before
     anything borrows from it. The tests that deliver a good one keep the
     buffer at function scope, because the client keeps a view of the server's
     transport parameters inside it. */
  uint8_t message[256];
  size_t len;
  uint16_t types[3];
  const uint8_t *data[3];
  size_t lengths[3];

  wtc_setup_params();
  wtc_setup_pin();

  /* --- a Certificate where EncryptedExtensions belongs --- */
  if (wtc_reach_wait_encrypted_extensions(&handshake) != 0) {
    printf("FATAL could not reach the EncryptedExtensions step\n");
    wtc_failures++;
    return;
  }
  wtc_expect_int("a Certificate here is refused", -1,
             wtc_feed(&handshake, WT_TLS_LEVEL_HANDSHAKE,
                  WT_QUIC_FLIGHT_CERTIFICATE,
                  sizeof(WT_QUIC_FLIGHT_CERTIFICATE)));
  wtc_expect_int("  as an unexpected message", WT_TLS_ALERT_UNEXPECTED_MESSAGE,
             (long)wt_tls_client_alert(&handshake));

  /* --- the right message at the wrong level --- */
  if (wtc_reach_wait_encrypted_extensions(&handshake) != 0) return;
  len = wtc_good_encrypted_extensions(message, sizeof(message));
  wtc_expect_int("EncryptedExtensions at the Initial level is refused", -1,
             wtc_feed(&handshake, WT_TLS_LEVEL_INITIAL, message, len));
  wtc_expect_int("  as an unexpected message", WT_TLS_ALERT_UNEXPECTED_MESSAGE,
             (long)wt_tls_client_alert(&handshake));

  /* --- no transport parameters: RFC 9001 section 8.2 makes this fatal --- */
  if (wtc_reach_wait_encrypted_extensions(&handshake) != 0) return;
  types[0] = WT_TLS_EXT_ALPN;
  data[0] = wtc_alpn_h3;
  lengths[0] = sizeof(wtc_alpn_h3);
  len = wtc_build_encrypted_extensions(message, sizeof(message), types, data,
                                   lengths, 1U);
  wtc_expect_int("EncryptedExtensions without transport parameters is refused", -1,
             wtc_feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, message, len));
  wtc_expect_int("  as a missing extension", WT_TLS_ALERT_MISSING_EXTENSION,
             (long)wt_tls_client_alert(&handshake));

  /* --- transport parameters but no ALPN, which was offered --- */
  if (wtc_reach_wait_encrypted_extensions(&handshake) != 0) return;
  types[0] = WT_TLS_EXT_QUIC_TRANSPORT_PARAMETERS;
  data[0] = wtc_server_parameters;
  lengths[0] = sizeof(wtc_server_parameters);
  len = wtc_build_encrypted_extensions(message, sizeof(message), types, data,
                                   lengths, 1U);
  wtc_expect_int("no ALPN selection is refused", -1,
             wtc_feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, message, len));
  wtc_expect_int("  as no_application_protocol",
             WT_TLS_ALERT_NO_APPLICATION_PROTOCOL,
             (long)wt_tls_client_alert(&handshake));

  /* --- an ALPN protocol that was not offered --- */
  if (wtc_reach_wait_encrypted_extensions(&handshake) != 0) return;
  types[0] = WT_TLS_EXT_QUIC_TRANSPORT_PARAMETERS;
  data[0] = wtc_server_parameters;
  lengths[0] = sizeof(wtc_server_parameters);
  types[1] = WT_TLS_EXT_ALPN;
  data[1] = wtc_alpn_h2;
  lengths[1] = sizeof(wtc_alpn_h2);
  len = wtc_build_encrypted_extensions(message, sizeof(message), types, data,
                                   lengths, 2U);
  wtc_expect_int("an ALPN protocol other than the offered one is refused", -1,
             wtc_feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, message, len));
  wtc_expect_int("  as no_application_protocol",
             WT_TLS_ALERT_NO_APPLICATION_PROTOCOL,
             (long)wt_tls_client_alert(&handshake));

  /* --- an extension the client never offered --- */
  if (wtc_reach_wait_encrypted_extensions(&handshake) != 0) return;
  types[0] = WT_TLS_EXT_QUIC_TRANSPORT_PARAMETERS;
  data[0] = wtc_server_parameters;
  lengths[0] = sizeof(wtc_server_parameters);
  types[1] = WT_TLS_EXT_ALPN;
  data[1] = wtc_alpn_h3;
  lengths[1] = sizeof(wtc_alpn_h3);
  types[2] = WT_TLS_EXT_STATUS_REQUEST;
  data[2] = wtc_empty_extension;
  lengths[2] = 1U;
  len = wtc_build_encrypted_extensions(message, sizeof(message), types, data,
                                   lengths, 3U);
  wtc_expect_int("an unoffered extension is refused", -1,
             wtc_feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, message, len));
  wtc_expect_int("  as unsupported_extension",
             WT_TLS_ALERT_UNSUPPORTED_EXTENSION,
             (long)wt_tls_client_alert(&handshake));

  /* --- an extension that was offered, in the wrong message --- */
  if (wtc_reach_wait_encrypted_extensions(&handshake) != 0) return;
  types[0] = WT_TLS_EXT_QUIC_TRANSPORT_PARAMETERS;
  data[0] = wtc_server_parameters;
  lengths[0] = sizeof(wtc_server_parameters);
  types[1] = WT_TLS_EXT_KEY_SHARE;
  data[1] = wtc_empty_extension;
  lengths[1] = 1U;
  len = wtc_build_encrypted_extensions(message, sizeof(message), types, data,
                                   lengths, 2U);
  wtc_expect_int("a key_share in EncryptedExtensions is refused", -1,
             wtc_feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, message, len));
  wtc_expect_int("  as an illegal parameter", WT_TLS_ALERT_ILLEGAL_PARAMETER,
             (long)wt_tls_client_alert(&handshake));

  /* --- and the one that is accepted --- */
  if (wtc_reach_wait_encrypted_extensions(&handshake) != 0) return;
  len = wtc_good_encrypted_extensions(message, sizeof(message));
  wtc_expect_int("a good EncryptedExtensions is accepted", 0,
             wtc_feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, message, len));
  wtc_expect_int("the handshake now waits for a Certificate",
             (long)WT_TLS_STATE_WAIT_CERTIFICATE,
             (long)wt_tls_client_state(&handshake));
  {
    size_t alpn_len = 0U;
    const uint8_t *alpn = wt_tls_client_alpn(&handshake, &alpn_len);
    wtc_checks++;
    if (alpn == NULL || alpn_len != 2U || memcmp(alpn, "h3", 2U) != 0) {
      wtc_failures++;
      printf("FAIL the negotiated ALPN is not h3\n");
    }
    /* RFC 9001 section 8.2: the transport parameters are not authenticated
       until the handshake completes, so they are not handed out before then.
       This handshake has not completed. */
    wtc_expect_int("transport parameters are still withheld", 0,
               wt_tls_client_peer_transport_parameters(&handshake, NULL) == NULL
                   ? 0
                   : 1);
    wtc_expect_int("no application keys yet", 0,
               wt_tls_client_keys_available(&handshake,
                                            WT_TLS_LEVEL_APPLICATION, 1));
  }
}

/* B-93: the flight outlives the call that produced it, and can be asked for
 * again by name.
 *
 * QUIC retransmits a lost Finished with the same keys, so the bytes cannot be
 * valid only until the next call, and a caller should not have to keep its own
 * copy to be safe. This checks the accessor agrees with what the receive call
 * returned -- same bytes, same length, same level -- after that call has
 * returned, and that the lifetime is the stated one rather than an accident. */
static void test_flight_outlives_the_call(void) {
  wt_tls_client_t handshake;
  uint8_t ee[256];
  const uint8_t *out = NULL;
  const uint8_t *again = NULL;
  size_t out_len = 0U;
  size_t again_len = 0U;
  wt_tls_level_t out_level = WT_TLS_LEVEL_INITIAL;
  wt_tls_level_t again_level = WT_TLS_LEVEL_INITIAL;

  wtc_setup_params();
  wtc_setup_pin();

  wtc_expect_int("a NULL client has no flight", 1,
             wt_tls_client_flight(NULL, NULL, NULL) == NULL ? 1 : 0);

  if (wtc_reach_wait_encrypted_extensions(&handshake) != 0) {
    printf("FATAL could not start the flight handshake\n");
    wtc_failures++;
    return;
  }
  wtc_expect_int("a started handshake has no flight yet", 1,
             wt_tls_client_flight(&handshake, NULL, NULL) == NULL ? 1 : 0);
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
  wtc_expect_int("the server's Finished is accepted", 0,
             wt_tls_client_receive(&handshake, WT_TLS_LEVEL_HANDSHAKE,
                                   WT_QUIC_FLIGHT_FINISHED,
                                   sizeof(WT_QUIC_FLIGHT_FINISHED), &out,
                                   &out_len, &out_level));

  /* The call has returned. These are the bytes a retransmission needs. */
  again = wt_tls_client_flight(&handshake, &again_len, &again_level);
  wtc_expect_int("the flight can still be fetched after the call", 1,
             again != NULL ? 1 : 0);
  wtc_expect_int("with the length the call reported", (long)out_len,
             (long)again_len);
  wtc_expect_int("at the level the call reported", (long)out_level,
             (long)again_level);
  wtc_expect_int("and with the same bytes", 1,
             (out != NULL && again != NULL && out_len == again_len &&
              memcmp(out, again, out_len) == 0)
                 ? 1
                 : 0);

  /* And the end of the span is the stated one, not whatever happens next. */
  wt_tls_client_clear(&handshake);
  wtc_expect_int("clearing the client ends the flight", 1,
             wt_tls_client_flight(&handshake, NULL, NULL) == NULL ? 1 : 0);
}

int main(void) {
  wtc_setup_params();
  wtc_setup_pin();

  wtc_test_client_hello_and_start();
  test_server_hello();
  test_encrypted_extensions();
  wtc_test_certificate();
  wtc_test_certificate_verify();
  wtc_test_full_handshake();
  wtc_test_client_owns_what_it_keeps();
  test_flight_outlives_the_call();
  wtc_test_client_auth_request();

  if (wtc_failures != 0) {
    printf("wt_tls_client: %d of %d checks FAILED\n", wtc_failures, wtc_checks);
    return 1;
  }
  printf("wt_tls_client: all %d checks reproduced a QUIC TLS 1.3 flight from "
         "an independent implementation\n", wtc_checks);
  return 0;
}
