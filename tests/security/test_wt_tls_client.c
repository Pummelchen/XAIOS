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

#include <stdio.h>
#include <string.h>

static int g_failures;
static int g_checks;

static void expect_int(const char *name, long want, long got) {
  g_checks++;
  if (want == got) return;
  g_failures++;
  printf("FAIL %s: want %ld, got %ld\n", name, want, got);
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

/* ------------------------------------------------------------- fixtures */

/* The ClientHello this handshake sends. It is not RFC 8448's -- that trace
 * offers extensions this builder does not (renegotiation_info, session_ticket,
 * psk_key_exchange_modes, record_size_limit), which is why the transcript here
 * cannot be RFC 8448's either. The oracle's ClientHello is the one the rest of
 * the fixture is computed around, and the first check in this suite is that
 * this builder produces it byte for byte. */
static const uint8_t client_random[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
    0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};
static const uint16_t cipher_suites[1] = {WT_TLS_CIPHER_AES_128_GCM_SHA256};
static const uint16_t supported_groups[1] = {WT_TLS_GROUP_X25519};
static const uint16_t signature_algorithms[1] = {WT_TLS_SIG_RSA_PSS_RSAE_SHA256};
static const uint8_t alpn_offer[3] = {0x02U, 'h', '3'};
static const uint8_t transport_parameters[4] = {0x01U, 0x02U, 0x03U, 0x04U};

static wt_tls_client_hello_params_t g_params;
static wt_tls_key_share_t g_share;
static uint8_t g_hello[512];

static void setup_params(void) {
  g_share.group = WT_TLS_GROUP_X25519;
  g_share.public_key = WT_QUIC_FLIGHT_CLIENT_PUBLIC;
  g_share.public_key_len = sizeof(WT_QUIC_FLIGHT_CLIENT_PUBLIC);

  memset(&g_params, 0, sizeof(g_params));
  g_params.random = client_random;
  g_params.cipher_suites = cipher_suites;
  g_params.cipher_suite_count = 1U;
  g_params.key_shares = &g_share;
  g_params.key_share_count = 1U;
  g_params.supported_groups = supported_groups;
  g_params.supported_group_count = 1U;
  g_params.signature_algorithms = signature_algorithms;
  g_params.signature_algorithm_count = 1U;
  g_params.alpn_protocols = alpn_offer;
  g_params.alpn_protocols_len = sizeof(alpn_offer);
  g_params.server_name = "server";
  g_params.quic_transport_parameters = transport_parameters;
  g_params.quic_transport_parameters_len = sizeof(transport_parameters);
}

/* The pin the whole suite uses: the certificate the oracle generated, pinned by
 * its own key, built at run time from the certificate rather than transcribed,
 * so the fixture cannot carry a modulus that does not belong to it. */
static wt_tls_pinned_key_t g_pin;
static uint8_t g_certificate_der[4096];
static size_t g_certificate_der_len;

static void setup_pin(void) {
  wt_tls_certificate_chain_t chain;
  wt_tls_public_key_t key;

  if (wt_tls_parse_certificate(WT_QUIC_FLIGHT_CERTIFICATE,
                               sizeof(WT_QUIC_FLIGHT_CERTIFICATE),
                               &chain) != 0 ||
      chain.count == 0U) {
    printf("FATAL the fixture's Certificate does not parse\n");
    g_failures++;
    return;
  }
  if (chain.lengths[0] > sizeof(g_certificate_der)) {
    printf("FATAL the fixture's leaf certificate does not fit\n");
    g_failures++;
    return;
  }
  memcpy(g_certificate_der, chain.entries[0], chain.lengths[0]);
  g_certificate_der_len = chain.lengths[0];

  if (wt_tls_certificate_public_key(g_certificate_der, g_certificate_der_len,
                                    &key) != 0) {
    printf("FATAL the fixture's certificate has no readable key\n");
    g_failures++;
    return;
  }
  if (wt_tls_pinned_key_set_rsa(&g_pin, key.rsa.n, key.rsa.nlen, key.rsa.e,
                                key.rsa.elen) != 0) {
    printf("FATAL the fixture's key could not be pinned\n");
    g_failures++;
  }
}

/* Start a handshake and leave it waiting for a ServerHello. Returns 0 when the
 * ClientHello was produced. */
static int start_client(wt_tls_client_t *handshake) {
  wt_tls_client_config_t config;
  size_t len;

  memset(&config, 0, sizeof(config));
  config.params = &g_params;
  config.pin = &g_pin;
  config.client_key_private = WT_QUIC_FLIGHT_CLIENT_PRIVATE;
  config.client_key_private_len = sizeof(WT_QUIC_FLIGHT_CLIENT_PRIVATE);

  len = wt_tls_client_start(handshake, &config, g_hello, sizeof(g_hello));
  if (len == 0U) return -1;
  return 0;
}

/* Feed one message and report whether it was accepted. */
static int feed(wt_tls_client_t *handshake, wt_tls_level_t level,
                const uint8_t *message, size_t message_len) {
  const uint8_t *out = NULL;
  size_t out_len = 0U;
  wt_tls_level_t out_level = WT_TLS_LEVEL_INITIAL;
  int status = wt_tls_client_receive(handshake, level, message, message_len,
                                     &out, &out_len, &out_level);
  if (status == 0) {
    /* A response must always be consistent: bytes and a level, or neither. */
    if ((out_len == 0U) != (out == NULL)) {
      printf("FAIL a response flight is half reported\n");
      g_failures++;
    }
  }
  return status;
}

/* ------------------------------------------------ synthetic ServerHellos */

/* Build a ServerHello for the parameters above but with `suite`, `group` and
 * `key_share` under the test's control, so each check in the handler can be
 * aimed at one field. Returns the message length. */
static size_t build_server_hello(uint8_t *out, size_t capacity, uint16_t suite,
                                 uint16_t group, const uint8_t *key_share,
                                 size_t key_share_len, int retry,
                                 uint16_t version) {
  size_t body;
  size_t extensions;
  size_t offset = 0U;
  size_t i;

  /* body = legacy_version(2) + random(32) + session_id_len(1)
            + suites(2) + compression(1) + extensions_len(2) + extensions */
  /* supported_versions is 2 type + 2 length + 2 data = 6; key_share is
     2 type + 2 length + 2 group + 2 key length + the key. Declaring less than
     what is written makes the message truncated, which the parser refuses as a
     decode error -- so a check aimed at one field would report the wrong alert
     and look like a defect in the handler. */
  extensions = 6U + (8U + key_share_len);
  body = 2U + 32U + 1U + 2U + 1U + 2U + extensions;
  if (capacity < 4U + body) return 0U;

  out[0] = WT_TLS_HS_SERVER_HELLO;
  out[1] = (uint8_t)((body >> 16) & 0xFFU);
  out[2] = (uint8_t)((body >> 8) & 0xFFU);
  out[3] = (uint8_t)(body & 0xFFU);
  offset = 4U;
  out[offset++] = 0x03U;
  out[offset++] = 0x03U;
  for (i = 0U; i < 32U; i++) {
    static const uint8_t retry_random[32] = {
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C,
        0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB,
        0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
    };
    out[offset++] = retry ? retry_random[i] : (uint8_t)(0x40U + i);
  }
  out[offset++] = 0x00U; /* legacy_session_id_echo: empty, as QUIC requires */
  out[offset++] = (uint8_t)(suite >> 8);
  out[offset++] = (uint8_t)(suite & 0xFFU);
  out[offset++] = 0x00U; /* legacy_compression_method */
  out[offset++] = (uint8_t)(extensions >> 8);
  out[offset++] = (uint8_t)(extensions & 0xFFU);
  /* supported_versions */
  out[offset++] = 0x00U;
  out[offset++] = 0x2BU;
  out[offset++] = 0x00U;
  out[offset++] = 0x02U;
  out[offset++] = (uint8_t)(version >> 8);
  out[offset++] = (uint8_t)(version & 0xFFU);
  /* key_share: group || length || key */
  out[offset++] = 0x00U;
  out[offset++] = 0x33U;
  out[offset++] = (uint8_t)((2U + 2U + key_share_len) >> 8);
  out[offset++] = (uint8_t)((2U + 2U + key_share_len) & 0xFFU);
  out[offset++] = (uint8_t)(group >> 8);
  out[offset++] = (uint8_t)(group & 0xFFU);
  out[offset++] = (uint8_t)(key_share_len >> 8);
  out[offset++] = (uint8_t)(key_share_len & 0xFFU);
  if (key_share_len != 0U) {
    memcpy(out + offset, key_share, key_share_len);
    offset += key_share_len;
  }
  return offset;
}

/* An EncryptedExtensions carrying exactly the extensions named by `types` and
 * `data`, so a test can build a message with a missing extension, an
 * unrequested one, or one that does not belong in this message. */
static size_t build_encrypted_extensions(uint8_t *out, size_t capacity,
                                         const uint16_t *types,
                                         const uint8_t *const *data,
                                         const size_t *lengths, size_t count) {
  size_t extensions = 0U;
  size_t i;
  size_t offset;

  for (i = 0U; i < count; i++) extensions += 4U + lengths[i];
  if (capacity < 6U + extensions || extensions > 0xFFFFU) return 0U;

  out[0] = WT_TLS_HS_ENCRYPTED_EXTENSIONS;
  out[1] = 0x00U;
  out[2] = (uint8_t)(((2U + extensions) >> 8) & 0xFFU);
  out[3] = (uint8_t)((2U + extensions) & 0xFFU);
  out[4] = (uint8_t)(extensions >> 8);
  out[5] = (uint8_t)(extensions & 0xFFU);
  offset = 6U;
  for (i = 0U; i < count; i++) {
    out[offset++] = (uint8_t)(types[i] >> 8);
    out[offset++] = (uint8_t)(types[i] & 0xFFU);
    out[offset++] = (uint8_t)(lengths[i] >> 8);
    out[offset++] = (uint8_t)(lengths[i] & 0xFFU);
    if (lengths[i] != 0U) {
      memcpy(out + offset, data[i], lengths[i]);
      offset += lengths[i];
    }
  }
  return offset;
}

/* The two extensions a QUIC server must send, as pointers for the builder.
   RFC 7301 section 3.1: the server's extension_data is a ProtocolNameList
   containing exactly one name, so it begins with a two-byte list length --
   the same structure the client's offer uses, not a flattened single name. */
static const uint8_t alpn_h3[5] = {0x00U, 0x03U, 0x02U, 'h', '3'};
static const uint8_t alpn_h2[5] = {0x00U, 0x03U, 0x02U, 'h', '2'};
static const uint8_t server_parameters[6] = {0x0aU, 0x0bU, 0x0cU,
                                             0x0dU, 0x0eU, 0x0fU};
static const uint8_t empty_extension[1] = {0x00U};

/* A good EncryptedExtensions: ALPN h3 and the transport parameters. */
static size_t good_encrypted_extensions(uint8_t *out, size_t capacity) {
  const uint16_t types[2] = {WT_TLS_EXT_ALPN,
                             WT_TLS_EXT_QUIC_TRANSPORT_PARAMETERS};
  const uint8_t *data[2] = {alpn_h3, server_parameters};
  const size_t lengths[2] = {sizeof(alpn_h3), sizeof(server_parameters)};
  return build_encrypted_extensions(out, capacity, types, data, lengths, 2U);
}

/* ----------------------------------------------- the ClientHello it sends */

static void test_client_hello_and_start(void) {
  wt_tls_client_t handshake;
  wt_tls_client_config_t config;
  size_t needed;
  size_t written;

  setup_params();
  setup_pin();
  expect_int("the fixture's pin is set", 1, wt_tls_pinned_key_is_set(&g_pin));

  memset(&config, 0, sizeof(config));
  config.params = &g_params;
  config.pin = &g_pin;
  config.client_key_private = WT_QUIC_FLIGHT_CLIENT_PRIVATE;
  config.client_key_private_len = sizeof(WT_QUIC_FLIGHT_CLIENT_PRIVATE);

  /* --- refusals, each before a byte is sent --- */
  expect_int("a NULL handshake is refused", 0,
             (long)wt_tls_client_start(NULL, &config, g_hello, sizeof(g_hello)));
  expect_int("a NULL configuration is refused", 0,
             (long)wt_tls_client_start(&handshake, NULL, g_hello,
                                       sizeof(g_hello)));
  {
    wt_tls_client_config_t broken = config;
    broken.params = NULL;
    expect_int("no ClientHello parameters is refused", 0,
               (long)wt_tls_client_start(&handshake, &broken, g_hello,
                                         sizeof(g_hello)));
    expect_int("  and the handshake says why", (long)WT_TLS_STATE_FAILED,
               (long)wt_tls_client_state(&handshake));
    g_checks++;
    if (wt_tls_client_fail_reason(&handshake) == NULL) {
      g_failures++;
      printf("FAIL a failure has no reason\n");
    }
  }
  {
    wt_tls_client_config_t broken = config;
    broken.pin = NULL;
    expect_int("no pin is refused", 0,
               (long)wt_tls_client_start(&handshake, &broken, g_hello,
                                         sizeof(g_hello)));
    expect_int("  with handshake_failure", WT_TLS_ALERT_HANDSHAKE_FAILURE,
               (long)wt_tls_client_alert(&handshake));
  }
  {
    wt_tls_pinned_key_t unset;
    wt_tls_client_config_t broken = config;
    memset(&unset, 0, sizeof(unset));
    broken.pin = &unset;
    expect_int("an unset pin is refused", 0,
               (long)wt_tls_client_start(&handshake, &broken, g_hello,
                                         sizeof(g_hello)));
  }
  {
    /* RFC 9001 section 8.2: a QUIC ClientHello without transport parameters is
       one a server closes the connection over, so it is refused before it is
       sent rather than discovered by watching the peer hang up. */
    wt_tls_client_hello_params_t without = g_params;
    wt_tls_client_config_t broken = config;
    without.quic_transport_parameters = NULL;
    without.quic_transport_parameters_len = 0U;
    broken.params = &without;
    expect_int("transport parameters are required in the ClientHello", 0,
               (long)wt_tls_client_start(&handshake, &broken, g_hello,
                                         sizeof(g_hello)));
    expect_int("  with handshake_failure", WT_TLS_ALERT_HANDSHAKE_FAILURE,
               (long)wt_tls_client_alert(&handshake));
  }
  {
    wt_tls_client_config_t broken = config;
    broken.client_key_private = NULL;
    expect_int("no private key is refused", 0,
               (long)wt_tls_client_start(&handshake, &broken, g_hello,
                                         sizeof(g_hello)));
    broken.client_key_private = WT_QUIC_FLIGHT_CLIENT_PRIVATE;
    broken.client_key_private_len = 31U;
    expect_int("a 31-byte private key is refused", 0,
               (long)wt_tls_client_start(&handshake, &broken, g_hello,
                                         sizeof(g_hello)));
  }

  needed = wt_tls_client_hello_size(&g_params);
  expect_int("the ClientHello has a size", 1, needed > 0U ? 1 : 0);
  expect_int("a buffer one byte too small is refused", 0,
             (long)wt_tls_client_start(&handshake, &config, g_hello,
                                       needed - 1U));
  expect_int("a NULL buffer is refused", 0,
             (long)wt_tls_client_start(&handshake, &config, NULL, needed));

  /* --- the message itself --- */
  written = wt_tls_client_start(&handshake, &config, g_hello, sizeof(g_hello));
  expect_int("the ClientHello is produced", (long)needed, (long)written);
  expect_int("the handshake is waiting for a ServerHello",
             (long)WT_TLS_STATE_WAIT_SERVER_HELLO,
             (long)wt_tls_client_state(&handshake));
  /* THE BUILDER AND THE ORACLE MUST AGREE. The rest of the fixture is computed
     around this exact message; if the builder and the Python encoder ever
     disagree, every later check would fail for a reason that looks like a
     crypto problem, so it is checked first and by itself. */
  expect_bytes("the ClientHello is the one the oracle computed",
               WT_QUIC_FLIGHT_CLIENT_HELLO, g_hello,
               sizeof(WT_QUIC_FLIGHT_CLIENT_HELLO));
  expect_int("no keys exist before a ServerHello", 0,
             wt_tls_client_keys_available(&handshake, WT_TLS_LEVEL_HANDSHAKE,
                                          0));
  expect_int("and none at the application level either", 0,
             wt_tls_client_keys_available(&handshake, WT_TLS_LEVEL_APPLICATION,
                                          1));
  expect_int("the Initial keys are not this module's to report", -1,
             wt_tls_client_keys(&handshake, WT_TLS_LEVEL_INITIAL, 0, NULL));
  expect_int("and no ALPN is negotiated yet", 0,
             wt_tls_client_alpn(&handshake, NULL) == NULL ? 0 : 1);
  expect_int("and no transport parameters are visible yet", 0,
             wt_tls_client_peer_transport_parameters(&handshake, NULL) == NULL
                 ? 0
                 : 1);
  expect_int("the negotiated AEAD is AES-128-GCM", 1,
             wt_tls_client_aead(&handshake) == WT_TLS_AEAD_AES_128_GCM ? 1 : 0);
}

/* -------------------------------------------------- the ServerHello step */

static void test_server_hello(void) {
  /* Zeroed before use: the argument checks below ask what an unstarted
     handshake does, and an unstarted handshake is a zeroed one. */
  wt_tls_client_t handshake;
  uint8_t message[256];
  size_t len;

  memset(&handshake, 0, sizeof(handshake));
  setup_params();
  setup_pin();

  /* --- a handshake that was never started accepts nothing --- */
  {
    const uint8_t *out = NULL;
    size_t out_len = 0U;
    wt_tls_level_t out_level = WT_TLS_LEVEL_INITIAL;
    wt_tls_client_t fresh;
    memset(&fresh, 0, sizeof(fresh));
    expect_int("a receive on an unstarted handshake is refused", -1,
               wt_tls_client_receive(&fresh, WT_TLS_LEVEL_INITIAL,
                                     WT_QUIC_FLIGHT_SERVER_HELLO,
                                     sizeof(WT_QUIC_FLIGHT_SERVER_HELLO), &out,
                                     &out_len, &out_level));
    expect_int("  as an unexpected message", WT_TLS_ALERT_UNEXPECTED_MESSAGE,
               (long)wt_tls_client_alert(&fresh));
    /* A refusal is terminal, as the header says, so an unstarted handshake
       that is handed a message ends up FAILED rather than quietly back at the
       start. The state it must never reach is CONNECTED. */
    expect_int("and it did not become connected",
               (long)WT_TLS_STATE_FAILED, (long)wt_tls_client_state(&fresh));
    g_checks++;
    if (wt_tls_client_fail_reason(&fresh) == NULL) {
      g_failures++;
      printf("FAIL a failed handshake has no reason\n");
    }
  }
  /* --- bad arguments to a getter are refusals, not crashes --- */
  {
    wt_tls_traffic_keys_t keys;
    expect_int("a NULL handshake reports no keys", 0,
               wt_tls_client_keys_available(NULL, WT_TLS_LEVEL_HANDSHAKE, 0));
    /* A level outside the enum is refused rather than shifting by it. */
    expect_int("a level outside the enum reports no keys", 0,
               wt_tls_client_keys_available(&handshake, (wt_tls_level_t)99, 0));
    expect_int("and a negative one does not either", 0,
               wt_tls_client_keys_available(&handshake, (wt_tls_level_t)-1, 0));
    expect_int("a NULL handshake has no keys", -1,
               wt_tls_client_keys(NULL, WT_TLS_LEVEL_HANDSHAKE, 0, &keys));
    expect_int("a NULL output is refused", -1,
               wt_tls_client_keys(&handshake, WT_TLS_LEVEL_APPLICATION, 0,
                                  NULL));
    expect_int("a NULL handshake is failed", (long)WT_TLS_STATE_FAILED,
               (long)wt_tls_client_state(NULL));
    expect_int("a NULL handshake has no reason", 0,
               wt_tls_client_fail_reason(NULL) == NULL ? 0 : 1);
    expect_int("a NULL handshake has no ALPN", 0,
               wt_tls_client_alpn(NULL, NULL) == NULL ? 0 : 1);
    expect_int("a NULL handshake has no transport parameters", 0,
               wt_tls_client_peer_transport_parameters(NULL, NULL) == NULL ? 0
                                                                          : 1);
    wt_tls_client_clear(NULL);
    expect_int("clearing a NULL handshake is harmless", 1, 1);
  }

  /* --- the wrong message where a ServerHello belongs --- */
  if (start_client(&handshake) != 0) {
    printf("FATAL the ClientHello could not be built\n");
    g_failures++;
    return;
  }
  expect_int("a Certificate where a ServerHello belongs is refused", -1,
             feed(&handshake, WT_TLS_LEVEL_INITIAL,
                  WT_QUIC_FLIGHT_CERTIFICATE,
                  sizeof(WT_QUIC_FLIGHT_CERTIFICATE)));
  expect_int("  as an unexpected message", WT_TLS_ALERT_UNEXPECTED_MESSAGE,
             (long)wt_tls_client_alert(&handshake));
  expect_int("a refusal is terminal", -1,
             feed(&handshake, WT_TLS_LEVEL_INITIAL,
                  WT_QUIC_FLIGHT_SERVER_HELLO,
                  sizeof(WT_QUIC_FLIGHT_SERVER_HELLO)));

  /* --- the right message at the wrong encryption level --- */
  if (start_client(&handshake) != 0) return;
  expect_int("a ServerHello at the Handshake level is refused", -1,
             feed(&handshake, WT_TLS_LEVEL_HANDSHAKE,
                  WT_QUIC_FLIGHT_SERVER_HELLO,
                  sizeof(WT_QUIC_FLIGHT_SERVER_HELLO)));
  expect_int("  as an unexpected message", WT_TLS_ALERT_UNEXPECTED_MESSAGE,
             (long)wt_tls_client_alert(&handshake));

  /* --- truncation --- */
  if (start_client(&handshake) != 0) return;
  expect_int("a truncated ServerHello is refused", -1,
             feed(&handshake, WT_TLS_LEVEL_INITIAL,
                  WT_QUIC_FLIGHT_SERVER_HELLO,
                  sizeof(WT_QUIC_FLIGHT_SERVER_HELLO) - 1U));
  expect_int("  as a decode error", WT_TLS_ALERT_DECODE_ERROR,
             (long)wt_tls_client_alert(&handshake));

  /* --- a HelloRetryRequest, which this client does not implement --- */
  if (start_client(&handshake) != 0) return;
  len = build_server_hello(message, sizeof(message),
                           WT_TLS_CIPHER_AES_128_GCM_SHA256, WT_TLS_GROUP_X25519,
                           WT_QUIC_FLIGHT_CLIENT_PUBLIC, 32U, 1, 0x0304U);
  expect_int("the HelloRetryRequest is built", 1, len > 0U ? 1 : 0);
  expect_int("a HelloRetryRequest is refused by name", -1,
             feed(&handshake, WT_TLS_LEVEL_INITIAL, message, len));
  expect_int("  as a handshake failure", WT_TLS_ALERT_HANDSHAKE_FAILURE,
             (long)wt_tls_client_alert(&handshake));
  g_checks++;
  if (wt_tls_client_fail_reason(&handshake) == NULL ||
      strstr(wt_tls_client_fail_reason(&handshake), "HelloRetryRequest") ==
          NULL) {
    g_failures++;
    printf("FAIL the refusal does not name HelloRetryRequest\n");
  }

  /* --- a suite that was not offered --- */
  if (start_client(&handshake) != 0) return;
  len = build_server_hello(message, sizeof(message), 0x1302U, WT_TLS_GROUP_X25519,
                           WT_QUIC_FLIGHT_CLIENT_PUBLIC, 32U, 0, 0x0304U);
  expect_int("a cipher suite that was not offered is refused", -1,
             feed(&handshake, WT_TLS_LEVEL_INITIAL, message, len));
  expect_int("  as an illegal parameter", WT_TLS_ALERT_ILLEGAL_PARAMETER,
             (long)wt_tls_client_alert(&handshake));

  /* --- a version that is not 1.3 --- */
  if (start_client(&handshake) != 0) return;
  len = build_server_hello(message, sizeof(message),
                           WT_TLS_CIPHER_AES_128_GCM_SHA256, WT_TLS_GROUP_X25519,
                           WT_QUIC_FLIGHT_CLIENT_PUBLIC, 32U, 0, 0x0303U);
  expect_int("TLS 1.2 in supported_versions is refused", -1,
             feed(&handshake, WT_TLS_LEVEL_INITIAL, message, len));

  /* --- a group this module cannot perform --- */
  if (start_client(&handshake) != 0) return;
  len = build_server_hello(message, sizeof(message),
                           WT_TLS_CIPHER_AES_128_GCM_SHA256, 0x0017U,
                           WT_QUIC_FLIGHT_CLIENT_PUBLIC, 32U, 0, 0x0304U);
  expect_int("an unimplemented group is refused", -1,
             feed(&handshake, WT_TLS_LEVEL_INITIAL, message, len));
  expect_int("  as an illegal parameter", WT_TLS_ALERT_ILLEGAL_PARAMETER,
             (long)wt_tls_client_alert(&handshake));

  /* --- a key share of the wrong length --- */
  if (start_client(&handshake) != 0) return;
  len = build_server_hello(message, sizeof(message),
                           WT_TLS_CIPHER_AES_128_GCM_SHA256, WT_TLS_GROUP_X25519,
                           WT_QUIC_FLIGHT_CLIENT_PUBLIC, 31U, 0, 0x0304U);
  expect_int("a 31-byte key share is refused", -1,
             feed(&handshake, WT_TLS_LEVEL_INITIAL, message, len));

  /* --- an all-zero key share: the low-order point, the same secret for every
     private key --- */
  if (start_client(&handshake) != 0) return;
  {
    static const uint8_t zeros[32] = {0};
    len = build_server_hello(message, sizeof(message),
                             WT_TLS_CIPHER_AES_128_GCM_SHA256,
                             WT_TLS_GROUP_X25519, zeros, 32U, 0, 0x0304U);
    expect_int("an all-zero key share is refused", -1,
               feed(&handshake, WT_TLS_LEVEL_INITIAL, message, len));
  }

  /* --- the real ServerHello: RFC 8448's, whose key share is the server's
     real x25519 public key and whose client private key the RFC prints. The
     transcript here is NOT RFC 8448's (the ClientHello differs), so the secrets
     are not the RFC's either -- but the schedule runs on real key material and
     the resulting keys must be non-zero and complete. --- */
  if (start_client(&handshake) != 0) return;
  expect_int("the oracle's ServerHello is accepted", 0,
             feed(&handshake, WT_TLS_LEVEL_INITIAL,
                  WT_QUIC_FLIGHT_SERVER_HELLO,
                  sizeof(WT_QUIC_FLIGHT_SERVER_HELLO)));
  expect_int("the handshake now waits for EncryptedExtensions",
             (long)WT_TLS_STATE_WAIT_ENCRYPTED_EXTENSIONS,
             (long)wt_tls_client_state(&handshake));
  expect_int("handshake keys are available for reading", 1,
             wt_tls_client_keys_available(&handshake, WT_TLS_LEVEL_HANDSHAKE,
                                          1));
  expect_int("and for writing", 1,
             wt_tls_client_keys_available(&handshake, WT_TLS_LEVEL_HANDSHAKE,
                                          0));
  expect_int("application keys are not available yet", 0,
             wt_tls_client_keys_available(&handshake, WT_TLS_LEVEL_APPLICATION,
                                          0));
  {
    wt_tls_traffic_keys_t client_keys;
    wt_tls_traffic_keys_t server_keys;
    uint8_t zeros[WT_TLS_KEY_LEN];
    memset(zeros, 0, sizeof(zeros));
    expect_int("the client's handshake keys are readable", 0,
               wt_tls_client_keys(&handshake, WT_TLS_LEVEL_HANDSHAKE, 0,
                                  &client_keys));
    expect_int("the server's handshake keys are readable", 0,
               wt_tls_client_keys(&handshake, WT_TLS_LEVEL_HANDSHAKE, 1,
                                  &server_keys));
    expect_int("the two directions have different keys", 1,
               memcmp(client_keys.key, server_keys.key, 16U) == 0 ? 0 : 1);
    expect_int("the client's key is not all zeros", 1,
               memcmp(client_keys.key, zeros, 16U) == 0 ? 0 : 1);
    expect_int("the AEAD key length is 16", 16, (long)client_keys.key_len);
    expect_int("the header protection length is 16", 16,
               (long)client_keys.hp_len);
    /* RFC 9001 section 5.1: the traffic keys come from the traffic secret, and
       the oracle derived that secret independently. If the transcript or the
       schedule order were wrong, these would not match. */
    expect_bytes("the client handshake secret is the oracle's",
                 WT_QUIC_FLIGHT_CLIENT_HANDSHAKE_SECRET, client_keys.secret,
                 WT_TLS_HASH_LEN);
    expect_bytes("the server handshake secret is the oracle's",
                 WT_QUIC_FLIGHT_SERVER_HANDSHAKE_SECRET, server_keys.secret,
                 WT_TLS_HASH_LEN);
  }
}

/* ------------------------------------------- the EncryptedExtensions step */

/* Drive a handshake to the point where EncryptedExtensions is expected. */
static int reach_wait_encrypted_extensions(wt_tls_client_t *handshake) {
  if (start_client(handshake) != 0) return -1;
  if (feed(handshake, WT_TLS_LEVEL_INITIAL, WT_QUIC_FLIGHT_SERVER_HELLO,
           sizeof(WT_QUIC_FLIGHT_SERVER_HELLO)) != 0) {
    return -1;
  }
  return 0;
}

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

  setup_params();
  setup_pin();

  /* --- a Certificate where EncryptedExtensions belongs --- */
  if (reach_wait_encrypted_extensions(&handshake) != 0) {
    printf("FATAL could not reach the EncryptedExtensions step\n");
    g_failures++;
    return;
  }
  expect_int("a Certificate here is refused", -1,
             feed(&handshake, WT_TLS_LEVEL_HANDSHAKE,
                  WT_QUIC_FLIGHT_CERTIFICATE,
                  sizeof(WT_QUIC_FLIGHT_CERTIFICATE)));
  expect_int("  as an unexpected message", WT_TLS_ALERT_UNEXPECTED_MESSAGE,
             (long)wt_tls_client_alert(&handshake));

  /* --- the right message at the wrong level --- */
  if (reach_wait_encrypted_extensions(&handshake) != 0) return;
  len = good_encrypted_extensions(message, sizeof(message));
  expect_int("EncryptedExtensions at the Initial level is refused", -1,
             feed(&handshake, WT_TLS_LEVEL_INITIAL, message, len));
  expect_int("  as an unexpected message", WT_TLS_ALERT_UNEXPECTED_MESSAGE,
             (long)wt_tls_client_alert(&handshake));

  /* --- no transport parameters: RFC 9001 section 8.2 makes this fatal --- */
  if (reach_wait_encrypted_extensions(&handshake) != 0) return;
  types[0] = WT_TLS_EXT_ALPN;
  data[0] = alpn_h3;
  lengths[0] = sizeof(alpn_h3);
  len = build_encrypted_extensions(message, sizeof(message), types, data,
                                   lengths, 1U);
  expect_int("EncryptedExtensions without transport parameters is refused", -1,
             feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, message, len));
  expect_int("  as a missing extension", WT_TLS_ALERT_MISSING_EXTENSION,
             (long)wt_tls_client_alert(&handshake));

  /* --- transport parameters but no ALPN, which was offered --- */
  if (reach_wait_encrypted_extensions(&handshake) != 0) return;
  types[0] = WT_TLS_EXT_QUIC_TRANSPORT_PARAMETERS;
  data[0] = server_parameters;
  lengths[0] = sizeof(server_parameters);
  len = build_encrypted_extensions(message, sizeof(message), types, data,
                                   lengths, 1U);
  expect_int("no ALPN selection is refused", -1,
             feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, message, len));
  expect_int("  as no_application_protocol",
             WT_TLS_ALERT_NO_APPLICATION_PROTOCOL,
             (long)wt_tls_client_alert(&handshake));

  /* --- an ALPN protocol that was not offered --- */
  if (reach_wait_encrypted_extensions(&handshake) != 0) return;
  types[0] = WT_TLS_EXT_QUIC_TRANSPORT_PARAMETERS;
  data[0] = server_parameters;
  lengths[0] = sizeof(server_parameters);
  types[1] = WT_TLS_EXT_ALPN;
  data[1] = alpn_h2;
  lengths[1] = sizeof(alpn_h2);
  len = build_encrypted_extensions(message, sizeof(message), types, data,
                                   lengths, 2U);
  expect_int("an ALPN protocol other than the offered one is refused", -1,
             feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, message, len));
  expect_int("  as no_application_protocol",
             WT_TLS_ALERT_NO_APPLICATION_PROTOCOL,
             (long)wt_tls_client_alert(&handshake));

  /* --- an extension the client never offered --- */
  if (reach_wait_encrypted_extensions(&handshake) != 0) return;
  types[0] = WT_TLS_EXT_QUIC_TRANSPORT_PARAMETERS;
  data[0] = server_parameters;
  lengths[0] = sizeof(server_parameters);
  types[1] = WT_TLS_EXT_ALPN;
  data[1] = alpn_h3;
  lengths[1] = sizeof(alpn_h3);
  types[2] = WT_TLS_EXT_STATUS_REQUEST;
  data[2] = empty_extension;
  lengths[2] = 1U;
  len = build_encrypted_extensions(message, sizeof(message), types, data,
                                   lengths, 3U);
  expect_int("an unoffered extension is refused", -1,
             feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, message, len));
  expect_int("  as unsupported_extension",
             WT_TLS_ALERT_UNSUPPORTED_EXTENSION,
             (long)wt_tls_client_alert(&handshake));

  /* --- an extension that was offered, in the wrong message --- */
  if (reach_wait_encrypted_extensions(&handshake) != 0) return;
  types[0] = WT_TLS_EXT_QUIC_TRANSPORT_PARAMETERS;
  data[0] = server_parameters;
  lengths[0] = sizeof(server_parameters);
  types[1] = WT_TLS_EXT_KEY_SHARE;
  data[1] = empty_extension;
  lengths[1] = 1U;
  len = build_encrypted_extensions(message, sizeof(message), types, data,
                                   lengths, 2U);
  expect_int("a key_share in EncryptedExtensions is refused", -1,
             feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, message, len));
  expect_int("  as an illegal parameter", WT_TLS_ALERT_ILLEGAL_PARAMETER,
             (long)wt_tls_client_alert(&handshake));

  /* --- and the one that is accepted --- */
  if (reach_wait_encrypted_extensions(&handshake) != 0) return;
  len = good_encrypted_extensions(message, sizeof(message));
  expect_int("a good EncryptedExtensions is accepted", 0,
             feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, message, len));
  expect_int("the handshake now waits for a Certificate",
             (long)WT_TLS_STATE_WAIT_CERTIFICATE,
             (long)wt_tls_client_state(&handshake));
  {
    size_t alpn_len = 0U;
    const uint8_t *alpn = wt_tls_client_alpn(&handshake, &alpn_len);
    g_checks++;
    if (alpn == NULL || alpn_len != 2U || memcmp(alpn, "h3", 2U) != 0) {
      g_failures++;
      printf("FAIL the negotiated ALPN is not h3\n");
    }
    /* RFC 9001 section 8.2: the transport parameters are not authenticated
       until the handshake completes, so they are not handed out before then.
       This handshake has not completed. */
    expect_int("transport parameters are still withheld", 0,
               wt_tls_client_peer_transport_parameters(&handshake, NULL) == NULL
                   ? 0
                   : 1);
    expect_int("no application keys yet", 0,
               wt_tls_client_keys_available(&handshake,
                                            WT_TLS_LEVEL_APPLICATION, 1));
  }
}

/* ------------------------------------------------- the Certificate step */

static void test_certificate(void) {
  wt_tls_client_t handshake;
  wt_tls_pinned_key_t other_pin;
  wt_tls_public_key_t key;
  /* Function scope: see test_encrypted_extensions. */
  uint8_t ee[256];
  uint8_t message[1024];

  setup_params();
  setup_pin();

  /* --- an empty chain: a server that cannot authenticate --- */
  if (reach_wait_encrypted_extensions(&handshake) != 0) return;
  {
    size_t len = good_encrypted_extensions(ee, sizeof(ee));
    if (feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, ee, len) != 0) return;
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
  expect_int("an empty certificate chain is refused", -1,
             feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, message, 10U));
  expect_int("  as a decode error", WT_TLS_ALERT_DECODE_ERROR,
             (long)wt_tls_client_alert(&handshake));

  /* --- a certificate that is not the pinned one --- */
  if (reach_wait_encrypted_extensions(&handshake) != 0) return;
  {
    size_t len = good_encrypted_extensions(ee, sizeof(ee));
    if (feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, ee, len) != 0) return;
  }
  expect_int("the fixture's key is readable", 0,
             wt_tls_certificate_public_key(g_certificate_der,
                                           g_certificate_der_len, &key));
  {
    /* The same key with one bit of the modulus flipped: a real key of the
       right shape that is not the pinned one. */
    uint8_t modulus[WT_TLS_PUBLIC_KEY_MAX];
    memcpy(modulus, key.rsa.n, key.rsa.nlen);
    modulus[64] ^= 0x01U;
    expect_int("the other pin is set", 0,
               wt_tls_pinned_key_set_rsa(&other_pin, modulus, key.rsa.nlen,
                                         key.rsa.e, key.rsa.elen));
  }
  {
    wt_tls_client_config_t config;
    wt_tls_client_t pinned_elsewhere;
    uint8_t hello[512];
    memset(&config, 0, sizeof(config));
    config.params = &g_params;
    config.pin = &other_pin;
    config.client_key_private = WT_QUIC_FLIGHT_CLIENT_PRIVATE;
    config.client_key_private_len = sizeof(WT_QUIC_FLIGHT_CLIENT_PRIVATE);
    if (wt_tls_client_start(&pinned_elsewhere, &config, hello,
                            sizeof(hello)) == 0U) {
      printf("FATAL the second handshake could not be built\n");
      g_failures++;
      return;
    }
    if (feed(&pinned_elsewhere, WT_TLS_LEVEL_INITIAL,
             WT_QUIC_FLIGHT_SERVER_HELLO,
             sizeof(WT_QUIC_FLIGHT_SERVER_HELLO)) != 0) {
      return;
    }
    {
      size_t len = good_encrypted_extensions(ee, sizeof(ee));
      if (feed(&pinned_elsewhere, WT_TLS_LEVEL_HANDSHAKE, ee, len) != 0) return;
    }
    expect_int("a certificate that is not the pinned key is refused", -1,
               feed(&pinned_elsewhere, WT_TLS_LEVEL_HANDSHAKE,
                    WT_QUIC_FLIGHT_CERTIFICATE,
                    sizeof(WT_QUIC_FLIGHT_CERTIFICATE)));
    expect_int("  as an unknown CA", WT_TLS_ALERT_UNKNOWN_CA,
               (long)wt_tls_client_alert(&pinned_elsewhere));
  }

  /* --- a certificate that is not a certificate --- */
  if (reach_wait_encrypted_extensions(&handshake) != 0) return;
  {
    size_t len = good_encrypted_extensions(ee, sizeof(ee));
    if (feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, ee, len) != 0) return;
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
    expect_int("a Certificate whose entry is not DER is refused", -1,
               feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, garbage, offset));
    expect_int("  as a bad certificate", WT_TLS_ALERT_BAD_CERTIFICATE,
               (long)wt_tls_client_alert(&handshake));
  }

  /* --- the pinned certificate --- */
  if (reach_wait_encrypted_extensions(&handshake) != 0) return;
  {
    size_t len = good_encrypted_extensions(ee, sizeof(ee));
    if (feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, ee, len) != 0) return;
  }
  expect_int("the pinned certificate is accepted", 0,
             feed(&handshake, WT_TLS_LEVEL_HANDSHAKE,
                  WT_QUIC_FLIGHT_CERTIFICATE,
                  sizeof(WT_QUIC_FLIGHT_CERTIFICATE)));
  expect_int("the handshake now waits for CertificateVerify",
             (long)WT_TLS_STATE_WAIT_CERTIFICATE_VERIFY,
             (long)wt_tls_client_state(&handshake));
  expect_int("transport parameters are still withheld", 0,
             wt_tls_client_peer_transport_parameters(&handshake, NULL) == NULL
                 ? 0
                 : 1);
}

/* -------------------------------------------------------- CertificateVerify */

static void test_certificate_verify(void) {
  wt_tls_client_t handshake;
  /* Function scope: see test_encrypted_extensions. */
  uint8_t ee[256];
  uint8_t message[512];

  setup_params();
  setup_pin();

  /* --- a scheme that was not offered --- */
  if (reach_wait_encrypted_extensions(&handshake) != 0) return;
  {
    size_t len = good_encrypted_extensions(ee, sizeof(ee));
    if (feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, ee, len) != 0) return;
    if (feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, WT_QUIC_FLIGHT_CERTIFICATE,
             sizeof(WT_QUIC_FLIGHT_CERTIFICATE)) != 0) {
      return;
    }
  }
  {
    /* The CertificateVerify with its scheme changed to ECDSA-P256-SHA256,
       which this client did not offer. The signature is not examined: the
       scheme check comes first, because a client that checked the signature
       before the scheme would be checking with something it never said it
       could check. */
    memcpy(message, WT_QUIC_FLIGHT_CERTIFICATE_VERIFY,
           sizeof(WT_QUIC_FLIGHT_CERTIFICATE_VERIFY));
    message[4] = 0x04U;
    message[5] = 0x03U;
    expect_int("an unoffered signature scheme is refused", -1,
               feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, message,
                    sizeof(WT_QUIC_FLIGHT_CERTIFICATE_VERIFY)));
    expect_int("  as an illegal parameter", WT_TLS_ALERT_ILLEGAL_PARAMETER,
               (long)wt_tls_client_alert(&handshake));
  }

  /* --- a signature that does not verify over this transcript --- */
  if (reach_wait_encrypted_extensions(&handshake) != 0) return;
  {
    size_t len = good_encrypted_extensions(ee, sizeof(ee));
    if (feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, ee, len) != 0) return;
    if (feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, WT_QUIC_FLIGHT_CERTIFICATE,
             sizeof(WT_QUIC_FLIGHT_CERTIFICATE)) != 0) {
      return;
    }
  }
  {
    /* RFC 8448's CertificateVerify, which is a real RSA-PSS signature over RFC
       8448's transcript. Against this transcript it must not verify: that is
       the whole point of the transcript being in the signed content. */
    expect_int("a signature over another transcript is refused", -1,
               feed(&handshake, WT_TLS_LEVEL_HANDSHAKE,
                    WT_RFC8448_CERTIFICATE_VERIFY,
                    sizeof(WT_RFC8448_CERTIFICATE_VERIFY)));
    expect_int("  as a decrypt error", WT_TLS_ALERT_DECRYPT_ERROR,
               (long)wt_tls_client_alert(&handshake));
  }

  /* --- a single-bit forgery of the real signature --- */
  if (reach_wait_encrypted_extensions(&handshake) != 0) return;
  {
    size_t len = good_encrypted_extensions(ee, sizeof(ee));
    if (feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, ee, len) != 0) return;
    if (feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, WT_QUIC_FLIGHT_CERTIFICATE,
             sizeof(WT_QUIC_FLIGHT_CERTIFICATE)) != 0) {
      return;
    }
  }
  {
    /* The signature starts at offset 8: two bytes of scheme, two of length.
       Flipping a byte inside it, not after it -- an earlier version computed
       the offset past the end of the message, changed a byte of the test's own
       buffer, and then reported that the untouched message was accepted. */
    memcpy(message, WT_QUIC_FLIGHT_CERTIFICATE_VERIFY,
           sizeof(WT_QUIC_FLIGHT_CERTIFICATE_VERIFY));
    message[8U + 10U] ^= 0x01U;
    expect_int("a one-bit forgery is refused", -1,
               feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, message,
                    sizeof(WT_QUIC_FLIGHT_CERTIFICATE_VERIFY)));
    expect_int("  as a decrypt error", WT_TLS_ALERT_DECRYPT_ERROR,
               (long)wt_tls_client_alert(&handshake));
  }
}

/* -------------------------------------------------------- the whole flight */

static void test_full_handshake(void) {
  wt_tls_client_t handshake;
  wt_tls_traffic_keys_t keys;
  /* Function scope: see test_encrypted_extensions. */
  uint8_t ee[256];
  const uint8_t *out = NULL;
  const uint8_t *parameters = NULL;
  size_t parameters_len = 0U;
  size_t out_len = 0U;
  wt_tls_level_t out_level = WT_TLS_LEVEL_INITIAL;

  setup_params();
  setup_pin();

  if (reach_wait_encrypted_extensions(&handshake) != 0) {
    printf("FATAL could not start the full handshake\n");
    g_failures++;
    return;
  }
  {
    size_t len = good_encrypted_extensions(ee, sizeof(ee));
    if (feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, ee, len) != 0) return;
  }
  if (feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, WT_QUIC_FLIGHT_CERTIFICATE,
           sizeof(WT_QUIC_FLIGHT_CERTIFICATE)) != 0) {
    return;
  }
  if (feed(&handshake, WT_TLS_LEVEL_HANDSHAKE,
           WT_QUIC_FLIGHT_CERTIFICATE_VERIFY,
           sizeof(WT_QUIC_FLIGHT_CERTIFICATE_VERIFY)) != 0) {
    return;
  }
  expect_int("the handshake now waits for Finished",
             (long)WT_TLS_STATE_WAIT_FINISHED,
             (long)wt_tls_client_state(&handshake));

  /* --- the server's Finished, and the client's own --- */
  expect_int("the server's Finished is accepted", 0,
             wt_tls_client_receive(&handshake, WT_TLS_LEVEL_HANDSHAKE,
                                   WT_QUIC_FLIGHT_FINISHED,
                                   sizeof(WT_QUIC_FLIGHT_FINISHED), &out,
                                   &out_len, &out_level));
  expect_int("the handshake is complete", (long)WT_TLS_STATE_CONNECTED,
             (long)wt_tls_client_state(&handshake));
  expect_int("the client's flight goes out at the Handshake level",
             (long)WT_TLS_LEVEL_HANDSHAKE, (long)out_level);
  expect_int("the flight is exactly a Finished", (long)(4U + 32U),
             (long)out_len);
  expect_int("and it was reported", 1, out != NULL ? 1 : 0);
  g_checks++;
  if (out == NULL || out_len < 36U) {
    g_failures++;
    printf("FAIL no client flight was produced\n");
  } else {
    expect_int("it is a Finished message", WT_TLS_HS_FINISHED, (long)out[0]);
    expect_int("of 32 bytes", 32, (long)out[3]);
    /* THE CHECK THAT MATTERS: the client's Finished MAC, computed over the
       transcript through the server's Finished with the client handshake
       traffic secret, must equal the value the independent Python
       implementation computed for the same flight. A transcript that absorbed
       a message twice, or in the wrong order, or took the hash before absorbing
       the server's Finished, produces a different MAC here. */
    expect_bytes("the client's Finished MAC is the oracle's",
                 WT_QUIC_FLIGHT_CLIENT_FINISHED, out + 4U, 32U);
  }

  /* --- the client's client-authentication flight would come first if the
     server had asked; it did not, so the flight is just the Finished --- */

  /* --- the application keys, against the oracle's own derivation --- */
  expect_int("application keys are available for reading", 1,
             wt_tls_client_keys_available(&handshake, WT_TLS_LEVEL_APPLICATION,
                                          1));
  expect_int("and for writing", 1,
             wt_tls_client_keys_available(&handshake, WT_TLS_LEVEL_APPLICATION,
                                          0));
  expect_int("the server's application keys are readable", 0,
             wt_tls_client_keys(&handshake, WT_TLS_LEVEL_APPLICATION, 1, &keys));
  expect_bytes("the server application secret is the oracle's",
               WT_QUIC_FLIGHT_SERVER_APPLICATION_SECRET, keys.secret, 32U);
  expect_int("the client's application keys are readable", 0,
             wt_tls_client_keys(&handshake, WT_TLS_LEVEL_APPLICATION, 0, &keys));
  expect_bytes("the client application secret is the oracle's",
               WT_QUIC_FLIGHT_CLIENT_APPLICATION_SECRET, keys.secret, 32U);

  /* --- the transport parameters, now that they are authenticated --- */
  parameters = wt_tls_client_peer_transport_parameters(&handshake,
                                                       &parameters_len);
  expect_int("the transport parameters are released once the handshake "
             "completes",
             1, parameters != NULL ? 1 : 0);
  expect_bytes("and they are the ones the server sent",
               WT_QUIC_FLIGHT_SERVER_TRANSPORT_PARAMETERS, parameters,
               sizeof(WT_QUIC_FLIGHT_SERVER_TRANSPORT_PARAMETERS));
  expect_int("with the right length",
             (long)sizeof(WT_QUIC_FLIGHT_SERVER_TRANSPORT_PARAMETERS),
             (long)parameters_len);
  {
    size_t alpn_len = 0U;
    const uint8_t *alpn = wt_tls_client_alpn(&handshake, &alpn_len);
    expect_int("and the negotiated ALPN is still h3", 1,
               (alpn != NULL && alpn_len == 2U && memcmp(alpn, "h3", 2U) == 0)
                   ? 1
                   : 0);
  }

  /* --- the handshake is passive afterwards --- */
  expect_int("a message after completion is refused", -1,
             feed(&handshake, WT_TLS_LEVEL_APPLICATION,
                  WT_QUIC_FLIGHT_FINISHED, sizeof(WT_QUIC_FLIGHT_FINISHED)));
  expect_int("  as an unexpected message", WT_TLS_ALERT_UNEXPECTED_MESSAGE,
             (long)wt_tls_client_alert(&handshake));

  /* --- clearing wipes the keys --- */
  wt_tls_client_clear(&handshake);
  expect_int("cleared keys are not available", 0,
             wt_tls_client_keys_available(&handshake, WT_TLS_LEVEL_APPLICATION,
                                          1));
  expect_int("and not readable", -1,
             wt_tls_client_keys(&handshake, WT_TLS_LEVEL_APPLICATION, 1, &keys));
}

/* ------------------------------------------------------- a client auth ask */

/* RFC 8446 section 4.4.2: a client with no suitable certificate must send an
 * empty Certificate message rather than nothing, and must echo the
 * certificate_request_context. The flight is therefore longer than the
 * no-client-auth one, and -- this is the part worth testing -- the Finished MAC
 * covers the Certificate, so it is a different MAC. The oracle computed the
 * whole client flight for this variant, so it is compared byte for byte. */
static void test_client_auth_request(void) {
  wt_tls_client_t handshake;
  /* Function scope: see test_encrypted_extensions. */
  uint8_t ee[256];
  const uint8_t *out = NULL;
  size_t out_len = 0U;
  wt_tls_level_t out_level = WT_TLS_LEVEL_INITIAL;

  setup_params();
  setup_pin();

  if (reach_wait_encrypted_extensions(&handshake) != 0) return;
  {
    size_t len = good_encrypted_extensions(ee, sizeof(ee));
    if (feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, ee, len) != 0) return;
  }

  expect_int("a CertificateRequest is accepted", 0,
             feed(&handshake, WT_TLS_LEVEL_HANDSHAKE,
                  WT_QUIC_FLIGHT_CLIENT_AUTH_REQUEST,
                  sizeof(WT_QUIC_FLIGHT_CLIENT_AUTH_REQUEST)));
  expect_int("and the handshake still wants a Certificate",
             (long)WT_TLS_STATE_WAIT_CERTIFICATE,
             (long)wt_tls_client_state(&handshake));

  if (feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, WT_QUIC_FLIGHT_CERTIFICATE,
           sizeof(WT_QUIC_FLIGHT_CERTIFICATE)) != 0) {
    return;
  }
  if (feed(&handshake, WT_TLS_LEVEL_HANDSHAKE,
           WT_QUIC_FLIGHT_CLIENT_AUTH_CERTIFICATE_VERIFY,
           sizeof(WT_QUIC_FLIGHT_CLIENT_AUTH_CERTIFICATE_VERIFY)) != 0) {
    return;
  }
  expect_int("the server's Finished for this transcript is accepted", 0,
             wt_tls_client_receive(&handshake, WT_TLS_LEVEL_HANDSHAKE,
                                   WT_QUIC_FLIGHT_CLIENT_AUTH_FINISHED,
                                   sizeof(WT_QUIC_FLIGHT_CLIENT_AUTH_FINISHED),
                                   &out, &out_len, &out_level));
  expect_int("the handshake is complete", (long)WT_TLS_STATE_CONNECTED,
             (long)wt_tls_client_state(&handshake));
  expect_int("the client's flight is 46 bytes", 46, (long)out_len);
  g_checks++;
  if (out == NULL || out_len != 46U) {
    g_failures++;
    printf("FAIL the client auth flight is not 46 bytes\n");
    return;
  }
  /* Byte for byte against the independent implementation: the empty
     Certificate, the echoed (empty) context, the empty list, the empty
     extension block, and a Finished whose MAC covers all of it. */
  expect_bytes("the client auth flight is the oracle's",
               WT_QUIC_FLIGHT_CLIENT_AUTH_FLIGHT, out, 46U);
  expect_int("it starts with a Certificate", WT_TLS_HS_CERTIFICATE,
             (long)out[0]);
  expect_int("with a six-byte body", 6, (long)out[3]);
  expect_int("an empty context", 0, (long)out[4]);
  expect_int("an empty certificate list", 0, (long)(out[5] | out[6] | out[7]));
  expect_int("an empty extension block", 0, (long)(out[8] | out[9]));
  expect_int("then a Finished", WT_TLS_HS_FINISHED, (long)out[10]);
  expect_int("of 32 bytes", 32, (long)out[13]);
  /* And the MAC is not the one from the flight without a Certificate: the
     Certificate is in the transcript the MAC is taken over. */
  g_checks++;
  if (memcmp(out + 14U, WT_QUIC_FLIGHT_CLIENT_FINISHED, 32U) == 0) {
    g_failures++;
    printf("FAIL the client auth Finished MAC ignores the Certificate\n");
  }
  expect_bytes("the client auth MAC is the oracle's",
               WT_QUIC_FLIGHT_CLIENT_AUTH_FINISHED_VALUE, out + 14U, 32U);
}

/* ------------------------------------------------------------- entry point */

int main(void) {
  setup_params();
  setup_pin();

  test_client_hello_and_start();
  test_server_hello();
  test_encrypted_extensions();
  test_certificate();
  test_certificate_verify();
  test_full_handshake();
  test_client_auth_request();

  if (g_failures != 0) {
    printf("wt_tls_client: %d of %d checks FAILED\n", g_failures, g_checks);
    return 1;
  }
  printf("wt_tls_client: all %d checks reproduced a QUIC TLS 1.3 flight from "
         "an independent implementation\n", g_checks);
  return 0;
}
