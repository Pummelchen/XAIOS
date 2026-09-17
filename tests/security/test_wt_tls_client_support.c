/* The suite's fixture: the counters and the two check helpers, the pinned key
 * and the certificate it is read from, the message builders, the ClientHello
 * test they were built around, and the CertificateVerify refusals.
 *
 * This was the top of `test_wt_tls_client.c`. The driver keeps the suite's
 * opening comment, the entry point and the ServerHello and EncryptedExtensions
 * steps; `test_wt_tls_client_flight.c` keeps the Certificate step and the
 * flights that run to completion. Everything this file lends either of them is
 * declared once in `test_wt_tls_client_support.h`.
 */
#include "test_wt_tls_client_support.h"

#include "wt_rfc8448_vectors.h"
#include "wt_quic_flight_vectors.h"

#include <stdio.h>
#include <string.h>

int wtc_failures;
int wtc_checks;

void wtc_expect_int(const char *name, long want, long got) {
  wtc_checks++;
  if (want == got) return;
  wtc_failures++;
  printf("FAIL %s: want %ld, got %ld\n", name, want, got);
}

void wtc_expect_bytes(const char *name, const uint8_t *want,
                         const uint8_t *got, size_t len) {
  wtc_checks++;
  if (memcmp(want, got, len) == 0) return;
  wtc_failures++;
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

wt_tls_client_hello_params_t wtc_params;
static wt_tls_key_share_t g_share;
static uint8_t g_hello[512];

void wtc_setup_params(void) {
  g_share.group = WT_TLS_GROUP_X25519;
  g_share.public_key = WT_QUIC_FLIGHT_CLIENT_PUBLIC;
  g_share.public_key_len = sizeof(WT_QUIC_FLIGHT_CLIENT_PUBLIC);

  memset(&wtc_params, 0, sizeof(wtc_params));
  wtc_params.random = client_random;
  wtc_params.cipher_suites = cipher_suites;
  wtc_params.cipher_suite_count = 1U;
  wtc_params.key_shares = &g_share;
  wtc_params.key_share_count = 1U;
  wtc_params.supported_groups = supported_groups;
  wtc_params.supported_group_count = 1U;
  wtc_params.signature_algorithms = signature_algorithms;
  wtc_params.signature_algorithm_count = 1U;
  wtc_params.alpn_protocols = alpn_offer;
  wtc_params.alpn_protocols_len = sizeof(alpn_offer);
  wtc_params.server_name = "server";
  wtc_params.quic_transport_parameters = transport_parameters;
  wtc_params.quic_transport_parameters_len = sizeof(transport_parameters);
}

/* The pin the whole suite uses: the certificate the oracle generated, pinned by
 * its own key, built at run time from the certificate rather than transcribed,
 * so the fixture cannot carry a modulus that does not belong to it. */
static wt_tls_pinned_key_t g_pin;
uint8_t wtc_certificate_der[4096];
size_t wtc_certificate_der_len;

void wtc_setup_pin(void) {
  wt_tls_certificate_chain_t chain;
  wt_tls_public_key_t key;

  if (wt_tls_parse_certificate(WT_QUIC_FLIGHT_CERTIFICATE,
                               sizeof(WT_QUIC_FLIGHT_CERTIFICATE),
                               &chain) != 0 ||
      chain.count == 0U) {
    printf("FATAL the fixture's Certificate does not parse\n");
    wtc_failures++;
    return;
  }
  if (chain.lengths[0] > sizeof(wtc_certificate_der)) {
    printf("FATAL the fixture's leaf certificate does not fit\n");
    wtc_failures++;
    return;
  }
  memcpy(wtc_certificate_der, chain.entries[0], chain.lengths[0]);
  wtc_certificate_der_len = chain.lengths[0];

  if (wt_tls_certificate_public_key(wtc_certificate_der, wtc_certificate_der_len,
                                    &key) != 0) {
    printf("FATAL the fixture's certificate has no readable key\n");
    wtc_failures++;
    return;
  }
  if (wt_tls_pinned_key_set_rsa(&g_pin, key.rsa.n, key.rsa.nlen, key.rsa.e,
                                key.rsa.elen) != 0) {
    printf("FATAL the fixture's key could not be pinned\n");
    wtc_failures++;
  }
}

/* Start a handshake and leave it waiting for a ServerHello. Returns 0 when the
 * ClientHello was produced. */
int wtc_start_client(wt_tls_client_t *handshake) {
  wt_tls_client_config_t config;
  size_t len;

  memset(&config, 0, sizeof(config));
  config.params = &wtc_params;
  config.pin = &g_pin;
  config.client_key_private = WT_QUIC_FLIGHT_CLIENT_PRIVATE;
  config.client_key_private_len = sizeof(WT_QUIC_FLIGHT_CLIENT_PRIVATE);

  len = wt_tls_client_start(handshake, &config, g_hello, sizeof(g_hello));
  if (len == 0U) return -1;
  return 0;
}

/* Feed one message and report whether it was accepted. */
int wtc_feed(wt_tls_client_t *handshake, wt_tls_level_t level,
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
      wtc_failures++;
    }
  }
  return status;
}

/* ------------------------------------------------ synthetic ServerHellos */

/* Build a ServerHello for the parameters above but with `suite`, `group` and
 * `key_share` under the test's control, so each check in the handler can be
 * aimed at one field. Returns the message length. */
size_t wtc_build_server_hello(uint8_t *out, size_t capacity, uint16_t suite,
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
size_t wtc_build_encrypted_extensions(uint8_t *out, size_t capacity,
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
const uint8_t wtc_alpn_h3[5] = {0x00U, 0x03U, 0x02U, 'h', '3'};
const uint8_t wtc_alpn_h2[5] = {0x00U, 0x03U, 0x02U, 'h', '2'};
const uint8_t wtc_server_parameters[6] = {0x0aU, 0x0bU, 0x0cU,
                                             0x0dU, 0x0eU, 0x0fU};
const uint8_t wtc_empty_extension[1] = {0x00U};

/* A good EncryptedExtensions: ALPN h3 and the transport parameters. */
size_t wtc_good_encrypted_extensions(uint8_t *out, size_t capacity) {
  const uint16_t types[2] = {WT_TLS_EXT_ALPN,
                             WT_TLS_EXT_QUIC_TRANSPORT_PARAMETERS};
  const uint8_t *data[2] = {wtc_alpn_h3, wtc_server_parameters};
  const size_t lengths[2] = {sizeof(wtc_alpn_h3), sizeof(wtc_server_parameters)};
  return wtc_build_encrypted_extensions(out, capacity, types, data, lengths, 2U);
}

/* ----------------------------------------------- the ClientHello it sends */

void wtc_test_client_hello_and_start(void) {
  wt_tls_client_t handshake;
  wt_tls_client_config_t config;
  size_t needed;
  size_t written;

  wtc_setup_params();
  wtc_setup_pin();
  wtc_expect_int("the fixture's pin is set", 1, wt_tls_pinned_key_is_set(&g_pin));

  memset(&config, 0, sizeof(config));
  config.params = &wtc_params;
  config.pin = &g_pin;
  config.client_key_private = WT_QUIC_FLIGHT_CLIENT_PRIVATE;
  config.client_key_private_len = sizeof(WT_QUIC_FLIGHT_CLIENT_PRIVATE);

  /* --- refusals, each before a byte is sent --- */
  wtc_expect_int("a NULL handshake is refused", 0,
             (long)wt_tls_client_start(NULL, &config, g_hello, sizeof(g_hello)));
  wtc_expect_int("a NULL configuration is refused", 0,
             (long)wt_tls_client_start(&handshake, NULL, g_hello,
                                       sizeof(g_hello)));
  {
    wt_tls_client_config_t broken = config;
    broken.params = NULL;
    wtc_expect_int("no ClientHello parameters is refused", 0,
               (long)wt_tls_client_start(&handshake, &broken, g_hello,
                                         sizeof(g_hello)));
    wtc_expect_int("  and the handshake says why", (long)WT_TLS_STATE_FAILED,
               (long)wt_tls_client_state(&handshake));
    wtc_checks++;
    if (wt_tls_client_fail_reason(&handshake) == NULL) {
      wtc_failures++;
      printf("FAIL a failure has no reason\n");
    }
  }
  {
    wt_tls_client_config_t broken = config;
    broken.pin = NULL;
    wtc_expect_int("no pin is refused", 0,
               (long)wt_tls_client_start(&handshake, &broken, g_hello,
                                         sizeof(g_hello)));
    wtc_expect_int("  with handshake_failure", WT_TLS_ALERT_HANDSHAKE_FAILURE,
               (long)wt_tls_client_alert(&handshake));
  }
  {
    wt_tls_pinned_key_t unset;
    wt_tls_client_config_t broken = config;
    memset(&unset, 0, sizeof(unset));
    broken.pin = &unset;
    wtc_expect_int("an unset pin is refused", 0,
               (long)wt_tls_client_start(&handshake, &broken, g_hello,
                                         sizeof(g_hello)));
  }
  {
    /* RFC 9001 section 8.2: a QUIC ClientHello without transport parameters is
       one a server closes the connection over, so it is refused before it is
       sent rather than discovered by watching the peer hang up. */
    wt_tls_client_hello_params_t without = wtc_params;
    wt_tls_client_config_t broken = config;
    without.quic_transport_parameters = NULL;
    without.quic_transport_parameters_len = 0U;
    broken.params = &without;
    wtc_expect_int("transport parameters are required in the ClientHello", 0,
               (long)wt_tls_client_start(&handshake, &broken, g_hello,
                                         sizeof(g_hello)));
    wtc_expect_int("  with handshake_failure", WT_TLS_ALERT_HANDSHAKE_FAILURE,
               (long)wt_tls_client_alert(&handshake));
  }
  {
    wt_tls_client_config_t broken = config;
    broken.client_key_private = NULL;
    wtc_expect_int("no private key is refused", 0,
               (long)wt_tls_client_start(&handshake, &broken, g_hello,
                                         sizeof(g_hello)));
    broken.client_key_private = WT_QUIC_FLIGHT_CLIENT_PRIVATE;
    broken.client_key_private_len = 31U;
    wtc_expect_int("a 31-byte private key is refused", 0,
               (long)wt_tls_client_start(&handshake, &broken, g_hello,
                                         sizeof(g_hello)));
  }

  needed = wt_tls_client_hello_size(&wtc_params);
  wtc_expect_int("the ClientHello has a size", 1, needed > 0U ? 1 : 0);
  wtc_expect_int("a buffer one byte too small is refused", 0,
             (long)wt_tls_client_start(&handshake, &config, g_hello,
                                       needed - 1U));
  wtc_expect_int("a NULL buffer is refused", 0,
             (long)wt_tls_client_start(&handshake, &config, NULL, needed));

  /* --- the message itself --- */
  written = wt_tls_client_start(&handshake, &config, g_hello, sizeof(g_hello));
  wtc_expect_int("the ClientHello is produced", (long)needed, (long)written);
  wtc_expect_int("the handshake is waiting for a ServerHello",
             (long)WT_TLS_STATE_WAIT_SERVER_HELLO,
             (long)wt_tls_client_state(&handshake));
  /* THE BUILDER AND THE ORACLE MUST AGREE. The rest of the fixture is computed
     around this exact message; if the builder and the Python encoder ever
     disagree, every later check would fail for a reason that looks like a
     crypto problem, so it is checked first and by itself. */
  wtc_expect_bytes("the ClientHello is the one the oracle computed",
               WT_QUIC_FLIGHT_CLIENT_HELLO, g_hello,
               sizeof(WT_QUIC_FLIGHT_CLIENT_HELLO));
  wtc_expect_int("no keys exist before a ServerHello", 0,
             wt_tls_client_keys_available(&handshake, WT_TLS_LEVEL_HANDSHAKE,
                                          0));
  wtc_expect_int("and none at the application level either", 0,
             wt_tls_client_keys_available(&handshake, WT_TLS_LEVEL_APPLICATION,
                                          1));
  wtc_expect_int("the Initial keys are not this module's to report", -1,
             wt_tls_client_keys(&handshake, WT_TLS_LEVEL_INITIAL, 0, NULL));
  wtc_expect_int("and no ALPN is negotiated yet", 0,
             wt_tls_client_alpn(&handshake, NULL) == NULL ? 0 : 1);
  wtc_expect_int("and no transport parameters are visible yet", 0,
             wt_tls_client_peer_transport_parameters(&handshake, NULL) == NULL
                 ? 0
                 : 1);
  wtc_expect_int("the negotiated AEAD is AES-128-GCM", 1,
             wt_tls_client_aead(&handshake) == WT_TLS_AEAD_AES_128_GCM ? 1 : 0);
}

/* -------------------------------------------------------- CertificateVerify */

void wtc_test_certificate_verify(void) {
  wt_tls_client_t handshake;
  /* Function scope: see test_encrypted_extensions. */
  uint8_t ee[256];
  uint8_t message[512];

  wtc_setup_params();
  wtc_setup_pin();

  /* --- a scheme that was not offered --- */
  if (wtc_reach_wait_encrypted_extensions(&handshake) != 0) return;
  {
    size_t len = wtc_good_encrypted_extensions(ee, sizeof(ee));
    if (wtc_feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, ee, len) != 0) return;
    if (wtc_feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, WT_QUIC_FLIGHT_CERTIFICATE,
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
    wtc_expect_int("an unoffered signature scheme is refused", -1,
               wtc_feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, message,
                    sizeof(WT_QUIC_FLIGHT_CERTIFICATE_VERIFY)));
    wtc_expect_int("  as an illegal parameter", WT_TLS_ALERT_ILLEGAL_PARAMETER,
               (long)wt_tls_client_alert(&handshake));
  }

  /* --- a signature that does not verify over this transcript --- */
  if (wtc_reach_wait_encrypted_extensions(&handshake) != 0) return;
  {
    size_t len = wtc_good_encrypted_extensions(ee, sizeof(ee));
    if (wtc_feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, ee, len) != 0) return;
    if (wtc_feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, WT_QUIC_FLIGHT_CERTIFICATE,
             sizeof(WT_QUIC_FLIGHT_CERTIFICATE)) != 0) {
      return;
    }
  }
  {
    /* RFC 8448's CertificateVerify, which is a real RSA-PSS signature over RFC
       8448's transcript. Against this transcript it must not verify: that is
       the whole point of the transcript being in the signed content. */
    wtc_expect_int("a signature over another transcript is refused", -1,
               wtc_feed(&handshake, WT_TLS_LEVEL_HANDSHAKE,
                    WT_RFC8448_CERTIFICATE_VERIFY,
                    sizeof(WT_RFC8448_CERTIFICATE_VERIFY)));
    wtc_expect_int("  as a decrypt error", WT_TLS_ALERT_DECRYPT_ERROR,
               (long)wt_tls_client_alert(&handshake));
  }

  /* --- a single-bit forgery of the real signature --- */
  if (wtc_reach_wait_encrypted_extensions(&handshake) != 0) return;
  {
    size_t len = wtc_good_encrypted_extensions(ee, sizeof(ee));
    if (wtc_feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, ee, len) != 0) return;
    if (wtc_feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, WT_QUIC_FLIGHT_CERTIFICATE,
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
    wtc_expect_int("a one-bit forgery is refused", -1,
               wtc_feed(&handshake, WT_TLS_LEVEL_HANDSHAKE, message,
                    sizeof(WT_QUIC_FLIGHT_CERTIFICATE_VERIFY)));
    wtc_expect_int("  as a decrypt error", WT_TLS_ALERT_DECRYPT_ERROR,
               (long)wt_tls_client_alert(&handshake));
  }
}
