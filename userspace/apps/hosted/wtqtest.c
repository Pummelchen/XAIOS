/*
 * /bin/wtqtest -- the XAIOS end of the WebTransport handshake gate (B-131).
 *
 * This is the port's client on a booted guest: the vendored library's runtime
 * session, the XAIOS socket seam for its datagrams, this repository's BearSSL
 * crypto backend, and this repository's trust, certificate and signature code.
 * It connects to the host peer at `10.0.2.2:4433` -- QEMU's user network puts
 * the host there -- pins the certificate that peer presents, and prints
 * `WT-HANDSHAKE-OK` only once the handshake is complete and the peer's
 * transport parameters are in force.
 *
 * With no arguments it uses the pin of the certificate in
 * `tests/fixtures/wt-peer-cert.der`, which is what makes the gate a one-line
 * command. The arguments exist so the same binary can be pointed at another
 * peer without a rebuild, which is how it is first tried by hand.
 *
 * Usage: wtqtest [host] [port] [pin-hex]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "webtransport/quic/transport_parameters.h"
#include "webtransport/runtime/session.h"
#include "webtransport/writer.h"

#ifndef XAIOS_WTQTEST_DEFAULT_HOST
#define XAIOS_WTQTEST_DEFAULT_HOST "10.0.2.2"
#endif
#ifndef XAIOS_WTQTEST_DEFAULT_PORT
#define XAIOS_WTQTEST_DEFAULT_PORT 4433U
#endif

/* The SHA-256 of `tests/fixtures/wt-peer-cert.der`. A pin is a decision made
 * before the first packet, so it is a constant here rather than something the
 * peer talks this program into; `generate_wt_peer_identity.py` prints the same
 * value when it re-verifies the fixture. */
#define XAIOS_WTQTEST_PIN \
  "d4664ca34bd74e2e2b3d4f7ac38b85007f1db172fb8bcb336068d840e9f19dca"

/* One round is a one-millisecond wait plus a pump, so this is a little over
 * twenty seconds of handshake. A QUIC handshake over loopback takes single
 * digit milliseconds; the bound is here so a peer that never answers is a
 * failure with a number rather than a program that hangs the gate. */
#define WTQTEST_MAX_ROUNDS 20000U

static const uint8_t k_client_connection_id[8] = {0x11U, 0x22U, 0x33U, 0x44U,
                                                  0x55U, 0x66U, 0x77U, 0x88U};

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int parse_pin(const char *text, uint8_t out[32]) {
  size_t index;
  if (text == NULL || strlen(text) != 64U) return -1;
  for (index = 0U; index < 32U; ++index) {
    int high = hex_nibble(text[index * 2U]);
    int low = hex_nibble(text[index * 2U + 1U]);
    if (high < 0 || low < 0) return -1;
    out[index] = (uint8_t)((high << 4) | low);
  }
  return 0;
}

static uint64_t build_parameters(uint8_t *out, size_t capacity,
                                 const uint8_t *source, size_t source_length) {
  wt_quic_transport_parameters_t params;
  wt_writer_t writer = wt_writer_init(out, capacity);
  if (wt_quic_transport_parameters_build(&params, 0, source, source_length,
                                         NULL, 0U, 0, NULL, 0U) != WT_OK) {
    return 0U;
  }
  if (wt_quic_transport_parameters_encode(&writer, &params) != WT_OK) return 0U;
  return (uint64_t)wt_writer_offset(&writer);
}

int main(int argc, char **argv) {
  wt_runtime_session_t session;
  wt_quic_connection_config_t connection;
  wt_tls_client_config_t tls;
  static const char *const alpn_h3[] = {"h3"};
  wt_udp_socket_t socket;
  wt_udp_address_t peer;
  uint8_t parameters[256];
  uint8_t pin[32];
  const char *host = XAIOS_WTQTEST_DEFAULT_HOST;
  const char *pin_text = XAIOS_WTQTEST_PIN;
  unsigned long port = XAIOS_WTQTEST_DEFAULT_PORT;
  uint64_t parameters_len;
  uint64_t now = 1000U;
  char joined[192];
  unsigned round;
  int ready = 0;

  if (argc > 1) host = argv[1];
  if (argc > 2) port = strtoul(argv[2], NULL, 10);
  if (argc > 3) pin_text = argv[3];
  if (port == 0U || port > 65535U) {
    printf("wtqtest: port %lu is not a port\n", port);
    return 2;
  }
  if (parse_pin(pin_text, pin) != 0) {
    printf("wtqtest: the pin is not 64 hexadecimal digits\n");
    return 2;
  }

  printf("wtqtest: connecting to %s:%lu\n", host, port);
  fflush(stdout);

  (void)snprintf(joined, sizeof(joined), "%s:%lu", host, port);
  if (wt_udp_address_parse_host_port(joined, &peer) != WT_OK) {
    printf("wtqtest: WT-HANDSHAKE-FAILED cannot parse %s\n", joined);
    return 1;
  }
  if (wt_udp_socket_open(&socket, peer.family) != WT_OK) {
    printf("wtqtest: WT-HANDSHAKE-FAILED cannot open a UDP socket\n");
    return 1;
  }

  parameters_len = build_parameters(parameters, sizeof(parameters),
                                    k_client_connection_id,
                                    sizeof(k_client_connection_id));
  if (parameters_len == 0U) {
    printf("wtqtest: WT-HANDSHAKE-FAILED cannot build transport parameters\n");
    wt_udp_close(&socket);
    return 1;
  }

  memset(&tls, 0, sizeof(tls));
  tls.alpn = alpn_h3;
  tls.alpn_count = 1U;
  tls.host_name = "localhost";
  tls.require_transport_parameters = 1;
  tls.transport_parameters = parameters;
  tls.transport_parameters_len = (size_t)parameters_len;
  tls.trust.mode = WT_TLS_TRUST_PINNED_CERTIFICATE;
  tls.trust.host_name = "localhost";
  memcpy(tls.trust.fingerprints[0], pin, 32U);
  tls.trust.fingerprint_count = 1U;

  memset(&connection, 0, sizeof(connection));
  connection.role = WT_QUIC_ROLE_CLIENT;
  connection.version = WT_QUIC_VERSION_1;
  connection.local_connection_id = k_client_connection_id;
  connection.local_connection_id_length = sizeof(k_client_connection_id);
  connection.peer_connection_id = k_client_connection_id;
  connection.peer_connection_id_length = sizeof(k_client_connection_id);
  connection.aead = WT_AEAD_AES_128_GCM;
  connection.max_ack_delay = 25000U;
  connection.local_max_ack_delay = 25000U;
  connection.idle_timeout = 30000000U;
  connection.max_datagram_size = 1200U;

  if (wt_runtime_session_start_client(&session, &socket, &peer,
                                      k_client_connection_id,
                                      sizeof(k_client_connection_id),
                                      &connection, &tls, now) != WT_OK) {
    printf("wtqtest: WT-HANDSHAKE-FAILED cannot start the client session\n");
    wt_udp_close(&socket);
    return 1;
  }
  /* The advertised limits, in force: the promise and the enforcement in one
     place, or the first frame the peer sends is refused as a flow-control
     error and the handshake looks like a peer that says nothing. */
  (void)wt_runtime_session_advertise(&session, 100000U, 4096U, 8U, 8U);
  (void)wt_runtime_session_keep_spare_connection_id(&session);

  for (round = 0U; round < WTQTEST_MAX_ROUNDS; ++round) {
    wt_status_t failure;
    if (wt_runtime_session_handshake_done(&session) != 0 &&
        session.peer_parameters_applied != 0) {
      ready = 1;
      break;
    }
    failure = wt_runtime_session_failure(&session);
    if (failure != WT_OK) {
      printf("wtqtest: WT-HANDSHAKE-FAILED round=%u status=%s\n", round,
             wt_status_name(failure));
      wt_runtime_session_clear(&session);
      wt_udp_close(&socket);
      return 1;
    }
    (void)wt_udp_wait(&socket, 1000U);
    (void)wt_runtime_session_pump(&session, now);
    now += 1000U;
    /* A stall has two shapes -- "nothing arrived" and "things arrived and were
       not consumed" -- and they look the same from a timeout alone. This says
       which, and it is a progress line only because a gate reads it when the
       run failed. */
    if ((round % 2000U) == 1999U) {
      printf("wtqtest: progress round=%u packets=%u bytes=%llu received=%s "
             "errors=%u\n",
             round + 1U, session.packets_seen,
             (unsigned long long)session.connection.bytes_received,
             wt_status_name(session.last_receive), session.receive_errors);
      fflush(stdout);
    }
  }

  if (!ready) {
    printf("wtqtest: WT-HANDSHAKE-FAILED timed out after %u rounds "
           "(handshake_done=%d peer_parameters_applied=%d receive_errors=%u "
           "first=%s)\n",
           WTQTEST_MAX_ROUNDS, wt_runtime_session_handshake_done(&session),
           session.peer_parameters_applied, session.receive_errors,
           wt_status_name(session.first_receive_error));
    (void)wt_runtime_session_pump(&session, now);
    wt_runtime_session_clear(&session);
    wt_udp_close(&socket);
    return 1;
  }

  /* A round more, so the peer's Finished is acknowledged before this side goes
     quiet; a client that exits on the instant it is ready leaves the server
     with nothing to confirm. */
  (void)wt_udp_wait(&socket, 1000U);
  (void)wt_runtime_session_pump(&session, now);
  printf("wtqtest: WT-HANDSHAKE-OK rounds=%u packets=%u\n", round,
         session.packets_seen);
  fflush(stdout);
  wt_runtime_session_clear(&session);
  wt_udp_close(&socket);
  return 0;
}
