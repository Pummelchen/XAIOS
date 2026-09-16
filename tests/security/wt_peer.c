/*
 * A QUIC + TLS 1.3 handshake endpoint for the host (B-131).
 *
 * This is the far side of the XAIOS WebTransport port's handshake gate and the
 * two ends of its interop test. It drives the vendored library's runtime
 * session -- socket, QUIC connection and TLS handshake together -- and nothing
 * above it, so a failure here is a handshake failure and not a session that
 * could not be negotiated.
 *
 * Only the handshake is wanted, so only the handshake is driven. The HTTP/3 and
 * WebTransport layers are compiled and checked elsewhere; a gate that had to
 * negotiate a session before it could say whether a handshake happened would
 * report the wrong failure.
 *
 * The identity is the DER pair beside the repository's throwaway PEM one
 * (`tests/fixtures/wt-peer-*`), loaded from disk rather than generated, because
 * a generated certificate has a different fingerprint every run and the client
 * pins one before the first packet.
 *
 * `xaios_random` is defined here for the host: the key-share and RSA-PSS salt
 * both draw from it on the target, and `getentropy` is the same guarantee --
 * the platform's entropy rather than a library's own generator.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/random.h>

#include <xaios_user.h>

#include "webtransport/crypto/crypto.h"
#include "webtransport/quic/packet.h"
#include "webtransport/quic/transport_parameters.h"
#include "webtransport/runtime/session.h"
#include "webtransport/writer.h"

int xaios_random(void *buffer, u64 size) {
  unsigned char *at = (unsigned char *)buffer;
  u64 remaining = size;
  if (buffer == NULL) return -1;
  while (remaining > 0U) {
    /* getentropy refuses more than 256 bytes at a time. */
    size_t chunk = remaining > 256U ? 256U : (size_t)remaining;
    if (getentropy(at, chunk) != 0) return -1;
    at += chunk;
    remaining -= (u64)chunk;
  }
  return 0;
}

/* Upstream's own tool uses fixed connection IDs so that both ends address each
 * other the same way every run. This endpoint is reached by address and never
 * by connection ID, so a fixed pair costs nothing and makes a capture
 * readable. */
static const uint8_t k_client_connection_id[8] = {0x11U, 0x22U, 0x33U, 0x44U,
                                                  0x55U, 0x66U, 0x77U, 0x88U};
static const uint8_t k_server_connection_id[8] = {0x21U, 0x32U, 0x43U, 0x54U,
                                                  0x65U, 0x76U, 0x87U, 0x98U};

#define WT_PEER_MAX_PUMP_ROUNDS 4000U

typedef struct wt_peer {
  wt_runtime_session_t session;
  wt_udp_socket_t socket;
  wt_udp_address_t peer;
  uint64_t now;
  wt_status_t last_receive_error;
  unsigned receive_errors;
} wt_peer_t;

/* The certificate and key, owned here because the identity borrows them for
 * the whole run. */
static uint8_t g_certificate[8192];
static size_t g_certificate_len;
static uint8_t g_private_key[8192];
static size_t g_private_key_len;

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

static int read_file(const char *path, uint8_t *out, size_t capacity,
                     size_t *out_length) {
  FILE *file = fopen(path, "rb");
  size_t length;
  if (file == NULL) {
    printf("WT-PEER-FAILED cannot open %s\n", path);
    return -1;
  }
  length = fread(out, 1U, capacity, file);
  if (ferror(file) != 0) {
    printf("WT-PEER-FAILED cannot read %s\n", path);
    fclose(file);
    return -1;
  }
  fclose(file);
  if (length == 0U || length == capacity) {
    printf("WT-PEER-FAILED %s is empty or larger than this tool carries\n", path);
    return -1;
  }
  *out_length = length;
  return 0;
}

static uint64_t build_parameters(uint8_t *out, size_t capacity, int is_server,
                                 const uint8_t *source, size_t source_length,
                                 const uint8_t *original_destination,
                                 size_t original_length) {
  wt_quic_transport_parameters_t params;
  wt_writer_t writer = wt_writer_init(out, capacity);
  if (wt_quic_transport_parameters_build(&params, is_server, source,
                                         source_length, original_destination,
                                         original_length, 0, NULL, 0U) !=
      WT_OK) {
    return 0U;
  }
  if (wt_quic_transport_parameters_encode(&writer, &params) != WT_OK) return 0U;
  return (uint64_t)wt_writer_offset(&writer);
}

static void connection_config(wt_quic_connection_config_t *config,
                              wt_quic_role_t role, const uint8_t *connection_id,
                              size_t connection_id_length) {
  memset(config, 0, sizeof(*config));
  config->role = role;
  config->version = WT_QUIC_VERSION_1;
  config->local_connection_id = connection_id;
  config->local_connection_id_length = connection_id_length;
  config->peer_connection_id = connection_id;
  config->peer_connection_id_length = connection_id_length;
  config->aead = WT_AEAD_AES_128_GCM;
  config->max_ack_delay = 25000U;
  config->local_max_ack_delay = 25000U;
  config->idle_timeout = 30000000U;
  config->max_datagram_size = 1200U;
}

/* One bounded round: wait for a datagram, pump, advance the clock. */
static void pump_once(wt_peer_t *peer) {
  (void)wt_udp_wait(&peer->socket, 1000U);
  (void)wt_runtime_session_pump(&peer->session, peer->now);
  if (peer->session.receive_errors != 0U && peer->receive_errors == 0U) {
    peer->receive_errors = peer->session.receive_errors;
    peer->last_receive_error = peer->session.first_receive_error;
  }
  peer->now += 1000U;
}

static int handshake_ready(const wt_peer_t *peer) {
  return wt_runtime_session_handshake_done(&peer->session) != 0 &&
         peer->session.peer_parameters_applied != 0;
}

/* Pump until the handshake completes, the connection closes, or the bound is
 * reached. On failure say what the runtime saw rather than only that time
 * passed: "nothing arrived" and "things arrived and were refused" look the same
 * from a timeout alone. */
static int run_until_ready(wt_peer_t *peer, const char *who) {
  unsigned round;
  for (round = 0U; round < WT_PEER_MAX_PUMP_ROUNDS; ++round) {
    if (handshake_ready(peer)) return 0;
    if (wt_runtime_session_failure(&peer->session) != WT_OK) {
      wt_status_t failure = wt_runtime_session_failure(&peer->session);
      /* The NAME rather than the number: a gate that asserted on "12" would
         pass on any status that happened to share the ordinal. */
      printf("WT-PEER-FAILED %s: session failure %s\n", who,
             wt_status_name(failure));
      return 1;
    }
    pump_once(peer);
  }
  printf("WT-PEER-TIMEOUT %s: handshake_done=%d peer_parameters_applied=%d "
         "receive_errors=%u first=%s\n",
         who, wt_runtime_session_handshake_done(&peer->session),
         peer->session.peer_parameters_applied, peer->receive_errors,
         wt_status_name(peer->last_receive_error));
  return 1;
}

static int run_server(const char *bind_host, uint16_t port, const char *cert_path,
                      const char *key_path) {
  wt_peer_t peer;
  wt_quic_connection_config_t connection;
  wt_tls_server_config_t tls;
  wt_tls_server_identity_t identity;
  uint8_t parameters[256];
  uint8_t fingerprint[WT_SHA256_LEN];
  uint64_t parameters_len;
  uint8_t header[64];
  const uint8_t *client_destination = NULL;
  size_t client_destination_length = 0U;
  char joined[128];
  wt_udp_address_t local;
  unsigned waited;
  int arrived = 0;

  if (read_file(cert_path, g_certificate, sizeof(g_certificate),
                &g_certificate_len) != 0) {
    return 1;
  }
  if (read_file(key_path, g_private_key, sizeof(g_private_key),
                &g_private_key_len) != 0) {
    return 1;
  }
  memset(&peer, 0, sizeof(peer));
  peer.now = 1000U;

  (void)snprintf(joined, sizeof(joined), "%s:%u", bind_host, (unsigned)port);
  if (wt_udp_address_parse_host_port(joined, &local) != WT_OK) {
    printf("WT-PEER-FAILED cannot parse %s\n", joined);
    return 1;
  }
  if (wt_udp_socket_open(&peer.socket, local.family) != WT_OK) {
    printf("WT-PEER-FAILED cannot open a socket\n");
    return 1;
  }
  if (wt_udp_bind(&peer.socket, &local) != WT_OK) {
    printf("WT-PEER-FAILED cannot bind %s\n", joined);
    wt_udp_close(&peer.socket);
    return 1;
  }

  /* The fingerprint of the certificate this peer will present, printed so the
     client can pin it without either side sharing a file. */
  if (wt_sha256(g_certificate, g_certificate_len, fingerprint) != WT_OK) {
    printf("WT-PEER-FAILED cannot hash the certificate\n");
    wt_udp_close(&peer.socket);
    return 1;
  }
  printf("WT-PEER-BOUND port=%u\n", (unsigned)peer.socket.port);
  printf("WT-PEER-PIN ");
  {
    size_t index;
    for (index = 0U; index < sizeof(fingerprint); ++index) {
      printf("%02x", fingerprint[index]);
    }
  }
  printf("\n");
  fflush(stdout);

  /* The peer's address is not known until a packet arrives, and the datagram
     that names it must still be in the queue when the connection is armed, so
     it is PEEKED rather than received. The client's first Initial names both
     connection IDs this server needs: the destination it chose, which the
     transport parameters must echo, is the one the Initial keys derive from. */
  for (waited = 0U; waited < 2000U; ++waited) {
    size_t datagram_length = 0U;
    size_t available = 0U;
    wt_udp_address_t candidate;
    if (wt_udp_peek(&peer.socket, header, sizeof(header), &datagram_length,
                    &available, &candidate) == WT_OK) {
      const uint8_t *destination = NULL;
      size_t destination_length = 0U;
      const uint8_t *source = NULL;
      size_t source_length = 0U;
      if (wt_quic_long_header_connection_ids(header, available, &destination,
                                             &destination_length, &source,
                                             &source_length) == WT_OK &&
          destination_length > 0U && source_length > 0U) {
        peer.peer = candidate;
        client_destination = destination;
        client_destination_length = destination_length;
        arrived = 1;
        break;
      }
    }
    (void)wt_udp_wait(&peer.socket, 10000U);
  }
  if (arrived == 0) {
    printf("WT-PEER-TIMEOUT no Initial arrived\n");
    wt_udp_close(&peer.socket);
    return 1;
  }

  parameters_len = build_parameters(parameters, sizeof(parameters), 1,
                                    k_server_connection_id,
                                    sizeof(k_server_connection_id),
                                    client_destination,
                                    client_destination_length);
  if (parameters_len == 0U) {
    printf("WT-PEER-FAILED cannot build transport parameters\n");
    wt_udp_close(&peer.socket);
    return 1;
  }

  memset(&identity, 0, sizeof(identity));
  identity.certificate[0] = g_certificate;
  identity.certificate_len[0] = g_certificate_len;
  identity.certificate_count = 1U;
  identity.private_key = g_private_key;
  identity.private_key_len = g_private_key_len;
  /* The fixture is an RSA key, so the scheme is the RSA-PSS one the client
     offers and this port's verifier carries. */
  identity.signature_scheme = WT_TLS_SIGNATURE_RSA_PSS_RSAE_SHA256;

  memset(&tls, 0, sizeof(tls));
  tls.identity = &identity;
  tls.alpn = "h3";
  tls.require_transport_parameters = 1;
  tls.transport_parameters = parameters;
  tls.transport_parameters_len = (size_t)parameters_len;

  connection_config(&connection, WT_QUIC_ROLE_SERVER, k_server_connection_id,
                    sizeof(k_server_connection_id));
  if (wt_runtime_session_start_server(&peer.session, &peer.socket, &peer.peer,
                                      client_destination,
                                      client_destination_length, &connection,
                                      &tls, peer.now) != WT_OK) {
    printf("WT-PEER-FAILED cannot start the server session\n");
    wt_udp_close(&peer.socket);
    return 1;
  }
  (void)wt_runtime_session_advertise(&peer.session, 100000U, 4096U, 8U, 8U);
  (void)wt_runtime_session_keep_spare_connection_id(&peer.session);

  if (run_until_ready(&peer, "server") != 0) {
    wt_runtime_session_clear(&peer.session);
    wt_udp_close(&peer.socket);
    return 1;
  }
  printf("WT-PEER-HANDSHAKE-OK server\n");
  fflush(stdout);
  /* A few more rounds so the client's Finished is acknowledged before the
     socket goes away: a peer that exits the instant it is ready leaves the
     client retransmitting into a closed port. */
  pump_once(&peer);
  pump_once(&peer);
  pump_once(&peer);
  wt_runtime_session_clear(&peer.session);
  wt_udp_close(&peer.socket);
  return 0;
}

static int run_client(const char *host, uint16_t port, const char *authority,
                      const char *pin_text) {
  wt_peer_t peer;
  wt_quic_connection_config_t connection;
  wt_tls_client_config_t tls;
  static const char *const alpn_h3[] = {"h3"};
  uint8_t parameters[256];
  uint64_t parameters_len;
  uint8_t pin[32];
  char joined[256];
  wt_udp_address_t peer_address;

  memset(&peer, 0, sizeof(peer));
  peer.now = 1000U;
  (void)snprintf(joined, sizeof(joined), "%s:%u", host, (unsigned)port);
  if (wt_udp_address_parse_host_port(joined, &peer_address) != WT_OK) {
    printf("WT-PEER-FAILED cannot parse %s\n", joined);
    return 1;
  }
  if (wt_udp_socket_open(&peer.socket, peer_address.family) != WT_OK) {
    printf("WT-PEER-FAILED cannot open a socket\n");
    return 1;
  }
  peer.peer = peer_address;

  parameters_len = build_parameters(parameters, sizeof(parameters), 0,
                                    k_client_connection_id,
                                    sizeof(k_client_connection_id), NULL, 0U);
  if (parameters_len == 0U) {
    printf("WT-PEER-FAILED cannot build transport parameters\n");
    wt_udp_close(&peer.socket);
    return 1;
  }

  memset(&tls, 0, sizeof(tls));
  tls.alpn = alpn_h3;
  tls.alpn_count = 1U;
  tls.host_name = authority;
  tls.require_transport_parameters = 1;
  tls.transport_parameters = parameters;
  tls.transport_parameters_len = (size_t)parameters_len;
  if (pin_text != NULL) {
    if (parse_pin(pin_text, pin) != 0) {
      printf("WT-PEER-FAILED the pin is not 64 hex digits\n");
      wt_udp_close(&peer.socket);
      return 1;
    }
    tls.trust.mode = WT_TLS_TRUST_PINNED_CERTIFICATE;
    tls.trust.host_name = authority;
    memcpy(tls.trust.fingerprints[0], pin, 32U);
    tls.trust.fingerprint_count = 1U;
    printf("WT-CLIENT-PINNED\n");
  } else {
    tls.trust.mode = WT_TLS_TRUST_LOCAL_DEVELOPMENT;
    tls.trust.host_name = authority;
    printf("WT-CLIENT-DEVELOPMENT\n");
  }
  fflush(stdout);

  connection_config(&connection, WT_QUIC_ROLE_CLIENT, k_client_connection_id,
                    sizeof(k_client_connection_id));
  if (wt_runtime_session_start_client(&peer.session, &peer.socket,
                                      &peer_address, k_client_connection_id,
                                      sizeof(k_client_connection_id),
                                      &connection, &tls, peer.now) != WT_OK) {
    printf("WT-PEER-FAILED cannot start the client session\n");
    wt_udp_close(&peer.socket);
    return 1;
  }
  (void)wt_runtime_session_advertise(&peer.session, 100000U, 4096U, 8U, 8U);
  (void)wt_runtime_session_keep_spare_connection_id(&peer.session);

  if (run_until_ready(&peer, "client") != 0) {
    wt_runtime_session_clear(&peer.session);
    wt_udp_close(&peer.socket);
    return 1;
  }
  printf("WT-CLIENT-HANDSHAKE-OK\n");
  fflush(stdout);
  pump_once(&peer);
  wt_runtime_session_clear(&peer.session);
  wt_udp_close(&peer.socket);
  return 0;
}

int main(int argc, char **argv) {
  const char *mode = NULL;
  const char *host = "127.0.0.1";
  const char *authority = "localhost";
  const char *pin = NULL;
  const char *cert = NULL;
  const char *key = NULL;
  uint16_t port = 4433U;
  int index;

  for (index = 1; index < argc; ++index) {
    if (strcmp(argv[index], "--server") == 0) {
      mode = "server";
    } else if (strcmp(argv[index], "--client") == 0) {
      mode = "client";
    } else if (strcmp(argv[index], "--host") == 0 && index + 1 < argc) {
      host = argv[++index];
    } else if (strcmp(argv[index], "--authority") == 0 && index + 1 < argc) {
      authority = argv[++index];
    } else if (strcmp(argv[index], "--pin") == 0 && index + 1 < argc) {
      pin = argv[++index];
    } else if (strcmp(argv[index], "--cert") == 0 && index + 1 < argc) {
      cert = argv[++index];
    } else if (strcmp(argv[index], "--key") == 0 && index + 1 < argc) {
      key = argv[++index];
    } else if (strcmp(argv[index], "--port") == 0 && index + 1 < argc) {
      port = (uint16_t)atoi(argv[++index]);
    } else {
      printf("WT-PEER-FAILED unknown argument: %s\n", argv[index]);
      return 2;
    }
  }
  if (mode == NULL) {
    printf("usage: wt_peer --server --port N --cert DER --key DER\n"
           "       wt_peer --client --host H --port N [--authority A] "
           "[--pin HEX]\n");
    return 2;
  }
  if (strcmp(mode, "server") == 0) {
    if (cert == NULL || key == NULL) {
      printf("WT-PEER-FAILED --server needs --cert and --key\n");
      return 2;
    }
    return run_server(host, port, cert, key);
  }
  return run_client(host, port, authority, pin);
}
