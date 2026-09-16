/*
 * The TLS 1.3 handshake over QUIC, driven from CRYPTO frames.
 *
 * WHAT THIS FILE IS. It is the join between two things that were built separately and deliberately do
 * not know about each other: `tls/session.h`, which is a message-at-a-time TLS 1.3 state machine, and
 * `quic/connection.h`, which is a packet layer that hands frames to whoever installed a handler. This
 * driver is that handler. It reassembles the CRYPTO stream of each encryption level, walks it into whole
 * handshake messages, feeds them to the TLS machine in order, takes what the machine produces, and
 * installs the packet keys each step of the handshake makes available.
 *
 * THE THREE THINGS IT HAS TO GET RIGHT.
 *
 * The MESSAGE BOUNDARY is the transport's, not TLS's. QUIC carries handshake bytes as a stream of
 * CRYPTO frames, so two messages can share a frame and one message can span two; the reassembler holds
 * bytes until a whole message is there, and only then does the TLS machine see anything. Feeding it a
 * partial message would be a parse of half a message, and feeding it two at once would leave the
 * machine waiting for a message it had already been given.
 *
 * THE KEYS COME AS THE HANDSHAKE MAKES THEM, not all at the start. The Initial keys exist before TLS
 * says anything and belong to the caller, because they are derived from the connection ID; the
 * handshake keys appear with the ServerHello (client) or the ClientHello (server), and the application
 * keys only when the handshake is confirmed in both directions. A driver that installed them early
 * would protect a packet with a key the peer does not have yet, which reads as a broken cipher rather
 * than as a missing handshake step.
 *
 * A LOST FLIGHT IS SENT AGAIN FROM HERE. QUIC retransmits CRYPTO data rather than asking TLS to produce
 * it twice -- an RSA-PSS signature is randomised, so a second flight would not match the transcript the
 * first one signed -- which is why `tls/session.h` builds its flight once and why this driver keeps the
 * bytes it has sent and hands them back when the connection reports the packet lost.
 */

#ifndef WEBTRANSPORT_QUIC_HANDSHAKE_H
#define WEBTRANSPORT_QUIC_HANDSHAKE_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/quic/connection.h"
#include "webtransport/quic/crypto_stream.h"
#include "webtransport/quic/error.h"
#include "webtransport/status.h"
#include "webtransport/tls/session.h"

#ifdef __cplusplus
extern "C" {
#endif

/* How many lost CRYPTO packets can be waiting to be sent again. The handshake is a handful of packets,
 * and a full list is a refusal rather than a silent drop: a flight that is not resent is a handshake
 * that hangs with nothing naming why. */
#define WT_QUIC_HANDSHAKE_RETRANSMIT_MAX 8U

/* The negotiated protocol and the peer's transport parameters are COPIED here, because the TLS
 * machine's views of them are only valid inside the call that produced them -- they point into the
 * CRYPTO window, which the next consume slides over. Both are needed for the connection's whole life:
 * the protocol picks the application layer and the parameters carry the limits it must obey. */
#define WT_QUIC_HANDSHAKE_ALPN_MAX 64U
/* The bound on the peer's transport parameters this endpoint keeps a copy of. It is deliberately several times
 * the largest parameter RFC 9000 defines, because a peer may legally send parameters this version does not
 * understand -- the GREASE parameters browsers send run to a few hundred bytes -- and refusing those would make
 * this endpoint reject exactly the peers the draft asks it to interoperate with. A peer that exceeds even this
 * bound is refused with a handshake failure rather than ignored: the parameters ARE the connection's limits and
 * its connection-ID checks, so a connection that dropped them would run without either, which is what the
 * audit found the 256-byte version doing. */
#define WT_QUIC_HANDSHAKE_PARAMETERS_MAX 1024U

typedef enum wt_quic_handshake_state {
  /* Nothing has been started. */
  WT_QUIC_HANDSHAKE_IDLE = 0,
  /* A client with its ClientHello sent, waiting for the server. */
  WT_QUIC_HANDSHAKE_CLIENT_WAITING,
  /* A server with its flight sent, waiting for the client's Finished. */
  WT_QUIC_HANDSHAKE_SERVER_WAITING,
  /* The handshake is complete and the application secrets are installed. */
  WT_QUIC_HANDSHAKE_CONNECTED,
  /* A message was refused and the connection cannot continue. */
  WT_QUIC_HANDSHAKE_FAILED
} wt_quic_handshake_state_t;

typedef struct wt_quic_handshake_retransmit {
  int in_use;
  wt_quic_space_t space;
  uint64_t offset;
  size_t length;
} wt_quic_handshake_retransmit_t;

typedef struct wt_quic_handshake {
  /* The marker the TLS machines use, so that a handshake this driver has never started can be told
   * from one that is live. */
  uint64_t live;
  int is_client;
  /* The connection this handshake protects, borrowed: the driver installs keys into it and sends
   * through it, and never owns it. */
  wt_quic_connection_t *connection;
  wt_tls_client_t client;
  wt_tls_server_t server;
  /* One stream per direction and encryption level, because that is what a CRYPTO frame is. */
  wt_quic_crypto_send_t send[WT_QUIC_SPACE_COUNT];
  wt_quic_crypto_recv_t recv[WT_QUIC_SPACE_COUNT];
  wt_quic_handshake_retransmit_t retransmit[WT_QUIC_HANDSHAKE_RETRANSMIT_MAX];
  wt_quic_handshake_state_t state;
  /* Why it failed, and the transport error code to close with: RFC 9000 section 20.1 gives a failed
   * handshake CRYPTO_ERROR with the TLS alert in the low byte, and this is what goes in the frame. */
  wt_status_t failure;
  uint64_t error_code;
  /* Whether the levels' keys have been installed, so that the second ServerHello-like message cannot
   * install them twice. */
  int handshake_keys_installed;
  int application_keys_installed;
  /* Whether the rest of the server's flight has been built. It is built once, because the
   * CertificateVerify signature is randomised and a second flight would not match the transcript the
   * first one signed -- which is why the TLS machine refuses a second call and why this driver does not
   * ask for one. */
  int server_flight_built;
  /* A server's handshake is confirmed for the client by a HANDSHAKE_DONE frame, which is this layer's
   * to send once the handshake completes. */
  int handshake_done_pending;
  /* Whether the handshake is confirmed, which the client sets when the server's HANDSHAKE_DONE
   * arrives and the server sets when its own handshake completes. */
  int confirmed;
  /* The copies described above, filled as the messages that carry them arrive. */
  uint8_t alpn[WT_QUIC_HANDSHAKE_ALPN_MAX];
  size_t alpn_len;
  uint8_t peer_parameters[WT_QUIC_HANDSHAKE_PARAMETERS_MAX];
  size_t peer_parameters_len;
} wt_quic_handshake_t;

/* Start a client handshake and build the ClientHello into the Initial space's send buffer. The
 * connection must already have its Initial keys and its peer's address: those are the caller's,
 * because they come from the connection ID and the socket rather than from TLS. */
wt_status_t wt_quic_handshake_start_client(wt_quic_handshake_t *handshake,
                                           wt_quic_connection_t *connection,
                                           const wt_tls_client_config_t *config);

/* Start a server handshake. Nothing is sent until a ClientHello arrives. */
wt_status_t wt_quic_handshake_start_server(wt_quic_handshake_t *handshake,
                                           wt_quic_connection_t *connection,
                                           const wt_tls_server_config_t *config);

/* The connection's frame handler. It acts on CRYPTO frames and on HANDSHAKE_DONE, and ignores
 * everything else -- so a caller with more than one consumer (a stream layer, a session layer) installs
 * a handler that calls this one first and then its own, which is why it returns WT_OK for frames that
 * are not its business rather than refusing them. */
wt_status_t wt_quic_handshake_on_frame(void *context, wt_quic_space_t space,
                                       const wt_quic_frame_t *frame);

/* The connection's lost handler: a CRYPTO packet that was declared lost is remembered so that the next
 * flush sends its bytes again. */
void wt_quic_handshake_on_lost(void *context, const wt_quic_tx_frame_t *frame);

/* Send what the handshake has to say: the resends a loss asked for, then the messages the TLS machine
 * produced, then a server's HANDSHAKE_DONE. Nothing is sent when the handshake is idle or failed.
 * WT_ERR_AGAIN from the connection (no room in the congestion window, or every retransmission slot
 * taken) is not an error here: it means "call again after the next acknowledgement". */
wt_status_t wt_quic_handshake_flush(wt_quic_handshake_t *handshake, uint64_t now);

/* Whether anything is waiting to be sent, which is what tells an event loop that it has work to do
 * before it waits for the socket. */
int wt_quic_handshake_pending(const wt_quic_handshake_t *handshake);

wt_quic_handshake_state_t wt_quic_handshake_state(const wt_quic_handshake_t *handshake);
int wt_quic_handshake_is_connected(const wt_quic_handshake_t *handshake);

/* The protocol the peer chose and the transport parameters it sent, copied when the messages that
 * carry them arrived: valid for the handshake's lifetime, and NULL before then. A copy rather than a
 * view because the TLS machine's views point into the CRYPTO window, which is consumed and slid over as
 * the handshake proceeds. */
const uint8_t *wt_quic_handshake_alpn(const wt_quic_handshake_t *handshake, size_t *out_len);
const uint8_t *wt_quic_handshake_peer_transport_parameters(const wt_quic_handshake_t *handshake,
                                                           size_t *out_len);

/* Zero the secrets and release the hash contexts this handshake held, which is what a connection does
 * when it is finished with it -- successfully or not. */
void wt_quic_handshake_clear(wt_quic_handshake_t *handshake);

/* "idle", "client-waiting", "server-waiting", "connected", "failed". Never NULL. */
const char *wt_quic_handshake_state_name(wt_quic_handshake_state_t state);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_QUIC_HANDSHAKE_H */
