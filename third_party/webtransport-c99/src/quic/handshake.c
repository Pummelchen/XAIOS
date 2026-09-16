/* The TLS handshake over CRYPTO frames. See webtransport/quic/handshake.h.
 *
 * The flow of one message is the whole file: bytes arrive as CRYPTO frames into a per-level reassembler,
 * the reassembler delivers whole handshake messages, the TLS machine consumes one and may produce one,
 * what it produces is appended to the send stream of the level it belongs to, and the keys the step made
 * available are installed into the connection. A loss comes back through the lost handler and puts the
 * same bytes in the send stream again, because TLS is asked for a flight once.
 */

#include "webtransport/quic/handshake.h"

#include <string.h>

#include "webtransport/quic/frame.h"
#include "webtransport/quic/protection.h"
#include "webtransport/tls/handshake.h"

/* The ClientHello this implementation builds is bounded by the TLS header's own macro; the server's
 * flight, which carries a certificate chain, is not, so a caller-sized buffer is used and a flight that
 * does not fit is reported rather than truncated. */
#define WT_QUIC_HANDSHAKE_FLIGHT_MAX 4096U
/* The largest single message the TLS machine produces on its own: a ServerHello or a Finished. */
#define WT_QUIC_HANDSHAKE_MESSAGE_MAX 1024U
/* What one packet may carry, leaving room for the header and the tag. */
#define WT_QUIC_HANDSHAKE_PACKET_RESERVE 128U

/* RFC 9000 section 20.1: CRYPTO_ERROR is 0x0100 plus the TLS alert (RFC 8446 section 6), so the peer
 * can tell a refused certificate from a broken implementation. The mapping is from this library's
 * statuses to the alerts that describe them. */
static uint64_t alert_for(wt_status_t status) {
  /* Every status is listed rather than defaulted: the switch is over the library's own enum, so a
   * status added later fails the build here instead of silently becoming "internal error". The alerts
   * are RFC 8446 section 6.2's. */
  switch (status) {
    case WT_OK:
      return 0x0100U | 80U; /* internal_error: a failure path reached with success */
    case WT_ERR_INVALID_ARGUMENT:
      return 0x0100U | 47U; /* illegal_parameter */
    case WT_ERR_OUT_OF_MEMORY:
      return 0x0100U | 80U; /* internal_error */
    case WT_ERR_TIMEOUT:
      return 0x0100U | 80U; /* internal_error */
    case WT_ERR_PROTOCOL:
      return 0x0100U | 50U; /* decode_error */
    case WT_ERR_TLS:
      return 0x0100U | 40U; /* handshake_failure */
    case WT_ERR_CLOSED:
      return 0x0100U | 80U; /* internal_error */
    case WT_ERR_AGAIN:
      return 0x0100U | 80U; /* internal_error */
    case WT_ERR_TRUNCATED:
      return 0x0100U | 50U; /* decode_error */
    case WT_ERR_LIMIT:
      return 0x0100U | 80U; /* internal_error */
    case WT_ERR_OVERFLOW:
      return 0x0100U | 80U; /* internal_error */
    case WT_ERR_STATE:
      return 0x0100U | 10U; /* unexpected_message */
    case WT_ERR_TRUST:
      return 0x0100U | 42U; /* bad_certificate */
    case WT_ERR_UNSUPPORTED:
      return 0x0100U | 80U; /* internal_error */
    case WT_ERR_AUTHENTICATION:
      return 0x0100U | 51U; /* decrypt_error */
    case WT_ERR_IO:
      return 0x0100U | 80U; /* internal_error */
  }
  return 0x0100U | 80U;
}

const char *wt_quic_handshake_state_name(wt_quic_handshake_state_t state) {
  switch (state) {
    case WT_QUIC_HANDSHAKE_IDLE:
      return "idle";
    case WT_QUIC_HANDSHAKE_CLIENT_WAITING:
      return "client-waiting";
    case WT_QUIC_HANDSHAKE_SERVER_WAITING:
      return "server-waiting";
    case WT_QUIC_HANDSHAKE_CONNECTED:
      return "connected";
    case WT_QUIC_HANDSHAKE_FAILED:
      return "failed";
  }
  return "unknown";
}

static void fail(wt_quic_handshake_t *handshake, wt_status_t status, uint64_t frame_type) {
  handshake->state = WT_QUIC_HANDSHAKE_FAILED;
  handshake->failure = status;
  handshake->error_code = alert_for(status);
  /* The connection is not closed here: this runs inside its frame walk, and the connection closes when
   * the handler returns a failure. Naming the code first is what makes that close a CRYPTO_ERROR. */
  if (handshake->connection != NULL) {
    handshake->connection->close_code = handshake->error_code;
    handshake->connection->close_frame_type = frame_type;
    handshake->connection->close_code_set = 1;
  }
}

/* Install one level's two key sets from its traffic secrets. The read secret is the peer's and the
 * write secret is ours, which is the convention both TLS machines use. */
static wt_status_t install_level(wt_quic_handshake_t *handshake, wt_quic_space_t space,
                                 const uint8_t *read_secret, const uint8_t *write_secret) {
  wt_quic_packet_keys_t keys;
  wt_status_t status;

  if (handshake->connection == NULL) return WT_ERR_STATE;
  status = wt_quic_packet_keys_from_secret(read_secret, handshake->connection->config.aead, &keys);
  if (status != WT_OK) return status;
  status = wt_quic_connection_set_keys(handshake->connection, space, 1, &keys);
  wt_quic_packet_keys_clear(&keys);
  if (status != WT_OK) return status;

  status = wt_quic_packet_keys_from_secret(write_secret, handshake->connection->config.aead, &keys);
  if (status != WT_OK) return status;
  status = wt_quic_connection_set_keys(handshake->connection, space, 0, &keys);
  wt_quic_packet_keys_clear(&keys);
  return status;
}

static wt_status_t install_handshake_keys(wt_quic_handshake_t *handshake) {
  uint8_t read_secret[WT_TLS13_SECRET_LEN];
  uint8_t write_secret[WT_TLS13_SECRET_LEN];
  wt_status_t status;

  if (handshake->handshake_keys_installed) return WT_OK;
  if (handshake->is_client) {
    status = wt_tls_client_handshake_secrets(&handshake->client, read_secret, write_secret);
  } else {
    status = wt_tls_server_handshake_secrets(&handshake->server, read_secret, write_secret);
  }
  if (status != WT_OK) return status;
  /* A connection that never had Initial keys cannot have handshake keys either, and the failure would
   * otherwise show up as a packet that will not decrypt. */
  if (handshake->connection == NULL || !handshake->connection->has_keys_in[WT_QUIC_SPACE_INITIAL]) {
    return WT_ERR_STATE;
  }
  status = install_level(handshake, WT_QUIC_SPACE_HANDSHAKE, read_secret, write_secret);
  if (status != WT_OK) return status;
  handshake->handshake_keys_installed = 1;
  return WT_OK;
}

static wt_status_t install_application_keys(wt_quic_handshake_t *handshake) {
  uint8_t read_secret[WT_TLS13_SECRET_LEN];
  uint8_t write_secret[WT_TLS13_SECRET_LEN];
  wt_status_t status;

  if (handshake->application_keys_installed) return WT_OK;
  if (handshake->is_client) {
    status = wt_tls_client_application_secrets(&handshake->client, read_secret, write_secret);
  } else {
    status = wt_tls_server_application_secrets(&handshake->server, read_secret, write_secret);
  }
  if (status != WT_OK) return status;
  status = install_level(handshake, WT_QUIC_SPACE_APPLICATION, read_secret, write_secret);
  if (status != WT_OK) return status;
  handshake->application_keys_installed = 1;
  return WT_OK;
}

/* Append a message the TLS machine produced to the level it belongs to. */
static wt_status_t queue_message(wt_quic_handshake_t *handshake, wt_quic_space_t space,
                                 const uint8_t *message, size_t length) {
  wt_status_t status = wt_quic_crypto_send_append(&handshake->send[space], message, length);
  if (status == WT_ERR_LIMIT) {
    /* The flight does not fit the buffer this driver holds. That is a limit of this implementation
     * rather than of the peer, and it is reported as an internal error rather than as a peer's fault. */
    fail(handshake, WT_ERR_LIMIT, 0U);
  }
  return status;
}

/* Walk every whole handshake message the level has, in order, feeding the TLS machine one at a time. */
static wt_status_t process_messages(wt_quic_handshake_t *handshake, wt_quic_space_t space) {
  uint8_t output[WT_QUIC_HANDSHAKE_MESSAGE_MAX];

  for (;;) {
    const uint8_t *data = NULL;
    size_t available = wt_quic_crypto_recv_available(&handshake->recv[space], &data);
    size_t message_len;
    size_t output_len = 0U;
    wt_status_t status;

    if (available == 0U) return WT_OK;
    /* A partial message is not a message: QUIC splits the handshake stream wherever a packet boundary
     * falls, so both of these cases mean "wait for more". */
    message_len = wt_tls_handshake_message_len(data, available);
    if (message_len == 0U || message_len > available) return WT_OK;

    if (handshake->is_client) {
      status = wt_tls_client_receive(&handshake->client, data, message_len, output, sizeof(output),
                                     &output_len);
    } else {
      status = wt_tls_server_receive(&handshake->server, data, message_len, output, sizeof(output),
                                     &output_len);
    }
    if (status != WT_OK) {
      fail(handshake, status, WT_QUIC_FRAME_CRYPTO);
      return status;
    }
    /* The ALPN and the transport parameters are read out of the message before it is consumed: the TLS
     * machine's views point into the CRYPTO window, and consuming slides that window over the bytes
     * they point at. Copying here is what keeps them valid for the connection's lifetime. */
    {
      const uint8_t *view = NULL;
      size_t view_len = 0U;

      if (handshake->is_client) {
        view = wt_tls_client_alpn(&handshake->client, &view_len);
      } else {
        view = wt_tls_server_alpn(&handshake->server, &view_len);
      }
      /* Only the FIRST time it is reported: the TLS machine keeps the view it set when the message
       * arrived, and after a later message that pointer is into bytes the window has since slid over.
       * Copying it again would overwrite the good copy with a stale one. */
      if (handshake->alpn_len == 0U && view != NULL && view_len != 0U &&
          view_len <= sizeof(handshake->alpn)) {
        memcpy(handshake->alpn, view, view_len);
        handshake->alpn_len = view_len;
      }
      view = NULL;
      view_len = 0U;
      if (handshake->is_client) {
        view = wt_tls_client_transport_parameters(&handshake->client, &view_len);
      } else {
        view = wt_tls_server_transport_parameters(&handshake->server, &view_len);
      }
      if (handshake->peer_parameters_len == 0U && view != NULL && view_len != 0U) {
        /* A peer whose parameters do not fit is REFUSED, and this is the branch that matters: the first version
         * guarded the copy with `view_len <= sizeof(...)` and had no else, so the parameters were silently
         * dropped, `peer_parameters_len` stayed zero, `apply_peer_parameters` returned WT_OK without applying
         * anything, and the handshake completed -- with none of RFC 9000 section 7.3's connection-ID checks and
         * none of the peer's limits, which is a connection that "works" while obeying neither. RFC 9000 section
         * 7.4.1 makes an endpoint that cannot process them close with TRANSPORT_PARAMETER_ERROR, and the alert
         * mapping below turns this status into that code. */
        if (view_len > sizeof(handshake->peer_parameters)) {
          /* The code is named rather than taken from `fail`'s alert table: RFC 9000 section 7.4.1 has a
           * transport-level code for exactly this case (0x08, TRANSPORT_PARAMETER_ERROR), and reporting a
           * CRYPTO_ERROR would blame the TLS layer for a QUIC bound. */
          handshake->state = WT_QUIC_HANDSHAKE_FAILED;
          handshake->failure = WT_ERR_LIMIT;
          handshake->error_code = (uint64_t)WT_QUIC_TRANSPORT_PARAMETER_ERROR;
          if (handshake->connection != NULL) {
            handshake->connection->close_code = handshake->error_code;
            handshake->connection->close_frame_type = WT_QUIC_FRAME_CRYPTO;
            handshake->connection->close_code_set = 1;
          }
          return WT_ERR_LIMIT;
        }
        memcpy(handshake->peer_parameters, view, view_len);
        handshake->peer_parameters_len = view_len;
      }
    }

    status = wt_quic_crypto_recv_consume(&handshake->recv[space], message_len);
    if (status != WT_OK) return status;

    /* The two directions' outputs belong to different encryption levels, and getting it wrong is a
     * packet protected with keys the peer does not have yet. A client's only output is its Finished,
     * which goes under the handshake keys; a server's is the ServerHello, which is what the Initial keys
     * are for -- the rest of its flight is built below and goes under the handshake keys. */
    if (output_len != 0U) {
      wt_quic_space_t output_space =
          handshake->is_client ? WT_QUIC_SPACE_HANDSHAKE : WT_QUIC_SPACE_INITIAL;
      status = queue_message(handshake, output_space, output, output_len);
      if (status != WT_OK) return status;
    }

    if (handshake->is_client) {
      /* The ServerHello is what makes the handshake secrets available, so this is the moment the
       * Handshake level becomes readable -- including for the rest of the same datagram, which is how
       * a coalesced ServerHello and flight is read at all. */
      if (wt_tls_client_state(&handshake->client) >= WT_TLS_CLIENT_WAIT_ENCRYPTED_EXTENSIONS) {
        status = install_handshake_keys(handshake);
        if (status != WT_OK) {
          fail(handshake, status, WT_QUIC_FRAME_CRYPTO);
          return status;
        }
      }
      if (wt_tls_client_state(&handshake->client) == WT_TLS_CLIENT_CONNECTED) {
        status = install_application_keys(handshake);
        if (status != WT_OK) {
          fail(handshake, status, WT_QUIC_FRAME_CRYPTO);
          return status;
        }
        handshake->state = WT_QUIC_HANDSHAKE_CONNECTED;
      }
    } else {
      if (wt_tls_server_state(&handshake->server) >= WT_TLS_SERVER_WAIT_CLIENT_FINISHED) {
        status = install_handshake_keys(handshake);
        if (status != WT_OK) {
          fail(handshake, status, WT_QUIC_FRAME_CRYPTO);
          return status;
        }
        /* The rest of the flight is built once and sent under the handshake keys. */
      if (!handshake->server_flight_built) {
          uint8_t flight[WT_QUIC_HANDSHAKE_FLIGHT_MAX];
          size_t flight_len = 0U;
          status = wt_tls_server_flight(&handshake->server, flight, sizeof(flight), &flight_len);
          if (status != WT_OK) {
            fail(handshake, status, WT_QUIC_FRAME_CRYPTO);
            return status;
          }
          handshake->server_flight_built = 1;
          status = queue_message(handshake, WT_QUIC_SPACE_HANDSHAKE, flight, flight_len);
          if (status != WT_OK) return status;
        }
      }
      if (wt_tls_server_state(&handshake->server) == WT_TLS_SERVER_CONNECTED) {
        status = install_application_keys(handshake);
        if (status != WT_OK) {
          fail(handshake, status, WT_QUIC_FRAME_CRYPTO);
          return status;
        }
        handshake->state = WT_QUIC_HANDSHAKE_CONNECTED;
        handshake->confirmed = 1;
        handshake->handshake_done_pending = 1;
        /* RFC 9001 section 4.9.2: the Handshake keys are discarded when the handshake is confirmed,
         * which for a server is the moment it has verified the client's Finished. */
        (void)wt_quic_connection_discard_keys(handshake->connection, WT_QUIC_SPACE_HANDSHAKE);
      }
    }
  }
}

wt_status_t wt_quic_handshake_start_client(wt_quic_handshake_t *handshake,
                                           wt_quic_connection_t *connection,
                                           const wt_tls_client_config_t *config) {
  uint8_t client_hello[WT_TLS_CLIENT_HELLO_MAX];
  size_t client_hello_len = 0U;
  wt_status_t status;

  if (handshake == NULL || connection == NULL || config == NULL) return WT_ERR_INVALID_ARGUMENT;
  memset(handshake, 0, sizeof(*handshake));
  handshake->is_client = 1;
  handshake->connection = connection;
  {
    size_t i;
    for (i = 0U; i < WT_QUIC_SPACE_COUNT; i++) {
      wt_quic_crypto_send_init(&handshake->send[i]);
      wt_quic_crypto_recv_init(&handshake->recv[i]);
    }
  }

  status = wt_tls_client_begin_built(&handshake->client, config, client_hello, sizeof(client_hello),
                                     &client_hello_len);
  if (status != WT_OK) {
    handshake->failure = status;
    handshake->state = WT_QUIC_HANDSHAKE_FAILED;
    return status;
  }
  status = queue_message(handshake, WT_QUIC_SPACE_INITIAL, client_hello, client_hello_len);
  if (status != WT_OK) return status;
  handshake->live = 1U;
  handshake->state = WT_QUIC_HANDSHAKE_CLIENT_WAITING;
  return WT_OK;
}

wt_status_t wt_quic_handshake_start_server(wt_quic_handshake_t *handshake,
                                           wt_quic_connection_t *connection,
                                           const wt_tls_server_config_t *config) {
  wt_status_t status;

  if (handshake == NULL || connection == NULL || config == NULL) return WT_ERR_INVALID_ARGUMENT;
  memset(handshake, 0, sizeof(*handshake));
  handshake->is_client = 0;
  handshake->connection = connection;
  {
    size_t i;
    for (i = 0U; i < WT_QUIC_SPACE_COUNT; i++) {
      wt_quic_crypto_send_init(&handshake->send[i]);
      wt_quic_crypto_recv_init(&handshake->recv[i]);
    }
  }

  status = wt_tls_server_begin(&handshake->server, config);
  if (status != WT_OK) {
    handshake->failure = status;
    handshake->state = WT_QUIC_HANDSHAKE_FAILED;
    return status;
  }
  handshake->live = 1U;
  handshake->state = WT_QUIC_HANDSHAKE_SERVER_WAITING;
  return WT_OK;
}

wt_status_t wt_quic_handshake_on_frame(void *context, wt_quic_space_t space,
                                       const wt_quic_frame_t *frame) {
  wt_quic_handshake_t *handshake = context;
  wt_status_t status;

  if (handshake == NULL || frame == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (space >= WT_QUIC_SPACE_COUNT) return WT_ERR_INVALID_ARGUMENT;
  if (handshake->state == WT_QUIC_HANDSHAKE_FAILED) return WT_OK;

  switch (frame->kind) {
    case WT_QUIC_FRAME_KIND_CRYPTO:
      status = wt_quic_crypto_recv_insert(&handshake->recv[space], frame->as.crypto.offset,
                                          frame->as.crypto.data, frame->as.crypto.length);
      if (status == WT_ERR_LIMIT) {
        /* The peer's handshake does not fit the window. RFC 9000 section 20.1 has a code for exactly
         * this, and a peer that reads it knows its handshake was too large rather than malformed. */
        handshake->state = WT_QUIC_HANDSHAKE_FAILED;
        handshake->failure = status;
        handshake->error_code = WT_QUIC_CRYPTO_BUFFER_EXCEEDED;
        if (handshake->connection != NULL) {
          handshake->connection->close_code = handshake->error_code;
          handshake->connection->close_frame_type = WT_QUIC_FRAME_CRYPTO;
          handshake->connection->close_code_set = 1;
        }
        return status;
      }
      if (status != WT_OK) return status;
      return process_messages(handshake, space);
    case WT_QUIC_FRAME_KIND_HANDSHAKE_DONE:
      /* RFC 9001 section 4.1.2: the server's HANDSHAKE_DONE is what tells the client the handshake is
       * confirmed, which is what allows an acknowledgement delay to be subtracted from a round trip
       * sample (RFC 9002 section 5.3). */
      if (handshake->is_client && handshake->connection != NULL) {
        handshake->connection->handshake_confirmed = 1;
        handshake->confirmed = 1;
        /* Confirmed for the client by the server's HANDSHAKE_DONE, which is the same moment
         * RFC 9001 section 4.9.2 names. */
        (void)wt_quic_connection_discard_keys(handshake->connection, WT_QUIC_SPACE_HANDSHAKE);
      }
      return WT_OK;
    case WT_QUIC_FRAME_KIND_PADDING:
    case WT_QUIC_FRAME_KIND_PING:
    case WT_QUIC_FRAME_KIND_ACK:
    case WT_QUIC_FRAME_KIND_RESET_STREAM:
    case WT_QUIC_FRAME_KIND_STOP_SENDING:
    case WT_QUIC_FRAME_KIND_NEW_TOKEN:
    case WT_QUIC_FRAME_KIND_STREAM:
    case WT_QUIC_FRAME_KIND_MAX_DATA:
    case WT_QUIC_FRAME_KIND_MAX_STREAM_DATA:
    case WT_QUIC_FRAME_KIND_MAX_STREAMS:
    case WT_QUIC_FRAME_KIND_DATA_BLOCKED:
    case WT_QUIC_FRAME_KIND_STREAM_DATA_BLOCKED:
    case WT_QUIC_FRAME_KIND_STREAMS_BLOCKED:
    case WT_QUIC_FRAME_KIND_NEW_CONNECTION_ID:
    case WT_QUIC_FRAME_KIND_RETIRE_CONNECTION_ID:
    case WT_QUIC_FRAME_KIND_PATH_CHALLENGE:
    case WT_QUIC_FRAME_KIND_PATH_RESPONSE:
    case WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_TRANSPORT:
    case WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_APPLICATION:
    case WT_QUIC_FRAME_KIND_RESET_STREAM_AT:
    case WT_QUIC_FRAME_KIND_DATAGRAM:
      /* Not this layer's frame. A composition of handlers calls this one first, so answering WT_OK is
       * what lets the next one see it. */
      return WT_OK;
  }
  return WT_ERR_STATE;
}

void wt_quic_handshake_on_lost(void *context, const wt_quic_tx_frame_t *frame) {
  wt_quic_handshake_t *handshake = context;
  size_t i;

  if (handshake == NULL || frame == NULL) return;
  if (!frame->is_crypto) return;
  if (frame->space >= WT_QUIC_SPACE_COUNT) return;
  for (i = 0U; i < WT_QUIC_HANDSHAKE_RETRANSMIT_MAX; i++) {
    if (!handshake->retransmit[i].in_use) {
      handshake->retransmit[i].in_use = 1;
      handshake->retransmit[i].space = frame->space;
      handshake->retransmit[i].offset = frame->offset;
      handshake->retransmit[i].length = frame->length;
      return;
    }
  }
  /* Every slot is taken. The losses keep being reported and a later flush drains the list, so the
   * bytes are not lost -- but a list that stays full is a handshake that is not progressing, which is
   * why the size is a named bound rather than "as many as arrive". */
}

/* The room one CRYPTO frame has in a packet of this connection's size. A Retry's token is part of every Initial
 * after one (RFC 9000 section 17.2.5.3), so it comes off the room here: section 17.2.5.3 notes that including the
 * token "reduces the available space for the cryptographic handshake message, which might result in the client
 * needing to send multiple Initial packets", and a range that ignored it would be a CRYPTO frame the 1200-byte
 * padding then cannot fit (WT-166). */
static size_t crypto_range_max(const wt_quic_connection_t *connection) {
  size_t datagram = connection->config.max_datagram_size;
  size_t reserved = WT_QUIC_HANDSHAKE_PACKET_RESERVE;
  if (connection->retry_accepted != 0 && connection->retry_token_length < reserved) {
    reserved += connection->retry_token_length;
  }
  if (datagram <= reserved) return 1U;
  return datagram - reserved;
}

wt_status_t wt_quic_handshake_flush(wt_quic_handshake_t *handshake, uint64_t now) {
  size_t i;
  wt_status_t status;

  if (handshake == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (handshake->connection == NULL) return WT_ERR_STATE;
  if (handshake->state == WT_QUIC_HANDSHAKE_IDLE || handshake->state == WT_QUIC_HANDSHAKE_FAILED) {
    return WT_OK;
  }

  /* What a loss asked for first: the peer is waiting on a gap that is holding the handshake back. */
  for (i = 0U; i < WT_QUIC_HANDSHAKE_RETRANSMIT_MAX; i++) {
    const uint8_t *data = NULL;
    if (!handshake->retransmit[i].in_use) continue;
    status = wt_quic_crypto_send_retransmit(&handshake->send[handshake->retransmit[i].space],
                                            handshake->retransmit[i].offset,
                                            handshake->retransmit[i].length, &data);
    if (status != WT_OK) {
      /* The buffer no longer holds those bytes, which cannot happen while the handshake is in
       * progress: nothing is ever dropped from it. Clearing the slot is the honest answer to a request
       * this driver cannot satisfy. */
      handshake->retransmit[i].in_use = 0;
      continue;
    }
    status = wt_quic_connection_send_crypto(handshake->connection, handshake->retransmit[i].space,
                                            handshake->retransmit[i].offset, data,
                                            handshake->retransmit[i].length, now);
    if (status == WT_ERR_AGAIN || status == WT_ERR_LIMIT) return WT_OK;
    if (status != WT_OK) return status;
    handshake->retransmit[i].in_use = 0;
  }

  /* Then the messages the TLS machine produced, oldest level first: the Initial space carries what the
   * peer needs to be able to read the Handshake space at all. */
  for (i = 0U; i < WT_QUIC_SPACE_COUNT; i++) {
    wt_quic_space_t space = (wt_quic_space_t)i;
    for (;;) {
      const uint8_t *data = NULL;
      uint64_t offset = 0U;
      size_t length = 0U;

      status = wt_quic_crypto_send_next(&handshake->send[space], crypto_range_max(handshake->connection),
                                        &offset, &data, &length);
      if (status == WT_ERR_STATE) break;
      if (status != WT_OK) return status;
      status = wt_quic_connection_send_crypto(handshake->connection, space, offset, data, length, now);
      if (status == WT_ERR_AGAIN || status == WT_ERR_LIMIT) return WT_OK;
      if (status != WT_OK) return status;
      status = wt_quic_crypto_send_advance(&handshake->send[space], length);
      if (status != WT_OK) return status;
    }
  }

  /* And the server's confirmation, once, when the handshake is complete. */
  if (handshake->handshake_done_pending && handshake->connection->has_keys_out[WT_QUIC_SPACE_APPLICATION]) {
    wt_quic_frame_t frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_HANDSHAKE_DONE);
    status = wt_quic_connection_send_frame(handshake->connection, WT_QUIC_SPACE_APPLICATION, &frame,
                                           1, now);
    if (status == WT_OK) {
      handshake->handshake_done_pending = 0;
    } else if (status != WT_ERR_AGAIN && status != WT_ERR_LIMIT) {
      return status;
    }
  }
  return WT_OK;
}

int wt_quic_handshake_pending(const wt_quic_handshake_t *handshake) {
  size_t i;

  if (handshake == NULL) return 0;
  if (handshake->state == WT_QUIC_HANDSHAKE_IDLE || handshake->state == WT_QUIC_HANDSHAKE_FAILED) {
    return 0;
  }
  for (i = 0U; i < WT_QUIC_SPACE_COUNT; i++) {
    if (wt_quic_crypto_send_pending(&handshake->send[i])) return 1;
  }
  for (i = 0U; i < WT_QUIC_HANDSHAKE_RETRANSMIT_MAX; i++) {
    if (handshake->retransmit[i].in_use) return 1;
  }
  return handshake->handshake_done_pending;
}

wt_quic_handshake_state_t wt_quic_handshake_state(const wt_quic_handshake_t *handshake) {
  return handshake == NULL ? WT_QUIC_HANDSHAKE_IDLE : handshake->state;
}

int wt_quic_handshake_is_connected(const wt_quic_handshake_t *handshake) {
  return handshake != NULL && handshake->state == WT_QUIC_HANDSHAKE_CONNECTED;
}

const uint8_t *wt_quic_handshake_alpn(const wt_quic_handshake_t *handshake, size_t *out_len) {
  if (handshake == NULL || handshake->alpn_len == 0U) {
    if (out_len != NULL) *out_len = 0U;
    return NULL;
  }
  if (out_len != NULL) *out_len = handshake->alpn_len;
  return handshake->alpn;
}

const uint8_t *wt_quic_handshake_peer_transport_parameters(const wt_quic_handshake_t *handshake,
                                                           size_t *out_len) {
  if (handshake == NULL || handshake->peer_parameters_len == 0U) {
    if (out_len != NULL) *out_len = 0U;
    return NULL;
  }
  if (out_len != NULL) *out_len = handshake->peer_parameters_len;
  return handshake->peer_parameters;
}

void wt_quic_handshake_clear(wt_quic_handshake_t *handshake) {
  if (handshake == NULL) return;
  /* Both clear calls are safe on a machine that never began, which is what the marker is for, and both
   * zero the secrets they hold. */
  wt_tls_client_clear(&handshake->client);
  wt_tls_server_clear(&handshake->server);
  memset(handshake, 0, sizeof(*handshake));
}
