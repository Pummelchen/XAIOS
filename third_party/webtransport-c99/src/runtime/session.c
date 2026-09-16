/* A packet session: a socket, a QUIC connection and a TLS handshake, driven together (Phase 9). */

#include "webtransport/runtime/session.h"

#include <string.h>

#include "webtransport/crypto/crypto.h"
#include "webtransport/quic/protection.h"

/* The session's own frame handler: the handshake first, then whatever the caller installed. The order
 * matters and is the reason the handshake returns WT_OK for frames that are not its business -- a
 * handler that refused them would stop the walk before the layer behind it saw anything. */
static wt_status_t session_on_frame(void *context, wt_quic_space_t space,
                                    const wt_quic_frame_t *frame) {
  wt_runtime_session_t *session = context;
  wt_status_t status;

  status = wt_quic_handshake_on_frame(&session->handshake, space, frame);
  if (status != WT_OK) return status;
  if (session->next_handler != NULL) {
    return session->next_handler(session->next_context, space, frame);
  }
  return WT_OK;
}

/* WT-171: keep one spare connection ID issued, and replace it when the peer retires it.
 *
 * The work is done HERE rather than in `session_on_frame` for one reason: the frame handler is composed of layers
 * (the handshake, then whatever the caller installed) and a replacement is not any of their business -- it is this
 * session's own transport policy, driven by the peer's `active_connection_id_limit`. The retire still ARRIVES
 * through the handler chain, which is what the layer above needs; what this adds is that somebody answers it. A
 * retire read during the pump leaves `issued_count` one lower, and this call then sees room for exactly one spare
 * -- so the replacement is issued in the SAME round that read the retire, and no counter is duplicated to notice
 * it. That is also why there is nothing to reset: "one spare, if the peer allows one" is the whole state.
 *
 * The gate on 1-RTT keys is not decoration: a NEW_CONNECTION_ID lives in the Application space, and the peer's
 * parameters arrive one message BEFORE a client has those keys, so a session that issued the spare as soon as the
 * limit was known would ask for a packet it cannot protect and retry every round until it could. */
static wt_status_t provide_spare_connection_id(wt_runtime_session_t *session, uint64_t now) {
  wt_quic_connection_t *connection = &session->connection;
  uint8_t id[WT_QUIC_MAX_CONNECTION_ID_LENGTH];
  uint8_t token[16];
  uint64_t allowed;
  wt_status_t status;

  if (session->spare_connection_id == 0) return WT_OK;
  if (connection->local_connection_id_length == 0U) return WT_OK;
  if (wt_quic_connection_is_closed(connection) != 0) return WT_OK;
  if (!connection->peer_limits.set) return WT_OK;
  if (!wt_runtime_session_keys_ready(session)) return WT_OK;

  /* Section 5.1.1's arithmetic, which is the same one `wt_quic_connection_issue_connection_id` enforces: the
   * peer's limit counts the handshake's ID, so one spare is what the default of two allows. Being at the allowed
   * count already is the ordinary state after the first spare, and the reason this needs no flag of its own. */
  allowed = connection->peer_limits.active_connection_id_limit;
  if (allowed > 0U) allowed -= 1U;
  if ((uint64_t)connection->issued_count >= allowed) return WT_OK;

  status = wt_random_bytes(id, connection->local_connection_id_length);
  if (status != WT_OK) return status;
  status = wt_random_bytes(token, sizeof(token));
  if (status != WT_OK) return status;

  /* A peer that retires every ID this endpoint issues would otherwise get one replacement per round trip for the
   * life of the connection, so replacements are RATE LIMITED (WT-173): the first is free -- a peer that retires a
   * spare once is following section 5.1.2 -- and every one after it costs the interval. The refusal is counted
   * separately from "the peer's limit allowed none", because they are different facts about the peer. */
  if (session->spare_ids_issued > 0U) {
    uint64_t retires = wt_quic_connection_retires_received(connection);
    if (retires != session->spare_id_retires_seen) {
      session->spare_id_retires_seen = retires;
      session->spare_id_pending = 1U;
    }
    if (session->spare_id_pending == 0U) return WT_OK; /* no request outstanding: nothing to answer */
    if (session->spare_ids_replaced > 0U && now < session->spare_id_next_allowed) {
      if (session->spare_id_pending == 1U) {
        session->spare_id_refusals++;
        session->spare_ids_rate_limited++;
        session->spare_id_pending = 2U;
      }
      return WT_OK;
    }
    session->spare_id_pending = 0U;
  }

  status = wt_quic_connection_issue_connection_id(connection, id, connection->local_connection_id_length, token,
                                                  now);
  if (status == WT_OK) {
    session->spare_ids_issued++;
    if (session->spare_ids_issued > 1U) {
      session->spare_ids_replaced++;
      session->spare_id_next_allowed = now + WT_RUNTIME_SPARE_ID_INTERVAL;
    }
    return WT_OK;
  }
  /* A peer that allows no spare, a table that is full, or state that has moved on: the session is still usable,
   * so this is counted rather than returned. `provide` runs once per pump round, and the attempts stop the moment
   * one succeeds. */
  session->spare_id_refusals++;
  return WT_OK;
}

wt_status_t wt_runtime_session_keep_spare_connection_id(wt_runtime_session_t *session) {
  if (session == NULL) return WT_ERR_INVALID_ARGUMENT;
  session->spare_connection_id = 1;
  return WT_OK;
}

static void session_on_lost(void *context, const wt_quic_tx_frame_t *frame) {
  wt_runtime_session_t *session = context;

  if (session == NULL || frame == NULL) return;
  /* The handshake first: CRYPTO frames are its business whatever else is listening. */
  wt_quic_handshake_on_lost(&session->handshake, frame);
  /* And then the layer behind it -- without this, a lost STREAM frame reached nobody and was never
   * retransmitted (WT-135). */
  if (session->lost_handler != NULL) session->lost_handler(session->lost_context, frame);
}

wt_status_t wt_runtime_session_set_lost_frame_handler(wt_runtime_session_t *session,
                                                      wt_runtime_lost_frame_fn handler, void *context) {
  if (session == NULL) return WT_ERR_INVALID_ARGUMENT;
  session->lost_handler = handler;
  session->lost_context = context;
  return WT_OK;
}

static wt_status_t install_initial_keys(wt_runtime_session_t *session, const uint8_t *connection_id,
                                        size_t connection_id_length, int is_server) {
  uint8_t initial_secret[WT_SHA256_LEN];
  wt_quic_packet_keys_t keys;
  wt_status_t status;

  status = wt_quic_initial_secret(wt_quic_initial_salt_v1, sizeof(wt_quic_initial_salt_v1),
                                  connection_id, connection_id_length, initial_secret);
  if (status != WT_OK) return status;

  /* This endpoint's SEND keys are the peer's opposite: a server sends with the server keys and receives
   * with the client keys, and the flag says which of the two is being derived. */
  status = wt_quic_initial_packet_keys(initial_secret, is_server, WT_AEAD_AES_128_GCM, &keys);
  if (status != WT_OK) return status;
  status = wt_quic_connection_set_keys(&session->connection, WT_QUIC_SPACE_INITIAL, 0, &keys);
  if (status != WT_OK) {
    wt_quic_packet_keys_clear(&keys);
    return status;
  }
  status = wt_quic_initial_packet_keys(initial_secret, !is_server, WT_AEAD_AES_128_GCM, &keys);
  if (status != WT_OK) {
    wt_quic_packet_keys_clear(&keys);
    return status;
  }
  status = wt_quic_connection_set_keys(&session->connection, WT_QUIC_SPACE_INITIAL, 1, &keys);
  wt_quic_packet_keys_clear(&keys);
  return status;
}

wt_status_t wt_runtime_session_start_client(wt_runtime_session_t *session,
                                            const wt_udp_socket_t *socket,
                                            const wt_udp_address_t *peer,
                                            const uint8_t *initial_connection_id,
                                            size_t initial_connection_id_length,
                                            const wt_quic_connection_config_t *connection_config,
                                            const wt_tls_client_config_t *tls_config, uint64_t now) {
  wt_status_t status;

  (void)now;
  if (session == NULL || socket == NULL || peer == NULL || initial_connection_id == NULL ||
      connection_config == NULL || tls_config == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  memset(session, 0, sizeof(*session));
  session->socket = socket;
  session->peer = *peer;
  session->is_client = 1;

  status = wt_quic_connection_init(&session->connection, connection_config);
  if (status != WT_OK) return status;
  status = wt_quic_connection_attach(&session->connection, socket, peer);
  if (status != WT_OK) return status;
  /* What this client chose as the destination of its first Initial. Three rules need it and the client never
   * recorded it: RFC 9000 section 7.3 has the server echo it back and the client CHECK it, and RFC 9001 section
   * 5.8 computes a Retry's integrity tag over it -- so an endpoint that does not keep it can validate neither.
   * Nothing noticed because no peer in this tree's tests ever retried or echoed it (WT-166). */
  status = wt_quic_connection_set_original_destination_id(&session->connection, initial_connection_id,
                                                          initial_connection_id_length);
  if (status != WT_OK) return status;
  status = install_initial_keys(session, initial_connection_id, initial_connection_id_length, 0);
  if (status != WT_OK) return status;

  /* The handlers before the handshake starts, so a ClientHello-sized Initial packet that arrives during
   * the same round is already routed. */
  wt_quic_connection_set_handlers(&session->connection, session_on_frame, session, session_on_lost,
                                  session);
  status = wt_quic_handshake_start_client(&session->handshake, &session->connection, tls_config);
  if (status != WT_OK) {
    wt_runtime_session_clear(session);
    return status;
  }
  session->started = 1;
  return WT_OK;
}

/* The one body both server starts share. `initial_connection_id` is the Destination Connection ID of the
 * client's Initial that this server is answering -- which is what the Initial keys derive from (RFC 9001
 * section 5.2) -- and `original_destination_connection_id` is the one the client's FIRST Initial carried, which
 * is what this server has to name in its transport parameters (RFC 9000 section 7.3) and what it must answer to
 * until the client has adopted its own Source Connection ID. A server that did not retry has one ID for both and
 * calls `wt_runtime_session_start_server`; a server that DID retry has two, and calls
 * `wt_runtime_session_start_server_retried` (WT-168). */
static wt_status_t start_server_with_ids(wt_runtime_session_t *session, const wt_udp_socket_t *socket,
                                        const wt_udp_address_t *peer, const uint8_t *initial_connection_id,
                                        size_t initial_connection_id_length,
                                        const uint8_t *original_destination_connection_id,
                                        size_t original_destination_connection_id_length,
                                        const wt_quic_connection_config_t *connection_config,
                                        const wt_tls_server_config_t *tls_config) {
  wt_status_t status;

  if (session == NULL || socket == NULL || peer == NULL || initial_connection_id == NULL ||
      original_destination_connection_id == NULL || connection_config == NULL || tls_config == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  memset(session, 0, sizeof(*session));
  session->socket = socket;
  session->peer = *peer;
  session->is_client = 0;

  status = wt_quic_connection_init(&session->connection, connection_config);
  if (status != WT_OK) return status;
  status = wt_quic_connection_attach(&session->connection, socket, peer);
  if (status != WT_OK) return status;
  status = wt_quic_connection_set_original_destination_id(
      &session->connection, original_destination_connection_id, original_destination_connection_id_length);
  if (status != WT_OK) return status;
  status = install_initial_keys(session, initial_connection_id, initial_connection_id_length, 1);
  if (status != WT_OK) return status;
  wt_quic_connection_set_handlers(&session->connection, session_on_frame, session, session_on_lost,
                                  session);
  status = wt_quic_handshake_start_server(&session->handshake, &session->connection, tls_config);
  if (status != WT_OK) {
    wt_runtime_session_clear(session);
    return status;
  }
  session->started = 1;
  return WT_OK;
}

wt_status_t wt_runtime_session_start_server(wt_runtime_session_t *session,
                                            const wt_udp_socket_t *socket,
                                            const wt_udp_address_t *peer,
                                            const uint8_t *initial_connection_id,
                                            size_t initial_connection_id_length,
                                            const wt_quic_connection_config_t *connection_config,
                                            const wt_tls_server_config_t *tls_config, uint64_t now) {
  (void)now;
  /* One ID for both rules: a server that did not retry is addressed by the ID the client chose, and the Initial
   * keys come from that same ID. */
  return start_server_with_ids(session, socket, peer, initial_connection_id, initial_connection_id_length,
                              initial_connection_id, initial_connection_id_length, connection_config,
                              tls_config);
}

wt_status_t wt_runtime_session_start_server_retried(
    wt_runtime_session_t *session, const wt_udp_socket_t *socket, const wt_udp_address_t *peer,
    const uint8_t *initial_connection_id, size_t initial_connection_id_length,
    const uint8_t *original_destination_connection_id, size_t original_destination_connection_id_length,
    const wt_quic_connection_config_t *connection_config, const wt_tls_server_config_t *tls_config,
    uint64_t now) {
  (void)now;
  /* Two, because a Retry separates them: the client's answering Initial is addressed to the Retry's Source
   * Connection ID (so that is what the Initial keys derive from), while the destination it chose BEFORE the
   * Retry is what the transport parameters must name and what the client compares. Passing one value for both --
   * which is what `wt_runtime_session_start_server` does -- is how a server that retried would name the wrong
   * original destination and be refused. */
  return start_server_with_ids(session, socket, peer, initial_connection_id, initial_connection_id_length,
                              original_destination_connection_id, original_destination_connection_id_length,
                              connection_config, tls_config);
}

wt_status_t wt_runtime_session_advertise(wt_runtime_session_t *session, uint64_t initial_max_data,
                                         uint64_t initial_max_stream_data,
                                         uint64_t initial_max_streams_bidi,
                                         uint64_t initial_max_streams_uni) {
  wt_status_t status;

  if (session == NULL) return WT_ERR_INVALID_ARGUMENT;

  /* The per-stream limit is a field of the connection's configuration rather than a frame: it is read when a
   * stream is created, so it must be in place before the first peer stream arrives. The three counts and the
   * data limit are state the connection updates and can also announce. */
  session->connection.config.local_max_stream_data = initial_max_stream_data;
  status = wt_quic_connection_set_max_data(&session->connection, initial_max_data);
  if (status != WT_OK) return status;
  status = wt_quic_connection_set_max_streams(&session->connection, WT_QUIC_STREAM_BIDIRECTIONAL,
                                              initial_max_streams_bidi);
  if (status != WT_OK) return status;
  return wt_quic_connection_set_max_streams(&session->connection, WT_QUIC_STREAM_UNIDIRECTIONAL,
                                            initial_max_streams_uni);
}

wt_status_t wt_runtime_session_set_frame_handler(wt_runtime_session_t *session,
                                                 wt_runtime_frame_handler_fn handler,
                                                 void *context) {
  if (session == NULL) return WT_ERR_INVALID_ARGUMENT;
  session->next_handler = handler;
  session->next_context = context;
  return WT_OK;
}

/* The peer's transport parameters, applied once, the moment the handshake has them: they ARE this connection's
 * limits, and a connection without them refuses the unidirectional streams HTTP/3 opens before it sends anything.
 *
 * It is a function rather than a block because it has to run TWICE per pump, and the second time is the one that
 * was missing: a packet can be the same one that carries the parameters AND completes this endpoint's handshake,
 * so the Finished is flushed later in the SAME call -- and `wt_quic_connection_set_peer_parameters` is also where
 * RFC 9000 section 7.2's rule is applied, that everything after the server's Initial goes to the server's Source
 * Connection ID. Adopting it only at the top of the next pump sent the Finished to the connection ID this client
 * chose, a third-party peer ignored it as a packet for an unknown connection ("ignoring non-initial packet for
 * unknown connection 1122334455667788"), dropped every 1-RTT packet that followed because its own handshake was
 * still incomplete ("dropping short packet during handshake"), and established the connection two probe timeouts
 * later -- by which time a session had no time left to start (WT-145). */
static wt_status_t apply_peer_parameters(wt_runtime_session_t *session) {
  if (session->peer_parameters_applied != 0) return WT_OK;
  if (session->handshake.peer_parameters_len == 0U) return WT_OK;
  {
    wt_status_t status = wt_quic_connection_set_peer_parameters(&session->connection,
                                                                session->handshake.peer_parameters,
                                                                session->handshake.peer_parameters_len);
    if (status != WT_OK) return status;
  }
  session->peer_parameters_applied = 1;
  return WT_OK;
}

wt_status_t wt_runtime_session_pump(wt_runtime_session_t *session, uint64_t now) {
  wt_status_t received;
  wt_status_t status;

  if (session == NULL || session->started == 0) return WT_ERR_INVALID_ARGUMENT;

  /* One packet per call, and the caller loops: a pump that drained the socket would starve the other
   * endpoint in a two-session test, which is exactly the shape a test has. */
  status = apply_peer_parameters(session);
  if (status != WT_OK) return status;

  received = wt_quic_connection_receive(&session->connection, now);
  session->last_receive = received;
  if (received == WT_OK) {
    session->packets_seen++;
  } else if (received != WT_ERR_AGAIN) {
    if (session->receive_errors == 0U) session->first_receive_error = received;
    session->receive_errors++;
  }

  /* BEFORE the flushes, because the packet just read may have carried them (see above). */
  status = apply_peer_parameters(session);
  if (status != WT_OK) return status;

  /* The spare connection ID, or the replacement for one the retire in the packet just read took away (WT-171).
   * Here, after the parameters and before the flushes, because this is the first point in the round at which both
   * facts a spare needs -- the peer's limit and the packet that may have retired one -- are known. */
  status = provide_spare_connection_id(session, now);
  if (status != WT_OK) return status;

  /* RFC 9000 section 17.2.5.2: a Retry just read moved the destination connection ID, and the Initial keys are a
   * function of it (RFC 9001 section 5.2) -- so they are derived again HERE, before either flush. A flush before
   * this would protect the new Initial with the keys the server threw away when it sent the Retry, which the peer
   * discards exactly as it discards a client that never answered (WT-166). The connection refuses to send at
   * Initial level until this clears the flag, so the two cannot get out of order. */
  if (wt_quic_connection_retry_pending_keys(&session->connection) != 0) {
    const uint8_t *retry_source = NULL;
    size_t retry_source_length = 0U;

    status = wt_quic_connection_retry(&session->connection, NULL, NULL, &retry_source, &retry_source_length);
    if (status != WT_OK) return status;
    status = install_initial_keys(session, retry_source, retry_source_length, 0);
    if (status != WT_OK) return status;
    wt_quic_connection_retry_keys_installed(&session->connection);
  }

  status = wt_quic_handshake_flush(&session->handshake, now);
  if (status != WT_OK && status != WT_ERR_AGAIN) return status;
  if (status == WT_OK) session->flushes++;

  status = wt_quic_connection_flush(&session->connection, now);
  session->last_flush = status;
  if (status != WT_OK && status != WT_ERR_AGAIN) return status;

  status = wt_quic_connection_on_timeout(&session->connection, now);
  if (status != WT_OK && status != WT_ERR_AGAIN) return status;

  /* Nothing to read and nothing owed is the ordinary case in a pump loop, not an error: the caller
   * decides when to give up, which is what its --timeout-ms is for. */
  return WT_OK;
}

int wt_runtime_session_handshake_done(const wt_runtime_session_t *session) {
  if (session == NULL) return 0;
  /* The handshake's own CONNECTED state: both Finished messages are in, and 1-RTT keys are installed. A client
   * may send 1-RTT data from here; CONFIRMED (below) is the server's HANDSHAKE_DONE and matters for discarding
   * the Handshake keys (RFC 9000 section 7). */
  return wt_quic_handshake_is_connected(&session->handshake);
}

int wt_runtime_session_established(const wt_runtime_session_t *session) {
  if (session == NULL || session->started == 0) return 0;
  return session->handshake.confirmed;
}

wt_status_t wt_runtime_session_failure(const wt_runtime_session_t *session) {
  if (session == NULL) return WT_ERR_INVALID_ARGUMENT;
  return session->handshake.failure;
}

int wt_runtime_session_keys_ready(const wt_runtime_session_t *session) {
  if (session == NULL || session->started == 0) return 0;
  return session->handshake.application_keys_installed;
}

void wt_runtime_session_clear(wt_runtime_session_t *session) {
  if (session == NULL) return;
  wt_quic_handshake_clear(&session->handshake);
  wt_quic_connection_clear(&session->connection);
  session->started = 0;
  session->socket = NULL;
  session->next_handler = NULL;
  session->next_context = NULL;
}
