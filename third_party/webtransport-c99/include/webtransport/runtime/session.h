/* A packet session: a socket, a QUIC connection and a TLS handshake, driven together (Phase 9).
 *
 * Every piece of a WebTransport client or server already exists in this library and none of them knows
 * about the others: the connection needs somewhere to send, the handshake needs a connection with
 * Initial keys, the socket needs a caller to pump it. This is that caller, and it is deliberately the
 * ONLY place where the three meet -- so a test can stand up two of them over loopback, and so a caller
 * that wants to drive the layers itself still can.
 *
 * The rules it encodes are the ones that are easy to get wrong once and hard to see afterwards:
 *
 *   - THE INITIAL KEYS COME FROM THE DESTINATION CONNECTION ID, both directions, and the `from_server`
 *     flag is the OPPOSITE for this endpoint's receive direction. Getting that backwards produces a
 *     connection that encrypts and decrypts nothing, which looks like a peer that never answers.
 *
 *   - THE HANDSHAKE HANDLER IS CHAINED, not replaced: it returns WT_OK for every frame that is not its
 *     business, so the HTTP/3 layer's handler can be installed behind it. This session installs only the
 *     handshake for now, and `wt_runtime_session_set_frame_handler` is how the next layer joins it.
 *
 *   - THE PEER'S TRANSPORT PARAMETERS BECOME THE CONNECTION'S LIMITS, as soon as the handshake has them.
 *     Nothing else does it: the handshake carries the bytes, and a connection whose limits were never
 *     applied refuses its own HTTP/3 streams -- which presents as a state error from an open call rather
 *     than as a missing step, and cost this phase a debugging round.
 *
 *   - A PUMP IS BOUNDED. `wt_runtime_session_pump` reads what is there, flushes what is owed and
 *     returns; it never waits, because a tool that waited inside a library call could not honour its own
 *     `--timeout-ms` and could not be interrupted. The caller owns the clock and passes `now`.
 */

#ifndef WEBTRANSPORT_RUNTIME_SESSION_H
#define WEBTRANSPORT_RUNTIME_SESSION_H

#include <stdint.h>

#include "webtransport/quic/connection.h"
#include "webtransport/quic/handshake.h"
#include "webtransport/runtime/udp.h"
#include "webtransport/status.h"
#include "webtransport/tls/session.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct wt_runtime_session {
  wt_quic_connection_t connection;
  wt_quic_handshake_t handshake;
  /* Borrowed: the caller owns the socket and the address, because a test binds them and a tool closes
   * them, and an object that owned them would have to decide when. */
  const wt_udp_socket_t *socket;
  wt_udp_address_t peer;
  int is_client;
  int started;
  /* What the pump has seen, for a caller that logs or asserts: packets that were there to read and
   * rounds in which something was flushed. */
  unsigned packets_seen;
  unsigned flushes;
  /* Whether the peer's transport parameters have become this connection's limits. The handshake carries
   * them; a connection whose limits were never applied refuses the streams HTTP/3 must open before it can
   * send anything, and the refusal looks like a state error rather than a missing step. */
  int peer_parameters_applied;
  /* What the last flush SAID. A pump that discarded it could not tell "nothing to send" from "refused to
   * send", and this session spent three rounds unable to see the difference -- so the status is kept and
   * reported rather than swallowed. */
  wt_status_t last_flush;
  wt_status_t last_receive;
  /* Receives that failed for a reason that is NEITHER "nothing there" nor success: a packet that arrived
   * and was refused, which a pump that only counts successes cannot see. */
  unsigned receive_errors;
  wt_status_t first_receive_error;
  /* The layer behind the handshake, if one was installed: a function pointer and its context, because
   * the only thing that varies between "no next layer yet" and the HTTP/3 driver is which function. */
  wt_status_t (*next_handler)(void *context, wt_quic_space_t space, const wt_quic_frame_t *frame);
  void *next_context;
  /* The layer that owns the frames the handshake does not, told about the ones that were LOST. */
  void (*lost_handler)(void *context, const wt_quic_tx_frame_t *frame);
  void *lost_context;
  /* WT-171: whether this session keeps a spare connection ID of its own issued, and what it has done about it.
   * `spare_ids_issued` counts the spares that went out -- one at the handshake, one per retire after that -- so
   * "the peer retired one and it was replaced" is a number rather than an inference. */
  int spare_connection_id;
  unsigned spare_ids_issued;
  unsigned spare_id_refusals;
  /* How many of those refusals were the RATE LIMIT rather than the peer's own limit, so "this peer is retiring
   * IDs faster than any migration would" is a number a caller can see (WT-173). */
  unsigned spare_ids_rate_limited;
  /* The number of replacements performed, and the earliest time the next one may be. The FIRST replacement is
   * never limited: a peer that retires a spare once is following section 5.1.2's advice, and a bound that refused
   * it would break the flow this policy exists to serve. */
  unsigned spare_ids_replaced;
  uint64_t spare_id_next_allowed;
  /* The number of retires this session has already NOTICED, and whether the request they made is still
   * outstanding: 0 none, 1 waiting for the interval, 2 waiting and already counted. A retire that arrives while
   * the rate limit is in force stays PENDING rather than being dropped -- it is answered once the interval passes,
   * so a peer that retires once and is refused is not left without a spare for ever -- and the refusal is counted
   * once per REQUEST, not once per pump round (a counter that ran every round said thirty refusals for one
   * retire). */
  uint64_t spare_id_retires_seen;
  unsigned spare_id_pending;
} wt_runtime_session_t;

/* A RULE THE CALLER MUST KEEP, and the one that cost this phase several rounds: the connection-level
 * receive credit is the ENFORCEMENT of the `initial_max_data` the endpoint ADVERTISES in its transport
 * parameters, and nothing pairs the two. A connection whose flow account was never granted starts at zero,
 * so the FIRST stream frame it receives is refused as FLOW_CONTROL_ERROR (transport code 3, frame type 8)
 * and the connection closes -- which presents as a peer that says nothing, not as a missing grant. Call
 * `wt_quic_connection_set_max_data(connection, <the value you advertised>)` before any peer stream can
 * arrive; the same is true per stream through the connection's `local_max_stream_data`, and for stream
 * COUNTS through `wt_quic_connection_set_max_streams`. Pairing them automatically is a task on the tracker
 * (it needs the advertised parameters, which this driver does not see). */
/* Put the limits this endpoint ADVERTISED in its transport parameters into force.
 *
 * It exists because the two halves must agree and nothing paired them: the advertised `initial_max_data` is a
 * promise and `wt_quic_connection_set_max_data` is the enforcement, so an endpoint that advertised a limit and
 * granted nothing refused the FIRST stream frame it received as FLOW_CONTROL_ERROR and closed the connection --
 * which presents as a peer that says nothing rather than as a missing grant (WT-110's root cause, found after
 * several rounds of measurement). Calling this once, after starting a session, moves the pairing into the
 * driver instead of leaving it in every caller's memory.
 *
 * It is a separate call rather than more parameters on `start_client`/`start_server` so that a caller's
 * arguments cannot drift out of order: four more numbers on a call that already takes seven is a mistake
 * waiting for a tired afternoon. Calling it twice is not an error -- the values are monotonic limits -- and a
 * caller that advertises nothing simply does not call it (WT-113). */
wt_status_t wt_runtime_session_advertise(wt_runtime_session_t *session, uint64_t initial_max_data,
                                         uint64_t initial_max_stream_data,
                                         uint64_t initial_max_streams_bidi,
                                         uint64_t initial_max_streams_uni);

typedef wt_status_t (*wt_runtime_frame_handler_fn)(void *context, wt_quic_space_t space,
                                                   const wt_quic_frame_t *frame);

/* Start a client: the connection is initialised, attached to its socket and peer, given its Initial
 * keys in both directions, and the TLS ClientHello is built into the Initial space. The peer's address
 * must be the one the packets go to; the socket's own family decides the wire. */
wt_status_t wt_runtime_session_start_client(wt_runtime_session_t *session,
                                            const wt_udp_socket_t *socket,
                                            const wt_udp_address_t *peer,
                                            const uint8_t *initial_connection_id,
                                            size_t initial_connection_id_length,
                                            const wt_quic_connection_config_t *connection_config,
                                            const wt_tls_client_config_t *tls_config, uint64_t now);

/* Start a server. Nothing is sent until a ClientHello arrives, so this only arms the endpoint. */
wt_status_t wt_runtime_session_start_server(wt_runtime_session_t *session,
                                            const wt_udp_socket_t *socket,
                                            const wt_udp_address_t *peer,
                                            const uint8_t *initial_connection_id,
                                            size_t initial_connection_id_length,
                                            const wt_quic_connection_config_t *connection_config,
                                            const wt_tls_server_config_t *tls_config, uint64_t now);

/* Start a server that RETRIED this client (WT-168), where the two connection IDs a server answers to are no
 * longer the same one.
 *
 * `initial_connection_id` is the Destination Connection ID of the Initial being answered -- the Retry's Source
 * Connection ID, which is what the client addresses and what the Initial keys derive from (RFC 9001 section 5.2).
 * `original_destination_connection_id` is the connection ID the client's FIRST Initial carried, which the token
 * brought back and which this server must name in its `original_destination_connection_id` transport parameter
 * (RFC 9000 section 7.3) for the client to accept it. `wt_runtime_session_start_server` is the one-ID form, for a
 * server that answered the first Initial directly. */
wt_status_t wt_runtime_session_start_server_retried(
    wt_runtime_session_t *session, const wt_udp_socket_t *socket, const wt_udp_address_t *peer,
    const uint8_t *initial_connection_id, size_t initial_connection_id_length,
    const uint8_t *original_destination_connection_id, size_t original_destination_connection_id_length,
    const wt_quic_connection_config_t *connection_config, const wt_tls_server_config_t *tls_config,
    uint64_t now);

/* A LOST frame, reported to the layer that sent it.
 *
 * `wt_quic_connection_set_handlers` takes a received-frame handler AND a lost-frame one; the runtime installs
 * its own for both, and until this hook existed the lost one went to the handshake alone -- whose handler returns
 * immediately for anything that is not CRYPTO. A lost STREAM frame therefore reached nobody and was never
 * retransmitted, which is what a third-party peer showed and a relayed packet drop reproduces (WT-135). */
typedef void (*wt_runtime_lost_frame_fn)(void *context, const wt_quic_tx_frame_t *frame);

/* Install that layer. The handshake is always told first, because CRYPTO frames are its business whatever else
 * is listening. */
wt_status_t wt_runtime_session_set_lost_frame_handler(wt_runtime_session_t *session,
                                                      wt_runtime_lost_frame_fn handler, void *context);

/* Install a handler behind the handshake's, for the layer that owns frames it does not. */
wt_status_t wt_runtime_session_set_frame_handler(wt_runtime_session_t *session,
                                                 wt_runtime_frame_handler_fn handler,
                                                 void *context);

/* The shortest interval between two REPLACEMENTS of a retired spare, in the units of the clock the session's
 * caller passes (microseconds): four seconds, which is three times RFC 9002 section 6.2.1's initial probe timeout.
 * RFC 9000 section 5.1.2 makes a retire a REQUEST for another ID, and a peer that retires every ID as it arrives
 * can make this endpoint issue one per round trip for the life of the connection -- each NEW_CONNECTION_ID is a
 * frame the peer pays nothing for, which is the amplification this bound exists to refuse (WT-173). The first
 * replacement is NOT limited: a peer that retires a spare once is doing what section 5.1.2 recommends, and a
 * bound that refused it would break the very flow the policy serves. */
#define WT_RUNTIME_SPARE_ID_INTERVAL 4000000U

/* Keep ONE spare connection ID issued for the peer, and replace it when the peer retires it (WT-171).
 *
 * RFC 9000 section 5.1.2 asks an endpoint to REPLACE a connection ID the peer retires -- the retire is a request
 * for another one, not just a withdrawal -- and section 5.1.1 sizes the spare: the peer's
 * `active_connection_id_limit` COUNTS the connection ID the handshake used, so a peer at the default of two
 * allows exactly one. This is the policy that keeps that one out there: the session issues a spare as soon as it
 * can protect a 1-RTT packet and the peer's limit is known, and issues another whenever a retire takes one away.
 *
 * Opt-in, and deliberately so: a library that started sending NEW_CONNECTION_ID frames to every peer would change
 * every session's wire behaviour to serve a caller who may have its own connection-ID policy (a load balancer's
 * routing prefix, or tokens derived from a secret it holds). The bytes here are `wt_random_bytes` -- unpredictable
 * by construction, which is what section 5.1 and section 10.3.2 ask of an ID and its stateless reset token -- so a
 * caller with no policy of its own gets a correct one by calling this once, and a caller with one keeps the seam
 * `wt_runtime_session_set_frame_handler` gives it.
 *
 * Never fails because the peer allows no spare or this endpoint's table is full; those are counted in
 * `spare_id_refusals` instead, because a peer that granted `active_connection_id_limit` of one is a peer this
 * session can still talk to. WT_ERR_INVALID_ARGUMENT for a null session, and the randomness failure is returned:
 * a session that cannot get randomness cannot proceed. */
wt_status_t wt_runtime_session_keep_spare_connection_id(wt_runtime_session_t *session);

/* Read what is there, drive the handshake and flush what is owed. Never blocks. Returns WT_OK when the
 * round completed, whatever it contained. */
wt_status_t wt_runtime_session_pump(wt_runtime_session_t *session, uint64_t now);

/* Whether the handshake is DONE -- the two ends have exchanged their Finished messages and this endpoint holds
 * 1-RTT keys -- and whether it is CONFIRMED, with why it failed if it did.
 *
 * They are not the same state, and conflating them cost the interop round several measurements: a QUIC client
 * may send 1-RTT data as soon as its handshake is DONE, while CONFIRMATION is the server's HANDSHAKE_DONE and
 * matters for discarding the Handshake keys (RFC 9000 section 7). A caller that waits for confirmation before
 * speaking can stall a session that is entirely able to proceed, which is exactly what happened against a
 * third-party peer (WT-142). */
int wt_runtime_session_handshake_done(const wt_runtime_session_t *session);
int wt_runtime_session_established(const wt_runtime_session_t *session);
wt_status_t wt_runtime_session_failure(const wt_runtime_session_t *session);

/* The application keys, once the handshake has them, so a caller can protect data traffic. WT_ERR_STATE
 * before then, which is the difference between "not yet" and "never". */
int wt_runtime_session_keys_ready(const wt_runtime_session_t *session);

/* Release what the session holds and leave it ready to be STARTED again.
 *
 * THIS IS THE SHUTDOWN PATH, so what it does and does not do matters as much as the release itself:
 *
 *   - It zeroes the traffic keys and the handshake secrets (`wt_quic_connection_clear`,
 *     `wt_quic_handshake_clear`), forgets the peer, drops both handlers and marks the session not started. The
 *     first thing a key-holding structure must do when a connection ends is forget its keys, and the two clears
 *     are what do it -- the same two a connection calls when a peer closes.
 *   - It does NOT close the socket, which the caller owns and may be sharing with other connections (the header
 *     of `quic/connection.h` states the rule for the layer below), and it does NOT tell the peer anything: a
 *     caller that wants the peer told calls `wt_quic_connection_close` and pumps the flush BEFORE clearing, or
 *     the peer learns of the end by timing out -- which is the difference between a shutdown and a drop.
 *   - It is IDEMPOTENT, and safe on a session that was never started (a zeroed struct): a signal handler or a
 *     deployment script routinely runs the shutdown path twice, and a second call that freed a pointer again
 *     would turn the safety net into the crash. The tests drive it twice, on a live session, on a session that
 *     never started, and in the middle of a handshake.
 *   - The session may be STARTED AGAIN afterwards on the same struct: every start zeroes it before it configures
 *     anything, which is why a caller reusing one does not have to clear it between tries. The SOCKET is the
 *     caller's business either way -- a socket that still holds datagrams from the abandoned attempt hands them
 *     to the next session, so a caller that restarts on the same socket drains it first or accepts that. */
void wt_runtime_session_clear(wt_runtime_session_t *session);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_RUNTIME_SESSION_H */
