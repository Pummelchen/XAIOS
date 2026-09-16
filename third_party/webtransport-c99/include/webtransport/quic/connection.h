/*
 * The QUIC connection runtime: one connection, its timer, and its socket.
 *
 * WHAT THIS LAYER DECIDES AND WHAT IT DOES NOT. It owns everything RFC 9000 asks a connection to
 * remember about packets: the four packet number spaces, the keys of each, the received sets and the
 * acknowledgements they owe, the sent-packet list with loss detection and probe timeouts, the
 * congestion controller, and the close paths. It does not own frames. A frame it does not have a rule
 * for -- CRYPTO, STREAM, the flow control limits, NEW_CONNECTION_ID, DATAGRAM -- is handed to a
 * handler the caller installs, which is where the TLS handshake, the stream layer and the WebTransport
 * session live. That seam is deliberate: it is what lets the packet layer be tested against a real
 * socket without a handshake, and it is what keeps the peer's frame types out of this file.
 *
 * THE EVENT LOOP IS THE CALLER'S, AND `now` IS A PARAMETER. There is no thread and no hidden timer:
 * `wt_quic_connection_receive` reads one datagram, `wt_quic_connection_flush` sends what is owed,
 * `wt_quic_connection_next_timeout` says how long the caller may wait, and `wt_quic_connection_on_timeout`
 * does what the deadline was for. A connection that is driven by a scheduler, a poll loop or a test
 * with a synthetic clock is the same connection, which is what makes the timer behavior testable at
 * all -- a wall clock inside this file would make every timing test a test of the machine's load.
 *
 * THE SOCKET IS BORROWED, NOT OWNED. The connection is given an open socket and an address and never
 * closes the descriptor: a caller that owns one socket and several connections (which is what a QUIC
 * server does, and what a test with two connections does) must not have the first connection to finish
 * close it. `wt_quic_connection_clear` zeroes the keys and nothing else.
 */

#ifndef WEBTRANSPORT_QUIC_CONNECTION_H
#define WEBTRANSPORT_QUIC_CONNECTION_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/quic/close.h"
#include "webtransport/quic/datagram.h"
#include "webtransport/quic/congestion.h"
#include "webtransport/quic/error.h"
#include "webtransport/quic/frame.h"
#include "webtransport/quic/loss.h"
#include "webtransport/quic/packet.h"
#include "webtransport/quic/pn_space.h"
#include "webtransport/quic/protection.h"
#include "webtransport/quic/stream.h"
#include "webtransport/runtime/udp.h"
#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum wt_quic_role {
  WT_QUIC_ROLE_CLIENT = 0,
  WT_QUIC_ROLE_SERVER = 1
} wt_quic_role_t;

/* The longest Retry token this endpoint will carry. RFC 9000 section 17.2.5 lets a server choose the token's
 * length, and section 8.1.4 suggests it is a small integrity-protected structure (quiche's is 44 bytes), so this
 * is generous by an order of magnitude; a token beyond it is discarded rather than obeyed, because a bound this
 * endpoint does not enforce is a buffer a peer sizes. */
#define WT_QUIC_MAX_RETRY_TOKEN 256U

/* The packet number spaces of RFC 9000 section 12.3. 0-RTT and 1-RTT share the Application space, so
 * there are three and not four. */
typedef enum wt_quic_space {
  WT_QUIC_SPACE_INITIAL = 0,
  WT_QUIC_SPACE_HANDSHAKE = 1,
  WT_QUIC_SPACE_APPLICATION = 2,
  WT_QUIC_SPACE_COUNT = 3
} wt_quic_space_t;

/* How many packets can be remembered as carrying retransmittable frames. The loss list itself holds
 * WT_QUIC_SENT_PACKETS_MAX, but a packet that carries nothing worth resending (an ACK, a PING) needs
 * no descriptor, so this is the number of CRYPTO or STREAM payloads in flight and not the number of
 * packets. A connection that reaches it refuses to send rather than sending something it cannot
 * retransmit, because a payload that is silently not retransmitted is a handshake or a stream that
 * stalls with nothing naming why. */
#define WT_QUIC_CONNECTION_FRAMES_MAX 16U

/* The wire bytes of the ranges of one ACK frame. Bounded because the alternative is a buffer sized by
 * a peer's packet count; a received set with more gaps than this sends what fits and the rest is
 * acknowledged by a later frame, which RFC 9000 section 13.2.4 allows. */
#define WT_QUIC_CONNECTION_ACK_RANGES_MAX 256U

/* What the peer's transport parameters say about what it will accept and what it allows. They are the
 * other half of every limit this endpoint enforces: a sender may not open more streams than the peer's
 * `initial_max_streams`, may not send more data than its `initial_max_data`, and may not send a
 * datagram larger than its `max_datagram_frame_size`. A parameter the peer did not send has the
 * default RFC 9000 section 18.2 gives it, which for the flow control limits is zero -- a peer that
 * says nothing grants nothing -- and for max_udp_payload_size is 65527. */
typedef struct wt_quic_peer_limits {
  uint64_t max_idle_timeout;      /* microseconds; 0 when the peer did not limit it */
  uint64_t max_udp_payload_size;  /* never below WT_QUIC_MIN_MAX_UDP_PAYLOAD_SIZE */
  uint64_t initial_max_data;
  uint64_t initial_max_stream_data_bidi_local;
  uint64_t initial_max_stream_data_bidi_remote;
  uint64_t initial_max_stream_data_uni;
  uint64_t initial_max_streams_bidi;
  uint64_t initial_max_streams_uni;
  uint64_t active_connection_id_limit;
  uint64_t max_datagram_frame_size; /* 0 when the peer does not support DATAGRAM at all */
  /* Whether the peer sent the empty `reset_stream_at` parameter, which is what says it can receive a
   * RESET_STREAM_AT frame: the extension is negotiated by that flag and by nothing else, so a sender that used the
   * frame without it would be relying on an extension the peer never advertised. */
  int reset_stream_at;
  int set;                          /* whether a parameter list has been parsed at all */
} wt_quic_peer_limits_t;

/* A connection ID the PEER issued, with the stateless reset token that goes with it (RFC 9000 section
 * 19.15). Bounded by the `active_connection_id_limit` this endpoint advertised, because the peer may only
 * send as many as that and anything beyond it is the CONNECTION_ID_LIMIT_ERROR of section 5.1.1. */
typedef struct wt_quic_peer_connection_id {
  int in_use;
  uint64_t sequence;
  uint8_t id[WT_QUIC_MAX_CONNECTION_ID_LENGTH];
  size_t length;
  uint8_t reset_token[16];
} wt_quic_peer_connection_id_t;

#define WT_QUIC_PEER_CONNECTION_IDS_MAX 8U

typedef struct wt_quic_connection_config {
  wt_quic_role_t role;
  uint32_t version;
  /* The connection IDs. `local` is what this endpoint answers to and what it puts in the Source
   * Connection ID field; `peer` is what it sends to. Initial keys are bound to the *original*
   * destination connection ID, which is the caller's business and not this file's. */
  const uint8_t *local_connection_id;
  size_t local_connection_id_length;
  const uint8_t *peer_connection_id;
  size_t peer_connection_id_length;
  /* The AEAD every packet is protected with. RFC 9001 section 5.3 allows the *handshake* to negotiate
   * a different one per packet number space, which the keys carry, so this is the connection's default
   * and the one used when nothing else is set. */
  wt_aead_t aead;
  /* The two acknowledgement delays, which are different numbers and are confused easily. `max_ack_delay`
   * is the PEER's transport parameter: it is how long the peer may sit on an acknowledgement, so it is
   * what a round trip sample is allowed to subtract (RFC 9002 section 5.3). `local_max_ack_delay` is
   * this endpoint's own: how long IT may delay an acknowledgement before sending one (RFC 9000 section
   * 13.2.1), which is what arms the acknowledgement timer. */
  uint64_t max_ack_delay;
  uint64_t local_max_ack_delay;
  /* How many connection IDs THIS endpoint is willing to store from the peer, which is what it advertised
   * in its own `active_connection_id_limit`: RFC 9000 section 5.1.1 counts the handshake's ID among them,
   * and a peer that sends more is the CONNECTION_ID_LIMIT_ERROR of that section. Two -- the RFC's own
   * default -- is the smallest useful value and the one used when this is zero. */
  uint64_t local_active_connection_id_limit;
  /* The largest amount of stream data this endpoint will receive on ONE stream before raising the
   * limit: the receive-side counterpart of the peer's initial_max_stream_data_*, and zero -- which
   * grants nothing -- until a caller that knows what it can buffer sets it. */
  uint64_t local_max_stream_data;
  /* The longest this endpoint will let the connection sit idle before closing it silently (RFC 9000 section
   * 10.1), in MICROSECONDS, because it is compared against the same clock as `now`. The wire's
   * `max_idle_timeout` is in MILLISECONDS, and the conversion happens once, where the peer's parameters are
   * read (WT-145). Zero means no local limit. */
  uint64_t idle_timeout;
  /* The largest packet this path will carry. RFC 9000 section 14.1 requires every datagram to hold at
   * least WT_QUIC_MAX_PACKET, so a smaller value is refused rather than used. */
  size_t max_datagram_size;
} wt_quic_connection_config_t;

/* What a sent packet carried, so that a loss can be reported to whoever can send it again. This is
 * the caller's `tag` in the loss list's terms: the runtime keeps one per retransmittable packet and
 * hands it back when that packet is lost. `in_use` is how a slot is reused. */
typedef struct wt_quic_tx_frame {
  int in_use;
  wt_quic_space_t space;
  /* WHAT THE PACKET CARRIED, so the owner can send it again: a CRYPTO payload is bytes of the
   * handshake stream, and a STREAM payload is bytes of one stream. `stream_id` is meaningful only when
   * `is_crypto` is clear, and the tag's use is the same in both cases -- the connection hands the
   * descriptor back when the packet is declared lost, and the layer that keeps the bytes sends them
   * again. */
  int is_crypto;
  uint64_t stream_id;
  /* A CONTROL frame is the CONNECTION's own -- MAX_DATA, a RETIRE_CONNECTION_ID, HANDSHAKE_DONE -- and it has no
   * stream to name. The sentinel is what tells it apart in `on_lost`, where the two owners are told different
   * things: a CRYPTO or STREAM frame goes back to the layer that keeps its bytes, and a control frame is
   * re-sent by this layer from the table below, because the connection is what decided to send it. Stream IDs
   * are below 2^62 (RFC 9000 section 2.1), so the value cannot collide with one. `offset` is the table index for
   * such a descriptor and `length` is its wire length. */
  uint64_t offset;
  size_t length;
} wt_quic_tx_frame_t;

/* A control frame this connection sent and has not had acknowledged, kept so that a LOST packet carrying it can
 * be answered (RFC 9000 section 13.3: the frames whose retransmission still carries information are sent again
 * until acknowledged). The WIRE BYTES are kept rather than the frame, because a value that has moved on
 * (MAX_DATA's limit) must be re-sent as it was: re-deriving it would be re-sending a different frame under the
 * same obligation, and for a RETIRE_CONNECTION_ID there is nothing to re-derive from at all. */
#define WT_QUIC_CONTROL_STREAM_ID UINT64_MAX
#define WT_QUIC_CONTROL_FRAMES_MAX 8U
/* The longest control frame this table keeps. NEW_CONNECTION_ID is the largest of the fixed ones at 54 bytes; a
 * NEW_TOKEN carrying a long token is the realistic overflow, and a frame longer than this goes out with no slot
 * and is counted (`control_frames_unretained`). */
#define WT_QUIC_CONTROL_WIRE_MAX 64U

/* Path validation (RFC 9000 section 8.2, WT-172): how many PATH_CHALLENGEs are sent before the path is declared
 * unvalidated. Each carries a DIFFERENT payload, which is why the section says the payload must differ -- a
 * repeated one would be indistinguishable from the packet of an attacker replaying an old challenge. Three is the
 * shape RFC 9002 uses for a probe ("one, two, then give up"), and the wait between them is the connection's own
 * probe timeout. */
#define WT_QUIC_PATH_VALIDATION_ATTEMPTS 3U

typedef struct wt_quic_control_frame {
  int in_use;
  /* Set when a re-send of this retained frame could not go out. The obligation stands -- the slot is still
   * in_use -- but no packet is in flight that a later loss could name it by, because the descriptor is freed
   * with the failed send. `wt_quic_connection_flush` re-drives every flagged slot. */
  int resend_pending;
  wt_quic_space_t space;
  uint8_t wire[WT_QUIC_CONTROL_WIRE_MAX];
  size_t wire_length;
} wt_quic_control_frame_t;

/* A frame this layer does not act on. The return value stops the walk of that packet: WT_OK continues,
 * anything else ends it and is returned by the receive call, which is how a handler reports a protocol
 * error. The frame is reused by the decoder between calls, so a handler that keeps one must copy it. */
typedef wt_status_t (*wt_quic_frame_handler_fn)(void *context, wt_quic_space_t space,
                                                const wt_quic_frame_t *frame);

/* A packet that was declared lost, and what it carried. Only packets with a descriptor are reported:
 * an acknowledgement has nothing to send again. */
typedef void (*wt_quic_frame_lost_fn)(void *context, const wt_quic_tx_frame_t *frame);

/* How many connection IDs this endpoint may have outstanding, beyond the one the handshake used: the
 * peer's `active_connection_id_limit`, less the initial one, because RFC 9000 section 5.1.1 counts that
 * ID among what the peer will store. */
#define WT_QUIC_CONNECTION_IDS_MAX 8U

typedef struct wt_quic_issued_connection_id {
  int in_use;
  uint64_t sequence;
  uint8_t id[WT_QUIC_MAX_CONNECTION_ID_LENGTH];
  size_t length;
  uint8_t reset_token[16];
} wt_quic_issued_connection_id_t;

typedef struct wt_quic_connection {
  wt_quic_connection_config_t config;

  wt_udp_socket_t socket;
  wt_udp_address_t peer;
  int has_peer;

  /* The connection IDs, copied out of the configuration so that the caller's buffers may go away. */
  uint8_t local_connection_id[WT_QUIC_MAX_CONNECTION_ID_LENGTH];
  size_t local_connection_id_length;
  uint8_t peer_connection_id[WT_QUIC_MAX_CONNECTION_ID_LENGTH];
  size_t peer_connection_id_length;
  /* The value the CLIENT put in the Destination Connection ID of its first Initial, which only a server has.
   * A client chooses it arbitrarily (RFC 9000 section 7.2), so a server cannot know it from its configuration --
   * and until it is accepted, a third-party client's first packet looks like a packet for another connection.
   * It is also what an Initial packet's keys are derived from (RFC 9001 section 5.2), which is why the runtime
   * learns it before the connection is armed. Accepted until the handshake is confirmed, by which time the
   * client has the server's own Source Connection ID and stops using this one. */
  uint8_t original_destination_id[WT_QUIC_MAX_CONNECTION_ID_LENGTH];
  size_t original_destination_id_length;
  /* The Source Connection ID of the first authenticated long-header (Initial or Handshake) packet this
   * endpoint received from the peer. RFC 9000 section 7.3 requires the peer's `initial_source_connection_id`
   * transport parameter to match it, so it is recorded here from the packet itself rather than taken from the
   * parameter it is supposed to validate. `..._set` is 0 for a connection that was never handed a real packet
   * (the synthetic objects tests and some callers build), where there is nothing to compare. */
  uint8_t peer_source_connection_id[WT_QUIC_MAX_CONNECTION_ID_LENGTH];
  size_t peer_source_connection_id_length;
  int peer_source_connection_id_set;

  /* One key set per space and direction. A direction that has not been installed -- the Handshake
   * keys before the handshake produces them -- means a packet for that space cannot be read or sent,
   * which is reported rather than guessed. */
  wt_quic_packet_keys_t keys_in[WT_QUIC_SPACE_COUNT];
  wt_quic_packet_keys_t keys_out[WT_QUIC_SPACE_COUNT];
  int has_keys_in[WT_QUIC_SPACE_COUNT];
  int has_keys_out[WT_QUIC_SPACE_COUNT];

  wt_quic_pn_space_t spaces[WT_QUIC_SPACE_COUNT];
  wt_quic_loss_t loss;
  wt_quic_congestion_t congestion;
  wt_quic_close_state_t close;
  /* The peer's limits, parsed from the transport parameters its handshake carried. */
  wt_quic_peer_limits_t peer_limits;
  /* The connection-level limit this endpoint grants the peer, and whether it has been seeded. */
  uint64_t local_max_data;
  int local_max_data_set;
  /* The connection IDs this endpoint has issued, bounded: a NEW_CONNECTION_ID is peer-visible state and
   * an endpoint that issued them without a bound would be growing on its own instructions. */
  wt_quic_issued_connection_id_t issued_ids[WT_QUIC_CONNECTION_IDS_MAX];
  size_t issued_count;
  /* The sequence number the next issued ID will carry. RFC 9000 section 5.1.1 gives the connection ID the
   * handshake used sequence 0, so the first ID a peer is TOLD about is sequence 1: numbering the spares
   * from zero would announce a second ID under a sequence the handshake's ID already owns, and a
   * RETIRE_CONNECTION_ID naming that sequence would be ambiguous. */
  uint64_t next_issued_sequence;
  /* And the ones the peer has issued to this endpoint. */
  wt_quic_peer_connection_id_t peer_ids[WT_QUIC_PEER_CONNECTION_IDS_MAX];
  size_t peer_id_count;
  /* The sequence of the peer ID this endpoint is sending TO, when it is one the peer issued rather than the
   * handshake's or a Retry's -- those have no sequence. A client that switches IDs (section 5.1.2: "An endpoint
   * can change the connection ID it uses for a peer to another available one at any time") has to know which one
   * it is abandoning, because abandoning it means retiring it, and `peer_ids_retired` counts those for the
   * diagnostics a connection-ID bug is invisible without. */
  uint64_t current_peer_sequence;
  int current_peer_sequence_set;
  uint64_t peer_ids_retired;
  /* How many RETIRE_CONNECTION_ID frames this endpoint has RECEIVED, which is not the same number: `issued_count`
   * falls by one for each, but a session that answers a retire with a replacement needs to know that a NEW request
   * arrived rather than that the state is still the one it already answered (WT-173). Counted here because the
   * connection is what receives them. */
  uint64_t retires_received;
  /* Set while a NEW_CONNECTION_ID is being handled whose retire_prior_to retired the ID this endpoint was
   * using: the replacement arrives in that same frame, so it is adopted once it has been stored. */
  int retire_current_after_store;
  /* The streams this connection has, bounded by the table. */
  wt_quic_stream_table_t streams;
  /* The CONNECTION-level flow control, both directions: what this endpoint has granted and received,
   * and what the peer granted. The per-stream limits live on the streams; these are the sum the RFC
   * checks first (RFC 9000 section 4.1). */
  wt_quic_flow_t flow;
  uint64_t local_max_streams[2]; /* indexed by wt_quic_stream_direction_t */
  int local_max_streams_set[2];
  /* The datagrams that have arrived and not been read, bounded and with the newest discarded when it
   * is full (RFC 9221's frames are unreliable, so dropping one is not an error). */
  wt_quic_datagram_queue_t datagrams;

  /* PATH VALIDATION of the path this connection is on (RFC 9000 section 8.2, and section 10.1.1's liveness test,
   * WT-172). The connection drives it itself because every part of it is a protocol rule rather than a policy: a
   * challenge the peer must echo, a payload that must be NEW on every attempt, a timer, and a bound after which
   * the path is declared unvalidated. Only the DECISION to validate -- and what to do about a failure -- belongs
   * to the caller, which is why there is an entry point and not a caller-supplied frame. */
  int path_validating;
  int path_challenge_pending;
  uint8_t path_challenge[WT_QUIC_PATH_CHALLENGE_LENGTH];
  unsigned path_validation_attempts;
  uint64_t path_validation_deadline;
  int path_validated;
  uint64_t path_challenges_sent;
  uint64_t path_responses_sent;
  uint64_t path_responses_matched;
  uint64_t path_validation_failures;

  wt_quic_tx_frame_t frames[WT_QUIC_CONNECTION_FRAMES_MAX];
  /* The connection's own unacknowledged control frames, re-sent when the packet carrying one is lost. */
  wt_quic_control_frame_t control_frames[WT_QUIC_CONTROL_FRAMES_MAX];
  /* Control frames sent WITHOUT a slot, because the table was full: a bound this endpoint enforces rather than
   * a table it grows, counted so that "the retransmission did not happen" is visible. */
  uint64_t control_frames_unretained;
  /* Retained control frames whose re-send could not go out (congestion, a full sent list or descriptor table,
   * the path's datagram limit, an I/O error). They are still owed and `flush` re-drives them; counted so that
   * "the retransmission has not happened YET" is visible rather than silent. */
  uint64_t control_frames_resend_deferred;

  wt_quic_frame_handler_fn handler;
  void *handler_context;
  /* Set by a frame handler that is about to refuse a frame, so that the CONNECTION_CLOSE the connection
   * then sends names the handler's error code rather than a generic one. It matters most for the TLS
   * handshake: RFC 9000 section 20.1 puts a failed handshake in CRYPTO_ERROR with the alert in its low
   * byte, and a peer that reads INTERNAL_ERROR where a CRYPTO_ERROR belongs cannot tell a refused
   * certificate from a broken implementation. The handler sets `close_code` (and, if it knows it, the
   * frame type) before returning a failure; the connection clears the hint after using it. */
  uint64_t close_code;
  uint64_t close_frame_type;
  int close_code_set;
  /* Whether that code is an APPLICATION error code rather than a transport one, which decides the kind of
   * CONNECTION_CLOSE the peer is sent. RFC 9114 section 8 carries every HTTP/3 error in the application form
   * (type 0x1d) with the HTTP/3 code, so a layer above whose refusal IS an HTTP/3 error says so here -- a handler
   * that only returns a status would otherwise close the TRANSPORT with INTERNAL_ERROR, which names a different
   * rule in a different frame (WT-158). */
  int close_code_application;
  /* Why THIS endpoint closed, as the status of the handler that refused the frame. It is kept after the close
   * because `close_code` above is a HINT that is cleared once it has been used, so a caller reading it to ask
   * "what did we actually send" reads nothing -- which is how a tool reported a successful session after the
   * connection had been closed with INTERNAL_ERROR (WT-144). */
  wt_status_t close_cause;
  /* The frame whose delivery produced `close_cause`, by wire type: "a handler returned TRUNCATED" names no frame,
   * and which frame it was is the whole question a caller has left (WT-154). */
  uint64_t close_cause_frame;
  wt_quic_frame_lost_fn lost_handler;
  void *lost_context;

  /* When the last packet arrived or was sent, for the idle timeout, and when the packet that was
   * acknowledged most recently arrived in each space, which is the delay an acknowledgement reports. */
  uint64_t last_activity;
  uint64_t received_at[WT_QUIC_SPACE_COUNT];

  uint64_t packets_sent;
  uint64_t packets_received;
  uint64_t bytes_sent;
  uint64_t bytes_received;
  /* Every frame the walk visited, how many of them were STREAM frames, and how many reached the caller's
   * handler. They are diagnostics rather than protocol state, and they exist because a session whose
   * packets arrive and whose handler is never called has exactly one question to ask -- did the walk see
   * the frame? -- and no way to ask it from outside. */
  uint64_t frames_walked;
  uint64_t stream_frames_seen;
  uint64_t frames_delivered;
  /* Whether the handshake is confirmed, which RFC 9002 section 5.3 requires before an acknowledgement
   * delay is subtracted from a round trip sample. */
  int handshake_confirmed;
  /* Packets DECLARED lost, by packet-number space, and how many of those could not name a retransmission
   * descriptor. Two counters, because "the loss was never declared" and "the loss had nothing to name" are the
   * two ways a lost frame goes unreported -- and reading the code had already failed to tell them apart (WT-135). */
  uint64_t packets_declared_lost[WT_QUIC_SPACE_COUNT];
  uint64_t lost_without_descriptor;
  /* Probe timeouts that fired, by space, and how many of them had an outstanding frame to report. A probe is not
   * a loss, so the counters above cannot say whether the timer ran at all -- and "no probe" and "probe with
   * nothing to report" are different defects (WT-135). */
  uint64_t probes_sent[WT_QUIC_SPACE_COUNT];
  uint64_t probes_with_data;
  /* Packets SENT, by space. "Did we send a Handshake-level packet at all" is the difference between a client that
   * never finished its handshake and one whose Finished the peer cannot read, and the peer's log looks identical
   * either way (WT-135). */
  uint64_t packets_sent_by_space[WT_QUIC_SPACE_COUNT];
  /* ACK frames SENT, by space, and the largest packet number each named. "Is an acknowledgement going out, and
   * does it name a packet the peer actually sent" is what the peer's "Scheduled CRYPTO data for retransmission"
   * is asking from its side (WT-135). */
  uint64_t acks_sent[WT_QUIC_SPACE_COUNT];
  uint64_t ack_largest[WT_QUIC_SPACE_COUNT];
  /* Packets the PEER acknowledged, by space, counted where the sent list is walked and a packet is found to be
   * covered by an acknowledgement. "Did the peer read what we send, or is everything we send still owed?" is the
   * one question the sent/lost/probe counters cannot answer between them: a space with packets sent, nothing
   * declared lost, and nothing acknowledged is a peer that is not reading this endpoint at all, and that is a
   * different defect from a peer that reads and does not answer (WT-145). */
  uint64_t packets_acked[WT_QUIC_SPACE_COUNT];

  /* The Retry this client accepted, if any (RFC 9000 section 17.2.5). A Retry is a whole address-validation
   * exchange in three fields: the token every later Initial must carry, the server's Source Connection ID, which
   * replaces the destination of every packet this endpoint sends, and the fact that it happened at all -- which
   * the transport parameters are then checked against, because the section makes a missing or mismatched
   * `retry_source_connection_id` a connection error and a present one without a Retry an error too.
   *
   * `retry_pending_keys` is the one piece the connection cannot do itself: the Initial keys are derived from the
   * DESTINATION connection ID, so the endpoint that owns the keys (the runtime session) has to derive them again
   * from the new one before anything else goes out. Until it does, this flag says so. */
  uint8_t retry_token[WT_QUIC_MAX_RETRY_TOKEN];
  size_t retry_token_length;
  uint8_t retry_source_connection_id[WT_QUIC_MAX_CONNECTION_ID_LENGTH];
  size_t retry_source_connection_id_length;
  int retry_accepted;
  int retry_pending_keys;
  /* Whether a packet from the server has been RECEIVED AND PROCESSED, which section 17.2.5.2 makes the moment every
   * later Retry must be discarded. */
  int server_packet_received;
  /* Packets discarded because they were Retries this endpoint must ignore: a second one, one with a bad integrity
   * tag, one with no token, one that names this endpoint's own destination ID, one that arrived after the server
   * had already spoken, and every Retry a server receives (which MUST discard them). Counted separately from
   * `packets_discarded` because "the peer retried us and we could not answer" is a different diagnosis from "a
   * packet arrived for another connection" (WT-166). */
  uint64_t retries_discarded;
  uint64_t retry_accepted_count;

  /* The 1-RTT key update lifecycle (RFC 9001 section 6). Only the Application space has one: the Initial and
   * Handshake keys come from the handshake and are discarded rather than updated, so everything here is about
   * the keys a WebTransport session actually runs on.
   *
   * `key_phase` and `key_phase_in` are the two directions' phase bits, which are NOT the same value: section
   * 6.1 makes the initiator update its receive keys too, but a peer that has not yet responded still reads
   * this endpoint's packets with the phase it negotiated. The next phase's keys are derived AHEAD of time
   * (section 6.3) so that a packet which starts an update can be read where it arrives, and the phase being
   * retired is retained for packets the network reordered (sections 6.1 and 6.5).
   *
   * `key_phase_first_pn` is the lowest packet number sent in the current phase, which section 6.1 makes the
   * test for a SECOND update: it is allowed only once an acknowledgement has reached that number.
   * `key_phase_in_first_pn` is the first packet number RECEIVED in the current incoming phase, and it is what
   * tells a reordered packet from one that starts the next phase -- those two carry the SAME phase bit
   * (section 6.5), so the packet number is the only thing that can decide. */
  int key_phase;
  int key_phase_in;
  wt_quic_packet_keys_t next_keys_in;
  int next_keys_in_ready;
  wt_quic_packet_keys_t next_keys_out;
  int next_keys_out_ready;
  wt_quic_packet_keys_t previous_keys_in;
  int previous_keys_in_ready;
  uint64_t key_phase_first_pn;
  int key_phase_first_pn_set;
  uint64_t key_phase_in_first_pn;
  int key_phase_in_first_pn_set;
  int key_update_awaiting_confirmation;
  /* Set when this endpoint has responded to the peer's update but has not yet sent anything in the new phase.
   * A second update arriving then is section 6.2's consecutive-update error. */
  int key_update_response_pending;
  /* Diagnostics rather than protocol state: how many updates this endpoint initiated, how many the peer
   * started, and how many were refused. A run whose keys never moved looks exactly like a run whose sessions
   * were short without them. */
  uint64_t key_updates_initiated;
  uint64_t key_updates_responded;
  uint64_t key_update_errors;

  /* RFC 9001 section 6.6's usage limits, which are what a key update exists to stay inside. `aead_encrypted`
   * counts the packets protected with the CURRENT key set of each space -- section 6.6: "Endpoints MUST count the
   * number of encrypted packets for each set of keys" -- and `aead_failed` counts the received packets that
   * failed authentication over the LIFETIME of the connection and across ALL keys, because that is the number the
   * integrity limit bounds: an attacker's forgery attempts, not a per-key quantity.
   *
   * The limits are derived from the suite in `wt_quic_connection_init` (AES-GCM and ChaCha20-Poly1305 have very
   * different ones) and are fields rather than constants so that a caller which bounds its packet sizes can use
   * the higher limits appendix B allows -- and so that a test can drive the thresholds down far enough to reach
   * them, which no test could do with 2^23 packets. */
  uint64_t aead_encrypted[WT_QUIC_SPACE_COUNT];
  uint64_t aead_failed;
  uint64_t aead_confidentiality_limit;
  uint64_t aead_integrity_limit;

  /* Whether a CONNECTION_CLOSE frame has been sent, so that closing twice does not send two. A close
   * that is silent -- the idle timeout, RFC 9000 section 10.1 -- sets this without sending, which is
   * how "do not send" and "have not sent yet" are told apart. */
  int close_sent;

  /* Whether a CONNECTION_CLOSE FRAME actually went to the peer, which `close_sent` above does not say: the idle
   * timeout closes silently (RFC 9000 section 10.1) and sets `close_sent` too, because it means "send nothing
   * further" rather than "one was sent". The difference is the whole question a tool asks -- did the peer get
   * told the connection is over, or did this endpoint simply give up? -- and answering it from `close` alone is
   * how a silent idle timeout would read as a close this endpoint announced (WT-144, WT-145). */
  int close_frame_sent;

  /* The close the peer sent. It is separate from `close` above, which is this endpoint's own intent:
   * the peer's close ends the connection without this endpoint sending anything, and a caller that
   * wanted to know why needs the peer's code rather than its own. The reason phrase is copied, because
   * the frame's bytes are the decrypted packet buffer and do not outlive the datagram. */
  int peer_closed;
  wt_quic_close_kind_t peer_close_kind;
  uint64_t peer_error_code;
  uint64_t peer_frame_type;
  uint8_t peer_reason[64];
  size_t peer_reason_length;

  /* Packets dropped before they were read: a destination connection ID that is not this endpoint's,
   * or a failure that RFC 9001 section 5.3 says to discard for rather than to act on. */
  uint64_t packets_discarded;
} wt_quic_connection_t;

/* Set the connection up. The configuration is copied; the connection IDs it points at are copied too,
 * so a caller may let its own buffer go. Refuses a null connection or configuration, a connection ID
 * longer than twenty bytes, a datagram size below WT_QUIC_MAX_PACKET, and an AEAD of none. */
wt_status_t wt_quic_connection_init(wt_quic_connection_t *connection,
                                    const wt_quic_connection_config_t *config);

/* Borrow `socket` and send to `peer`. A null `peer` is allowed only for a server that learns its
 * peer's address from the first packet, which is what RFC 9000 section 7.2's server does. */
wt_status_t wt_quic_connection_attach(wt_quic_connection_t *connection,
                                      const wt_udp_socket_t *socket,
                                      const wt_udp_address_t *peer);

/* Install one direction's keys for a space. The keys are copied and zeroed by
 * `wt_quic_connection_clear`. */
wt_status_t wt_quic_connection_set_keys(wt_quic_connection_t *connection, wt_quic_space_t space,
                                        int inbound, const wt_quic_packet_keys_t *keys);

/* Parse the peer's transport parameters, which the TLS handshake carried, and keep the limits they
 * state. The idle timeout this connection uses becomes the smaller of its own and the peer's, because
 * RFC 9000 section 10.1 makes the effective idle timeout the minimum of the two -- a connection that
 * enforced only its own would stay open after the peer had forgotten it, and one that enforced only the
 * peer's would outlive its own configuration.
 *
 * WT_ERR_PROTOCOL when the list breaks RFC 9000 section 18.2's rules (with the offender available from
 * the codec), WT_ERR_TRUNCATED when a parameter's length runs past the end of the extension. */
wt_status_t wt_quic_connection_set_peer_parameters(wt_quic_connection_t *connection,
                                                   const uint8_t *data, size_t length);

/* The peer's limits, and whether any have been parsed. A caller that sends streams or datagrams reads
 * them: `set` is 0 before the handshake has produced them, and a limit the peer did not send is zero,
 * which is the RFC's default and means "none granted". */
const wt_quic_peer_limits_t *wt_quic_connection_peer_limits(const wt_quic_connection_t *connection);

/* Send one DATAGRAM frame (RFC 9221). The payload is bounded by BOTH the peer's
 * `max_datagram_frame_size` -- zero means it does not accept datagrams at all, which is
 * WT_ERR_UNSUPPORTED rather than a limit -- and what the path will carry, and the smaller of the two is
 * what is enforced. A datagram is not retransmitted and carries no retransmission descriptor: that is
 * what makes it unreliable, and a caller that needs the bytes to arrive uses a stream.
 *
 * WT_ERR_LIMIT when the payload is larger than either bound, WT_ERR_STATE before the peer's parameters
 * have been parsed (nothing is known about what it accepts), WT_ERR_AGAIN when the congestion window has
 * no room. */
wt_status_t wt_quic_connection_send_datagram(wt_quic_connection_t *connection, const uint8_t *data,
                                             size_t length, uint64_t now);

/* Open a stream this endpoint initiates, and report its number.
 *
 * The number is derived from the counts the table keeps -- a client's bidirectional streams are 0, 4, 8
 * and so on, its unidirectional ones 2, 6, 10 (RFC 9000 section 2.1) -- so a number is never reused and
 * never invented by the caller. The new stream starts with the flow control this endpoint's
 * configuration grants: its own `local_max_stream_data` for receiving and the peer's
 * `initial_max_stream_data_*` for sending, which is where the two directions' different limits come
 * from.
 *
 * WT_ERR_STATE before the peer's transport parameters have been parsed (nothing is known about what it
 * will accept), WT_ERR_LIMIT when the peer's `initial_max_streams_*` does not allow one more, and
 * WT_ERR_LIMIT when the table is full -- the caller tells those apart by reading the counts. */
wt_status_t wt_quic_connection_open_stream(wt_quic_connection_t *connection, int bidirectional,
                                           uint64_t *out_stream_id);

/* The connection's streams, and the table's own answers. */
wt_quic_stream_table_t *wt_quic_connection_streams(wt_quic_connection_t *connection);
wt_quic_stream_t *wt_quic_connection_stream(wt_quic_connection_t *connection, uint64_t stream_id);

/* Cancel a stream this endpoint is sending on: RFC 9000 section 19.4's RESET_STREAM ends the send half
 * with an application error code and the final size the peer needs to tell a truncated stream from a
 * complete one. The stream's state moves to Reset Sent, which is what stops anything further being sent
 * on it.
 *
 * WT_ERR_STATE before the peer's parameters are known or for a stream that is not this endpoint's to send
 * on -- a peer's unidirectional stream, or a number that was never opened -- WT_ERR_STATE for a send half
 * that has already finished, and WT_ERR_AGAIN when the congestion window has no room. */
wt_status_t wt_quic_connection_reset_stream(wt_quic_connection_t *connection, uint64_t stream_id,
                                            uint64_t error_code, uint64_t now);

/* Ask the peer to stop sending on a stream: RFC 9000 section 19.5's STOP_SENDING, with the application
 * error code the peer will see in the RESET_STREAM it is expected to answer with (section 3.5).
 *
 * It is the other half of cancellation: a RESET_STREAM cancels what THIS endpoint is sending, and a
 * STOP_SENDING asks the peer to stop what it is sending. The stream must exist and this endpoint must be
 * receiving on it, and one may only be sent once -- a second is the STREAM_STATE_ERROR of section 19.5
 * rather than a duplicate to be ignored. */
wt_status_t wt_quic_connection_stop_sending(wt_quic_connection_t *connection, uint64_t stream_id,
                                            uint64_t error_code, uint64_t now);

/* Send one STREAM frame (RFC 9000 section 19.8) carrying `length` bytes of `stream_id` at `offset`,
 * with FIN when this is the end of the stream.
 *
 * WHAT THIS IS AND IS NOT. It is the wire half of sending on a stream: it checks that the stream is one
 * this endpoint may open at all against the peer's `initial_max_streams_bidi`/`_uni`, encodes the frame
 * and sends it. It is NOT the stream layer: nothing here remembers the bytes, so a STREAM frame is not
 * retransmitted (the caller that keeps the data must send it again), and nothing counts the flow control
 * credit spent -- `wt_quic_connection_peer_limits` is what a stream layer reads to do that. It exists
 * because the send path and the wire format are worth having and testing on their own, and because the
 * stream layer's first part is exactly this plus the state that remembers.
 *
 * WT_ERR_LIMIT when the stream number is beyond what the peer granted, WT_ERR_STATE before its parameters
 * have been parsed, WT_ERR_INVALID_ARGUMENT for a null payload with a length, WT_ERR_AGAIN when the
 * congestion window has no room. */
/* Reset a stream while committing to deliver its first `reliable_size` bytes (the reliable-stream-reset
 * extension). WT_ERR_STATE when the peer did not advertise the extension -- the frame may not be sent to a peer
 * that cannot read it -- or when the stream cannot be reset by this endpoint; WT_ERR_INVALID_ARGUMENT when
 * `reliable_size` is past the end of the stream, which the receiver would have to reject. */
wt_status_t wt_quic_connection_reset_stream_at(wt_quic_connection_t *connection, uint64_t stream_id,
                                               uint64_t error_code, uint64_t reliable_size, uint64_t now);

wt_status_t wt_quic_connection_send_stream(wt_quic_connection_t *connection, uint64_t stream_id,
                                           uint64_t offset, const uint8_t *data, size_t length,
                                           int fin, uint64_t now);

/* Issue a connection ID this endpoint is willing to answer to, and tell the peer with a NEW_CONNECTION_ID
 * (RFC 9000 section 19.15). `reset_token` is the stateless reset token that goes with it: it must be
 * unguessable and it is the caller's to derive from a secret this layer does not hold (RFC 9000 section
 * 10.3), so it is taken rather than invented.
 *
 * Refuses a connection ID of a length other than this endpoint's own, because a short header does not
 * carry that length and an ID of another length could never be received here; a connection ID longer than
 * twenty bytes or shorter than one (section 17.2); a sequence number
 * already used -- RFC 9000 section 19.15 makes a repeat a PROTOCOL_VIOLATION, and this layer reports it as
 * a caller error before anything is sent -- a null reset token, and one more ID than the peer's
 * `active_connection_id_limit` allows, because a peer that cannot store it is a peer that will close the
 * connection. WT_ERR_LIMIT when this endpoint's own bounded table of issued IDs is full. */
wt_status_t wt_quic_connection_issue_connection_id(wt_quic_connection_t *connection,
                                                   const uint8_t *id, size_t length,
                                                   const uint8_t reset_token[16], uint64_t now);

/* The connection ID issued with this sequence number, or NULL. */
const wt_quic_issued_connection_id_t *wt_quic_connection_issued_id(
    const wt_quic_connection_t *connection, uint64_t sequence);

/* How many bytes this endpoint has SENT on a stream: the stream's send offset, which is what a reliable reset's
 * Reliable Size is bounded by.
 *
 * Draft-ietf-quic-reliable-stream-reset makes a Reliable Size larger than the Final Size a FRAME_ENCODING_ERROR at
 * the receiver -- and the final size of a stream this endpoint resets is the bytes it sent -- so a caller that
 * wants to commit to a prefix (which is what draft-ietf-webtrans-http3-16 section 4.4 requires when a WebTransport
 * stream is reset) has to know how much of it went out. The connection knows; this is how it says so.
 *
 * WT_ERR_STATE when the stream is not in this connection's table, which is not an error about the caller's number
 * but about a stream that was never opened or received here. */
wt_status_t wt_quic_connection_stream_send_offset(const wt_quic_connection_t *connection,
                                                  uint64_t stream_id, uint64_t *out_offset);

/* Send one MAX_DATA frame (RFC 9000 section 19.9): the connection-level flow control limit this
 * endpoint grants the peer, counted in bytes of stream data received in total.
 *
 * This is the limit this endpoint ADVERTISES, which is the other direction from `peer_limits`: what the
 * peer granted this endpoint is parsed from its transport parameters, and what this endpoint grants the
 * peer needs to be raised as the application reads. RFC 9000 section 4.1 makes a limit that only ever
 * decreases a protocol error, so a caller must not lower one; this function refuses a limit below the
 * last one it sent for exactly that reason, and the caller that owns the receive accounting is the one
 * that knows when there is more room.
 *
 * The initial value is the one this endpoint sent in its own `initial_max_data` transport parameter,
 * which this layer does not send, so `wt_quic_connection_set_max_data` seeds it: a caller that parses its
 * own parameters (or simply knows what it advertised) sets it there and this function then only ever
 * raises it. WT_ERR_STATE before that seed, WT_ERR_LIMIT for a limit that does not advance. */
wt_status_t wt_quic_connection_set_max_data(wt_quic_connection_t *connection, uint64_t maximum);
wt_status_t wt_quic_connection_send_max_data(wt_quic_connection_t *connection, uint64_t maximum,
                                             uint64_t now);
uint64_t wt_quic_connection_max_data(const wt_quic_connection_t *connection);

/* The stream-count limits this endpoint grants, the same shape as the connection-level one above and for
 * the same reason: RFC 9000 section 4.6 makes a MAX_STREAMS that decreases a protocol error, because the
 * peer has already been told it may open that many. The two directions have separate counts, since a
 * bidirectional stream costs the peer one of its own and one of ours while a unidirectional one costs
 * only ours. `direction` is the direction of the streams being granted, which is what the frame carries. */
wt_status_t wt_quic_connection_set_max_streams(wt_quic_connection_t *connection,
                                               wt_quic_stream_direction_t direction,
                                               uint64_t maximum);
wt_status_t wt_quic_connection_send_max_streams(wt_quic_connection_t *connection,
                                                wt_quic_stream_direction_t direction,
                                                uint64_t maximum, uint64_t now);
uint64_t wt_quic_connection_max_streams(const wt_quic_connection_t *connection,
                                        wt_quic_stream_direction_t direction);

/* The largest DATAGRAM payload this connection may send right now: the smaller of the peer's frame
 * limit and what the path carries, with the frame's own length field accounted for. Zero when the peer
 * does not accept datagrams. */
uint64_t wt_quic_connection_max_datagram_payload(const wt_quic_connection_t *connection);

/* A received DATAGRAM frame, for a caller's frame handler to hand to the connection: this is the
 * receive half of the same API, and it is a function rather than something this layer does by itself so
 * that a frame handler composed of several consumers can decide what to do with it. A datagram the queue
 * cannot hold is discarded and counted, never refused, because a datagram is not guaranteed to arrive. */
wt_status_t wt_quic_connection_on_datagram(wt_quic_connection_t *connection, const uint8_t *data,
                                           size_t length, uint64_t now);

/* Take the oldest datagram that arrived. WT_ERR_AGAIN when there is none. */
wt_status_t wt_quic_connection_receive_datagram(wt_quic_connection_t *connection, uint8_t *out,
                                                size_t capacity, size_t *out_length,
                                                uint64_t *out_received_at);

/* Discard one space's keys, in both directions. RFC 9001 section 4.9 makes this a MUST, not a
 * tidy-up: the Initial keys are derived from a connection ID both ends can see, so an endpoint that
 * keeps them stays readable to anyone who saw the first packet, and the Handshake keys are no better
 * once the handshake is confirmed. The connection does it by itself where the RFC says when -- the
 * Initial keys go when a Handshake packet is first received or sent, the Handshake keys when the
 * handshake is confirmed -- and this is exposed because a caller that ends a connection early has to be
 * able to do it too. Idempotent, and a space that never had keys is not an error. */
wt_status_t wt_quic_connection_discard_keys(wt_quic_connection_t *connection, wt_quic_space_t space);

/* Install the frame and loss handlers. Both are optional; without the first, frames this layer does
 * not act on are ignored -- which is correct for a connection whose owner has nothing to do with them
 * yet, and wrong for a connection that needs them. */
void wt_quic_connection_set_handlers(wt_quic_connection_t *connection,
                                     wt_quic_frame_handler_fn handler, void *handler_context,
                                     wt_quic_frame_lost_fn lost_handler, void *lost_context);

/* Send one CRYPTO payload in one packet. The bytes are not copied: the descriptor records where they
 * are in the handshake stream, and a loss is reported to the lost handler so that the owner can send
 * them again from the buffer it owns. Returns WT_ERR_AGAIN when the congestion window or the loss
 * list has no room, which is the caller's signal to try later; WT_ERR_LIMIT when every retransmission
 * slot is taken. */
wt_status_t wt_quic_connection_send_crypto(wt_quic_connection_t *connection, wt_quic_space_t space,
                                           uint64_t offset, const uint8_t *data, size_t length,
                                           uint64_t now);

/* Send one frame by itself, in one packet, with the keys of that space.
 *
 * This is the general path for the frames this layer does not produce -- HANDSHAKE_DONE, the flow
 * control limits, the stream frames -- and it takes a frame the frame codec has already validated.
 * `ack_eliciting` is the caller's to state because it follows from the frame's type (RFC 9000 section
 * 13.2.1): PADDING, ACK and CONNECTION_CLOSE do not ask for an acknowledgement and everything else
 * does. It refuses, rather than silently succeeding, when the congestion window, the loss list or a
 * retransmission slot has no room. */
wt_status_t wt_quic_connection_send_frame(wt_quic_connection_t *connection, wt_quic_space_t space,
                                          const wt_quic_frame_t *frame, int ack_eliciting,
                                          uint64_t now);

/* Send an acknowledgement if one is owed in this space, and a probe (an ack-eliciting PING) if one is
 * owed because a probe timeout fired. Returns WT_OK whether or not anything was sent; the count of
 * packets sent is the caller's way to tell. */
wt_status_t wt_quic_connection_flush(wt_quic_connection_t *connection, uint64_t now);

/* Read and process one datagram. WT_ERR_AGAIN when none is waiting, which is not a failure.
 *
 * A packet that fails authentication ends the datagram: RFC 9001 section 5.3 discards it, and the
 * packets coalesced after it cannot be found reliably once one has been skipped. A protocol error in a
 * frame closes the connection and is reported. */
wt_status_t wt_quic_connection_receive(wt_quic_connection_t *connection, uint64_t now);

/* How long the caller may wait before calling `wt_quic_connection_on_timeout`, and WT_ERR_STATE when
 * no timer is armed -- which is not the same as a zero delay: a connection with nothing in flight
 * waits for the application, indefinitely. */
wt_status_t wt_quic_connection_next_timeout(wt_quic_connection_t *connection, uint64_t now,
                                           uint64_t *out_micros);

/* Do what the deadline was armed for: declare packets lost, send a probe, or end an idle or draining
 * period. */
wt_status_t wt_quic_connection_on_timeout(wt_quic_connection_t *connection, uint64_t now);

/* Close, sending a CONNECTION_CLOSE frame if one has not been sent. RFC 9000 section 10.2: the intent
 * to close is a frame, so this sends it and then waits out the draining period. A reason phrase is a
 * view and must outlive the call, which is why it is passed and not stored. */
wt_status_t wt_quic_connection_close(wt_quic_connection_t *connection, uint64_t error_code,
                                     uint64_t frame_type, const uint8_t *reason, size_t reason_length,
                                     uint64_t now);

/* Whether the peer closed, so that nothing but PADDING and the close's own frames is processed. */
int wt_quic_connection_is_closed(const wt_quic_connection_t *connection);

/* The close THIS endpoint sent: its kind, error code, frame type and reason phrase, or a state whose kind is
 * `WT_QUIC_CLOSE_NONE` when it has sent none. It is the record of what the peer was told, which is a different
 * question from `close_code`'s -- that is the hint a refusing handler leaves, and the connection clears it once
 * it has been used (WT-144). The state is owned by the connection and the reason phrase is a view into the
 * caller's bytes, so it lives as long as whatever passed them to `wt_quic_connection_close`. */
const wt_quic_close_state_t *wt_quic_connection_close_state(const wt_quic_connection_t *connection);

/* Refuse with an APPLICATION error code, which is how an HTTP/3 error reaches the peer (RFC 9114 section 8).
 * The hint is used by the next refusal, exactly as `close_code` is, and it decides the KIND of the close: the
 * transport form names a frame type and the application form has none. */
void wt_quic_connection_refuse_application(wt_quic_connection_t *connection, uint64_t error_code,
                                           uint64_t frame_type);

/* Tell a SERVER which connection ID the client used as the destination of its first Initial, so that the
 * packets which carry it are this connection's rather than another's. A client chooses that value arbitrarily
 * (RFC 9000 section 7.2), so there is nowhere else for the server to learn it, and a server that does not
 * accept it refuses every third-party client whose choice differs from its own Source Connection ID. Ignored
 * for a client, which has no such ID. */
wt_status_t wt_quic_connection_set_original_destination_id(wt_quic_connection_t *connection,
                                                           const uint8_t *id, size_t length);

/* Whether a Retry has been accepted and the Initial keys have NOT yet been derived from the connection ID it
 * chose. RFC 9000 section 17.2.5.2 makes the keys a function of that destination connection ID (RFC 9001 section
 * 5.2), so the endpoint that owns the keys has to derive them again -- and until it does, every Initial this
 * connection sends is protected with keys the server has thrown away.
 *
 * The sequence the runtime session follows is: pump the socket, and if this answers true, derive the Initial keys
 * again from `connection->peer_connection_id` and call `wt_quic_connection_retry_keys_installed`. */
int wt_quic_connection_retry_pending_keys(const wt_quic_connection_t *connection);

/* The Initial keys now match the accepted Retry's connection ID. Clears the flag above; without a Retry it does
 * nothing, because there is nothing pending. */
void wt_quic_connection_retry_keys_installed(wt_quic_connection_t *connection);

/* Initiate a 1-RTT key update (RFC 9001 section 6.1): the next write secret is derived, the Key Phase bit is
 * toggled, the receive keys move to the same phase -- "the endpoint that initiates a key update also updates
 * the keys that it uses for receiving packets" -- and the phase being left behind is retained for packets the
 * network reordered.
 *
 * WT_ERR_STATE when the handshake is not confirmed (a MUST NOT), and WT_ERR_STATE when a previous update has
 * not yet been acknowledged (the other MUST NOT: "unless it has received an acknowledgment for a packet that
 * was sent protected with keys from the current key phase"). Both are the caller's errors rather than the
 * peer's, so neither closes anything. */
wt_status_t wt_quic_connection_initiate_key_update(wt_quic_connection_t *connection, uint64_t now);

/* Whether an update may be initiated now, which is the two conditions above and nothing else. A caller that
 * updates on a counter asks this first. */
int wt_quic_connection_key_update_allowed(const wt_quic_connection_t *connection);

/* Switch to another connection ID the PEER issued (RFC 9000 section 5.1.2): "An endpoint can change the
 * connection ID it uses for a peer to another available one at any time during the connection." The ID being
 * abandoned is RETIRED with a frame, because the section also says an endpoint must not forget a connection ID
 * without retiring it -- and a retire is what asks the peer for a replacement.
 *
 * WT_ERR_STATE when the peer has issued nothing to switch to, which is the ordinary state of a connection whose
 * peer sent no NEW_CONNECTION_ID (the handshake's ID is not one of these and needs no retiring to leave, though
 * leaving it does retire it if it came from a NEW_CONNECTION_ID).
 *
 * A caller uses this to migrate, or simply to stop being linkable by a connection ID it has used for a while
 * (section 9.5). */
wt_status_t wt_quic_connection_use_new_connection_id(wt_quic_connection_t *connection, uint64_t now);

/* Start validating the path this connection is on (RFC 9000 section 8.2.1): a PATH_CHALLENGE with eight
 * unpredictable bytes goes out, the peer's PATH_RESPONSE with the SAME bytes proves the path works in both
 * directions, and a path that does not answer is retried with a NEW payload up to
 * `WT_QUIC_PATH_VALIDATION_ATTEMPTS` times before it is declared unvalidated (section 8.2.4).
 *
 * In this tree a connection has ONE peer address, which its caller gave it at `attach`; what is validated is
 * therefore that path -- a liveness test a caller runs on a session it has not heard from, which is what section
 * 10.1.1 asks for. This is also the RFC's own first use for a PATH_CHALLENGE, and the reason the connection owns
 * the machinery rather than the caller: a challenge whose payload does not change between attempts is the one
 * mistake section 8.2.1 names by hand.
 *
 * The decision to validate is the caller's, and so is the reaction to a failure: a path that stops answering is
 * a diagnostic here (`wt_quic_connection_path_validation_failures`), not a close, because only the caller knows
 * whether it has another path to try. WT_ERR_STATE when the connection is closed, and WT_OK when a validation is
 * already running -- asking twice is not an error, and a caller that wants a fresh one can wait for the first to
 * finish or fail. */
wt_status_t wt_quic_connection_validate_path(wt_quic_connection_t *connection, uint64_t now);
int wt_quic_connection_path_validating(const wt_quic_connection_t *connection);
int wt_quic_connection_path_validated(const wt_quic_connection_t *connection);
uint64_t wt_quic_connection_path_challenges_sent(const wt_quic_connection_t *connection);
uint64_t wt_quic_connection_path_responses_sent(const wt_quic_connection_t *connection);
uint64_t wt_quic_connection_path_validation_failures(const wt_quic_connection_t *connection);

/* Retire a connection ID the PEER issued that this endpoint is NOT using (RFC 9000 section 5.1.2), which is also
 * how a caller asks the peer for a replacement: "Sending a RETIRE_CONNECTION_ID frame ... requests that the peer
 * replace it with a new connection ID using a NEW_CONNECTION_ID frame."
 *
 * The frame and the forgetting are ONE CALL because they are one act -- "An endpoint MUST NOT forget a connection
 * ID without retiring it" -- and a caller that built its own RETIRE_CONNECTION_ID frame would leave this layer's
 * table holding an ID the peer counts as gone. The next NEW_CONNECTION_ID would then be refused with
 * CONNECTION_ID_LIMIT_ERROR, which is this endpoint closing a healthy connection with its own bookkeeping; the
 * test that drove a real retire through a real pair found exactly that (WT-171).
 *
 * WT_ERR_STATE when the sequence names the ID currently in use -- section 19.16 forbids a RETIRE_CONNECTION_ID
 * from naming the destination of the packet carrying it, and `wt_quic_connection_use_new_connection_id` is the
 * call that gives that ID up by adopting another first -- when the sequence is not stored (including one already
 * retired), and when the connection is closed. */
wt_status_t wt_quic_connection_retire_peer_connection_id(wt_quic_connection_t *connection,
                                                         uint64_t sequence, uint64_t now);

/* How many RETIRE_CONNECTION_ID frames this endpoint has RECEIVED -- the peer asking for replacements. */
uint64_t wt_quic_connection_retires_received(const wt_quic_connection_t *connection);

/* How many connection IDs this endpoint has retired from the peer -- the ones it stopped using -- and how many
 * of the peer's are stored and available. Diagnostics: a retire that was never sent looks exactly like a peer
 * that never asked. */
uint64_t wt_quic_connection_peer_ids_retired(const wt_quic_connection_t *connection);
size_t wt_quic_connection_peer_id_count(const wt_quic_connection_t *connection);

/* RFC 9001 section 6.6's counters and limits. `aead_encrypted` is per packet-number space and is reset for the
 * Application space by a key update, because it counts packets per KEY SET; `aead_failed` is the connection's,
 * because the integrity limit bounds forgery attempts across every key it has used.
 *
 * The limits come from the AEAD the connection was configured with: 2^23 encrypted packets and 2^52 invalid ones
 * for AES-GCM, ChaCha20-Poly1305's confidentiality limit is above the packet number space itself and so is
 * effectively unlimited while its integrity limit is 2^36 (section 6.6 and appendix B.1). A caller that bounds
 * packet sizes may raise them, which appendix B permits; the connection enforces whatever they hold. */
uint64_t wt_quic_connection_aead_encrypted(const wt_quic_connection_t *connection, wt_quic_space_t space);
uint64_t wt_quic_connection_aead_failed(const wt_quic_connection_t *connection);
uint64_t wt_quic_connection_aead_confidentiality_limit(const wt_quic_connection_t *connection);
uint64_t wt_quic_connection_aead_integrity_limit(const wt_quic_connection_t *connection);

/* The phase bit this endpoint protects its packets with: the header's Key Phase, which a peer reads to know
 * which keys to use. */
int wt_quic_connection_key_phase(const wt_quic_connection_t *connection);

/* How many updates this endpoint has initiated and how many the peer has started, plus how many were refused
 * with KEY_UPDATE_ERROR. Diagnostics, because a key that never moved is invisible from the outside. */
uint64_t wt_quic_connection_key_updates_initiated(const wt_quic_connection_t *connection);
uint64_t wt_quic_connection_key_updates_responded(const wt_quic_connection_t *connection);
uint64_t wt_quic_connection_key_update_errors(const wt_quic_connection_t *connection);

/* The Retry this connection accepted: its token and the Source Connection ID it named, for a caller that has to
 * derive keys from the latter or say what happened. WT_ERR_STATE when no Retry was accepted. The token is a view
 * into the connection, which owns it. */
wt_status_t wt_quic_connection_retry(const wt_quic_connection_t *connection, const uint8_t **out_token,
                                     size_t *out_token_length, const uint8_t **out_source_connection_id,
                                     size_t *out_source_connection_id_length);

/* The status of the handler whose refusal closed this connection, or WT_OK when no handler refused -- a close
 * this endpoint chose deliberately, or one the peer sent, has no cause here. A tool asks because a session that
 * ended this way did NOT end well, whatever the exchange counters say. */
wt_status_t wt_quic_connection_close_cause(const wt_quic_connection_t *connection);

/* Whether a CONNECTION_CLOSE frame was actually SENT to the peer. A close this endpoint decided on but never
 * announced -- the idle timeout, RFC 9000 section 10.1 -- is not one the peer was told about, so a caller must
 * ask this and not infer it from `wt_quic_connection_close_state`: the state is set either way (WT-144). */
int wt_quic_connection_close_was_sent(const wt_quic_connection_t *connection);

/* Whether the draining period has passed, after which the connection is gone and its state may be
 * released. */
int wt_quic_connection_is_drained(const wt_quic_connection_t *connection, uint64_t now);

/* Zero the keys and forget the peer. Does not close the socket, which the connection never owned. */
void wt_quic_connection_clear(wt_quic_connection_t *connection);

/* The name of a space, for diagnostics: "initial", "handshake", "application". Never NULL. */
const char *wt_quic_space_name(wt_quic_space_t space);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_QUIC_CONNECTION_H */
