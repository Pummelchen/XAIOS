/* Stream state machines and flow control (RFC 9000 sections 2, 3 and 4).
 *
 * TWO STATE MACHINES PER STREAM, AND THEY ARE INDEPENDENT. A stream has a send half and a receive
 * half, and each moves through its own states: the send half is Ready until the first byte is sent,
 * then Send, then Data Sent once everything including the FIN is written, then Data Recvd once the
 * peer has acknowledged all of it. The receive half is Recv until a FIN arrives, then Size Known,
 * then Data Recvd as the bytes are delivered in order, then Data Read when the application has taken
 * them. A stream that is reset in one direction stays usable in the other, which is why this is two
 * machines and not one.
 *
 * THE FINAL SIZE IS THE PART THAT IS EASY TO GET WRONG, AND IT IS A SECURITY BOUNDARY. Once a
 * stream's size is known -- from a FIN or from a RESET_STREAM -- every later frame is measured
 * against it: data at or beyond it is FINAL_SIZE_ERROR, and a second FIN with a different size is
 * FINAL_SIZE_ERROR too. Without that, a peer could append to a stream after claiming it had ended,
 * which is how a length-delimited protocol on top of QUIC gets its framing confused.
 *
 * FLOW CONTROL IS TWO-LEVEL, AND IT COUNTS OFFSETS RATHER THAN DELIVERED BYTES (RFC 9000 sections
 * 4.1 and 4.2). The connection has a limit and every stream has one, and a frame is legal only if it
 * fits under both. What each level tracks is the stream's MAXIMUM OFFSET, not the number of bytes
 * that have arrived: a peer that writes ten bytes at offset one million has consumed a million bytes
 * of the connection's credit even though ten arrived. That is deliberate in the RFC -- a gap cannot
 * be used to escape the accounting -- and it is why a frame's cost here is "how far the maximum
 * offset advanced" rather than "how many bytes are new".
 *
 * The limits in the other direction -- what the peer allows this endpoint to send -- are checked
 * before a frame is written rather than after, because a frame that is written and then refused has
 * already counted against them.
 *
 * WHAT IS NOT HERE: reassembly. Delivering out-of-order stream data in order is the connection's
 * job, because it needs the same buffer strategy as the CRYPTO stream, and this file only tracks how
 * far in order the data has been delivered and how far ahead the peer has written.
 */

#ifndef WEBTRANSPORT_QUIC_STREAM_H
#define WEBTRANSPORT_QUIC_STREAM_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/quic/error.h"
#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The connection's flow control, in the four numbers that matter (RFC 9000 section 4). */
typedef struct wt_quic_flow {
  /* Sending: the peer's limit and how much has been sent against it. */
  uint64_t peer_max_data;
  uint64_t data_sent;
  /* Receiving: the limit this endpoint has advertised and how much has arrived. */
  uint64_t max_data;
  uint64_t data_received;
  /* The window the limit is extended by when it is extended. */
  uint64_t window;
} wt_quic_flow_t;

/* `initial_max_data` is what this endpoint advertises, `peer_initial_max_data` what the peer does.
 * A connection that advertises nothing cannot receive, and one whose peer advertised nothing cannot
 * send, so both are taken as given rather than defaulted. */
void wt_quic_flow_init(wt_quic_flow_t *flow, uint64_t initial_max_data,
                       uint64_t peer_initial_max_data);

/* How many more bytes this endpoint may send on the connection as a whole. */
uint64_t wt_quic_flow_send_allowance(const wt_quic_flow_t *flow);

/* Whether `length` more bytes fit under the peer's limit. A caller checks this before writing a
 * frame, because a frame that is written and then refused has already been counted. */
int wt_quic_flow_can_send(const wt_quic_flow_t *flow, uint64_t length);

wt_status_t wt_quic_flow_on_sent(wt_quic_flow_t *flow, uint64_t length);
/* The peer raised its connection limit (a MAX_DATA frame). A limit that goes backwards is a peer
 * that has lost track of what it advertised, which RFC 9000 section 4.1 does not allow. */
wt_status_t wt_quic_flow_on_max_data(wt_quic_flow_t *flow, uint64_t new_max);
/* `length` bytes arrived on some stream. */
wt_status_t wt_quic_flow_on_received(wt_quic_flow_t *flow, uint64_t length);
/* Whether the received bytes have reached the advertised limit, which is when RFC 9000 section 4.1
 * expects a MAX_DATA to be sent; waiting for the limit itself leaves the peer unable to send. */
int wt_quic_flow_should_extend(const wt_quic_flow_t *flow);
/* The limit to advertise next: the window past what has arrived. */
uint64_t wt_quic_flow_next_max_data(const wt_quic_flow_t *flow);
void wt_quic_flow_on_max_data_sent(wt_quic_flow_t *flow, uint64_t new_max);

/* ------------------------------------------------------------------- streams */

typedef enum wt_quic_send_state {
  WT_QUIC_SEND_READY = 0,
  WT_QUIC_SEND_SEND,
  WT_QUIC_SEND_DATA_SENT,
  WT_QUIC_SEND_DATA_RECVD,
  WT_QUIC_SEND_RESET_SENT,
  WT_QUIC_SEND_RESET_RECVD
} wt_quic_send_state_t;

typedef enum wt_quic_recv_state {
  WT_QUIC_RECV_RECV = 0,
  WT_QUIC_RECV_SIZE_KNOWN,
  WT_QUIC_RECV_DATA_RECVD,
  WT_QUIC_RECV_DATA_READ,
  WT_QUIC_RECV_RESET_RECVD,
  WT_QUIC_RECV_RESET_READ
} wt_quic_recv_state_t;

typedef struct wt_quic_stream {
  uint64_t id;
  /* Whether this endpoint opened the stream, which decides who may send on it (RFC 9000
   * section 2.1) and which frames are legal to receive. */
  int initiated_by_us;
  int bidirectional;

  wt_quic_send_state_t send_state;
  wt_quic_recv_state_t recv_state;

  /* Sending. */
  uint64_t send_offset;      /* the next offset to write at */
  uint64_t send_acked;       /* the cumulative offset the peer has acknowledged */
  uint64_t final_size;       /* set when a FIN is sent: the stream's size on this side */
  int has_final_size;
  int fin_sent;
  uint64_t peer_max_stream_data;

  /* Receiving. */
  uint64_t recv_offset;      /* the next offset to deliver, in order */
  uint64_t recv_highest;     /* the highest offset the peer has written */
  uint64_t recv_final_size;  /* the size the peer claimed, from a FIN or a RESET_STREAM */
  int has_recv_final_size;
  uint64_t max_stream_data;
  uint64_t window;
  int sent_stop_sending;
  int peer_reset;
  uint64_t peer_error_code;
  /* The reliable-stream-reset extension: the offset the peer COMMITTED to delivering even though it reset the
   * stream, and whether it said so at all. A RESET_STREAM_AT may lower this and must never raise it, so the
   * lowest one seen is what the application may rely on (draft-ietf-quic-reliable-stream-reset). */
  uint64_t peer_reliable_size;
  int peer_reset_at;
} wt_quic_stream_t;

/* A stream that has been created but not yet used. `max_stream_data` is what this endpoint
 * advertises for it; `peer_max_stream_data` is what the peer does. */
void wt_quic_stream_init(wt_quic_stream_t *stream, uint64_t id, int initiated_by_us,
                         int bidirectional, uint64_t max_stream_data,
                         uint64_t peer_max_stream_data);

/* Whether the send half is finished: nothing more will be sent on it. */
int wt_quic_stream_send_finished(const wt_quic_stream_t *stream);
/* Whether the receive half is finished. */
int wt_quic_stream_recv_finished(const wt_quic_stream_t *stream);
/* Whether the stream can be forgotten, which is when both halves are done and acknowledged. */
int wt_quic_stream_complete(const wt_quic_stream_t *stream);

/* Sending data, by length. The caller has already had the frame written, so this records it: moving
 * from Ready to Send on the first byte is the state machine's business rather than the caller's.
 * WT_ERR_STATE when the send half is finished or reset. */
wt_status_t wt_quic_stream_on_data_sent(wt_quic_stream_t *stream, uint64_t length);
/* The FIN has been sent, which fixes the stream's size. WT_ERR_STATE if one was already sent. */
wt_status_t wt_quic_stream_on_fin_sent(wt_quic_stream_t *stream);
/* The peer acknowledged everything up to the cumulative offset `acknowledged`, which may complete
 * the send half. */
wt_status_t wt_quic_stream_on_ack(wt_quic_stream_t *stream, uint64_t acknowledged);
/* A RESET_STREAM was sent: the send half is finished and the final size is whatever was sent. */
wt_status_t wt_quic_stream_on_reset_sent(wt_quic_stream_t *stream, uint64_t error_code);
/* A RESET_STREAM was received. Its final size must agree with anything already known. */
wt_status_t wt_quic_stream_on_reset_received(wt_quic_stream_t *stream,
                                             uint64_t error_code,
                                             uint64_t final_size);
/* A RESET_STREAM_AT was received (the reliable-stream-reset extension): the stream ends exactly as a RESET_STREAM
 * ends it, and `reliable_size` bytes of it were committed to. Three of that extension's rules live here because
 * they are facts about the stream rather than about the frame:
 *
 *   - a Reliable Size larger than the Final Size is a FRAME_ENCODING_ERROR, reported as WT_ERR_PROTOCOL with that
 *     condition visible to the caller;
 *   - a frame that RAISES the reliable size must be ignored, so this returns WT_OK having changed nothing;
 *   - a changed application error code or final size is a STREAM_STATE_ERROR, reported the same way.
 *
 * WT_ERR_STATE means the stream was already reset by a plain RESET_STREAM, whose semantics cannot be revised. */
wt_status_t wt_quic_stream_on_reset_at_received(wt_quic_stream_t *stream, uint64_t error_code,
                                                uint64_t final_size, uint64_t reliable_size);
/* A STOP_SENDING was received: the peer wants this endpoint to stop sending. */
wt_status_t wt_quic_stream_on_stop_sending(wt_quic_stream_t *stream,
                                           uint64_t error_code);
/* The peer raised this stream's limit. */
wt_status_t wt_quic_stream_on_max_stream_data(wt_quic_stream_t *stream,
                                              uint64_t new_max);

/* How many more bytes may be sent on this stream, which is the smaller of the stream's own
 * allowance and the connection's. */
uint64_t wt_quic_stream_send_allowance(const wt_quic_stream_t *stream,
                                       const wt_quic_flow_t *flow);
int wt_quic_stream_can_send(const wt_quic_stream_t *stream,
                            const wt_quic_flow_t *flow, uint64_t length);

/* Stream data arrived at `offset`. `fin` says the frame carried the end of the stream.
 *
 * WT_ERR_PROTOCOL for data at or beyond a known final size, for a FIN that contradicts one, and for
 * data that would take the stream past the limit this endpoint advertised -- RFC 9000 sections 4.1
 * and 4.2 make those errors rather than something to tolerate.
 *
 * `out_credit` is how much flow control credit the frame consumed: the amount by which the stream's
 * maximum offset advanced, which is zero for a retransmission and is the whole offset for a first
 * frame that starts in the middle of a stream. It is what the caller subtracts from the connection's
 * accounting, and it is not the length of the frame.
 *
 * `in_order` is set when the frame's offset is the next one to deliver, which is what a caller needs
 * to know without keeping its own copy of the offset. */
wt_status_t wt_quic_stream_on_data(wt_quic_stream_t *stream, wt_quic_flow_t *flow,
                                   uint64_t offset, uint64_t length, int fin,
                                   uint64_t *out_credit, int *in_order);

/* The application took `length` bytes of delivered data. */
wt_status_t wt_quic_stream_on_data_read(wt_quic_stream_t *stream, uint64_t length);

/* The application has been told that the peer reset this stream, which completes the receive half.
 * RFC 9000 section 3.2 puts a state between the reset arriving and the stream being done with --
 * Reset Recvd, then Reset Read -- and the difference matters: a stream whose reset has arrived but
 * has not been reported is one the application is still waiting on, and a connection that forgot it
 * would leak the stream. */
wt_status_t wt_quic_stream_on_reset_read(wt_quic_stream_t *stream);

/* Whether this endpoint should extend the stream's limit, and the value to advertise. */
int wt_quic_stream_should_extend(const wt_quic_stream_t *stream);
uint64_t wt_quic_stream_next_max_stream_data(const wt_quic_stream_t *stream);
void wt_quic_stream_on_max_stream_data_sent(wt_quic_stream_t *stream,
                                            uint64_t new_max);

/* Names for diagnostics. */
const char *wt_quic_send_state_name(wt_quic_send_state_t state);
const char *wt_quic_recv_state_name(wt_quic_recv_state_t state);

#ifdef __cplusplus
}
#endif

/* The four fields RFC 9000 section 2.1 packs into one stream number: the low bit is the initiator,
 * the next is the directionality, and the rest is an index within that class. Read and written in one
 * place, so that no rule shifts bits at its own call site. */
uint64_t wt_quic_stream_id_index(uint64_t stream_id);
int wt_quic_stream_id_from_client(uint64_t stream_id);
int wt_quic_stream_id_is_bidirectional(uint64_t stream_id);
uint64_t wt_quic_stream_id_make(int from_client, int bidirectional, uint64_t index);

/* ------------------------------------------------------------------- the table
 *
 * ONE STREAM IS A STATE MACHINE; A CONNECTION HAS MANY. The table is bounded, which is the resource
 * limit the plan names: a peer chooses how many streams it opens, so a receiver that allocated a
 * structure per stream number would let the peer choose its memory. A full table refuses a new stream
 * rather than dropping an old one, because a stream that is silently forgotten is data the application
 * never sees, and a stream is only forgotten when BOTH halves are done, which is what RFC 9000 section
 * 3.3 requires before its number is never seen again.
 *
 * It owns the state and nothing else: no frames, no bytes, no policy about when to send. What it answers
 * is which stream a frame is about, whether one more may be opened, and which streams are still alive.
 */
#define WT_QUIC_STREAM_TABLE_MAX 32U

typedef struct wt_quic_stream_table {
  wt_quic_stream_t streams[WT_QUIC_STREAM_TABLE_MAX];
  uint8_t used[WT_QUIC_STREAM_TABLE_MAX];
  size_t count;
  /* The cumulative stream count per class, which is also the index the NEXT number of that class is built
   * from. RFC 9000 section 2.1 forbids reusing a stream number, and section 4.6 measures `initial_max_streams_*`
   * over the connection's life rather than over the streams live now, so these are MONOTONIC: a reclaim or a
   * close frees the slot (`used`, `count`) and leaves these alone. */
  uint64_t opened_by_us_bidi;
  uint64_t opened_by_us_uni;
  uint64_t opened_by_peer_bidi;
  uint64_t opened_by_peer_uni;
} wt_quic_stream_table_t;

void wt_quic_stream_table_init(wt_quic_stream_table_t *table);
/* Open a stream. `limit` is the OPENER's stream-count limit: a peer-initiated stream costs the peer one
 * of its allowance, not this endpoint one of its own (RFC 9000 section 4.6). WT_ERR_LIMIT when the table
 * is full or the limit does not allow one more -- one answer, because the caller's reaction is the same
 * -- and WT_ERR_STATE for a stream that is already in the table. The new stream has NO flow control
 * credit: the caller sets the two limits from the transport parameters, which this layer does not know. */
wt_status_t wt_quic_stream_table_open(wt_quic_stream_table_t *table, uint64_t stream_id,
                                      int initiated_by_us, uint64_t limit);
wt_quic_stream_t *wt_quic_stream_table_find(wt_quic_stream_table_t *table, uint64_t stream_id);
const wt_quic_stream_t *wt_quic_stream_table_find_const(const wt_quic_stream_table_t *table,
                                                        uint64_t stream_id);
/* Forget a stream whose two halves are done, which frees its slot. WT_ERR_STATE for a stream that is
 * still open, or one that is not there. */
wt_status_t wt_quic_stream_table_close(wt_quic_stream_table_t *table, uint64_t stream_id);
wt_quic_stream_t *wt_quic_stream_table_at(wt_quic_stream_table_t *table, size_t index);
size_t wt_quic_stream_table_count(const wt_quic_stream_table_t *table);
uint64_t wt_quic_stream_table_opened_by_us(const wt_quic_stream_table_t *table, int bidirectional);
uint64_t wt_quic_stream_table_opened_by_peer(const wt_quic_stream_table_t *table, int bidirectional);

#endif /* WEBTRANSPORT_QUIC_STREAM_H */
