/* Stream state machines and flow control. See webtransport/quic/stream.h. */

#include "webtransport/quic/stream.h"

#include <string.h>

/* ------------------------------------------------------------- the connection */

void wt_quic_flow_init(wt_quic_flow_t *flow, uint64_t initial_max_data,
                       uint64_t peer_initial_max_data) {
  if (flow == NULL) return;
  memset(flow, 0, sizeof(*flow));
  flow->max_data = initial_max_data;
  flow->peer_max_data = peer_initial_max_data;
  /* A window of half the limit: an extension that doubled it would let a peer that never reads
   * consume memory twice as fast, and one that extended by a little would send MAX_DATA frames for
   * every packet. Half is what leaves room for the frames in flight while the extension is decided. */
  flow->window = initial_max_data / 2U;
}

uint64_t wt_quic_flow_send_allowance(const wt_quic_flow_t *flow) {
  if (flow == NULL) return 0U;
  if (flow->data_sent >= flow->peer_max_data) return 0U;
  return flow->peer_max_data - flow->data_sent;
}

int wt_quic_flow_can_send(const wt_quic_flow_t *flow, uint64_t length) {
  return wt_quic_flow_send_allowance(flow) >= length;
}

wt_status_t wt_quic_flow_on_sent(wt_quic_flow_t *flow, uint64_t length) {
  if (flow == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* A caller that sends past the limit has already put the bytes on the wire, and the peer will
   * close the connection for it: refusing here means the accounting cannot be the thing that is
   * wrong, and the caller's contract is to check first. */
  if (!wt_quic_flow_can_send(flow, length)) return WT_ERR_STATE;
  flow->data_sent += length;
  return WT_OK;
}

wt_status_t wt_quic_flow_on_max_data(wt_quic_flow_t *flow, uint64_t new_max) {
  if (flow == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* RFC 9000 section 4.1: a limit may only be raised. A peer that lowers it is either confused or
   * hostile, and quietly accepting a smaller limit would make this endpoint's accounting wrong in
   * the direction that gets a connection closed. */
  if (new_max < flow->peer_max_data) return WT_ERR_PROTOCOL;
  flow->peer_max_data = new_max;
  return WT_OK;
}

wt_status_t wt_quic_flow_on_received(wt_quic_flow_t *flow, uint64_t length) {
  if (flow == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* The connection's limit is a bound on what may arrive, and a peer that exceeds it is a flow
   * control error (RFC 9000 section 4.1). Checked before the addition so that a length near the
   * top of the range cannot wrap the total. */
  if (length > flow->max_data - flow->data_received) return WT_ERR_PROTOCOL;
  flow->data_received += length;
  return WT_OK;
}

int wt_quic_flow_should_extend(const wt_quic_flow_t *flow) {
  if (flow == NULL) return 0;
  return flow->data_received >= flow->max_data;
}

uint64_t wt_quic_flow_next_max_data(const wt_quic_flow_t *flow) {
  if (flow == NULL) return 0U;
  return flow->data_received + flow->window;
}

void wt_quic_flow_on_max_data_sent(wt_quic_flow_t *flow, uint64_t new_max) {
  if (flow == NULL) return;
  if (new_max > flow->max_data) flow->max_data = new_max;
}

/* ------------------------------------------------------------------ streams */

void wt_quic_stream_init(wt_quic_stream_t *stream, uint64_t id, int initiated_by_us,
                         int bidirectional, uint64_t max_stream_data,
                         uint64_t peer_max_stream_data) {
  if (stream == NULL) return;
  memset(stream, 0, sizeof(*stream));
  stream->id = id;
  stream->initiated_by_us = initiated_by_us ? 1 : 0;
  stream->bidirectional = bidirectional ? 1 : 0;
  stream->send_state = WT_QUIC_SEND_READY;
  stream->recv_state = WT_QUIC_RECV_RECV;
  stream->max_stream_data = max_stream_data;
  stream->window = max_stream_data / 2U;
  stream->peer_max_stream_data = peer_max_stream_data;
}

int wt_quic_stream_send_finished(const wt_quic_stream_t *stream) {
  if (stream == NULL) return 1;
  return stream->send_state == WT_QUIC_SEND_DATA_SENT ||
         stream->send_state == WT_QUIC_SEND_DATA_RECVD ||
         stream->send_state == WT_QUIC_SEND_RESET_SENT ||
         stream->send_state == WT_QUIC_SEND_RESET_RECVD;
}

int wt_quic_stream_recv_finished(const wt_quic_stream_t *stream) {
  if (stream == NULL) return 1;
  return stream->recv_state == WT_QUIC_RECV_DATA_READ ||
         stream->recv_state == WT_QUIC_RECV_RESET_READ;
}

int wt_quic_stream_complete(const wt_quic_stream_t *stream) {
  if (stream == NULL) return 1;
  return wt_quic_stream_send_finished(stream) && wt_quic_stream_recv_finished(stream);
}

wt_status_t wt_quic_stream_on_data_sent(wt_quic_stream_t *stream, uint64_t length) {
  if (stream == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (wt_quic_stream_send_finished(stream)) return WT_ERR_STATE;
  /* The first byte moves the stream out of Ready, which is what makes "has this stream been used"
   * a question the state answers rather than a flag. */
  if (stream->send_state == WT_QUIC_SEND_READY && length != 0U) {
    stream->send_state = WT_QUIC_SEND_SEND;
  }
  stream->send_offset += length;
  return WT_OK;
}

wt_status_t wt_quic_stream_on_fin_sent(wt_quic_stream_t *stream) {
  if (stream == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (stream->fin_sent || wt_quic_stream_send_finished(stream)) return WT_ERR_STATE;
  stream->fin_sent = 1;
  stream->final_size = stream->send_offset;
  stream->has_final_size = 1;
  stream->send_state = WT_QUIC_SEND_DATA_SENT;
  return WT_OK;
}

wt_status_t wt_quic_stream_on_ack(wt_quic_stream_t *stream, uint64_t acknowledged) {
  if (stream == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* Acknowledgements are cumulative: a lower value is an older frame arriving late, and moving the
   * watermark backwards would make this endpoint believe data it knows arrived is outstanding. */
  if (acknowledged > stream->send_acked) stream->send_acked = acknowledged;
  if (stream->send_state == WT_QUIC_SEND_DATA_SENT && stream->has_final_size &&
      stream->send_acked >= stream->final_size) {
    stream->send_state = WT_QUIC_SEND_DATA_RECVD;
  }
  /* A reset stream's acknowledgement completes the send half too: there is nothing more to send. */
  if (stream->send_state == WT_QUIC_SEND_RESET_SENT &&
      stream->send_acked >= stream->final_size) {
    stream->send_state = WT_QUIC_SEND_RESET_RECVD;
  }
  return WT_OK;
}

wt_status_t wt_quic_stream_on_reset_sent(wt_quic_stream_t *stream, uint64_t error_code) {
  if (stream == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (wt_quic_stream_send_finished(stream)) return WT_ERR_STATE;
  (void)error_code;
  /* RFC 9000 section 3.1: a reset ends the send half. The final size is what had been sent, because
   * a RESET_STREAM carries it and the peer must be able to tell a truncated stream from a complete
   * one. */
  stream->final_size = stream->send_offset;
  stream->has_final_size = 1;
  stream->send_state = WT_QUIC_SEND_RESET_SENT;
  return WT_OK;
}

/* The two ways a stream's size becomes known must agree, which is the check that keeps a truncated
 * stream from being read as a complete one. */
static wt_status_t check_final_size(wt_quic_stream_t *stream, uint64_t final_size) {
  if (stream->has_recv_final_size && stream->recv_final_size != final_size) {
    return WT_ERR_PROTOCOL;
  }
  /* Data that has already arrived cannot be beyond the size the peer now claims. */
  if (stream->recv_highest > final_size) return WT_ERR_PROTOCOL;
  stream->recv_final_size = final_size;
  stream->has_recv_final_size = 1;
  if (stream->recv_state == WT_QUIC_RECV_RECV) {
    stream->recv_state = WT_QUIC_RECV_SIZE_KNOWN;
    /* A stream whose whole body has already arrived is complete the moment the FIN does. */
    if (stream->recv_offset >= final_size) {
      stream->recv_state = WT_QUIC_RECV_DATA_RECVD;
    }
  }
  return WT_OK;
}

wt_status_t wt_quic_stream_on_reset_received(wt_quic_stream_t *stream,
                                             uint64_t error_code, uint64_t final_size) {
  wt_status_t status;
  if (stream == NULL) return WT_ERR_INVALID_ARGUMENT;
  status = check_final_size(stream, final_size);
  if (status != WT_OK) return status;
  stream->peer_reset = 1;
  stream->peer_error_code = error_code;
  stream->recv_state = WT_QUIC_RECV_RESET_RECVD;
  return WT_OK;
}

wt_status_t wt_quic_stream_on_reset_at_received(wt_quic_stream_t *stream, uint64_t error_code,
                                                uint64_t final_size, uint64_t reliable_size) {
  wt_status_t status;

  if (stream == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* The extension's own encoding rule, and the one a sender must never produce: a commitment beyond the end of
   * the stream is not a smaller promise but a broken one. The connection turns WT_ERR_PROTOCOL into the codes the
   * draft names, because which of them it is depends on this condition rather than on the status. */
  if (reliable_size > final_size) return WT_ERR_PROTOCOL;
  if (stream->peer_reset != 0 && stream->peer_reset_at == 0) {
    /* A plain RESET_STREAM already ended this half with a reliable size of zero by definition. */
    return WT_ERR_STATE;
  }
  status = check_final_size(stream, final_size);
  if (status != WT_OK) return status;
  if (stream->peer_reset_at != 0) {
    /* The error code and the final size are fixed by the first reset of this stream, whatever form it took. */
    if (stream->peer_error_code != error_code) return WT_ERR_PROTOCOL;
    /* And a frame that RAISES the reliable size is ignored rather than applied: the peer may promise less than it
     * promised before, never more. */
    if (reliable_size >= stream->peer_reliable_size) return WT_OK;
    stream->peer_reliable_size = reliable_size;
    return WT_OK;
  }
  stream->peer_reset = 1;
  stream->peer_reset_at = 1;
  stream->peer_error_code = error_code;
  stream->peer_reliable_size = reliable_size;
  stream->recv_state = WT_QUIC_RECV_RESET_RECVD;
  return WT_OK;
}

wt_status_t wt_quic_stream_on_stop_sending(wt_quic_stream_t *stream, uint64_t error_code) {
  if (stream == NULL) return WT_ERR_INVALID_ARGUMENT;
  (void)error_code;
  /* RFC 9000 section 3.5: a STOP_SENDING asks for the stream to be reset, so the send half is
   * finished as far as this endpoint is concerned. Marking it here rather than waiting for the
   * caller to send the RESET_STREAM means a caller that forgets cannot keep writing to a stream the
   * peer has abandoned. */
  stream->sent_stop_sending = 1;
  if (!wt_quic_stream_send_finished(stream)) {
    stream->final_size = stream->send_offset;
    stream->has_final_size = 1;
    stream->send_state = WT_QUIC_SEND_RESET_SENT;
  }
  return WT_OK;
}

wt_status_t wt_quic_stream_on_max_stream_data(wt_quic_stream_t *stream,
                                              uint64_t new_max) {
  if (stream == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* Like the connection limit, a stream limit may only be raised (RFC 9000 section 4.1). */
  if (new_max < stream->peer_max_stream_data) return WT_ERR_PROTOCOL;
  stream->peer_max_stream_data = new_max;
  return WT_OK;
}

uint64_t wt_quic_stream_send_allowance(const wt_quic_stream_t *stream,
                                       const wt_quic_flow_t *flow) {
  uint64_t stream_allowance;
  uint64_t connection_allowance;
  if (stream == NULL) return 0U;
  if (wt_quic_stream_send_finished(stream)) return 0U;
  stream_allowance = (stream->send_offset >= stream->peer_max_stream_data)
                         ? 0U
                         : stream->peer_max_stream_data - stream->send_offset;
  connection_allowance = wt_quic_flow_send_allowance(flow);
  return (stream_allowance < connection_allowance) ? stream_allowance : connection_allowance;
}

int wt_quic_stream_can_send(const wt_quic_stream_t *stream,
                            const wt_quic_flow_t *flow, uint64_t length) {
  return wt_quic_stream_send_allowance(stream, flow) >= length;
}

wt_status_t wt_quic_stream_on_data(wt_quic_stream_t *stream, wt_quic_flow_t *flow,
                                  uint64_t offset, uint64_t length, int fin,
                                  uint64_t *out_credit, int *in_order) {
  uint64_t end;
  uint64_t credit;
  wt_status_t status;

  if (stream == NULL || flow == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (out_credit != NULL) *out_credit = 0U;
  if (in_order != NULL) *in_order = 0;

  /* A frame that arrives after the receive half is finished is a peer that has not noticed: it is
   * refused rather than counted, because counting it would spend flow control credit on data this
   * endpoint has already delivered. */
  if (stream->recv_state == WT_QUIC_RECV_DATA_READ ||
      stream->recv_state == WT_QUIC_RECV_RESET_READ) {
    if (length != 0U || fin) return WT_ERR_STATE;
  }
  /* A length that would overflow the offset arithmetic is refused before the addition, because the
   * wrapped value would compare as a small offset and be accepted. */
  if (offset > UINT64_MAX - length) return WT_ERR_PROTOCOL;
  end = offset + length;

  /* The final size, when it is known, bounds everything (RFC 9000 section 4.5). */
  if (stream->has_recv_final_size) {
    if (end > stream->recv_final_size) return WT_ERR_PROTOCOL;
    if (fin && end != stream->recv_final_size) return WT_ERR_PROTOCOL;
  }

  /* Overlap is not an error: a retransmission is ordinary, and it costs nothing because the maximum
   * offset does not move. What the frame costs is the advance of that maximum, which for a first
   * frame starting in the middle of a stream is its whole offset. */
  credit = (end > stream->recv_highest) ? end - stream->recv_highest : 0U;
  {
    /* The stream's limit is checked before the credit is counted, so a frame that overruns it does
     * not leave the accounting somewhere a later frame cannot be judged against. */
    uint64_t total = stream->recv_highest + credit;
    if (total > stream->max_stream_data) return WT_ERR_PROTOCOL;
  }
  status = wt_quic_flow_on_received(flow, credit);
  if (status != WT_OK) return status;
  if (end > stream->recv_highest) stream->recv_highest = end;
  if (out_credit != NULL) *out_credit = credit;
  if (in_order != NULL && offset == stream->recv_offset) *in_order = 1;

  if (fin) {
    status = check_final_size(stream, end);
    if (status != WT_OK) return status;
  }
  /* The receive half is complete when everything up to the final size has arrived; the bytes are
   * delivered in order by the caller, so the completion of the state is the arrival of the last
   * byte rather than its delivery. */
  if (stream->has_recv_final_size && stream->recv_highest >= stream->recv_final_size &&
      stream->recv_state == WT_QUIC_RECV_SIZE_KNOWN) {
    stream->recv_state = WT_QUIC_RECV_DATA_RECVD;
  }
  return WT_OK;
}

wt_status_t wt_quic_stream_on_data_read(wt_quic_stream_t *stream, uint64_t length) {
  if (stream == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (stream->recv_state == WT_QUIC_RECV_RESET_RECVD ||
      stream->recv_state == WT_QUIC_RECV_RESET_READ) {
    return WT_ERR_STATE;
  }
  if (length > stream->recv_highest - stream->recv_offset) return WT_ERR_INVALID_ARGUMENT;
  stream->recv_offset += length;
  if (stream->recv_state == WT_QUIC_RECV_DATA_RECVD &&
      stream->recv_offset >= stream->recv_final_size) {
    stream->recv_state = WT_QUIC_RECV_DATA_READ;
  }
  return WT_OK;
}

wt_status_t wt_quic_stream_on_reset_read(wt_quic_stream_t *stream) {
  if (stream == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (stream->recv_state != WT_QUIC_RECV_RESET_RECVD) return WT_ERR_STATE;
  stream->recv_state = WT_QUIC_RECV_RESET_READ;
  return WT_OK;
}

int wt_quic_stream_should_extend(const wt_quic_stream_t *stream) {
  if (stream == NULL) return 0;
  return stream->recv_highest >= stream->max_stream_data;
}

uint64_t wt_quic_stream_next_max_stream_data(const wt_quic_stream_t *stream) {
  if (stream == NULL) return 0U;
  return stream->recv_highest + stream->window;
}

void wt_quic_stream_on_max_stream_data_sent(wt_quic_stream_t *stream, uint64_t new_max) {
  if (stream == NULL) return;
  if (new_max > stream->max_stream_data) stream->max_stream_data = new_max;
}

const char *wt_quic_send_state_name(wt_quic_send_state_t state) {
  switch (state) {
    case WT_QUIC_SEND_READY:
      return "ready";
    case WT_QUIC_SEND_SEND:
      return "send";
    case WT_QUIC_SEND_DATA_SENT:
      return "data-sent";
    case WT_QUIC_SEND_DATA_RECVD:
      return "data-received";
    case WT_QUIC_SEND_RESET_SENT:
      return "reset-sent";
    case WT_QUIC_SEND_RESET_RECVD:
      return "reset-received";
    default:
      return "unknown";
  }
}

const char *wt_quic_recv_state_name(wt_quic_recv_state_t state) {
  switch (state) {
    case WT_QUIC_RECV_RECV:
      return "recv";
    case WT_QUIC_RECV_SIZE_KNOWN:
      return "size-known";
    case WT_QUIC_RECV_DATA_RECVD:
      return "data-received";
    case WT_QUIC_RECV_DATA_READ:
      return "data-read";
    case WT_QUIC_RECV_RESET_RECVD:
      return "reset-received";
    case WT_QUIC_RECV_RESET_READ:
      return "reset-read";
    default:
      return "unknown";
  }
}

uint64_t wt_quic_stream_id_index(uint64_t stream_id) { return stream_id >> 2; }

int wt_quic_stream_id_from_client(uint64_t stream_id) { return (stream_id & 0x01U) == 0U; }

int wt_quic_stream_id_is_bidirectional(uint64_t stream_id) { return (stream_id & 0x02U) == 0U; }

uint64_t wt_quic_stream_id_make(int from_client, int bidirectional, uint64_t index) {
  uint64_t id = index << 2;
  if (!from_client) id |= 0x01U;
  if (!bidirectional) id |= 0x02U;
  return id;
}

/* ------------------------------------------------------------------- the table */

void wt_quic_stream_table_init(wt_quic_stream_table_t *table) {
  if (table == NULL) return;
  /* Zeroed: `used` is what says a slot is live, so clearing it is what makes the table empty. */
  memset(table, 0, sizeof(*table));
}

static size_t table_slot(const wt_quic_stream_table_t *table, uint64_t stream_id) {
  size_t i;
  for (i = 0U; i < WT_QUIC_STREAM_TABLE_MAX; i++) {
    if (table->used[i] && table->streams[i].id == stream_id) return i;
  }
  return WT_QUIC_STREAM_TABLE_MAX;
}

wt_status_t wt_quic_stream_table_open(wt_quic_stream_table_t *table, uint64_t stream_id,
                                      int initiated_by_us, uint64_t limit) {
  uint64_t *opened;
  size_t slot = WT_QUIC_STREAM_TABLE_MAX;
  size_t i;
  int bidirectional;

  if (table == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (table_slot(table, stream_id) != WT_QUIC_STREAM_TABLE_MAX) return WT_ERR_STATE;
  bidirectional = wt_quic_stream_id_is_bidirectional(stream_id);
  opened = initiated_by_us ? (bidirectional ? &table->opened_by_us_bidi : &table->opened_by_us_uni)
                           : (bidirectional ? &table->opened_by_peer_bidi : &table->opened_by_peer_uni);
  if (*opened >= limit) return WT_ERR_LIMIT;
  for (i = 0U; i < WT_QUIC_STREAM_TABLE_MAX; i++) {
    if (!table->used[i]) {
      slot = i;
      break;
    }
  }
  if (slot == WT_QUIC_STREAM_TABLE_MAX) {
    /* RECLAIM BEFORE REFUSING. `wt_quic_stream_table_close` requires a stream to be COMPLETE and had no caller
     * anywhere in the library, so a slot was never reused: a connection that opened and finished 32 streams could
     * not open a 33rd, and the peer that finished them got `WT_ERR_LIMIT` for traffic it was entitled to send. An
     * audit found the missing caller. The sweep is here because this is the one place that asks "is there room",
     * and a stream that is complete by definition is not using its room.
     *
     * A RECLAIMED SLOT RELEASES A SLOT, NOT A STREAM NUMBER. The opened counts are not a live-stream gauge: they
     * are the index the next stream number is built from (RFC 9000 section 2.1 numbers streams by how many of
     * their class came before), so they are monotonic and RFC 9000 section 2.1 forbids handing the number out
     * again. Decrementing them here made the caller that reads the count to choose the next number
     * (`wt_quic_connection_open_stream`) rebuild a number a finished stream had already used -- and because the
     * slot was free after this same sweep, `wt_quic_stream_table_open` accepted it rather than reporting the
     * duplicate, so two different streams shared one number. Section 4.6 is the reason the counter cannot simply
     * track the live streams either: `initial_max_streams_*` limits the CUMULATIVE number of streams a peer may
     * open, so the count that is checked against it only ever grows. `close` above already leaves these counts
     * alone; this reclaim must too. */
    for (i = 0U; i < WT_QUIC_STREAM_TABLE_MAX; i++) {
      if (table->used[i] && wt_quic_stream_complete(&table->streams[i])) {
        table->used[i] = 0U;
        table->count--;
        if (slot == WT_QUIC_STREAM_TABLE_MAX) slot = i;
      }
    }
    if (slot == WT_QUIC_STREAM_TABLE_MAX) return WT_ERR_LIMIT;
  }

  wt_quic_stream_init(&table->streams[slot], stream_id, initiated_by_us, bidirectional, 0U, 0U);
  table->used[slot] = 1U;
  (*opened)++;
  table->count++;
  return WT_OK;
}

wt_quic_stream_t *wt_quic_stream_table_find(wt_quic_stream_table_t *table, uint64_t stream_id) {
  size_t slot;
  if (table == NULL) return NULL;
  slot = table_slot(table, stream_id);
  return slot == WT_QUIC_STREAM_TABLE_MAX ? NULL : &table->streams[slot];
}

const wt_quic_stream_t *wt_quic_stream_table_find_const(const wt_quic_stream_table_t *table,
                                                        uint64_t stream_id) {
  size_t slot;
  if (table == NULL) return NULL;
  slot = table_slot(table, stream_id);
  return slot == WT_QUIC_STREAM_TABLE_MAX ? NULL : &table->streams[slot];
}

wt_status_t wt_quic_stream_table_close(wt_quic_stream_table_t *table, uint64_t stream_id) {
  size_t slot;
  if (table == NULL) return WT_ERR_INVALID_ARGUMENT;
  slot = table_slot(table, stream_id);
  if (slot == WT_QUIC_STREAM_TABLE_MAX) return WT_ERR_STATE;
  if (!wt_quic_stream_complete(&table->streams[slot])) return WT_ERR_STATE;
  table->used[slot] = 0U;
  table->count--;
  return WT_OK;
}

wt_quic_stream_t *wt_quic_stream_table_at(wt_quic_stream_table_t *table, size_t index) {
  if (table == NULL || index >= WT_QUIC_STREAM_TABLE_MAX) return NULL;
  return table->used[index] ? &table->streams[index] : NULL;
}

size_t wt_quic_stream_table_count(const wt_quic_stream_table_t *table) {
  return table == NULL ? 0U : table->count;
}

uint64_t wt_quic_stream_table_opened_by_us(const wt_quic_stream_table_t *table, int bidirectional) {
  if (table == NULL) return 0U;
  return bidirectional ? table->opened_by_us_bidi : table->opened_by_us_uni;
}

uint64_t wt_quic_stream_table_opened_by_peer(const wt_quic_stream_table_t *table, int bidirectional) {
  if (table == NULL) return 0U;
  return bidirectional ? table->opened_by_peer_bidi : table->opened_by_peer_uni;
}

