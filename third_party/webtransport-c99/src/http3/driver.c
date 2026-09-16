/* Driving an HTTP/3 endpoint from a connection (Phase 9). */

#include <stdio.h>
#include <stdlib.h>

#include "webtransport/http3/driver.h"

#include "webtransport/webtransport/error.h"

#include "webtransport/cursor.h"
#include <string.h>

#include "webtransport/quic/stream.h"
#include "webtransport/webtransport/framing.h"
#include "webtransport/webtransport/session_request.h"
#include "webtransport/quic/varint.h"

/* Defined with the capsule-stream table, used by the frame loop above it: a completed HEADERS frame on a marked
 * CONNECT stream is what turns the rest of that stream into the session's capsules (WT-164). */
static void settle_capsule_stream(wt_http3_driver_t *driver, uint64_t stream_id);

void wt_http3_driver_init(wt_http3_driver_t *driver, wt_http3_endpoint_t *endpoint) {
  if (driver == NULL) return;
  /* Zeroed WHOLE rather than field by field. Naming every field was here so that adding one would force this
   * function to be revisited -- and it did not work: `data_stream_count` was added and left holding whatever the
   * caller's stack had, which is a segfault the moment the receive path asks how many data streams there are.
   * Zeroing the struct makes a forgotten field impossible, and the one field that is not zero is named here. */
  memset(driver, 0, sizeof(*driver));
  driver->endpoint = endpoint;
  /* Named rather than left zeroed, because "no error" is NOT zero in the HTTP/3 error space: WT_HTTP3_NO_ERROR is
   * 0x100, so a zeroed field would read as a refusal with code 0 and the caller would report one. This is the same
   * trap the connection-ID work hit from the other side -- a memset is right for everything whose zero is the
   * default, and wrong for a value whose zero means something else (WT-158). */
  driver->last_error = WT_HTTP3_NO_ERROR;
}

/* Remember a stream whose prefix is settled: this endpoint opened it, or the peer did and the prefix said
 * WebTransport. One table, one rule -- the bytes after the prefix are the session's. `our_prefix_length` is what
 * THIS endpoint wrote on that stream (0 for one the peer opened), kept for the reset section 4.4 requires.
 * `session_id` is the session the prefix named, or `session_id_set` 0 when there is none to name (WT-180). */
static wt_status_t remember_data_stream(wt_http3_driver_t *driver, uint64_t stream_id,
                                        uint64_t our_prefix_length, uint64_t session_id,
                                        int session_id_set) {
  if (driver->data_stream_count >= WT_HTTP3_DRIVER_DATA_STREAMS_MAX) return WT_ERR_LIMIT;
  driver->data_streams[driver->data_stream_count].stream_id = stream_id;
  driver->data_streams[driver->data_stream_count].prefix_length = our_prefix_length;
  driver->data_streams[driver->data_stream_count].session_id = session_id;
  driver->data_streams[driver->data_stream_count].session_id_set = session_id_set != 0 ? 1 : 0;
  driver->data_stream_count++;
  return WT_OK;
}

void wt_http3_driver_set_session_id(wt_http3_driver_t *driver, uint64_t session_id) {
  if (driver == NULL) return;
  driver->session_id = session_id;
  driver->session_id_set = 1;
}

void wt_http3_driver_set_upgrade_token(wt_http3_driver_t *driver, wt_webtransport_upgrade_token_t token) {
  if (driver == NULL) return;
  driver->upgrade_token = token;
}

size_t wt_http3_driver_pending_count(const wt_http3_driver_t *driver) {
  if (driver == NULL) return 0U;
  return driver->pending_count;
}

wt_status_t wt_http3_driver_start_control(wt_http3_driver_t *driver,
                                          const wt_http3_settings_t *settings, uint8_t *scratch,
                                          size_t scratch_capacity, wt_writer_t *w) {
  wt_writer_t payload;
  wt_http3_frame_t frame;
  wt_status_t status;

  if (driver == NULL || driver->endpoint == NULL || settings == NULL || scratch == NULL ||
      w == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }

  /* The prefix first, through the endpoint's once-only rule: a caller that starts a second
   * control stream should find out before any bytes go out. */
  status = wt_http3_endpoint_write_prefix(driver->endpoint, WT_HTTP3_ENDPOINT_STREAM_CONTROL, w);
  if (status != WT_OK) return status;

  /* Pass one: measure the SETTINGS payload into the caller's scratch. */
  payload = wt_writer_init(scratch, scratch_capacity);
  status = wt_http3_settings_encode_payload(&payload, settings);
  if (status != WT_OK) return status;
  if (!wt_writer_ok(&payload)) return WT_ERR_LIMIT;

  /* Pass two: the frame around it, now that its length is known rather than guessed. */
  frame = wt_http3_frame_make(WT_HTTP3_FRAME_SETTINGS);
  frame.payload = scratch;
  frame.length = wt_writer_offset(&payload);
  return wt_http3_frame_encode(w, &frame);
}

wt_status_t wt_http3_driver_start_qpack_stream(wt_http3_driver_t *driver, int encoder,
                                               wt_writer_t *w) {
  if (driver == NULL || driver->endpoint == NULL || w == NULL) return WT_ERR_INVALID_ARGUMENT;
  return wt_http3_endpoint_write_prefix(
      driver->endpoint,
      encoder != 0 ? WT_HTTP3_ENDPOINT_STREAM_QPACK_ENCODER : WT_HTTP3_ENDPOINT_STREAM_QPACK_DECODER,
      w);
}

static wt_http3_driver_pending_t *find_pending(wt_http3_driver_t *driver, uint64_t stream_id) {
  size_t i;
  for (i = 0U; i < driver->pending_count; i++) {
    if (driver->pending[i].stream_id == stream_id) return &driver->pending[i];
  }
  return NULL;
}

static void forget_pending(wt_http3_driver_t *driver, uint64_t stream_id) {
  size_t i;
  for (i = 0U; i < driver->pending_count; i++) {
    if (driver->pending[i].stream_id == stream_id) {
      driver->pending[i] = driver->pending[driver->pending_count - 1U];
      driver->pending_count--;
      return;
    }
  }
}

/* How much of `bytes` completes a varint from `have` bytes already held, or zero when the
 * prefix is still incomplete. The bound is the varint's own length encoding: the first byte's
 * top two bits say how many bytes the whole thing takes, so a prefix can never need more
 * than eight. */
static size_t prefix_needed(const uint8_t *bytes, size_t have) {
  uint8_t first = bytes[0];
  size_t width = (size_t)1U << (first >> 6);
  (void)have;
  return width;
}

/* How many bytes the WHOLE prefix of a unidirectional stream needs, given `have` bytes assembled so far. The
 * prefix is the stream TYPE varint and -- for the draft's WebTransport type -- the SESSION ID varint that
 * follows it (draft-16 section 4.2); the session ID is part of the prefix, not payload, so it is reassembled
 * here exactly as the type is. The answer never exceeds 8 + 8 = 16, which is the pending table's own bound, and
 * a value larger than `have` means more bytes are needed. */
static size_t uni_prefix_length(const uint8_t *bytes, size_t have) {
  size_t type_width;
  wt_cursor_t cursor;
  uint64_t type = 0U;

  if (have == 0U) return 1U; /* wait for the type's first byte */
  type_width = prefix_needed(bytes, have);
  if (have < type_width) return type_width;
  cursor = wt_cursor_init(bytes, type_width);
  if (wt_quic_varint_decode(&cursor, &type) != WT_OK) return type_width;
  if (type != WT_WEBTRANSPORT_STREAM_UNI) return type_width;
  if (have == type_width) return type_width + 1U; /* wait for the session ID's first byte */
  return type_width + prefix_needed(bytes + type_width, have - type_width);
}

wt_status_t wt_http3_driver_on_uni_stream_data(wt_http3_driver_t *driver, uint64_t stream_id,
                                               uint64_t offset, const uint8_t *data, size_t length,
                                               wt_http3_endpoint_stream_kind_t *out_kind,
                                               const uint8_t **out_payload,
                                               size_t *out_payload_length,
                                               size_t *out_prefix_consumed,
                                               wt_http3_error_t *out_error) {
  wt_http3_driver_pending_t *pending;
  /* `have` is the contract: only the first `have` bytes are ever read, and `uni_prefix_length`
   * returns before touching a byte when `have == 0`, so the copy below can be skipped. That is
   * true of the code but was not provable to cppcheck, which reported `uninitvar` at the
   * `uni_prefix_length(prefix, have)` call and failed the gate (`--error-exitcode=1`). Sixteen
   * bytes of zeroing make it provable, and the check still fails on a real uninitialised read. */
  uint8_t prefix[WT_HTTP3_DRIVER_PREFIX_MAX] = {0};
  size_t have = 0U;
  size_t needed;
  size_t take = 0U;
  wt_status_t status;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (out_kind != NULL) *out_kind = WT_HTTP3_ENDPOINT_STREAM_UNKNOWN;
  if (out_payload != NULL) *out_payload = NULL;
  if (out_payload_length != NULL) *out_payload_length = 0U;
  if (out_prefix_consumed != NULL) *out_prefix_consumed = 0U;
  if (driver == NULL || driver->endpoint == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (data == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;

  pending = find_pending(driver, stream_id);
  if (pending != NULL) {
    /* The claim has to hold for the whole stream: a prefix that started at offset zero and
     * resumes at anything else means the caller is not replaying the stream in order. */
    if (offset != pending->length) return WT_ERR_STATE;
    have = pending->length;
  } else if (offset != 0U) {
    /* The stream's first byte was never seen, so nothing here can be classified. This is the
     * caller's accounting, not the peer's. */
    return WT_ERR_STATE;
  }

  if (length == 0U) {
    /* No bytes: nothing to add, nothing classified. A peer may send an empty STREAM frame. */
    return WT_OK;
  }

  /* Hold the prefix in one place while it is read, so the two sources (what was held and
   * what just arrived) look the same to the classifier. */
  if (have > 0U) {
    size_t i;
    for (i = 0U; i < have; i++) prefix[i] = pending->bytes[i];
  }

  /* Assemble the WHOLE prefix -- the stream type and, for the draft's WebTransport type, the session ID that
   * follows it -- before anything is classified. Classifying the type as soon as IT was complete is the defect
   * this loop closes: a frame carrying only the type marked the stream WEBTRANSPORT in the endpoint and then
   * returned WT_ERR_TRUNCATED, so the connection closed with INTERNAL_ERROR for a legal fragmented prefix, and
   * the later frame that completed it saw a stored WEBTRANSPORT kind and handed the session ID's bytes to the
   * session with no session check at all. A QUIC peer may put the type and the session ID in separate STREAM
   * frames, so the held bytes are reassembled here and the type is decoded only when both varints are in. */
  for (;;) {
    needed = uni_prefix_length(prefix, have);
    if (have >= needed) break;
    {
      size_t want = needed - have;
      size_t i;
      if (want > length - take) want = length - take;
      for (i = 0U; i < want; i++) prefix[have + i] = data[take + i];
      have += want;
      take += want;
      if (out_prefix_consumed != NULL) *out_prefix_consumed = take;
      if (want == 0U) break;
    }
  }

  if (have < needed) {
    /* Still incomplete, and incomplete is not malformed on a stream: hold what there is and
     * wait. The table is fixed, so a peer that opens more streams than this has run into the
     * endpoint's bound rather than the protocol's. */
    if (pending == NULL) {
      if (driver->pending_count >= WT_HTTP3_DRIVER_PENDING_MAX) return WT_ERR_LIMIT;
      pending = &driver->pending[driver->pending_count];
      pending->stream_id = stream_id;
      pending->length = 0U;
      driver->pending_count++;
    }
    {
      size_t i;
      for (i = 0U; i < have; i++) pending->bytes[i] = prefix[i];
    }
    pending->length = have;
    return WT_OK;
  }

  /* The prefix is complete, so the local copy above replaces the held bytes: the table entry goes whether or
   * not classification succeeds. */
  if (pending != NULL) forget_pending(driver, stream_id);

  {
    wt_cursor_t type_cursor = wt_cursor_init(prefix, have);
    uint64_t type = 0U;
    uint64_t session_id = 0U;
    int is_webtransport = 0;

    if (wt_quic_varint_decode(&type_cursor, &type) != WT_OK) return WT_ERR_TRUNCATED;
    if (type == WT_WEBTRANSPORT_STREAM_UNI) {
      size_t type_bytes = have - wt_cursor_remaining(&type_cursor);
      wt_cursor_t session_cursor = wt_cursor_init(prefix + type_bytes, have - type_bytes);
      if (wt_quic_varint_decode(&session_cursor, &session_id) != WT_OK) return WT_ERR_TRUNCATED;
      /* The session the prefix names must be THIS session, and the check is here -- BEFORE the endpoint is told
       * the stream's kind -- because classification is what makes a later frame on this stream skip the prefix
       * entirely, and because a stream for somebody else must leave no trace in the endpoint table. Sessions on
       * one connection are mutually hostile: the draft says a stream that names a session this endpoint does
       * not have is H3_ID_ERROR, and a data stream is the easiest place to smuggle one. */
      if (driver->session_id_set != 0 && session_id != driver->session_id) {
        if (out_error != NULL) *out_error = WT_HTTP3_ID_ERROR;
        return WT_ERR_PROTOCOL;
      }
      is_webtransport = 1;
    }

    /* The prefix is settled. Classify it through the endpoint, which applies the rules that belong to a stream
     * of that type -- one control stream, one of each QPACK stream, and the draft's WebTransport type claimed
     * for the layer above. */
    status = wt_http3_endpoint_on_uni_stream(driver->endpoint, stream_id, prefix, have, NULL, out_kind,
                                             out_error);
    if (status != WT_OK) return status;

    if (is_webtransport != 0) {
      /* The stream is remembered, with the session its prefix named (WT-180). A peer's unidirectional
       * WebTransport stream is a data stream like a bidirectional one -- section 4.6's buffering rule and
       * section 6's reset both apply to it -- and the ID in its prefix is what a caller asks for when it needs
       * to know whether the session is known yet. Remembering it also means the bytes that follow are routed as
       * the session's rather than classified a second time. */
      wt_status_t remembered = remember_data_stream(driver, stream_id, 0U, session_id, 1);
      if (remembered != WT_OK) return remembered;
    }
  }

  if (out_payload != NULL) *out_payload = data + take;
  if (out_payload_length != NULL) *out_payload_length = length - take;
  return WT_OK;
}

wt_status_t wt_http3_driver_on_uni_stream_end(wt_http3_driver_t *driver, uint64_t stream_id,
                                              wt_http3_error_t *out_error) {
  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (driver == NULL || driver->endpoint == NULL) return WT_ERR_INVALID_ARGUMENT;

  if (find_pending(driver, stream_id) != NULL) {
    /* The stream ended before its type prefix was complete, so it never became a stream of
     * any type and there is nothing for the endpoint's rules to apply to. */
    forget_pending(driver, stream_id);
    (void)wt_http3_driver_forget_frame(driver, stream_id);
    return WT_OK;
  }
  {
    /* The stream is over, so any frame state it had goes with it: this is one of the two release points (the
     * other is the fin path in `on_stream_bytes`), and without them the eight-slot table filled up and stayed
     * full. */
    wt_status_t status = wt_http3_endpoint_on_uni_stream_end(driver->endpoint, stream_id, out_error);
    (void)wt_http3_driver_forget_frame(driver, stream_id);
    return status;
  }
}

/* ---------------------------------------------- frame boundaries */

static wt_http3_driver_frame_state_t *find_frame_state(wt_http3_driver_t *driver,
                                                       uint64_t stream_id) {
  size_t i;
  for (i = 0U; i < driver->frame_count; i++) {
    if (driver->frames[i].stream_id == stream_id) return &driver->frames[i];
  }
  return NULL;
}

int wt_http3_driver_forget_frame(wt_http3_driver_t *driver, uint64_t stream_id) {
  size_t i;

  if (driver == NULL) return 0;
  for (i = 0U; i < driver->frame_count; i++) {
    if (driver->frames[i].stream_id == stream_id) {
      int was_in_frame = driver->frames[i].in_frame;
      /* RELEASED, not merely cleared. The comment here used to say "the slot is kept while the stream lives",
       * which is right -- and the stream's END is exactly when that stops being true, except that nothing on the
       * request path called this at all: eight streams that began and ended left the table full and the ninth
       * stream was refused WT_ERR_LIMIT, which an audit reproduced with eight empty DATA frames. The table is
       * unordered, so the last entry fills the hole. */
      driver->frames[i] = driver->frames[driver->frame_count - 1U];
      driver->frame_count--;
      return was_in_frame;
    }
  }
  return 0;
}

/* A varint at the start of `bytes`, and how many bytes it took, or zero when it is not yet
 * complete. */
static size_t read_varint(const uint8_t *bytes, size_t length, uint64_t *out) {
  wt_cursor_t c = wt_cursor_init(bytes, length);
  uint64_t value = 0U;
  if (wt_quic_varint_decode(&c, &value) != WT_OK) return 0U;
  *out = value;
  return length - wt_cursor_remaining(&c);
}

wt_status_t wt_http3_driver_on_stream_bytes(wt_http3_driver_t *driver, uint64_t stream_id,
                                            const uint8_t *data, size_t length, int fin,
                                            uint64_t max_frame_bytes,
                                            const wt_http3_driver_sink_t *sink,
                                            wt_http3_error_t *out_error) {
  wt_http3_driver_frame_state_t *state;
  size_t position = 0U;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (driver == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (data == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;

  /* A WebTransport CONNECT stream whose one HEADERS frame has passed carries the SESSION's capsules, not HTTP/3
   * frames (draft-16 section 5): a capsule's type is a varint this parser would read as a frame type and its
   * length as a frame length, and for a flow-control capsule -- an UNKNOWN frame type -- that means the grant is
   * skipped in silence (WT-164). The stream-data sink is where the session's own bytes go, and capsules are
   * exactly that; which stream they belong to is the caller's to know, and it does.
   *
   * The check is here AND at the top of the loop below, and the loop's copy is not redundant: the mark can settle
   * DURING this call, because the sink marks the stream from inside the HEADERS frame's own delivery -- a server
   * marks when it accepts the request, and a client's mark settles as its response is delivered. A single check
   * before the loop would frame the capsules that arrived in the same STREAM frame as that HEADERS. */
  if (wt_http3_driver_is_capsule_stream(driver, stream_id)) {
    if (sink == NULL || sink->on_stream_data == NULL || (length == 0U && fin == 0)) return WT_OK;
    return sink->on_stream_data(sink->context, stream_id, length == 0U ? NULL : data, length, fin);
  }

  state = find_frame_state(driver, stream_id);
  if (state == NULL) {
    if (driver->frame_count >= WT_HTTP3_DRIVER_FRAMES_MAX) return WT_ERR_LIMIT;
    state = &driver->frames[driver->frame_count];
    state->stream_id = stream_id;
    state->header_length = 0U;
    state->in_frame = 0;
    driver->frame_count++;
  }

  while (position < length) {
    if (wt_http3_driver_is_capsule_stream(driver, stream_id)) {
      if (sink == NULL || sink->on_stream_data == NULL) return WT_OK;
      return sink->on_stream_data(sink->context, stream_id, data + position, length - position, fin);
    }
    if (!state->in_frame) {
      /* Fill the header before the payload: the length is what says how much payload to
       * expect, so the header has to be complete first. */
      while (position < length &&
             state->header_length < (size_t)WT_HTTP3_DRIVER_FRAME_HEADER_MAX) {
        state->header[state->header_length] = data[position];
        state->header_length++;
        position++;
        {
          uint64_t type = 0U;
          uint64_t payload_length = 0U;
          size_t type_bytes = read_varint(state->header, state->header_length, &type);
          size_t length_bytes;
          if (type_bytes == 0U) continue;
          length_bytes = read_varint(state->header + type_bytes, state->header_length - type_bytes,
                                     &payload_length);
          if (length_bytes == 0U) continue;
          if (payload_length > max_frame_bytes) {
            /* The peer's declared length is over what this endpoint will deliver, so it is
             * excessive load rather than a buffer to allocate. */
            state->header_length = 0U;
            if (out_error != NULL) *out_error = WT_HTTP3_EXCESSIVE_LOAD;
            return WT_ERR_LIMIT;
          }
          state->type = type;
          state->payload_length = payload_length;
          state->payload_received = 0U;
          state->in_frame = 1;
          /* The header loop appends ONE byte at a time and breaks the moment both varints
           * parse, so header_length == type_bytes + length_bytes here and there is never a
           * remainder to shift down. The clear is still required: the payload path below reads
           * a non-zero header_length as "payload bytes arrived with the header". A copy loop
           * sized by the (always zero) remainder was here and is gone. */
          state->header_length = 0U;
          break;
        }
      }
      if (!state->in_frame) continue;
    }

    /* Inside a frame: deliver what has arrived, up to what is left of it. */
    {
      uint64_t remaining = state->payload_length - state->payload_received;
      size_t available = length - position;
      size_t take = available;
      int last;

      if (state->header_length > 0U) {
        /* Bytes that arrived with the header are the payload's start. */
        size_t from_header = state->header_length;
        if ((uint64_t)from_header >= remaining) from_header = (size_t)remaining;
        if (sink != NULL && sink->on_frame_payload != NULL) {
          last = ((uint64_t)from_header == remaining) ? 1 : 0;
          {
            wt_status_t status = sink->on_frame_payload(sink->context, stream_id, state->type,
                                                       state->header, from_header, last);
            if (status != WT_OK) return status;
          }
        }
        state->payload_received += (uint64_t)from_header;
        state->header_length = 0U;
        if (state->payload_received == state->payload_length) {
          /* The frame is over, so the flag is cleared BEFORE the stream may be settled below. Settling calls
           * `wt_http3_driver_forget_frame`, which RELEASES this stream's slot and fills it with the table's last
           * entry -- another live stream, possibly mid-frame. Writing `state->in_frame = 0` after that would
           * clear THAT stream's flag through the stale pointer and desynchronise its framing. */
          state->in_frame = 0;
          if (state->type == (uint64_t)WT_HTTP3_FRAME_HEADERS) settle_capsule_stream(driver, stream_id);
          continue;
        }
      }

      if ((uint64_t)take > remaining) take = (size_t)remaining;
      if (take > 0U) {
        if (sink != NULL && sink->on_frame_payload != NULL) {
          last = ((uint64_t)take == remaining) ? 1 : 0;
          {
            wt_status_t status = sink->on_frame_payload(sink->context, stream_id, state->type,
                                                       data + position, take, last);
            if (status != WT_OK) return status;
          }
        }
        state->payload_received += (uint64_t)take;
        position += take;
      }
      if (state->payload_received == state->payload_length) {
        if (state->payload_length == 0U && sink != NULL && sink->on_frame_payload != NULL) {
          /* An empty frame is still a frame: report it once, with nothing in it. */
          wt_status_t status = sink->on_frame_payload(sink->context, stream_id, state->type, NULL,
                                                      0U, 1);
          if (status != WT_OK) return status;
        }
        /* Cleared BEFORE the settle, for the reason given at the other completion point above: the settle
         * releases this slot and refills it from the table's tail. */
        state->in_frame = 0;
        if (state->type == (uint64_t)WT_HTTP3_FRAME_HEADERS) settle_capsule_stream(driver, stream_id);
      }
    }
  }

  /* The stream's own end, on a CONNECT stream whose capsules have begun: there is no frame state to report, but
   * the session has to be told the stream is over. This is also where a mark that settled on the last byte of this
   * buffer is honoured -- the loop above has no bytes left to test it with. */
  if (fin != 0 && wt_http3_driver_is_capsule_stream(driver, stream_id)) {
    if (sink == NULL || sink->on_stream_data == NULL) return WT_OK;
    return sink->on_stream_data(sink->context, stream_id, NULL, 0U, fin);
  }

  if (fin != 0) {
    /* The stream ended part way through a frame -- and a partial frame HEADER counts, which is the case a naive
     * implementation misses: one byte of a two-varint header is exactly as incomplete as one byte of a payload.
     * Nothing more is coming, which is what turns the wait into a refusal. Read BEFORE the slot is released,
     * because `state` points into the table. */
    int incomplete = state->in_frame || state->header_length > 0U;
    (void)wt_http3_driver_forget_frame(driver, stream_id);
    if (incomplete) {
      if (out_error != NULL) *out_error = WT_HTTP3_FRAME_ERROR;
      return WT_ERR_TRUNCATED;
    }
  }
  return WT_OK;
}

/* ---------------------------------------------- routing a connection's frames */

/* Whether this endpoint is the one that opens a stream with this ID: the low bit of a QUIC
 * stream ID says which side initiated it (RFC 9000 section 2.1). */
static int stream_is_ours(const wt_http3_endpoint_t *endpoint, uint64_t stream_id) {
  int from_client = wt_quic_stream_id_from_client(stream_id);
  return endpoint->role == WT_HTTP3_ROLE_CLIENT ? from_client : !from_client;
}

static wt_status_t route_quic_frame(wt_http3_driver_t *driver, wt_quic_space_t space,
                                    const wt_quic_frame_t *frame, const wt_http3_driver_sink_t *sink,
                                    uint64_t max_frame_bytes, wt_http3_error_t *out_error);

wt_status_t wt_http3_driver_on_quic_frame(void *context, wt_quic_space_t space,
                                          const wt_quic_frame_t *frame,
                                          const wt_http3_driver_sink_t *sink,
                                          uint64_t max_frame_bytes) {
  wt_http3_driver_t *driver = context;
  wt_status_t status;

  if (driver == NULL || driver->endpoint == NULL || frame == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* Cleared first, so that the code below is this frame's refusal rather than an older one's: the caller reads it
   * only when the status is a failure, and a stale code would name a rule the peer did not break. */
  driver->last_error = WT_HTTP3_NO_ERROR;
  status = route_quic_frame(driver, space, frame, sink, max_frame_bytes, &driver->last_error);
  if (status != WT_OK && driver->connection != NULL && driver->last_error != WT_HTTP3_NO_ERROR) {
    /* The refusal IS an HTTP/3 error, so the peer is told the HTTP/3 code -- in the application form, which is the
     * only form that carries one (RFC 9114 section 8). A refusal WITHOUT an HTTP/3 error is a caller's own bound
     * and leaves the connection's default in force. */
    wt_quic_connection_refuse_application(driver->connection, (uint64_t)driver->last_error, 0U);
  }
  return status;
}

void wt_http3_driver_bind_connection(wt_http3_driver_t *driver, wt_quic_connection_t *connection) {
  if (driver == NULL) return;
  driver->connection = connection;
}

/* The routing itself, with the HTTP/3 error code OUT so that the caller can record it: a refusal is reported to
 * the connection with this code, and an HTTP/3 error is an APPLICATION close (RFC 9114 section 8), which is a
 * different frame from the transport close a bare status would otherwise produce (WT-158). */
static wt_status_t route_quic_frame(wt_http3_driver_t *driver, wt_quic_space_t space,
                                    const wt_quic_frame_t *frame, const wt_http3_driver_sink_t *sink,
                                    uint64_t max_frame_bytes, wt_http3_error_t *out_error) {
  wt_status_t status;

  (void)space;

  /* An if-chain rather than a switch, and the reason is the compiler: -Wswitch-enum requires
   * every enumerator of a switch to be named, and this handler deliberately acts on two of
   * them and ignores the rest. Naming twenty-one no-op cases to satisfy the warning would
   * make the two that matter harder to find, which is the opposite of what the warning is
   * for. */
  if (frame->kind == WT_QUIC_FRAME_KIND_STREAM) {
      uint64_t stream_id = frame->as.stream.id;
      /* A DIAGNOSTIC, gated by WT_HTTP3_STREAM_LOG: the STREAM frames this layer is asked to route, as the
       * connection reported them. Which of the two -- a WebTransport data stream or an HTTP/3 request stream -- is
       * decided below, and "the prefix arrived in two frames" and "the prefix was never recognized" look the same
       * from the caller's side without this (WT-156). */
      {
        const char *stream_log_path = getenv("WT_HTTP3_STREAM_LOG");
        if (stream_log_path != NULL) {
          FILE *stream_log = fopen(stream_log_path, "a");
          if (stream_log != NULL) {
            size_t index;
            fprintf(stream_log, "stream=%llu offset=%llu has_length=%d length=%llu fin=%d bytes=",
                    (unsigned long long)stream_id, (unsigned long long)frame->as.stream.offset,
                    frame->as.stream.has_length, (unsigned long long)frame->as.stream.length,
                    frame->as.stream.fin);
            for (index = 0U; index < frame->as.stream.length && index < 48U; index++) {
              fprintf(stream_log, "%02x", frame->as.stream.data[index]);
            }
            fprintf(stream_log, "\n");
            (void)fclose(stream_log);
          }
        }
      }
      /* A WebTransport data stream THIS endpoint opened: the prefix went out with the first bytes, so what
       * arrives on it is the responder's payload. Classifying it again is what the peer's echo tripped over --
       * its first bytes were read as a signal value, refused, and the refusal closed the connection (WT-135). */
      if (wt_http3_driver_is_data_stream(driver, stream_id)) {
        if (sink == NULL || sink->on_stream_data == NULL) return WT_OK;
        return sink->on_stream_data(sink->context, stream_id, frame->as.stream.data,
                                    frame->as.stream.length, frame->as.stream.fin);
      }
      if (stream_is_ours(driver->endpoint, stream_id) &&
          !wt_quic_stream_id_is_bidirectional(stream_id)) {
        /* A UNIDIRECTIONAL stream this endpoint opened: the peer cannot write on it, so there is nothing to
         * route. A BIDIRECTIONAL one is a different matter, and dropping it here (which this code did) is why
         * the response never reached the caller: the peer's frames on a stream WE opened ARE the response, and
         * RFC 9114 section 4.1 gives the two directions of one exchange their own HEADERS frames on that same
         * stream. The connection delivered the frame, the chain called this layer, and this early return said
         * there was nothing to route. */
        return WT_OK;
      }
      if (wt_quic_stream_id_is_bidirectional(stream_id)) {
        /* A bidirectional stream is a request stream -- and there are TWO ways this layer meets one. If the
         * endpoint already tracks it, this endpoint OPENED it and what arrives is the RESPONSE, which is the
         * other direction of the same exchange (RFC 9114 section 4.1 gives each direction its own HEADERS).
         * If it does not, the peer initiated it and it becomes a request stream now.
         *
         * Getting this wrong is what stopped the response from arriving: routing a tracked stream through
         * `on_request_stream` again is refused as a duplicate, and the refusal ABORTED the frame routing, so
         * the response was never reported to the caller at all. */
        wt_http3_request_state_t state = WT_HTTP3_REQUEST_EXPECT_HEADERS;
        int tracked = wt_http3_endpoint_request_state(driver->endpoint, stream_id, &state) == WT_OK;

        /* A prefix that arrives in PIECES: hold the bytes in the same pending table the unidirectional path
         * uses, and when enough arrive either deliver what follows the prefix to the session or REPLAY the held
         * bytes into the request path (which must see a stream's first bytes, not the middle of them).
         *
         * The held-bytes lookup comes FIRST, and that is the whole bug the counter found: a CONTINUATION frame
         * has a non-zero offset, so a condition of "offset zero" skipped the assembly for exactly the frame that
         * would have completed the prefix -- and the frame then fell into the request path, where its middle
         * bytes were read as a stream's first and refused. */
        {
          wt_http3_driver_pending_t *held = find_pending(driver, stream_id);
          if (!tracked && (held != NULL || (frame->as.stream.offset == 0U && frame->as.stream.length > 0U))) {
          uint8_t assembled[WT_HTTP3_DRIVER_PREFIX_MAX];
          size_t have = 0U;
          size_t copied;
          wt_http3_bidi_start_kind_t start_kind = WT_HTTP3_BIDI_START_REQUEST;
          size_t consumed = 0U;
          uint64_t prefix_session = 0U;
          wt_status_t classified;

          if (held != NULL) {
            have = held->length;
            memcpy(assembled, held->bytes, have);
          }
          copied = frame->as.stream.length;
          if (copied > (size_t)WT_HTTP3_DRIVER_PREFIX_MAX - have) {
            copied = (size_t)WT_HTTP3_DRIVER_PREFIX_MAX - have;
          }
          memcpy(assembled + have, frame->as.stream.data, copied);
          classified = wt_http3_driver_classify_bidi_start(assembled, have + copied, &start_kind, &prefix_session,
                                                           &consumed);
          if (classified == WT_ERR_TRUNCATED) {
            if (held == NULL) {
              if (driver->pending_count >= WT_HTTP3_DRIVER_PENDING_MAX) {
                      return WT_ERR_LIMIT;
              }
              held = &driver->pending[driver->pending_count];
              held->stream_id = stream_id;
              held->length = 0U;
              driver->pending_count++;
            }
            memcpy(held->bytes, assembled, have + copied);
            held->length = have + copied;
            return WT_OK;
          }
          if (held != NULL) forget_pending(driver, stream_id);
          if (classified == WT_OK && start_kind == WT_HTTP3_BIDI_START_WEBTRANSPORT) {
            if (driver->session_id_set != 0 && prefix_session != driver->session_id) return WT_ERR_PROTOCOL;
            /* The prefix is settled: recorded so that the bytes the peer sends NEXT on this stream are the
             * session's payload rather than a second prefix or an HTTP/3 frame. A peer may send the prefix and
             * its message in separate STREAM frames -- which is what aioquic does, and what this tree's own
             * client never did, so the omission was invisible (WT-156). */
            {
              /* The prefix that was just classified is the PEER's: this endpoint has written nothing on this
               * stream, so what a later reset may commit to is zero bytes. */
              wt_status_t remembered = remember_data_stream(driver, stream_id, 0U, prefix_session, 1);
              if (remembered != WT_OK) return remembered;
            }
            if (sink != NULL && sink->on_stream_data != NULL) {
              size_t from_assembled = have + copied - consumed;
              if (from_assembled > 0U) {
                wt_status_t delivered = sink->on_stream_data(sink->context, stream_id, assembled + consumed,
                                                             from_assembled,
                                                             frame->as.stream.length > copied
                                                                 ? 0
                                                                 : frame->as.stream.fin);
                if (delivered != WT_OK) return delivered;
              }
              if (frame->as.stream.length > copied) {
                return sink->on_stream_data(sink->context, stream_id, frame->as.stream.data + copied,
                                            frame->as.stream.length - copied, frame->as.stream.fin);
              }
            }
            return WT_OK;
          }
          if (have > 0U) {
            wt_status_t replayed = wt_http3_driver_on_stream_bytes(driver, stream_id, assembled, have, 0,
                                                                   max_frame_bytes, sink, NULL);
              if (replayed != WT_OK) return replayed;
          }
        }
        }

        if (!tracked) {
          status = wt_http3_endpoint_on_request_stream(driver->endpoint, stream_id, out_error);
          if (status != WT_OK) return status;
        }
        return wt_http3_driver_on_stream_bytes(driver, stream_id, frame->as.stream.data,
                                               frame->as.stream.length, frame->as.stream.fin,
                                               max_frame_bytes, sink, out_error);
      }

      /* A peer-initiated unidirectional stream: its type prefix first, then whichever of the
       * two kinds of bytes the type says follow it. */
      {
        wt_http3_endpoint_stream_kind_t kind = WT_HTTP3_ENDPOINT_STREAM_UNKNOWN;
        const uint8_t *payload = NULL;
        size_t payload_length = 0U;
        size_t consumed = 0U;
        int finished_prefix;

        /* A stream the endpoint already classified does not carry a prefix any more. */
        kind = wt_http3_endpoint_stream_kind(driver->endpoint, stream_id);
        finished_prefix = kind != WT_HTTP3_ENDPOINT_STREAM_UNKNOWN;
        if (finished_prefix) {
          payload = frame->as.stream.data;
          payload_length = frame->as.stream.length;
        } else {
          status = wt_http3_driver_on_uni_stream_data(driver, stream_id, frame->as.stream.offset,
                                                      frame->as.stream.data, frame->as.stream.length,
                                                      &kind, &payload, &payload_length, &consumed,
                                                      out_error);
          if (status != WT_OK) return status;
          if (kind == WT_HTTP3_ENDPOINT_STREAM_UNKNOWN) {
            /* Either the prefix is still incomplete -- the bytes are held in the pending
             * table and nothing is routed -- or it named a stream type this build does not
             * know, which section 6.2.1 says to stop reading. Both drop the bytes. */
            return WT_OK;
          }
        }

        if (kind == WT_HTTP3_ENDPOINT_STREAM_WEBTRANSPORT) {
          /* The session's own stream: its bytes are not HTTP/3 frames, so they go to the
           * session as they are. */
          if (sink != NULL && sink->on_stream_data != NULL && payload_length > 0U) {
            return sink->on_stream_data(sink->context, stream_id, payload, payload_length,
                                        frame->as.stream.fin);
          }
          return WT_OK;
        }

        /* HTTP/3's own streams carry frames, and the frame boundary is reassembled for them
         * the same way it is for a request stream. */
        if (payload_length > 0U || frame->as.stream.fin != 0) {
          status = wt_http3_driver_on_stream_bytes(driver, stream_id, payload, payload_length,
                                                   frame->as.stream.fin, max_frame_bytes, sink,
                                                   out_error);
          if (status != WT_OK) return status;
        }
        if (frame->as.stream.fin != 0) {
          return wt_http3_driver_on_uni_stream_end(driver, stream_id, out_error);
        }
        return WT_OK;
      }
  }
  if (frame->kind == WT_QUIC_FRAME_KIND_DATAGRAM) {
    /* The payload is the session's, and this layer does not look inside it: what a datagram
     * means is the draft's framing, which the session layer reads. */
    if (sink != NULL && sink->on_datagram != NULL) {
      return sink->on_datagram(sink->context, frame->as.datagram.data, frame->as.datagram.length);
    }
    return WT_OK;
  }
  /* Every other kind belongs to the connection or to nobody here. */
  return WT_OK;
}

/* ---------------------------------------------- sending through a transport */

wt_status_t wt_http3_driver_start_own_streams(wt_http3_driver_t *driver,
                                              const wt_http3_driver_transport_t *transport,
                                              const wt_http3_settings_t *settings, uint64_t now) {
  uint64_t stream_id = 0U;
  wt_writer_t w;
  size_t length;
  wt_status_t status;
  int i;

  if (driver == NULL || driver->endpoint == NULL || transport == NULL ||
      transport->open_stream == NULL || transport->send_stream == NULL || settings == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }

  /* Each stream is BUILT before it is opened, and that order is deliberate: the once-per-
   * connection rules are applied while the bytes are built, so a second call refuses without
   * opening a stream it would then have nothing to send on. An orphaned stream is a stream the
   * peer sees and this endpoint cannot explain.
   *
   * The frame goes into the first half of the scratch and its payload into the second, so the
   * two cannot overlap while a payload is smaller than half the buffer -- which the SETTINGS
   * encoder's own bound enforces. */
  w = wt_writer_init(driver->scratch, sizeof(driver->scratch) / 2U);
  status = wt_http3_driver_start_control(driver, settings,
                                         driver->scratch + sizeof(driver->scratch) / 2U,
                                         sizeof(driver->scratch) / 2U, &w);
  if (status != WT_OK) return status;
  length = wt_writer_offset(&w);
  status = transport->open_stream(transport->context, 0, &stream_id, now);
  if (status != WT_OK) return status;
  status = transport->send_stream(transport->context, stream_id, driver->scratch, length, 0, now);
  if (status != WT_OK) return status;

  /* The two QPACK streams: their prefixes alone, since what follows on them is the QPACK
   * layer's to write. */
  for (i = 0; i < 2; i++) {
    w = wt_writer_init(driver->scratch, sizeof(driver->scratch) / 2U);
    status = wt_http3_driver_start_qpack_stream(driver, i == 0 ? 1 : 0, &w);
    if (status != WT_OK) return status;
    length = wt_writer_offset(&w);
    status = transport->open_stream(transport->context, 0, &stream_id, now);
    if (status != WT_OK) return status;
    status = transport->send_stream(transport->context, stream_id, driver->scratch, length, 0, now);
    if (status != WT_OK) return status;
  }
  return WT_OK;
}

wt_status_t wt_http3_driver_open_request(wt_http3_driver_t *driver,
                                         const wt_http3_driver_transport_t *transport, uint64_t now,
                                         uint64_t *out_stream_id, wt_http3_error_t *out_error) {
  uint64_t stream_id = 0U;
  wt_status_t status;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (driver == NULL || driver->endpoint == NULL || transport == NULL ||
      transport->open_stream == NULL || out_stream_id == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }

  /* A request stream is BIDIRECTIONAL and this endpoint initiates it: HTTP/3 has no server-initiated
   * request, which the endpoint's own rule also enforces. */
  status = transport->open_stream(transport->context, 1, &stream_id, now);
  if (status != WT_OK) return status;
  status = wt_http3_endpoint_open_request(driver->endpoint, stream_id, out_error);
  if (status != WT_OK) return status;
  *out_stream_id = stream_id;
  return WT_OK;
}

wt_status_t wt_http3_driver_send_message(wt_http3_driver_t *driver,
                                         const wt_http3_driver_transport_t *transport,
                                         uint64_t stream_id, const wt_http3_message_t *message,
                                         uint64_t peer_max_entries, int fin, uint64_t now) {
  wt_writer_t w;
  wt_status_t status;

  if (driver == NULL || driver->endpoint == NULL || transport == NULL ||
      transport->send_stream == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  /* The section is measured into its own buffer and the frame written into `scratch`: writing the frame over the
   * bytes the section was measured into is an overlapping `memcpy` (the writer moves the section down by the
   * frame header's length inside the same buffer), which is undefined behaviour and was ASan's
   * `memcpy-param-overlap` in an audit. */
  w = wt_writer_init(driver->scratch, sizeof(driver->scratch));
  status = wt_http3_endpoint_write_headers(driver->endpoint, message, peer_max_entries,
                                           driver->section, sizeof(driver->section), &w, NULL);
  if (status != WT_OK) return status;
  /* Retained on the way out: a probe timeout may have to send these very bytes again (WT-135). */
  driver->request_stream_id = stream_id;
  driver->request_length = wt_writer_offset(&w);
  driver->request_retained = 1;
  return transport->send_stream(transport->context, stream_id, driver->scratch,
                                wt_writer_offset(&w), fin, now);
}

wt_status_t wt_http3_driver_open_data_stream(wt_http3_driver_t *driver,
                                             const wt_http3_driver_transport_t *transport,
                                             int unidirectional, const uint8_t *data, size_t length,
                                             int fin, uint64_t now, uint64_t *out_stream_id) {
  uint8_t framed[WT_HTTP3_DRIVER_PREFIX_MAX + WT_HTTP3_DRIVER_SCRATCH];
  wt_writer_t w = wt_writer_init(framed, sizeof(framed));
  uint64_t stream_id = 0U;
  size_t prefix_length = 0U;
  wt_status_t status;

  if (driver == NULL || driver->endpoint == NULL || transport == NULL ||
      transport->open_stream == NULL || transport->send_stream == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (data == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (length > (size_t)WT_HTTP3_DRIVER_SCRATCH) return WT_ERR_LIMIT;
  /* The session must be known before a stream names it: a prefix that names no session is one the peer has to
   * refuse, which is a worse outcome than saying so here. */
  if (driver->session_id_set == 0) return WT_ERR_STATE;
  /* Section 6: an endpoint that has learned its session is over "MUST NOT send any new datagrams or open any new
   * streams", so a data stream after that point is refused by name rather than sent into a session nobody has. */
  if (driver->session_ended != 0) return WT_ERR_STATE;
  if (driver->data_stream_count >= WT_HTTP3_DRIVER_DATA_STREAMS_MAX) return WT_ERR_LIMIT;

  if (wt_webtransport_stream_prefix_write(&w, unidirectional, driver->session_id) != WT_OK) {
    return WT_ERR_LIMIT;
  }
  /* Where the prefix ended, taken HERE rather than recomputed: it is the offset before the payload is written,
   * and it is what a later reset of this stream has to commit to (section 4.4). */
  prefix_length = wt_writer_offset(&w);
  wt_writer_bytes(&w, data, length);
  if (!wt_writer_ok(&w)) return WT_ERR_LIMIT;

  /* Opened before the prefix is written, because which class of stream the ID is comes from the transport and
   * the prefix's type has to agree with it. */
  status = transport->open_stream(transport->context, unidirectional ? 0 : 1, &stream_id, now);
  if (status != WT_OK) return status;
  if (wt_quic_stream_id_is_bidirectional(stream_id) != (unidirectional ? 0 : 1)) {
    /* The transport handed back a stream of the other class, so this prefix would describe the wrong thing. */
    return WT_ERR_STATE;
  }

  status = transport->send_stream(transport->context, stream_id, framed, wt_writer_offset(&w), fin, now);
  if (status != WT_OK) return status;

  /* Remembered only once the bytes are away: an owner that has not sent anything yet would make the receive
   * path treat the stream as this endpoint's data stream while the peer has no reason to know it exists. The
   * prefix length recorded is the one THIS endpoint wrote, which is what a reset has to commit to. */
  status = remember_data_stream(driver, stream_id, (uint64_t)prefix_length, driver->session_id,
                                driver->session_id_set);
  if (status != WT_OK) return status;
  if (out_stream_id != NULL) *out_stream_id = stream_id;
  return WT_OK;
}


/* Whether THIS endpoint has a SEND half on `stream_id`, so that a RESET_STREAM is a frame the stream machine
 * can apply: every bidirectional stream, and a unidirectional one this endpoint opened. A peer's unidirectional
 * stream is receive-only here, which is why section 4.6 says "RESET_STREAM and/or STOP_SENDING" rather than both:
 * for that stream the rejection IS the STOP_SENDING. */
static int has_send_half(const wt_quic_connection_t *connection, uint64_t stream_id) {
  if (wt_quic_stream_id_is_bidirectional(stream_id) != 0) return 1;
  return wt_quic_stream_id_from_client(stream_id) ==
         (connection->config.role == WT_QUIC_ROLE_CLIENT);
}

/* And the other half: whether this endpoint can receive on it, so a STOP_SENDING is a frame the peer will
 * understand as "stop sending on this stream". */
static int has_receive_half(const wt_quic_connection_t *connection, uint64_t stream_id) {
  if (wt_quic_stream_id_is_bidirectional(stream_id) != 0) return 1;
  return wt_quic_stream_id_from_client(stream_id) !=
         (connection->config.role == WT_QUIC_ROLE_CLIENT);
}

wt_status_t wt_http3_driver_end_session_streams(wt_http3_driver_t *driver, uint64_t now,
                                                size_t *out_streams_ended) {
  size_t index;
  size_t ended = 0U;
  wt_status_t first_refusal = WT_OK;

  if (out_streams_ended != NULL) *out_streams_ended = 0U;
  if (driver == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* A reset is a frame, so this needs the connection a refusal would be stated to as well (WT-158, WT-159): the
   * driver is where the code is known and the connection is where the frame goes. */
  if (driver->connection == NULL) return WT_ERR_STATE;

  /* The session is over from here on, whatever happens below: section 6's "MUST NOT send any new datagrams or
   * open any new streams" is about the session's state, not about how many resets succeeded. */
  driver->session_ended = 1;

  for (index = 0U; index < driver->data_stream_count; index++) {
    uint64_t stream_id = driver->data_streams[index].stream_id;
    uint64_t send_offset = 0U;
    uint64_t reliable_size;
    int skip_reset = 0;
    wt_status_t status;

    /* Section 4.4: a reset of a WebTransport stream commits to at least the prefix that associates it, and a
     * commitment past what has been sent is a FRAME_ENCODING_ERROR at the peer -- so the commitment is the prefix
     * capped by the bytes actually sent. A stream the peer opened has no prefix of ours (0), and one this endpoint
     * wrote a prefix on has sent at least those bytes. */
    reliable_size = driver->data_streams[index].prefix_length;
    if (wt_quic_connection_stream_send_offset(driver->connection, stream_id, &send_offset) == WT_OK &&
        reliable_size > send_offset) {
      reliable_size = send_offset;
    }

    /* A stream whose SEND half is already finished -- or already reset -- has nothing for section 6 to abort, and
     * the stream machine refuses a second reset with WT_ERR_STATE. Skipping it is not a refusal: a stream this
     * endpoint ended cleanly is ended, and the peer learns the session is gone from the streams that were still
     * open (and from this endpoint's own close). Its RECEIVE half is still aborted below, which is the half the
     * section speaks about separately. */
    {
      const wt_quic_stream_t *stream = wt_quic_connection_stream(driver->connection, stream_id);
      if (stream != NULL && (stream->send_state == WT_QUIC_SEND_DATA_SENT ||
                             stream->send_state == WT_QUIC_SEND_DATA_RECVD ||
                             stream->send_state == WT_QUIC_SEND_RESET_SENT ||
                             stream->send_state == WT_QUIC_SEND_RESET_RECVD)) {
        skip_reset = 1;
      }
    }

    status = (skip_reset != 0 || has_send_half(driver->connection, stream_id) == 0)
                 ? WT_OK
                 : wt_quic_connection_reset_stream_at(driver->connection, stream_id,
                                                      WT_WEBTRANSPORT_ERROR_SESSION_GONE, reliable_size,
                                                      now);
    if (status == WT_OK) {
      if (skip_reset == 0) ended++;
    } else if (first_refusal == WT_OK) {
      /* A stream the connection no longer has, one this endpoint may not reset, or a peer that did not negotiate
       * the reliable reset: the first refusal is reported and the rest of the streams are still attempted, because
       * one stream that cannot be reset does not excuse the others. */
      first_refusal = status;
    }

    /* And the receive side: "abort reading on the receive side". A STOP_SENDING the connection refuses (a stream
     * this endpoint cannot receive on, or one already ended) is not an error of this call. */
    if (has_receive_half(driver->connection, stream_id) != 0) {
      (void)wt_quic_connection_stop_sending(driver->connection, stream_id,
                                            WT_WEBTRANSPORT_ERROR_SESSION_GONE, now);
    }

    /* Forgotten, so that a second call is a no-op rather than a second reset of a stream that is already gone. */
    driver->data_streams[index].stream_id = 0U;
    driver->data_streams[index].prefix_length = 0U;
  }
  driver->data_stream_count = 0U;
  if (out_streams_ended != NULL) *out_streams_ended = ended;
  return first_refusal;
}

int wt_http3_driver_session_ended(const wt_http3_driver_t *driver) {
  return driver != NULL ? driver->session_ended : 0;
}

wt_http3_error_t wt_http3_driver_last_error(const wt_http3_driver_t *driver) {
  if (driver == NULL) return WT_HTTP3_NO_ERROR;
  return driver->last_error;
}

int wt_http3_driver_is_data_stream(const wt_http3_driver_t *driver, uint64_t stream_id) {
  size_t index;

  if (driver == NULL) return 0;
  for (index = 0U; index < driver->data_stream_count; index++) {
    if (driver->data_streams[index].stream_id == stream_id) return 1;
  }
  return 0;
}

wt_status_t wt_http3_driver_data_stream_session_id(const wt_http3_driver_t *driver, uint64_t stream_id,
                                                   uint64_t *out_session_id) {
  size_t index;

  if (driver == NULL) return WT_ERR_INVALID_ARGUMENT;
  for (index = 0U; index < driver->data_stream_count; index++) {
    if (driver->data_streams[index].stream_id != stream_id) continue;
    if (driver->data_streams[index].session_id_set == 0) {
      /* Remembered, but this endpoint wrote the prefix and has not been told which session it serves, so
       * there is no ID to hand back. Saying so is the difference between "not mine" and "not known yet". */
      return WT_ERR_STATE;
    }
    if (out_session_id != NULL) *out_session_id = driver->data_streams[index].session_id;
    return WT_OK;
  }
  return WT_ERR_CLOSED;
}

/* Forget one remembered data stream. The table's order carries no meaning -- it is walked to reset what it
 * holds -- so the last entry fills the hole rather than everything after it moving down. */
static void forget_data_stream(wt_http3_driver_t *driver, size_t index) {
  driver->data_streams[index] = driver->data_streams[driver->data_stream_count - 1U];
  driver->data_stream_count--;
}

wt_status_t wt_http3_driver_reject_data_stream(wt_http3_driver_t *driver, uint64_t stream_id,
                                               uint64_t error_code, uint64_t now) {
  size_t index;
  uint64_t send_offset = 0U;
  uint64_t reliable_size;
  wt_status_t status;

  if (driver == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (driver->connection == NULL) return WT_ERR_STATE;

  for (index = 0U; index < driver->data_stream_count; index++) {
    if (driver->data_streams[index].stream_id == stream_id) break;
  }
  if (index == driver->data_stream_count) return WT_ERR_CLOSED;

  /* The Reliable Size rule of section 4.4, exactly as `wt_http3_driver_end_session_streams` applies it: a
   * reset commits to at least the prefix that associates the stream with the session, capped by what has
   * actually been sent, because a commitment past the send offset is a FRAME_ENCODING_ERROR at the peer. */
  reliable_size = driver->data_streams[index].prefix_length;
  if (wt_quic_connection_stream_send_offset(driver->connection, stream_id, &send_offset) == WT_OK &&
      reliable_size > send_offset) {
    reliable_size = send_offset;
  }

  /* The section's "RESET_STREAM and/or STOP_SENDING": whichever halves this endpoint has. A peer's
   * unidirectional stream has no send half here, so the rejection is its STOP_SENDING, and asking the
   * connection for a reset would be WT_ERR_STATE rather than a frame. */
  status = has_send_half(driver->connection, stream_id) != 0
               ? wt_quic_connection_reset_stream_at(driver->connection, stream_id, error_code,
                                                    reliable_size, now)
               : WT_OK;

  /* And the receive side: the peer's bytes on a stream this endpoint is rejecting are refused too. A stream
   * this endpoint cannot receive on refuses the STOP_SENDING, and that is not this call's error. */
  if (has_receive_half(driver->connection, stream_id) != 0) {
    (void)wt_quic_connection_stop_sending(driver->connection, stream_id, error_code, now);
  }

  forget_data_stream(driver, index);
  return status;
}

/* The marked CONNECT stream `stream_id`, or NULL. One function looks a stream up, so the mark and the question
 * cannot disagree about what "settled" means. */
static wt_http3_driver_capsule_stream_t *find_capsule_stream(wt_http3_driver_t *driver, uint64_t stream_id) {
  size_t index;

  if (driver == NULL) return NULL;
  for (index = 0U; index < driver->capsule_stream_count; index++) {
    if (driver->capsule_streams[index].stream_id == stream_id) return &driver->capsule_streams[index];
  }
  return NULL;
}

wt_status_t wt_http3_driver_mark_capsule_stream(wt_http3_driver_t *driver, uint64_t stream_id,
                                                int headers_pending) {
  wt_http3_driver_capsule_stream_t *marked;

  if (driver == NULL) return WT_ERR_INVALID_ARGUMENT;
  marked = find_capsule_stream(driver, stream_id);
  if (marked != NULL) {
    /* Already marked: the FIRST mark's state stands. A caller that marked a stream whose HEADERS frame has not
     * arrived and then marks it again has not made that frame arrive sooner, and letting the second call settle it
     * early would route the HEADERS frame itself as capsules. */
    return WT_OK;
  }
  if (driver->capsule_stream_count >= WT_HTTP3_DRIVER_CAPSULE_STREAMS_MAX) return WT_ERR_LIMIT;
  driver->capsule_streams[driver->capsule_stream_count].stream_id = stream_id;
  driver->capsule_streams[driver->capsule_stream_count].headers_pending = headers_pending != 0 ? 1 : 0;
  driver->capsule_stream_count++;
  return WT_OK;
}

int wt_http3_driver_is_capsule_stream(const wt_http3_driver_t *driver, uint64_t stream_id) {
  size_t index;

  if (driver == NULL) return 0;
  for (index = 0U; index < driver->capsule_stream_count; index++) {
    if (driver->capsule_streams[index].stream_id == stream_id) {
      return driver->capsule_streams[index].headers_pending == 0 ? 1 : 0;
    }
  }
  return 0;
}

/* The HEADERS frame of a marked CONNECT stream has been delivered: the stream's capsules begin here. Any frame
 * state is dropped with the mark, because a stream that is no longer framed must not keep a half-read frame header
 * that a later capsule byte would be appended to. */
static void settle_capsule_stream(wt_http3_driver_t *driver, uint64_t stream_id) {
  wt_http3_driver_capsule_stream_t *marked = find_capsule_stream(driver, stream_id);

  if (marked == NULL || marked->headers_pending == 0) return;
  marked->headers_pending = 0;
  (void)wt_http3_driver_forget_frame(driver, stream_id);
}

wt_status_t wt_http3_driver_resend_request(wt_http3_driver_t *driver,
                                           const wt_http3_driver_transport_t *transport, uint64_t now) {
  if (driver == NULL || transport == NULL || transport->send_stream == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (driver->request_retained == 0 || driver->request_length == 0U) return WT_ERR_STATE;
  return transport->send_stream(transport->context, driver->request_stream_id, driver->scratch,
                                driver->request_length, 0, now);
}

wt_status_t wt_http3_driver_classify_bidi_start(const uint8_t *bytes, size_t length,
                                                wt_http3_bidi_start_kind_t *out_kind,
                                                uint64_t *out_session_id, size_t *out_consumed) {
  wt_cursor_t cursor;
  uint64_t type = 0U;
  uint64_t session_id = 0U;
  size_t type_bytes;
  size_t session_bytes;

  if (out_kind == NULL || out_session_id == NULL || out_consumed == NULL) return WT_ERR_INVALID_ARGUMENT;
  *out_kind = WT_HTTP3_BIDI_START_REQUEST;
  *out_session_id = 0U;
  *out_consumed = 0U;
  if (bytes == NULL) return length == 0U ? WT_OK : WT_ERR_INVALID_ARGUMENT;

  cursor = wt_cursor_init(bytes, length);
  if (wt_quic_varint_decode(&cursor, &type) != WT_OK) {
    /* Not even the type has arrived. On a stream that is a wait: the caller comes back with more bytes. */
    return WT_ERR_TRUNCATED;
  }
  if (type != WT_WEBTRANSPORT_STREAM_BIDI) {
    /* An HTTP/3 request stream, and the type varint it "has" is really the first byte of a QPACK prefix. */
    return WT_OK;
  }
  type_bytes = length - wt_cursor_remaining(&cursor);
  if (wt_quic_varint_decode(&cursor, &session_id) != WT_OK) return WT_ERR_TRUNCATED;
  session_bytes = (length - type_bytes) - wt_cursor_remaining(&cursor);
  *out_kind = WT_HTTP3_BIDI_START_WEBTRANSPORT;
  *out_session_id = session_id;
  *out_consumed = type_bytes + session_bytes;
  return WT_OK;
}

wt_status_t wt_http3_driver_open_session_stream(wt_http3_driver_t *driver,
                                                const wt_http3_driver_transport_t *transport,
                                                const wt_http3_settings_t *settings, uint64_t now,
                                                uint64_t *out_stream_id, wt_http3_error_t *out_error) {
  uint64_t stream_id = 0U;
  wt_status_t status;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (driver == NULL || driver->endpoint == NULL || transport == NULL || settings == NULL ||
      out_stream_id == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }

  /* The endpoint's own streams first: a CONNECT cannot be interpreted by a peer that has not been told what
   * this endpoint's SETTINGS say, and the QPACK streams are what any field section may reference. */
  status = wt_http3_driver_start_own_streams(driver, transport, settings, now);
  if (status != WT_OK) return status;

  status = wt_http3_driver_open_request(driver, transport, now, &stream_id, out_error);
  if (status != WT_OK) return status;
  /* The session IS the request stream (draft-16 section 3.2: "Session IDs are derived from the stream ID of the
   * CONNECT stream"), so this is where the driver learns which session it serves -- and a prefix it writes or
   * reads names this stream's ID. Nothing else sets it, which is why a data stream had no session to name. */
  wt_http3_driver_set_session_id(driver, stream_id);
  /* And it is a WebTransport CONNECT stream from here on: the RESPONSE is the one HTTP/3 frame still to come on
   * it, and everything the server sends after that is a capsule on this session (WT-164). Marked BEFORE the
   * request goes out, because the answer can arrive in the very next packet and a mark made after sending would
   * race it. */
  status = wt_http3_driver_mark_capsule_stream(driver, stream_id, 1);
  if (status != WT_OK) return status;

  *out_stream_id = stream_id;
  return WT_OK;
}

wt_status_t wt_http3_driver_send_session_request(wt_http3_driver_t *driver,
                                                 const wt_http3_driver_transport_t *transport,
                                                 uint64_t stream_id, const char *authority,
                                                 const char *path, uint64_t peer_max_entries, uint64_t now,
                                                 wt_http3_error_t *out_error) {
  wt_http3_message_t request;
  const char *token;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (driver == NULL || driver->endpoint == NULL || transport == NULL || authority == NULL ||
      path == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }

  /* The extended CONNECT of draft-16 section 3.1, as the fields the request line needs: CONNECT with a
   * :protocol, over https, for the authority and path the caller named. */
  memset(&request, 0, sizeof(request));
  request.type = WT_HTTP3_HEADER_REQUEST;
  request.method = (const uint8_t *)"CONNECT";
  request.method_length = 7U;
  request.scheme = (const uint8_t *)"https";
  request.scheme_length = 5U;
  request.authority = (const uint8_t *)authority;
  request.authority_length = strlen(authority);
  request.path = (const uint8_t *)path;
  request.path_length = strlen(path);
  /* The token is this endpoint's choice, not a constant: draft-16 section 3.2 names `webtransport-h3` and that
   * is the default, while a peer that predates the rename needs the pre-draft `webtransport` and gets it only
   * when the caller selected it (see `wt_http3_driver_set_upgrade_token`). */
  token = wt_webtransport_upgrade_token_value(driver->upgrade_token);
  request.protocol = (const uint8_t *)token;
  request.protocol_length = strlen(token);

  return wt_http3_driver_send_message(driver, transport, stream_id, &request, peer_max_entries, 0, now);
}

wt_status_t wt_http3_driver_start_session(wt_http3_driver_t *driver,
                                          const wt_http3_driver_transport_t *transport,
                                          const wt_http3_settings_t *settings, const char *authority,
                                          const char *path, uint64_t peer_max_entries, uint64_t now,
                                          uint64_t *out_stream_id, wt_http3_error_t *out_error) {
  uint64_t stream_id = 0U;
  wt_status_t status;

  if (out_stream_id == NULL) return WT_ERR_INVALID_ARGUMENT;
  status = wt_http3_driver_open_session_stream(driver, transport, settings, now, &stream_id, out_error);
  if (status != WT_OK) return status;
  status = wt_http3_driver_send_session_request(driver, transport, stream_id, authority, path,
                                                peer_max_entries, now, out_error);
  if (status != WT_OK) return status;
  *out_stream_id = stream_id;
  return WT_OK;
}

wt_status_t wt_http3_driver_send_response(wt_http3_driver_t *driver,
                                          const wt_http3_driver_transport_t *transport,
                                          uint64_t stream_id, uint32_t status, uint64_t peer_max_entries,
                                          int fin, uint64_t now) {
  wt_http3_message_t response;

  if (driver == NULL || driver->endpoint == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* The request stream this answers IS the session (draft-16 section 3.2), so answering it is also the moment
   * this endpoint knows which session its own streams and prefixes name. */
  wt_http3_driver_set_session_id(driver, stream_id);
  memset(&response, 0, sizeof(response));
  response.type = WT_HTTP3_HEADER_RESPONSE;
  response.status = (uint64_t)status;
  response.has_status = 1;
  return wt_http3_driver_send_message(driver, transport, stream_id, &response, peer_max_entries, fin,
                                      now);
}

wt_status_t wt_http3_driver_send_datagram(wt_http3_driver_t *driver,
                                          const wt_http3_driver_transport_t *transport,
                                          const uint8_t *data, size_t length) {
  if (driver == NULL || transport == NULL || transport->send_datagram == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (data == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;
  /* Section 6's other MUST NOT: a datagram is not sent into a session that is over. */
  if (driver->session_ended != 0) return WT_ERR_STATE;
  return transport->send_datagram(transport->context, data, length);
}
