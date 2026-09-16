/* The HTTP/3 endpoint's own streams (Phase 9). */

#include "webtransport/http3/endpoint.h"

#include "webtransport/quic/varint.h"
#include "webtransport/webtransport/framing.h"

static wt_status_t refuse(wt_status_t status, wt_http3_error_t code, wt_http3_error_t *out_error) {
  if (out_error != NULL) *out_error = code;
  return status;
}

void wt_http3_endpoint_init(wt_http3_endpoint_t *endpoint, wt_http3_role_t role) {
  size_t i;

  if (endpoint == NULL) return;
  endpoint->role = role;
  wt_http3_control_init(&endpoint->peer_control);
  endpoint->peer_qpack_encoder_seen = 0;
  endpoint->peer_qpack_decoder_seen = 0;
  endpoint->peer_webtransport_streams_seen = 0;
  endpoint->control_sent = 0;
  endpoint->qpack_encoder_sent = 0;
  endpoint->qpack_decoder_sent = 0;
  endpoint->stream_count = 0U;
  for (i = 0U; i < WT_HTTP3_ENDPOINT_STREAMS_MAX; i++) {
    endpoint->streams[i].stream_id = 0U;
    endpoint->streams[i].kind = WT_HTTP3_ENDPOINT_STREAM_UNKNOWN;
    endpoint->streams[i].type = 0U;
  }
  /* Zero capacity: no dynamic table has been advertised, so a section that needs one is
   * QPACK_DECOMPRESSION_FAILED rather than a guess. */
  wt_qpack_dynamic_init(&endpoint->decoder_table, 0U);
  endpoint->decoder_insert_count = 0U;
  endpoint->decoder_capacity_set = 0;
  endpoint->request_count = 0U;
  for (i = 0U; i < WT_HTTP3_ENDPOINT_REQUESTS_MAX; i++) {
    endpoint->requests[i].stream_id = 0U;
    endpoint->requests[i].locally_opened = 0;
    wt_http3_request_init(&endpoint->requests[i].request);
  }
}

/* ------------------------------------------------ request streams */

static wt_http3_endpoint_request_t *find_request(wt_http3_endpoint_t *endpoint,
                                                 uint64_t stream_id) {
  size_t i;
  for (i = 0U; i < endpoint->request_count; i++) {
    if (endpoint->requests[i].stream_id == stream_id) return &endpoint->requests[i];
  }
  return NULL;
}

static void forget_request(wt_http3_endpoint_t *endpoint, uint64_t stream_id) {
  size_t i;
  for (i = 0U; i < endpoint->request_count; i++) {
    if (endpoint->requests[i].stream_id == stream_id) {
      endpoint->requests[i] = endpoint->requests[endpoint->request_count - 1U];
      endpoint->request_count--;
      return;
    }
  }
}

static wt_status_t track_request(wt_http3_endpoint_t *endpoint, uint64_t stream_id,
                                 int locally_opened) {
  wt_http3_endpoint_request_t *slot;

  if (find_request(endpoint, stream_id) != NULL) {
    /* Tracked twice: the caller lost its place, and applying a stream's frames to two
     * machines would make the state meaningless. */
    return WT_ERR_STATE;
  }
  if (endpoint->request_count >= WT_HTTP3_ENDPOINT_REQUESTS_MAX) {
    /* This endpoint's bound. No error code: nothing the peer did caused it. */
    return WT_ERR_LIMIT;
  }
  slot = &endpoint->requests[endpoint->request_count];
  slot->stream_id = stream_id;
  slot->locally_opened = locally_opened;
  /* CLEARED here, because this is the only place a slot is created: the table hands out slots by reuse, so a
   * request that follows a finished one inherits the finished one's fields unless every field is set. The first
   * version left `response_seen` alone, so the next request's FIRST response was refused as a second one
   * (`WT-ERR_STATE`) whenever the slot had been used before -- a stale byte deciding whether a valid response is
   * accepted, which is the shape of bug that only a reused slot shows. */
  slot->response_seen = 0;
  wt_http3_request_init(&slot->request);
  endpoint->request_count++;
  return WT_OK;
}

wt_status_t wt_http3_endpoint_open_request(wt_http3_endpoint_t *endpoint, uint64_t stream_id,
                                           wt_http3_error_t *out_error) {
  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (endpoint == NULL) return WT_ERR_INVALID_ARGUMENT;

  /* HTTP/3 has no server-initiated request: a server that opens a request stream is
   * building a stream the peer is required to treat as a connection error. */
  if (endpoint->role != WT_HTTP3_ROLE_CLIENT) return WT_ERR_STATE;
  return track_request(endpoint, stream_id, 1);
}

wt_status_t wt_http3_endpoint_on_request_stream(wt_http3_endpoint_t *endpoint, uint64_t stream_id,
                                                wt_http3_error_t *out_error) {
  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (endpoint == NULL) return WT_ERR_INVALID_ARGUMENT;

  /* Section 6.1: a server-initiated bidirectional stream is a connection error for a
   * client, because the only bidirectional streams HTTP/3 defines are requests the client
   * began. */
  if (endpoint->role == WT_HTTP3_ROLE_CLIENT) {
    return refuse(WT_ERR_PROTOCOL, WT_HTTP3_STREAM_CREATION_ERROR, out_error);
  }
  return track_request(endpoint, stream_id, 0);
}

wt_status_t wt_http3_endpoint_set_decoder_capacity(wt_http3_endpoint_t *endpoint, size_t capacity) {
  if (endpoint == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (endpoint->decoder_capacity_set != 0 && endpoint->decoder_table.capacity == capacity) {
    /* The same capacity twice is not a reconfiguration, and treating it as one would let a
     * caller silently discard the peer's insertions. */
    return WT_OK;
  }
  wt_qpack_dynamic_init(&endpoint->decoder_table, capacity);
  endpoint->decoder_insert_count = 0U;
  endpoint->decoder_capacity_set = 1;
  return WT_OK;
}

wt_status_t wt_http3_endpoint_on_request_headers(wt_http3_endpoint_t *endpoint, uint64_t stream_id,
                                                 const uint8_t *payload, size_t length,
                                                 uint8_t *scratch, size_t scratch_capacity,
                                                 wt_http3_message_t *out_message,
                                                 wt_http3_error_t *out_error) {
  wt_status_t status;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (endpoint == NULL || out_message == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (payload == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;

  {
    wt_http3_endpoint_request_t *request = NULL;
    wt_http3_request_state_t before = WT_HTTP3_REQUEST_EXPECT_HEADERS;
    size_t i;

    for (i = 0U; i < endpoint->request_count; i++) {
      if (endpoint->requests[i].stream_id == stream_id) request = &endpoint->requests[i];
    }
    /* Whether this is the request's own section or its trailer is a question about the state
     * BEFORE the frame is applied, so it is read first. */
    if (request != NULL) before = request->request.state;

    /* The FRAME ORDERING question is answered FIRST, and the order is deliberate rather than incidental (an
     * audit filed it as "state advanced before HEADERS validation" and this is the answer): a HEADERS frame that
     * arrived has arrived, whatever its section says, so the machine advances and a section the MESSAGE layer
     * refuses is reported as the message error it is. Doing it the other way round -- decode, then advance --
     * reports a content error where the caller's own ordering is wrong, which the assertion "an untracked stream
     * is a state error" pins: the section in that case decodes fine, and the answer must still be the state
     * error, not a message error. What the reverse order buys -- a DATA frame accepted after a refused HEADERS --
     * is never observable, because the caller aborts the request on the message error.
     *
     * The ordering rule is the request machine's, applied exactly as any other frame's: a
     * HEADERS frame after the trailer is as invalid here as anywhere. */
    status = wt_http3_endpoint_on_request_frame(endpoint, stream_id, WT_HTTP3_FRAME_HEADERS,
                                                out_error);
    if (status != WT_OK) return status;

    status = wt_http3_message_decode(out_message, WT_HTTP3_HEADER_REQUEST, payload, length,
                                     &endpoint->decoder_table,
                                     wt_qpack_max_entries(endpoint->decoder_table.capacity),
                                     endpoint->decoder_insert_count, scratch, scratch_capacity,
                                     out_error);
    if (status != WT_OK) return status;

    if (before != WT_HTTP3_REQUEST_EXPECT_HEADERS) {
      /* Section 4.1: "Trailers MUST NOT contain pseudo-header fields." The decoder has one
       * request shape and one response shape, so a trailer is decoded with the request
       * rules and the pseudo-headers it must NOT carry are refused here -- which is the
       * rule the message layer cannot state for a section it cannot tell from a request. */
      if (out_message->method_length != 0U || out_message->scheme_length != 0U ||
          out_message->path_length != 0U || out_message->authority_length != 0U ||
          out_message->protocol_length != 0U) {
        if (out_error != NULL) *out_error = WT_HTTP3_MESSAGE_ERROR;
        return WT_ERR_PROTOCOL;
      }
    }
    return WT_OK;
  }
}

wt_status_t wt_http3_endpoint_write_headers(wt_http3_endpoint_t *endpoint,
                                            const wt_http3_message_t *message,
                                            uint64_t peer_max_entries, uint8_t *scratch,
                                            size_t scratch_capacity, wt_writer_t *w,
                                            wt_http3_error_t *out_error) {
  wt_writer_t section;
  wt_http3_frame_t frame;
  wt_status_t status;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (endpoint == NULL || message == NULL || scratch == NULL || w == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }

  /* Pass one: measure the section into the caller's scratch. */
  section = wt_writer_init(scratch, scratch_capacity);
  status = wt_http3_message_encode(&section, message, peer_max_entries, out_error);
  if (status != WT_OK) return status;
  if (!wt_writer_ok(&section)) {
    /* The section did not fit: this endpoint's buffer, so no error code and no blame. */
    if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
    return WT_ERR_LIMIT;
  }

  /* Pass two: the frame, now that its length is known rather than guessed. */
  frame = wt_http3_frame_make(WT_HTTP3_FRAME_HEADERS);
  frame.payload = scratch;
  frame.length = wt_writer_offset(&section);
  status = wt_http3_frame_encode(w, &frame);
  if (status != WT_OK && out_error != NULL) *out_error = WT_HTTP3_FRAME_ERROR;
  return status;
}

wt_status_t wt_http3_endpoint_on_response_headers(wt_http3_endpoint_t *endpoint, uint64_t stream_id,
                                                  const uint8_t *payload, size_t length,
                                                  uint8_t *scratch, size_t scratch_capacity,
                                                  wt_http3_message_t *out_message,
                                                  wt_http3_error_t *out_error) {
  wt_http3_endpoint_request_t *request;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (endpoint == NULL || out_message == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (payload == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;

  request = find_request(endpoint, stream_id);
  if (request == NULL) return WT_ERR_STATE;
  if (request->request.ended != 0) return WT_ERR_STATE;
  if (request->response_seen != 0) {
    /* The exchange has one response. A second HEADERS frame here is a trailer, which the request path
     * handles, or a peer that has lost track of the stream -- and neither is a second response. */
    return WT_ERR_STATE;
  }
  /* Marked seen BEFORE the section is decoded, for the reason the request path above records: the frame
   * arrived, and a section the message layer refuses is reported as a message error. A caller that treated that
   * error as survivable and waited for another response would be wrong about the protocol, not about this
   * flag. */
  request->response_seen = 1;
  return wt_http3_message_decode(out_message, WT_HTTP3_HEADER_RESPONSE, payload, length,
                                 &endpoint->decoder_table,
                                 wt_qpack_max_entries(endpoint->decoder_table.capacity),
                                 endpoint->decoder_insert_count, scratch, scratch_capacity,
                                 out_error);
}

wt_status_t wt_http3_endpoint_on_request_frame(wt_http3_endpoint_t *endpoint, uint64_t stream_id,
                                               uint64_t type, wt_http3_error_t *out_error) {
  wt_http3_endpoint_request_t *request;

  if (endpoint == NULL) return WT_ERR_INVALID_ARGUMENT;
  request = find_request(endpoint, stream_id);
  if (request == NULL) {
    if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
    return WT_ERR_STATE;
  }
  return wt_http3_request_on_frame(&request->request, type, out_error);
}

wt_status_t wt_http3_endpoint_on_request_end(wt_http3_endpoint_t *endpoint, uint64_t stream_id,
                                             wt_http3_error_t *out_error) {
  wt_http3_endpoint_request_t *request;
  wt_status_t status;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (endpoint == NULL) return WT_ERR_INVALID_ARGUMENT;
  request = find_request(endpoint, stream_id);
  if (request == NULL) return WT_ERR_STATE;

  status = wt_http3_request_on_end(&request->request, out_error);
  forget_request(endpoint, stream_id);
  return status;
}

wt_status_t wt_http3_endpoint_on_request_reset(wt_http3_endpoint_t *endpoint, uint64_t stream_id) {
  wt_http3_endpoint_request_t *request;

  if (endpoint == NULL) return WT_ERR_INVALID_ARGUMENT;
  request = find_request(endpoint, stream_id);
  if (request == NULL) return WT_ERR_STATE;
  (void)wt_http3_request_on_reset(&request->request);
  forget_request(endpoint, stream_id);
  return WT_OK;
}

wt_status_t wt_http3_endpoint_request_state(const wt_http3_endpoint_t *endpoint, uint64_t stream_id,
                                            wt_http3_request_state_t *out_state) {
  size_t i;

  if (endpoint == NULL || out_state == NULL) return WT_ERR_INVALID_ARGUMENT;
  for (i = 0U; i < endpoint->request_count; i++) {
    if (endpoint->requests[i].stream_id == stream_id) {
      *out_state = endpoint->requests[i].request.state;
      return WT_OK;
    }
  }
  return WT_ERR_STATE;
}

size_t wt_http3_endpoint_request_count(const wt_http3_endpoint_t *endpoint) {
  if (endpoint == NULL) return 0U;
  return endpoint->request_count;
}

static wt_status_t write_type_prefix(uint64_t type, wt_writer_t *w) {
  uint8_t encoded[8];
  size_t length = wt_quic_varint_encode(type, encoded, sizeof(encoded));

  if (length == 0U) return WT_ERR_LIMIT;
  wt_writer_bytes(w, encoded, length);
  /* The writer has a sticky overflow flag rather than a status, so the write has to be
   * asked about: a prefix that did not fit means the stream would start with zero bytes. */
  return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
}

wt_status_t wt_http3_endpoint_write_prefix(wt_http3_endpoint_t *endpoint,
                                           wt_http3_endpoint_stream_kind_t kind, wt_writer_t *w) {
  if (endpoint == NULL || w == NULL) return WT_ERR_INVALID_ARGUMENT;

  switch (kind) {
    case WT_HTTP3_ENDPOINT_STREAM_CONTROL: {
      wt_status_t status;
      if (endpoint->control_sent != 0) return WT_ERR_STATE;
      status = write_type_prefix(WT_HTTP3_STREAM_CONTROL, w);
      /* The latch records a stream that was OPENED. A prefix the writer refused opened
       * nothing, so it must not consume the one control stream the endpoint is allowed. */
      if (status != WT_OK) return status;
      endpoint->control_sent = 1;
      return WT_OK;
    }
    case WT_HTTP3_ENDPOINT_STREAM_QPACK_ENCODER: {
      wt_status_t status;
      if (endpoint->qpack_encoder_sent != 0) return WT_ERR_STATE;
      status = write_type_prefix(WT_HTTP3_STREAM_QPACK_ENCODER, w);
      if (status != WT_OK) return status;
      endpoint->qpack_encoder_sent = 1;
      return WT_OK;
    }
    case WT_HTTP3_ENDPOINT_STREAM_QPACK_DECODER: {
      wt_status_t status;
      if (endpoint->qpack_decoder_sent != 0) return WT_ERR_STATE;
      status = write_type_prefix(WT_HTTP3_STREAM_QPACK_DECODER, w);
      if (status != WT_OK) return status;
      endpoint->qpack_decoder_sent = 1;
      return WT_OK;
    }
    case WT_HTTP3_ENDPOINT_STREAM_PUSH:
    case WT_HTTP3_ENDPOINT_STREAM_WEBTRANSPORT:
    case WT_HTTP3_ENDPOINT_STREAM_UNKNOWN:
      break;
  }
  /* A push stream is not something this endpoint opens, and a WebTransport stream is opened
   * by the session layer with its own prefix (which names the session), not here. */
  return WT_ERR_INVALID_ARGUMENT;
}

static wt_http3_endpoint_stream_t *find_stream(wt_http3_endpoint_t *endpoint, uint64_t stream_id) {
  size_t i;
  for (i = 0U; i < endpoint->stream_count; i++) {
    if (endpoint->streams[i].stream_id == stream_id) return &endpoint->streams[i];
  }
  return NULL;
}

static void forget_stream(wt_http3_endpoint_t *endpoint, uint64_t stream_id) {
  size_t i;
  for (i = 0U; i < endpoint->stream_count; i++) {
    if (endpoint->streams[i].stream_id == stream_id) {
      /* Unordered on purpose: the table is a set of live streams, not a sequence. */
      endpoint->streams[i] = endpoint->streams[endpoint->stream_count - 1U];
      endpoint->stream_count--;
      return;
    }
  }
}

size_t wt_http3_endpoint_stream_count(const wt_http3_endpoint_t *endpoint) {
  if (endpoint == NULL) return 0U;
  return endpoint->stream_count;
}

wt_http3_endpoint_stream_kind_t wt_http3_endpoint_stream_kind(
    const wt_http3_endpoint_t *endpoint, uint64_t stream_id) {
  size_t i;

  if (endpoint == NULL) return WT_HTTP3_ENDPOINT_STREAM_UNKNOWN;
  for (i = 0U; i < endpoint->stream_count; i++) {
    if (endpoint->streams[i].stream_id == stream_id) return endpoint->streams[i].kind;
  }
  return WT_HTTP3_ENDPOINT_STREAM_UNKNOWN;
}

wt_status_t wt_http3_endpoint_on_uni_stream(wt_http3_endpoint_t *endpoint, uint64_t stream_id,
                                            const uint8_t *bytes, size_t length,
                                            size_t *out_consumed,
                                            wt_http3_endpoint_stream_kind_t *out_kind,
                                            wt_http3_error_t *out_error) {
  wt_cursor_t cursor;
  uint64_t type = 0U;
  wt_http3_endpoint_stream_kind_t kind = WT_HTTP3_ENDPOINT_STREAM_UNKNOWN;
  wt_http3_endpoint_stream_t *slot;
  size_t consumed;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (out_consumed != NULL) *out_consumed = 0U;
  if (out_kind != NULL) *out_kind = WT_HTTP3_ENDPOINT_STREAM_UNKNOWN;
  if (endpoint == NULL || bytes == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (find_stream(endpoint, stream_id) != NULL) {
    /* The caller classified this stream already. Re-reading its prefix would mean the
     * caller lost its place, which is a bug on this side of the wire. */
    return WT_ERR_STATE;
  }

  cursor = wt_cursor_init(bytes, length);
  if (wt_quic_varint_decode(&cursor, &type) != WT_OK) {
    /* A stream's type prefix is a varint: one that has not fully arrived is incomplete, and
     * incomplete is not malformed on a stream. The connection is not committed to anything
     * yet, and the caller comes back with more bytes. */
    return WT_ERR_TRUNCATED;
  }
  consumed = length - wt_cursor_remaining(&cursor);
  if (out_consumed != NULL) *out_consumed = consumed;

  /* The draft's WebTransport stream first: it is not HTTP/3's to interpret, and the HTTP/3
   * classifier would call it unknown and have the caller ignore it, which would lose a
   * session's streams one by one. */
  if (type == WT_WEBTRANSPORT_STREAM_UNI) {
    kind = WT_HTTP3_ENDPOINT_STREAM_WEBTRANSPORT;
    endpoint->peer_webtransport_streams_seen = 1;
  } else if (type == WT_HTTP3_STREAM_CONTROL) {
    kind = WT_HTTP3_ENDPOINT_STREAM_CONTROL;
    {
      wt_status_t status = wt_http3_control_peer_opened(&endpoint->peer_control, out_error);
      if (status != WT_OK) return status;
    }
  } else if (type == WT_HTTP3_STREAM_QPACK_ENCODER) {
    if (endpoint->peer_qpack_encoder_seen != 0) {
      /* QPACK section 4.2: one encoder stream per connection. */
      return refuse(WT_ERR_PROTOCOL, WT_HTTP3_STREAM_CREATION_ERROR, out_error);
    }
    endpoint->peer_qpack_encoder_seen = 1;
    kind = WT_HTTP3_ENDPOINT_STREAM_QPACK_ENCODER;
  } else if (type == WT_HTTP3_STREAM_QPACK_DECODER) {
    if (endpoint->peer_qpack_decoder_seen != 0) {
      return refuse(WT_ERR_PROTOCOL, WT_HTTP3_STREAM_CREATION_ERROR, out_error);
    }
    endpoint->peer_qpack_decoder_seen = 1;
    kind = WT_HTTP3_ENDPOINT_STREAM_QPACK_DECODER;
  } else if (type == WT_HTTP3_STREAM_PUSH) {
    /* A push stream is refused deterministically rather than ignored: this build has no
     * MAX_PUSH_ID and WebTransport does not use push, so a client that did not ask for one
     * is H3_ID_ERROR, and a client may not send one at all. Ignoring it would leave a
     * stream the peer believes is delivering a response.
     *
     * The stream is NOT recorded, and that is a memory-safety fix rather than a tidy-up: the first version
     * recorded it here -- before the `stream_count >= MAX` check further down, which this branch returns before
     * reaching -- so a 33rd stream wrote `streams[32]` one past the end of the array and overwrote `stream_count`
     * with a peer-controlled stream ID (an audit grew the count from 32 to 133 with one push, and UBSan named the
     * index). A stream this endpoint is refusing is not a stream it tracks. */
    if (endpoint->role == WT_HTTP3_ROLE_CLIENT) {
      return refuse(WT_ERR_PROTOCOL, WT_HTTP3_ID_ERROR, out_error);
    }
    return refuse(WT_ERR_PROTOCOL, WT_HTTP3_STREAM_CREATION_ERROR, out_error);
  } else {
    /* Section 6.2.1: an unknown type is not an error. The caller is told so it can stop
     * reading the stream, which is what the RFC asks for. */
    kind = WT_HTTP3_ENDPOINT_STREAM_UNKNOWN;
  }

  if (kind == WT_HTTP3_ENDPOINT_STREAM_UNKNOWN) {
    if (out_kind != NULL) *out_kind = kind;
    return WT_OK;
  }

  if (endpoint->stream_count >= WT_HTTP3_ENDPOINT_STREAMS_MAX) {
    /* This endpoint's bound, not the peer's mistake: WT_ERR_LIMIT with no error code, so a
     * caller cannot mistake it for something the peer did. */
    return WT_ERR_LIMIT;
  }
  slot = &endpoint->streams[endpoint->stream_count];
  slot->stream_id = stream_id;
  slot->kind = kind;
  slot->type = type;
  endpoint->stream_count++;

  if (out_kind != NULL) *out_kind = kind;
  return WT_OK;
}

wt_status_t wt_http3_endpoint_on_control_frame(wt_http3_endpoint_t *endpoint, uint64_t type,
                                               wt_http3_error_t *out_error) {
  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (endpoint == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* Section 7.2.7: "A server MUST NOT send a MAX_PUSH_ID frame. A client MUST treat the receipt of a MAX_PUSH_ID
   * frame as a connection error of type H3_FRAME_UNEXPECTED." The control machine owns the rules that are about
   * the CONTROL STREAM; this one is about the endpoint's ROLE, which only the endpoint knows -- and it lived in
   * `wt_http3_frame_allowed`, a table nothing calls, so a client accepted a frame it must refuse. An audit found
   * it. */
  if (type == WT_HTTP3_FRAME_MAX_PUSH_ID && endpoint->role == WT_HTTP3_ROLE_CLIENT) {
    if (out_error != NULL) *out_error = WT_HTTP3_FRAME_UNEXPECTED;
    return WT_ERR_PROTOCOL;
  }
  return wt_http3_control_on_frame(&endpoint->peer_control, type, out_error);
}

wt_status_t wt_http3_endpoint_on_uni_stream_end(wt_http3_endpoint_t *endpoint, uint64_t stream_id,
                                                wt_http3_error_t *out_error) {
  wt_http3_endpoint_stream_kind_t kind;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (endpoint == NULL) return WT_ERR_INVALID_ARGUMENT;

  kind = wt_http3_endpoint_stream_kind(endpoint, stream_id);
  if (kind == WT_HTTP3_ENDPOINT_STREAM_UNKNOWN) {
    /* Either a stream this endpoint never classified, or one it deliberately does not
     * track (an unknown type it was told to ignore). Neither is an error. */
    return WT_OK;
  }
  if (kind == WT_HTTP3_ENDPOINT_STREAM_CONTROL) {
    /* Section 6.2.1: closing the control stream is the error, whether or not SETTINGS had
     * arrived. The control machine owns that judgement. */
    wt_status_t status = wt_http3_control_on_closed(&endpoint->peer_control, out_error);
    forget_stream(endpoint, stream_id);
    return status;
  }
  if (kind == WT_HTTP3_ENDPOINT_STREAM_QPACK_ENCODER ||
      kind == WT_HTTP3_ENDPOINT_STREAM_QPACK_DECODER) {
    /* RFC 9114 section 6.2.1 and RFC 9204 section 4.2: the QPACK encoder and decoder streams are CRITICAL, so
     * closing either one is H3_CLOSED_CRITICAL_STREAM -- not a quiet end. The first version special-cased only
     * the control stream and forgot these two with WT_OK, which left a peer free to close the stream its
     * instructions were arriving on and continue as if the table were still in sync. */
    forget_stream(endpoint, stream_id);
    if (out_error != NULL) *out_error = WT_HTTP3_CLOSED_CRITICAL_STREAM;
    return WT_ERR_PROTOCOL;
  }
  forget_stream(endpoint, stream_id);
  return WT_OK;
}
