/* QUIC frame codec. See webtransport/quic/frame.h. */

#include "webtransport/quic/frame.h"

#include "webtransport/checked.h"

#include <string.h>
#include "webtransport/endian.h"

/* A length field is a varint, so it can name more bytes than any packet can
 * hold. Every one of them is refused against the cursor's remaining bytes before
 * it is used: a length of 2^40 becomes WT_ERR_TRUNCATED rather than a walk off
 * the end.
 *
 * THE STATUS IS THE FAILURE SIGNAL AND NOT THE POINTER. A zero-length field is
 * legitimate -- an empty CRYPTO frame is what a handshake sends when it has
 * nothing to add -- and `wt_cursor_bytes(c, 0)` returns NULL for a cursor whose
 * buffer is NULL, which is a valid empty range. A caller testing the pointer
 * would refuse that frame; a caller testing the status does not. */
static wt_status_t wt_quic_take(wt_cursor_t *c, uint64_t length,
                                const uint8_t **out, size_t *out_length) {
  size_t narrowed = 0U;
  if (out == NULL || out_length == NULL) return WT_ERR_INVALID_ARGUMENT;
  *out = NULL;
  *out_length = 0U;
  if (wt_checked_narrow_u64_to_size(length, &narrowed) != WT_OK) {
    return WT_ERR_OVERFLOW;
  }
  if (narrowed > wt_cursor_remaining(c)) return WT_ERR_TRUNCATED;
  *out = wt_cursor_bytes(c, narrowed);
  *out_length = narrowed;
  return WT_OK;
}

/* A varint read that turns the cursor's own failure into the codec's status. */
static wt_status_t wt_quic_read_varint(wt_cursor_t *c, uint64_t *out) {
  if (wt_quic_varint_decode(c, out) != WT_OK) return WT_ERR_TRUNCATED;
  return WT_OK;
}

wt_quic_frame_t wt_quic_frame_make(wt_quic_frame_type_t kind) {
  wt_quic_frame_t frame;
  /* The WHOLE structure is zeroed, not just the fields the kind uses. A frame is
   * a public value type, so a caller may copy it, compare it or log it, and all
   * three read every byte -- including the union members the kind does not
   * define, which are indeterminate if the structure is not cleared.
   *
   * The first version of this cleared one byte, on the reasoning that a reader
   * only touches the member its kind names. That is true of this library's own
   * reader and false of everything else, and it failed as a Release-only test
   * failure: a copy of a mostly-uninitialized union was optimized differently at
   * -O2 than at -O0, and a frame that encoded correctly in the debug build
   * overflowed its writer in the release build. */
  memset(&frame, 0, sizeof(frame));
  frame.kind = kind;
  return frame;
}

const char *wt_quic_frame_kind_name(wt_quic_frame_type_t kind) {
  switch (kind) {
    case WT_QUIC_FRAME_KIND_PADDING:
      return "padding";
    case WT_QUIC_FRAME_KIND_PING:
      return "ping";
    case WT_QUIC_FRAME_KIND_ACK:
      return "ack";
    case WT_QUIC_FRAME_KIND_RESET_STREAM:
      return "reset-stream";
    case WT_QUIC_FRAME_KIND_STOP_SENDING:
      return "stop-sending";
    case WT_QUIC_FRAME_KIND_CRYPTO:
      return "crypto";
    case WT_QUIC_FRAME_KIND_NEW_TOKEN:
      return "new-token";
    case WT_QUIC_FRAME_KIND_STREAM:
      return "stream";
    case WT_QUIC_FRAME_KIND_MAX_DATA:
      return "max-data";
    case WT_QUIC_FRAME_KIND_MAX_STREAM_DATA:
      return "max-stream-data";
    case WT_QUIC_FRAME_KIND_MAX_STREAMS:
      return "max-streams";
    case WT_QUIC_FRAME_KIND_DATA_BLOCKED:
      return "data-blocked";
    case WT_QUIC_FRAME_KIND_STREAM_DATA_BLOCKED:
      return "stream-data-blocked";
    case WT_QUIC_FRAME_KIND_STREAMS_BLOCKED:
      return "streams-blocked";
    case WT_QUIC_FRAME_KIND_NEW_CONNECTION_ID:
      return "new-connection-id";
    case WT_QUIC_FRAME_KIND_RETIRE_CONNECTION_ID:
      return "retire-connection-id";
    case WT_QUIC_FRAME_KIND_PATH_CHALLENGE:
      return "path-challenge";
    case WT_QUIC_FRAME_KIND_PATH_RESPONSE:
      return "path-response";
    case WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_TRANSPORT:
      return "connection-close";
    case WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_APPLICATION:
      return "connection-close-application";
    case WT_QUIC_FRAME_KIND_HANDSHAKE_DONE:
      return "handshake-done";
    case WT_QUIC_FRAME_KIND_RESET_STREAM_AT:
      return "reset-stream-at";
    case WT_QUIC_FRAME_KIND_DATAGRAM:
      return "datagram";
    default:
      return "unknown";
  }
}

static wt_status_t wt_quic_decode_fail(wt_quic_error_t *out_error,
                                       wt_quic_error_t code) {
  if (out_error != NULL) *out_error = code;
  return WT_ERR_PROTOCOL;
}

wt_status_t wt_quic_frame_decode(wt_cursor_t *c, wt_quic_frame_t *out,
                                 wt_quic_error_t *out_error) {
  uint64_t type = 0U;
  size_t type_size = 0U;

  if (c == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;

  /* Cleared for the same reason wt_quic_frame_make clears: a parsed frame is a
   * value a caller may copy, and every byte of it has to be defined for that to
   * be safe. The cost is one memset of about 150 bytes per frame, against a
   * packet decryption that is orders of magnitude more expensive. */
  memset(out, 0, sizeof(*out));

  /* RFC 9000 section 12.4: the frame type MUST be minimally encoded. A type
   * written in four bytes that fits in one is a PROTOCOL_VIOLATION, and the only
   * way to see it is to compare the encoding's size against the value. The
   * decoder is asked for both, so no second parse is needed. */
  if (wt_quic_varint_decode_sized(c, &type, &type_size) != WT_OK) {
    return WT_ERR_TRUNCATED;
  }
  if (!wt_quic_varint_is_minimal(type, type_size)) {
    return wt_quic_decode_fail(out_error, WT_QUIC_PROTOCOL_VIOLATION);
  }

  switch (type) {
    case WT_QUIC_FRAME_PADDING:
      out->kind = WT_QUIC_FRAME_KIND_PADDING;
      return WT_OK;

    case WT_QUIC_FRAME_PING:
      out->kind = WT_QUIC_FRAME_KIND_PING;
      return WT_OK;

    case WT_QUIC_FRAME_ACK:
    case WT_QUIC_FRAME_ACK_ECN: {
      uint64_t range_count = 0U;
      wt_status_t status;
      out->kind = WT_QUIC_FRAME_KIND_ACK;
      status = wt_quic_read_varint(c, &out->as.ack.largest);
      if (status != WT_OK) return status;
      status = wt_quic_read_varint(c, &out->as.ack.delay);
      if (status != WT_OK) return status;
      status = wt_quic_read_varint(c, &range_count);
      if (status != WT_OK) return status;
      status = wt_quic_read_varint(c, &out->as.ack.first_range);
      if (status != WT_OK) return status;
      out->as.ack.range_count = range_count;
      /* The ranges are kept as the bytes they arrived as. `wt_cursor_rest`
       * hands over what is left, and the count of ranges is what a reader uses
       * to know how much of it belongs to this frame: an ACK is followed by
       * other frames, so the parser cannot simply consume the rest. */
      {
        size_t available = 0U;
        const uint8_t *rest = wt_cursor_rest(c, &available);
        size_t consumed = 0U;
        uint64_t i;
        for (i = 0U; i < range_count; i++) {
          wt_cursor_t probe = wt_cursor_init(rest + consumed, available - consumed);
          uint64_t gap = 0U;
          uint64_t length = 0U;
          if (wt_quic_read_varint(&probe, &gap) != WT_OK ||
              wt_quic_read_varint(&probe, &length) != WT_OK) {
            return WT_ERR_TRUNCATED;
          }
          /* Accumulated, not assigned: the probe's offset is relative to its
           * own start, so assigning it made the length the size of the LAST
           * range rather than of all of them -- an ACK with three ranges
           * reported a two-byte range list and the rest of the ranges read as
           * truncated. */
          consumed += probe.offset;
        }
        out->as.ack.ranges = rest;
        out->as.ack.ranges_len = consumed;
        (void)wt_cursor_skip(c, consumed);
      }
      if (type == WT_QUIC_FRAME_ACK_ECN) {
        out->as.ack.has_ecn = 1;
        if (wt_quic_read_varint(c, &out->as.ack.ect0) != WT_OK ||
            wt_quic_read_varint(c, &out->as.ack.ect1) != WT_OK ||
            wt_quic_read_varint(c, &out->as.ack.ecn_ce) != WT_OK) {
          return WT_ERR_TRUNCATED;
        }
      }
      return WT_OK;
    }

    case WT_QUIC_FRAME_RESET_STREAM:
      out->kind = WT_QUIC_FRAME_KIND_RESET_STREAM;
      if (wt_quic_read_varint(c, &out->as.reset_stream.id) != WT_OK ||
          wt_quic_read_varint(c, &out->as.reset_stream.application_error_code) !=
              WT_OK ||
          wt_quic_read_varint(c, &out->as.reset_stream.final_size) != WT_OK) {
        return WT_ERR_TRUNCATED;
      }
      return WT_OK;

    case WT_QUIC_FRAME_RESET_STREAM_AT:
      out->kind = WT_QUIC_FRAME_KIND_RESET_STREAM_AT;
      if (wt_quic_read_varint(c, &out->as.reset_stream_at.id) != WT_OK ||
          wt_quic_read_varint(
              c, &out->as.reset_stream_at.application_error_code) != WT_OK ||
          wt_quic_read_varint(c, &out->as.reset_stream_at.final_size) != WT_OK ||
          wt_quic_read_varint(c, &out->as.reset_stream_at.reliable_size) !=
              WT_OK) {
        return WT_ERR_TRUNCATED;
      }
      /* The reliable size is the part of the stream that survives the reset, so
       * it cannot exceed the final size: nothing beyond the end of a stream can
       * be delivered. The Swift mirror refuses this at parse time too. */
      if (out->as.reset_stream_at.reliable_size >
          out->as.reset_stream_at.final_size) {
        return wt_quic_decode_fail(out_error, WT_QUIC_FRAME_ENCODING_ERROR);
      }
      return WT_OK;

    case WT_QUIC_FRAME_STOP_SENDING:
      out->kind = WT_QUIC_FRAME_KIND_STOP_SENDING;
      if (wt_quic_read_varint(c, &out->as.stop_sending.id) != WT_OK ||
          wt_quic_read_varint(c, &out->as.stop_sending.application_error_code) !=
              WT_OK) {
        return WT_ERR_TRUNCATED;
      }
      return WT_OK;

    case WT_QUIC_FRAME_CRYPTO:
      out->kind = WT_QUIC_FRAME_KIND_CRYPTO;
      if (wt_quic_read_varint(c, &out->as.crypto.offset) != WT_OK) {
        return WT_ERR_TRUNCATED;
      }
      {
        uint64_t length = 0U;
        if (wt_quic_read_varint(c, &length) != WT_OK) return WT_ERR_TRUNCATED;
        /* One take: it advances the cursor, so calling it twice would read past
         * the field the first call already consumed. */
        return wt_quic_take(c, length, &out->as.crypto.data,
                            &out->as.crypto.length);
      }

    case WT_QUIC_FRAME_NEW_TOKEN: {
      uint64_t length = 0U;
      wt_status_t status;
      out->kind = WT_QUIC_FRAME_KIND_NEW_TOKEN;
      if (wt_quic_read_varint(c, &length) != WT_OK) return WT_ERR_TRUNCATED;
      /* RFC 9000 section 19.7: a token must not be empty, because an empty one
       * buys the peer nothing and is a way to make an endpoint allocate. */
      if (length == 0U) {
        return wt_quic_decode_fail(out_error, WT_QUIC_FRAME_ENCODING_ERROR);
      }
      status = wt_quic_take(c, length, &out->as.new_token.token,
                            &out->as.new_token.length);
      out->as.new_token.token_length = length;
      return status;
    }

    case WT_QUIC_FRAME_MAX_DATA:
      out->kind = WT_QUIC_FRAME_KIND_MAX_DATA;
      if (wt_quic_read_varint(c, &out->as.max_data.maximum) != WT_OK) {
        return WT_ERR_TRUNCATED;
      }
      return WT_OK;

    case WT_QUIC_FRAME_MAX_STREAM_DATA:
      out->kind = WT_QUIC_FRAME_KIND_MAX_STREAM_DATA;
      if (wt_quic_read_varint(c, &out->as.max_stream_data.id) != WT_OK ||
          wt_quic_read_varint(c, &out->as.max_stream_data.maximum) != WT_OK) {
        return WT_ERR_TRUNCATED;
      }
      return WT_OK;

    case WT_QUIC_FRAME_MAX_STREAMS_BIDI:
    case WT_QUIC_FRAME_MAX_STREAMS_UNI:
      out->kind = WT_QUIC_FRAME_KIND_MAX_STREAMS;
      out->as.max_streams.direction =
          (type == WT_QUIC_FRAME_MAX_STREAMS_BIDI) ? WT_QUIC_STREAM_BIDIRECTIONAL
                                                   : WT_QUIC_STREAM_UNIDIRECTIONAL;
      if (wt_quic_read_varint(c, &out->as.max_streams.maximum) != WT_OK) {
        return WT_ERR_TRUNCATED;
      }
      /* RFC 9000 section 19.11: a stream count above 2^60 is a
       * FRAME_ENCODING_ERROR, because the stream identifier arithmetic around it
       * would not fit. */
      if (out->as.max_streams.maximum > (UINT64_C(1) << 60)) {
        return wt_quic_decode_fail(out_error, WT_QUIC_FRAME_ENCODING_ERROR);
      }
      return WT_OK;

    case WT_QUIC_FRAME_DATA_BLOCKED:
      out->kind = WT_QUIC_FRAME_KIND_DATA_BLOCKED;
      if (wt_quic_read_varint(c, &out->as.data_blocked.maximum) != WT_OK) {
        return WT_ERR_TRUNCATED;
      }
      return WT_OK;

    case WT_QUIC_FRAME_STREAM_DATA_BLOCKED:
      out->kind = WT_QUIC_FRAME_KIND_STREAM_DATA_BLOCKED;
      if (wt_quic_read_varint(c, &out->as.stream_data_blocked.id) != WT_OK ||
          wt_quic_read_varint(c, &out->as.stream_data_blocked.offset) != WT_OK) {
        return WT_ERR_TRUNCATED;
      }
      return WT_OK;

    case WT_QUIC_FRAME_STREAMS_BLOCKED_BIDI:
    case WT_QUIC_FRAME_STREAMS_BLOCKED_UNI:
      out->kind = WT_QUIC_FRAME_KIND_STREAMS_BLOCKED;
      out->as.streams_blocked.direction =
          (type == WT_QUIC_FRAME_STREAMS_BLOCKED_BIDI)
              ? WT_QUIC_STREAM_BIDIRECTIONAL
              : WT_QUIC_STREAM_UNIDIRECTIONAL;
      if (wt_quic_read_varint(c, &out->as.streams_blocked.maximum) != WT_OK) {
        return WT_ERR_TRUNCATED;
      }
      if (out->as.streams_blocked.maximum > (UINT64_C(1) << 60)) {
        return wt_quic_decode_fail(out_error, WT_QUIC_FRAME_ENCODING_ERROR);
      }
      return WT_OK;

    case WT_QUIC_FRAME_NEW_CONNECTION_ID: {
      uint8_t length = 0U;
      out->kind = WT_QUIC_FRAME_KIND_NEW_CONNECTION_ID;
      if (wt_quic_read_varint(c, &out->as.new_connection_id.sequence) != WT_OK ||
          wt_quic_read_varint(c, &out->as.new_connection_id.retire_prior_to) !=
              WT_OK) {
        return WT_ERR_TRUNCATED;
      }
      /* RFC 9000 section 19.15: the length is a single byte, and "Values less
       * than 1 and greater than 20 are invalid and MUST be treated as a
       * connection error of type FRAME_ENCODING_ERROR." */
      {
        const uint8_t *at = wt_cursor_bytes(c, 1U);
        if (at == NULL) return WT_ERR_TRUNCATED;
        length = at[0];
      }
      if (length < 1U || length > WT_QUIC_MAX_CONNECTION_ID_LENGTH) {
        return wt_quic_decode_fail(out_error, WT_QUIC_FRAME_ENCODING_ERROR);
      }
      out->as.new_connection_id.connection_id =
          wt_cursor_bytes(c, (size_t)length);
      if (out->as.new_connection_id.connection_id == NULL) {
        return WT_ERR_TRUNCATED;
      }
      out->as.new_connection_id.connection_id_length = (size_t)length;
      out->as.new_connection_id.stateless_reset_token =
          wt_cursor_bytes(c, WT_QUIC_STATELESS_RESET_TOKEN_LENGTH);
      if (out->as.new_connection_id.stateless_reset_token == NULL) {
        return WT_ERR_TRUNCATED;
      }
      /* RFC 9000 section 19.15: a retire_prior_to above the sequence is a
       * FRAME_ENCODING_ERROR, since it would retire the connection ID the frame
       * is issuing. */
      if (out->as.new_connection_id.retire_prior_to >
          out->as.new_connection_id.sequence) {
        return wt_quic_decode_fail(out_error, WT_QUIC_FRAME_ENCODING_ERROR);
      }
      return WT_OK;
    }

    case WT_QUIC_FRAME_RETIRE_CONNECTION_ID:
      out->kind = WT_QUIC_FRAME_KIND_RETIRE_CONNECTION_ID;
      if (wt_quic_read_varint(c, &out->as.retire_connection_id.sequence) !=
          WT_OK) {
        return WT_ERR_TRUNCATED;
      }
      return WT_OK;

    case WT_QUIC_FRAME_PATH_CHALLENGE:
      out->kind = WT_QUIC_FRAME_KIND_PATH_CHALLENGE;
      out->as.path_challenge.data = wt_cursor_bytes(c, WT_QUIC_PATH_CHALLENGE_LENGTH);
      if (out->as.path_challenge.data == NULL) return WT_ERR_TRUNCATED;
      return WT_OK;

    case WT_QUIC_FRAME_PATH_RESPONSE:
      out->kind = WT_QUIC_FRAME_KIND_PATH_RESPONSE;
      out->as.path_response.data = wt_cursor_bytes(c, WT_QUIC_PATH_CHALLENGE_LENGTH);
      if (out->as.path_response.data == NULL) return WT_ERR_TRUNCATED;
      return WT_OK;

    case WT_QUIC_FRAME_CONNECTION_CLOSE_TRANSPORT:
    case WT_QUIC_FRAME_CONNECTION_CLOSE_APPLICATION: {
      uint64_t reason_length = 0U;
      wt_status_t status;
      out->kind = (type == WT_QUIC_FRAME_CONNECTION_CLOSE_TRANSPORT)
                      ? WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_TRANSPORT
                      : WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_APPLICATION;
      if (wt_quic_read_varint(c, &out->as.connection_close.error_code) != WT_OK) {
        return WT_ERR_TRUNCATED;
      }
      if (type == WT_QUIC_FRAME_CONNECTION_CLOSE_TRANSPORT) {
        out->as.connection_close.has_frame_type = 1;
        if (wt_quic_read_varint(c, &out->as.connection_close.frame_type) !=
            WT_OK) {
          return WT_ERR_TRUNCATED;
        }
      } else {
        out->as.connection_close.has_frame_type = 0;
        out->as.connection_close.frame_type = 0U;
      }
      if (wt_quic_read_varint(c, &reason_length) != WT_OK) {
        return WT_ERR_TRUNCATED;
      }
      status = wt_quic_take(c, reason_length, &out->as.connection_close.reason,
                            &out->as.connection_close.reason_length);
      return status;
    }

    case WT_QUIC_FRAME_HANDSHAKE_DONE:
      out->kind = WT_QUIC_FRAME_KIND_HANDSHAKE_DONE;
      return WT_OK;

    case WT_QUIC_FRAME_DATAGRAM:
    case WT_QUIC_FRAME_DATAGRAM_LEN: {
      out->kind = WT_QUIC_FRAME_KIND_DATAGRAM;
      if (type == WT_QUIC_FRAME_DATAGRAM) {
        /* Without the length the datagram runs to the end of the packet, so
         * there can be no frame after it. RFC 9221 section 4. */
        size_t remaining = 0U;
        const uint8_t *rest = wt_cursor_rest(c, &remaining);
        if (rest == NULL && remaining != 0U) return WT_ERR_TRUNCATED;
        out->as.datagram.data = rest;
        out->as.datagram.length = remaining;
        if (remaining != 0U) (void)wt_cursor_skip(c, remaining);
        return WT_OK;
      }
      {
        uint64_t length = 0U;
        if (wt_quic_read_varint(c, &length) != WT_OK) return WT_ERR_TRUNCATED;
        return wt_quic_take(c, length, &out->as.datagram.data,
                            &out->as.datagram.length);
      }
    }

    default:
      /* The STREAM range is not a `case` list because its low three bits are
       * flags: the type says both what the frame is and how its body is
       * laid out. */
      if (type >= WT_QUIC_FRAME_STREAM_BASE && type <= WT_QUIC_FRAME_STREAM_LAST) {
        uint8_t flags = (uint8_t)(type & 0x07U);
        uint64_t length = 0U;
        out->kind = WT_QUIC_FRAME_KIND_STREAM;
        out->as.stream.has_offset = (flags & WT_QUIC_STREAM_FLAG_OFF) ? 1 : 0;
        out->as.stream.has_length = (flags & WT_QUIC_STREAM_FLAG_LEN) ? 1 : 0;
        out->as.stream.fin = (flags & WT_QUIC_STREAM_FLAG_FIN) ? 1 : 0;
        out->as.stream.offset = 0U;
        if (wt_quic_read_varint(c, &out->as.stream.id) != WT_OK) {
          return WT_ERR_TRUNCATED;
        }
        if (out->as.stream.has_offset) {
          if (wt_quic_read_varint(c, &out->as.stream.offset) != WT_OK) {
            return WT_ERR_TRUNCATED;
          }
        }
        if (out->as.stream.has_length) {
          if (wt_quic_read_varint(c, &length) != WT_OK) return WT_ERR_TRUNCATED;
          return wt_quic_take(c, length, &out->as.stream.data,
                              &out->as.stream.length);
        }
        {
          size_t remaining = 0U;
          const uint8_t *rest = wt_cursor_rest(c, &remaining);
          out->as.stream.data = rest;
          out->as.stream.length = remaining;
          if (remaining != 0U) (void)wt_cursor_skip(c, remaining);
        }
        return WT_OK;
      }
      /* RFC 9000 section 12.4: "An endpoint MUST treat the receipt of a frame
       * of unknown type as a connection error of type FRAME_ENCODING_ERROR."
       * Skipping it would desynchronise the parse, and guessing at its length
       * is what the rule exists to forbid. */
      return wt_quic_decode_fail(out_error, WT_QUIC_FRAME_ENCODING_ERROR);
  }
}

wt_status_t wt_quic_frames_decode(const uint8_t *data, size_t length,
                                  wt_quic_frame_visitor_fn visit, void *context,
                                  wt_quic_error_t *out_error) {
  wt_cursor_t c;
  wt_quic_frame_t frame;

  if (data == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;
  c = wt_cursor_init(data, length);
  while (wt_cursor_remaining(&c) > 0U) {
    wt_status_t status = wt_quic_frame_decode(&c, &frame, out_error);
    if (status != WT_OK) return status;
    if (visit != NULL) {
      status = visit(context, &frame);
      if (status != WT_OK) return status;
    }
  }
  return WT_OK;
}

wt_status_t wt_quic_frame_ack_range_at(const wt_quic_frame_t *frame,
                                       uint64_t index,
                                       wt_quic_ack_range_t *out) {
  wt_cursor_t c;
  uint64_t i;
  if (frame == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (frame->kind != WT_QUIC_FRAME_KIND_ACK) return WT_ERR_INVALID_ARGUMENT;
  if (index >= frame->as.ack.range_count) return WT_ERR_INVALID_ARGUMENT;
  c = wt_cursor_init(frame->as.ack.ranges, frame->as.ack.ranges_len);
  for (i = 0U; i <= index; i++) {
    if (wt_quic_varint_decode(&c, &out->gap) != WT_OK ||
        wt_quic_varint_decode(&c, &out->length) != WT_OK) {
      return WT_ERR_TRUNCATED;
    }
  }
  return WT_OK;
}

/* --------------------------------------------------------------- encoding */

static wt_status_t wt_quic_encode_fail(void) { return WT_ERR_INVALID_ARGUMENT; }

wt_status_t wt_quic_frame_encode(wt_writer_t *w, const wt_quic_frame_t *frame) {
  if (w == NULL || frame == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (w->overflow) return WT_ERR_LIMIT;

  switch (frame->kind) {
    case WT_QUIC_FRAME_KIND_PADDING:
      (void)wt_quic_writer_varint(w, WT_QUIC_FRAME_PADDING);
      return WT_OK;

    case WT_QUIC_FRAME_KIND_PING:
      (void)wt_quic_writer_varint(w, WT_QUIC_FRAME_PING);
      return WT_OK;

    case WT_QUIC_FRAME_KIND_ACK: {
      uint64_t i;
      (void)wt_quic_writer_varint(w, frame->as.ack.has_ecn
                                         ? WT_QUIC_FRAME_ACK_ECN
                                         : WT_QUIC_FRAME_ACK);
      (void)wt_quic_writer_varint(w, frame->as.ack.largest);
      (void)wt_quic_writer_varint(w, frame->as.ack.delay);
      (void)wt_quic_writer_varint(w, frame->as.ack.range_count);
      (void)wt_quic_writer_varint(w, frame->as.ack.first_range);
      for (i = 0U; i < frame->as.ack.range_count; i++) {
        wt_quic_ack_range_t range;
        if (wt_quic_frame_ack_range_at(frame, i, &range) != WT_OK) {
          return wt_quic_encode_fail();
        }
        (void)wt_quic_writer_varint(w, range.gap);
        (void)wt_quic_writer_varint(w, range.length);
      }
      if (frame->as.ack.has_ecn) {
        (void)wt_quic_writer_varint(w, frame->as.ack.ect0);
        (void)wt_quic_writer_varint(w, frame->as.ack.ect1);
        (void)wt_quic_writer_varint(w, frame->as.ack.ecn_ce);
      }
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
    }

    case WT_QUIC_FRAME_KIND_CRYPTO:
      (void)wt_quic_writer_varint(w, WT_QUIC_FRAME_CRYPTO);
      (void)wt_quic_writer_varint(w, frame->as.crypto.offset);
      (void)wt_quic_writer_varint(w, (uint64_t)frame->as.crypto.length);
      wt_writer_bytes(w, frame->as.crypto.data, frame->as.crypto.length);
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;

    case WT_QUIC_FRAME_KIND_NEW_TOKEN:
      if (frame->as.new_token.length == 0U || frame->as.new_token.token == NULL) {
        return wt_quic_encode_fail();
      }
      (void)wt_quic_writer_varint(w, WT_QUIC_FRAME_NEW_TOKEN);
      (void)wt_quic_writer_varint(w, (uint64_t)frame->as.new_token.length);
      wt_writer_bytes(w, frame->as.new_token.token, frame->as.new_token.length);
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;

    case WT_QUIC_FRAME_KIND_STREAM: {
      uint8_t flags = 0U;
      uint64_t type;
      if (frame->as.stream.has_offset) flags |= WT_QUIC_STREAM_FLAG_OFF;
      if (frame->as.stream.has_length) flags |= WT_QUIC_STREAM_FLAG_LEN;
      if (frame->as.stream.fin) flags |= WT_QUIC_STREAM_FLAG_FIN;
      type = WT_QUIC_FRAME_STREAM_BASE | (uint64_t)flags;
      (void)wt_quic_writer_varint(w, type);
      (void)wt_quic_writer_varint(w, frame->as.stream.id);
      if (frame->as.stream.has_offset) {
        (void)wt_quic_writer_varint(w, frame->as.stream.offset);
      }
      if (frame->as.stream.has_length) {
        (void)wt_quic_writer_varint(w, (uint64_t)frame->as.stream.length);
      }
      wt_writer_bytes(w, frame->as.stream.data, frame->as.stream.length);
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
    }

    case WT_QUIC_FRAME_KIND_RESET_STREAM:
      (void)wt_quic_writer_varint(w, WT_QUIC_FRAME_RESET_STREAM);
      (void)wt_quic_writer_varint(w, frame->as.reset_stream.id);
      (void)wt_quic_writer_varint(w,
                                  frame->as.reset_stream.application_error_code);
      (void)wt_quic_writer_varint(w, frame->as.reset_stream.final_size);
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;

    case WT_QUIC_FRAME_KIND_RESET_STREAM_AT:
      if (frame->as.reset_stream_at.reliable_size >
          frame->as.reset_stream_at.final_size) {
        return wt_quic_encode_fail();
      }
      (void)wt_quic_writer_varint(w, WT_QUIC_FRAME_RESET_STREAM_AT);
      (void)wt_quic_writer_varint(w, frame->as.reset_stream_at.id);
      (void)wt_quic_writer_varint(
          w, frame->as.reset_stream_at.application_error_code);
      (void)wt_quic_writer_varint(w, frame->as.reset_stream_at.final_size);
      (void)wt_quic_writer_varint(w, frame->as.reset_stream_at.reliable_size);
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;

    case WT_QUIC_FRAME_KIND_STOP_SENDING:
      (void)wt_quic_writer_varint(w, WT_QUIC_FRAME_STOP_SENDING);
      (void)wt_quic_writer_varint(w, frame->as.stop_sending.id);
      (void)wt_quic_writer_varint(
          w, frame->as.stop_sending.application_error_code);
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;

    case WT_QUIC_FRAME_KIND_MAX_DATA:
      (void)wt_quic_writer_varint(w, WT_QUIC_FRAME_MAX_DATA);
      (void)wt_quic_writer_varint(w, frame->as.max_data.maximum);
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;

    case WT_QUIC_FRAME_KIND_MAX_STREAM_DATA:
      (void)wt_quic_writer_varint(w, WT_QUIC_FRAME_MAX_STREAM_DATA);
      (void)wt_quic_writer_varint(w, frame->as.max_stream_data.id);
      (void)wt_quic_writer_varint(w, frame->as.max_stream_data.maximum);
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;

    case WT_QUIC_FRAME_KIND_MAX_STREAMS:
      (void)wt_quic_writer_varint(
          w, (frame->as.max_streams.direction == WT_QUIC_STREAM_BIDIRECTIONAL)
                 ? WT_QUIC_FRAME_MAX_STREAMS_BIDI
                 : WT_QUIC_FRAME_MAX_STREAMS_UNI);
      (void)wt_quic_writer_varint(w, frame->as.max_streams.maximum);
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;

    case WT_QUIC_FRAME_KIND_DATA_BLOCKED:
      (void)wt_quic_writer_varint(w, WT_QUIC_FRAME_DATA_BLOCKED);
      (void)wt_quic_writer_varint(w, frame->as.data_blocked.maximum);
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;

    case WT_QUIC_FRAME_KIND_STREAM_DATA_BLOCKED:
      (void)wt_quic_writer_varint(w, WT_QUIC_FRAME_STREAM_DATA_BLOCKED);
      (void)wt_quic_writer_varint(w, frame->as.stream_data_blocked.id);
      (void)wt_quic_writer_varint(w, frame->as.stream_data_blocked.offset);
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;

    case WT_QUIC_FRAME_KIND_STREAMS_BLOCKED:
      (void)wt_quic_writer_varint(
          w, (frame->as.streams_blocked.direction == WT_QUIC_STREAM_BIDIRECTIONAL)
                 ? WT_QUIC_FRAME_STREAMS_BLOCKED_BIDI
                 : WT_QUIC_FRAME_STREAMS_BLOCKED_UNI);
      (void)wt_quic_writer_varint(w, frame->as.streams_blocked.maximum);
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;

    case WT_QUIC_FRAME_KIND_NEW_CONNECTION_ID:
      if (frame->as.new_connection_id.connection_id_length < 1U ||
          frame->as.new_connection_id.connection_id_length >
              WT_QUIC_MAX_CONNECTION_ID_LENGTH ||
          frame->as.new_connection_id.connection_id == NULL ||
          frame->as.new_connection_id.stateless_reset_token == NULL) {
        return wt_quic_encode_fail();
      }
      if (frame->as.new_connection_id.retire_prior_to >
          frame->as.new_connection_id.sequence) {
        return wt_quic_encode_fail();
      }
      (void)wt_quic_writer_varint(w, WT_QUIC_FRAME_NEW_CONNECTION_ID);
      (void)wt_quic_writer_varint(w, frame->as.new_connection_id.sequence);
      (void)wt_quic_writer_varint(w, frame->as.new_connection_id.retire_prior_to);
      wt_writer_u8(w, (uint8_t)frame->as.new_connection_id.connection_id_length);
      wt_writer_bytes(w, frame->as.new_connection_id.connection_id,
                      frame->as.new_connection_id.connection_id_length);
      wt_writer_bytes(w, frame->as.new_connection_id.stateless_reset_token,
                      WT_QUIC_STATELESS_RESET_TOKEN_LENGTH);
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;

    case WT_QUIC_FRAME_KIND_RETIRE_CONNECTION_ID:
      (void)wt_quic_writer_varint(w, WT_QUIC_FRAME_RETIRE_CONNECTION_ID);
      (void)wt_quic_writer_varint(w, frame->as.retire_connection_id.sequence);
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;

    case WT_QUIC_FRAME_KIND_PATH_CHALLENGE:
      if (frame->as.path_challenge.data == NULL) return wt_quic_encode_fail();
      (void)wt_quic_writer_varint(w, WT_QUIC_FRAME_PATH_CHALLENGE);
      wt_writer_bytes(w, frame->as.path_challenge.data,
                      WT_QUIC_PATH_CHALLENGE_LENGTH);
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;

    case WT_QUIC_FRAME_KIND_PATH_RESPONSE:
      if (frame->as.path_response.data == NULL) return wt_quic_encode_fail();
      (void)wt_quic_writer_varint(w, WT_QUIC_FRAME_PATH_RESPONSE);
      wt_writer_bytes(w, frame->as.path_response.data,
                      WT_QUIC_PATH_CHALLENGE_LENGTH);
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;

    case WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_TRANSPORT:
    case WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_APPLICATION:
      (void)wt_quic_writer_varint(
          w, (frame->kind == WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_TRANSPORT)
                 ? WT_QUIC_FRAME_CONNECTION_CLOSE_TRANSPORT
                 : WT_QUIC_FRAME_CONNECTION_CLOSE_APPLICATION);
      (void)wt_quic_writer_varint(w, frame->as.connection_close.error_code);
      if (frame->as.connection_close.has_frame_type) {
        if (frame->kind != WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_TRANSPORT) {
          /* The application close form has no frame type field, so a caller
           * that set one is asking for something the wire cannot carry. */
          return wt_quic_encode_fail();
        }
        (void)wt_quic_writer_varint(w, frame->as.connection_close.frame_type);
      } else if (frame->kind == WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_TRANSPORT) {
        /* A transport close always carries the field, and RFC 9000 section
         * 19.19 says an endpoint that cannot name the frame uses 0. */
        (void)wt_quic_writer_varint(w, 0U);
      }
      (void)wt_quic_writer_varint(
          w, (uint64_t)frame->as.connection_close.reason_length);
      wt_writer_bytes(w, frame->as.connection_close.reason,
                      frame->as.connection_close.reason_length);
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;

    case WT_QUIC_FRAME_KIND_HANDSHAKE_DONE:
      (void)wt_quic_writer_varint(w, WT_QUIC_FRAME_HANDSHAKE_DONE);
      return WT_OK;

    case WT_QUIC_FRAME_KIND_DATAGRAM:
      /* The frame the parser produced for either DATAGRAM form encodes as the
       * length-carrying form, because a frame without a length must be last in
       * a packet and an encoder here cannot know that. A caller that wants the
       * other form writes the type itself; this is the safe encoding. */
      (void)wt_quic_writer_varint(w, WT_QUIC_FRAME_DATAGRAM_LEN);
      (void)wt_quic_writer_varint(w, (uint64_t)frame->as.datagram.length);
      wt_writer_bytes(w, frame->as.datagram.data, frame->as.datagram.length);
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;

    default:
      return wt_quic_encode_fail();
  }
}
