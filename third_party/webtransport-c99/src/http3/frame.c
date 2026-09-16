/* HTTP/3 frames and stream type prefixes. See webtransport/http3/frame.h. */

#include "webtransport/http3/frame.h"

#include "webtransport/quic/varint.h"

wt_http3_frame_t wt_http3_frame_make(uint64_t type) {
  wt_http3_frame_t frame;
  frame.type = type;
  frame.payload = NULL;
  frame.length = 0U;
  return frame;
}

const char *wt_http3_frame_type_name(uint64_t type) {
  switch (type) {
    case WT_HTTP3_FRAME_DATA:
      return "data";
    case WT_HTTP3_FRAME_HEADERS:
      return "headers";
    case WT_HTTP3_FRAME_CANCEL_PUSH:
      return "cancel-push";
    case WT_HTTP3_FRAME_SETTINGS:
      return "settings";
    case WT_HTTP3_FRAME_PUSH_PROMISE:
      return "push-promise";
    case WT_HTTP3_FRAME_GOAWAY:
      return "goaway";
    case WT_HTTP3_FRAME_MAX_PUSH_ID:
      return "max-push-id";
    default:
      return "unknown";
  }
}

int wt_http3_frame_type_is_reserved(uint64_t type) {
  /* RFC 9114 section 7.2.8, first paragraph: "Frame types that were used in HTTP/2 where there is no corresponding
   * HTTP/3 frame have also been reserved ... These frame types MUST NOT be sent, and their receipt MUST be treated
   * as a connection error of type H3_FRAME_UNEXPECTED." Section 11.2.1 names them: PRIORITY (0x02), PING (0x06),
   * WINDOW_UPDATE (0x08) and CONTINUATION (0x09).
   *
   * The first version of this function had it the OTHER way round -- it reserved `0x1f * N + 0x21`, which the
   * same section says a peer MAY send and MUST have ignored, and accepted 0x02 and friends -- so this layer
   * refused conforming padding frames and accepted the four types the RFC forbids. `is_exerciser` below is the
   * other half, and a unit test had pinned the inversion. */
  return type == (uint64_t)0x02 || type == (uint64_t)0x06 || type == (uint64_t)0x08 ||
         type == (uint64_t)0x09;
}

int wt_http3_frame_type_is_exerciser(uint64_t type) {
  /* Section 7.2.8, second paragraph: "Frame types of the format 0x1f * N + 0x21 ... are reserved to exercise the
   * requirement that unknown types be ignored ... These frames have no semantics, and they MAY be sent on any
   * stream where frames are allowed to be sent. This enables their use for application-layer padding. Endpoints
   * MUST NOT consider these frames to have any meaning upon receipt." So these are IGNORED, not refused, and this
   * predicate exists so that the rule is stated rather than implied by falling into the unknown-type path. */
  if (type < (uint64_t)0x21) return 0;
  return ((type - (uint64_t)0x21) % (uint64_t)0x1f) == 0U;
}

wt_status_t wt_http3_frame_encode(wt_writer_t *w, const wt_http3_frame_t *frame) {
  if (w == NULL || frame == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (frame->payload == NULL && frame->length != 0U) return WT_ERR_INVALID_ARGUMENT;
  /* A type or a length the varint cannot carry is a caller error, and it is
   * checked here rather than left to the writer, which would encode the low bits
   * of a value it cannot represent. */
  if (frame->type > WT_QUIC_VARINT_MAX) return WT_ERR_INVALID_ARGUMENT;
  if ((uint64_t)frame->length > WT_QUIC_VARINT_MAX) return WT_ERR_INVALID_ARGUMENT;

  (void)wt_quic_writer_varint(w, frame->type);
  (void)wt_quic_writer_varint(w, (uint64_t)frame->length);
  if (frame->length != 0U) wt_writer_bytes(w, frame->payload, frame->length);
  return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
}

wt_status_t wt_http3_frame_encoded_size(const wt_http3_frame_t *frame, size_t *out_size) {
  size_t total;

  if (frame == NULL || out_size == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (frame->payload == NULL && frame->length != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (frame->type > WT_QUIC_VARINT_MAX) return WT_ERR_INVALID_ARGUMENT;
  if ((uint64_t)frame->length > WT_QUIC_VARINT_MAX) return WT_ERR_INVALID_ARGUMENT;

  total = wt_quic_varint_size(frame->type) + wt_quic_varint_size((uint64_t)frame->length);
  if (total > SIZE_MAX - frame->length) return WT_ERR_OVERFLOW;
  *out_size = total + frame->length;
  return WT_OK;
}

/* The frame decoding both entry points share, from a cursor positioned at the
 * frame's type. */
static wt_status_t frame_decode_at(wt_cursor_t *c, wt_http3_frame_t *out,
                                   wt_http3_error_t *out_error) {
  uint64_t type;
  uint64_t length;
  const uint8_t *payload;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (wt_quic_varint_decode(c, &type) != WT_OK) {
    /* The type is the first thing a frame has, so a buffer that ends here is not
     * a frame: a partial frame is the caller's to assemble (section 7.1). */
    if (out_error != NULL) *out_error = WT_HTTP3_FRAME_ERROR;
    return WT_ERR_TRUNCATED;
  }
  if (wt_quic_varint_decode(c, &length) != WT_OK) {
    if (out_error != NULL) *out_error = WT_HTTP3_FRAME_ERROR;
    return WT_ERR_TRUNCATED;
  }
  if (length > (uint64_t)SIZE_MAX) {
    /* A frame this program cannot hold is refused rather than narrowed: the
     * length would otherwise wrap on a 32-bit target and describe other bytes. */
    if (out_error != NULL) *out_error = WT_HTTP3_FRAME_ERROR;
    return WT_ERR_LIMIT;
  }
  payload = wt_cursor_bytes(c, (size_t)length);
  if (payload == NULL && length != 0U) {
    if (out_error != NULL) *out_error = WT_HTTP3_FRAME_ERROR;
    return WT_ERR_TRUNCATED;
  }
  out->type = type;
  out->payload = payload;
  out->length = (size_t)length;
  return WT_OK;
}

wt_status_t wt_http3_frame_decode(wt_cursor_t *c, wt_http3_frame_t *out,
                                  wt_http3_error_t *out_error) {
  wt_cursor_t before;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (c == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* A frame that fails to decode must not consume its bytes: the caller cannot
   * tell a malformed frame from a short read otherwise, and leaving the cursor
   * where it was is what lets a caller report which frame failed. */
  before = *c;
  {
    wt_status_t status = frame_decode_at(c, out, out_error);
    if (status != WT_OK) *c = before;
    return status;
  }
}

wt_status_t wt_http3_frame_decode_prefix(const uint8_t *data, size_t length,
                                         wt_http3_frame_t *out, size_t *out_consumed,
                                         wt_http3_error_t *out_error) {
  wt_cursor_t c;
  wt_status_t status;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (out == NULL || out_consumed == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (data == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;
  *out_consumed = 0U;

  c = wt_cursor_init(data, length);
  status = frame_decode_at(&c, out, out_error);
  if (status != WT_OK) return status;
  *out_consumed = length - wt_cursor_remaining(&c);
  return WT_OK;
}

wt_status_t wt_http3_stream_type_read(wt_cursor_t *c, uint64_t *out_type,
                                      wt_http3_error_t *out_error) {
  wt_cursor_t before;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (c == NULL || out_type == NULL) return WT_ERR_INVALID_ARGUMENT;

  before = *c;
  if (wt_quic_varint_decode(c, out_type) != WT_OK) {
    *c = before;
    /* RFC 9114 section 6.2: the type is the first thing on a stream, and a
     * stream whose type is not there cannot be used for anything -- the frame
     * that would explain it is exactly what is missing. */
    if (out_error != NULL) *out_error = WT_HTTP3_STREAM_CREATION_ERROR;
    return WT_ERR_TRUNCATED;
  }
  return WT_OK;
}
