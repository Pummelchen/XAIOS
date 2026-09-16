/* Which frames may appear on which HTTP/3 stream. See webtransport/http3/streams.h. */

#include "webtransport/http3/streams.h"

wt_status_t wt_http3_frame_allowed(wt_http3_role_t receiver, wt_http3_stream_kind_t kind,
                                   uint64_t type, wt_http3_error_t *out_error) {
  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;

  /* Section 7.2.8: the frame types HTTP/2 used, where HTTP/3 has no equivalent,
   * are reserved on every stream. Checked first so a reserved type is reported as
   * reserved rather than as whatever it resembles. */
  if (wt_http3_frame_type_is_reserved(type)) {
    if (out_error != NULL) *out_error = WT_HTTP3_FRAME_UNEXPECTED;
    return WT_ERR_PROTOCOL;
  }

  /* Section 4.2: a QPACK encoder or decoder stream carries QPACK instructions,
   * not HTTP/3 frames. "A receiver MUST treat the receipt of any other type of
   * frame on a QPACK encoder or decoder stream as a connection error of type
   * H3_FRAME_UNEXPECTED." There is nothing to except, so this is the whole rule
   * for those two kinds. */
  if (kind == WT_HTTP3_STREAM_KIND_QPACK_ENCODER || kind == WT_HTTP3_STREAM_KIND_QPACK_DECODER) {
    if (out_error != NULL) *out_error = WT_HTTP3_FRAME_UNEXPECTED;
    return WT_ERR_PROTOCOL;
  }

  if (kind == WT_HTTP3_STREAM_KIND_CONTROL) {
    /* Sections 7.2.1, 7.2.2 and 7.2.5: DATA, HEADERS and PUSH_PROMISE describe
     * requests and responses, and a control stream carries neither. */
    if (type == WT_HTTP3_FRAME_DATA || type == WT_HTTP3_FRAME_HEADERS ||
        type == WT_HTTP3_FRAME_PUSH_PROMISE) {
      if (out_error != NULL) *out_error = WT_HTTP3_FRAME_UNEXPECTED;
      return WT_ERR_PROTOCOL;
    }
    /* Section 7.2.7: "A server MUST NOT send a MAX_PUSH_ID frame. A client MUST
     * treat the receipt of a MAX_PUSH_ID frame as a connection error of type
     * H3_FRAME_UNEXPECTED." A client is a MAX_PUSH_ID's only sender. */
    if (type == WT_HTTP3_FRAME_MAX_PUSH_ID && receiver == WT_HTTP3_ROLE_CLIENT) {
      if (out_error != NULL) *out_error = WT_HTTP3_FRAME_UNEXPECTED;
      return WT_ERR_PROTOCOL;
    }
    /* SETTINGS, GOAWAY, MAX_PUSH_ID and CANCEL_PUSH belong here, and so does any
     * extension frame this build has never heard of. */
    return WT_OK;
  }

  if (kind == WT_HTTP3_STREAM_KIND_REQUEST) {
    /* Section 7.2.4, 7.2.6, 7.2.7 and 7.2.3: the connection-management frames
     * travel on the control stream and say so in the same words -- "Receipt of a
     * MAX_PUSH_ID frame on any other stream MUST be treated as a connection error
     * of type H3_FRAME_UNEXPECTED" is the pattern. */
    if (type == WT_HTTP3_FRAME_SETTINGS || type == WT_HTTP3_FRAME_GOAWAY ||
        type == WT_HTTP3_FRAME_MAX_PUSH_ID || type == WT_HTTP3_FRAME_CANCEL_PUSH) {
      if (out_error != NULL) *out_error = WT_HTTP3_FRAME_UNEXPECTED;
      return WT_ERR_PROTOCOL;
    }
    /* Section 7.2.5: a PUSH_PROMISE is "from server to client on a request
     * stream", so a server that receives one has been sent a frame only it may
     * send. */
    if (type == WT_HTTP3_FRAME_PUSH_PROMISE && receiver == WT_HTTP3_ROLE_SERVER) {
      if (out_error != NULL) *out_error = WT_HTTP3_FRAME_UNEXPECTED;
      return WT_ERR_PROTOCOL;
    }
    return WT_OK;
  }

  /* A push stream carries a promised response: HEADERS and DATA, with interim
   * responses before the final one (section 6.2.2). The connection frames are as
   * out of place there as they are on a request stream, and a push cannot promise
   * another push. */
  if (type == WT_HTTP3_FRAME_SETTINGS || type == WT_HTTP3_FRAME_GOAWAY ||
      type == WT_HTTP3_FRAME_MAX_PUSH_ID || type == WT_HTTP3_FRAME_CANCEL_PUSH ||
      type == WT_HTTP3_FRAME_PUSH_PROMISE) {
    if (out_error != NULL) *out_error = WT_HTTP3_FRAME_UNEXPECTED;
    return WT_ERR_PROTOCOL;
  }
  return WT_OK;
}

wt_status_t wt_http3_stream_kind_for_type(uint64_t stream_type, wt_http3_stream_kind_t *out_kind) {
  if (out_kind == NULL) return WT_ERR_INVALID_ARGUMENT;
  switch (stream_type) {
    case WT_HTTP3_STREAM_CONTROL:
      *out_kind = WT_HTTP3_STREAM_KIND_CONTROL;
      return WT_OK;
    case WT_HTTP3_STREAM_QPACK_ENCODER:
      *out_kind = WT_HTTP3_STREAM_KIND_QPACK_ENCODER;
      return WT_OK;
    case WT_HTTP3_STREAM_QPACK_DECODER:
      *out_kind = WT_HTTP3_STREAM_KIND_QPACK_DECODER;
      return WT_OK;
    case WT_HTTP3_STREAM_PUSH:
      *out_kind = WT_HTTP3_STREAM_KIND_PUSH;
      return WT_OK;
    default:
      /* Not an error: section 6.2.1 leaves unknown stream types for future
       * revisions, and the caller ignores the stream. */
      return WT_ERR_STATE;
  }
}
