/* The frames of a request stream, in order. See webtransport/http3/request.h. */

#include "webtransport/http3/request.h"

void wt_http3_request_init(wt_http3_request_stream_t *request) {
  if (request == NULL) return;
  request->state = WT_HTTP3_REQUEST_EXPECT_HEADERS;
  request->ended = 0;
}

wt_status_t wt_http3_request_on_frame(wt_http3_request_stream_t *request, uint64_t type,
                                      wt_http3_error_t *out_error) {
  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (request == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (request->ended) return WT_ERR_STATE;

  switch (request->state) {
    case WT_HTTP3_REQUEST_EXPECT_HEADERS:
      if (type == WT_HTTP3_FRAME_HEADERS) {
        request->state = WT_HTTP3_REQUEST_BODY;
        return WT_OK;
      }
      /* Section 4.1: "a DATA frame before any HEADERS frame ... is considered
       * invalid". The same sentence covers every other type here, because the
       * request's shape starts with HEADERS and nothing else may precede it. */
      if (out_error != NULL) *out_error = WT_HTTP3_FRAME_UNEXPECTED;
      return WT_ERR_PROTOCOL;

    case WT_HTTP3_REQUEST_BODY:
      if (type == WT_HTTP3_FRAME_DATA) return WT_OK;
      if (type == WT_HTTP3_FRAME_HEADERS) {
        /* The trailer section: "optionally, the trailer section, if present, sent
         * as a single HEADERS frame". A second one has nowhere to go, and the
         * state below refuses it. */
        request->state = WT_HTTP3_REQUEST_COMPLETE;
        return WT_OK;
      }
      /* Anything else is out of place on a request stream: the frames that manage
       * the connection are refused by the stream rules, and this catches the rest
       * -- a PUSH_PROMISE from a client, for instance. */
      if (out_error != NULL) *out_error = WT_HTTP3_FRAME_UNEXPECTED;
      return WT_ERR_PROTOCOL;

    case WT_HTTP3_REQUEST_COMPLETE:
      /* Section 4.1: "a HEADERS or DATA frame after the trailing HEADERS frame is
       * considered invalid", and so is anything else: the request is whole. */
      if (out_error != NULL) *out_error = WT_HTTP3_FRAME_UNEXPECTED;
      return WT_ERR_PROTOCOL;
  }
  /* Not reachable: the switch covers every state of the enum the caller can set.
   * Reported as a state error rather than silence, since a caller that set the
   * state itself would learn nothing from WT_OK. */
  return WT_ERR_STATE;
}

wt_status_t wt_http3_request_on_end(wt_http3_request_stream_t *request,
                                    wt_http3_error_t *out_error) {
  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (request == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (request->ended) return WT_ERR_STATE;

  request->ended = 1;
  if (request->state == WT_HTTP3_REQUEST_EXPECT_HEADERS) {
    /* Section 4.1: "If a client-initiated stream terminates without enough of the
     * HTTP message to provide a complete response, the server SHOULD abort its
     * response stream with the error code H3_REQUEST_INCOMPLETE." A stream error,
     * not a connection error, which is why the code travels as one. */
    if (out_error != NULL) *out_error = WT_HTTP3_REQUEST_INCOMPLETE;
    return WT_ERR_PROTOCOL;
  }
  return WT_OK;
}

wt_status_t wt_http3_request_on_reset(wt_http3_request_stream_t *request) {
  if (request == NULL) return WT_ERR_INVALID_ARGUMENT;
  request->ended = 1;
  return WT_OK;
}
