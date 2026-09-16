/* The frames of a request stream, in order (RFC 9114 section 4.1).
 *
 * A request stream carries exactly one request, and section 4.1 fixes its shape:
 * a single HEADERS frame, then optionally the content as a series of DATA frames,
 * then optionally the trailer section as a single HEADERS frame. "Receipt of an
 * invalid sequence of frames MUST be treated as a connection error of type
 * H3_FRAME_UNEXPECTED. In particular, a DATA frame before any HEADERS frame, or a
 * HEADERS or DATA frame after the trailing HEADERS frame, is considered invalid."
 *
 * This is the REQUEST direction: what a server receives from a client. The
 * response direction -- what a client receives -- is not here, and the reason is
 * concrete rather than a matter of scope: section 4.1 lets a server send zero or
 * more informational (1xx) responses before the final one, and whether a HEADERS
 * frame is informational is only known once its `:status` field has been decoded.
 * That needs QPACK, so the response machine lands with it; guessing from frame
 * order alone would report a legal pair of responses as a duplicate.
 *
 * A stream that ends before the request's HEADERS is not a malformed sequence but
 * an incomplete request: section 4.1 has the server abort its response stream
 * with H3_REQUEST_INCOMPLETE, which is a STREAM error and not a connection error.
 * This machine reports it as such, because a caller that closed the connection
 * for it would be treating its own decision as the peer's fault.
 */

#ifndef WEBTRANSPORT_HTTP3_REQUEST_H
#define WEBTRANSPORT_HTTP3_REQUEST_H

#include <stdint.h>

#include "webtransport/http3/frame.h"
#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum wt_http3_request_state {
  /* Nothing yet: the first frame must be HEADERS. */
  WT_HTTP3_REQUEST_EXPECT_HEADERS = 0,
  /* The request's HEADERS frame has arrived; DATA and the trailer may follow. */
  WT_HTTP3_REQUEST_BODY = 1,
  /* The trailing HEADERS frame has arrived: the stream carries nothing more. */
  WT_HTTP3_REQUEST_COMPLETE = 2
} wt_http3_request_state_t;

typedef struct wt_http3_request_stream {
  wt_http3_request_state_t state;
  /* The peer ended the stream. */
  int ended;
} wt_http3_request_stream_t;

void wt_http3_request_init(wt_http3_request_stream_t *request);

/* One frame arrived on the request stream. H3_FRAME_UNEXPECTED (WT_ERR_PROTOCOL)
 * for a sequence section 4.1 makes invalid, and WT_ERR_STATE for a frame after the
 * stream ended, which is the caller's own ordering rather than the peer's. */
wt_status_t wt_http3_request_on_frame(wt_http3_request_stream_t *request, uint64_t type,
                                      wt_http3_error_t *out_error);

/* The peer ended the stream cleanly. A stream that ends before the request's
 * HEADERS was incomplete: H3_REQUEST_INCOMPLETE, which section 4.1 defines as the
 * code for aborting the RESPONSE stream and not for closing the connection. */
wt_status_t wt_http3_request_on_end(wt_http3_request_stream_t *request,
                                    wt_http3_error_t *out_error);

/* The peer reset the stream. Not a frame-ordering matter at all -- the layer that
 * owns resets decides what to do -- so this only records that nothing follows. */
wt_status_t wt_http3_request_on_reset(wt_http3_request_stream_t *request);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_HTTP3_REQUEST_H */
