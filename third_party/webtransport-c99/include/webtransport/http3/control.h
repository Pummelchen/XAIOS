/* The peer's HTTP/3 control stream (RFC 9114 section 6.2.1).
 *
 * Each side opens exactly one control stream and its first frame is its
 * SETTINGS. Everything else about the stream is a rule about what a peer may do
 * with it, and all four are connection errors:
 *
 *   - a first frame that is not SETTINGS is H3_MISSING_SETTINGS;
 *   - a second control stream from the same peer is H3_STREAM_CREATION_ERROR;
 *   - the stream closing at any point is H3_CLOSED_CRITICAL_STREAM, because the
 *     connection's whole configuration travels on it and a closed one cannot be
 *     reopened (section 6.2.1: "the sender MUST NOT close the control stream");
 *   - a frame the section does not allow there -- DATA, HEADERS, PUSH_PROMISE, a
 *     second SETTINGS, or one of the frame types section 7.2.8 reserved for
 *     HTTP/2 -- is H3_FRAME_UNEXPECTED.
 *
 * The state machine only decides PERMISSION. What a SETTINGS, GOAWAY or
 * MAX_PUSH_ID frame says is parsed by whoever owns that frame, which is why this
 * takes a frame type and not a frame.
 *
 * It is not wired to QUIC streams yet: the layer that owns HTTP/3 streams passes
 * events in and reports the error it is handed, exactly as the QUIC runtime does
 * with its own state machines.
 */

#ifndef WEBTRANSPORT_HTTP3_CONTROL_H
#define WEBTRANSPORT_HTTP3_CONTROL_H

#include <stdint.h>

#include "webtransport/http3/frame.h"
#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct wt_http3_control_stream {
  /* The peer's control stream exists. A second one is an error, so this outlives
   * any single stream object. */
  int opened;
  /* Its SETTINGS frame has been processed, which is what makes every later frame
   * subject to the frame rules rather than to the first-frame rule. */
  int settings_received;
  /* The stream ended. The connection is committed to an error by then. */
  int closed;
} wt_http3_control_stream_t;

void wt_http3_control_init(wt_http3_control_stream_t *control);

/* The peer opened a stream whose type prefix says control (0x00). A second one is
 * H3_STREAM_CREATION_ERROR. */
wt_status_t wt_http3_control_peer_opened(wt_http3_control_stream_t *control,
                                         wt_http3_error_t *out_error);

/* A frame arrived on the peer's control stream. Sets `out_error` to the code the
 * rule names and returns WT_ERR_PROTOCOL when it may not be there, and
 * WT_ERR_STATE when the caller's own ordering is wrong (a frame before the stream
 * was opened, or after it closed). */
wt_status_t wt_http3_control_on_frame(wt_http3_control_stream_t *control, uint64_t type,
                                      wt_http3_error_t *out_error);

/* The peer's control stream ended, for any reason. Always
 * H3_CLOSED_CRITICAL_STREAM, whether or not SETTINGS had arrived: section 6.2.1
 * makes the closure itself the error. */
wt_status_t wt_http3_control_on_closed(wt_http3_control_stream_t *control,
                                       wt_http3_error_t *out_error);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_HTTP3_CONTROL_H */
