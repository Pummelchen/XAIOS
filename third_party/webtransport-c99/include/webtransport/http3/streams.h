/* Which frames may appear on which HTTP/3 stream (RFC 9114 section 7.2).
 *
 * Every frame section ends with the same sentence in one form or another: a frame
 * that arrived on a stream it has no business on is a connection error of type
 * H3_FRAME_UNEXPECTED. DATA and HEADERS describe requests and responses; SETTINGS,
 * GOAWAY, MAX_PUSH_ID and CANCEL_PUSH manage the connection and travel on the
 * control stream; PUSH_PROMISE travels from a server to a client on a request
 * stream; and the QPACK streams carry no HTTP/3 frames at all (section 4.2).
 *
 * Two rules are about the ROLE rather than the stream, which is why this takes the
 * receiving endpoint's role: section 7.2.7 makes MAX_PUSH_ID a client's frame, so a
 * client that receives one has been sent something only it may send, and section
 * 7.2.5 makes PUSH_PROMISE a server's, with the same consequence in the other
 * direction. Unknown frame types are allowed: HTTP/3 grows by extension frames, and
 * section 9's rule is that a frame a layer does not understand is that layer's to
 * ignore -- except on a QPACK stream, where the bytes are instructions rather than
 * frames, so an HTTP/3 frame there is malformed however well formed it looks.
 *
 * Server push is not implemented in this tree. The push rules are here because the
 * table has to be complete to be usable, and a peer that pushes will be answered by
 * whatever the layer that owns push streams decides; nothing in this build sends a
 * PUSH_PROMISE or opens a push stream.
 */

#ifndef WEBTRANSPORT_HTTP3_STREAMS_H
#define WEBTRANSPORT_HTTP3_STREAMS_H

#include <stdint.h>

#include "webtransport/http3/frame.h"
#include "webtransport/http3/role.h"
#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum wt_http3_stream_kind {
  /* The peer's control stream: a unidirectional stream whose type prefix is
   * WT_HTTP3_STREAM_CONTROL. */
  WT_HTTP3_STREAM_KIND_CONTROL = 0,
  /* A request stream: a client-initiated bidirectional stream carrying a request
   * and its response. */
  WT_HTTP3_STREAM_KIND_REQUEST = 1,
  /* A push stream: a server-initiated unidirectional stream carrying a promised
   * response (section 6.2.2). */
  WT_HTTP3_STREAM_KIND_PUSH = 2,
  WT_HTTP3_STREAM_KIND_QPACK_ENCODER = 3,
  WT_HTTP3_STREAM_KIND_QPACK_DECODER = 4
} wt_http3_stream_kind_t;

/* Whether a frame of this type may appear on a stream of this kind, for an
 * endpoint in this role. Sets `out_error` to H3_FRAME_UNEXPECTED when it may not,
 * which is the only code these rules use, and returns WT_ERR_PROTOCOL. */
wt_status_t wt_http3_frame_allowed(wt_http3_role_t receiver, wt_http3_stream_kind_t kind,
                                   uint64_t type, wt_http3_error_t *out_error);

/* The stream kind a stream type prefix names, for the prefixes this core knows.
 * An unknown prefix is not an error here -- section 6.2.1 leaves unknown stream
 * types for later revisions -- so the caller is told and can ignore the stream. */
wt_status_t wt_http3_stream_kind_for_type(uint64_t stream_type, wt_http3_stream_kind_t *out_kind);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_HTTP3_STREAMS_H */
