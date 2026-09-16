/* WebTransport capsules (draft-ietf-webtrans-http3-16 section 5, on RFC 9297's
 * capsules).
 *
 * The CONNECT stream carries the session's control messages as capsules: a varint
 * type, a varint length and that many bytes. The two that end a session are
 * WT_DRAIN_SESSION, which has no value at all, and CLOSE_WEBTRANSPORT_SESSION, whose
 * value is a four-byte application error code followed by a UTF-8 reason no longer
 * than 1024 bytes. The rest carry flow control and are ordinary varint values.
 *
 * Two rules shape the decoder. A capsule whose length is longer than the bytes present
 * is INCOMPLETE rather than malformed -- the stream delivers it in pieces, exactly as
 * QPACK's instructions are delivered -- so the caller waits. And an unknown capsule
 * type is decoded and handed on rather than refused: RFC 9297 section 3.2 has a
 * receiver ignore a capsule it does not understand, which is how the format grows.
 */

#ifndef WEBTRANSPORT_WEBTRANSPORT_CAPSULE_H
#define WEBTRANSPORT_WEBTRANSPORT_CAPSULE_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/cursor.h"
#include "webtransport/http3/frame.h"
#include "webtransport/status.h"
#include "webtransport/writer.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The draft-16 capsule types, from its own registry. */
#define WT_CAPSULE_DRAIN_SESSION ((uint64_t)0x78ae)
#define WT_CAPSULE_CLOSE_WEBTRANSPORT_SESSION ((uint64_t)0x2843)
#define WT_CAPSULE_MAX_DATA ((uint64_t)0x190b4d3d)
#define WT_CAPSULE_MAX_STREAM_DATA ((uint64_t)0x190b4d3e)
#define WT_CAPSULE_MAX_STREAMS_BIDI ((uint64_t)0x190b4d3f)
#define WT_CAPSULE_MAX_STREAMS_UNI ((uint64_t)0x190b4d40)
#define WT_CAPSULE_DATA_BLOCKED ((uint64_t)0x190b4d41)
#define WT_CAPSULE_STREAM_DATA_BLOCKED ((uint64_t)0x190b4d42)
#define WT_CAPSULE_STREAMS_BLOCKED_BIDI ((uint64_t)0x190b4d43)
#define WT_CAPSULE_STREAMS_BLOCKED_UNI ((uint64_t)0x190b4d44)

/* The longest close reason the draft allows (section 5.4). A peer sending more is not
 * making a longer statement, it is making a malformed one. */
#define WT_CAPSULE_CLOSE_MAX_REASON 1024U

/* One capsule, as a view into the caller's bytes. */
typedef struct wt_webtransport_capsule {
  uint64_t type;
  const uint8_t *value;
  size_t value_length;
  /* How many bytes the capsule occupied, so a caller can walk a stream. */
  size_t bytes_consumed;
} wt_webtransport_capsule_t;

/* Read one capsule. WT_ERR_TRUNCATED means the rest has not arrived; `max_length` is
 * how large a value this endpoint will buffer at all (WT_ERR_LIMIT beyond it), which is
 * the bound every other table in this library carries. */
wt_status_t wt_webtransport_capsule_decode(wt_cursor_t *c, size_t max_length,
                                           wt_webtransport_capsule_t *out,
                                           wt_http3_error_t *out_error);

wt_status_t wt_webtransport_capsule_encode(wt_writer_t *w, const wt_webtransport_capsule_t *capsule);

/* The close capsule's value: a four-byte error code and a reason. */
wt_status_t wt_webtransport_close_session_write(wt_writer_t *w, uint32_t error_code,
                                                const uint8_t *reason, size_t reason_length);
wt_status_t wt_webtransport_close_session_parse(const wt_webtransport_capsule_t *capsule,
                                                uint32_t *out_error_code, const uint8_t **out_reason,
                                                size_t *out_reason_length,
                                                wt_http3_error_t *out_error);

/* The drain capsule, which has no value. */
wt_status_t wt_webtransport_drain_session_write(wt_writer_t *w);

/* ------------------------------------- draft-16 section 5.1's flow control capsules
 *
 * The session has its own flow control, carried as capsules on the CONNECT stream: a
 * connection-level data limit, a per-stream one, the number of streams of each
 * direction, and the blocked signals that ask for more. Each value is one varint -- two
 * for the per-stream and blocked capsules, which name a stream as well -- and a
 * capsule whose value is not exactly that is malformed rather than short. */

/* The draft's error code for a flow-control violation, which is what an endpoint sends when a limit goes
 * backwards. It is defined in `webtransport/error.h` with the rest of the draft's registered codes -- one owner
 * for the five numbers, so that a second copy cannot drift from the registry (WT-181) -- and this name stays
 * because it is the one this file's callers use. */
#include "webtransport/webtransport/error.h"
#define WT_WEBTRANSPORT_FLOW_CONTROL_ERROR WT_WEBTRANSPORT_ERROR_FLOW_CONTROL

/* The draft's ceiling on a stream-count limit: a limit above it is a flow-control error
 * rather than a number to remember, because the stream ID space it would describe does
 * not exist. */
#define WT_WEBTRANSPORT_MAX_STREAMS_VALUE (UINT64_C(1) << 60)

wt_status_t wt_webtransport_max_data_write(wt_writer_t *w, uint64_t maximum);
wt_status_t wt_webtransport_max_stream_data_write(wt_writer_t *w, uint64_t stream_id,
                                                  uint64_t maximum);
wt_status_t wt_webtransport_max_streams_write(wt_writer_t *w, int bidirectional, uint64_t maximum);
wt_status_t wt_webtransport_data_blocked_write(wt_writer_t *w, uint64_t maximum);
wt_status_t wt_webtransport_stream_data_blocked_write(wt_writer_t *w, uint64_t stream_id,
                                                      uint64_t maximum);
wt_status_t wt_webtransport_streams_blocked_write(wt_writer_t *w, int bidirectional,
                                                 uint64_t maximum);

/* Parse the one-varint capsules. Anything but exactly one varint is
 * H3_MESSAGE_ERROR: a flow-control value that is not a number is not a limit. */
wt_status_t wt_webtransport_max_data_parse(const wt_webtransport_capsule_t *capsule,
                                           uint64_t *out_maximum, wt_http3_error_t *out_error);
wt_status_t wt_webtransport_max_streams_parse(const wt_webtransport_capsule_t *capsule,
                                              uint64_t *out_maximum, wt_http3_error_t *out_error);
wt_status_t wt_webtransport_data_blocked_parse(const wt_webtransport_capsule_t *capsule,
                                               uint64_t *out_maximum, wt_http3_error_t *out_error);

/* Parse the two-varint capsules: a stream id and a value. */
wt_status_t wt_webtransport_max_stream_data_parse(const wt_webtransport_capsule_t *capsule,
                                                  uint64_t *out_stream_id, uint64_t *out_maximum,
                                                  wt_http3_error_t *out_error);
wt_status_t wt_webtransport_stream_data_blocked_parse(const wt_webtransport_capsule_t *capsule,
                                                      uint64_t *out_stream_id,
                                                      uint64_t *out_maximum,
                                                      wt_http3_error_t *out_error);
wt_status_t wt_webtransport_streams_blocked_parse(const wt_webtransport_capsule_t *capsule,
                                                  uint64_t *out_maximum,
                                                  wt_http3_error_t *out_error);

/* The connection-level limits a session's peer has granted, with the rule that they must
 * STRICTLY increase (section 5.1): a value at or below what was sent before is
 * WT_FLOW_CONTROL_ERROR. A repeat is refused along with a decrease because a repeat is
 * what a peer sends when it is confused about what it already granted, and accepting it
 * would hide the confusion. The first capsule establishes a limit; there is no default. */
typedef struct wt_webtransport_flow_limits {
  uint64_t max_data;
  int max_data_set;
  uint64_t max_streams_bidi;
  int max_streams_bidi_set;
  uint64_t max_streams_uni;
  int max_streams_uni_set;
} wt_webtransport_flow_limits_t;

void wt_webtransport_flow_limits_init(wt_webtransport_flow_limits_t *limits);
wt_status_t wt_webtransport_flow_on_max_data(wt_webtransport_flow_limits_t *limits, uint64_t maximum,
                                             uint64_t *out_error);
wt_status_t wt_webtransport_flow_on_max_streams(wt_webtransport_flow_limits_t *limits,
                                                int bidirectional, uint64_t maximum,
                                                uint64_t *out_error);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_WEBTRANSPORT_CAPSULE_H */
