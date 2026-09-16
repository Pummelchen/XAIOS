/* The session's send-side flow control (Phase 8).
 *
 * Draft-16 gives a WebTransport session its own flow control on top of QUIC's: a peer
 * grants a session-level data limit, a count of streams in each direction, and per-stream
 * data limits, as capsules on the CONNECT stream. This header is the endpoint's view of
 * what it may SEND, and it exists so that "may I send this" is a question with an answer
 * rather than an assumption -- which is what backpressure means when there is no socket to
 * block on.
 *
 * The rules are the draft's and the Swift implementation's, and two of them are worth
 * stating here because they are the ones a caller gets wrong:
 *
 *   - FLOW CONTROL IS OFF UNTIL BOTH ENDPOINTS SAY OTHERWISE. The draft enables it with
 *     SETTINGS, and `wt_session_flow_configure` is where a caller reports what the peer's
 *     SETTINGS said. While it is off, a flow-control capsule is IGNORED rather than
 *     refused, because a peer that sends one anyway is not breaking anything this endpoint
 *     relies on.
 *
 *   - LIMITS STRICTLY INCREASE. A capsule at or below a limit already granted is the
 *     draft's flow-control error, and a limit above the draft's ceiling for stream counts
 *     is the same error, because the stream ID space it would describe does not exist.
 *
 * Every limit here is the PEER's grant, so a refusal is about this endpoint's arithmetic
 * or the peer's capsule, never about data this endpoint mis-sent: the allowance functions
 * are how a caller avoids ever reaching the refusal.
 */

#ifndef WEBTRANSPORT_API_FLOW_H
#define WEBTRANSPORT_API_FLOW_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/api/session.h"
#include "webtransport/http3/settings.h"
#include "webtransport/webtransport/session_request.h"

#ifdef __cplusplus
extern "C" {
#endif

/* What is known about one limit. `UNLIMITED` means no limit has been communicated, which
 * is a state of the conversation and not the number infinity; the first capsule
 * establishes the limit rather than being rejected as a decrease. `DISABLED` means this
 * session agreed no flow control at all and every limit is unenforced. */
typedef enum wt_session_limit_state {
  WT_SESSION_LIMIT_DISABLED = 0,
  WT_SESSION_LIMIT_ZERO = 1,
  WT_SESSION_LIMIT_UNLIMITED = 2,
  WT_SESSION_LIMIT_LIMITED = 3
} wt_session_limit_state_t;

/* A snapshot, so a caller can log or test the whole picture without holding a pointer
 * into the session. `*_value` is meaningful only for `LIMITED`. */
typedef struct wt_session_flow_state {
  int enabled;
  wt_session_limit_state_t max_data_state;
  uint64_t max_data;
  wt_session_limit_state_t max_streams_bidi_state;
  uint64_t max_streams_bidi;
  wt_session_limit_state_t max_streams_uni_state;
  uint64_t max_streams_uni;
  /* What this endpoint has already sent against `max_data`, and how many streams it has
   * started in each direction. */
  uint64_t used_data;
  uint64_t opened_streams_bidi;
  uint64_t opened_streams_uni;
} wt_session_flow_state_t;

/* The draft's "this endpoint advertises flow control" rule for one endpoint's SETTINGS:
 * any of the three initial limits is non-zero. A session is enabled when the LOCAL answer
 * and the PEER's answer are both yes, which is what a caller computes from its own
 * SETTINGS and the peer's. An endpoint that omits the settings answers no. */
int wt_session_flow_advertised(const wt_http3_settings_t *settings);

/* Configure this session from the peer's SETTINGS, which carry the session's INITIAL
 * limits. A setting the peer omitted is zero, exactly as it is on the wire, so a session
 * enabled through one setting and not another starts that other limit at zero rather than
 * unlimited. Replaces every limit and zeroes the usage counters, so it is called once,
 * when the handshake's SETTINGS are read. */
wt_status_t wt_session_flow_configure(wt_session_t *session, int enabled, uint64_t initial_max_data,
                                      uint64_t initial_max_streams_bidi,
                                      uint64_t initial_max_streams_uni);

wt_session_flow_state_t wt_session_flow_snapshot(const wt_session_t *session);

/* This endpoint sent `bytes` of session data. Refused with `WT_ERR_LIMIT` -- and the
 * draft's flow-control code, which is what the peer would be sent for the violation --
 * when it would exceed the limit. A caller that asks the allowance first never sees it. */
wt_status_t wt_session_flow_record_data(wt_session_t *session, size_t bytes);

/* This endpoint is starting a stream. Refused the same way when the direction's count is
 * already reached. */
wt_status_t wt_session_flow_register_stream(wt_session_t *session, int unidirectional);

/* How much may still be sent, saturating rather than wrapping. `UINT64_MAX` means no limit
 * is in force, which is not the same as "send an unbounded amount now" -- QUIC's own
 * congestion and stream flow control still apply -- and zero means wait. */
uint64_t wt_session_flow_data_allowance(const wt_session_t *session);
uint64_t wt_session_flow_stream_allowance(const wt_session_t *session, int unidirectional);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_API_FLOW_H */
