/* The session handle's layout, shared by the API's translation units.
 *
 * This header is NOT installed and NOT public: `api/session.h` declares `wt_session_t` as
 * an incomplete type deliberately, so the layout may change between releases. Only the
 * files that make up the API see it. */

#ifndef WEBTRANSPORT_API_SESSION_INTERNAL_H
#define WEBTRANSPORT_API_SESSION_INTERNAL_H

#include "webtransport/api/events.h"
#include "webtransport/api/flow.h"
#include "webtransport/webtransport/session.h"

/* A peer stream this handle is tracking. */
typedef struct wt_session_stream_slot {
  uint64_t stream_id;
  int unidirectional;
} wt_session_stream_slot_t;

struct wt_session {
  wt_webtransport_session_t machine;
  wt_session_error_t error;
  /* The CONNECT stream ID this session lives on, which is what a datagram's quarter
   * stream ID and a WebTransport stream's prefix must both name. */
  uint64_t session_id;
  size_t max_capsule_bytes;
  size_t max_datagram_bytes;
  size_t max_streams;
  char authority[WT_SESSION_AUTHORITY_MAX];
  char path[WT_SESSION_AUTHORITY_MAX];
  wt_session_callbacks_t callbacks;
  /* The peer's grants and this endpoint's usage against them. */
  wt_webtransport_flow_limits_t limits;
  int flow_enabled;
  uint64_t used_data;
  uint64_t opened_streams_bidi;
  uint64_t opened_streams_uni;
  /* Fixed, because a stream table that grows with a peer is a heap exhaustion path with a
   * peer's name on it. */
  wt_session_stream_slot_t streams[WT_SESSION_STREAM_MAX];
  size_t stream_count;
};

/* Derive the state of one limit from its recorded value, for both translation units. */
wt_session_limit_state_t wt_session_limit_state_of(int enabled, int is_set, uint64_t value);

/* Record the last failure. Used by both translation units so a session's error surface
 * cannot drift between them. */
void wt_session_set_error(wt_session_t *session, wt_status_t status, uint64_t code);

/* Find a tracked peer stream, or NULL. */
wt_session_stream_slot_t *wt_session_find_stream(wt_session_t *session, uint64_t stream_id);

/* Stop tracking a stream. */
void wt_session_forget_stream(wt_session_t *session, uint64_t stream_id);

#endif /* WEBTRANSPORT_API_SESSION_INTERNAL_H */
