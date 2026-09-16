/* The session's send-side flow control (Phase 8). */

#include "webtransport/api/flow.h"

#include "session_internal.h"
#include "webtransport/webtransport/capsule.h"

wt_session_limit_state_t wt_session_limit_state_of(int enabled, int is_set, uint64_t value) {
  if (!enabled) return WT_SESSION_LIMIT_DISABLED;
  if (!is_set) return WT_SESSION_LIMIT_UNLIMITED;
  return value == 0U ? WT_SESSION_LIMIT_ZERO : WT_SESSION_LIMIT_LIMITED;
}

/* One setting, read the way the settings layer reports it: the value, and whether the
 * endpoint sent it at all. */
static uint64_t advertised_value(const wt_http3_settings_t *settings, uint64_t identifier) {
  int present = 0;
  uint64_t value = wt_http3_settings_get(settings, identifier, &present);
  return present != 0 ? value : 0U;
}

int wt_session_flow_advertised(const wt_http3_settings_t *settings) {
  if (settings == NULL) return 0;

  /* Any one of the three being non-zero is the draft's answer. A setting the endpoint
   * omitted is not a grant of zero; it is silence, and silence does not enable flow
   * control. */
  if (advertised_value(settings, WT_HTTP3_SETTING_WT_INITIAL_MAX_DATA) > 0U) return 1;
  if (advertised_value(settings, WT_HTTP3_SETTING_WT_INITIAL_MAX_STREAMS_UNI) > 0U) return 1;
  if (advertised_value(settings, WT_HTTP3_SETTING_WT_INITIAL_MAX_STREAMS_BIDI) > 0U) return 1;
  return 0;
}

wt_status_t wt_session_flow_configure(wt_session_t *session, int enabled, uint64_t initial_max_data,
                                      uint64_t initial_max_streams_bidi,
                                      uint64_t initial_max_streams_uni) {
  uint64_t error = 0U;
  wt_status_t status;

  if (session == NULL) return WT_ERR_INVALID_ARGUMENT;

  wt_webtransport_flow_limits_init(&session->limits);
  session->flow_enabled = enabled != 0;
  session->used_data = 0U;
  session->opened_streams_bidi = 0U;
  session->opened_streams_uni = 0U;

  if (session->flow_enabled == 0) {
    /* Nothing to record: with flow control off, the values are not limits this endpoint
     * enforces, and pretending otherwise would make an unenforced number look like a
     * promise. */
    wt_session_set_error(session, WT_OK, 0U);
    return WT_OK;
  }

  /* The initial limits go through the same monotonic path as a capsule, so a SETTINGS
   * value above the stream ceiling is refused here rather than at the first capsule. */
  status = wt_webtransport_flow_on_max_data(&session->limits, initial_max_data, &error);
  if (status != WT_OK) {
    wt_session_set_error(session, status, error);
    return status;
  }
  status = wt_webtransport_flow_on_max_streams(&session->limits, 1, initial_max_streams_bidi,
                                              &error);
  if (status != WT_OK) {
    wt_session_set_error(session, status, error);
    return status;
  }
  status = wt_webtransport_flow_on_max_streams(&session->limits, 0, initial_max_streams_uni,
                                              &error);
  if (status != WT_OK) {
    wt_session_set_error(session, status, error);
    return status;
  }
  wt_session_set_error(session, WT_OK, 0U);
  return WT_OK;
}

wt_session_flow_state_t wt_session_flow_snapshot(const wt_session_t *session) {
  wt_session_flow_state_t state;

  state.enabled = 0;
  state.max_data_state = WT_SESSION_LIMIT_DISABLED;
  state.max_data = 0U;
  state.max_streams_bidi_state = WT_SESSION_LIMIT_DISABLED;
  state.max_streams_bidi = 0U;
  state.max_streams_uni_state = WT_SESSION_LIMIT_DISABLED;
  state.max_streams_uni = 0U;
  state.used_data = 0U;
  state.opened_streams_bidi = 0U;
  state.opened_streams_uni = 0U;
  if (session == NULL) return state;

  state.enabled = session->flow_enabled;
  state.max_data_state = wt_session_limit_state_of(session->flow_enabled,
                                                   session->limits.max_data_set,
                                                   session->limits.max_data);
  state.max_data = session->limits.max_data;
  state.max_streams_bidi_state =
      wt_session_limit_state_of(session->flow_enabled, session->limits.max_streams_bidi_set,
                                session->limits.max_streams_bidi);
  state.max_streams_bidi = session->limits.max_streams_bidi;
  state.max_streams_uni_state =
      wt_session_limit_state_of(session->flow_enabled, session->limits.max_streams_uni_set,
                                session->limits.max_streams_uni);
  state.max_streams_uni = session->limits.max_streams_uni;
  state.used_data = session->used_data;
  state.opened_streams_bidi = session->opened_streams_bidi;
  state.opened_streams_uni = session->opened_streams_uni;
  return state;
}

uint64_t wt_session_flow_data_allowance(const wt_session_t *session) {
  uint64_t limit;

  if (session == NULL || session->flow_enabled == 0 || session->limits.max_data_set == 0) {
    return UINT64_MAX;
  }
  limit = session->limits.max_data;
  /* Saturating: a limit at the counter's top and a usage of zero must not report a
   * wrapped "plenty left". */
  if (session->used_data >= limit) return 0U;
  return limit - session->used_data;
}

uint64_t wt_session_flow_stream_allowance(const wt_session_t *session, int unidirectional) {
  uint64_t limit;
  uint64_t opened;
  int is_set;

  if (session == NULL || session->flow_enabled == 0) return UINT64_MAX;
  is_set = unidirectional != 0 ? session->limits.max_streams_uni_set
                               : session->limits.max_streams_bidi_set;
  if (is_set == 0) return UINT64_MAX;
  limit = unidirectional != 0 ? session->limits.max_streams_uni : session->limits.max_streams_bidi;
  opened = unidirectional != 0 ? session->opened_streams_uni : session->opened_streams_bidi;
  if (opened >= limit) return 0U;
  return limit - opened;
}

wt_status_t wt_session_flow_record_data(wt_session_t *session, size_t bytes) {
  uint64_t count = (uint64_t)bytes;

  if (session == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (session->flow_enabled == 0) {
    wt_session_set_error(session, WT_OK, 0U);
    return WT_OK;
  }
  /* There is no "enabled but no limit yet" state to special-case: `flow_enabled` is written
   * only by `wt_session_flow_configure`, which resets the limits and then ALWAYS calls
   * `wt_webtransport_flow_on_max_data`, which sets `max_data_set`. An enabled session
   * therefore always has a limit here, so the first capsule is measured against it. */
  if (count > session->limits.max_data - session->used_data) {
    /* Refused with the code the peer would be sent for the violation, so a caller that
     * propagates it closes the session correctly instead of inventing a code. */
    wt_session_set_error(session, WT_ERR_LIMIT, WT_WEBTRANSPORT_FLOW_CONTROL_ERROR);
    return WT_ERR_LIMIT;
  }
  session->used_data += count;
  wt_session_set_error(session, WT_OK, 0U);
  return WT_OK;
}

wt_status_t wt_session_flow_register_stream(wt_session_t *session, int unidirectional) {
  uint64_t *opened;
  uint64_t limit;
  int is_set;

  if (session == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (session->flow_enabled == 0) {
    wt_session_set_error(session, WT_OK, 0U);
    return WT_OK;
  }

  opened = unidirectional != 0 ? &session->opened_streams_uni : &session->opened_streams_bidi;
  is_set = unidirectional != 0 ? session->limits.max_streams_uni_set
                               : session->limits.max_streams_bidi_set;
  limit = unidirectional != 0 ? session->limits.max_streams_uni : session->limits.max_streams_bidi;

  if (is_set != 0 && *opened >= limit) {
    wt_session_set_error(session, WT_ERR_LIMIT, WT_WEBTRANSPORT_FLOW_CONTROL_ERROR);
    return WT_ERR_LIMIT;
  }
  (*opened)++;
  wt_session_set_error(session, WT_OK, 0U);
  return WT_OK;
}
