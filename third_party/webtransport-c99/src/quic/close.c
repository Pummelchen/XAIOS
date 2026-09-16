/* Connection close paths. See webtransport/quic/close.h. */

#include "webtransport/quic/close.h"

#include <string.h>

void wt_quic_close_state_init(wt_quic_close_state_t *state) {
  if (state == NULL) return;
  memset(state, 0, sizeof(*state));
  state->kind = WT_QUIC_CLOSE_NONE;
}

static wt_status_t close_common(wt_quic_close_state_t *state, uint64_t error_code,
                                uint64_t frame_type, const uint8_t *reason,
                                size_t reason_length, uint64_t now, uint64_t pto) {
  if (state == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (reason == NULL && reason_length != 0U) return WT_ERR_INVALID_ARGUMENT;
  /* A connection closes once. A second close would move the draining deadline and could be sent as a
   * different kind of frame, which would tell the peer two different things about why the connection
   * ended. */
  if (state->kind != WT_QUIC_CLOSE_NONE) return WT_ERR_STATE;

  state->error_code = error_code;
  state->frame_type = frame_type;
  state->reason = reason;
  state->reason_length = reason_length;
  state->closed_at = now;
  /* RFC 9000 section 10.2.2: three times the probe timeout, which is the time an endpoint waits
   * before forgetting a connection it has closed. A caller with no probe timeout yet -- nothing has
   * been sent, so nothing has been measured -- passes zero and gets no deadline, which is different
   * from a deadline in the past. */
  if (pto != 0U) {
    state->draining_until = now + WT_QUIC_DRAINING_PERIOD_PTO_MULTIPLIER * pto;
    state->has_draining_deadline = 1;
  }
  return WT_OK;
}

wt_status_t wt_quic_close_transport(wt_quic_close_state_t *state, uint64_t error_code,
                                    uint64_t frame_type, const uint8_t *reason,
                                    size_t reason_length, uint64_t now, uint64_t pto) {
  wt_status_t status = close_common(state, error_code, frame_type, reason, reason_length,
                                    now, pto);
  if (status != WT_OK) return status;
  state->kind = WT_QUIC_CLOSE_TRANSPORT;
  return WT_OK;
}

wt_status_t wt_quic_close_application(wt_quic_close_state_t *state, uint64_t error_code,
                                      const uint8_t *reason, size_t reason_length,
                                      uint64_t now, uint64_t pto) {
  wt_status_t status = close_common(state, error_code, 0U, reason, reason_length, now, pto);
  if (status != WT_OK) return status;
  state->kind = WT_QUIC_CLOSE_APPLICATION;
  return WT_OK;
}

int wt_quic_close_is_closed(const wt_quic_close_state_t *state) {
  return (state == NULL) ? 0 : (state->kind != WT_QUIC_CLOSE_NONE);
}

wt_quic_close_kind_t wt_quic_close_kind(const wt_quic_close_state_t *state) {
  return (state == NULL) ? WT_QUIC_CLOSE_NONE : state->kind;
}

int wt_quic_close_draining_expired(const wt_quic_close_state_t *state, uint64_t now) {
  if (state == NULL || state->kind == WT_QUIC_CLOSE_NONE) return 0;
  /* Without a deadline there is nothing to expire: the caller has no timer to arm, so the connection
   * stays closed until it is destroyed rather than being forgotten on a deadline nobody set. */
  if (!state->has_draining_deadline) return 0;
  return now >= state->draining_until;
}

wt_status_t wt_quic_close_frame(const wt_quic_close_state_t *state, wt_quic_frame_t *out) {
  if (state == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (state->kind == WT_QUIC_CLOSE_NONE) return WT_ERR_STATE;
  memset(out, 0, sizeof(*out));
  if (state->kind == WT_QUIC_CLOSE_TRANSPORT) {
    out->kind = WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_TRANSPORT;
    /* The transport form carries the frame type that caused the error; zero is a real frame type
     * (PADDING), so the flag is what says whether the field means anything. The caller that has no
     * frame to name passes 0 and the flag stays set, because the RFC's field is required rather than
     * optional in this form. */
    out->as.connection_close.has_frame_type = 1;
    out->as.connection_close.frame_type = state->frame_type;
  } else {
    out->kind = WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_APPLICATION;
    /* RFC 9000 section 19.19: the application form has no frame type field, which is why the flag is
     * what distinguishes the two rather than the value. */
    out->as.connection_close.has_frame_type = 0;
    out->as.connection_close.frame_type = 0U;
  }
  out->as.connection_close.error_code = state->error_code;
  out->as.connection_close.reason = state->reason;
  out->as.connection_close.reason_length = state->reason_length;
  return WT_OK;
}

int wt_quic_close_accepts_frame_type(uint64_t frame_type) {
  /* RFC 9000 section 10.2.1: an endpoint in the closing state processes a packet only if it contains
   * CONNECTION_CLOSE, PADDING, or a probe. Everything else is a peer that has not yet learned the
   * connection is over, and acting on its frames would be acting on a closed connection. */
  switch (frame_type) {
    case WT_QUIC_FRAME_CONNECTION_CLOSE_TRANSPORT:
    case WT_QUIC_FRAME_CONNECTION_CLOSE_APPLICATION:
    case WT_QUIC_FRAME_PADDING:
    case WT_QUIC_FRAME_PING:
    case WT_QUIC_FRAME_PATH_CHALLENGE:
    case WT_QUIC_FRAME_PATH_RESPONSE:
      return 1;
    default:
      return 0;
  }
}
