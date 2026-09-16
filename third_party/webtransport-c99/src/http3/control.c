/* The peer's HTTP/3 control stream. See webtransport/http3/control.h. */

#include "webtransport/http3/control.h"

void wt_http3_control_init(wt_http3_control_stream_t *control) {
  if (control == NULL) return;
  control->opened = 0;
  control->settings_received = 0;
  control->closed = 0;
}

wt_status_t wt_http3_control_peer_opened(wt_http3_control_stream_t *control,
                                         wt_http3_error_t *out_error) {
  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (control == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (control->opened) {
    /* Section 6.2.1: "Only one control stream per peer is permitted; receipt of
     * a second stream claiming to be a control stream MUST be treated as a
     * connection error of type H3_STREAM_CREATION_ERROR." */
    if (out_error != NULL) *out_error = WT_HTTP3_STREAM_CREATION_ERROR;
    return WT_ERR_PROTOCOL;
  }
  control->opened = 1;
  return WT_OK;
}

wt_status_t wt_http3_control_on_frame(wt_http3_control_stream_t *control, uint64_t type,
                                      wt_http3_error_t *out_error) {
  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (control == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (!control->opened || control->closed) {
    /* The caller's own ordering: a frame cannot arrive on a stream that does not
     * exist, or after it ended. This is not a peer error, so it is not one of the
     * codes. */
    return WT_ERR_STATE;
  }

  if (!control->settings_received) {
    if (type == WT_HTTP3_FRAME_SETTINGS) {
      control->settings_received = 1;
      return WT_OK;
    }
    /* Section 6.2.1: "If the first frame of the control stream is any other frame
     * type, this MUST be treated as a connection error of type
     * H3_MISSING_SETTINGS." */
    if (out_error != NULL) *out_error = WT_HTTP3_MISSING_SETTINGS;
    return WT_ERR_PROTOCOL;
  }

  /* Section 7.2.8: the frame types HTTP/2 used where HTTP/3 has no equivalent
   * MUST NOT be sent, and receiving one is H3_FRAME_UNEXPECTED. Checked before
   * the types below so a reserved type is reported as reserved rather than as
   * whatever it resembles. */
  if (wt_http3_frame_type_is_reserved(type)) {
    if (out_error != NULL) *out_error = WT_HTTP3_FRAME_UNEXPECTED;
    return WT_ERR_PROTOCOL;
  }

  /* Section 7.2.4: SETTINGS "MUST be sent as the first frame of each control
   * stream ... and it MUST NOT be sent subsequently", and a second one is
   * H3_FRAME_UNEXPECTED. */
  if (type == WT_HTTP3_FRAME_SETTINGS) {
    if (out_error != NULL) *out_error = WT_HTTP3_FRAME_UNEXPECTED;
    return WT_ERR_PROTOCOL;
  }

  /* Sections 7.2.1, 7.2.2 and 7.2.5: DATA, HEADERS and PUSH_PROMISE describe
   * requests and responses. On a control stream there is nothing for them to
   * describe, and each section makes receipt H3_FRAME_UNEXPECTED. */
  if (type == WT_HTTP3_FRAME_DATA || type == WT_HTTP3_FRAME_HEADERS ||
      type == WT_HTTP3_FRAME_PUSH_PROMISE) {
    if (out_error != NULL) *out_error = WT_HTTP3_FRAME_UNEXPECTED;
    return WT_ERR_PROTOCOL;
  }

  /* CANCEL_PUSH, GOAWAY and MAX_PUSH_ID belong here (sections 7.2.3, 7.2.6 and
   * 7.2.7), and so does anything this build has never heard of: HTTP/3 grows by
   * extension frames, and section 9's rule is that an unknown frame type is
   * ignored by the layer that does not need it. */
  return WT_OK;
}

wt_status_t wt_http3_control_on_closed(wt_http3_control_stream_t *control,
                                       wt_http3_error_t *out_error) {
  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (control == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (!control->opened || control->closed) return WT_ERR_STATE;
  control->closed = 1;
  /* Section 6.2.1: "The sender MUST NOT close the control stream ... If either
   * control stream is closed at any point, this MUST be treated as a connection
   * error of type H3_CLOSED_CRITICAL_STREAM." Whether SETTINGS had arrived is
   * irrelevant: the closure is the error, and a stream that never carried
   * SETTINGS has already been reported by the first-frame rule if it carried
   * something else. */
  if (out_error != NULL) *out_error = WT_HTTP3_CLOSED_CRITICAL_STREAM;
  return WT_ERR_PROTOCOL;
}
