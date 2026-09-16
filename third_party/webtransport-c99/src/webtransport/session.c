/* A WebTransport session's lifecycle (draft-ietf-webtrans-http3-16 sections 3 to 5). */

#include "webtransport/webtransport/session.h"

void wt_webtransport_session_init(wt_webtransport_session_t *session) {
  if (session == NULL) return;
  session->state = WT_WEBTRANSPORT_SESSION_ESTABLISHING;
  session->close_error_code = 0U;
  session->close_error_set = 0;
  session->drain_sent = 0;
  session->drain_received = 0;
  session->close_sent = 0;
  session->close_received = 0;
}

wt_status_t wt_webtransport_session_established(wt_webtransport_session_t *session) {
  if (session == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* Only from the establishing state: a session that is draining or closed cannot be
   * established by a late response, and saying so is better than silently ignoring it. */
  if (session->state != WT_WEBTRANSPORT_SESSION_ESTABLISHING) return WT_ERR_STATE;
  session->state = WT_WEBTRANSPORT_SESSION_ESTABLISHED;
  return WT_OK;
}

wt_status_t wt_webtransport_session_on_drain(wt_webtransport_session_t *session, int sent) {
  if (session == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (session->state == WT_WEBTRANSPORT_SESSION_CLOSED) return WT_ERR_STATE;
  if (sent) {
    session->drain_sent = 1;
  } else {
    session->drain_received = 1;
  }
  /* A drain is only meaningful once the session exists; from the establishing state it
   * still records what happened, and the state stays where it is because the session is
   * not yet usable either way. */
  if (session->state == WT_WEBTRANSPORT_SESSION_ESTABLISHED) {
    session->state = WT_WEBTRANSPORT_SESSION_DRAINING;
  }
  return WT_OK;
}

wt_status_t wt_webtransport_session_on_close(wt_webtransport_session_t *session, int sent,
                                             uint32_t error_code) {
  if (session == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (sent) {
    session->close_sent = 1;
  } else {
    session->close_received = 1;
  }
  /* The first close's code is the session's: a second close, from either side, is
   * accepted and does not rewrite what the session ended with. */
  if (!session->close_error_set) {
    session->close_error_code = error_code;
    session->close_error_set = 1;
  }
  session->state = WT_WEBTRANSPORT_SESSION_CLOSED;
  return WT_OK;
}

wt_status_t wt_webtransport_session_on_stream_end(wt_webtransport_session_t *session) {
  if (session == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (session->state == WT_WEBTRANSPORT_SESSION_CLOSED) return WT_ERR_STATE;
  /* No capsule came with the end, so there is no application code to report -- which is
   * different from a close whose code happens to be zero, and the flag above is what
   * keeps the two apart. */
  session->state = WT_WEBTRANSPORT_SESSION_CLOSED;
  return WT_OK;
}

int wt_webtransport_session_allows_new_streams(const wt_webtransport_session_t *session) {
  if (session == NULL) return 0;
  return session->state == WT_WEBTRANSPORT_SESSION_ESTABLISHED;
}

wt_status_t wt_webtransport_session_write_drain(wt_webtransport_session_t *session, wt_writer_t *w) {
  wt_status_t status;

  if (session == NULL || w == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (session->state == WT_WEBTRANSPORT_SESSION_CLOSED) return WT_ERR_STATE;

  status = wt_webtransport_drain_session_write(w);
  if (status != WT_OK) return status;
  return wt_webtransport_session_on_drain(session, 1);
}

wt_status_t wt_webtransport_session_write_close(wt_webtransport_session_t *session, wt_writer_t *w,
                                               uint32_t error_code, const uint8_t *reason,
                                               size_t reason_length) {
  wt_status_t status;

  if (session == NULL || w == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (session->state == WT_WEBTRANSPORT_SESSION_CLOSED) return WT_ERR_STATE;
  /* Never established: the session never existed, so there is nothing to close. */
  if (session->state == WT_WEBTRANSPORT_SESSION_ESTABLISHING) return WT_ERR_STATE;

  status = wt_webtransport_close_session_write(w, error_code, reason, reason_length);
  if (status != WT_OK) return status;
  return wt_webtransport_session_on_close(session, 1, error_code);
}

wt_status_t wt_webtransport_session_on_capsule_bytes(wt_webtransport_session_t *session,
                                                     wt_cursor_t *cursor, size_t max_capsule_bytes,
                                                     wt_webtransport_capsule_fn observe, void *context,
                                                     wt_http3_error_t *out_error) {
  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (session == NULL || cursor == NULL) return WT_ERR_INVALID_ARGUMENT;

  if (session->state == WT_WEBTRANSPORT_SESSION_CLOSED && wt_cursor_remaining(cursor) > 0U) {
    /* Section 5.4: a WT_CLOSE_SESSION capsule is the LAST thing on the CONNECT stream. A caller that rebuilds a
     * cursor per delivery -- apps/support/capsule_stream.c does, once per STREAM frame -- would otherwise apply a
     * capsule that arrived in a LATER frame after the close, because the close branch's own tail check only sees
     * the remainder of the buffer the close capsule itself was in. The state is therefore checked on ENTRY too.
     * An EMPTY delivery is left alone: a CONNECT stream that merely ends after the close is the ordinary FIN, not
     * a capsule, and refusing it would turn a normal end into a message error. */
    if (out_error != NULL) *out_error = WT_HTTP3_MESSAGE_ERROR;
    return WT_ERR_PROTOCOL;
  }

  for (;;) {
    wt_webtransport_capsule_t capsule;
    /* Walked in a COPY, so that a capsule which has not fully arrived leaves the caller's cursor on its first
     * byte. The decoder consumes the header before it can know whether the value is here, so committing the
     * cursor only on success is what makes "come back with more bytes" work. */
    wt_cursor_t ahead = *cursor;
    size_t remaining = wt_cursor_remaining(cursor);
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    wt_status_t status;

    if (remaining == 0U) return WT_OK;
    status = wt_webtransport_capsule_decode(&ahead, max_capsule_bytes, &capsule, &error);
    if (status == WT_ERR_TRUNCATED) return WT_ERR_TRUNCATED;
    if (status != WT_OK) {
      if (out_error != NULL) *out_error = error;
      return status;
    }

    if (capsule.type == WT_CAPSULE_DRAIN_SESSION) {
      /* Section 5.2 fixes the value at Length=0 -- "the application does not need to send any additional data" --
       * so a value here is a capsule this layer cannot read rather than one it can ignore. It used to be ignored,
       * which is a malformed capsule accepted in silence. */
      if (capsule.value_length != 0U) {
        if (out_error != NULL) *out_error = WT_HTTP3_MESSAGE_ERROR;
        return WT_ERR_PROTOCOL;
      }
      /* The peer is going away: no new streams, and the ones in flight may finish (section 5.2). */
      status = wt_webtransport_session_on_drain(session, 0);
      error = WT_HTTP3_NO_ERROR;
    } else if (capsule.type == WT_CAPSULE_CLOSE_WEBTRANSPORT_SESSION) {
      uint32_t code = 0U;
      const uint8_t *reason = NULL;
      size_t reason_length = 0U;

      status = wt_webtransport_close_session_parse(&capsule, &code, &reason, &reason_length, &error);
      if (status == WT_OK) status = wt_webtransport_session_on_close(session, 0, code);
      if (status == WT_OK && wt_cursor_remaining(&ahead) > 0U) {
        /* Section 5.4: a WT_CLOSE_SESSION capsule is the LAST thing on the CONNECT stream. Bytes after it are
         * not capsules any more, and this layer used to keep walking them and applying whatever they named --
         * a peer could close the session and then send another grant, which the endpoint would honour. The
         * stream's remainder is a message error. */
        if (out_error != NULL) *out_error = WT_HTTP3_MESSAGE_ERROR;
        return WT_ERR_PROTOCOL;
      }
    } else if (observe != NULL) {
      error = WT_HTTP3_NO_ERROR;
      status = observe(context, &capsule, &error);
    } else {
      status = WT_OK;
    }
    if (status != WT_OK) {
      if (out_error != NULL) *out_error = error;
      return status;
    }
    /* Committed only now: every complete capsule in the buffer has been applied, and the next iteration is the
     * one that may find a partial one. */
    *cursor = ahead;
  }
}
