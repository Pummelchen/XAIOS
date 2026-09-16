/* The event-loop seam (Phase 8). */

#include "webtransport/api/events.h"

#include <string.h>

#include "session_internal.h"
#include "webtransport/webtransport/framing.h"

wt_status_t wt_session_set_callbacks(wt_session_t *session, const wt_session_callbacks_t *callbacks) {
  if (session == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (callbacks == NULL) {
    /* Clearing is a memset rather than a flag, so a stale pointer cannot be called after
     * the caller withdrew it. */
    memset(&session->callbacks, 0, sizeof(session->callbacks));
  } else {
    session->callbacks = *callbacks;
  }
  wt_session_set_error(session, WT_OK, 0U);
  return WT_OK;
}

wt_session_stream_slot_t *wt_session_find_stream(wt_session_t *session, uint64_t stream_id) {
  size_t i;
  for (i = 0U; i < session->stream_count; i++) {
    if (session->streams[i].stream_id == stream_id) return &session->streams[i];
  }
  return NULL;
}

void wt_session_forget_stream(wt_session_t *session, uint64_t stream_id) {
  size_t i;
  for (i = 0U; i < session->stream_count; i++) {
    if (session->streams[i].stream_id == stream_id) {
      /* The table is unordered, so the last entry fills the hole: order carries no
       * meaning here and a shift would cost a copy per close. */
      session->streams[i] = session->streams[session->stream_count - 1U];
      session->stream_count--;
      return;
    }
  }
}

size_t wt_session_stream_count(const wt_session_t *session) {
  if (session == NULL) return 0U;
  return session->stream_count;
}

wt_status_t wt_session_on_stream_opened(wt_session_t *session, uint64_t stream_id,
                                        int unidirectional, uint64_t session_id) {
  wt_session_stream_slot_t *slot;

  if (session == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (stream_id == 0U) return WT_ERR_INVALID_ARGUMENT;

  /* A stream whose prefix named a different session is not ours to deliver, and the code
   * is HTTP/3's identifier error: the peer named an ID that cannot be for this session. */
  if (session_id != session->session_id) {
    wt_session_set_error(session, WT_ERR_STATE, (uint64_t)WT_HTTP3_ID_ERROR);
    return WT_ERR_STATE;
  }

  if (wt_session_find_stream(session, stream_id) != NULL) {
    /* Opened twice: the application's ordering, not the wire's. */
    wt_session_set_error(session, WT_ERR_STATE, 0U);
    return WT_ERR_STATE;
  }

  if (session->stream_count >= session->max_streams) {
    /* The bound this endpoint published. Refused rather than grown, and the code says
     * the load was excessive rather than that the peer malformed anything. */
    wt_session_set_error(session, WT_ERR_LIMIT, (uint64_t)WT_HTTP3_EXCESSIVE_LOAD);
    return WT_ERR_LIMIT;
  }

  slot = &session->streams[session->stream_count];
  slot->stream_id = stream_id;
  slot->unidirectional = unidirectional;
  session->stream_count++;

  /* Recorded BEFORE the callback and touched nowhere after it: the callback is the last thing this function does
   * to the session, so the error surface it can read is this call's, and the library does not write through a
   * handle the callback may have released. `webtransport/api/events.h` states the contract the callback is held
   * to -- it must not call back into the session, because the driver owns the handle next. */
  wt_session_set_error(session, WT_OK, 0U);
  if (session->callbacks.on_stream_opened != NULL) {
    session->callbacks.on_stream_opened(session->callbacks.context, stream_id, unidirectional);
  }
  return WT_OK;
}

wt_status_t wt_session_on_stream_data(wt_session_t *session, uint64_t stream_id,
                                      const uint8_t *data, size_t length, int end_stream) {
  if (session == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (data == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (wt_session_find_stream(session, stream_id) == NULL) {
    wt_session_set_error(session, WT_ERR_STATE, 0U);
    return WT_ERR_STATE;
  }

  /* The state and the error surface are settled BEFORE the callback, and nothing touches the session after it
   * returns. The first version forgot the stream AFTER the callback "so the callback still sees it as open",
   * which bought a callback a stream count that was about to change and paid for it with a write through a
   * handle the callback could have released. A callback is told `end_stream` in its arguments, so it does not
   * need the table to still hold the stream to know the stream has ended. */
  if (end_stream != 0) wt_session_forget_stream(session, stream_id);
  wt_session_set_error(session, WT_OK, 0U);
  if (session->callbacks.on_stream_data != NULL) {
    session->callbacks.on_stream_data(session->callbacks.context, stream_id, data, length,
                                      end_stream != 0);
  }
  return WT_OK;
}

wt_status_t wt_session_on_stream_reset(wt_session_t *session, uint64_t stream_id,
                                       uint64_t error_code) {
  if (session == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (wt_session_find_stream(session, stream_id) == NULL) {
    wt_session_set_error(session, WT_ERR_STATE, 0U);
    return WT_ERR_STATE;
  }

  /* Settled before the callback, for the reason the stream-data path above records. */
  wt_session_forget_stream(session, stream_id);
  wt_session_set_error(session, WT_OK, error_code);
  if (session->callbacks.on_stream_reset != NULL) {
    /* The peer's code, unchanged: a refusal keeps the peer's code at this surface too. */
    session->callbacks.on_stream_reset(session->callbacks.context, stream_id, error_code);
  }
  return WT_OK;
}

wt_status_t wt_session_on_datagram(wt_session_t *session, const uint8_t *data, size_t length) {
  uint64_t quarter = 0U;
  const uint8_t *payload = NULL;
  size_t payload_length = 0U;
  wt_http3_error_t h3_error = WT_HTTP3_NO_ERROR;
  wt_status_t status;

  if (session == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (data == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;

  status = wt_webtransport_datagram_parse(data, length, &quarter, &payload, &payload_length,
                                          &h3_error);
  if (status != WT_OK) {
    wt_session_set_error(session, status, (uint64_t)h3_error);
    return status;
  }

  if (quarter != wt_webtransport_quarter_stream_id(session->session_id)) {
    /* A datagram for another session on this connection. Refused with HTTP/3's identifier
     * error, not delivered to the wrong session and not silently dropped: the peer named
     * an ID that is not ours. */
    wt_session_set_error(session, WT_ERR_STATE, (uint64_t)WT_HTTP3_ID_ERROR);
    return WT_ERR_STATE;
  }

  if (payload_length > session->max_datagram_bytes) {
    wt_session_set_error(session, WT_ERR_LIMIT, (uint64_t)WT_HTTP3_EXCESSIVE_LOAD);
    return WT_ERR_LIMIT;
  }

  wt_session_set_error(session, WT_OK, 0U);
  if (session->callbacks.on_datagram != NULL) {
    session->callbacks.on_datagram(session->callbacks.context, payload, payload_length);
  }
  return WT_OK;
}
