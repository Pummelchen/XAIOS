/* Section 4.6's buffering rule for streams and datagrams that arrive before their session
 * (draft-ietf-webtrans-http3-16). See `webtransport/webtransport/buffered.h` for the rule and the
 * bounds; this file is the mechanism. */

#include "webtransport/webtransport/buffered.h"

#include <string.h>

#include "webtransport/webtransport/error.h"

void wt_webtransport_buffered_init(wt_webtransport_buffered_t *buffer) {
  if (buffer == NULL) return;
  memset(buffer, 0, sizeof(*buffer));
}

/* Drop one parked stream, keeping the arrival order of the rest: the drain delivers in that order,
 * so a hole filled from the end would reorder the flight. */
static void drop_stream(wt_webtransport_buffered_t *buffer, size_t index) {
  size_t i;
  for (i = index; i + 1U < buffer->stream_count; i++) {
    buffer->streams[i] = buffer->streams[i + 1U];
  }
  buffer->stream_count--;
}

/* The rejection section 4.6 names: the stream is not held, and the caller is told which one so it
 * can send the reset. One place records it, so the count, the ID and the status cannot disagree. */
static wt_status_t reject_stream(wt_webtransport_buffered_t *buffer, uint64_t stream_id) {
  buffer->streams_rejected++;
  buffer->last_rejected_stream_id = stream_id;
  return WT_ERR_LIMIT;
}

static wt_webtransport_buffered_stream_t *find_stream(wt_webtransport_buffered_t *buffer,
                                                      uint64_t stream_id) {
  size_t index;
  for (index = 0U; index < buffer->stream_count; index++) {
    if (buffer->streams[index].stream_id == stream_id) return &buffer->streams[index];
  }
  return NULL;
}

wt_status_t wt_webtransport_buffered_park_stream(wt_webtransport_buffered_t *buffer, uint64_t stream_id,
                                                 uint64_t session_id, int unidirectional,
                                                 const uint8_t *data, size_t length) {
  wt_webtransport_buffered_stream_t *parked;

  if (buffer == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (data == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;

  parked = find_stream(buffer, stream_id);
  if (parked == NULL) {
    if (buffer->stream_count >= WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX) {
      /* The bound the section requires, reached with streams still waiting to be associated. The
       * stream is rejected rather than held or dropped silently. */
      return reject_stream(buffer, stream_id);
    }
    if (length > WT_WEBTRANSPORT_BUFFERED_STREAM_BYTES_MAX) {
      return reject_stream(buffer, stream_id);
    }
    parked = &buffer->streams[buffer->stream_count];
    parked->stream_id = stream_id;
    parked->session_id = session_id;
    parked->unidirectional = unidirectional != 0 ? 1 : 0;
    parked->length = 0U;
    buffer->stream_count++;
  } else if (length > WT_WEBTRANSPORT_BUFFERED_STREAM_BYTES_MAX - parked->length) {
    /* A later piece of a stream already parked does not fit the hold. The whole stream is rejected
     * rather than its tail dropped: a stream delivered with a hole in it would be a corrupt message
     * rather than a short one. What was held for it goes too -- the stream is not parked any more,
     * and the reset the caller sends ends it. */
    size_t index = (size_t)(parked - buffer->streams);
    uint64_t rejected_id = parked->stream_id;
    drop_stream(buffer, index);
    return reject_stream(buffer, rejected_id);
  }

  if (length > 0U) memcpy(parked->bytes + parked->length, data, length);
  parked->length += length;
  return WT_OK;
}

wt_status_t wt_webtransport_buffered_drain_streams(wt_webtransport_buffered_t *buffer,
                                                   uint64_t session_id,
                                                   wt_webtransport_buffered_stream_fn deliver,
                                                   void *context, size_t *out_delivered,
                                                   size_t *out_dropped) {
  size_t delivered = 0U;
  size_t dropped = 0U;
  size_t index;
  wt_status_t first_error = WT_OK;

  if (out_delivered != NULL) *out_delivered = 0U;
  if (out_dropped != NULL) *out_dropped = 0U;
  if (buffer == NULL) return WT_ERR_INVALID_ARGUMENT;

  for (index = 0U; index < buffer->stream_count; index++) {
    const wt_webtransport_buffered_stream_t *parked = &buffer->streams[index];
    if (parked->session_id != session_id) {
      /* Not this session: dropped, and not an error. The peer sent it before this endpoint had a
       * reference point, so the ID it names was never checkable. */
      dropped++;
      continue;
    }
    if (deliver != NULL) {
      wt_status_t status = deliver(context, parked->stream_id, parked->unidirectional, parked->bytes,
                                   parked->length);
      if (status != WT_OK) {
        /* The callback's refusal stops the drain: the caller is being told something about the
         * session, and the streams behind this one are not delivered into a failing session. They
         * are not kept either -- the reference point exists now, so nothing is parked any more. The
         * count is of deliveries the callback ACCEPTED, so this one is not in it. */
        first_error = status;
        break;
      }
    }
    delivered++;
  }

  buffer->stream_count = 0U;
  if (out_delivered != NULL) *out_delivered = delivered;
  if (out_dropped != NULL) *out_dropped = dropped;
  return first_error;
}

int wt_webtransport_buffered_park_datagram(wt_webtransport_buffered_t *buffer,
                                           uint64_t quarter_stream_id, const uint8_t *payload,
                                           size_t length) {
  wt_webtransport_buffered_datagram_t *parked;

  if (buffer == NULL) return 0;
  if (payload == NULL && length != 0U) return 0;
  if (length > WT_WEBTRANSPORT_BUFFERED_DATAGRAM_BYTES_MAX) {
    buffer->datagrams_dropped++;
    return 0;
  }
  if (buffer->datagram_count >= WT_WEBTRANSPORT_BUFFERED_DATAGRAMS_MAX) {
    buffer->datagrams_dropped++;
    return 0;
  }

  parked = &buffer->datagrams[buffer->datagram_count];
  parked->quarter_stream_id = quarter_stream_id;
  parked->length = length;
  if (length > 0U) memcpy(parked->bytes, payload, length);
  buffer->datagram_count++;
  return 1;
}

wt_status_t wt_webtransport_buffered_drain_datagrams(wt_webtransport_buffered_t *buffer,
                                                     uint64_t quarter_stream_id,
                                                     wt_webtransport_buffered_datagram_fn deliver,
                                                     void *context, size_t *out_delivered,
                                                     size_t *out_dropped) {
  size_t delivered = 0U;
  size_t dropped = 0U;
  size_t index;
  wt_status_t first_error = WT_OK;

  if (out_delivered != NULL) *out_delivered = 0U;
  if (out_dropped != NULL) *out_dropped = 0U;
  if (buffer == NULL) return WT_ERR_INVALID_ARGUMENT;

  for (index = 0U; index < buffer->datagram_count; index++) {
    const wt_webtransport_buffered_datagram_t *parked = &buffer->datagrams[index];
    if (parked->quarter_stream_id != quarter_stream_id) {
      dropped++;
      continue;
    }
    if (deliver != NULL) {
      wt_status_t status = deliver(context, parked->quarter_stream_id, parked->bytes, parked->length);
      if (status != WT_OK) {
        first_error = status;
        break;
      }
    }
    delivered++;
  }

  buffer->datagram_count = 0U;
  if (out_delivered != NULL) *out_delivered = delivered;
  if (out_dropped != NULL) *out_dropped = dropped;
  return first_error;
}

size_t wt_webtransport_buffered_stream_count(const wt_webtransport_buffered_t *buffer) {
  return buffer != NULL ? buffer->stream_count : 0U;
}

size_t wt_webtransport_buffered_datagram_count(const wt_webtransport_buffered_t *buffer) {
  return buffer != NULL ? buffer->datagram_count : 0U;
}

uint64_t wt_webtransport_buffered_streams_rejected(const wt_webtransport_buffered_t *buffer) {
  return buffer != NULL ? buffer->streams_rejected : 0U;
}

uint64_t wt_webtransport_buffered_datagrams_dropped(const wt_webtransport_buffered_t *buffer) {
  return buffer != NULL ? buffer->datagrams_dropped : 0U;
}

uint64_t wt_webtransport_buffered_last_rejected_stream_id(const wt_webtransport_buffered_t *buffer) {
  return buffer != NULL ? buffer->last_rejected_stream_id : 0U;
}
