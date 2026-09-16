/* QUIC transport parameters. See webtransport/quic/transport_parameters.h.
 *
 * Framing and duplicates are refused here; the value rules of RFC 9000 section
 * 18.2 are a separate opt-in check, because the same bytes are parsed as a TLS
 * extension by a layer that must not refuse them itself.
 */

#include "webtransport/quic/transport_parameters.h"

#include "webtransport/checked.h"
#include "webtransport/cursor.h"

#include <string.h>

const char *wt_quic_transport_parameter_name(uint64_t id) {
  switch (id) {
    case WT_QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID:
      return "original_destination_connection_id";
    case WT_QUIC_TP_MAX_IDLE_TIMEOUT:
      return "max_idle_timeout";
    case WT_QUIC_TP_STATELESS_RESET_TOKEN:
      return "stateless_reset_token";
    case WT_QUIC_TP_MAX_UDP_PAYLOAD_SIZE:
      return "max_udp_payload_size";
    case WT_QUIC_TP_INITIAL_MAX_DATA:
      return "initial_max_data";
    case WT_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
      return "initial_max_stream_data_bidi_local";
    case WT_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
      return "initial_max_stream_data_bidi_remote";
    case WT_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI:
      return "initial_max_stream_data_uni";
    case WT_QUIC_TP_INITIAL_MAX_STREAMS_BIDI:
      return "initial_max_streams_bidi";
    case WT_QUIC_TP_INITIAL_MAX_STREAMS_UNI:
      return "initial_max_streams_uni";
    case WT_QUIC_TP_ACK_DELAY_EXPONENT:
      return "ack_delay_exponent";
    case WT_QUIC_TP_MAX_ACK_DELAY:
      return "max_ack_delay";
    case WT_QUIC_TP_DISABLE_ACTIVE_MIGRATION:
      return "disable_active_migration";
    case WT_QUIC_TP_PREFERRED_ADDRESS:
      return "preferred_address";
    case WT_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT:
      return "active_connection_id_limit";
    case WT_QUIC_TP_INITIAL_SOURCE_CONNECTION_ID:
      return "initial_source_connection_id";
    case WT_QUIC_TP_RETRY_SOURCE_CONNECTION_ID:
      return "retry_source_connection_id";
    case WT_QUIC_TP_MAX_DATAGRAM_FRAME_SIZE:
      return "max_datagram_frame_size";
    case WT_QUIC_TP_GREASE_QUIC_BIT:
      return "grease_quic_bit";
    default:
      return "unknown";
  }
}

void wt_quic_transport_parameters_init(wt_quic_transport_parameters_t *params) {
  if (params == NULL) return;
  memset(params, 0, sizeof(*params));
  /* An empty list is sorted, which is what a lookup's binary search needs to be
   * able to assume. */
  params->sorted = 1;
}

/* Where `id` belongs in a sorted list: the index of the first entry that is not
 * below it. */
static size_t wt_quic_tp_lower_bound(const wt_quic_transport_parameters_t *p,
                                     uint64_t id) {
  size_t low = 0U;
  size_t high = p->count;
  while (low < high) {
    size_t mid = low + (high - low) / 2U;
    if (p->entries[mid].id < id) {
      low = mid + 1U;
    } else {
      high = mid;
    }
  }
  return low;
}

/* The entry for `id`, or NULL. Internal: the public lookup answers with a status
 * so that presence is not confused with a zero-length value. */
static const wt_quic_transport_parameter_t *wt_quic_tp_entry(
    const wt_quic_transport_parameters_t *params, uint64_t id) {
  size_t i;
  if (params == NULL) return NULL;
  if (params->sorted) {
    size_t at = wt_quic_tp_lower_bound(params, id);
    if (at < params->count && params->entries[at].id == id) {
      return &params->entries[at];
    }
    return NULL;
  }
  /* A list that arrived unsorted is scanned. RFC 9000 section 18 does not order
   * the parameters, so this is not an error path, just a slower one. */
  for (i = 0U; i < params->count; i++) {
    if (params->entries[i].id == id) return &params->entries[i];
  }
  return NULL;
}

wt_status_t wt_quic_transport_parameters_get(
    const wt_quic_transport_parameters_t *params, uint64_t id,
    const uint8_t **out_value, size_t *out_length) {
  const wt_quic_transport_parameter_t *entry;
  if (out_value != NULL) *out_value = NULL;
  if (out_length != NULL) *out_length = 0U;
  if (params == NULL) return WT_ERR_INVALID_ARGUMENT;
  entry = wt_quic_tp_entry(params, id);
  if (entry == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (out_value != NULL) *out_value = entry->value;
  if (out_length != NULL) *out_length = entry->length;
  return WT_OK;
}

wt_status_t wt_quic_transport_parameters_integer(
    const wt_quic_transport_parameters_t *params, uint64_t id, uint64_t *out) {
  size_t length = 0U;
  const uint8_t *value = NULL;
  wt_cursor_t c;
  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* Absent is not zero. A caller that wants a default asks for the default; one
   * that gets WT_ERR_INVALID_ARGUMENT knows the peer said nothing. */
  if (wt_quic_transport_parameters_get(params, id, &value, &length) != WT_OK) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (length == 0U || value == NULL) return WT_ERR_TRUNCATED;
  c = wt_cursor_init(value, length);
  if (wt_quic_varint_decode(&c, out) != WT_OK) return WT_ERR_TRUNCATED;
  /* RFC 9000 section 18: a value that is an integer must be exactly one varint,
   * so trailing bytes are a framing error rather than something to ignore. */
  if (!wt_cursor_at_end(&c)) return WT_ERR_TRUNCATED;
  return WT_OK;
}

wt_status_t wt_quic_transport_parameters_decode(
    const uint8_t *data, size_t length, wt_quic_transport_parameters_t *out,
    wt_quic_error_t *out_error) {
  wt_cursor_t c;
  size_t i;

  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  wt_quic_transport_parameters_init(out);
  if (data == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;

  c = wt_cursor_init(data, length);
  while (wt_cursor_remaining(&c) > 0U) {
    const uint8_t *start;
    size_t start_offset;
    uint64_t id = 0U;
    uint64_t value_len = 0U;
    size_t value_len_size = 0U;
    const uint8_t *value;

    if (out->count >= WT_QUIC_MAX_TRANSPORT_PARAMETERS) {
      if (out_error != NULL) *out_error = WT_QUIC_TRANSPORT_PARAMETER_ERROR;
      return WT_ERR_PROTOCOL;
    }
    start = c.data + c.offset;
    start_offset = c.offset;
    if (wt_quic_varint_decode(&c, &id) != WT_OK) return WT_ERR_TRUNCATED;
    if (wt_quic_varint_decode_sized(&c, &value_len, &value_len_size) != WT_OK) {
      return WT_ERR_TRUNCATED;
    }
    /* RFC 9000 section 18: a parameter's length must be minimally encoded. The
     * same rule as the frame type, for the same reason. */
    if (!wt_quic_varint_is_minimal(value_len, value_len_size)) {
      if (out_error != NULL) *out_error = WT_QUIC_TRANSPORT_PARAMETER_ERROR;
      return WT_ERR_PROTOCOL;
    }
    {
      size_t narrowed = 0U;
      if (wt_checked_narrow_u64_to_size(value_len, &narrowed) != WT_OK) {
        return WT_ERR_TRUNCATED;
      }
      if (narrowed > wt_cursor_remaining(&c)) return WT_ERR_TRUNCATED;
      value = wt_cursor_bytes(&c, narrowed);
    }
    out->entries[out->count].id = id;
    out->entries[out->count].value = value;
    out->entries[out->count].length = (size_t)value_len;
    out->count++;

    /* Sorted as it arrives? Every received list is either wholly sorted or
     * treated as unsorted, never half of each. */
    if (out->count > 1U &&
        out->entries[out->count - 2U].id > out->entries[out->count - 1U].id) {
      out->sorted = 0;
    }
    (void)start;
    (void)start_offset;
  }

  /* Duplicates, which RFC 9000 section 7.4 makes a TRANSPORT_PARAMETER_ERROR.
   * Checked after the walk rather than during it, because the identifiers are
   * only known once they are all read and the count is bounded, so this is at
   * most 32 squared comparisons with no peer-controlled loop. */
  for (i = 0U; i < out->count; i++) {
    size_t j;
    for (j = i + 1U; j < out->count; j++) {
      if (out->entries[i].id == out->entries[j].id) {
        if (out_error != NULL) *out_error = WT_QUIC_TRANSPORT_PARAMETER_ERROR;
        return WT_ERR_PROTOCOL;
      }
    }
  }
  return WT_OK;
}

wt_status_t wt_quic_transport_parameters_check(
    const wt_quic_transport_parameters_t *params, int peer_is_client,
    wt_quic_error_t *out_error, uint64_t *out_offender) {
  wt_status_t status;
  uint64_t value = 0U;

  if (params == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (out_offender != NULL) *out_offender = 0U;

#define WT_QUIC_TP_REJECT(id)                          \
  do {                                                 \
    if (out_error != NULL) {                           \
      *out_error = WT_QUIC_TRANSPORT_PARAMETER_ERROR;  \
    }                                                  \
    if (out_offender != NULL) *out_offender = (id);    \
    return WT_ERR_PROTOCOL;                            \
  } while (0)

  /* RFC 9000 section 18.2: max_udp_payload_size below 1200 is a violation. A
   * peer that advertised less could not receive a packet this endpoint is
   * required to be able to send. */
  status = wt_quic_transport_parameters_integer(
      params, WT_QUIC_TP_MAX_UDP_PAYLOAD_SIZE, &value);
  if (status == WT_OK && value < WT_QUIC_MIN_MAX_UDP_PAYLOAD_SIZE) {
    WT_QUIC_TP_REJECT(WT_QUIC_TP_MAX_UDP_PAYLOAD_SIZE);
  }
  /* ack_delay_exponent is at most 20. */
  status = wt_quic_transport_parameters_integer(
      params, WT_QUIC_TP_ACK_DELAY_EXPONENT, &value);
  if (status == WT_OK && value > 20U) {
    WT_QUIC_TP_REJECT(WT_QUIC_TP_ACK_DELAY_EXPONENT);
  }
  /* The reliable-stream-reset parameter is a FLAG: its value is empty, and an endpoint that understands it must
   * treat a non-empty value as TRANSPORT_PARAMETER_ERROR. A value nobody reads is a negotiation nobody can rely
   * on, which is why the rule is here rather than in a caller (draft-ietf-quic-reliable-stream-reset). */
  {
    const uint8_t *value_bytes = NULL;
    size_t value_length = 0U;
    if (wt_quic_transport_parameters_get(params, WT_QUIC_TP_RESET_STREAM_AT, &value_bytes,
                                         &value_length) == WT_OK &&
        value_length != 0U) {
      WT_QUIC_TP_REJECT(WT_QUIC_TP_RESET_STREAM_AT);
    }
  }
  /* max_ack_delay is below 2^14 milliseconds. */
  status = wt_quic_transport_parameters_integer(params, WT_QUIC_TP_MAX_ACK_DELAY,
                                               &value);
  if (status == WT_OK && value >= (UINT64_C(1) << 14)) {
    WT_QUIC_TP_REJECT(WT_QUIC_TP_MAX_ACK_DELAY);
  }
  /* active_connection_id_limit is at least 2, because a connection needs its own
   * ID and at least one spare to migrate. */
  status = wt_quic_transport_parameters_integer(
      params, WT_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT, &value);
  if (status == WT_OK && value < 2U) {
    WT_QUIC_TP_REJECT(WT_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT);
  }
  /* RFC 9000 section 4.6: "If a max_streams transport parameter or a MAX_STREAMS frame is received with a value
   * greater than 2^60 ... the connection MUST be closed immediately with a connection error of type
   * TRANSPORT_PARAMETER_ERROR if the offending value was received in a transport parameter". 2^60 itself is the
   * boundary and is legal; only a value above it is refused. The frame half is enforced in `frame.c`. */
  status = wt_quic_transport_parameters_integer(params, WT_QUIC_TP_INITIAL_MAX_STREAMS_BIDI, &value);
  if (status == WT_OK && value > (UINT64_C(1) << 60)) {
    WT_QUIC_TP_REJECT(WT_QUIC_TP_INITIAL_MAX_STREAMS_BIDI);
  }
  status = wt_quic_transport_parameters_integer(params, WT_QUIC_TP_INITIAL_MAX_STREAMS_UNI, &value);
  if (status == WT_OK && value > (UINT64_C(1) << 60)) {
    WT_QUIC_TP_REJECT(WT_QUIC_TP_INITIAL_MAX_STREAMS_UNI);
  }
  /* A stateless reset token is exactly sixteen bytes. */
  {
    size_t token_length = 0U;
    if (wt_quic_transport_parameters_get(
            params, WT_QUIC_TP_STATELESS_RESET_TOKEN, NULL,
            &token_length) == WT_OK &&
        token_length != 16U) {
      WT_QUIC_TP_REJECT(WT_QUIC_TP_STATELESS_RESET_TOKEN);
    }
    /* RFC 9000 section 18.2: "This parameter is valid only for a server. ... A server MUST treat receipt of a
     * stateless_reset_token transport parameter as a connection error of type TRANSPORT_PARAMETER_ERROR." The
     * length rule above cannot cover it: a well-formed token from the wrong role is still an error, and a
     * server (peer_is_client == 0) may send one. */
    if (peer_is_client != 0 &&
        wt_quic_transport_parameters_get(params, WT_QUIC_TP_STATELESS_RESET_TOKEN, NULL, NULL) == WT_OK) {
      WT_QUIC_TP_REJECT(WT_QUIC_TP_STATELESS_RESET_TOKEN);
    }
  }
  /* original_destination_connection_id is never zero: RFC 9000 section 7.2
   * requires the client's first destination connection ID to be at least eight
   * bytes, and this parameter carries it back for the client to check. */
  {
    size_t length = 0U;
    if (wt_quic_transport_parameters_get(
            params, WT_QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID, NULL,
            &length) == WT_OK) {
      if (length == 0U || length > 20U) {
        WT_QUIC_TP_REJECT(WT_QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID);
      }
    }
  }
  /* The two source connection ID parameters may be zero -- RFC 9000 section 7.3
   * allows a zero-length connection ID -- but not longer than twenty. */
  {
    static const uint64_t cid_ids[2] = {
        WT_QUIC_TP_INITIAL_SOURCE_CONNECTION_ID,
        WT_QUIC_TP_RETRY_SOURCE_CONNECTION_ID};
    size_t i;
    for (i = 0U; i < 2U; i++) {
      size_t length = 0U;
      if (wt_quic_transport_parameters_get(params, cid_ids[i], NULL,
                                           &length) == WT_OK) {
        if (length > 20U) WT_QUIC_TP_REJECT(cid_ids[i]);
      }
    }
  }
  /* A zero max_datagram_frame_size is deliberately NOT refused: RFC 9221 section
   * 3 defines zero as "DATAGRAM frames are not supported", which is also what
   * the parameter's absence means, so an explicit zero is conforming. */
#undef WT_QUIC_TP_REJECT
  return WT_OK;
}

wt_status_t wt_quic_transport_parameters_encode(
    wt_writer_t *w, const wt_quic_transport_parameters_t *params) {
  size_t i;
  size_t j;
  if (w == NULL || params == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (params->count > WT_QUIC_MAX_TRANSPORT_PARAMETERS) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  /* A duplicate is refused before anything is written, so a caller that ignores
   * the status is not left with a half-written extension. */
  for (i = 0U; i < params->count; i++) {
    for (j = i + 1U; j < params->count; j++) {
      if (params->entries[i].id == params->entries[j].id) {
        return WT_ERR_INVALID_ARGUMENT;
      }
    }
  }
  for (i = 0U; i < params->count; i++) {
    (void)wt_quic_writer_varint(w, params->entries[i].id);
    (void)wt_quic_writer_varint(w, (uint64_t)params->entries[i].length);
    wt_writer_bytes(w, params->entries[i].value, params->entries[i].length);
  }
  return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
}

/* Insert an entry, keeping the list sorted by identifier. */
static wt_status_t wt_quic_tp_insert(wt_quic_transport_parameters_t *params,
                                     uint64_t id, const uint8_t *value,
                                     size_t length) {
  size_t at;
  size_t i;
  if (params == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (params->count >= WT_QUIC_MAX_TRANSPORT_PARAMETERS) return WT_ERR_LIMIT;
  if (length != 0U && value == NULL) return WT_ERR_INVALID_ARGUMENT;

  if (params->sorted) {
    at = wt_quic_tp_lower_bound(params, id);
    if (at < params->count && params->entries[at].id == id) {
      return WT_ERR_INVALID_ARGUMENT; /* duplicate */
    }
  } else {
    for (i = 0U; i < params->count; i++) {
      if (params->entries[i].id == id) return WT_ERR_INVALID_ARGUMENT;
    }
    at = params->count;
  }
  for (i = params->count; i > at; i--) {
    params->entries[i] = params->entries[i - 1U];
  }
  params->entries[at].id = id;
  params->entries[at].value = value;
  params->entries[at].length = length;
  params->count++;
  return WT_OK;
}

wt_status_t wt_quic_transport_parameters_add_integer(
    wt_quic_transport_parameters_t *params, uint64_t id, uint64_t value) {
  uint8_t *slot;
  size_t written;
  wt_status_t status;

  if (params == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (params->integer_slots_used >= WT_QUIC_MAX_TRANSPORT_PARAMETERS) {
    return WT_ERR_LIMIT;
  }
  /* The value is encoded into the structure's own storage, so a caller does not
   * have to keep a buffer alive for every integer it adds -- which is what a
   * view-based list would otherwise require, and the kind of lifetime rule that
   * is forgotten once and then debugged for an afternoon. */
  slot = params->integer_storage + (params->integer_slots_used * 8U);
  written = wt_quic_varint_encode(value, slot, 8U);
  if (written == 0U) return WT_ERR_OVERFLOW;
  status = wt_quic_tp_insert(params, id, slot, written);
  /* The slot is only consumed when the insert succeeded: a refused duplicate
   * must not burn one of the thirty-two. */
  if (status == WT_OK) params->integer_slots_used++;
  return status;
}

wt_status_t wt_quic_transport_parameters_add_bytes(
    wt_quic_transport_parameters_t *params, uint64_t id, const uint8_t *value,
    size_t length) {
  return wt_quic_tp_insert(params, id, value, length);
}

wt_status_t wt_quic_transport_parameters_build(wt_quic_transport_parameters_t *params, int is_server,
                                               const uint8_t *source_connection_id, size_t source_length,
                                               const uint8_t *original_destination_connection_id,
                                               size_t original_length, int retried,
                                               const uint8_t *retry_source_connection_id,
                                               size_t retry_source_length) {
  wt_status_t status;

  if (params == NULL || source_connection_id == NULL || source_length == 0U) return WT_ERR_INVALID_ARGUMENT;
  if (is_server && (original_destination_connection_id == NULL || original_length == 0U)) {
    /* A server that does not say which connection ID the client addressed it by is missing a parameter the RFC
     * requires of it, and the peer cannot tell that from a mis-routed packet. */
    return WT_ERR_INVALID_ARGUMENT;
  }
  /* Both directions of section 7.3's rule are refused here rather than sent: a Retry the parameters do not name,
   * and a name for a Retry that was never sent. The second is the one a caller reaches by accident -- passing a
   * leftover value on a path where `retried` is false -- and a client that checks (this tree's does, since
   * WT-166) answers it with TRANSPORT_PARAMETER_ERROR. */
  if (retried != 0 && (!is_server || retry_source_connection_id == NULL || retry_source_length == 0U)) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (retried == 0 && retry_source_connection_id != NULL && retry_source_length != 0U) {
    return WT_ERR_INVALID_ARGUMENT;
  }

  wt_quic_transport_parameters_init(params);

  /* RFC 9000 section 7.3: both endpoints send this, and it must be the Source Connection ID they used in their
   * Initial packets -- a peer compares it, and a mismatch (including its absence) is TRANSPORT_PARAMETER_ERROR.
   * This is the parameter whose omission a third-party peer named on the first handshake that reached one. */
  status = wt_quic_transport_parameters_add_bytes(params, WT_QUIC_TP_INITIAL_SOURCE_CONNECTION_ID,
                                                  source_connection_id, source_length);
  if (status != WT_OK) return status;

  if (is_server) {
    status = wt_quic_transport_parameters_add_bytes(params, WT_QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID,
                                                    original_destination_connection_id, original_length);
    if (status != WT_OK) return status;
  }
  if (retried != 0) {
    status = wt_quic_transport_parameters_add_bytes(params, WT_QUIC_TP_RETRY_SOURCE_CONNECTION_ID,
                                                    retry_source_connection_id, retry_source_length);
    if (status != WT_OK) return status;
  }

  /* The limits this library advertises, in one place: a caller that added its own would be the second owner of
   * a number that has to agree with what the runtime enforces. */
  status = wt_quic_transport_parameters_add_integer(params, WT_QUIC_TP_INITIAL_MAX_DATA, 100000U);
  if (status != WT_OK) return status;
  status = wt_quic_transport_parameters_add_integer(params, WT_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                                                    4096U);
  if (status != WT_OK) return status;
  /* RFC 9000 section 18.2: this is the limit for data the PEER sends on streams THIS endpoint opened, which is
   * the response on the request stream and every answer on a WebTransport data stream. A client that omits it --
   * which this did -- advertises zero, so a peer that honours the limit may send nothing back at all. Omitting it
   * looked harmless because aioquic's server sent its answer anyway, and the two ends of this tree's own tests
   * never had a peer to refuse (WT-145). */
  status = wt_quic_transport_parameters_add_integer(
      params, WT_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, 4096U);
  if (status != WT_OK) return status;
  status = wt_quic_transport_parameters_add_integer(params, WT_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI, 4096U);
  if (status != WT_OK) return status;
  status = wt_quic_transport_parameters_add_integer(params, WT_QUIC_TP_INITIAL_MAX_STREAMS_BIDI, 8U);
  if (status != WT_OK) return status;
  status = wt_quic_transport_parameters_add_integer(params, WT_QUIC_TP_INITIAL_MAX_STREAMS_UNI, 8U);
  if (status != WT_OK) return status;
  /* WebTransport over HTTP/3 requires the reliable-stream-reset extension of BOTH roles (draft-16 section 3.1):
   * a WebTransport stream carries its session prefix before any payload, and a reset that dropped the prefix would
   * leave the peer with a stream it cannot attribute to a session at all. The value is empty -- it advertises the
   * extension rather than configuring it. */
  status = wt_quic_transport_parameters_add_bytes(params, WT_QUIC_TP_RESET_STREAM_AT, NULL, 0U);
  if (status != WT_OK) return status;
  return wt_quic_transport_parameters_add_integer(params, WT_QUIC_TP_MAX_DATAGRAM_FRAME_SIZE, 1200U);
}
