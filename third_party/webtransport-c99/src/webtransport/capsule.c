/* WebTransport capsules (draft-ietf-webtrans-http3-16 section 5). */

#include "webtransport/webtransport/capsule.h"

#include "webtransport/quic/varint.h"

wt_status_t wt_webtransport_capsule_decode(wt_cursor_t *c, size_t max_length,
                                           wt_webtransport_capsule_t *out,
                                           wt_http3_error_t *out_error) {
  uint64_t type;
  uint64_t length;
  const uint8_t *value;
  size_t before;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (c == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;

  before = wt_cursor_remaining(c);
  if (wt_quic_varint_decode(c, &type) != WT_OK) {
    /* Not even the type is here: the capsule has not arrived, which is ordinary on a
     * stream (RFC 9297 section 3.2's receivers buffer). */
    return WT_ERR_TRUNCATED;
  }
  if (wt_quic_varint_decode(c, &length) != WT_OK) return WT_ERR_TRUNCATED;

  /* The length is the peer's to choose and this endpoint's to bound: a capsule longer
   * than the caller will buffer is refused rather than allocated for. */
  if (length > (uint64_t)max_length) {
    if (out_error != NULL) *out_error = WT_HTTP3_EXCESSIVE_LOAD;
    return WT_ERR_LIMIT;
  }
  value = wt_cursor_bytes(c, (size_t)length);
  if (value == NULL && length != 0U) return WT_ERR_TRUNCATED;

  out->type = type;
  out->value = value;
  out->value_length = (size_t)length;
  out->bytes_consumed = before - wt_cursor_remaining(c);
  return WT_OK;
}

wt_status_t wt_webtransport_capsule_encode(wt_writer_t *w, const wt_webtransport_capsule_t *capsule) {
  if (w == NULL || capsule == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (capsule->value == NULL && capsule->value_length != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (capsule->type > WT_QUIC_VARINT_MAX) return WT_ERR_INVALID_ARGUMENT;
  if ((uint64_t)capsule->value_length > WT_QUIC_VARINT_MAX) return WT_ERR_INVALID_ARGUMENT;

  (void)wt_quic_writer_varint(w, capsule->type);
  (void)wt_quic_writer_varint(w, (uint64_t)capsule->value_length);
  if (capsule->value_length != 0U) wt_writer_bytes(w, capsule->value, capsule->value_length);
  return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
}

wt_status_t wt_webtransport_close_session_write(wt_writer_t *w, uint32_t error_code,
                                                const uint8_t *reason, size_t reason_length) {
  uint8_t code[4];

  if (w == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (reason == NULL && reason_length != 0U) return WT_ERR_INVALID_ARGUMENT;
  /* Section 5.4's ceiling, enforced at the writer so this build cannot send a capsule
   * its own reader would refuse. */
  if (reason_length > (size_t)WT_CAPSULE_CLOSE_MAX_REASON) return WT_ERR_LIMIT;

  /* The value is the four-byte code followed by the reason, so the length covers both
   * and the code is written big-endian (section 5.4 fixes the order). */
  code[0] = (uint8_t)(error_code >> 24);
  code[1] = (uint8_t)((error_code >> 16) & 0xffU);
  code[2] = (uint8_t)((error_code >> 8) & 0xffU);
  code[3] = (uint8_t)(error_code & 0xffU);

  (void)wt_quic_writer_varint(w, WT_CAPSULE_CLOSE_WEBTRANSPORT_SESSION);
  (void)wt_quic_writer_varint(w, (uint64_t)4U + (uint64_t)reason_length);
  wt_writer_bytes(w, code, sizeof(code));
  if (reason_length != 0U) wt_writer_bytes(w, reason, reason_length);
  return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
}

/* Whether `bytes` is well-formed UTF-8 (RFC 3629).
 *
 * Draft-16 section 6 makes the close reason a UTF-8 string, and a decoder that accepts arbitrary bytes hands a
 * caller something it cannot print or compare. The rules are the short ones: a lead byte fixes the length, every
 * continuation byte is 10xxxxxx, no overlong form, no surrogate (U+D800..U+DFFF) and nothing above U+10FFFF. */
static int utf8_is_well_formed(const uint8_t *bytes, size_t length) {
  size_t i = 0U;

  while (i < length) {
    uint8_t lead = bytes[i];
    size_t extra;
    uint32_t value;
    size_t j;

    if (lead < 0x80U) {
      i++;
      continue;
    }
    if ((lead & 0xe0U) == 0xc0U) {
      extra = 1U;
      value = (uint32_t)(lead & 0x1fU);
    } else if ((lead & 0xf0U) == 0xe0U) {
      extra = 2U;
      value = (uint32_t)(lead & 0x0fU);
    } else if ((lead & 0xf8U) == 0xf0U) {
      extra = 3U;
      value = (uint32_t)(lead & 0x07U);
    } else {
      return 0;
    }
    if (length - i < extra + 1U) return 0;
    for (j = 1U; j <= extra; j++) {
      if ((bytes[i + j] & 0xc0U) != 0x80U) return 0;
      value = (value << 6) | (uint32_t)(bytes[i + j] & 0x3fU);
    }
    /* The shortest form for the length, and the two ranges the standard excludes. */
    if (extra == 1U && value < 0x80U) return 0;
    if (extra == 2U && value < 0x800U) return 0;
    if (extra == 3U && value < 0x10000U) return 0;
    if (value >= 0xd800U && value <= 0xdfffU) return 0;
    if (value > 0x10ffffU) return 0;
    i += extra + 1U;
  }
  return 1;
}

wt_status_t wt_webtransport_close_session_parse(const wt_webtransport_capsule_t *capsule,
                                                uint32_t *out_error_code, const uint8_t **out_reason,
                                                size_t *out_reason_length,
                                                wt_http3_error_t *out_error) {
  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (capsule == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (capsule->type != WT_CAPSULE_CLOSE_WEBTRANSPORT_SESSION) {
    if (out_error != NULL) *out_error = WT_HTTP3_MESSAGE_ERROR;
    return WT_ERR_INVALID_ARGUMENT;
  }
  /* The four-byte code is mandatory, so a shorter value is a malformed capsule rather
   * than one with nothing to say. */
  if (capsule->value_length < 4U) {
    if (out_error != NULL) *out_error = WT_HTTP3_MESSAGE_ERROR;
    return WT_ERR_PROTOCOL;
  }
  if (capsule->value_length - 4U > (size_t)WT_CAPSULE_CLOSE_MAX_REASON) {
    if (out_error != NULL) *out_error = WT_HTTP3_MESSAGE_ERROR;
    return WT_ERR_PROTOCOL;
  }
  /* Section 6 makes the reason a UTF-8 string, so bytes that are not one are a malformed capsule rather than a
   * string a caller can print. An audit found the reason unvalidated. The error code is written only after
   * this check passes: a capsule that is refused must not leave a value from the refused capsule in a caller's
   * out-parameter (include/webtransport/status.h states that rule). */
  if (!utf8_is_well_formed(capsule->value + 4U, capsule->value_length - 4U)) {
    if (out_error != NULL) *out_error = WT_HTTP3_MESSAGE_ERROR;
    return WT_ERR_PROTOCOL;
  }
  if (out_error_code != NULL) {
    *out_error_code = ((uint32_t)capsule->value[0] << 24) | ((uint32_t)capsule->value[1] << 16) |
                      ((uint32_t)capsule->value[2] << 8) | (uint32_t)capsule->value[3];
  }
  if (out_reason != NULL) *out_reason = capsule->value + 4U;
  if (out_reason_length != NULL) *out_reason_length = capsule->value_length - 4U;
  return WT_OK;
}

wt_status_t wt_webtransport_drain_session_write(wt_writer_t *w) {
  if (w == NULL) return WT_ERR_INVALID_ARGUMENT;
  (void)wt_quic_writer_varint(w, WT_CAPSULE_DRAIN_SESSION);
  (void)wt_quic_writer_varint(w, 0U);
  return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
}

/* ------------------------------------------------------- flow control capsules */

/* One varint, exactly. A value with trailing bytes is not a bigger number, it is a
 * capsule this layer cannot read, so it is a message error rather than a limit. */
static wt_status_t parse_one(wt_webtransport_capsule_t const *capsule, uint64_t expected_type,
                             uint64_t *out_value, wt_http3_error_t *out_error) {
  wt_cursor_t c;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (capsule == NULL || out_value == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (capsule->type != expected_type) {
    if (out_error != NULL) *out_error = WT_HTTP3_MESSAGE_ERROR;
    return WT_ERR_INVALID_ARGUMENT;
  }
  c = wt_cursor_init(capsule->value, capsule->value_length);
  if (wt_quic_varint_decode(&c, out_value) != WT_OK) {
    if (out_error != NULL) *out_error = WT_HTTP3_MESSAGE_ERROR;
    return WT_ERR_PROTOCOL;
  }
  if (!wt_cursor_at_end(&c)) {
    if (out_error != NULL) *out_error = WT_HTTP3_MESSAGE_ERROR;
    return WT_ERR_PROTOCOL;
  }
  return WT_OK;
}

/* Two varints, exactly, in the order the draft fixes: the stream first, then the value. */
static wt_status_t parse_two(const wt_webtransport_capsule_t *capsule, uint64_t expected_type,
                             uint64_t *out_first, uint64_t *out_second, wt_http3_error_t *out_error) {
  wt_cursor_t c;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (capsule == NULL || out_first == NULL || out_second == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (capsule->type != expected_type) {
    if (out_error != NULL) *out_error = WT_HTTP3_MESSAGE_ERROR;
    return WT_ERR_INVALID_ARGUMENT;
  }
  c = wt_cursor_init(capsule->value, capsule->value_length);
  if (wt_quic_varint_decode(&c, out_first) != WT_OK ||
      wt_quic_varint_decode(&c, out_second) != WT_OK) {
    if (out_error != NULL) *out_error = WT_HTTP3_MESSAGE_ERROR;
    return WT_ERR_PROTOCOL;
  }
  if (!wt_cursor_at_end(&c)) {
    if (out_error != NULL) *out_error = WT_HTTP3_MESSAGE_ERROR;
    return WT_ERR_PROTOCOL;
  }
  return WT_OK;
}

static wt_status_t write_one(wt_writer_t *w, uint64_t type, uint64_t value) {
  if (w == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (type > WT_QUIC_VARINT_MAX || value > WT_QUIC_VARINT_MAX) return WT_ERR_INVALID_ARGUMENT;
  (void)wt_quic_writer_varint(w, type);
  /* The length is the value's own encoded size, which is one to eight bytes: writing a
   * constant one describes a capsule whose value is one byte long whatever it holds, and
   * a decoder reading it would stop after the first byte of a longer number. */
  (void)wt_quic_writer_varint(w, (uint64_t)wt_quic_varint_size(value));
  (void)wt_quic_writer_varint(w, value);
  /* Four assignments to a `wt_webtransport_capsule_t` used to sit here, left over from a version that built one
   * and never read it. clang's `-Wunused-but-set-variable` does not catch that; GCC's does, and the Windows
   * cross-compile is a GCC -- so the whole library compiles for Windows because a dead local was removed. */
  return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
}

static wt_status_t write_two(wt_writer_t *w, uint64_t type, uint64_t first, uint64_t second) {
  uint8_t value[16];
  wt_writer_t inner = wt_writer_init(value, sizeof(value));

  if (w == NULL) return WT_ERR_INVALID_ARGUMENT;
  (void)wt_quic_writer_varint(&inner, first);
  (void)wt_quic_writer_varint(&inner, second);
  if (!wt_writer_ok(&inner)) return WT_ERR_LIMIT;
  (void)wt_quic_writer_varint(w, type);
  (void)wt_quic_writer_varint(w, (uint64_t)wt_writer_offset(&inner));
  wt_writer_bytes(w, value, wt_writer_offset(&inner));
  return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
}

wt_status_t wt_webtransport_max_data_write(wt_writer_t *w, uint64_t maximum) {
  return write_one(w, WT_CAPSULE_MAX_DATA, maximum);
}

wt_status_t wt_webtransport_max_stream_data_write(wt_writer_t *w, uint64_t stream_id,
                                                  uint64_t maximum) {
  return write_two(w, WT_CAPSULE_MAX_STREAM_DATA, stream_id, maximum);
}

wt_status_t wt_webtransport_max_streams_write(wt_writer_t *w, int bidirectional, uint64_t maximum) {
  return write_one(w, bidirectional ? WT_CAPSULE_MAX_STREAMS_BIDI : WT_CAPSULE_MAX_STREAMS_UNI,
                   maximum);
}

wt_status_t wt_webtransport_data_blocked_write(wt_writer_t *w, uint64_t maximum) {
  return write_one(w, WT_CAPSULE_DATA_BLOCKED, maximum);
}

wt_status_t wt_webtransport_stream_data_blocked_write(wt_writer_t *w, uint64_t stream_id,
                                                      uint64_t maximum) {
  return write_two(w, WT_CAPSULE_STREAM_DATA_BLOCKED, stream_id, maximum);
}

wt_status_t wt_webtransport_streams_blocked_write(wt_writer_t *w, int bidirectional,
                                                 uint64_t maximum) {
  return write_one(w, bidirectional ? WT_CAPSULE_STREAMS_BLOCKED_BIDI : WT_CAPSULE_STREAMS_BLOCKED_UNI,
                   maximum);
}

wt_status_t wt_webtransport_max_data_parse(const wt_webtransport_capsule_t *capsule,
                                           uint64_t *out_maximum, wt_http3_error_t *out_error) {
  return parse_one(capsule, WT_CAPSULE_MAX_DATA, out_maximum, out_error);
}

wt_status_t wt_webtransport_data_blocked_parse(const wt_webtransport_capsule_t *capsule,
                                               uint64_t *out_maximum, wt_http3_error_t *out_error) {
  return parse_one(capsule, WT_CAPSULE_DATA_BLOCKED, out_maximum, out_error);
}

wt_status_t wt_webtransport_max_streams_parse(const wt_webtransport_capsule_t *capsule,
                                              uint64_t *out_maximum, wt_http3_error_t *out_error) {
  if (capsule == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (capsule->type == WT_CAPSULE_MAX_STREAMS_BIDI || capsule->type == WT_CAPSULE_MAX_STREAMS_UNI) {
    return parse_one(capsule, capsule->type, out_maximum, out_error);
  }
  if (out_error != NULL) *out_error = WT_HTTP3_MESSAGE_ERROR;
  return WT_ERR_INVALID_ARGUMENT;
}

wt_status_t wt_webtransport_max_stream_data_parse(const wt_webtransport_capsule_t *capsule,
                                                  uint64_t *out_stream_id, uint64_t *out_maximum,
                                                  wt_http3_error_t *out_error) {
  return parse_two(capsule, WT_CAPSULE_MAX_STREAM_DATA, out_stream_id, out_maximum, out_error);
}

wt_status_t wt_webtransport_stream_data_blocked_parse(const wt_webtransport_capsule_t *capsule,
                                                      uint64_t *out_stream_id,
                                                      uint64_t *out_maximum,
                                                      wt_http3_error_t *out_error) {
  return parse_two(capsule, WT_CAPSULE_STREAM_DATA_BLOCKED, out_stream_id, out_maximum, out_error);
}

wt_status_t wt_webtransport_streams_blocked_parse(const wt_webtransport_capsule_t *capsule,
                                                  uint64_t *out_maximum,
                                                  wt_http3_error_t *out_error) {
  if (capsule == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (capsule->type == WT_CAPSULE_STREAMS_BLOCKED_BIDI ||
      capsule->type == WT_CAPSULE_STREAMS_BLOCKED_UNI) {
    return parse_one(capsule, capsule->type, out_maximum, out_error);
  }
  if (out_error != NULL) *out_error = WT_HTTP3_MESSAGE_ERROR;
  return WT_ERR_INVALID_ARGUMENT;
}

void wt_webtransport_flow_limits_init(wt_webtransport_flow_limits_t *limits) {
  if (limits == NULL) return;
  limits->max_data = 0U;
  limits->max_data_set = 0;
  limits->max_streams_bidi = 0U;
  limits->max_streams_bidi_set = 0;
  limits->max_streams_uni = 0U;
  limits->max_streams_uni_set = 0;
}

wt_status_t wt_webtransport_flow_on_max_data(wt_webtransport_flow_limits_t *limits, uint64_t maximum,
                                             uint64_t *out_error) {
  if (out_error != NULL) *out_error = 0U;
  if (limits == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (limits->max_data_set && maximum <= limits->max_data) {
    /* Section 5.1: the limits strictly increase. A limit that shrinks would invalidate
     * data already sent against the old one, and a limit that repeats says the peer has
     * lost track of what it granted; both are flow-control errors rather than new
     * limits. */
    if (out_error != NULL) *out_error = WT_WEBTRANSPORT_FLOW_CONTROL_ERROR;
    return WT_ERR_PROTOCOL;
  }
  limits->max_data = maximum;
  limits->max_data_set = 1;
  return WT_OK;
}

wt_status_t wt_webtransport_flow_on_max_streams(wt_webtransport_flow_limits_t *limits,
                                                int bidirectional, uint64_t maximum,
                                                uint64_t *out_error) {
  if (out_error != NULL) *out_error = 0U;
  if (limits == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* The draft's ceiling applies before the monotonic rule: a value the stream ID space
   * cannot hold is not a limit at all. */
  if (maximum > WT_WEBTRANSPORT_MAX_STREAMS_VALUE) {
    if (out_error != NULL) *out_error = WT_WEBTRANSPORT_FLOW_CONTROL_ERROR;
    return WT_ERR_PROTOCOL;
  }
  if (bidirectional) {
    if (limits->max_streams_bidi_set && maximum <= limits->max_streams_bidi) {
      if (out_error != NULL) *out_error = WT_WEBTRANSPORT_FLOW_CONTROL_ERROR;
      return WT_ERR_PROTOCOL;
    }
    limits->max_streams_bidi = maximum;
    limits->max_streams_bidi_set = 1;
    return WT_OK;
  }
  if (limits->max_streams_uni_set && maximum <= limits->max_streams_uni) {
    if (out_error != NULL) *out_error = WT_WEBTRANSPORT_FLOW_CONTROL_ERROR;
    return WT_ERR_PROTOCOL;
  }
  limits->max_streams_uni = maximum;
  limits->max_streams_uni_set = 1;
  return WT_OK;
}
