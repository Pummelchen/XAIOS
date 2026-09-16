/* QUIC packet headers. See webtransport/quic/packet.h.
 *
 * Both decoders read the first byte first and dispatch on its top bit, and both
 * check the fixed bit and -- for a long header -- the reserved bits, because
 * those are the fields that decide whether the bytes are a QUIC packet at all
 * before any of the rest can be trusted.
 *
 * The Length field is re-derived on encode rather than taken from the caller.
 * RFC 9000 section 17.2 defines it as the packet number length plus the payload
 * length, and an API that let a caller pass it separately would let the two
 * disagree -- a class of defect that is silent until a peer refuses the packet
 * for a reason that names neither field.
 */

#include "webtransport/quic/packet.h"

#include "webtransport/checked.h"
#include "webtransport/quic/packet_number.h"
#include "webtransport/endian.h"

#include <string.h>

/* The largest connection ID length RFC 9000 section 17.2 allows. */
#define WT_QUIC_MAX_CID_LEN 20U
/* The Retry integrity tag, RFC 9000 section 17.2.5. */
#define WT_QUIC_RETRY_INTEGRITY_TAG_LEN 16U

const char *wt_quic_packet_type_name(wt_quic_packet_type_t type) {
  switch (type) {
    case WT_QUIC_PACKET_INITIAL:
      return "initial";
    case WT_QUIC_PACKET_ZERO_RTT:
      return "0-rtt";
    case WT_QUIC_PACKET_HANDSHAKE:
      return "handshake";
    case WT_QUIC_PACKET_RETRY:
      return "retry";
    default:
      return "unknown";
  }
}

static wt_status_t wt_quic_packet_fail(wt_quic_error_t *out_error,
                                       wt_quic_error_t code,
                                       wt_status_t status) {
  if (out_error != NULL) *out_error = code;
  return status;
}

wt_status_t wt_quic_packet_kind(const uint8_t *data, size_t length,
                                wt_quic_packet_kind_t *out) {
  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* A zero-length datagram holds no packet at all, which is a truncation rather
   * than a bad argument: the caller had a datagram and it was empty. */
  if (data == NULL || length == 0U) return WT_ERR_TRUNCATED;
  if ((data[0] & WT_QUIC_LONG_HEADER_BIT) == 0U) {
    *out = WT_QUIC_PACKET_KIND_SHORT;
    return WT_OK;
  }
  /* A long header whose version is zero is a Version Negotiation packet, which
   * has no Length field and therefore cannot be walked like the others. */
  if (length < 5U) return WT_ERR_TRUNCATED;
  if (wt_load_be32(data + 1U) == WT_QUIC_VERSION_NEGOTIATION) {
    *out = WT_QUIC_PACKET_KIND_VERSION_NEGOTIATION;
    return WT_OK;
  }
  *out = WT_QUIC_PACKET_KIND_LONG;
  return WT_OK;
}

/* A connection ID is on the wire as a one-byte length then that many bytes. Both
 * decoders read it the same way and both refuse a length above twenty, which is
 * the rule RFC 9000 section 17.2 states for the field. */
static wt_status_t wt_quic_read_connection_id(
    wt_cursor_t *c, const uint8_t **out, size_t *out_len,
    wt_quic_error_t *out_error) {
  const uint8_t *length_byte = wt_cursor_bytes(c, 1U);
  uint8_t length;
  const uint8_t *id;
  if (length_byte == NULL) return WT_ERR_TRUNCATED;
  length = length_byte[0];
  if ((size_t)length > WT_QUIC_MAX_CID_LEN) {
    return wt_quic_packet_fail(out_error, WT_QUIC_PROTOCOL_VIOLATION,
                               WT_ERR_PROTOCOL);
  }
  id = wt_cursor_bytes(c, (size_t)length);
  if (id == NULL && length != 0U) return WT_ERR_TRUNCATED;
  *out = id;
  *out_len = (size_t)length;
  return WT_OK;
}

/* The two connection IDs a long header names -- see the header for why a listener cannot ask the full decoder
 * for this. It is deliberately strict about what it has READ and uninterested in everything it has not: the
 * Length field, the token and the payload are the receive path's business, and requiring them here is what made
 * a 1200-byte Initial undecodable from a 64-byte peek. */
wt_status_t wt_quic_initial_token(const uint8_t *data, size_t length, const uint8_t **out_token,
                                  size_t *out_token_length) {
  wt_cursor_t c;
  uint8_t first;
  uint64_t token_length = 0U;
  const uint8_t *token = NULL;

  if (data == NULL || out_token == NULL || out_token_length == NULL) return WT_ERR_INVALID_ARGUMENT;
  *out_token = NULL;
  *out_token_length = 0U;
  if (length == 0U) return WT_ERR_TRUNCATED;
  first = data[0];
  if ((first & WT_QUIC_LONG_HEADER_BIT) == 0U || (first & WT_QUIC_FIXED_BIT) == 0U) {
    return WT_ERR_PROTOCOL;
  }
  if ((wt_quic_packet_type_t)((first & 0x30U) >> 4) != WT_QUIC_PACKET_INITIAL) return WT_ERR_PROTOCOL;

  c = wt_cursor_init(data, length);
  (void)wt_cursor_u8(&c);
  if (wt_cursor_bytes(&c, WT_BE32_SIZE) == NULL) return WT_ERR_TRUNCATED;
  /* The reader writes through both of its outputs, so it is given somewhere to write: skipping a connection ID is
   * not what it is for, and passing NULL here would be a null dereference rather than a skip. */
  {
    const uint8_t *skipped = NULL;
    size_t skipped_length = 0U;
    if (wt_quic_read_connection_id(&c, &skipped, &skipped_length, NULL) != WT_OK) return WT_ERR_TRUNCATED;
    if (wt_quic_read_connection_id(&c, &skipped, &skipped_length, NULL) != WT_OK) return WT_ERR_TRUNCATED;
  }
  /* The Token Length field and the token itself: a caller that peeked only the front of a 1200-byte Initial gets
   * TRUNCATED here rather than a view of bytes that are not in its buffer. The bound is the cursor's own offset,
   * which is how far into the caller's buffer the header has been read. */
  if (wt_quic_varint_decode(&c, &token_length) != WT_OK) return WT_ERR_TRUNCATED;
  if (token_length == 0U) return WT_OK;
  if (c.offset > length || token_length > (uint64_t)(length - c.offset)) return WT_ERR_TRUNCATED;
  token = wt_cursor_bytes(&c, (size_t)token_length);
  if (token == NULL) return WT_ERR_TRUNCATED;
  *out_token = token;
  *out_token_length = (size_t)token_length;
  return WT_OK;
}

wt_status_t wt_quic_long_header_connection_ids(const uint8_t *data, size_t length,
                                               const uint8_t **out_destination,
                                               size_t *out_destination_length,
                                               const uint8_t **out_source,
                                               size_t *out_source_length) {
  wt_cursor_t c;
  uint8_t first;

  if (data == NULL || out_destination == NULL || out_destination_length == NULL || out_source == NULL ||
      out_source_length == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  *out_destination = NULL;
  *out_destination_length = 0U;
  *out_source = NULL;
  *out_source_length = 0U;
  if (length == 0U) return WT_ERR_TRUNCATED;
  first = data[0];
  if ((first & WT_QUIC_LONG_HEADER_BIT) == 0U) return WT_ERR_PROTOCOL;
  if ((first & WT_QUIC_FIXED_BIT) == 0U) return WT_ERR_PROTOCOL;

  c = wt_cursor_init(data, length);
  (void)wt_cursor_u8(&c);
  if (wt_cursor_bytes(&c, WT_BE32_SIZE) == NULL) return WT_ERR_TRUNCATED;
  if (wt_quic_read_connection_id(&c, out_destination, out_destination_length, NULL) != WT_OK) {
    return WT_ERR_TRUNCATED;
  }
  if (wt_quic_read_connection_id(&c, out_source, out_source_length, NULL) != WT_OK) {
    return WT_ERR_TRUNCATED;
  }
  return WT_OK;
}

wt_status_t wt_quic_protected_pn_offset(const uint8_t *data, size_t length,
                                        size_t local_connection_id_len,
                                        size_t *out_offset, size_t *out_total_len,
                                        int *out_short_header) {
  wt_cursor_t c;
  uint8_t first;
  uint32_t type_bits;
  uint64_t length_field = 0U;
  uint64_t token_len = 0U;
  size_t narrowed = 0U;
  const uint8_t *token;

  if (data == NULL || out_offset == NULL || out_total_len == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  *out_offset = 0U;
  *out_total_len = 0U;
  if (length == 0U) return WT_ERR_TRUNCATED;
  if (out_short_header != NULL) *out_short_header = 0;

  first = data[0];
  if ((first & WT_QUIC_LONG_HEADER_BIT) == 0U) {
    /* A short header: one first byte, then the connection ID whose length is not on the wire, then the
     * packet number. There is nothing to walk and nothing to validate -- the first byte's low bits are
     * masked, so reading them here would be reading the mask. */
    if (out_short_header != NULL) *out_short_header = 1;
    if (local_connection_id_len > WT_QUIC_MAX_CID_LEN) return WT_ERR_INVALID_ARGUMENT;
    /* Two bytes beyond the first byte and the ID are needed even for the shortest packet number, so a
     * datagram that cannot hold them is short rather than interesting. */
    if (length < 1U + local_connection_id_len + 1U) return WT_ERR_TRUNCATED;
    *out_offset = 1U + local_connection_id_len;
    *out_total_len = length;
    return WT_OK;
  }

  c = wt_cursor_init(data, length);
  (void)wt_cursor_u8(&c); /* the first byte, whose low bits the mask owns */
  {
    const uint8_t *version = wt_cursor_bytes(&c, WT_BE32_SIZE);
    if (version == NULL) return WT_ERR_TRUNCATED;
    if (wt_load_be32(version) == WT_QUIC_VERSION_NEGOTIATION) {
      /* A Version Negotiation is a long header with version zero and no Length field, so this walk
       * would read its version list as one. */
      return WT_ERR_INVALID_ARGUMENT;
    }
  }
  type_bits = (uint32_t)((first >> 4) & 0x03U);
  if ((wt_quic_packet_type_t)type_bits == WT_QUIC_PACKET_RETRY) {
    /* A Retry has no packet number: its last sixteen bytes are an integrity tag, and the low bits of
     * its first byte are the unused 0b1111 rather than a length. */
    return WT_ERR_INVALID_ARGUMENT;
  }

  /* The destination connection ID, then the source connection ID, each a length byte and that many
   * bytes: the same reader the decoder uses, so the twenty-byte rule is stated once. */
  {
    const uint8_t *id = NULL;
    size_t id_len = 0U;
    wt_status_t status = wt_quic_read_connection_id(&c, &id, &id_len, NULL);
    if (status != WT_OK) return status;
    status = wt_quic_read_connection_id(&c, &id, &id_len, NULL);
    if (status != WT_OK) return status;
  }

  if ((wt_quic_packet_type_t)type_bits == WT_QUIC_PACKET_INITIAL) {
    if (wt_quic_varint_decode(&c, &token_len) != WT_OK) return WT_ERR_TRUNCATED;
    if (wt_checked_narrow_u64_to_size(token_len, &narrowed) != WT_OK) return WT_ERR_OVERFLOW;
    if (narrowed > wt_cursor_remaining(&c)) return WT_ERR_TRUNCATED;
    token = wt_cursor_bytes(&c, narrowed);
    if (token == NULL) return WT_ERR_TRUNCATED;
  }

  if (wt_quic_varint_decode(&c, &length_field) != WT_OK) return WT_ERR_TRUNCATED;
  if (wt_checked_narrow_u64_to_size(length_field, &narrowed) != WT_OK) return WT_ERR_OVERFLOW;
  *out_offset = c.offset;
  /* The Length field covers the packet number and the payload, so the packet ends that many bytes
   * after the field -- and a length the datagram cannot hold is a truncation rather than a packet. */
  if (narrowed > length - c.offset) return WT_ERR_TRUNCATED;
  *out_total_len = c.offset + narrowed;
  return WT_OK;
}

wt_status_t wt_quic_long_header_decode(wt_cursor_t *c,
                                       wt_quic_long_header_t *out,
                                       wt_quic_error_t *out_error) {
  const uint8_t *start;
  uint8_t first;
  uint32_t type_bits;
  wt_status_t status;
  size_t header_len;
  uint64_t length_field = 0U;

  if (c == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  memset(out, 0, sizeof(*out));

  start = c->data + c->offset;

  first = wt_cursor_u8(c);
  if (wt_cursor_failed(c)) return WT_ERR_TRUNCATED;
  if ((first & WT_QUIC_LONG_HEADER_BIT) == 0U) {
    return wt_quic_packet_fail(out_error, WT_QUIC_PROTOCOL_VIOLATION,
                               WT_ERR_PROTOCOL);
  }
  /* RFC 9000 section 17.2: the fixed bit must be set. A long header with it
   * cleared is not a packet in this version and must be discarded. */
  if ((first & WT_QUIC_FIXED_BIT) == 0U) {
    return wt_quic_packet_fail(out_error, WT_QUIC_PROTOCOL_VIOLATION,
                               WT_ERR_PROTOCOL);
  }
  /* RFC 9000 section 17.2 makes non-zero reserved bits a connection error -- "after removing both packet
   * and header protection". They are inside the AEAD's associated data, so a value that is non-zero here
   * may simply be a packet protected with another key set, which RFC 9001 section 5.3 says to DISCARD.
   * The decoder therefore REPORTS them and the caller refuses once the packet has authenticated: a
   * refusal here turned every packet from another key epoch into a violation against the peer
   * (WT-167). */
  out->reserved_bits_set = (first & 0x0cU) != 0U ? 1 : 0;
  type_bits = (uint32_t)((first >> 4) & 0x03U);
  out->type = (wt_quic_packet_type_t)type_bits;
  out->packet_number_len = (size_t)(first & 0x03U) + 1U;

  if (out->type == WT_QUIC_PACKET_RETRY) {
    /* A Retry has no Length field and no packet number, so the shape below does
     * not describe it. Its own parser is the one to call. */
    return wt_quic_packet_fail(out_error, WT_QUIC_PROTOCOL_VIOLATION,
                               WT_ERR_PROTOCOL);
  }

  {
    const uint8_t *version = wt_cursor_bytes(c, WT_BE32_SIZE);
    if (version == NULL) return WT_ERR_TRUNCATED;
    out->version = wt_load_be32(version);
  }
  status = wt_quic_read_connection_id(c, &out->destination_connection_id,
                                      &out->destination_connection_id_len,
                                      out_error);
  if (status != WT_OK) return status;
  status = wt_quic_read_connection_id(c, &out->source_connection_id,
                                      &out->source_connection_id_len,
                                      out_error);
  if (status != WT_OK) return status;

  if (out->type == WT_QUIC_PACKET_INITIAL) {
    uint64_t token_len = 0U;
    size_t narrowed = 0U;
    if (wt_quic_varint_decode(c, &token_len) != WT_OK) return WT_ERR_TRUNCATED;
    if (wt_checked_narrow_u64_to_size(token_len, &narrowed) != WT_OK) {
      return wt_quic_packet_fail(out_error, WT_QUIC_FRAME_ENCODING_ERROR,
                                 WT_ERR_OVERFLOW);
    }
    if (narrowed > wt_cursor_remaining(c)) return WT_ERR_TRUNCATED;
    out->token = wt_cursor_bytes(c, narrowed);
    out->token_len = narrowed;
  }

  if (wt_quic_varint_decode(c, &length_field) != WT_OK) return WT_ERR_TRUNCATED;

  {
    const uint8_t *packet_number = wt_cursor_bytes(c, out->packet_number_len);
    uint64_t value = 0U;
    size_t i;
    if (packet_number == NULL) return WT_ERR_TRUNCATED;
    for (i = 0U; i < out->packet_number_len; i++) {
      value = (value << 8) | (uint64_t)packet_number[i];
    }
    out->packet_number = value;
  }

  /* The header runs from the first byte THROUGH the packet number, which is what
   * RFC 9001 section 5.3 authenticates as the associated data. Computing it
   * before the packet number was read gave a header that stopped at the Length
   * field, and an AEAD that authenticated eighteen bytes of a twenty-two byte
   * header would reject every packet -- with a tag failure that names nothing.
   * The RFC's own client Initial makes the difference visible: eight of its
   * twenty-two header bytes are the packet number. */
  header_len = c->offset - (size_t)(start - c->data);

  /* The Length field covers the packet number and the payload. Subtracting is
   * how a mismatch is detected: a length that does not reach past the packet
   * number is a malformed packet and not a payload of negative size. */
  if (length_field < (uint64_t)out->packet_number_len) {
    return wt_quic_packet_fail(out_error, WT_QUIC_FRAME_ENCODING_ERROR,
                               WT_ERR_PROTOCOL);
  }
  {
    uint64_t payload_len = length_field - (uint64_t)out->packet_number_len;
    size_t narrowed = 0U;
    if (wt_checked_narrow_u64_to_size(payload_len, &narrowed) != WT_OK) {
      return wt_quic_packet_fail(out_error, WT_QUIC_FRAME_ENCODING_ERROR,
                                 WT_ERR_OVERFLOW);
    }
    if (narrowed > wt_cursor_remaining(c)) return WT_ERR_TRUNCATED;
    out->payload = wt_cursor_bytes(c, narrowed);
    out->payload_len = narrowed;
  }

  out->header = start;
  out->header_len = header_len;
  /* The header already includes the packet number, so the packet is the header
   * plus the payload and nothing else. Adding the packet number again -- which
   * this did while header_len excluded it -- reported every packet four bytes
   * too long and put the next coalesced packet's parse four bytes early. */
  out->total_len = header_len + out->payload_len;
  return WT_OK;
}

wt_status_t wt_quic_short_header_decode(wt_cursor_t *c,
                                        size_t destination_connection_id_len,
                                        wt_quic_short_header_t *out,
                                        wt_quic_error_t *out_error) {
  const uint8_t *start;
  uint8_t first;

  if (c == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  memset(out, 0, sizeof(*out));
  if (destination_connection_id_len > WT_QUIC_MAX_CID_LEN) {
    return WT_ERR_INVALID_ARGUMENT;
  }

  start = c->data + c->offset;
  first = wt_cursor_u8(c);
  if (wt_cursor_failed(c)) return WT_ERR_TRUNCATED;
  if ((first & WT_QUIC_LONG_HEADER_BIT) != 0U) {
    return wt_quic_packet_fail(out_error, WT_QUIC_PROTOCOL_VIOLATION,
                               WT_ERR_PROTOCOL);
  }
  if ((first & WT_QUIC_FIXED_BIT) == 0U) {
    return wt_quic_packet_fail(out_error, WT_QUIC_PROTOCOL_VIOLATION,
                               WT_ERR_PROTOCOL);
  }

  out->spin = (first & WT_QUIC_SPIN_BIT) ? 1 : 0;
  out->key_phase = (first & WT_QUIC_KEY_PHASE_BIT) ? 1 : 0;
  out->packet_number_len = (size_t)(first & 0x03U) + 1U;
  /* RFC 9000 section 17.3's reserved bits, reported for the same reason the long header's are: the rule
   * is about a packet whose protection has been REMOVED (WT-167). */
  out->reserved_bits_set = (first & 0x18U) != 0U ? 1 : 0;

  out->destination_connection_id = wt_cursor_bytes(
      c, destination_connection_id_len);
  if (out->destination_connection_id == NULL &&
      destination_connection_id_len != 0U) {
    return WT_ERR_TRUNCATED;
  }
  out->destination_connection_id_len = destination_connection_id_len;

  {
    const uint8_t *packet_number = wt_cursor_bytes(c, out->packet_number_len);
    uint64_t value = 0U;
    size_t i;
    if (packet_number == NULL) return WT_ERR_TRUNCATED;
    for (i = 0U; i < out->packet_number_len; i++) {
      value = (value << 8) | (uint64_t)packet_number[i];
    }
    out->packet_number = value;
  }

  /* A short header has no Length field, so the payload is everything left. That
   * is why a short header must be the last packet in a datagram. */
  {
    size_t remaining = 0U;
    out->payload = wt_cursor_rest(c, &remaining);
    out->payload_len = remaining;
    if (remaining != 0U) (void)wt_cursor_skip(c, remaining);
  }

  out->header = start;
  out->header_len = out->packet_number_len + 1U + destination_connection_id_len;
  out->total_len = out->header_len + out->payload_len;
  return WT_OK;
}

wt_status_t wt_quic_retry_packet_decode(const uint8_t *data, size_t length,
                                        wt_quic_retry_packet_t *out,
                                        wt_quic_error_t *out_error) {
  wt_cursor_t c;
  uint8_t first;
  wt_status_t status;
  size_t header_len;

  if (data == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  memset(out, 0, sizeof(*out));
  /* A Retry is a whole datagram: the token runs to the end minus the tag, so
   * there is nothing to coalesce and a shorter buffer is a truncated packet
   * rather than a prefix of a longer one. */
  if (length < 1U + WT_BE32_SIZE + 1U + 1U + WT_QUIC_RETRY_INTEGRITY_TAG_LEN) {
    return WT_ERR_TRUNCATED;
  }
  c = wt_cursor_init(data, length);

  first = wt_cursor_u8(&c);
  if ((first & WT_QUIC_LONG_HEADER_BIT) == 0U ||
      (first & WT_QUIC_FIXED_BIT) == 0U) {
    return wt_quic_packet_fail(out_error, WT_QUIC_PROTOCOL_VIOLATION,
                               WT_ERR_PROTOCOL);
  }
  if ((first & 0x0cU) != 0U) {
    return wt_quic_packet_fail(out_error, WT_QUIC_PROTOCOL_VIOLATION,
                               WT_ERR_PROTOCOL);
  }
  if ((wt_quic_packet_type_t)((first >> 4) & 0x03U) != WT_QUIC_PACKET_RETRY) {
    return wt_quic_packet_fail(out_error, WT_QUIC_PROTOCOL_VIOLATION,
                               WT_ERR_PROTOCOL);
  }
  {
    const uint8_t *version = wt_cursor_bytes(&c, WT_BE32_SIZE);
    if (version == NULL) return WT_ERR_TRUNCATED;
    out->version = wt_load_be32(version);
  }
  status = wt_quic_read_connection_id(&c, &out->destination_connection_id,
                                      &out->destination_connection_id_len,
                                      out_error);
  if (status != WT_OK) return status;
  status = wt_quic_read_connection_id(&c, &out->source_connection_id,
                                      &out->source_connection_id_len, out_error);
  if (status != WT_OK) return status;

  header_len = c.offset;
  /* The header is as long as its two connection ID lengths make it, so the check at the top of this function --
   * which only demands the SHORTEST possible Retry -- is not enough: `length - header_len - 16` underflows to
   * nearly `SIZE_MAX` for a datagram whose header runs into the tag, and the "token" view points past the end of
   * the buffer while the function reports WT_OK. A parser that hands out a length it did not verify is the
   * memory-safety defect an audit found here, and the guard is one comparison: the header and the tag have to
   * fit before anything may be called a token (`WT-203`). */
  if (length < header_len + WT_QUIC_RETRY_INTEGRITY_TAG_LEN) return WT_ERR_TRUNCATED;
  /* The token is what is left once the tag is reserved, and the tag is the last
   * sixteen bytes. A Retry with no token is malformed: RFC 9000 section 17.2.5
   * allows a zero-length token but then the packet is only a header and a tag,
   * which no retry would be. */
  out->token = data + header_len;
  out->token_len = length - header_len - WT_QUIC_RETRY_INTEGRITY_TAG_LEN;
  out->integrity_tag = data + length - WT_QUIC_RETRY_INTEGRITY_TAG_LEN;
  out->header = data;
  out->header_len = header_len;
  out->total_len = length;
  return WT_OK;
}

/* --------------------------------------------------------------- encoding */

static void wt_quic_write_connection_id(wt_writer_t *w, const uint8_t *id,
                                        size_t id_len) {
  wt_writer_u8(w, (uint8_t)id_len);
  wt_writer_bytes(w, id, id_len);
}

/* The body both encoders share. `with_payload` is 0 for the prefix form, where the caller is going
 * to produce the payload itself and only needs the header -- and the Length field, which is computed
 * here from the payload length the caller states, so the two forms cannot disagree about it. */
static wt_status_t long_header_encode(wt_writer_t *w, wt_quic_packet_type_t type,
                                      uint32_t version,
                                      const uint8_t *destination_connection_id,
                                      size_t destination_connection_id_len,
                                      const uint8_t *source_connection_id,
                                      size_t source_connection_id_len,
                                      const uint8_t *token, size_t token_len,
                                      uint64_t packet_number,
                                      size_t packet_number_len, const uint8_t *payload,
                                      size_t payload_len, int with_payload) {
  uint8_t first;
  uint8_t packet_number_bytes[4];
  size_t length_field;

  if (w == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* A Retry has a different shape and its own encoder; a Version Negotiation
   * packet is not a packet with a type at all. */
  if (type == WT_QUIC_PACKET_RETRY) return WT_ERR_INVALID_ARGUMENT;
  if ((type != WT_QUIC_PACKET_INITIAL && type != WT_QUIC_PACKET_ZERO_RTT &&
       type != WT_QUIC_PACKET_HANDSHAKE)) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (destination_connection_id_len > WT_QUIC_MAX_CID_LEN ||
      source_connection_id_len > WT_QUIC_MAX_CID_LEN) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (destination_connection_id_len != 0U && destination_connection_id == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (source_connection_id_len != 0U && source_connection_id == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (packet_number_len == 0U || packet_number_len > 4U) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  /* The token belongs to Initial packets only. A caller that set one on another
   * type is asking for a packet the peer will not parse. */
  if (type != WT_QUIC_PACKET_INITIAL && token_len != 0U) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (token_len != 0U && token == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (with_payload && payload_len != 0U && payload == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }

  first = (uint8_t)((unsigned int)WT_QUIC_LONG_HEADER_BIT |
                    (unsigned int)WT_QUIC_FIXED_BIT |
                    ((unsigned int)type << 4) |
                    (unsigned int)(packet_number_len - 1U));
  if (packet_number_len != wt_quic_packet_number_encode(packet_number,
                                                        packet_number_len,
                                                        packet_number_bytes)) {
    return WT_ERR_INVALID_ARGUMENT;
  }

  /* The Length field is computed here, never taken from the caller. */
  if (wt_checked_add_size(packet_number_len, payload_len, &length_field) !=
      WT_OK) {
    return WT_ERR_OVERFLOW;
  }
  if (wt_quic_varint_size((uint64_t)length_field) == 0U) {
    return WT_ERR_OVERFLOW;
  }

  wt_writer_u8(w, first);
  wt_writer_u32(w, version);
  wt_quic_write_connection_id(w, destination_connection_id,
                              destination_connection_id_len);
  wt_quic_write_connection_id(w, source_connection_id,
                              source_connection_id_len);
  if (type == WT_QUIC_PACKET_INITIAL) {
    (void)wt_quic_writer_varint(w, (uint64_t)token_len);
    wt_writer_bytes(w, token, token_len);
  }
  (void)wt_quic_writer_varint(w, (uint64_t)length_field);
  wt_writer_bytes(w, packet_number_bytes, packet_number_len);
  if (with_payload) wt_writer_bytes(w, payload, payload_len);
  return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
}

wt_status_t wt_quic_long_header_encode(wt_writer_t *w,
                                       wt_quic_packet_type_t type,
                                       uint32_t version,
                                       const uint8_t *destination_connection_id,
                                       size_t destination_connection_id_len,
                                       const uint8_t *source_connection_id,
                                       size_t source_connection_id_len,
                                       const uint8_t *token, size_t token_len,
                                       uint64_t packet_number,
                                       size_t packet_number_len,
                                       const uint8_t *payload,
                                       size_t payload_len) {
  return long_header_encode(w, type, version, destination_connection_id,
                            destination_connection_id_len, source_connection_id,
                            source_connection_id_len, token, token_len, packet_number,
                            packet_number_len, payload, payload_len, 1);
}

wt_status_t wt_quic_long_header_encode_prefix(
    wt_writer_t *w, wt_quic_packet_type_t type, uint32_t version,
    const uint8_t *destination_connection_id, size_t destination_connection_id_len,
    const uint8_t *source_connection_id, size_t source_connection_id_len,
    const uint8_t *token, size_t token_len, uint64_t packet_number,
    size_t packet_number_len, size_t payload_len) {
  return long_header_encode(w, type, version, destination_connection_id,
                            destination_connection_id_len, source_connection_id,
                            source_connection_id_len, token, token_len, packet_number,
                            packet_number_len, NULL, payload_len, 0);
}

wt_status_t wt_quic_short_header_encode(wt_writer_t *w,
                                        const uint8_t *destination_connection_id,
                                        size_t destination_connection_id_len,
                                        uint64_t packet_number,
                                        size_t packet_number_len, int key_phase,
                                        int spin, const uint8_t *payload,
                                        size_t payload_len) {
  uint8_t first;
  uint8_t packet_number_bytes[4];

  if (w == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (destination_connection_id_len > WT_QUIC_MAX_CID_LEN) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (destination_connection_id_len != 0U && destination_connection_id == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (packet_number_len == 0U || packet_number_len > 4U) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (payload_len != 0U && payload == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (wt_quic_packet_number_encode(packet_number, packet_number_len,
                                   packet_number_bytes) != packet_number_len) {
    return WT_ERR_INVALID_ARGUMENT;
  }

  first = (uint8_t)(WT_QUIC_FIXED_BIT | (uint8_t)(packet_number_len - 1U));
  if (spin) first |= WT_QUIC_SPIN_BIT;
  if (key_phase) first |= WT_QUIC_KEY_PHASE_BIT;
  wt_writer_u8(w, first);
  wt_writer_bytes(w, destination_connection_id, destination_connection_id_len);
  wt_writer_bytes(w, packet_number_bytes, packet_number_len);
  wt_writer_bytes(w, payload, payload_len);
  return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
}

wt_status_t wt_quic_retry_packet_encode(
    wt_writer_t *w, uint32_t version, const uint8_t *destination_connection_id,
    size_t destination_connection_id_len, const uint8_t *source_connection_id,
    size_t source_connection_id_len, const uint8_t *token, size_t token_len,
    const uint8_t integrity_tag[16]) {
  if (w == NULL || integrity_tag == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (destination_connection_id_len > WT_QUIC_MAX_CID_LEN ||
      source_connection_id_len > WT_QUIC_MAX_CID_LEN) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (source_connection_id_len == 0U || source_connection_id == NULL) {
    /* RFC 9000 section 17.2.5: the Source Connection ID in a Retry is the one the
     * server chose, and a server that has not chosen one cannot retry. */
    return WT_ERR_INVALID_ARGUMENT;
  }
  /* A Retry has no packet number, so the low two bits of the first byte are
   * reserved and zero; and it always uses the long header's Retry type. */
  wt_writer_u8(w, (uint8_t)(WT_QUIC_LONG_HEADER_BIT | WT_QUIC_FIXED_BIT |
                            ((uint8_t)WT_QUIC_PACKET_RETRY << 4)));
  wt_writer_u32(w, version);
  wt_quic_write_connection_id(w, destination_connection_id,
                              destination_connection_id_len);
  wt_quic_write_connection_id(w, source_connection_id,
                              source_connection_id_len);
  wt_writer_bytes(w, token, token_len);
  wt_writer_bytes(w, integrity_tag, WT_QUIC_RETRY_INTEGRITY_TAG_LEN);
  return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
}
