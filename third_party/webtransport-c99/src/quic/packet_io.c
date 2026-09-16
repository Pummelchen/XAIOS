/* One packet out, one packet in. See webtransport/quic/packet_io.h. */

#include "webtransport/quic/packet_io.h"

#include <string.h>

#include "webtransport/quic/packet_number.h"
#include "webtransport/writer.h"

wt_status_t wt_quic_packet_build(const wt_quic_packet_build_t *params, uint8_t *out,
                                 size_t capacity, size_t *out_len) {
  wt_writer_t w;
  size_t header_len;
  size_t ciphertext_len;
  const uint8_t *plaintext = NULL;
  size_t plaintext_len = 0U;
  uint8_t padding[WT_QUIC_HP_SAMPLE_OFFSET];
  wt_status_t status;

  if (params == NULL || out == NULL || out_len == NULL) return WT_ERR_INVALID_ARGUMENT;
  *out_len = 0U;
  if (params->keys == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (params->payload == NULL && params->payload_len != 0U) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (params->packet_number_length == 0U || params->packet_number_length > 4U) {
    return WT_ERR_INVALID_ARGUMENT;
  }

  /* RFC 9001 section 5.4.2 takes the header protection sample from the sixteen bytes starting four
   * bytes into the packet number field, and a packet too short to hold one cannot be protected -- so a
   * sender cannot put a two-byte frame such as RETIRE_CONNECTION_ID or PING on the wire on its own.
   * The header's own length cancels out of the sum, because the sample starts after the packet number
   * rather than after the header: what a packet needs is `offset + sample` bytes from the start of the
   * packet number, of which the tag supplies `WT_AEAD_TAG_LEN` and the packet number the rest. The
   * shortfall is at most three bytes and PADDING frames are what fills it (RFC 9000 section 19.1): they
   * carry nothing and every receiver ignores them.
   *
   * Padding here rather than at each caller is what makes the builder's contract honest -- a caller
   * that can encode a frame can send it -- and it is the same reason the receiver already tolerates
   * PADDING anywhere in a packet. */
  plaintext = params->payload;
  plaintext_len = params->payload_len;
  if (plaintext_len + params->packet_number_length + WT_AEAD_TAG_LEN <
      WT_QUIC_HP_SAMPLE_OFFSET + WT_QUIC_HP_SAMPLE_LENGTH) {
    size_t padded_len = WT_QUIC_HP_SAMPLE_OFFSET + WT_QUIC_HP_SAMPLE_LENGTH - WT_AEAD_TAG_LEN -
                        params->packet_number_length;
    /* `padded_len` is at most WT_QUIC_HP_SAMPLE_OFFSET-1 because the packet number contributes at
     * least one byte; the guard states that rather than assuming it. */
    if (padded_len > sizeof(padding)) return WT_ERR_STATE;
    memset(padding, 0, sizeof(padding));
    if (plaintext_len != 0U) {
      memcpy(padding, params->payload, plaintext_len);
    }
    plaintext = padding;
    plaintext_len = padded_len;
  }

  /* The ciphertext is the payload plus the tag, and its length is what the Length field covers. */
  if (plaintext_len > SIZE_MAX - WT_AEAD_TAG_LEN) return WT_ERR_OVERFLOW;
  ciphertext_len = plaintext_len + WT_AEAD_TAG_LEN;
  if (capacity < ciphertext_len) return WT_ERR_LIMIT;

  /* The header first: the AEAD authenticates it. */
  w = wt_writer_init(out, capacity);
  if (params->short_header) {
    if (params->source_connection_id_len != 0U || params->token_len != 0U) {
      /* Neither field exists in a short header, so a caller that set one is asking for a packet that
       * cannot be encoded rather than one that will be wrong. */
      return WT_ERR_INVALID_ARGUMENT;
    }
    status = wt_quic_short_header_encode(&w, params->destination_connection_id,
                                        params->destination_connection_id_len,
                                        params->packet_number,
                                        params->packet_number_length, params->key_phase,
                                        0, NULL, 0U);
  } else {
    status = wt_quic_long_header_encode_prefix(
        &w, params->type, params->version, params->destination_connection_id,
        params->destination_connection_id_len, params->source_connection_id,
        params->source_connection_id_len, params->token, params->token_len,
        params->packet_number, params->packet_number_length, ciphertext_len);
  }
  if (status != WT_OK) return status;
  header_len = wt_writer_offset(&w);
  if (capacity - header_len < ciphertext_len) return WT_ERR_LIMIT;

  /* The payload, sealed with the header as associated data. */
  status = wt_quic_protect_frames(params->keys, params->packet_number, out, header_len,
                                  plaintext, plaintext_len, out + header_len,
                                  capacity - header_len, &ciphertext_len);
  if (status != WT_OK) {
    memset(out, 0, header_len);
    return status;
  }

  /* Header protection last, because its sample comes from the ciphertext. */
  status = wt_quic_protect_header(params->keys->aead, params->keys->hp, params->keys->hp_len,
                                  out, header_len + ciphertext_len,
                                  header_len - params->packet_number_length,
                                  params->packet_number_length);
  if (status != WT_OK) {
    memset(out, 0, header_len + ciphertext_len);
    return status;
  }
  *out_len = header_len + ciphertext_len;
  return WT_OK;
}

wt_status_t wt_quic_packet_unprotect_header(uint8_t *packet, size_t length,
                                            const wt_quic_packet_keys_t *keys,
                                            size_t local_connection_id_len, size_t *out_pn_offset,
                                            size_t *out_total_len, size_t *out_pn_len,
                                            int *out_short_header) {
  wt_status_t status;
  size_t pn_offset = 0U;
  size_t total_len = 0U;
  int short_header = 0;
  size_t pn_len = 0U;

  if (packet == NULL || keys == NULL) return WT_ERR_INVALID_ARGUMENT;

  /* The packet number's offset cannot come from a decoder: the number's own length is behind the mask.
   * It comes from the layout, and with it the length of the packet -- which for a long header is the
   * Length field's and not the datagram's, because a datagram may hold several packets. */
  status = wt_quic_protected_pn_offset(packet, length, local_connection_id_len, &pn_offset, &total_len,
                                       &short_header);
  if (status != WT_OK) return status;

  /* Header protection comes off here: its sample is the ciphertext, and the packet number length it reveals
   * is what the rest of the read is measured against. A key update does NOT change the header protection
   * key (RFC 9001 section 6.1), so a caller may pass the phase it currently holds and still read a packet
   * from any phase -- which is the whole reason this is a separate step (WT-69). */
  status = wt_quic_unprotect_header(keys->aead, keys->hp, keys->hp_len, packet, total_len, pn_offset,
                                    &pn_len);
  if (status != WT_OK) return status;

  if (out_pn_offset != NULL) *out_pn_offset = pn_offset;
  if (out_total_len != NULL) *out_total_len = total_len;
  if (out_pn_len != NULL) *out_pn_len = pn_len;
  if (out_short_header != NULL) *out_short_header = short_header;
  return WT_OK;
}

wt_status_t wt_quic_packet_open(uint8_t *packet, size_t total_len, size_t pn_len,
                                const wt_quic_packet_keys_t *keys, uint64_t largest_received,
                                size_t local_connection_id_len, wt_quic_received_packet_t *out) {
  wt_status_t status;

  if (packet == NULL || keys == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  memset(out, 0, sizeof(*out));

  /* Parsed now that the mask is off: the first byte's low bits are the real packet number length, so the
   * header's own lengths are the ones the sender wrote. */
  {
    wt_cursor_t cursor = wt_cursor_init(packet, total_len);
    wt_quic_error_t error;
    uint64_t truncated;
    size_t header_len;
    const uint8_t *payload;
    size_t payload_len;
    int reserved_bits_set = 0;
    int short_header = (packet[0] & WT_QUIC_LONG_HEADER_BIT) == 0U ? 1 : 0;

    if (short_header) {
      wt_quic_short_header_t header;
      status = wt_quic_short_header_decode(&cursor, local_connection_id_len, &header, &error);
      /* A header this endpoint cannot parse -- a cleared fixed bit, a type that does not exist -- is not
       * evidence of a peer breaking a rule: the bytes cannot be shown to come from the peer at all until the
       * packet protection verifies, and RFC 9001 section 5.3 makes such a packet one to DISCARD. Reporting a
       * protocol violation here is how a packet from another key epoch (a Retry's predecessor, an injected
       * datagram) became an error against the peer (WT-167). */
      if (status == WT_ERR_PROTOCOL) return WT_ERR_AUTHENTICATION;
      if (status != WT_OK) return status;
      reserved_bits_set = header.reserved_bits_set;
      /* `type` is left zeroed: a short header does not carry one, and which space it belongs to is what the
       * keys the caller chose say. */
      out->key_phase = header.key_phase;
      out->destination_connection_id = header.destination_connection_id;
      out->destination_connection_id_len = header.destination_connection_id_len;
      header_len = header.header_len;
      payload = header.payload;
      payload_len = header.payload_len;
      truncated = header.packet_number;
      out->packet_number_length = header.packet_number_len;
    } else {
      wt_quic_long_header_t header;
      status = wt_quic_long_header_decode(&cursor, &header, &error);
      if (status == WT_ERR_PROTOCOL) return WT_ERR_AUTHENTICATION;
      if (status != WT_OK) return status;
      reserved_bits_set = header.reserved_bits_set;
      out->type = header.type;
      out->version = header.version;
      out->destination_connection_id = header.destination_connection_id;
      out->destination_connection_id_len = header.destination_connection_id_len;
      out->source_connection_id = header.source_connection_id;
      out->source_connection_id_len = header.source_connection_id_len;
      header_len = header.header_len;
      payload = header.payload;
      payload_len = header.payload_len;
      truncated = header.packet_number;
      out->packet_number_length = header.packet_number_len;
    }
    (void)pn_len;
    /* The packet number is the truncated one against the largest this endpoint has seen, and it is read after
     * the mask is off -- which is the whole reason the order here is what it is. */
    out->packet_number = wt_quic_packet_number_decode(truncated, out->packet_number_length,
                                                      largest_received);
    out->header_len = header_len;
    out->short_header = short_header;
    out->total_len = total_len;
    if (payload_len < WT_AEAD_TAG_LEN) return WT_ERR_TRUNCATED;
    /* The payload, authenticated with the header through the packet number as associated data. */
    status = wt_quic_unprotect_frames(keys, out->packet_number, packet, header_len, packet + header_len,
                                      payload_len - WT_AEAD_TAG_LEN,
                                      payload + payload_len - WT_AEAD_TAG_LEN);
    if (status != WT_OK) return status;
    /* NOW the reserved bits are worth a violation: the packet authenticated, so it really did come from
     * whoever holds the key, and RFC 9000 section 17.2's "after removing both packet and header protection"
     * is satisfied. Nothing reaches this line without a valid tag. */
    if (reserved_bits_set != 0) return WT_ERR_PROTOCOL;
    out->payload = packet + header_len;
    out->payload_len = payload_len - WT_AEAD_TAG_LEN;
  }
  return WT_OK;
}

wt_status_t wt_quic_packet_read(uint8_t *packet, size_t length,
                                const wt_quic_packet_keys_t *keys,
                                uint64_t largest_received,
                                size_t local_connection_id_len,
                                wt_quic_received_packet_t *out) {
  size_t total_len = 0U;
  size_t pn_len = 0U;
  wt_status_t status;

  if (packet == NULL || keys == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  memset(out, 0, sizeof(*out));

  status = wt_quic_packet_unprotect_header(packet, length, keys, local_connection_id_len, NULL, &total_len,
                                           &pn_len, NULL);
  if (status != WT_OK) return status;
  return wt_quic_packet_open(packet, total_len, pn_len, keys, largest_received, local_connection_id_len, out);
}
