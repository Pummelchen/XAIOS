/* The server's half of a Retry: answer an Initial, then check the token that comes back (see the header). */

#include "webtransport/runtime/server_retry.h"

#include <string.h>

#include "webtransport/crypto/crypto.h"
#include "webtransport/quic/packet.h"
#include "webtransport/quic/protection.h"
#include "webtransport/writer.h"

/* The connection ID length the tools use, which `arm` requires rather than invents: the caller's connection is
 * configured with an ID of some length, and a Retry that named one of another length would put the client's
 * subsequent packets on a connection ID this endpoint cannot parse. */
#define WT_RUNTIME_SERVER_RETRY_MIN_ID 1U

wt_status_t wt_runtime_server_retry_arm(wt_runtime_server_retry_t *retry, size_t connection_id_length,
                                        uint64_t token_max_age) {
  wt_status_t status;

  if (retry == NULL) return WT_ERR_INVALID_ARGUMENT;
  memset(retry, 0, sizeof(*retry));
  if (connection_id_length < WT_RUNTIME_SERVER_RETRY_MIN_ID ||
      connection_id_length > WT_QUIC_MAX_CONNECTION_ID_LENGTH) {
    return WT_ERR_INVALID_ARGUMENT;
  }

  status = wt_random_bytes(retry->secret, sizeof(retry->secret));
  if (status != WT_OK) return status;
  /* A fresh ID per Retry, from the same source as the secret: an ID a client could predict would be one an
   * off-path attacker could use, and section 5.1 asks for unpredictability for exactly that reason. */
  status = wt_random_bytes(retry->source_connection_id, connection_id_length);
  if (status != WT_OK) return status;
  retry->source_connection_id_length = connection_id_length;
  retry->token_max_age = token_max_age;
  retry->armed = 1;
  return WT_OK;
}

const uint8_t *wt_runtime_server_retry_source_id(const wt_runtime_server_retry_t *retry, size_t *out_length) {
  if (out_length != NULL) *out_length = 0U;
  if (retry == NULL || retry->armed == 0) return NULL;
  if (out_length != NULL) *out_length = retry->source_connection_id_length;
  return retry->source_connection_id;
}

/* What a caller needs from a client's Initial, read from a datagram that may be TRUNCATED after the header: the
 * two connection IDs and the token. NOT the full decoder -- a listener peeks 64 bytes of a 1200-byte Initial, and
 * the full decoder wants the payload. */
typedef struct retry_initial {
  const uint8_t *destination_connection_id;
  size_t destination_connection_id_length;
  const uint8_t *source_connection_id;
  size_t source_connection_id_length;
  const uint8_t *token;
  size_t token_length;
} retry_initial_t;

/* Returns WT_OK with `*out_initial` set when the datagram is an Initial this endpoint can read at all; every other
 * answer is "not an Initial for us", which the callers report as an ordinary outcome rather than an error. */
static wt_status_t read_initial(const uint8_t *datagram, size_t length, retry_initial_t *out,
                                int *out_initial) {
  wt_status_t status;

  *out_initial = 0;
  memset(out, 0, sizeof(*out));
  if (datagram == NULL || length == 0U) return WT_ERR_INVALID_ARGUMENT;
  if (wt_quic_long_header_connection_ids(datagram, length, &out->destination_connection_id,
                                         &out->destination_connection_id_length,
                                         &out->source_connection_id,
                                         &out->source_connection_id_length) != WT_OK) {
    return WT_OK;
  }
  /* The token is the field that says whether this is a first Initial or an answer to a Retry, and reading it
   * needs a few more bytes than the connection IDs did. A buffer that ends inside it is TRUNCATED, which is NOT
   * "no token": the two mean opposite things here, so it is reported as not-an-Initial rather than guessed. */
  status = wt_quic_initial_token(datagram, length, &out->token, &out->token_length);
  if (status != WT_OK) return WT_OK;
  *out_initial = 1;
  return WT_OK;
}

wt_status_t wt_runtime_server_retry_build(wt_runtime_server_retry_t *retry, const uint8_t *datagram,
                                          size_t length, const wt_udp_address_t *peer, uint64_t now,
                                          uint8_t *out, size_t capacity, size_t *out_length,
                                          int *out_is_retry) {
  retry_initial_t header;
  uint8_t token[WT_QUIC_RETRY_TOKEN_MAX];
  uint8_t address[WT_UDP_ADDRESS_ENCODED_LENGTH];
  uint8_t tag[WT_AEAD_TAG_LEN];
  wt_writer_t writer;
  size_t address_length;
  size_t token_length = 0U;
  size_t written;
  int is_initial = 0;
  wt_status_t status;

  if (out_is_retry != NULL) *out_is_retry = 0;
  if (out_length != NULL) *out_length = 0U;
  if (retry == NULL || datagram == NULL || peer == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (retry->armed == 0) return WT_ERR_STATE;

  status = read_initial(datagram, length, &header, &is_initial);
  if (status != WT_OK) return status;
  if (is_initial == 0) return WT_OK;
  /* A client that already carries a token is answering a Retry (possibly not this one): validating it is
   * `accept`'s job, and answering a second Retry here would be a loop. */
  if (header.token_length != 0U) return WT_OK;
  if (header.source_connection_id_length == 0U || header.destination_connection_id_length == 0U) return WT_OK;

  address_length = wt_udp_address_encode(peer, address, sizeof(address));
  if (address_length == 0U) return WT_ERR_INVALID_ARGUMENT;
  status = wt_quic_retry_token_build(retry->secret, address, address_length,
                                    header.destination_connection_id,
                                    header.destination_connection_id_length, now, token, sizeof(token),
                                    &token_length);
  if (status != WT_OK) return status;

  /* The Retry's Destination Connection ID is the client's Source Connection ID, and its Source Connection ID is
   * the one this connection will use from now on (RFC 9000 section 17.2.5). The tag covers the ORIGINAL
   * destination connection ID -- the one this Initial was addressed to -- which is why the client can only accept
   * a Retry from a server that saw its first Initial (RFC 9001 section 5.8).
   *
   * The packet is therefore encoded TWICE, and the reason is the tag's own definition: it covers the packet
   * WITHOUT the tag, so a first pass writes a placeholder that fixes the length, the tag is computed over
   * everything before it, and a second pass writes the packet with the tag in place. Getting this wrong -- either
   * order, or hashing the placeholder -- fails on the peer as an authentication failure with nothing to
   * distinguish it from a wrong key. */
  writer = wt_writer_init(out, capacity);
  status = wt_quic_retry_packet_encode(&writer, WT_QUIC_VERSION_1, header.source_connection_id,
                                       header.source_connection_id_length, retry->source_connection_id,
                                       retry->source_connection_id_length, token, token_length, tag);
  if (status != WT_OK) return status;
  written = wt_writer_offset(&writer);
  status = wt_quic_retry_integrity_tag(header.destination_connection_id, header.destination_connection_id_length,
                                      out, written - WT_AEAD_TAG_LEN, tag);
  if (status != WT_OK) return status;
  writer = wt_writer_init(out, capacity);
  status = wt_quic_retry_packet_encode(&writer, WT_QUIC_VERSION_1, header.source_connection_id,
                                       header.source_connection_id_length, retry->source_connection_id,
                                       retry->source_connection_id_length, token, token_length, tag);
  if (status != WT_OK) return status;
  written = wt_writer_offset(&writer);

  retry->retries_sent++;
  if (out_is_retry != NULL) *out_is_retry = 1;
  if (out_length != NULL) *out_length = written;
  return WT_OK;
}

wt_status_t wt_runtime_server_retry_accept(wt_runtime_server_retry_t *retry, const uint8_t *datagram,
                                           size_t length, const wt_udp_address_t *peer, uint64_t now,
                                           uint8_t *out_original, size_t capacity,
                                           size_t *out_original_length, int *out_accepted) {
  retry_initial_t header;
  uint8_t address[WT_UDP_ADDRESS_ENCODED_LENGTH];
  size_t address_length;
  size_t original_length = 0U;
  int is_initial = 0;
  wt_status_t status;

  if (out_accepted != NULL) *out_accepted = 0;
  if (out_original_length != NULL) *out_original_length = 0U;
  if (retry == NULL || datagram == NULL || peer == NULL || out_original == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (retry->armed == 0) return WT_ERR_STATE;

  status = read_initial(datagram, length, &header, &is_initial);
  if (status != WT_OK) return status;
  if (is_initial == 0) return WT_OK;
  /* No token means the client never saw a Retry (or ignored it): nothing to validate, and the caller decides what
   * that means. Addressed elsewhere means the packet is not an answer to this Retry. */
  if (header.token_length == 0U) return WT_OK;
  if (header.destination_connection_id_length != retry->source_connection_id_length ||
      memcmp(header.destination_connection_id, retry->source_connection_id,
             retry->source_connection_id_length) != 0) {
    return WT_OK;
  }

  address_length = wt_udp_address_encode(peer, address, sizeof(address));
  if (address_length == 0U) return WT_ERR_INVALID_ARGUMENT;
  status = wt_quic_retry_token_validate(retry->secret, address, address_length, now, retry->token_max_age,
                                       header.token, header.token_length, out_original, capacity,
                                       &original_length);
  if (status != WT_OK) {
    /* A token that is not this server's for this peer is counted and reported as "not accepted": the caller's
     * answer is another Retry, which is also the answer to a stale one. */
    retry->tokens_refused++;
    return status;
  }

  if (out_accepted != NULL) *out_accepted = 1;
  if (out_original_length != NULL) *out_original_length = original_length;
  return WT_OK;
}
