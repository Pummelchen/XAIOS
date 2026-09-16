/* Retry tokens: build and validate (see the header for the layout and the reasoning). */

#include "webtransport/quic/retry_token.h"

#include <string.h>

#include "webtransport/crypto/crypto.h"
#include "webtransport/endian.h"

/* The format byte, so a token from an older or newer layout is refused rather than misread. A server that
 * changes the layout bumps it, and every token in flight is then simply not this server's -- which costs those
 * clients one more Retry and is why the byte is here rather than implied by the length. */
#define WT_QUIC_RETRY_TOKEN_FORMAT 0x01U

/* Where each field starts, in one place: the two functions below are the only readers and writers, and a layout
 * that is described twice is a layout that drifts. */
#define WT_QUIC_RETRY_TOKEN_OFFSET_FORMAT 0U
#define WT_QUIC_RETRY_TOKEN_OFFSET_TIME 1U
#define WT_QUIC_RETRY_TOKEN_OFFSET_ADDRESS 9U
#define WT_QUIC_RETRY_TOKEN_ADDRESS_LENGTH (WT_QUIC_RETRY_TOKEN_OFFSET_ADDRESS + WT_QUIC_RETRY_TOKEN_ADDRESS_MAX)
#define WT_QUIC_RETRY_TOKEN_OFFSET_ODCID_LENGTH WT_QUIC_RETRY_TOKEN_ADDRESS_LENGTH
#define WT_QUIC_RETRY_TOKEN_OFFSET_ODCID (WT_QUIC_RETRY_TOKEN_OFFSET_ODCID_LENGTH + 1U)

/* The tag covers every byte before it. Both functions compute it the same way over the same length, which is what
 * makes the check a comparison rather than a parse. */
static wt_status_t token_tag(const uint8_t secret[WT_QUIC_RETRY_TOKEN_SECRET_LEN], const uint8_t *body,
                             size_t body_length, uint8_t out[WT_QUIC_RETRY_TOKEN_TAG_LEN]) {
  uint8_t mac[WT_SHA256_LEN];
  wt_status_t status = wt_hmac_sha256(secret, WT_QUIC_RETRY_TOKEN_SECRET_LEN, body, body_length, mac);

  if (status != WT_OK) return status;
  memcpy(out, mac, WT_QUIC_RETRY_TOKEN_TAG_LEN);
  return WT_OK;
}

static void token_body_header(uint8_t *out, uint64_t now, const uint8_t *address, size_t address_length) {
  out[WT_QUIC_RETRY_TOKEN_OFFSET_FORMAT] = WT_QUIC_RETRY_TOKEN_FORMAT;
  wt_store_be64(out + WT_QUIC_RETRY_TOKEN_OFFSET_TIME, now);
  /* The address is padded to the maximum with zeros so that two addresses of different lengths cannot produce the
   * same body, and so that the offset of everything after it is fixed. The LENGTH is not stored: the canonical
   * form is fixed-width, and a caller with a variable-width form binds the length by using a form that encodes it
   * (which `wt_udp_address_encode` does). */
  memset(out + WT_QUIC_RETRY_TOKEN_OFFSET_ADDRESS, 0, WT_QUIC_RETRY_TOKEN_ADDRESS_MAX);
  memcpy(out + WT_QUIC_RETRY_TOKEN_OFFSET_ADDRESS, address, address_length);
}

wt_status_t wt_quic_retry_token_build(const uint8_t secret[WT_QUIC_RETRY_TOKEN_SECRET_LEN],
                                      const uint8_t *address, size_t address_length,
                                      const uint8_t *original_destination_id, size_t original_length,
                                      uint64_t now, uint8_t *out, size_t capacity, size_t *out_length) {
  uint8_t body[WT_QUIC_RETRY_TOKEN_MAX];
  uint8_t tag[WT_QUIC_RETRY_TOKEN_TAG_LEN];
  size_t body_length;
  wt_status_t status;

  if (out_length != NULL) *out_length = 0U;
  if (secret == NULL || address == NULL || original_destination_id == NULL || out == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (address_length == 0U || address_length > WT_QUIC_RETRY_TOKEN_ADDRESS_MAX) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  /* A connection ID is 1..20 bytes (RFC 9000 section 17.2), and the length is what a server hands back as
   * `original_destination_connection_id`, so a length that cannot be one is refused here rather than sent. */
  if (original_length == 0U || original_length > WT_QUIC_MAX_CONNECTION_ID_LENGTH) {
    return WT_ERR_INVALID_ARGUMENT;
  }

  body_length = WT_QUIC_RETRY_TOKEN_OFFSET_ODCID + original_length;
  if (capacity < body_length + WT_QUIC_RETRY_TOKEN_TAG_LEN) return WT_ERR_LIMIT;
  if (body_length + WT_QUIC_RETRY_TOKEN_TAG_LEN > WT_QUIC_RETRY_TOKEN_MAX) return WT_ERR_LIMIT;

  token_body_header(body, now, address, address_length);
  body[WT_QUIC_RETRY_TOKEN_OFFSET_ODCID_LENGTH] = (uint8_t)original_length;
  memcpy(body + WT_QUIC_RETRY_TOKEN_OFFSET_ODCID, original_destination_id, original_length);

  status = token_tag(secret, body, body_length, tag);
  if (status != WT_OK) return status;
  memcpy(out, body, body_length);
  memcpy(out + body_length, tag, WT_QUIC_RETRY_TOKEN_TAG_LEN);
  if (out_length != NULL) *out_length = body_length + WT_QUIC_RETRY_TOKEN_TAG_LEN;
  return WT_OK;
}

wt_status_t wt_quic_retry_token_validate(const uint8_t secret[WT_QUIC_RETRY_TOKEN_SECRET_LEN],
                                         const uint8_t *address, size_t address_length, uint64_t now,
                                         uint64_t max_age, const uint8_t *token, size_t token_length,
                                         uint8_t *out_original, size_t capacity,
                                         size_t *out_original_length) {
  uint8_t expected[WT_QUIC_RETRY_TOKEN_TAG_LEN];
  uint8_t padded[WT_QUIC_RETRY_TOKEN_MAX];
  uint64_t issued_at;
  size_t original_length;
  size_t body_length;
  wt_status_t status;

  if (out_original_length != NULL) *out_original_length = 0U;
  if (secret == NULL || address == NULL || token == NULL || out_original == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (address_length == 0U || address_length > WT_QUIC_RETRY_TOKEN_ADDRESS_MAX) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  /* The shortest well-formed token has a one-byte original destination ID; anything shorter cannot be one, and a
   * length beyond the layout is not this server's either. Both are the TOKEN's fault, not the caller's -- the
   * caller passes the length it received, whatever it is -- so both are AUTHENTICATION. */
  if (token_length < WT_QUIC_RETRY_TOKEN_OFFSET_ODCID + 1U + WT_QUIC_RETRY_TOKEN_TAG_LEN ||
      token_length > WT_QUIC_RETRY_TOKEN_MAX) {
    return WT_ERR_AUTHENTICATION;
  }
  if (token[WT_QUIC_RETRY_TOKEN_OFFSET_FORMAT] != WT_QUIC_RETRY_TOKEN_FORMAT) return WT_ERR_AUTHENTICATION;

  original_length = token[WT_QUIC_RETRY_TOKEN_OFFSET_ODCID_LENGTH];
  if (original_length == 0U || original_length > WT_QUIC_MAX_CONNECTION_ID_LENGTH) {
    return WT_ERR_AUTHENTICATION;
  }
  body_length = WT_QUIC_RETRY_TOKEN_OFFSET_ODCID + original_length;
  if (body_length + WT_QUIC_RETRY_TOKEN_TAG_LEN != token_length) return WT_ERR_AUTHENTICATION;

  /* The tag FIRST, over the bytes as they arrived. The LENGTH had to be read to know how long the body is, which
   * is why it is bounded above before anything else happens -- but no other field is looked at until the tag has
   * authenticated the buffer, so a caller never acts on values read out of an attacker's bytes. */
  status = token_tag(secret, token, body_length, expected);
  if (status != WT_OK) return status;
  if (wt_ct_equal(expected, token + body_length, WT_QUIC_RETRY_TOKEN_TAG_LEN) == 0) {
    return WT_ERR_AUTHENTICATION;
  }

  /* The address, in the same padded form the tag covered: a token issued for one peer must not validate for
   * another, or a client could pass it to an accomplice and have that peer's packets attributed to it. */
  memcpy(padded, token, body_length);
  memset(padded + WT_QUIC_RETRY_TOKEN_OFFSET_ADDRESS, 0, WT_QUIC_RETRY_TOKEN_ADDRESS_MAX);
  memcpy(padded + WT_QUIC_RETRY_TOKEN_OFFSET_ADDRESS, address, address_length);
  if (memcmp(padded + WT_QUIC_RETRY_TOKEN_OFFSET_ADDRESS, token + WT_QUIC_RETRY_TOKEN_OFFSET_ADDRESS,
             WT_QUIC_RETRY_TOKEN_ADDRESS_MAX) != 0) {
    return WT_ERR_AUTHENTICATION;
  }

  issued_at = wt_load_be64(token + WT_QUIC_RETRY_TOKEN_OFFSET_TIME);
  if (max_age != 0U) {
    /* Unsigned arithmetic, and `now < issued_at` is not an error but IS expired: a token from the future is a
     * clock that moved or a clock that lied, and either way it is not one to spend state on. */
    if (now < issued_at || now - issued_at > max_age) return WT_ERR_STATE;
  }

  if (capacity < original_length) return WT_ERR_LIMIT;
  memcpy(out_original, token + WT_QUIC_RETRY_TOKEN_OFFSET_ODCID, original_length);
  if (out_original_length != NULL) *out_original_length = original_length;
  return WT_OK;
}
