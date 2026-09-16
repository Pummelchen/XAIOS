/* TLS 1.3's key schedule and transcript. See webtransport/tls/keyschedule.h. */

#include "webtransport/tls/keyschedule.h"

#include <string.h>

/* RFC 8446 section 7.1's "0", a string of Hash.length zero bytes. It is the salt of
 * the Early Secret, the input keying material of the Master Secret, and the PSK of a
 * handshake that has none -- three uses of the same value, which is why it is one
 * constant here rather than three literals. */
static const uint8_t wt_tls13_zeros[WT_TLS13_SECRET_LEN];

/* ------------------------------------------------------------------- transcript */

wt_status_t wt_tls13_transcript_init(wt_tls13_transcript_t *transcript) {
  if (transcript == NULL) return WT_ERR_INVALID_ARGUMENT;
  memset(transcript, 0, sizeof(*transcript));
  return wt_sha256_init(&transcript->hash);
}

wt_status_t wt_tls13_transcript_append(wt_tls13_transcript_t *transcript,
                                       const uint8_t *message, size_t len) {
  size_t declared;
  wt_status_t status;

  if (transcript == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (message == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* HandshakeType (1) plus a three-octet length (RFC 8446 section 4). */
  if (len < 4U) return WT_ERR_TRUNCATED;
  declared = ((size_t)message[1] << 16) | ((size_t)message[2] << 8) |
             (size_t)message[3];
  if (declared != len - 4U) return WT_ERR_PROTOCOL;
  status = wt_sha256_update(&transcript->hash, message, len);
  if (status != WT_OK) return status;
  if (transcript->messages < (unsigned long)WT_TLS13_TRANSCRIPT_TYPES_MAX) {
    transcript->types[transcript->messages] = message[0];
  }
  transcript->messages++;
  return WT_OK;
}

wt_status_t wt_tls13_transcript_hash(const wt_tls13_transcript_t *transcript,
                                     uint8_t out[WT_TLS13_SECRET_LEN]) {
  if (transcript == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* A copy of the hash state, not its finalisation: the transcript is read at
   * several points and must survive all of them. */
  return wt_sha256_snapshot(&transcript->hash, out);
}

void wt_tls13_transcript_clear(wt_tls13_transcript_t *transcript) {
  uint8_t discarded[WT_SHA256_LEN];
  if (transcript == NULL) return;
  /* Finalising is what releases the backend's hash context; a bare memset would
   * leave it allocated. The digest is not wanted, only the release. */
  (void)wt_sha256_final(&transcript->hash, discarded);
  wt_secure_zero(discarded, sizeof(discarded));
  wt_secure_zero(transcript, sizeof(*transcript));
}

/* -------------------------------------------------------------- the extract chain */

wt_status_t wt_tls13_early_secret(const uint8_t *psk, size_t psk_len,
                                  uint8_t out[WT_TLS13_SECRET_LEN]) {
  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (psk == NULL && psk_len != 0U) return WT_ERR_INVALID_ARGUMENT;
  /* No pre-shared key: RFC 8446 section 7.1 makes the input keying material a string
   * of Hash.length zero bytes. An empty IKM would be a different HMAC key and
   * therefore a different Early Secret, and RFC 8448's trace is what says which of
   * the two the schedule uses. */
  if (psk_len == 0U) {
    return wt_hkdf_extract_sha256(wt_tls13_zeros, sizeof(wt_tls13_zeros),
                                  wt_tls13_zeros, sizeof(wt_tls13_zeros), out);
  }
  return wt_hkdf_extract_sha256(wt_tls13_zeros, sizeof(wt_tls13_zeros), psk, psk_len,
                                out);
}

wt_status_t wt_tls13_handshake_secret(
    const uint8_t early_secret[WT_TLS13_SECRET_LEN], const uint8_t *ecdhe,
    size_t ecdhe_len, uint8_t out[WT_TLS13_SECRET_LEN]) {
  uint8_t derived[WT_TLS13_SECRET_LEN];
  wt_status_t status;
  size_t index;
  int all_zero = 1;

  if (early_secret == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (ecdhe == NULL || ecdhe_len == 0U) return WT_ERR_INVALID_ARGUMENT;
  for (index = 0U; index < ecdhe_len; index++) {
    if (ecdhe[index] != 0U) {
      all_zero = 0;
      break;
    }
  }
  if (all_zero) return WT_ERR_PROTOCOL;

  status = wt_tls13_derived(early_secret, derived);
  if (status != WT_OK) return status;
  status = wt_hkdf_extract_sha256(derived, sizeof(derived), ecdhe, ecdhe_len, out);
  wt_secure_zero(derived, sizeof(derived));
  return status;
}

wt_status_t wt_tls13_master_secret(
    const uint8_t handshake_secret[WT_TLS13_SECRET_LEN],
    uint8_t out[WT_TLS13_SECRET_LEN]) {
  uint8_t derived[WT_TLS13_SECRET_LEN];
  wt_status_t status;

  if (handshake_secret == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  status = wt_tls13_derived(handshake_secret, derived);
  if (status != WT_OK) return status;
  status = wt_hkdf_extract_sha256(derived, sizeof(derived), wt_tls13_zeros,
                                  sizeof(wt_tls13_zeros), out);
  wt_secure_zero(derived, sizeof(derived));
  return status;
}

/* ------------------------------------------------------------------ derivations */

wt_status_t wt_tls13_derive_secret(const uint8_t secret[WT_TLS13_SECRET_LEN],
                                   const char *label,
                                   const uint8_t transcript_hash[WT_TLS13_SECRET_LEN],
                                   uint8_t out[WT_TLS13_SECRET_LEN]) {
  if (secret == NULL || label == NULL || transcript_hash == NULL || out == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  return wt_hkdf_expand_label_sha256(secret, WT_TLS13_SECRET_LEN, label,
                                     transcript_hash, WT_TLS13_SECRET_LEN, out,
                                     WT_TLS13_SECRET_LEN);
}

wt_status_t wt_tls13_derived(const uint8_t secret[WT_TLS13_SECRET_LEN],
                             uint8_t out[WT_TLS13_SECRET_LEN]) {
  uint8_t empty_transcript[WT_TLS13_SECRET_LEN];
  wt_status_t status;

  if (secret == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* Derive-Secret with no messages means the hash of the empty string, which is not
   * the same as an empty context: the context is length-prefixed into the expansion
   * either way, so the two differ. */
  status = wt_sha256("", 0U, empty_transcript);
  if (status != WT_OK) return status;
  status = wt_tls13_derive_secret(secret, "derived", empty_transcript, out);
  wt_secure_zero(empty_transcript, sizeof(empty_transcript));
  return status;
}

wt_status_t wt_tls13_handshake_traffic_secrets(
    const uint8_t handshake_secret[WT_TLS13_SECRET_LEN],
    const uint8_t transcript_hash[WT_TLS13_SECRET_LEN],
    uint8_t client_out[WT_TLS13_SECRET_LEN],
    uint8_t server_out[WT_TLS13_SECRET_LEN]) {
  wt_status_t status;
  if (client_out == NULL || server_out == NULL) return WT_ERR_INVALID_ARGUMENT;
  status = wt_tls13_derive_secret(handshake_secret, "c hs traffic", transcript_hash,
                                  client_out);
  if (status != WT_OK) return status;
  status = wt_tls13_derive_secret(handshake_secret, "s hs traffic", transcript_hash,
                                  server_out);
  if (status != WT_OK) {
    /* A half-derived pair would be a connection whose two directions disagree about
     * which secret they came from. */
    wt_secure_zero(client_out, WT_TLS13_SECRET_LEN);
    return status;
  }
  return WT_OK;
}

wt_status_t wt_tls13_application_traffic_secrets(
    const uint8_t master_secret[WT_TLS13_SECRET_LEN],
    const uint8_t transcript_hash[WT_TLS13_SECRET_LEN],
    uint8_t client_out[WT_TLS13_SECRET_LEN],
    uint8_t server_out[WT_TLS13_SECRET_LEN]) {
  wt_status_t status;
  if (client_out == NULL || server_out == NULL) return WT_ERR_INVALID_ARGUMENT;
  status = wt_tls13_derive_secret(master_secret, "c ap traffic", transcript_hash,
                                  client_out);
  if (status != WT_OK) return status;
  status = wt_tls13_derive_secret(master_secret, "s ap traffic", transcript_hash,
                                  server_out);
  if (status != WT_OK) {
    wt_secure_zero(client_out, WT_TLS13_SECRET_LEN);
    return status;
  }
  return WT_OK;
}

wt_status_t wt_tls13_exporter_master_secret(
    const uint8_t master_secret[WT_TLS13_SECRET_LEN],
    const uint8_t transcript_hash[WT_TLS13_SECRET_LEN],
    uint8_t out[WT_TLS13_SECRET_LEN]) {
  return wt_tls13_derive_secret(master_secret, "exp master", transcript_hash, out);
}

wt_status_t wt_tls13_resumption_master_secret(
    const uint8_t master_secret[WT_TLS13_SECRET_LEN],
    const uint8_t transcript_hash[WT_TLS13_SECRET_LEN],
    uint8_t out[WT_TLS13_SECRET_LEN]) {
  return wt_tls13_derive_secret(master_secret, "res master", transcript_hash, out);
}

wt_status_t wt_tls13_next_traffic_secret(const uint8_t secret[WT_TLS13_SECRET_LEN],
                                         uint8_t out[WT_TLS13_SECRET_LEN]) {
  if (secret == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  return wt_hkdf_expand_label_sha256(secret, WT_TLS13_SECRET_LEN, "traffic upd",
                                     NULL, 0U, out, WT_TLS13_SECRET_LEN);
}

wt_status_t wt_tls13_traffic_keys(const uint8_t secret[WT_TLS13_SECRET_LEN],
                                  uint8_t key[WT_TLS13_KEY_LEN],
                                  uint8_t iv[WT_TLS13_IV_LEN]) {
  wt_status_t status;

  if (secret == NULL || key == NULL || iv == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  status = wt_hkdf_expand_label_sha256(secret, WT_TLS13_SECRET_LEN, "key", NULL, 0U,
                                       key, WT_TLS13_KEY_LEN);
  if (status != WT_OK) return status;
  status = wt_hkdf_expand_label_sha256(secret, WT_TLS13_SECRET_LEN, "iv", NULL, 0U,
                                       iv, WT_TLS13_IV_LEN);
  if (status != WT_OK) {
    wt_secure_zero(key, WT_TLS13_KEY_LEN);
    return status;
  }
  return WT_OK;
}

/* --------------------------------------------------------------------- Finished */

wt_status_t wt_tls13_finished_key(const uint8_t base_key[WT_TLS13_SECRET_LEN],
                                  uint8_t out[WT_TLS13_FINISHED_LEN]) {
  if (base_key == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  return wt_hkdf_expand_label_sha256(base_key, WT_TLS13_SECRET_LEN, "finished", NULL,
                                     0U, out, WT_TLS13_FINISHED_LEN);
}

wt_status_t wt_tls13_finished_verify_data(
    const uint8_t base_key[WT_TLS13_SECRET_LEN],
    const uint8_t transcript_hash[WT_TLS13_SECRET_LEN],
    uint8_t out[WT_TLS13_FINISHED_LEN]) {
  uint8_t key[WT_TLS13_FINISHED_LEN];
  wt_status_t status;

  if (transcript_hash == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  status = wt_tls13_finished_key(base_key, key);
  if (status != WT_OK) return status;
  status = wt_hmac_sha256(key, sizeof(key), transcript_hash, WT_TLS13_SECRET_LEN, out);
  wt_secure_zero(key, sizeof(key));
  return status;
}

wt_status_t wt_tls13_finished_check(
    const uint8_t base_key[WT_TLS13_SECRET_LEN],
    const uint8_t transcript_hash[WT_TLS13_SECRET_LEN],
    const uint8_t *verify_data, size_t verify_data_len) {
  uint8_t expected[WT_TLS13_FINISHED_LEN];
  wt_status_t status;
  int equal;

  if (verify_data == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* A length that is not Hash.length is refused rather than compared over whatever
   * it is: comparing the first byte of a one-byte Finished would be a forgery, not a
   * verification. */
  if (verify_data_len != WT_TLS13_FINISHED_LEN) return WT_ERR_INVALID_ARGUMENT;
  status = wt_tls13_finished_verify_data(base_key, transcript_hash, expected);
  if (status != WT_OK) return status;
  equal = wt_ct_equal(expected, verify_data, WT_TLS13_FINISHED_LEN);
  wt_secure_zero(expected, sizeof(expected));
  return equal ? WT_OK : WT_ERR_AUTHENTICATION;
}
