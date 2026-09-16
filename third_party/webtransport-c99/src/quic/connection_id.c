/* QUIC connection ID storage. See webtransport/quic/connection_id.h. */

#include "webtransport/quic/connection_id.h"

#include <string.h>

wt_status_t wt_quic_connection_ids_init(wt_quic_connection_id_store_t *store,
                                        uint64_t peer_limit,
                                        uint64_t local_limit) {
  if (store == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* RFC 9000 section 18.2: active_connection_id_limit is at least 2. A peer that
   * sent less has already been refused by the parameter check, so a value below
   * two here is this endpoint's own misconfiguration and is raised to the
   * minimum rather than accepted -- an endpoint that allowed itself only one
   * connection ID could not migrate at all. */
  memset(store, 0, sizeof(*store));
  store->peer_limit = (peer_limit < 2U) ? 2U : peer_limit;
  store->local_limit = (local_limit < 2U) ? 2U : local_limit;
  if (store->local_limit > WT_QUIC_CONNECTION_ID_LIMIT) {
    store->local_limit = WT_QUIC_CONNECTION_ID_LIMIT;
  }
  store->next_sequence = 0U;
  store->retire_prior_to = 0U;
  return WT_OK;
}

static wt_quic_connection_id_t *wt_quic_cid_find_sequence(
    wt_quic_connection_id_store_t *store, uint64_t sequence) {
  size_t i;
  for (i = 0U; i < store->count; i++) {
    if (store->entries[i].sequence == sequence) return &store->entries[i];
  }
  return NULL;
}

size_t wt_quic_connection_ids_active(
    const wt_quic_connection_id_store_t *store) {
  size_t i;
  size_t active = 0U;
  if (store == NULL) return 0U;
  for (i = 0U; i < store->count; i++) {
    if (!store->entries[i].retired) active++;
  }
  return active;
}

uint64_t wt_quic_connection_ids_issueable(
    const wt_quic_connection_id_store_t *store) {
  uint64_t issued = 0U;
  size_t i;
  if (store == NULL) return 0U;
  for (i = 0U; i < store->count; i++) {
    /* A retired ID frees a slot in the peer's limit: RFC 9000 section 5.1.1
     * counts the connection IDs an endpoint is currently providing. */
    if (store->entries[i].issued && !store->entries[i].retired) issued++;
  }
  if (issued >= store->peer_limit) return 0U;
  return store->peer_limit - issued;
}

wt_status_t wt_quic_connection_ids_add_issued(
    wt_quic_connection_id_store_t *store, const uint8_t *id, size_t id_len,
    uint64_t *out_sequence) {
  wt_quic_connection_id_t *entry;

  if (store == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (out_sequence != NULL) *out_sequence = 0U;
  if (id_len > WT_QUIC_MAX_CONNECTION_ID_LENGTH) return WT_ERR_INVALID_ARGUMENT;
  if (id_len != 0U && id == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (store->count >= WT_QUIC_CONNECTION_ID_LIMIT) return WT_ERR_LIMIT;
  /* The peer's limit is a ceiling on what this endpoint may provide, and going
   * over it is the endpoint's own violation, not the peer's. */
  if (wt_quic_connection_ids_issueable(store) == 0U) return WT_ERR_LIMIT;

  entry = &store->entries[store->count];
  memset(entry, 0, sizeof(*entry));
  entry->sequence = store->next_sequence;
  entry->issued = 1;
  entry->id_len = id_len;
  if (id_len != 0U) memcpy(entry->id, id, id_len);
  store->count++;
  store->next_sequence++;
  if (out_sequence != NULL) *out_sequence = entry->sequence;
  return WT_OK;
}

/* Retire every entry below `sequence` and move the store's threshold up. Called
 * for the `retire_prior_to` of a NEW_CONNECTION_ID, which is a promise that the
 * peer has already stopped using everything below it. */
static void wt_quic_cid_retire_below(wt_quic_connection_id_store_t *store,
                                     uint64_t sequence) {
  size_t i;
  if (sequence > store->retire_prior_to) store->retire_prior_to = sequence;
  for (i = 0U; i < store->count; i++) {
    if (store->entries[i].sequence < store->retire_prior_to) {
      store->entries[i].retired = 1;
    }
  }
}

wt_status_t wt_quic_connection_ids_add_peer(
    wt_quic_connection_id_store_t *store, uint64_t sequence,
    uint64_t retire_prior_to, const uint8_t *id, size_t id_len,
    wt_quic_error_t *out_error) {
  if (store == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (id_len > WT_QUIC_MAX_CONNECTION_ID_LENGTH) {
    if (out_error != NULL) *out_error = WT_QUIC_PROTOCOL_VIOLATION;
    return WT_ERR_PROTOCOL;
  }
  if (id_len != 0U && id == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* RFC 9000 section 19.15: a retire_prior_to above the sequence would retire
   * the ID the frame is issuing. The frame parser refuses this too; it is
   * repeated here because this function is also reachable from a caller that
   * built the fields itself. */
  if (retire_prior_to > sequence) {
    if (out_error != NULL) *out_error = WT_QUIC_FRAME_ENCODING_ERROR;
    return WT_ERR_PROTOCOL;
  }
  /* Retiring is applied first, so the limit below counts what is left. */
  wt_quic_cid_retire_below(store, retire_prior_to);

  if (wt_quic_cid_find_sequence(store, sequence) != NULL) {
    /* Already known. Retiring below the sequence may have just retired it, which
     * is legal and not a duplicate to report. */
    return WT_OK;
  }
  if (wt_quic_connection_ids_active(store) >= store->local_limit) {
    /* RFC 9000 section 5.1.1: receiving more connection IDs than were advertised
     * is a CONNECTION_ID_LIMIT_ERROR. */
    if (out_error != NULL) *out_error = WT_QUIC_CONNECTION_ID_LIMIT_ERROR;
    return WT_ERR_LIMIT;
  }
  if (store->count >= WT_QUIC_CONNECTION_ID_LIMIT) {
    if (out_error != NULL) *out_error = WT_QUIC_CONNECTION_ID_LIMIT_ERROR;
    return WT_ERR_LIMIT;
  }
  {
    wt_quic_connection_id_t *entry = &store->entries[store->count];
    memset(entry, 0, sizeof(*entry));
    entry->sequence = sequence;
    entry->issued = 0;
    entry->retired = 0;
    entry->id_len = id_len;
    if (id_len != 0U) memcpy(entry->id, id, id_len);
    store->count++;
  }
  return WT_OK;
}

wt_status_t wt_quic_connection_ids_retire(
    wt_quic_connection_id_store_t *store, uint64_t sequence,
    wt_quic_error_t *out_error) {
  wt_quic_connection_id_t *entry;
  if (store == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* RFC 9000 section 19.16: "An endpoint cannot send this frame if it was
   * provided with a zero-length connection ID ... Receiving a RETIRE_CONNECTION_ID
   * frame containing a sequence number greater than any previously sent to the
   * peer MUST be treated as a connection error of type PROTOCOL_VIOLATION." */
  if (sequence >= store->next_sequence) {
    if (out_error != NULL) *out_error = WT_QUIC_PROTOCOL_VIOLATION;
    return WT_ERR_PROTOCOL;
  }
  entry = wt_quic_cid_find_sequence(store, sequence);
  if (entry == NULL) {
    /* An ID this endpoint issued and then forgot, or one it never issued. The
     * sequence is below the one it has reached, so the peer is retiring
     * something legitimately; there is nothing to do. */
    return WT_OK;
  }
  entry->retired = 1;
  return WT_OK;
}

wt_status_t wt_quic_connection_ids_find(
    const wt_quic_connection_id_store_t *store, const uint8_t *id, size_t id_len,
    size_t *out_index, int *out_retired) {
  size_t i;
  if (store == NULL || out_index == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (id_len > WT_QUIC_MAX_CONNECTION_ID_LENGTH) return WT_ERR_INVALID_ARGUMENT;
  if (id_len != 0U && id == NULL) return WT_ERR_INVALID_ARGUMENT;
  for (i = 0U; i < store->count; i++) {
    if (store->entries[i].id_len != id_len) continue;
    if (id_len != 0U && memcmp(store->entries[i].id, id, id_len) != 0) continue;
    *out_index = i;
    if (out_retired != NULL) *out_retired = store->entries[i].retired;
    return WT_OK;
  }
  return WT_ERR_CLOSED;
}
