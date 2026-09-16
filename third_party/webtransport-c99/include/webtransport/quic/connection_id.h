/* QUIC connection ID storage and retirement (RFC 9000 sections 5.1 and 10.2).
 *
 * An endpoint issues connection IDs so that a peer can migrate between addresses
 * without the connection breaking, and retires them so that an observer cannot
 * use an old one to inject packets. Three rules shape this:
 *
 *   - **The active limit is the peer's to set.** `active_connection_id_limit` is
 *     a transport parameter; an endpoint that issues more than the peer allows is
 *     in violation, and one that receives more than it advertised closes with
 *     CONNECTION_ID_LIMIT_ERROR (RFC 9000 section 5.1.1).
 *   - **`retire_prior_to` is a promise.** A NEW_CONNECTION_ID with a
 *     `retire_prior_to` means every ID below that sequence is retired, and a
 *     RETIRE_CONNECTION_ID for an ID the endpoint never issued is a
 *     PROTOCOL_VIOLATION (section 19.16).
 *   - **The sequence number is the identity, not the bytes.** Two IDs may compare
 *     equal by accident and still be different connection IDs, so everything here
 *     is keyed by sequence.
 *
 * The store is a fixed array. A peer chooses how many IDs it issues and the
 * limit is negotiated, so the array is sized to the largest limit this
 * implementation advertises and a peer that exceeds it is refused rather than
 * making this code allocate -- the same rule as every other parser here.
 */

#ifndef WEBTRANSPORT_QUIC_CONNECTION_ID_H
#define WEBTRANSPORT_QUIC_CONNECTION_ID_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/quic/error.h"
#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The largest connection ID RFC 9000 section 17.2 allows. */
#define WT_QUIC_MAX_CONNECTION_ID_LENGTH 20U

/* How many connection IDs this implementation is willing to hold at once. It is
 * also the value to advertise as `active_connection_id_limit`: RFC 9000 section
 * 18.2 requires at least 2, and the plan's rule is that every peer-controlled
 * table is bounded, so this is the bound and the advertisement is the same
 * number. */
#define WT_QUIC_CONNECTION_ID_LIMIT 8U

typedef struct wt_quic_connection_id {
  uint64_t sequence;
  uint8_t id[WT_QUIC_MAX_CONNECTION_ID_LENGTH];
  size_t id_len;
  int issued;      /* this endpoint issued it, so it can retire it */
  int retired;     /* retired and no longer usable */
} wt_quic_connection_id_t;

typedef struct wt_quic_connection_id_store {
  wt_quic_connection_id_t entries[WT_QUIC_CONNECTION_ID_LIMIT];
  size_t count;
  /* The lowest sequence not yet retired: RFC 9000 section 5.1.1 calls this the
   * "retire prior to" value, and it is monotonic. */
  uint64_t retire_prior_to;
  /* The highest sequence issued so far, plus one. */
  uint64_t next_sequence;
  /* How many IDs the peer allows this endpoint to issue, from its
   * `active_connection_id_limit`. */
  uint64_t peer_limit;
  /* How many this endpoint advertised and will hold. */
  uint64_t local_limit;
} wt_quic_connection_id_store_t;

/* An empty store. `peer_limit` is the peer's active_connection_id_limit and
 * `local_limit` is this endpoint's; both must be at least 2, which is what RFC
 * 9000 section 18.2 requires, and a smaller value is clamped up rather than
 * accepted. */
wt_status_t wt_quic_connection_ids_init(wt_quic_connection_id_store_t *store,
                                        uint64_t peer_limit,
                                        uint64_t local_limit);

/* Add an ID this endpoint issued, with the next sequence number. Refuses when
 * the peer's limit is already reached -- an endpoint "MUST NOT provide more
 * connection IDs than the peer's active_connection_id_limit", RFC 9000 section
 * 5.1.1 -- and when the store is full. */
wt_status_t wt_quic_connection_ids_add_issued(
    wt_quic_connection_id_store_t *store, const uint8_t *id, size_t id_len,
    uint64_t *out_sequence);

/* Record an ID the peer issued, from a NEW_CONNECTION_ID frame. `retire_prior_to`
 * retires every ID below it. Refuses an ID longer than twenty bytes, a
 * `retire_prior_to` above the sequence (which RFC 9000 section 19.15 makes a
 * FRAME_ENCODING_ERROR, and which the frame parser has already refused), more
 * IDs than this endpoint advertised, and a sequence already present.
 *
 * `out_error` is set to CONNECTION_ID_LIMIT_ERROR when the limit is what was
 * reached, which is the code RFC 9000 section 5.1.1 requires. */
wt_status_t wt_quic_connection_ids_add_peer(
    wt_quic_connection_id_store_t *store, uint64_t sequence,
    uint64_t retire_prior_to, const uint8_t *id, size_t id_len,
    wt_quic_error_t *out_error);

/* Retire one ID by sequence, as a RETIRE_CONNECTION_ID frame asks. Refuses a
 * sequence at or above `next_sequence`, which is an ID "that was not issued by
 * the endpoint" and therefore a PROTOCOL_VIOLATION (RFC 9000 section 19.16). */
wt_status_t wt_quic_connection_ids_retire(
    wt_quic_connection_id_store_t *store, uint64_t sequence,
    wt_quic_error_t *out_error);

/* Find an ID by its bytes, for the receive path: the ID a packet carries has to
 * be matched against the ones this endpoint issued. A retired ID still matches,
 * because a packet that arrives with one is a packet that has to be attributed
 * to the right connection before it can be refused -- the caller checks
 * `out_retired`. Returns WT_OK and writes the entry's index, or WT_ERR_CLOSED
 * when the bytes match no entry. */
wt_status_t wt_quic_connection_ids_find(
    const wt_quic_connection_id_store_t *store, const uint8_t *id, size_t id_len,
    size_t *out_index, int *out_retired);

/* How many IDs are usable: issued or peer-supplied, and not retired. */
size_t wt_quic_connection_ids_active(
    const wt_quic_connection_id_store_t *store);

/* The number of IDs this endpoint may still issue before the peer's limit is
 * reached. Zero means it must wait for a RETIRE_CONNECTION_ID. */
uint64_t wt_quic_connection_ids_issueable(
    const wt_quic_connection_id_store_t *store);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_QUIC_CONNECTION_ID_H */
