/* The server's half of a Retry: answer an Initial, then check the token that comes back (WT-168).
 *
 * A server that wants to validate a client's address before spending anything on it (RFC 9000 sections 8.1.2 and
 * 21.3) needs three things this repository now has in pieces: a token it can check later without keeping state
 * (`quic/retry_token.h`), a Retry packet whose integrity tag a client will accept (the packet codec and RFC 9001
 * section 5.8), and the transport parameters that name the Retry once the connection is established (the
 * `retry_source_connection_id` argument of `wt_quic_transport_parameters_build`). This is the flow that ties them
 * together, and it is a RUNTIME module rather than application code because every step of it is a protocol rule
 * rather than a policy: which Source Connection ID the rest of the connection must use, which original
 * destination connection ID the parameters must name, and which datagram is a Retry request at all.
 *
 * The two calls are deliberately separate, because they happen in different places on the wire: `build` is called
 * with the datagram a listener just peeked at, and `accept` with the one that arrives after the client has
 * answered. Between them the server keeps NOTHING about the client except the secret and the Source Connection ID
 * it chose -- which is what makes the retry an address validation rather than a state allocation.
 *
 * The Source Connection ID is FOUR things at once and they must not disagree: the Retry's Source Connection ID,
 * the `retry_source_connection_id` parameter, the `initial_source_connection_id` parameter, and the ID the
 * connection answers on. RFC 9000 section 7.2 makes the client adopt it and compare it, and a server that chose
 * another ID for the connection afterwards would be refused by a checking client -- so `source_id` here is the
 * one ID this flow hands to all four.
 */

#ifndef WEBTRANSPORT_RUNTIME_SERVER_RETRY_H
#define WEBTRANSPORT_RUNTIME_SERVER_RETRY_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/quic/retry_token.h"
#include "webtransport/runtime/udp.h"
#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The longest datagram this module is hand-built for: a Retry is a header, a token and a tag, and the bound is
 * here so a caller's buffer cannot be overrun by a token this server itself built (78 bytes) plus two connection
 * IDs. It is a fixed number rather than a growable buffer, like every other bound in this tree. */
#define WT_RUNTIME_SERVER_RETRY_MAX 256U

typedef struct wt_runtime_server_retry {
  uint8_t secret[WT_QUIC_RETRY_TOKEN_SECRET_LEN];
  /* The Source Connection ID of the Retry, and of everything after it (see the header). */
  uint8_t source_connection_id[WT_QUIC_MAX_CONNECTION_ID_LENGTH];
  size_t source_connection_id_length;
  /* How old an echoed token may be, in the units of the clock the caller passes. Zero disables the check, which
   * a caller that has no clock may want and a caller that has one should not. */
  uint64_t token_max_age;
  unsigned retries_sent;
  /* Tokens that came back and were not this server's for that peer: a count rather than a failure, because a
   * forged token is an ordinary event for a listener (section 8.1.4) and one that should leave a trace. */
  unsigned tokens_refused;
  int armed;
} wt_runtime_server_retry_t;

/* Arm: draw the secret and a fresh Source Connection ID. `connection_id_length` is the length this server uses
 * for its connection IDs -- the length must match the one its connection is configured with, because a short
 * header does not carry it (RFC 9000 section 17.2), and a Retry whose ID was another length would name a
 * connection the client's later packets could not be attributed to. Eight bytes is what the tools use. */
wt_status_t wt_runtime_server_retry_arm(wt_runtime_server_retry_t *retry, size_t connection_id_length,
                                        uint64_t token_max_age);

/* Read `datagram` and, if it is an Initial that carries NO token yet, write the Retry that answers it.
 *
 * `*out_is_retry` says which of the two ordinary outcomes this was: 1 with a datagram in `out`, or 0 with
 * nothing to send -- which is the case for a client that is already answering a Retry (its Initial carries the
 * token), for any packet that is not an Initial, and for a datagram this module cannot parse. A malformed
 * datagram is not an error here: a listener that refused to serve because somebody sent it junk would be a
 * listener anybody could stop, so the caller loops.
 *
 * WT_ERR_LIMIT when `capacity` cannot hold the Retry. */
wt_status_t wt_runtime_server_retry_build(wt_runtime_server_retry_t *retry, const uint8_t *datagram,
                                          size_t length, const wt_udp_address_t *peer, uint64_t now,
                                          uint8_t *out, size_t capacity, size_t *out_length,
                                          int *out_is_retry);

/* Check the token in `datagram`, which must be an Initial addressed to this retry's Source Connection ID, against
 * the address the packet actually came from.
 *
 * On success the ORIGINAL destination connection ID -- the one the client's first Initial carried, before the
 * Retry -- is copied out: that is the value the server's `original_destination_connection_id` transport parameter
 * must name (section 7.3), and the client compares it. `*out_accepted` is 0 for every other case (not an Initial,
 * no token, addressed elsewhere, not this server's token, too old) with a reason in the return value that a
 * caller can log but not act on: all of them mean the same thing, which is "answer with another Retry". */
wt_status_t wt_runtime_server_retry_accept(wt_runtime_server_retry_t *retry, const uint8_t *datagram,
                                           size_t length, const wt_udp_address_t *peer, uint64_t now,
                                           uint8_t *out_original, size_t capacity,
                                           size_t *out_original_length, int *out_accepted);

/* The Source Connection ID this retry chose, for the caller that has to configure its connection with it. */
const uint8_t *wt_runtime_server_retry_source_id(const wt_runtime_server_retry_t *retry, size_t *out_length);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_RUNTIME_SERVER_RETRY_H */
