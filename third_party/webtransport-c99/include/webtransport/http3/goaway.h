/* The HTTP/3 GOAWAY frame (RFC 9114 sections 7.2.6 and 5.2).
 *
 * GOAWAY is how an endpoint shuts a connection down gracefully: it says which
 * requests or pushes it has or might have processed, and everything at or above
 * the identifier it carries is rejected by its sender. Four rules matter to a
 * receiver, and section 5.2 is where three of them live:
 *
 *   - **The identifier means a stream ID one way and a push ID the other.** In
 *     the server-to-client direction it is a client-initiated bidirectional
 *     stream ID, and section 7.2.6 makes any other stream type H3_ID_ERROR.
 *   - **It never grows.** "the identifier in each frame MUST NOT be greater than
 *     the identifier in any previous frame ... Receiving a GOAWAY containing a
 *     larger identifier than previously received MUST be treated as a connection
 *     error of type H3_ID_ERROR" (section 5.2). This is what makes the frame
 *     usable: a client may already have retried the requests it was told were
 *     not processed.
 *   - **Requests at or above it are rejected**, and **no new requests or pushes
 *     may be started** once a GOAWAY has arrived.
 *   - **A graceful shutdown sends the maximum first** -- `2^62 - 4` for a server
 *     (the largest client-initiated bidirectional stream ID) and `2^62 - 1` for a
 *     client (the largest push ID) -- then a second GOAWAY with the last
 *     identifier it really processed, which the monotonic rule permits.
 *
 * The payload is exactly one varint: a payload with a second one or with trailing
 * bytes is a malformed frame, not a frame this endpoint reads partially, the same
 * rule the frame codec follows.
 */

#ifndef WEBTRANSPORT_HTTP3_GOAWAY_H
#define WEBTRANSPORT_HTTP3_GOAWAY_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/http3/frame.h"
#include "webtransport/http3/role.h"
#include "webtransport/status.h"
#include "webtransport/writer.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The largest identifier a server may name: the highest client-initiated
 * bidirectional stream ID, 4 * (2^60 - 1). */
#define WT_HTTP3_GOAWAY_SERVER_MAXIMUM ((uint64_t)0x3ffffffffffffffc)

/* The largest identifier a client may name: the highest push ID. */
#define WT_HTTP3_GOAWAY_CLIENT_MAXIMUM ((uint64_t)0x3fffffffffffffff)

/* What this endpoint has been told by the peer's GOAWAY frames. */
typedef struct wt_http3_goaway {
  /* A GOAWAY has arrived, so no new request or push may be started. */
  int received;
  /* The most recent identifier: the lowest one sent, because the rule forbids a
   * larger one later. */
  uint64_t identifier;
  /* Who sent it, which is what the identifier means. */
  wt_http3_role_t sender;
} wt_http3_goaway_t;

void wt_http3_goaway_init(wt_http3_goaway_t *goaway);

/* The identifier a graceful shutdown sends first, by the sender's role. */
uint64_t wt_http3_goaway_maximum_identifier(wt_http3_role_t sender);

/* Write the one-varint payload. */
wt_status_t wt_http3_goaway_encode_payload(wt_writer_t *w, uint64_t identifier);

/* Read the one-varint payload. A payload that is not exactly one varint is
 * H3_FRAME_ERROR. */
wt_status_t wt_http3_goaway_decode_payload(const uint8_t *payload, size_t length,
                                           uint64_t *out_identifier, wt_http3_error_t *out_error);

/* Record a received GOAWAY. Refuses a server's non-client-initiated-bidirectional
 * stream ID (H3_ID_ERROR, section 7.2.6) and an identifier larger than one
 * already received (H3_ID_ERROR, section 5.2). A lower identifier is accepted and
 * becomes the effective one. */
wt_status_t wt_http3_goaway_on_received(wt_http3_goaway_t *goaway, wt_http3_role_t sender,
                                        uint64_t identifier, wt_http3_error_t *out_error);

/* True when the identifier means the sender rejects this request stream. */
int wt_http3_goaway_rejects_stream(const wt_http3_goaway_t *goaway, uint64_t stream_id);

/* True while a new request (or push) may still be started. */
int wt_http3_goaway_allows_new_requests(const wt_http3_goaway_t *goaway);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_HTTP3_GOAWAY_H */
