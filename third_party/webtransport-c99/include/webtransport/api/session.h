/* The public session handle (Phase 8).
 *
 * This is the first header of the consumer-facing API, and it is deliberately thin: it
 * owns a draft-16 session's state and its error, and everything else -- the connection,
 * the streams, the datagrams -- arrives in later parts. What it establishes is the SHAPE
 * the rest of the API follows:
 *
 *   - the type is opaque. A consumer holds `wt_session_t *` and cannot see inside it, so
 *     the layout can change between releases without breaking source or binary;
 *   - construction and destruction are explicit and paired, and both take the ALLOCATOR
 *     the object was made with, so a session created with a pool returns to that pool;
 *   - the error surface is sanitized. `wt_session_last_error` reports a stable status
 *     NAME and, when the peer named a code, that code -- never a peer's text and never a
 *     framework's. A reason string this endpoint sends is the caller's; nothing a peer
 *     sent is ever quoted back.
 *
 * Nothing here allocates for a peer: the capsule bound in the configuration is the largest
 * capsule value this session will look at, and a peer that sends more is refused with a
 * status that says the bound was reached.
 */

#ifndef WEBTRANSPORT_API_SESSION_H
#define WEBTRANSPORT_API_SESSION_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/allocator.h"
#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The session's state, as a consumer sees it. The names match the draft's phases rather
 * than this implementation's internals, so a caller reads them without a header of ours
 * in hand. */
/* The longest authority or path a session handle copies, so a caller can bound its own
 * strings without reading a private header. A longer one is refused, never truncated: a
 * truncated authority names a different session. */
#define WT_SESSION_AUTHORITY_MAX 128U

/* A QUIC DATAGRAM frame cannot carry more than this, and the quarter stream ID travels
 * inside it, so it is the ceiling a datagram bound may ask for. */
#define WT_SESSION_DATAGRAM_MAX 65535U

typedef enum wt_session_state {
  WT_SESSION_ESTABLISHING = 0,
  WT_SESSION_ESTABLISHED = 1,
  WT_SESSION_DRAINING = 2,
  WT_SESSION_CLOSED = 3
} wt_session_state_t;

/* What the last operation left behind, in a form safe to log or show: a status name that
 * is this library's, and the application error code when there was one. */
typedef struct wt_session_error {
  wt_status_t status;
  /* The peer's or the draft's application error code, or zero when the failure had
   * none. Never a string. */
  uint64_t code;
} wt_session_error_t;

typedef struct wt_session_config {
  /* The authority and path this session was created for. Copied into the session, so
   * the caller's strings may go out of scope. */
  const char *authority;
  const char *path;
  /* The CONNECT stream ID this session lives on. A datagram's quarter stream ID and a
   * WebTransport stream's prefix are both checked against it, which is what keeps two
   * sessions on one connection from delivering each other's traffic. */
  uint64_t session_id;
  /* The largest capsule value this session will look at. A peer-controlled length above
   * it is refused rather than buffered. */
  size_t max_capsule_bytes;
  /* The largest datagram payload this session will deliver. Zero means the ceiling of
   * 65535 bytes the draft's own datagram bound implies -- a QUIC DATAGRAM frame cannot
   * carry more -- and a value above that ceiling is refused at create. */
  size_t max_datagram_bytes;
  /* How many peer streams may be open at once. Zero means `WT_SESSION_STREAM_MAX` from
   * `api/events.h`; a value above it is refused at create, because the table is fixed. */
  size_t max_streams;
} wt_session_config_t;

/* A configuration with every bound at its default and no authority, path or session ID:
 * a caller fills in the three required fields and changes only the bounds it cares about.
 * Returning the whole struct by value is deliberate -- a C caller that forgets a field
 * would otherwise pass whatever its stack held into a bound, which is exactly the class of
 * bug a bound exists to stop. */
wt_session_config_t wt_session_config_default(void);

typedef struct wt_session wt_session_t;

/* Create a session. `allocator` may be NULL for the default one; the handle must be
 * destroyed with the SAME allocator, which is why `wt_session_destroy` takes it too. */
wt_status_t wt_session_create(const wt_session_config_t *config, const wt_allocator_t *allocator,
                              wt_session_t **out);

void wt_session_destroy(wt_session_t *session, const wt_allocator_t *allocator);

wt_session_state_t wt_session_state(const wt_session_t *session);

/* The CONNECT stream ID this session was created for. */
uint64_t wt_session_id(const wt_session_t *session);

wt_session_error_t wt_session_last_error(const wt_session_t *session);

/* The response went out: the session may carry streams and datagrams. */
wt_status_t wt_session_established(wt_session_t *session);

/* Handle one capsule from the CONNECT stream: a drain or a close is applied to the
 * session, and anything else is accepted and left to a layer that understands it. */
wt_status_t wt_session_on_capsule(wt_session_t *session, const uint8_t *bytes, size_t length);

/* Write the capsule that goes with a transition. The reason is the CALLER's text and is
 * bounded by the draft's ceiling. */
wt_status_t wt_session_write_drain(wt_session_t *session, uint8_t *out, size_t capacity,
                                   size_t *out_length);
wt_status_t wt_session_write_close(wt_session_t *session, uint32_t error_code, const char *reason,
                                   uint8_t *out, size_t capacity, size_t *out_length);

/* A stable name for a status, for a log line or a message that must not carry peer text. */
const char *wt_session_status_name(wt_status_t status);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_API_SESSION_H */
