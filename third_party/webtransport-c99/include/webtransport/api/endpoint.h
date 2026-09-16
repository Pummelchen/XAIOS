/* The endpoint configuration (Phase 8).
 *
 * A session is not created in a vacuum: something has to say which side of the connection
 * this program is, what name the peer's certificate must be valid for, and how that
 * certificate is judged. That is this header. It exists separately from `api/session.h`
 * because it answers a different question -- a session is per-connection-stream, an
 * endpoint is per-program -- and because it is the one place where a misconfiguration is
 * cheap to catch: a wrong trust mode should be a return value here, not a handshake
 * failure twenty seconds later.
 *
 * The rule that shapes the trust surface is the one the TLS layer already enforces: A
 * DEVELOPMENT BYPASS IS TIED TO A LOOPBACK NAME. `WT_TLS_TRUST_LOCAL_DEVELOPMENT` is
 * refused for any host name that is not loopback, and that check is done here as well as
 * at the handshake, using the same function, so a caller that reached for the bypass
 * against a real endpoint is told before a packet is sent. It is not a warning and not a
 * flag to turn off.
 */

#ifndef WEBTRANSPORT_API_ENDPOINT_H
#define WEBTRANSPORT_API_ENDPOINT_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/api/session.h"
#include "webtransport/status.h"
#include "webtransport/tls/trust.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Which side of the connection this program is. There is deliberately no zero value: a
 * caller must say, because the two sides need different things and a default would hide
 * which one it got. */
typedef enum wt_endpoint_role {
  WT_ENDPOINT_ROLE_CLIENT = 1,
  WT_ENDPOINT_ROLE_SERVER = 2
} wt_endpoint_role_t;

typedef struct wt_endpoint_config {
  wt_endpoint_role_t role;

  /* The name the endpoint is reached at, and -- for a client -- the name the peer's
   * certificate must be valid for. A server uses it to build the authority when the
   * configuration does not name one. */
  const char *host;

  /* The port. A client must name one; a server may say 0, which leaves the choice to the
   * system and is what a test that binds an ephemeral port wants. */
  uint16_t port;

  /* What the CONNECT request carries. A NULL authority means `host`, and a NULL path
   * means "/", so the common case needs neither spelled out. */
  const char *authority;
  const char *path;

  /* How a CLIENT judges the peer's chain. A SERVER must leave this unset (mode 0): this
   * draft has no client authentication, so a server has no peer certificate to judge, and
   * accepting a policy here would suggest otherwise. */
  wt_tls_trust_policy_t trust;
} wt_endpoint_config_t;

/* A configuration with nothing chosen: no role, no host, no port, path "/" and no trust
 * policy. Every bound of the sessions built from it is at its default. */
wt_endpoint_config_t wt_endpoint_config_default(void);

/* Check the configuration against the rules this library enforces, so a caller finds a
 * misconfiguration here rather than at the first handshake. Reports WT_ERR_INVALID_ARGUMENT
 * for a missing or impossible field, WT_ERR_TRUST for a trust mode used outside what it
 * allows -- including the development bypass against a non-loopback name -- and WT_ERR_LIMIT
 * for a value over a bound. Does not resolve names or touch the network. */
wt_status_t wt_endpoint_config_check(const wt_endpoint_config_t *config);

/* The session configuration for a CONNECT stream on this endpoint. The endpoint's authority
 * and path are copied, the session's bounds are the defaults, and the configuration is
 * checked first: an endpoint that does not pass `wt_endpoint_config_check` produces no
 * session configuration rather than a half-filled one. The result points at THIS endpoint's
 * strings, so it is valid while the endpoint is; `wt_session_create` copies them into the
 * handle, which is where they need to survive. */
wt_status_t wt_endpoint_session_config(const wt_endpoint_config_t *config, uint64_t session_id,
                                       wt_session_config_t *out);

/* A name for a role, for a log line or a usage message. */
const char *wt_endpoint_role_name(wt_endpoint_role_t role);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_API_ENDPOINT_H */
