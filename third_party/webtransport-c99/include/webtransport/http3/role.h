/* Which end of an HTTP/3 connection this is.
 *
 * Several of HTTP/3's rules are one-directional -- only a server sends a
 * PUSH_PROMISE, only a client sends a MAX_PUSH_ID, a GOAWAY's identifier means a
 * stream ID one way and a push ID the other -- so the layer that owns those rules
 * needs to know the role. Kept in its own header because a role is not a frame
 * property and every later part of the HTTP/3 core needs it.
 */

#ifndef WEBTRANSPORT_HTTP3_ROLE_H
#define WEBTRANSPORT_HTTP3_ROLE_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum wt_http3_role {
  WT_HTTP3_ROLE_CLIENT = 0,
  WT_HTTP3_ROLE_SERVER = 1
} wt_http3_role_t;

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_HTTP3_ROLE_H */
