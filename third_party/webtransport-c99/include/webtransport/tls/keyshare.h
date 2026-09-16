/* TLS 1.3 key agreement: X25519 (RFC 7748, RFC 8446 section 7.4).
 *
 * ONE GROUP, AND THE OFFER IS NARROWER THAN THE SUPPORT. X25519 is the only group this
 * implementation can complete a handshake with, so it is the only one it sends a key
 * share for and the only one a client should advertise in supported_groups. Advertising
 * a group without a share invites a HelloRetryRequest asking for it, and this
 * implementation refuses HelloRetryRequest rather than handling it: a client that
 * offered a group it cannot complete would be arranging its own failure. The read side
 * accepts a key share for X25519 and refuses anything else by name.
 *
 * THE ALL-ZERO SHARED SECRET IS REFUSED HERE, AT THE POINT IT IS COMPUTED. RFC 7748
 * section 6.1 and RFC 8446 section 7.4.2 both make it a handshake failure: it is what a
 * peer produces by sending a point of small order, and an endpoint that derived keys
 * from it would be agreeing with a peer that never held a private key. The key schedule
 * refuses it a second time (`wt_tls13_handshake_secret`), which is deliberate: this is
 * the layer that knows the secret came from a peer's bytes, and that is the layer that
 * should not hand it on.
 */

#ifndef WEBTRANSPORT_TLS_KEY_SHARE_H
#define WEBTRANSPORT_TLS_KEY_SHARE_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/status.h"
/* For the named groups. They are the same identifiers in `supported_groups` and in
 * `key_share` (RFC 8446 section 4.2.7), so they are defined once, in the extension
 * header, and the group arguments here are those constants rather than bare numbers. */
#include "webtransport/tls/extension.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The length of an X25519 private key, public key and shared secret. */
#define WT_TLS_X25519_KEY_LEN 32U

/* Whether this implementation can complete a handshake with a group. */
int wt_tls_key_share_supported(uint16_t group);

/* The key length a group's shares use, or 0 for a group that is not supported. */
size_t wt_tls_key_share_key_len(uint16_t group);

/* RFC 7748 section 5's X25519(k, u): the scalar-multiplied u-coordinate.
 *
 * WT_ERR_PROTOCOL for an input whose result is the all-zero value. RFC 7748 defines
 * X25519 to return zero for a point of small order, and RFC 8446 section 7.4.2 makes
 * that a handshake failure rather than a key, so this returns the failure instead of the
 * zeroes: a primitive that handed them back would put the decision on every caller.
 * RFC 7748's own vectors, including the ones whose u-coordinate is not the base point,
 * are what check the arithmetic. */

wt_status_t wt_tls_x25519(const uint8_t scalar[WT_TLS_X25519_KEY_LEN],
                          const uint8_t u_coordinate[WT_TLS_X25519_KEY_LEN],
                          uint8_t out[WT_TLS_X25519_KEY_LEN]);

/* Generate a key pair for a group, from the system's random source. */
wt_status_t wt_tls_key_share_generate(uint16_t group,
                                      uint8_t private_key[WT_TLS_X25519_KEY_LEN],
                                      uint8_t public_key[WT_TLS_X25519_KEY_LEN]);

/* The public key a private key produces. RFC 7748 section 6.1 calls this X25519(a, 9),
 * and it is what a test needs to check a private key against a published public key. */
wt_status_t wt_tls_key_share_public_key(
    uint16_t group, const uint8_t private_key[WT_TLS_X25519_KEY_LEN],
    uint8_t public_key[WT_TLS_X25519_KEY_LEN]);

/* The shared secret from our private key and a peer's public key.
 *
 * WT_ERR_UNSUPPORTED for a group this implementation cannot complete;
 * WT_ERR_INVALID_ARGUMENT for a peer key whose length is not the group's;
 * WT_ERR_PROTOCOL for an all-zero secret, which is a handshake failure and not a
 * usable key. On failure nothing is written to `out`. */
wt_status_t wt_tls_key_share_shared_secret(
    uint16_t group, const uint8_t private_key[WT_TLS_X25519_KEY_LEN],
    const uint8_t *peer_public, size_t peer_public_len,
    uint8_t out[WT_TLS_X25519_KEY_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_TLS_KEY_SHARE_H */
