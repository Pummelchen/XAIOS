/*
 * TLS 1.3 key agreement for the vendored WebTransport library (B-131).
 *
 * Upstream's `src/tls/keyshare.c` reaches X25519 through OpenSSL's
 * `EVP_PKEY_*`, which does not exist here. This file replaces it with the
 * ladder this repository already has -- `userspace/wt/src/wt_x25519.c`, the
 * same code the in-tree client uses and checks against RFC 7748's vectors --
 * and keeps upstream's shape: the group is X25519 or nothing, a peer key of
 * the wrong length is refused rather than padded, and a small-order peer is a
 * protocol failure rather than a secret.
 *
 * Key *generation* is the one thing that has to come from the platform, and
 * here that is `xaios_random`. The in-tree ladder clamps the scalar as RFC
 * 7748 requires, so the stored private key stays the raw unclamped bytes a
 * caller would export, exactly as OpenSSL's raw key is.
 *
 * `wt_tls_key_share_supported` and `wt_tls_key_share_key_len` have no caller
 * in the compiled set, but upstream declares them in the header this file
 * implements and a link that dropped them would be a link against a different
 * interface.
 */

#include "webtransport/tls/keyshare.h"

#include "webtransport/tls/extension.h"

#include "wt_crypto.h"

#include <string.h>

#include <xaios_user.h>

int wt_tls_key_share_supported(uint16_t group) {
  return group == WT_TLS_GROUP_X25519;
}

size_t wt_tls_key_share_key_len(uint16_t group) {
  return group == WT_TLS_GROUP_X25519 ? WT_TLS_X25519_KEY_LEN : 0U;
}

wt_status_t wt_tls_key_share_generate(uint16_t group,
                                      uint8_t private_key[WT_TLS_X25519_KEY_LEN],
                                      uint8_t public_key[WT_TLS_X25519_KEY_LEN]) {
  if (!wt_tls_key_share_supported(group)) return WT_ERR_UNSUPPORTED;
  if (private_key == NULL || public_key == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  /* A private key that is not unpredictable is not a private key, so a
     failure here is the whole operation failing rather than a retry with
     something weaker. */
  if (xaios_random(private_key, (u64)WT_TLS_X25519_KEY_LEN) != 0) {
    return WT_ERR_UNSUPPORTED;
  }
  if (wt_x25519_public_key(private_key, public_key) != 0) {
    memset(private_key, 0, WT_TLS_X25519_KEY_LEN);
    memset(public_key, 0, WT_TLS_X25519_KEY_LEN);
    return WT_ERR_UNSUPPORTED;
  }
  return WT_OK;
}

wt_status_t wt_tls_key_share_public_key(
    uint16_t group, const uint8_t private_key[WT_TLS_X25519_KEY_LEN],
    uint8_t public_key[WT_TLS_X25519_KEY_LEN]) {
  if (!wt_tls_key_share_supported(group)) return WT_ERR_UNSUPPORTED;
  if (private_key == NULL || public_key == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (wt_x25519_public_key(private_key, public_key) != 0) {
    return WT_ERR_UNSUPPORTED;
  }
  return WT_OK;
}

wt_status_t wt_tls_key_share_shared_secret(
    uint16_t group, const uint8_t private_key[WT_TLS_X25519_KEY_LEN],
    const uint8_t *peer_public, size_t peer_public_len,
    uint8_t out[WT_TLS_X25519_KEY_LEN]) {
  if (!wt_tls_key_share_supported(group)) return WT_ERR_UNSUPPORTED;
  if (private_key == NULL || peer_public == NULL || out == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  /* X25519 takes exactly 32 bytes, so anything else is a peer that disagrees
     about the group; padding it would be inventing a key. */
  if (peer_public_len != WT_TLS_X25519_KEY_LEN) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  /* The shared ladder already refuses the low-order point's all-zero result,
     which RFC 8446 section 7.4.2 requires the handshake to abort on. */
  if (wt_x25519_shared_secret(private_key, peer_public, out) != 0) {
    return WT_ERR_PROTOCOL;
  }
  return WT_OK;
}

wt_status_t wt_tls_x25519(const uint8_t scalar[WT_TLS_X25519_KEY_LEN],
                          const uint8_t u_coordinate[WT_TLS_X25519_KEY_LEN],
                          uint8_t out[WT_TLS_X25519_KEY_LEN]) {
  if (scalar == NULL || u_coordinate == NULL || out == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (wt_x25519_shared_secret(scalar, u_coordinate, out) != 0) {
    return WT_ERR_PROTOCOL;
  }
  return WT_OK;
}
