/* TLS 1.3 key agreement. See webtransport/tls/keyshare.h.
 *
 * This is the one file besides crypto_openssl.c that includes an OpenSSL header: the
 * X25519 ladder is a curve implementation, and writing a second one here would mean two
 * implementations of the same arithmetic in one repository, one of them unaudited. What
 * this file owns is the part that is this project's: what a group is, what a key length
 * is, and which results are refused.
 */

#include "webtransport/tls/keyshare.h"

#include "webtransport/tls/extension.h"

#include <openssl/evp.h>

#include <string.h>

int wt_tls_key_share_supported(uint16_t group) {
  return group == WT_TLS_GROUP_X25519;
}

size_t wt_tls_key_share_key_len(uint16_t group) {
  return (group == WT_TLS_GROUP_X25519) ? WT_TLS_X25519_KEY_LEN : 0U;
}

/* Whether a secret is all zeroes. RFC 7748 section 6.1 suggests exactly this check --
 * ORing the bytes together -- because it does not branch on the value. */
static int all_zero(const uint8_t *bytes, size_t len) {
  uint8_t accumulator = 0U;
  size_t i;
  for (i = 0U; i < len; i++) accumulator = (uint8_t)(accumulator | bytes[i]);
  return accumulator == 0U;
}

/* The X25519 derivation, with both keys taken as raw bytes. OpenSSL treats a 32-byte
 * public key as any u-coordinate, which is what RFC 7748's X25519(k, u) is, and it
 * clamps the scalar itself: the private keys in RFC 7748's own vectors are unclamped,
 * and the RFC's outputs are what a clamped scalar produces. */
static wt_status_t x25519_derive(const uint8_t scalar[WT_TLS_X25519_KEY_LEN],
                                 const uint8_t u_coordinate[WT_TLS_X25519_KEY_LEN],
                                 uint8_t out[WT_TLS_X25519_KEY_LEN]) {
  EVP_PKEY *mine = NULL;
  EVP_PKEY *theirs = NULL;
  EVP_PKEY_CTX *ctx = NULL;
  size_t out_len = WT_TLS_X25519_KEY_LEN;
  wt_status_t status = WT_ERR_UNSUPPORTED;

  mine = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, scalar,
                                      WT_TLS_X25519_KEY_LEN);
  if (mine == NULL) goto done;
  theirs = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, u_coordinate,
                                       WT_TLS_X25519_KEY_LEN);
  if (theirs == NULL) goto done;
  ctx = EVP_PKEY_CTX_new(mine, NULL);
  if (ctx == NULL) {
    status = WT_ERR_OUT_OF_MEMORY;
    goto done;
  }
  if (EVP_PKEY_derive_init(ctx) != 1) goto done;
  if (EVP_PKEY_derive_set_peer(ctx, theirs) != 1) goto done;
  if (EVP_PKEY_derive(ctx, out, &out_len) != 1) {
    /* OpenSSL's X25519 refuses a peer key of small order by FAILING rather than by
     * returning the all-zero value RFC 7748 defines for it, and with both keys already
     * accepted that refusal is the only way a derivation fails here. It is the same
     * handshake failure as a zero secret (RFC 8446 section 7.4.2), so it is reported as
     * one -- the check below then covers a backend that returns zeroes instead. */
    status = WT_ERR_PROTOCOL;
    goto done;
  }
  status = (out_len == WT_TLS_X25519_KEY_LEN) ? WT_OK : WT_ERR_UNSUPPORTED;

done:
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(theirs);
  EVP_PKEY_free(mine);
  if (status != WT_OK) memset(out, 0, WT_TLS_X25519_KEY_LEN);
  return status;
}

wt_status_t wt_tls_x25519(const uint8_t scalar[WT_TLS_X25519_KEY_LEN],
                          const uint8_t u_coordinate[WT_TLS_X25519_KEY_LEN],
                          uint8_t out[WT_TLS_X25519_KEY_LEN]) {
  if (scalar == NULL || u_coordinate == NULL || out == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  return x25519_derive(scalar, u_coordinate, out);
}

wt_status_t wt_tls_key_share_public_key(
    uint16_t group, const uint8_t private_key[WT_TLS_X25519_KEY_LEN],
    uint8_t public_key[WT_TLS_X25519_KEY_LEN]) {
  static const uint8_t base_point[WT_TLS_X25519_KEY_LEN] = {9U};
  if (!wt_tls_key_share_supported(group)) return WT_ERR_UNSUPPORTED;
  if (private_key == NULL || public_key == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* The base point is 9 followed by thirty-one zero bytes, which is what RFC 7748
   * section 6.1 writes as X25519(a, 9). */
  return x25519_derive(private_key, base_point, public_key);
}

wt_status_t wt_tls_key_share_generate(uint16_t group,
                                      uint8_t private_key[WT_TLS_X25519_KEY_LEN],
                                      uint8_t public_key[WT_TLS_X25519_KEY_LEN]) {
  EVP_PKEY_CTX *ctx = NULL;
  EVP_PKEY *key = NULL;
  size_t private_len = WT_TLS_X25519_KEY_LEN;
  size_t public_len = WT_TLS_X25519_KEY_LEN;
  wt_status_t status = WT_ERR_UNSUPPORTED;

  if (!wt_tls_key_share_supported(group)) return WT_ERR_UNSUPPORTED;
  if (private_key == NULL || public_key == NULL) return WT_ERR_INVALID_ARGUMENT;

  /* OpenSSL's own key generation, rather than a random scalar written here: the
   * generator is the one thing in a key agreement that has to come from the platform's
   * entropy source, and this is where a portable implementation should have nothing of
   * its own to get wrong. */
  ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
  if (ctx == NULL) return WT_ERR_OUT_OF_MEMORY;
  if (EVP_PKEY_keygen_init(ctx) != 1) goto done;
  if (EVP_PKEY_keygen(ctx, &key) != 1) goto done;
  if (EVP_PKEY_get_raw_private_key(key, private_key, &private_len) != 1) goto done;
  if (EVP_PKEY_get_raw_public_key(key, public_key, &public_len) != 1) goto done;
  if (private_len != WT_TLS_X25519_KEY_LEN || public_len != WT_TLS_X25519_KEY_LEN) {
    goto done;
  }
  status = WT_OK;

done:
  EVP_PKEY_free(key);
  EVP_PKEY_CTX_free(ctx);
  if (status != WT_OK) {
    memset(private_key, 0, WT_TLS_X25519_KEY_LEN);
    memset(public_key, 0, WT_TLS_X25519_KEY_LEN);
  }
  return status;
}

wt_status_t wt_tls_key_share_shared_secret(
    uint16_t group, const uint8_t private_key[WT_TLS_X25519_KEY_LEN],
    const uint8_t *peer_public, size_t peer_public_len,
    uint8_t out[WT_TLS_X25519_KEY_LEN]) {
  wt_status_t status;

  if (!wt_tls_key_share_supported(group)) return WT_ERR_UNSUPPORTED;
  if (private_key == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (peer_public == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* A peer key of the wrong length is refused before the derivation rather than padded
   * or truncated: X25519 takes exactly 32 bytes, and a shorter one is a peer that
   * disagrees about the group. */
  if (peer_public_len != WT_TLS_X25519_KEY_LEN) return WT_ERR_INVALID_ARGUMENT;

  status = x25519_derive(private_key, peer_public, out);
  if (status != WT_OK) return status;
  if (all_zero(out, WT_TLS_X25519_KEY_LEN)) {
    /* RFC 8446 section 7.4.2: "If the peer's public key is a point of small order, the
     * shared secret is all zeroes and the endpoint MUST abort the handshake." */
    memset(out, 0, WT_TLS_X25519_KEY_LEN);
    return WT_ERR_PROTOCOL;
  }
  return WT_OK;
}
