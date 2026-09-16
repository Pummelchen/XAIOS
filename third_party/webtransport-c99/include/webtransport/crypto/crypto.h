/* WebTransport C99: the cryptographic primitives, and the seam to the backend.
 *
 * Every algorithm the protocol needs is named here and nothing above this header
 * calls a crypto library directly. QUIC packet protection, the TLS key schedule
 * and the QPACK decoder all sit on these functions, so a change of backend is a
 * change of one file rather than a change of the protocol code -- which is what
 * makes the protocol code testable against published vectors at all.
 *
 * THE BACKEND IS CHOSEN AT BUILD TIME, not at run time. The plan names OpenSSL
 * 3.x as the production dependency for the portable platforms, and a freestanding
 * target (XAIOS) would need BearSSL instead; those two never appear in one
 * binary, because a library that links two implementations of AES is a library
 * whose behaviour depends on which one a call reached. `WEBTRANSPORT_C99_CRYPTO`
 * selects it, and the public API below is the same either way.
 *
 * WHAT IS DELIBERATELY NOT HERE: no TLS, no X.509, no record layer, and no
 * protocol state. This is arithmetic over byte strings. Everything that decides
 * anything lives above it, which is why this file can be checked against NIST and
 * RFC vectors without a peer.
 *
 * DECRYPT RETURNS THE TAG IT COMPUTED AND DOES NOT COMPARE IT. That is a
 * deliberate shape, and it is the one that has already caught a defect in this
 * project's sibling implementation: a function that decrypts and then checks has
 * to either write plaintext before it knows whether the plaintext is authentic,
 * or check a tag it has not computed yet. Handing the tag back makes the order
 * explicit, and the caller compares it with `wt_ct_equal` -- in constant time,
 * because a comparison that stops at the first difference is a forgery oracle --
 * and clears the plaintext when it differs. A caller that ignores the tag has
 * written a bug this API documents rather than hides.
 */

#ifndef WEBTRANSPORT_CRYPTO_CRYPTO_H
#define WEBTRANSPORT_CRYPTO_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SHA-256, the only hash this library uses: TLS_AES_128_GCM_SHA256 is the
 * mandatory QUIC suite (RFC 9001 section 5.1) and the only one whose key
 * schedule this implementation carries. A second hash would double the schedule
 * and the transcript for a suite nothing requires. */
#define WT_SHA256_LEN 32U
/* The largest hash this library may ever need, for a buffer that has to hold
 * SHA-512's output if a suite that uses it is added. */
#define WT_MAX_HASH_LEN 64U

/* Streaming SHA-256.
 *
 * The context is an opaque byte array with a published size, not a pointer: the
 * transcript hash is embedded in the TLS handshake state and a two-phase
 * create/destroy would put an allocation and a failure path on every handshake.
 * The size is asserted against the backend's own structure in the backend's
 * source, so a backend whose context outgrows it fails its own build rather than
 * a caller's frame. */
#define WT_SHA256_CTX_MAX 256U
typedef struct wt_sha256_ctx {
  /* Aligned so that the backend may place its own structure here, which is why
   * this is not a plain byte array. */
  uint64_t storage[(WT_SHA256_CTX_MAX + 7U) / 8U];
} wt_sha256_ctx_t;

/* `wt_sha256_init` must be called before update or final. `final` leaves the
 * context unusable and zeroes its state. */
wt_status_t wt_sha256_init(wt_sha256_ctx_t *ctx);
wt_status_t wt_sha256_update(wt_sha256_ctx_t *ctx, const void *data, size_t len);
wt_status_t wt_sha256_final(wt_sha256_ctx_t *ctx, uint8_t out[WT_SHA256_LEN]);

/* One-shot, for a value that is hashed once and not transcribed. */
wt_status_t wt_sha256(const void *data, size_t len, uint8_t out[WT_SHA256_LEN]);

/* The hash of everything absorbed so far, leaving the context usable.
 *
 * A handshake takes the transcript hash at several points -- after the
 * ServerHello, after the server's Finished, after the client's -- and each one is
 * over everything absorbed up to that moment. Consuming the context to read it
 * would end the transcript, and keeping the absorbed messages to re-hash them later
 * would hold a peer-controlled amount of memory for the length of a handshake, so
 * neither is what this does: the backend is asked for a copy of its own state.
 *
 * Returns WT_ERR_STATE for a context that was never initialised or has already
 * been finalised. */
wt_status_t wt_sha256_snapshot(const wt_sha256_ctx_t *ctx,
                               uint8_t out[WT_SHA256_LEN]);

/* HMAC-SHA256 (RFC 2104), which is what HKDF and the TLS Finished MAC are built
 * from. */
wt_status_t wt_hmac_sha256(const uint8_t *key, size_t key_len,
                           const uint8_t *data, size_t data_len,
                           uint8_t out[WT_SHA256_LEN]);

/* HKDF (RFC 5869). `salt` may be NULL with `salt_len` 0, which HKDF defines as an
 * all-zero salt of HashLen bytes -- NOT as "no salt". The distinction changes the
 * output, and the TLS 1.3 key schedule depends on it, so it is stated here rather
 * than left to the backend's convention.
 *
 * `wt_hkdf_expand_sha256` refuses `out_len` above 255 * 32 bytes, which is the
 * RFC's own bound; a longer output would wrap the one-byte block counter and
 * produce bytes that are not the RFC 5869 stream. */
wt_status_t wt_hkdf_extract_sha256(const uint8_t *salt, size_t salt_len,
                                   const uint8_t *ikm, size_t ikm_len,
                                   uint8_t out[WT_SHA256_LEN]);
wt_status_t wt_hkdf_expand_sha256(const uint8_t *prk, size_t prk_len,
                                  const uint8_t *info, size_t info_len,
                                  uint8_t *out, size_t out_len);

/* HKDF-Expand-Label (RFC 8446 section 7.1), which is the only way TLS 1.3 ever
 * calls HKDF-Expand: the label is prefixed with "tls13 " and the context is
 * length-prefixed, and both of those are places where a wrong choice produces
 * well-formed bytes. */
wt_status_t wt_hkdf_expand_label_sha256(const uint8_t *secret,
                                        size_t secret_len, const char *label,
                                        const uint8_t *context,
                                        size_t context_len, uint8_t *out,
                                        size_t out_len);

/* The AEADs QUIC defines. AES-128-GCM is mandatory and is the only one whose
 * TLS suite this implementation's key schedule carries; ChaCha20-Poly1305 is
 * optional for QUIC and is present because RFC 9001 publishes vectors for it and
 * because a header protection path that only ever ran AES would leave the
 * ChaCha20 code unexercised. */
typedef enum wt_aead {
  WT_AEAD_AES_128_GCM = 1,
  WT_AEAD_CHACHA20_POLY1305 = 2
} wt_aead_t;

/* The sizes each AEAD needs. `wt_aead_key_len` is 16 for AES-128-GCM and 32 for
 * ChaCha20-Poly1305, and it is also the header protection key length, because
 * RFC 9001 section 5.1 derives `quic hp` with the AEAD's own key size. */
size_t wt_aead_key_len(wt_aead_t aead);
size_t wt_aead_iv_len(wt_aead_t aead);
size_t wt_aead_tag_len(wt_aead_t aead);

#define WT_AEAD_MAX_KEY_LEN 32U
#define WT_AEAD_IV_LEN 12U
#define WT_AEAD_TAG_LEN 16U

/* Encrypt `len` bytes of `plain` into `out`, writing the tag to `tag`. `out` and
 * `plain` must not overlap. The tag is not included in `out`. */
wt_status_t wt_aead_seal(wt_aead_t aead, const uint8_t *key, const uint8_t *iv,
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *plain, size_t len, uint8_t *out,
                         uint8_t tag[WT_AEAD_TAG_LEN]);

/* Decrypt `len` bytes of `cipher` into `out` and verify the peer's `tag` over
 * the ciphertext and `aad`. Returns WT_OK only when the tag verifies, and
 * WT_ERR_AUTHENTICATION when it does not -- in which case `out` is cleared
 * before returning, so there is no moment at which a caller holds unauthenticated
 * plaintext it might parse by mistake.
 *
 * WHY THERE IS NO "COMPUTED TAG" OUT-PARAMETER, which the shape of an AEAD
 * library would otherwise suggest. A GCM implementation only ever produces a tag
 * as the result of an operation that either succeeded or did not: OpenSSL 3's
 * provider GCM computes the tag during finalisation and reports it only after
 * finalisation succeeds, which requires the expected tag to have been supplied
 * first (measured on OpenSSL 3.6.4: EVP_CTRL_AEAD_GET_TAG returns 0 both before
 * and after a finalisation with a placeholder tag, in decrypt mode). Returning a
 * tag to be compared by the caller would therefore have to be built on either an
 * unauthenticated decryption followed by a second pass, or a hand-written GHASH
 * and Poly1305 -- two ways to make an ordinary packet forgery look like a bug in
 * this library. The comparison happens inside the AEAD, in constant time, and the
 * single status is the whole answer.
 *
 * `out` and `cipher` may be the same buffer. On WT_ERR_AUTHENTICATION the return
 * value is the only usable output. */
wt_status_t wt_aead_open(wt_aead_t aead, const uint8_t *key, const uint8_t *iv,
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *cipher, size_t len,
                         const uint8_t tag[WT_AEAD_TAG_LEN], uint8_t *out);

/* AES-128 block encryption, for QUIC's AES-based header protection (RFC 9001
 * section 5.4.1), which encrypts a 16-byte sample and keeps five bytes of it. */
wt_status_t wt_aes128_ecb_encrypt_block(const uint8_t key[16],
                                        const uint8_t in[16], uint8_t out[16]);

/* ChaCha20 keystream XOR (RFC 8439), for QUIC's ChaCha20 header protection
 * (RFC 9001 section 5.4.4), which needs the raw keystream over five zero bytes.
 * This is not the AEAD: ChaCha20-Poly1305's authentication is a separate
 * construction and is not built from this. */
wt_status_t wt_chacha20_xor(const uint8_t key[32], const uint8_t nonce[12],
                            uint32_t counter, const uint8_t *in, size_t len,
                            uint8_t *out);

/* Constant-time comparison. Returns 1 when equal. A comparison that stopped at
 * the first differing byte would tell an attacker how much of a tag or a key it
 * had guessed, one byte at a time. */
int wt_ct_equal(const uint8_t *a, const uint8_t *b, size_t len);

/* Overwrite `len` bytes of `buffer` with zeros in a way the compiler is not
 * allowed to remove. Secrets that are no longer needed go through this, because
 * a plain memset to storage that is never read again may be optimised away. */
void wt_secure_zero(void *buffer, size_t len);

/* Fill `out` with `len` cryptographically secure random bytes. Every value that
 * has to be unpredictable -- a connection ID, an ephemeral key, a token -- comes
 * from here, and this is the one function in this header whose failure a caller
 * cannot work around: a protocol that cannot get randomness cannot proceed, so
 * an error must abort the operation rather than fall back. */
wt_status_t wt_random_bytes(uint8_t *out, size_t len);

/* Whether the backend was initialised. The OpenSSL backend needs no explicit
 * start-up, so this is here for a backend that does, and a caller may use it to
 * report the difference between "crypto is unavailable" and "this operation
 * failed". */
wt_status_t wt_crypto_init(void);

/* A short stable name for an AEAD: "aes-128-gcm", "chacha20-poly1305",
 * "unknown". Never NULL. */
const char *wt_aead_name(wt_aead_t aead);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_CRYPTO_CRYPTO_H */
