/* TLS 1.3 / QUIC cryptographic primitives, over BearSSL.
 *
 * This is the seam between the protocol code and the crypto library. Nothing
 * in `wt_tls.c` or `wt_quic_pkt.c` calls BearSSL directly; they call these, so
 * the protocol layer can be host-tested and audited without the protocol files
 * changing when the crypto backend does.
 *
 * BearSSL is what XAIOS vendors, and it is compiled into both the kernel and
 * `xapt` already, so this is not a new dependency -- it is the one the target
 * has. It provides HKDF (RFC 5869) and AES-128-GCM (RFC 5288) directly, and
 * AES-ECB for QUIC's AES-based header protection.
 *
 * WHAT IS NOT HERE. ChaCha20-Poly1305 is not implemented: BearSSL has ChaCha20
 * as a stream cipher but no Poly1305, so the AEAD would have to be written on
 * top, and that is a new cryptographic construction rather than a binding.
 * QUIC's mandatory cipher suite is TLS_AES_128_GCM_SHA256, which is what this
 * covers; ChaCha20-Poly1305 is optional and its absence is recorded rather
 * than papered over. wt_chacha20_xor is present and used only for the ChaCha20
 * *header protection* path of RFC 9001 section 5.4.4, which needs the raw
 * keystream and no AEAD at all -- that part is complete.
 *
 * Every function here is checked against a published RFC vector in
 * `tests/security/test_wt_crypto.c`. None of it is "obviously right":
 * HKDF-Expand-Label's length prefixes and the GCM nonce construction are both
 * places where a wrong choice still produces well-shaped output.
 */

#ifndef WT_CRYPTO_H
#define WT_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SHA-256 digest length, in bytes. The only hash this layer offers, because
   TLS_AES_128_GCM_SHA256 is the only suite implemented. */
#define WT_SHA256_LEN 32U

/* Streaming SHA-256.
 *
 * The context is an opaque struct with a published size, and callers declare
 * storage for it with WT_SHA256_CTX or the `wt_sha256_ctx_t` type. It is not
 * a malloc'd handle: C99 callers embed a hash in their own structures, and a
 * two-phase create/destroy would put an allocation and a failure path on every
 * hash. The layout is fixed by the backend; the size is asserted there against
 * WT_SHA256_CTX_MAX, so a backend change that outgrows it fails its own build
 * rather than a caller's frame. */
#define WT_SHA256_CTX_MAX 112U
typedef struct { unsigned char storage[WT_SHA256_CTX_MAX]; } wt_sha256_ctx_t;

/* The number of bytes a context actually needs. Never more than the maximum,
   and callers that care can check it. */
size_t wt_sha256_size(void);
int wt_sha256_init(wt_sha256_ctx_t *ctx);
int wt_sha256_update(wt_sha256_ctx_t *ctx, const void *data, size_t len);
int wt_sha256_final(wt_sha256_ctx_t *ctx, uint8_t out[WT_SHA256_LEN]);

/* One-shot SHA-256, for values that are hashed once and not transcribed. */
int wt_sha256(const void *data, size_t len, uint8_t out[WT_SHA256_LEN]);

/* HMAC-SHA256 (RFC 2104), used by HKDF and by the Finished MAC. */
int wt_hmac_sha256(const uint8_t *key, size_t key_len,
                   const uint8_t *data, size_t data_len,
                   uint8_t out[WT_SHA256_LEN]);

/* HKDF-Extract-SHA256 (RFC 5869 section 2.2).
 *
 * `salt` may be NULL with `salt_len` 0, which HKDF defines as an all-zero salt
 * of HashLen bytes -- not as "no salt". That distinction changes the output. */
int wt_hkdf_extract_sha256(const uint8_t *salt, size_t salt_len,
                           const uint8_t *ikm, size_t ikm_len,
                           uint8_t out[WT_SHA256_LEN]);

/* HKDF-Expand-SHA256 (RFC 5869 section 2.3). Fails if
 * `out_len > 255 * WT_SHA256_LEN`, which is the RFC's bound. */
int wt_hkdf_expand_sha256(const uint8_t *prk, size_t prk_len,
                          const uint8_t *info, size_t info_len,
                          uint8_t *out, size_t out_len);

/* AES-128-GCM (NIST SP 800-38D).
 *
 * `iv` is the 12-byte nonce, `aad` the additional authenticated data.
 *
 * Encrypt writes `len` ciphertext bytes to `out` and the 16-byte tag to `tag`.
 *
 * Decrypt writes `len` plaintext bytes to `out` and the tag it *computed* to
 * `computed_tag`; it does not compare tags, because comparing is the caller's
 * decision and the comparison belongs next to the decision. The caller must
 * compare with wt_ct_equal, which is constant time, and must discard the
 * plaintext on a mismatch.
 *
 * The split is deliberate rather than an inconvenience of the backend. BearSSL
 * requires the tag to be produced by `br_gcm_get_tag` after the ciphertext has
 * been processed, so a function that decrypts and then checks cannot satisfy
 * "write nothing when the tag fails" without a second buffer; and a function
 * that checks before decrypting cannot, because the tag is not yet known. The
 * first version of this tried the latter order and every decryption failed.
 * Handing the computed tag back makes the order explicit and the failure mode
 * a caller that ignores it, which the API documents rather than hides.
 *
 * `out` and `cipher` must not overlap. */
int wt_aes128_gcm_encrypt(const uint8_t key[16], const uint8_t iv[12],
                          const uint8_t *aad, size_t aad_len,
                          const uint8_t *plain, size_t len,
                          uint8_t *out, uint8_t tag[16]);
int wt_aes128_gcm_decrypt(const uint8_t key[16], const uint8_t iv[12],
                          const uint8_t *aad, size_t aad_len,
                          const uint8_t *cipher, size_t len,
                          uint8_t *out, uint8_t computed_tag[16]);

/* AES-128 block encryption (ECB over a single block), for QUIC's AES-based
   header protection, which encrypts the 16-byte sample and keeps 5 bytes. */
int wt_aes128_ecb_encrypt_block(const uint8_t key[16],
                                const uint8_t in[16], uint8_t out[16]);

/* ChaCha20 keystream XOR (RFC 8439).
 *
 * `counter` is the initial 32-bit block counter and `nonce` is 12 bytes.
 * Exposed for QUIC's ChaCha20 header protection (RFC 9001 section 5.4.4),
 * which needs the raw keystream over five zero bytes. It is not the AEAD. */
int wt_chacha20_xor(const uint8_t key[32], const uint8_t nonce[12],
                    uint32_t counter, const uint8_t *in, size_t len,
                    uint8_t *out);

/* X25519 Diffie-Hellman (RFC 7748), which is the key exchange QUIC's
 * TLS_AES_128_GCM_SHA256 connections use by default and the one RFC 8448's
 * trace is built on.
 *
 * The scalar is clamped in place by the implementation, as RFC 7748 requires,
 * so a caller does not have to remember to clear the three low bits and set
 * the high one. Both functions take the private key as the caller's buffer and
 * do not modify it.
 *
 * A shared secret that is all zeros is refused: it is the low-order-point
 * result, it is the same for every private key, and accepting it would let a
 * peer force a known secret. RFC 7748 section 6.1 says implementations MAY
 * check for it; for a protocol where a wrong secret is indistinguishable from
 * a wrong key, refusing is the only answer that fails safely. */

/* Derive the public key from a private key. `out` receives 32 bytes. */
int wt_x25519_public_key(const uint8_t private_key[32], uint8_t out[32]);

/* Derive the shared secret. `peer_public` is the peer's 32-byte u-coordinate as
 * it appears on the wire. Returns -1 on a bad argument or an all-zero result. */
int wt_x25519_shared_secret(const uint8_t private_key[32],
                            const uint8_t peer_public[32], uint8_t out[32]);

/* Whether a 32-byte value is a valid X25519 public key for this code's
 * purposes: not all zeros. Exposed so a caller can reject a peer's key before
 * doing the scalar multiplication. */
int wt_x25519_public_key_is_valid(const uint8_t peer_public[32]);

/* Constant-time comparison of two equal-length buffers. Returns 1 on equal.
   Used for tag and MAC checks; a timing-variable compare here is a forgery
   oracle. */
int wt_ct_equal(const uint8_t *a, const uint8_t *b, size_t len);

/* Overwrite a buffer with zeros in a way the compiler is not allowed to
   remove. Secrets that are no longer needed are cleared with this. */
void wt_secure_zero(void *buffer, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* WT_CRYPTO_H */
