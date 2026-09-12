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
 * Encrypt: writes `len` ciphertext bytes and a 16-byte tag.
 * Decrypt: writes `len` plaintext bytes only if the tag verifies, and returns
 * non-zero without writing when it does not. The compare is constant-time.
 *
 * `iv` is the 12-byte nonce, `aad` the additional authenticated data. */
int wt_aes128_gcm_encrypt(const uint8_t key[16], const uint8_t iv[12],
                          const uint8_t *aad, size_t aad_len,
                          const uint8_t *plain, size_t len,
                          uint8_t *out, uint8_t tag[16]);
int wt_aes128_gcm_decrypt(const uint8_t key[16], const uint8_t iv[12],
                          const uint8_t *aad, size_t aad_len,
                          const uint8_t *cipher, size_t len,
                          const uint8_t tag[16], uint8_t *out);

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
