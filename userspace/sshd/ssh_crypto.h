#ifndef SSH_CRYPTO_H
#define SSH_CRYPTO_H

#include <xaios/types.h>

/* SHA-256 (FIPS 180-4) */
#define SHA256_DIGEST_SIZE 32U
#define SHA256_BLOCK_SIZE 64U

typedef struct sha256_ctx {
  uint32_t state[8];
  uint64_t count;
  uint8_t buffer[64];
} sha256_ctx_t;

void sha256_init(sha256_ctx_t *ctx);
void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, uint64_t len);
void sha256_final(sha256_ctx_t *ctx, uint8_t digest[32]);
void sha256_hash(const uint8_t *data, uint64_t len, uint8_t digest[32]);

/* SHA-512 (FIPS 180-4) */
#define SHA512_DIGEST_SIZE 64U
#define SHA512_BLOCK_SIZE 128U

typedef struct sha512_ctx {
  uint64_t state[8];
  uint64_t count[2];
  uint8_t buffer[128];
} sha512_ctx_t;

void sha512_init(sha512_ctx_t *ctx);
void sha512_update(sha512_ctx_t *ctx, const uint8_t *data, uint64_t len);
void sha512_final(sha512_ctx_t *ctx, uint8_t digest[64]);
void sha512_hash(const uint8_t *data, uint64_t len, uint8_t digest[64]);

/* HMAC-SHA-256 (RFC 2104) */
void hmac_sha256(const uint8_t *key, uint64_t key_len, const uint8_t *data,
                 uint64_t data_len, uint8_t mac[32]);
int pbkdf2_hmac_sha256(const uint8_t *password, uint32_t password_len,
                       const uint8_t *salt, uint32_t salt_len,
                       uint32_t iterations, uint8_t output[32]);

/* AES-128-CTR (FIPS 197 + NIST SP 800-38A) */
#define AES128_KEY_SIZE 16U
#define AES_BLOCK_SIZE 16U

typedef struct aes128_ctx {
  uint32_t round_keys[44];
} aes128_ctx_t;

void aes128_init(aes128_ctx_t *ctx, const uint8_t key[16]);
void aes128_encrypt_block(const aes128_ctx_t *ctx, const uint8_t in[16],
                          uint8_t out[16]);
void aes128_ctr(const aes128_ctx_t *ctx, const uint8_t iv[16],
                const uint8_t *input, uint8_t *output, uint64_t len);

/* Curve25519 (RFC 7748) */
#define CURVE25519_SCALAR_SIZE 32U
#define CURVE25519_POINT_SIZE 32U

void curve25519_scalar_mult(uint8_t out[32], const uint8_t scalar[32],
                            const uint8_t point[32]);
void curve25519_base(uint8_t out[32], const uint8_t scalar[32]);

/* Ed25519 Digital Signatures (RFC 8032) */
#define ED25519_PUBLIC_KEY_SIZE 32U
#define ED25519_PRIVATE_KEY_SIZE 32U
#define ED25519_SEED_SIZE 32U
#define ED25519_SIGNATURE_SIZE 64U

void ed25519_keygen(uint8_t public_key[32], uint8_t private_key[32],
                    const uint8_t seed[32]);
int ed25519_sign(uint8_t signature[64], const uint8_t *message, uint32_t msg_len,
                 const uint8_t public_key[32], const uint8_t private_key[32]);
int ed25519_verify(const uint8_t signature[64], const uint8_t *message,
                   uint32_t msg_len, const uint8_t public_key[32]);

/* Hardware-seeded ChaCha20 DRBG. Initialization and reads fail closed. */
int crypto_random_init(void);
int crypto_random_bytes(uint8_t *buf, uint32_t len);

/* Self-test against known vectors */
int ssh_crypto_self_test(void);

#endif
