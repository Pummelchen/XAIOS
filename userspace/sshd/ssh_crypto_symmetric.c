/* HMAC-SHA-256 (RFC 2104), PBKDF2-HMAC-SHA-256, AES-128/256-CTR
   (FIPS 197 + NIST SP 800-38A) and the hardware-seeded ChaCha20 DRBG,
   split out of ssh_crypto.c. Definitions are verbatim -- only the
   shared big-endian load was renamed to ssh_crypto_be32. */

#include "ssh_crypto.h"
#include "ssh_utils.h"
#include "ssh_crypto_internal.h"
#include <xaios_user.h>

#if !defined(XAIOS_CRYPTO_HASHES_ONLY)
/* ---- HMAC-SHA-256 ---- */
void hmac_sha256(const uint8_t *key, uint64_t key_len, const uint8_t *data,
                 uint64_t data_len, uint8_t mac[32]) {
  uint8_t k_pad[64];
  uint8_t tk[32];
  if (key_len > 64) {
    sha256_hash(key, key_len, tk);
    key = tk; key_len = 32;
  }
  ssh_mem_zero(k_pad, 64);
  ssh_mem_copy(k_pad, key, key_len);
  for (uint32_t i = 0; i < 64; ++i) k_pad[i] ^= 0x36;
  sha256_ctx_t ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, k_pad, 64);
  sha256_update(&ctx, data, data_len);
  uint8_t inner[32];
  sha256_final(&ctx, inner);
  ssh_mem_zero(k_pad, 64);
  ssh_mem_copy(k_pad, key, key_len);
  for (uint32_t i = 0; i < 64; ++i) k_pad[i] ^= 0x5c;
  sha256_init(&ctx);
  sha256_update(&ctx, k_pad, 64);
  sha256_update(&ctx, inner, 32);
  sha256_final(&ctx, mac);
  ssh_mem_zero(k_pad, sizeof(k_pad));
  ssh_mem_zero(tk, sizeof(tk));
  ssh_mem_zero(inner, sizeof(inner));
  ssh_mem_zero(&ctx, sizeof(ctx));
}

typedef struct {
  sha256_ctx_t inner;
  sha256_ctx_t outer;
} hmac_sha256_precomputed_t;

static void hmac_sha256_precompute(const uint8_t *key, uint32_t key_len,
                                   hmac_sha256_precomputed_t *precomputed) {
  uint8_t key_block[64];
  uint8_t long_key[32];
  if (key_len > sizeof(key_block)) {
    sha256_hash(key, key_len, long_key);
    key = long_key;
    key_len = sizeof(long_key);
  }
  ssh_mem_zero(key_block, sizeof(key_block));
  ssh_mem_copy(key_block, key, key_len);
  for (uint32_t i = 0; i < sizeof(key_block); ++i) key_block[i] ^= 0x36U;
  sha256_init(&precomputed->inner);
  sha256_update(&precomputed->inner, key_block, sizeof(key_block));
  for (uint32_t i = 0; i < sizeof(key_block); ++i) {
    key_block[i] ^= 0x36U ^ 0x5cU;
  }
  sha256_init(&precomputed->outer);
  sha256_update(&precomputed->outer, key_block, sizeof(key_block));
  ssh_mem_zero(key_block, sizeof(key_block));
  ssh_mem_zero(long_key, sizeof(long_key));
}

static void hmac_sha256_precomputed(
    const hmac_sha256_precomputed_t *precomputed, const uint8_t *data,
    uint32_t data_len, uint8_t mac[32]) {
  sha256_ctx_t inner = precomputed->inner;
  sha256_ctx_t outer = precomputed->outer;
  uint8_t digest[32];
  sha256_update(&inner, data, data_len);
  sha256_final(&inner, digest);
  sha256_update(&outer, digest, sizeof(digest));
  sha256_final(&outer, mac);
  ssh_mem_zero(digest, sizeof(digest));
  ssh_mem_zero(&inner, sizeof(inner));
  ssh_mem_zero(&outer, sizeof(outer));
}

int pbkdf2_hmac_sha256(const uint8_t *password, uint32_t password_len,
                       const uint8_t *salt, uint32_t salt_len,
                       uint32_t iterations, uint8_t output[32]) {
  uint8_t salt_block[36];
  uint8_t u[32];
  hmac_sha256_precomputed_t precomputed;
  if (password == 0 || salt == 0 || output == 0 || salt_len == 0U ||
      salt_len > 32U || iterations == 0U) {
    return -1;
  }
  ssh_mem_copy(salt_block, salt, salt_len);
  salt_block[salt_len] = 0U;
  salt_block[salt_len + 1U] = 0U;
  salt_block[salt_len + 2U] = 0U;
  salt_block[salt_len + 3U] = 1U;
  hmac_sha256_precompute(password, password_len, &precomputed);
  hmac_sha256_precomputed(&precomputed, salt_block, salt_len + 4U, u);
  ssh_mem_copy(output, u, sizeof(u));
  for (uint32_t round = 1U; round < iterations; ++round) {
    hmac_sha256_precomputed(&precomputed, u, sizeof(u), u);
    for (uint32_t i = 0; i < sizeof(u); ++i) output[i] ^= u[i];
  }
  ssh_mem_zero(salt_block, sizeof(salt_block));
  ssh_mem_zero(u, sizeof(u));
  ssh_mem_zero(&precomputed, sizeof(precomputed));
  return 0;
}

/* ---- AES-128 ---- */
static const uint8_t aes_sbox[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t aes_rcon[11] = {
  0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

static uint32_t aes_sub_word(uint32_t value) {
  return ((uint32_t)aes_sbox[(value >> 24U) & 0xffU] << 24U) |
         ((uint32_t)aes_sbox[(value >> 16U) & 0xffU] << 16U) |
         ((uint32_t)aes_sbox[(value >> 8U) & 0xffU] << 8U) |
         (uint32_t)aes_sbox[value & 0xffU];
}

void aes128_init(aes128_ctx_t *ctx, const uint8_t key[16]) {
  for (uint32_t i = 0; i < 4; ++i) {
    ctx->round_keys[i] = ssh_crypto_be32(key + i * 4);
  }
  for (uint32_t i = 4; i < 44; ++i) {
    uint32_t temp = ctx->round_keys[i - 1];
    if (i % 4 == 0) {
      temp = ((uint32_t)aes_sbox[(temp >> 16) & 0xff] << 24) |
             ((uint32_t)aes_sbox[(temp >> 8) & 0xff] << 16) |
             ((uint32_t)aes_sbox[temp & 0xff] << 8) |
             (uint32_t)aes_sbox[(temp >> 24) & 0xff];
      temp ^= ((uint32_t)aes_rcon[i / 4] << 24);
    }
    ctx->round_keys[i] = ctx->round_keys[i - 4] ^ temp;
  }
}

static uint8_t xtime(uint8_t x) {
  return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

static void aes_encrypt_block(const uint32_t *round_keys, uint32_t rounds,
                              const uint8_t in[16], uint8_t out[16]) {
  uint8_t s[16];
  ssh_mem_copy(s, in, 16U);
  for (uint32_t i = 0U; i < 4U; ++i) {
    uint32_t key = round_keys[i];
    s[i * 4U] ^= (uint8_t)(key >> 24U);
    s[i * 4U + 1U] ^= (uint8_t)(key >> 16U);
    s[i * 4U + 2U] ^= (uint8_t)(key >> 8U);
    s[i * 4U + 3U] ^= (uint8_t)key;
  }
  for (uint32_t round = 1U; round <= rounds; ++round) {
    for (uint32_t i = 0U; i < 16U; ++i) s[i] = aes_sbox[s[i]];
    uint8_t temporary;
    temporary = s[1]; s[1] = s[5]; s[5] = s[9];
    s[9] = s[13]; s[13] = temporary;
    temporary = s[2]; s[2] = s[10]; s[10] = temporary;
    temporary = s[6]; s[6] = s[14]; s[14] = temporary;
    temporary = s[15]; s[15] = s[11]; s[11] = s[7];
    s[7] = s[3]; s[3] = temporary;
    if (round < rounds) {
      for (uint32_t column = 0U; column < 4U; ++column) {
        uint32_t offset = column * 4U;
        uint8_t a0 = s[offset], a1 = s[offset + 1U];
        uint8_t a2 = s[offset + 2U], a3 = s[offset + 3U];
        s[offset] = xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3;
        s[offset + 1U] = a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3;
        s[offset + 2U] = a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3;
        s[offset + 3U] = xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3);
      }
    }
    for (uint32_t i = 0U; i < 4U; ++i) {
      uint32_t key = round_keys[round * 4U + i];
      s[i * 4U] ^= (uint8_t)(key >> 24U);
      s[i * 4U + 1U] ^= (uint8_t)(key >> 16U);
      s[i * 4U + 2U] ^= (uint8_t)(key >> 8U);
      s[i * 4U + 3U] ^= (uint8_t)key;
    }
  }
  ssh_mem_copy(out, s, 16U);
  ssh_mem_zero(s, sizeof(s));
}

void aes128_encrypt_block(const aes128_ctx_t *ctx, const uint8_t in[16],
                          uint8_t out[16]) {
  aes_encrypt_block(ctx->round_keys, 10U, in, out);
}

void aes128_ctr(const aes128_ctx_t *ctx, const uint8_t iv[16],
                const uint8_t *input, uint8_t *output, uint64_t len) {
  uint8_t counter[16], keystream[16];
  ssh_mem_copy(counter, iv, 16);
  uint64_t pos = 0;
  while (pos < len) {
    aes128_encrypt_block(ctx, counter, keystream);
    uint64_t block_len = (len - pos < 16) ? len - pos : 16;
    for (uint64_t i = 0; i < block_len; ++i) {
      output[pos + i] = input[pos + i] ^ keystream[i];
    }
    pos += block_len;
    /* Increment counter (big-endian) */
    for (int i = 15; i >= 0; --i) {
      if (++counter[i] != 0) break;
    }
  }
}

void aes256_init(aes256_ctx_t *ctx, const uint8_t key[32]) {
  for (uint32_t i = 0U; i < 8U; ++i)
    ctx->round_keys[i] = ssh_crypto_be32(key + i * 4U);
  for (uint32_t i = 8U; i < 60U; ++i) {
    uint32_t temporary = ctx->round_keys[i - 1U];
    if (i % 8U == 0U) {
      temporary = (temporary << 8U) | (temporary >> 24U);
      temporary = aes_sub_word(temporary) ^
                  ((uint32_t)aes_rcon[i / 8U] << 24U);
    } else if (i % 8U == 4U) {
      temporary = aes_sub_word(temporary);
    }
    ctx->round_keys[i] = ctx->round_keys[i - 8U] ^ temporary;
  }
}

void aes256_encrypt_block(const aes256_ctx_t *ctx, const uint8_t in[16],
                          uint8_t out[16]) {
  aes_encrypt_block(ctx->round_keys, 14U, in, out);
}

void aes256_ctr(const aes256_ctx_t *ctx, const uint8_t iv[16],
                const uint8_t *input, uint8_t *output, uint64_t length) {
  uint8_t counter[16], keystream[16];
  ssh_mem_copy(counter, iv, sizeof(counter));
  uint64_t position = 0U;
  while (position < length) {
    aes256_encrypt_block(ctx, counter, keystream);
    uint64_t block_length = length - position < 16U ? length - position : 16U;
    for (uint64_t i = 0U; i < block_length; ++i)
      output[position + i] = input[position + i] ^ keystream[i];
    position += block_length;
    for (int i = 15; i >= 0; --i) if (++counter[i] != 0U) break;
  }
  ssh_mem_zero(counter, sizeof(counter));
  ssh_mem_zero(keystream, sizeof(keystream));
}

/* ---- Secure Random Number Generation (ChaCha20-based DRBG) ---- */

/* ChaCha20 quarter-round */
#define CHACHA20_QR(a, b, c, d) \
  do { \
    a += b; d ^= a; d = (d << 16) | (d >> 16); \
    c += d; b ^= c; b = (b << 12) | (b >> 20); \
    a += b; d ^= a; d = (d << 8)  | (d >> 24); \
    c += d; b ^= c; b = (b << 7)  | (b >> 25); \
  } while (0)

static void chacha20_block(uint32_t out[16], const uint32_t in[16]) {
  uint32_t x[16];
  for (int i = 0; i < 16; ++i) x[i] = in[i];
  for (int i = 0; i < 10; ++i) {  /* 20 rounds = 10 double-rounds */
    CHACHA20_QR(x[0], x[4], x[8],  x[12]);
    CHACHA20_QR(x[1], x[5], x[9],  x[13]);
    CHACHA20_QR(x[2], x[6], x[10], x[14]);
    CHACHA20_QR(x[3], x[7], x[11], x[15]);
    CHACHA20_QR(x[0], x[5], x[10], x[15]);
    CHACHA20_QR(x[1], x[6], x[11], x[12]);
    CHACHA20_QR(x[2], x[7], x[8],  x[13]);
    CHACHA20_QR(x[3], x[4], x[9],  x[14]);
  }
  for (int i = 0; i < 16; ++i) out[i] = x[i] + in[i];
}

static uint32_t g_drbg_state[16];
static uint32_t g_drbg_blocks;
static uint32_t g_drbg_ready;

static uint32_t load_le32(const uint8_t *bytes) {
  return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8U) |
         ((uint32_t)bytes[2] << 16U) | ((uint32_t)bytes[3] << 24U);
}

static int drbg_seed(void) {
  uint8_t seed[48];
  if (xaios_random(seed, sizeof(seed)) != 0) {
    ssh_mem_zero(seed, sizeof(seed));
    g_drbg_ready = 0U;
    return -1;
  }
  /* "expand 32-byte k" constant */
  g_drbg_state[0] = 0x61707865;
  g_drbg_state[1] = 0x3320646e;
  g_drbg_state[2] = 0x79622d32;
  g_drbg_state[3] = 0x6b206574;
  for (uint32_t i = 0; i < 8U; ++i) {
    g_drbg_state[4U + i] = load_le32(seed + i * 4U);
  }
  g_drbg_state[12] = load_le32(seed + 32U);
  g_drbg_state[13] = load_le32(seed + 36U);
  g_drbg_state[14] = load_le32(seed + 40U);
  g_drbg_state[15] = load_le32(seed + 44U);
  g_drbg_blocks = 0U;
  g_drbg_ready = 1U;
  ssh_mem_zero(seed, sizeof(seed));
  return 0;
}

int crypto_random_init(void) {
  ssh_mem_zero(g_drbg_state, sizeof(g_drbg_state));
  g_drbg_ready = 0U;
  return drbg_seed();
}

int crypto_random_bytes(uint8_t *buf, uint32_t len) {
  if (buf == 0 || len == 0U || g_drbg_ready == 0U) {
    return -1;
  }
  if (g_drbg_blocks >= 16384U && drbg_seed() != 0) {
    ssh_mem_zero(buf, len);
    return -1;
  }

  uint32_t pos = 0;
  while (pos < len) {
    uint32_t block[16];
    chacha20_block(block, g_drbg_state);
    ++g_drbg_state[12];
    if (g_drbg_state[12] == 0U) {
      ++g_drbg_state[13];
    }
    ++g_drbg_blocks;

    uint32_t remaining = len - pos;
    uint32_t copy = remaining < 64 ? remaining : 64;
    for (uint32_t i = 0; i < copy; ++i) {
      buf[pos + i] = (uint8_t)(block[i / 4] >> ((i % 4) * 8));
    }
    ssh_mem_zero(block, sizeof(block));
    pos += copy;
  }
  return 0;
}
#endif
