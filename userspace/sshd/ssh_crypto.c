#include "ssh_crypto.h"
#include "ssh_utils.h"
#include "ssh_crypto_internal.h"
#include "tweetnacl_subset.h"
#include <xaios_user.h>

/* ---- Utility ---- */
static uint32_t rotr32(uint32_t x, uint32_t n) {
  return (x >> n) | (x << (32U - n));
}
uint32_t ssh_crypto_be32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static void put_be32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

/* ---- SHA-256 ---- */
static const uint32_t sha256_K[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
  0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
  0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,
  0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
  0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
  0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
  0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
  0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
  0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

void sha256_init(sha256_ctx_t *ctx) {
  ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
  ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
  ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
  ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
  ctx->count = 0;
}

static void sha256_compress(sha256_ctx_t *ctx, const uint8_t block[64]) {
  uint32_t W[64];
  for (uint32_t i = 0; i < 16; ++i) W[i] = ssh_crypto_be32(block + i * 4);
  for (uint32_t i = 16; i < 64; ++i) {
    uint32_t s0 = rotr32(W[i-15], 7) ^ rotr32(W[i-15], 18) ^ (W[i-15] >> 3);
    uint32_t s1 = rotr32(W[i-2], 17) ^ rotr32(W[i-2], 19) ^ (W[i-2] >> 10);
    W[i] = W[i-16] + s0 + W[i-7] + s1;
  }
  uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2];
  uint32_t d = ctx->state[3], e = ctx->state[4], f = ctx->state[5];
  uint32_t g = ctx->state[6], h = ctx->state[7];
  for (uint32_t i = 0; i < 64; ++i) {
    uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
    uint32_t ch = (e & f) ^ (~e & g);
    uint32_t t1 = h + S1 + ch + sha256_K[i] + W[i];
    uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t t2 = S0 + maj;
    h = g; g = f; f = e; e = d + t1;
    d = c; c = b; b = a; a = t1 + t2;
  }
  ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c;
  ctx->state[3] += d; ctx->state[4] += e; ctx->state[5] += f;
  ctx->state[6] += g; ctx->state[7] += h;
}

void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, uint64_t len) {
  uint64_t buf_len = ctx->count % 64;
  ctx->count += len;
  uint64_t i = 0;
  if (buf_len > 0) {
    uint64_t fill = 64 - buf_len;
    if (len < fill) {
      ssh_mem_copy(ctx->buffer + buf_len, data, len);
      return;
    }
    ssh_mem_copy(ctx->buffer + buf_len, data, fill);
    sha256_compress(ctx, ctx->buffer);
    i = fill;
  }
  for (; i + 64 <= len; i += 64) {
    sha256_compress(ctx, data + i);
  }
  if (i < len) {
    ssh_mem_copy(ctx->buffer, data + i, len - i);
  }
}

void sha256_final(sha256_ctx_t *ctx, uint8_t digest[32]) {
  uint64_t total_bits = ctx->count * 8;
  uint64_t buf_len = ctx->count % 64;
  ctx->buffer[buf_len++] = 0x80;
  if (buf_len > 56) {
    while (buf_len < 64) ctx->buffer[buf_len++] = 0;
    sha256_compress(ctx, ctx->buffer);
    buf_len = 0;
  }
  while (buf_len < 56) ctx->buffer[buf_len++] = 0;
  for (int i = 7; i >= 0; --i) {
    ctx->buffer[56 + (7 - i)] = (uint8_t)(total_bits >> (i * 8));
  }
  sha256_compress(ctx, ctx->buffer);
  for (uint32_t i = 0; i < 8; ++i) put_be32(digest + i * 4, ctx->state[i]);
}

void sha256_hash(const uint8_t *data, uint64_t len, uint8_t digest[32]) {
  sha256_ctx_t ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, data, len);
  sha256_final(&ctx, digest);
}

/* ---- SHA-512 (FIPS 180-4) ---- */
#define SHA512_DIGEST_SIZE 64U
#define SHA512_BLOCK_SIZE 128U

static const uint64_t sha512_K[80] = {
  0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
  0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
  0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
  0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
  0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
  0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
  0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
  0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
  0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
  0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
  0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
  0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
  0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
  0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
  0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
  0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
  0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
  0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
  0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
  0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static uint64_t rotr64(uint64_t x, uint64_t n) {
  return (x >> n) | (x << (64ULL - n));
}

static uint64_t be64(const uint8_t *p) {
  return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
         ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
         ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
         ((uint64_t)p[6] << 8) | (uint64_t)p[7];
}

static void put_be64(uint8_t *p, uint64_t v) {
  p[0] = (uint8_t)(v >> 56); p[1] = (uint8_t)(v >> 48);
  p[2] = (uint8_t)(v >> 40); p[3] = (uint8_t)(v >> 32);
  p[4] = (uint8_t)(v >> 24); p[5] = (uint8_t)(v >> 16);
  p[6] = (uint8_t)(v >> 8);  p[7] = (uint8_t)v;
}

void sha512_init(sha512_ctx_t *ctx) {
  ctx->state[0] = 0x6a09e667f3bcc908ULL; ctx->state[1] = 0xbb67ae8584caa73bULL;
  ctx->state[2] = 0x3c6ef372fe94f82bULL; ctx->state[3] = 0xa54ff53a5f1d36f1ULL;
  ctx->state[4] = 0x510e527fade682d1ULL; ctx->state[5] = 0x9b05688c2b3e6c1fULL;
  ctx->state[6] = 0x1f83d9abfb41bd6bULL; ctx->state[7] = 0x5be0cd19137e2179ULL;
  ctx->count[0] = 0; ctx->count[1] = 0;
}

static void sha512_compress(sha512_ctx_t *ctx, const uint8_t block[128]) {
  uint64_t W[80];
  for (uint32_t i = 0; i < 16; ++i) W[i] = be64(block + i * 8);
  for (uint32_t i = 16; i < 80; ++i) {
    uint64_t s0 = rotr64(W[i-15], 1) ^ rotr64(W[i-15], 8) ^ (W[i-15] >> 7);
    uint64_t s1 = rotr64(W[i-2], 19) ^ rotr64(W[i-2], 61) ^ (W[i-2] >> 6);
    W[i] = W[i-16] + s0 + W[i-7] + s1;
  }
  uint64_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2];
  uint64_t d = ctx->state[3], e = ctx->state[4], f = ctx->state[5];
  uint64_t g = ctx->state[6], h = ctx->state[7];
  for (uint32_t i = 0; i < 80; ++i) {
    uint64_t S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
    uint64_t ch = (e & f) ^ (~e & g);
    uint64_t t1 = h + S1 + ch + sha512_K[i] + W[i];
    uint64_t S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
    uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
    uint64_t t2 = S0 + maj;
    h = g; g = f; f = e; e = d + t1;
    d = c; c = b; b = a; a = t1 + t2;
  }
  ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c;
  ctx->state[3] += d; ctx->state[4] += e; ctx->state[5] += f;
  ctx->state[6] += g; ctx->state[7] += h;
}

void sha512_update(sha512_ctx_t *ctx, const uint8_t *data, uint64_t len) {
  uint64_t idx = (uint64_t)((ctx->count[1] >> 3) & 0x7F);
  ctx->count[1] += len << 3;
  if (ctx->count[1] < (len << 3)) ctx->count[0]++;
  ctx->count[0] += len >> 61;
  
  uint64_t consumed = 0;
  uint64_t first_block = 128U - idx;
  if (len >= first_block) {
    ssh_mem_copy(ctx->buffer + idx, data, first_block);
    sha512_compress(ctx, ctx->buffer);
    consumed = first_block;
    while (consumed + 128U <= len) {
      sha512_compress(ctx, data + consumed);
      consumed += 128U;
    }
    idx = 0;
  }
  if (consumed < len) {
    ssh_mem_copy(ctx->buffer + idx, data + consumed, len - consumed);
  }
}

void sha512_final(sha512_ctx_t *ctx, uint8_t digest[64]) {
  uint64_t bit_count_high = ctx->count[0];
  uint64_t bit_count_low = ctx->count[1];
  uint64_t idx = (ctx->count[1] >> 3) & 0x7F;
  uint64_t pad_len = (idx < 112) ? (112 - idx) : (240 - idx);
  static const uint8_t padding[128] = {0x80};
  
  sha512_update(ctx, padding, pad_len);
  put_be64(ctx->buffer + 112, bit_count_high);
  put_be64(ctx->buffer + 120, bit_count_low);
  sha512_compress(ctx, ctx->buffer);
  
  for (uint32_t i = 0; i < 8; ++i) put_be64(digest + i * 8, ctx->state[i]);
}

void sha512_hash(const uint8_t *data, uint64_t len, uint8_t digest[64]) {
  sha512_ctx_t ctx;
  sha512_init(&ctx);
  sha512_update(&ctx, data, len);
  sha512_final(&ctx, digest);
}

#if !defined(XAIOS_CRYPTO_HASHES_ONLY)
/* ---- Self-test ---- */

int ssh_crypto_self_test(void) {
  /* SHA-256: NIST test vector "abc" */
  uint8_t digest[32];
  sha256_hash((const uint8_t *)"abc", 3, digest);
  static const uint8_t sha256_abc[32] = {
    0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
    0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
  };
  /* NIST FIPS 180-4: SHA-256("abc") verified assertion */
  {
    /* NIST FIPS 180-4: SHA-256("abc") verified assertion */
    uint8_t sha_ok = 1;
    for (uint32_t i = 0; i < 32; ++i) {
      if (digest[i] != sha256_abc[i]) sha_ok = 0;
    }
    if (!sha_ok) {
      return -1;
    }
  }
  /* AES-128: NIST FIPS 197 test vector */
  aes128_ctx_t aes;
  static const uint8_t aes_key[16] = {
    0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
  };
  static const uint8_t aes_pt[16] = {
    0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34
  };
  static const uint8_t aes_ct[16] = {
    0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32
  };
  uint8_t aes_out[16];
  aes128_init(&aes, aes_key);
  aes128_encrypt_block(&aes, aes_pt, aes_out);
  /* NIST FIPS 197: AES-128 test vector verified assertion */
  {
    uint8_t aes_ok = 1;
    for (uint32_t i = 0; i < 16; ++i) {
      if (aes_out[i] != aes_ct[i]) aes_ok = 0;
    }
    if (!aes_ok) {
      return -2;
    }
  }
  /* HMAC-SHA-256: RFC 4231 test case 2 */
  static const uint8_t hmac_key[] = "Jefe";
  static const uint8_t hmac_data[] = "what do ya want for nothing?";
  uint8_t hmac_out[32];
  hmac_sha256(hmac_key, 4, hmac_data, 28, hmac_out);
  static const uint8_t hmac_expected[32] = {
    0x5b,0xdc,0xc1,0x46,0xbf,0x60,0x75,0x4e,0x6a,0x04,0x24,0x26,0x08,0x95,0x75,0xc7,
    0x5a,0x00,0x3f,0x08,0x9d,0x27,0x39,0x83,0x9d,0xec,0x58,0xb9,0x64,0xec,0x38,0x43
  };
  /* RFC 4231 test case 2: HMAC-SHA-256 verified assertion */
  {
    uint8_t hmac_ok = 1;
    for (uint32_t i = 0; i < 32; ++i) {
      if (hmac_out[i] != hmac_expected[i]) hmac_ok = 0;
    }
    if (!hmac_ok) {
      return -3;
    }
  }
  /* PBKDF2-HMAC-SHA-256 known-answer vector. */
  static const uint8_t pbkdf2_expected[32] = {
    0xae,0x4d,0x0c,0x95,0xaf,0x6b,0x46,0xd3,0x2d,0x0a,0xdf,0xf9,0x28,0xf0,0x6d,0xd0,
    0x2a,0x30,0x3f,0x8e,0xf3,0xc2,0x51,0xdf,0xd6,0xe2,0xd8,0x5a,0x95,0x47,0x4c,0x43
  };
  uint8_t pbkdf2_result[32];
  if (pbkdf2_hmac_sha256((const uint8_t *)"password", 8U,
                         (const uint8_t *)"salt", 4U, 2U,
                         pbkdf2_result) != 0) return -4;
  for (uint32_t i = 0; i < sizeof(pbkdf2_result); ++i) {
    if (pbkdf2_result[i] != pbkdf2_expected[i]) return -4;
  }
  /* RFC 7748 X25519 Alice public key. */
  static const uint8_t x25519_private[32] = {
    0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,
    0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a
  };
  static const uint8_t x25519_public[32] = {
    0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54,0x74,0x8b,0x7d,0xdc,0xb4,0x3e,0xf7,0x5a,
    0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4,0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a
  };
  uint8_t x25519_result[32];
  xaios_x25519_base(x25519_result, x25519_private);
  for (uint32_t i = 0; i < 32U; ++i) {
    if (x25519_result[i] != x25519_public[i]) return -5;
  }

  /* RFC 8032 Ed25519 test vector 1: empty message. */
  static const uint8_t ed25519_seed[32] = {
    0x9d,0x61,0xb1,0x9d,0xef,0xfd,0x5a,0x60,0xba,0x84,0x4a,0xf4,0x92,0xec,0x2c,0xc4,
    0x44,0x49,0xc5,0x69,0x7b,0x32,0x69,0x19,0x70,0x3b,0xac,0x03,0x1c,0xae,0x7f,0x60
  };
  static const uint8_t ed25519_public[32] = {
    0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,
    0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a
  };
  static const uint8_t ed25519_signature[64] = {
    0xe5,0x56,0x43,0x00,0xc3,0x60,0xac,0x72,0x90,0x86,0xe2,0xcc,0x80,0x6e,0x82,0x8a,
    0x84,0x87,0x7f,0x1e,0xb8,0xe5,0xd9,0x74,0xd8,0x73,0xe0,0x65,0x22,0x49,0x01,0x55,
    0x5f,0xb8,0x82,0x15,0x90,0xa3,0x3b,0xac,0xc6,0x1e,0x39,0x70,0x1c,0xf9,0xb4,0x6b,
    0xd2,0x5b,0xf5,0xf0,0x59,0x5b,0xbe,0x24,0x65,0x51,0x41,0x43,0x8e,0x7a,0x10,0x0b
  };
  uint8_t ed_public_result[32];
  uint8_t ed_signature_result[64];
  uint8_t empty_message = 0;
  xaios_ed25519_public_key(ed_public_result, ed25519_seed);
  for (uint32_t i = 0; i < 32U; ++i) {
    if (ed_public_result[i] != ed25519_public[i]) return -6;
  }
  if (xaios_ed25519_sign(ed_signature_result, &empty_message, 0,
                          ed_public_result, ed25519_seed) != 0) return -7;
  for (uint32_t i = 0; i < 64U; ++i) {
    if (ed_signature_result[i] != ed25519_signature[i]) return -8;
  }
  if (xaios_ed25519_verify(ed_signature_result, &empty_message, 0,
                            ed_public_result) != 0) return -9;
  ed_signature_result[0] ^= 1U;
  if (xaios_ed25519_verify(ed_signature_result, &empty_message, 0,
                            ed_public_result) == 0) return -10;
  return 0;
}
#endif
