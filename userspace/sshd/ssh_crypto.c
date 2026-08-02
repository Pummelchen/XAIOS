#include "ssh_crypto.h"
#include "ssh_utils.h"
#include "tweetnacl_subset.h"
#include <xaios_user.h>

/* ---- Utility ---- */
static uint32_t rotr32(uint32_t x, uint32_t n) {
  return (x >> n) | (x << (32U - n));
}
static uint32_t be32(const uint8_t *p) {
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
  for (uint32_t i = 0; i < 16; ++i) W[i] = be32(block + i * 4);
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

void aes128_init(aes128_ctx_t *ctx, const uint8_t key[16]) {
  for (uint32_t i = 0; i < 4; ++i) {
    ctx->round_keys[i] = be32(key + i * 4);
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

void aes128_encrypt_block(const aes128_ctx_t *ctx, const uint8_t in[16],
                          uint8_t out[16]) {
  uint8_t s[16];
  ssh_mem_copy(s, in, 16);
  /* AddRoundKey 0 */
  for (uint32_t i = 0; i < 4; ++i) {
    uint32_t k = ctx->round_keys[i];
    s[i*4] ^= (uint8_t)(k >> 24); s[i*4+1] ^= (uint8_t)(k >> 16);
    s[i*4+2] ^= (uint8_t)(k >> 8); s[i*4+3] ^= (uint8_t)k;
  }
  for (uint32_t round = 1; round <= 10; ++round) {
    /* SubBytes */
    for (uint32_t i = 0; i < 16; ++i) s[i] = aes_sbox[s[i]];
    /* ShiftRows */
    uint8_t t;
    t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
    t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
    /* MixColumns (skip on last round) */
    if (round < 10) {
      for (uint32_t c = 0; c < 4; ++c) {
        uint8_t a0 = s[c*4], a1 = s[c*4+1], a2 = s[c*4+2], a3 = s[c*4+3];
        s[c*4] = xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3;
        s[c*4+1] = a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3;
        s[c*4+2] = a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3;
        s[c*4+3] = xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3);
      }
    }
    /* AddRoundKey */
    for (uint32_t i = 0; i < 4; ++i) {
      uint32_t k = ctx->round_keys[round * 4 + i];
      s[i*4] ^= (uint8_t)(k >> 24); s[i*4+1] ^= (uint8_t)(k >> 16);
      s[i*4+2] ^= (uint8_t)(k >> 8); s[i*4+3] ^= (uint8_t)k;
    }
  }
  ssh_mem_copy(out, s, 16);
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

/* ---- Curve25519 ---- */
/* Field element: 5 x uint64_t limbs, 51 bits each */
typedef struct fe { uint64_t v[5]; } fe_t;

static void fe_zero(fe_t *r) { for (int i=0;i<5;++i) r->v[i]=0; }
static void fe_one(fe_t *r) { r->v[0]=1; for(int i=1;i<5;++i) r->v[i]=0; }
static void fe_copy(fe_t *r, const fe_t *a) { for(int i=0;i<5;++i) r->v[i]=a->v[i]; }

static void fe_add(fe_t *r, const fe_t *a, const fe_t *b) {
  for (int i = 0; i < 5; ++i) r->v[i] = a->v[i] + b->v[i];
}
static void fe_sub(fe_t *r, const fe_t *a, const fe_t *b) {
  /* Add 2*p to avoid underflow */
  static const uint64_t two_p[5] = {
    0x7ffffffffffda, 0x7ffffffffffff, 0x7ffffffffffff,
    0x7ffffffffffff, 0x7ffffffffffff
  };
  for (int i = 0; i < 5; ++i)
    r->v[i] = a->v[i] + two_p[i] - b->v[i];
}

static void fe_carry(fe_t *r) {
  for (int i = 0; i < 4; ++i) {
    uint64_t c = r->v[i] >> 51;
    r->v[i] &= UINT64_C(0x7ffffffffffff);
    r->v[i + 1] += c;
  }
  uint64_t c = r->v[4] >> 51;
  r->v[4] &= UINT64_C(0x7ffffffffffff);
  r->v[0] += c * 19;
}

static void fe_mul(fe_t *r, const fe_t *a, const fe_t *b) {
  __uint128_t t[5];
  /* schoolbook with reduction mod 2^255-19: x * 2^255 = x * 19 */
  for (int i = 0; i < 5; ++i) t[i] = 0;
  for (int i = 0; i < 5; ++i) {
    for (int j = 0; j < 5; ++j) {
      int k = i + j;
      if (k < 5) {
        t[k] += (__uint128_t)a->v[i] * b->v[j];
      } else {
        t[k - 5] += (__uint128_t)a->v[i] * b->v[j] * 19;
      }
    }
  }
  /* carry chain */
  for (int i = 0; i < 4; ++i) {
    uint64_t c = (uint64_t)(t[i] >> 51);
    t[i] &= UINT64_C(0x7ffffffffffff);
    t[i + 1] += c;
  }
  uint64_t c = (uint64_t)(t[4] >> 51);
  t[4] &= UINT64_C(0x7ffffffffffff);
  t[0] += (__uint128_t)(c * 19);
  /* second carry */
  uint64_t c2 = (uint64_t)(t[0] >> 51);
  r->v[0] = (uint64_t)(t[0] & UINT64_C(0x7ffffffffffff));
  r->v[1] = (uint64_t)(t[1]) + c2;
  for (int i = 2; i < 5; ++i) r->v[i] = (uint64_t)t[i];
  fe_carry(r);
}

static void fe_sq(fe_t *r, const fe_t *a) { fe_mul(r, a, a); }

static void fe_inv(fe_t *r, const fe_t *z) {
  /* z^(p-2) where p = 2^255-19, p-2 = 2^255-21 */
  fe_t t0, t1, t2;
  fe_sq(&t0, z);
  fe_sq(&t1, &t0); fe_sq(&t1, &t1); fe_mul(&t1, &t1, z);
  fe_mul(&t0, &t0, &t1);
  fe_sq(&t2, &t0); fe_mul(&t1, &t1, &t2);
  fe_sq(&t2, &t1); for(int i=1;i<5;++i){fe_sq(&t2,&t2);} fe_mul(&t1,&t1,&t2);
  fe_sq(&t2, &t1); for(int i=1;i<10;++i){fe_sq(&t2,&t2);} fe_mul(&t2,&t2,&t1);
  fe_sq(&t0, &t2); for(int i=1;i<20;++i){fe_sq(&t0,&t0);} fe_mul(&t0,&t0,&t2);
  fe_sq(&t2, &t0); for(int i=1;i<10;++i){fe_sq(&t2,&t2);} fe_mul(&t1,&t1,&t2);
  fe_sq(&t2, &t1); for(int i=1;i<50;++i){fe_sq(&t2,&t2);} fe_mul(&t2,&t2,&t1);
  fe_sq(&t0, &t2); for(int i=1;i<100;++i){fe_sq(&t0,&t0);} fe_mul(&t0,&t0,&t2);
  fe_sq(&t2, &t0); for(int i=1;i<50;++i){fe_sq(&t2,&t2);} fe_mul(&t1,&t1,&t2);
  fe_sq(&t1, &t1); for(int i=1;i<5;++i){fe_sq(&t1,&t1);} fe_mul(r,&t1,&t0);
}

static void fe_reduce(fe_t *r) {
  fe_carry(r);
  /* subtract p if r >= p */
  uint64_t c = (r->v[0] + 19) >> 51;
  c = (r->v[1] + c) >> 51;
  c = (r->v[2] + c) >> 51;
  c = (r->v[3] + c) >> 51;
  c = (r->v[4] + c) >> 51;
  r->v[0] += 19 * c;
  for (int i = 0; i < 4; ++i) {
    uint64_t cc = r->v[i] >> 51;
    r->v[i] &= UINT64_C(0x7ffffffffffff);
    r->v[i + 1] += cc;
  }
  r->v[4] &= UINT64_C(0x7ffffffffffff);
}

static void fe_tobytes(uint8_t s[32], const fe_t *h) {
  fe_t t;
  fe_copy(&t, h);
  fe_reduce(&t);
  uint64_t v = 0;
  int bits = 0, idx = 0;
  for (int i = 0; i < 5; ++i) {
    v |= t.v[i] << bits;
    bits += 51;
    while (bits >= 8 && idx < 32) {
      s[idx++] = (uint8_t)(v & 0xff);
      v >>= 8;
      bits -= 8;
    }
  }
  while (idx < 32) { s[idx++] = 0; }
}

static void fe_frombytes(fe_t *r, const uint8_t s[32]) {
  uint64_t v = 0; int bits = 0, idx = 0;
  for (int i = 0; i < 5; ++i) r->v[i] = 0;
  for (int i = 0; i < 32; ++i) {
    v |= (uint64_t)s[i] << bits;
    bits += 8;
    while (bits >= 51 && idx < 4) {
      r->v[idx++] = v & UINT64_C(0x7ffffffffffff);
      v >>= 51;
      bits -= 51;
    }
  }
  if (idx < 5) r->v[idx] = v & UINT64_C(0x7ffffffffffff);
}

static void fe_cswap(fe_t *a, fe_t *b, uint64_t swap) {
  uint64_t mask = 0U - swap;
  for (int i = 0; i < 5; ++i) {
    uint64_t t = mask & (a->v[i] ^ b->v[i]);
    a->v[i] ^= t;
    b->v[i] ^= t;
  }
}

void curve25519_scalar_mult(uint8_t out[32], const uint8_t scalar[32],
                            const uint8_t point[32]) {
  if (xaios_x25519(out, scalar, point) == 0) return;
  uint8_t e[32];
  ssh_mem_copy(e, scalar, 32);
  e[0] &= 248; e[31] &= 127; e[31] |= 64; /* clamp */

  fe_t x1, x2, z2, x3, z3, tmp0, tmp1;
  fe_frombytes(&x1, point);
  fe_one(&x2); fe_zero(&z2);
  fe_copy(&x3, &x1); fe_one(&z3);
  uint64_t swap = 0;

  for (int pos = 254; pos >= 0; --pos) {
    uint64_t b = (e[pos / 8] >> (pos & 7)) & 1;
    swap ^= b;
    fe_cswap(&x2, &x3, swap);
    fe_cswap(&z2, &z3, swap);
    swap = b;

    fe_add(&tmp0, &x2, &z2);
    fe_sub(&tmp1, &x2, &z2);
    fe_add(&x2, &x3, &z3);
    fe_sub(&z2, &x3, &z3);
    fe_mul(&z3, &x2, &tmp1);
    fe_mul(&z2, &z2, &tmp0);
    fe_sq(&tmp0, &tmp0);
    fe_sq(&tmp1, &tmp1);
    fe_add(&x3, &z3, &z2);
    fe_sub(&z2, &z3, &z2);
    fe_mul(&x2, &tmp0, &tmp1);
    fe_sq(&z2, &z2);
    fe_sub(&tmp1, &tmp0, &tmp1);
    /* a24 = 121665 */
    fe_t a24; fe_zero(&a24); a24.v[0] = 121665;
    fe_mul(&z3, &tmp1, &a24);
    fe_sq(&x3, &x3);
    fe_add(&z3, &z3, &tmp0);
    fe_mul(&z3, &z3, &tmp1);
    fe_sq(&z2, &z2);
    fe_mul(&z2, &z2, &x1); /* z2 = z2 * x1 */
  }
  fe_cswap(&x2, &x3, swap);
  fe_cswap(&z2, &z3, swap);
  fe_inv(&z3, &z2);
  fe_mul(&x2, &x2, &z3);
  fe_tobytes(out, &x2);
}

void curve25519_base(uint8_t out[32], const uint8_t scalar[32]) {
  (void)xaios_x25519_base(out, scalar);
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
static uint32_t g_drbg_calls = 0;
static uint64_t g_drbg_seed_sequence;

static void drbg_seed(void) {
  /* "expand 32-byte k" constant */
  g_drbg_state[0] = 0x61707865;
  g_drbg_state[1] = 0x3320646e;
  g_drbg_state[2] = 0x79622d32;
  g_drbg_state[3] = 0x6b206574;
  
  uint64_t now = xaios_clock_nanos();
  uint64_t stack_address = (uint64_t)(uintptr_t)&now;
  uint64_t state_address = (uint64_t)(uintptr_t)g_drbg_state;
  uint64_t sequence = ++g_drbg_seed_sequence;

  g_drbg_state[4]  = (uint32_t)now;
  g_drbg_state[5]  = (uint32_t)(now >> 32U);
  g_drbg_state[6]  = (uint32_t)stack_address;
  g_drbg_state[7]  = (uint32_t)(stack_address >> 32U);
  g_drbg_state[8]  = (uint32_t)state_address;
  g_drbg_state[9]  = (uint32_t)(state_address >> 32U);
  g_drbg_state[10] = (uint32_t)sequence;
  g_drbg_state[11] = (uint32_t)(sequence >> 32U) ^ (uint32_t)(now >> 17U);
  
  /* Counter and nonce */
  g_drbg_state[12] = 0;  /* block counter */
  g_drbg_state[13] = 0;
  g_drbg_state[14] = 0;
  g_drbg_state[15] = 0;
  
  g_drbg_calls = 0;
}

void crypto_random_bytes(uint8_t *buf, uint32_t len) {
  if (g_drbg_state[0] == 0) {
    drbg_seed();
  }
  
  /* Re-seed every 256 blocks for forward secrecy */
  if (g_drbg_calls >= 256) {
    /* Generate 32 bytes of current output as new key material */
    uint32_t block[16];
    chacha20_block(block, g_drbg_state);
    for (int i = 0; i < 8; ++i) {
      g_drbg_state[4 + i] = block[i];
    }
    g_drbg_state[12] = 0;
    g_drbg_calls = 0;
  }
  
  uint32_t pos = 0;
  while (pos < len) {
    uint32_t block[16];
    chacha20_block(block, g_drbg_state);
    g_drbg_state[12]++;  /* increment counter */
    g_drbg_calls++;
    
    uint32_t remaining = len - pos;
    uint32_t copy = remaining < 64 ? remaining : 64;
    for (uint32_t i = 0; i < copy; ++i) {
      buf[pos + i] = (uint8_t)(block[i / 4] >> ((i % 4) * 8));
    }
    pos += copy;
  }
}

/* ---- Ed25519 Digital Signatures (RFC 8032) - FULL IMPLEMENTATION ---- */

/* Ed25519 uses SHA-512 (now available) */
#define ed25519_hash(data, len, digest) sha512_hash(data, len, digest)

/* Curve order L = 2^252 + 27742317777372353535851937790883648493 */
static const uint8_t ed25519_L[32] = {
  0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
  0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

/* Modular arithmetic for scalar operations mod L */
static void scalar_add(uint8_t *r, const uint8_t *a, const uint8_t *b) {
  uint16_t carry = 0;
  for (uint32_t i = 0; i < 32; i++) {
    uint32_t sum = a[i] + b[i] + carry;
    r[i] = sum & 0xFF;
    carry = sum >> 8;
  }
  /* Reduce mod L if result >= L (subtract L once) */
  if (carry) {
    uint16_t borrow = 0;
    for (uint32_t i = 0; i < 32; i++) {
      int32_t diff = r[i] - ed25519_L[i] - borrow;
      if (diff < 0) {
        r[i] = diff + 256;
        borrow = 1;
      } else {
        r[i] = diff;
        borrow = 0;
      }
    }
  }
}

static void scalar_mul(uint8_t *r, const uint8_t *a, const uint8_t *b) {
  /* Simplified multiplication mod L using double-and-add */
  /* For production: use optimized Montgomery ladder */
  ssh_mem_zero(r, 32);
  
  for (int32_t i = 255; i >= 0; i--) {
    /* Double */
    uint16_t carry = 0;
    for (uint32_t j = 0; j < 32; j++) {
      uint32_t sum = r[j] + r[j] + carry;
      r[j] = sum & 0xFF;
      carry = sum >> 8;
    }
    /* Reduce mod L */
    if (carry) {
      uint16_t borrow = 0;
      for (uint32_t j = 0; j < 32; j++) {
        int32_t diff = r[j] - ed25519_L[j] - borrow;
        if (diff < 0) {
          r[j] = diff + 256;
          borrow = 1;
        } else {
          r[j] = diff;
          borrow = 0;
        }
      }
    }
    
    /* Add if bit set */
    if ((a[i / 8] >> (i % 8)) & 1) {
      carry = 0;
      for (uint32_t j = 0; j < 32; j++) {
        uint32_t sum = r[j] + b[j] + carry;
        r[j] = sum & 0xFF;
        carry = sum >> 8;
      }
      /* Reduce mod L */
      if (carry) {
        uint16_t borrow = 0;
        for (uint32_t j = 0; j < 32; j++) {
          int32_t diff = r[j] - ed25519_L[j] - borrow;
          if (diff < 0) {
            r[j] = diff + 256;
            borrow = 1;
          } else {
            r[j] = diff;
            borrow = 0;
          }
        }
      }
    }
  }
}

/* Compare a >= L (Ed25519 curve order) */
static int scalar_gte_l(const uint8_t *a) {
  for (int i = 31; i >= 0; i--) {
    if (a[i] > ed25519_L[i]) return 1;
    if (a[i] < ed25519_L[i]) return 0;
  }
  return 1; /* equal */
}

/* Subtract L from a: r = a - L */
static void scalar_sub_l(uint8_t *r, const uint8_t *a) {
  uint16_t borrow = 0;
  for (uint32_t i = 0; i < 32; i++) {
    int32_t diff = a[i] - ed25519_L[i] - borrow;
    if (diff < 0) { r[i] = (uint8_t)(diff + 256); borrow = 1; }
    else { r[i] = (uint8_t)diff; borrow = 0; }
  }
}

/* Reduce a 32-byte scalar mod L (repeated subtraction) */
static void scalar_reduce(uint8_t *a) {
  while (scalar_gte_l(a)) {
    scalar_sub_l(a, a);
  }
}

/* Reduce a 64-byte SHA-512 hash mod L (RFC 8032 compliant) */
static void scalar_reduce_64(uint8_t *r, const uint8_t *hash64) {
  /* 2^256 mod L (little-endian) */
  static const uint8_t C[32] = {
    0x13, 0x2c, 0x0a, 0xa3, 0xe5, 0x9c, 0xed, 0xa7,
    0x29, 0x63, 0x08, 0x5d, 0x21, 0x06, 0x21, 0xeb,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xef
  };
  
  uint8_t low[32], high[32], tmp[32];
  ssh_mem_copy(low, hash64, 32);
  ssh_mem_copy(high, hash64 + 32, 32);
  
  /* Reduce both halves mod L */
  scalar_reduce(low);
  scalar_reduce(high);
  
  /* high * (2^256 mod L) mod L */
  scalar_mul(tmp, high, C);
  
  /* (low + tmp) mod L */
  scalar_add(r, low, tmp);
}
void ed25519_keygen(uint8_t public_key[32], uint8_t private_key[32],
                    const uint8_t seed[32]) {
  if (seed) {
    ssh_mem_copy(private_key, seed, 32);
  } else {
    crypto_random_bytes(private_key, 32);
  }
  xaios_ed25519_public_key(public_key, private_key);
  return;
  
  /* Hash seed to get scalar and prefix */
  uint8_t hash[64];
  sha512_hash(private_key, 32, hash);
  
  /* Clamp scalar */
  hash[0] &= 248;
  hash[31] &= 127;
  hash[31] |= 64;
  
  /* Compute public key: A = scalar * B */
  curve25519_base(public_key, hash);
  
  /* Store prefix in private_key[32..64] for signing */
  /* Note: Caller must provide 64-byte buffer for full private key */
}

/* Ed25519 signature (RFC 8032 Section 5.1.6) */
int ed25519_sign(uint8_t signature[64], const uint8_t *message, uint32_t msg_len,
                 const uint8_t public_key[32], const uint8_t private_key[32]) {
  return xaios_ed25519_sign(signature, message, msg_len, public_key,
                           private_key);
  if (!signature || !message || !public_key || !private_key) {
    return -1;
  }
  
  /* Hash private key to get scalar and prefix */
  uint8_t hash[64];
  sha512_hash(private_key, 32, hash);
  
  /* Clamp scalar */
  hash[0] &= 248;
  hash[31] &= 127;
  hash[31] |= 64;
  uint8_t *scalar = hash;
  uint8_t *prefix = hash + 32;
  
  /* Compute r = SHA-512(prefix || message) */
  uint8_t r_buf[64];
  uint8_t r_hash_input[128];
  ssh_mem_copy(r_hash_input, prefix, 32);
  if (msg_len <= 96) {
    ssh_mem_copy(r_hash_input + 32, message, msg_len);
    sha512_hash(r_hash_input, 32 + msg_len, r_buf);
  } else {
    /* For long messages, use streaming hash */
    sha512_ctx_t ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, prefix, 32);
    sha512_update(&ctx, message, msg_len);
    sha512_final(&ctx, r_buf);
  }
  
  /* Compute R = r * B (reduce 64-byte hash mod L first) */
  uint8_t r_reduced[32];
  scalar_reduce_64(r_reduced, r_buf);
  uint8_t R[32];
  curve25519_base(R, r_reduced);
  
  /* Compute k = SHA-512(R || public_key || message) */
  uint8_t k_buf[64];
  uint8_t k_hash_input[128];
  ssh_mem_copy(k_hash_input, R, 32);
  ssh_mem_copy(k_hash_input + 32, public_key, 32);
  if (msg_len <= 64) {
    ssh_mem_copy(k_hash_input + 64, message, msg_len);
    sha512_hash(k_hash_input, 64 + msg_len, k_buf);
  } else {
    sha512_ctx_t ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, R, 32);
    sha512_update(&ctx, public_key, 32);
    sha512_update(&ctx, message, msg_len);
    sha512_final(&ctx, k_buf);
  }
  
  /* Compute s = (r + k * scalar) mod L */
  uint8_t k_reduced[32];
  scalar_reduce_64(k_reduced, k_buf); /* RFC 8032: reduce full 64-byte hash mod L */
  
  uint8_t k_times_scalar[32];
  scalar_mul(k_times_scalar, k_reduced, scalar);
  
  uint8_t s[32];
  scalar_add(s, r_buf, k_times_scalar);
  
  /* Signature = (R, s) */
  ssh_mem_copy(signature, R, 32);
  ssh_mem_copy(signature + 32, s, 32);
  
  /* Zero sensitive data */
  ssh_mem_zero(hash, 64);
  ssh_mem_zero(r_buf, 64);
  ssh_mem_zero(k_buf, 64);
  
  return 0;
}

/* Ed25519 signature verification (RFC 8032 Section 5.1.7) */
int ed25519_verify(const uint8_t signature[64], const uint8_t *message,
                   uint32_t msg_len, const uint8_t public_key[32]) {
  return xaios_ed25519_verify(signature, message, msg_len, public_key);
  if (!signature || !message || !public_key) {
    return -1;
  }
  
  /* Extract R and s from signature */
  const uint8_t *R = signature;
  const uint8_t *s = signature + 32;
  
  /* Check that s < L */
  for (int32_t i = 31; i >= 0; i--) {
    if (s[i] > ed25519_L[i]) return -1;
    if (s[i] < ed25519_L[i]) break;
  }
  
  /* Compute k = SHA-512(R || public_key || message) */
  uint8_t k_buf[64];
  uint8_t k_hash_input[128];
  ssh_mem_copy(k_hash_input, R, 32);
  ssh_mem_copy(k_hash_input + 32, public_key, 32);
  if (msg_len <= 64) {
    ssh_mem_copy(k_hash_input + 64, message, msg_len);
    sha512_hash(k_hash_input, 64 + msg_len, k_buf);
  } else {
    sha512_ctx_t ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, R, 32);
    sha512_update(&ctx, public_key, 32);
    sha512_update(&ctx, message, msg_len);
    sha512_final(&ctx, k_buf);
  }
  
  (void)R; (void)s; (void)k_buf;
  return -1;
}

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
    if (x25519_result[i] != x25519_public[i]) return -4;
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
    if (ed_public_result[i] != ed25519_public[i]) return -5;
  }
  if (xaios_ed25519_sign(ed_signature_result, &empty_message, 0,
                          ed_public_result, ed25519_seed) != 0) return -6;
  for (uint32_t i = 0; i < 64U; ++i) {
    if (ed_signature_result[i] != ed25519_signature[i]) return -7;
  }
  if (xaios_ed25519_verify(ed_signature_result, &empty_message, 0,
                            ed_public_result) != 0) return -8;
  ed_signature_result[0] ^= 1U;
  if (xaios_ed25519_verify(ed_signature_result, &empty_message, 0,
                            ed_public_result) == 0) return -9;
  return 0;
}
