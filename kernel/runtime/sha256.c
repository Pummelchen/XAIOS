#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/sha256.h>

/* SHA-256 round constants (FIPS 180-4 Section 4.2.2) */
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static uint32_t rotr(uint32_t x, uint32_t n) {
  return (x >> n) | (x << (32U - n));
}

static uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
  return (x & y) ^ (~x & z);
}

static uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
  return (x & y) ^ (x & z) ^ (y & z);
}

static uint32_t sigma0(uint32_t x) {
  return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

static uint32_t sigma1(uint32_t x) {
  return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

static uint32_t gamma0(uint32_t x) {
  return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

static uint32_t gamma1(uint32_t x) {
  return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

static uint32_t load_be32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void store_be32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)v;
}

static void sha256_compress(uint32_t state[8], const uint8_t block[64]) {
  uint32_t W[64];
  for (uint32_t i = 0; i < 16; ++i) {
    W[i] = load_be32(block + i * 4U);
  }
  for (uint32_t i = 16; i < 64; ++i) {
    W[i] = gamma1(W[i - 2]) + W[i - 7] + gamma0(W[i - 15]) + W[i - 16];
  }

  uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
  uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

  for (uint32_t i = 0; i < 64; ++i) {
    uint32_t t1 = h + sigma1(e) + ch(e, f, g) + K[i] + W[i];
    uint32_t t2 = sigma0(a) + maj(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  state[5] += f;
  state[6] += g;
  state[7] += h;
}

void xaios_sha256_init(xaios_sha256_ctx_t *ctx) {
  if (ctx == 0) {
    return;
  }
  ctx->state[0] = 0x6a09e667;
  ctx->state[1] = 0xbb67ae85;
  ctx->state[2] = 0x3c6ef372;
  ctx->state[3] = 0xa54ff53a;
  ctx->state[4] = 0x510e527f;
  ctx->state[5] = 0x9b05688c;
  ctx->state[6] = 0x1f83d9ab;
  ctx->state[7] = 0x5be0cd19;
  ctx->bit_count = 0;
  ctx->buffer_len = 0;
  for (uint32_t i = 0; i < 64; ++i) {
    ctx->buffer[i] = 0;
  }
}

void xaios_sha256_update(xaios_sha256_ctx_t *ctx, const void *data,
                         uint64_t len) {
  if (ctx == 0 || data == 0 || len == 0) {
    return;
  }

  const uint8_t *bytes = (const uint8_t *)data;
  ctx->bit_count += len * 8U;

  /* If we have buffered data, try to fill a complete block */
  if (ctx->buffer_len > 0) {
    uint32_t space = 64U - ctx->buffer_len;
    uint32_t to_copy = (uint32_t)(len < space ? len : space);
    for (uint32_t i = 0; i < to_copy; ++i) {
      ctx->buffer[ctx->buffer_len + i] = bytes[i];
    }
    ctx->buffer_len += to_copy;
    bytes += to_copy;
    len -= to_copy;

    if (ctx->buffer_len == 64U) {
      sha256_compress(ctx->state, ctx->buffer);
      ctx->buffer_len = 0;
    }
  }

  /* Process complete blocks */
  while (len >= 64U) {
    sha256_compress(ctx->state, bytes);
    bytes += 64U;
    len -= 64U;
  }

  /* Buffer remaining bytes */
  if (len > 0) {
    for (uint64_t i = 0; i < len; ++i) {
      ctx->buffer[i] = bytes[i];
    }
    ctx->buffer_len = (uint32_t)len;
  }
}

void xaios_sha256_final(xaios_sha256_ctx_t *ctx, uint8_t hash[32]) {
  if (ctx == 0 || hash == 0) {
    return;
  }

  /* Padding must encode the message length before padding bytes are added. */
  uint64_t message_bit_count = ctx->bit_count;
  uint8_t pad = 0x80;
  xaios_sha256_update(ctx, &pad, 1);

  pad = 0x00;
  while (ctx->buffer_len != 56U) {
    xaios_sha256_update(ctx, &pad, 1);
  }

  /* Append bit count in big-endian */
  uint8_t count_bytes[8];
  for (uint32_t i = 0; i < 8; ++i) {
    count_bytes[7 - i] = (uint8_t)(message_bit_count >> (i * 8U));
  }
  xaios_sha256_update(ctx, count_bytes, 8);

  /* Output hash */
  for (uint32_t i = 0; i < 8; ++i) {
    store_be32(hash + i * 4U, ctx->state[i]);
  }
}

void xaios_sha256(const void *data, uint64_t len, uint8_t hash[32]) {
  xaios_sha256_ctx_t ctx;
  xaios_sha256_init(&ctx);
  xaios_sha256_update(&ctx, data, len);
  xaios_sha256_final(&ctx, hash);
}

void sha256_self_test(void) {
  /* NIST test vector: SHA-256("abc") */
  static const uint8_t expected_abc[32] = {
      0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
      0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
      0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};

  uint8_t hash[32];
  xaios_sha256("abc", 3, hash);

  for (uint32_t i = 0; i < 32; ++i) {
    kassert(hash[i] == expected_abc[i]);
  }

  /* NIST test vector: SHA-256("") */
  static const uint8_t expected_empty[32] = {
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4,
      0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b,
      0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};

  xaios_sha256("", 0, hash);
  for (uint32_t i = 0; i < 32; ++i) {
    kassert(hash[i] == expected_empty[i]);
  }

  klog("sha256: self-test passed (abc + empty vectors verified)\n");
}
