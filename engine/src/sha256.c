#include "sha256.h"

/* <string.h> is a hosted header, and this file is now built for XAIOS itself
   as well as for the hosted tests. A freestanding compiler defines
   __STDC_HOSTED__ as 0 and offers no such header, so declare the two functions
   this needs rather than depend on one. XAIOS's userspace library provides
   both under their standard names, which is what lets the linker resolve them
   there. */
#if defined(__STDC_HOSTED__) && __STDC_HOSTED__
#include <string.h>
#else
#include <stddef.h>
void *memcpy(void *destination, const void *source, size_t length);
void *memset(void *destination, int value, size_t length);
#endif

static const uint32_t k_round[64] = {
    UINT32_C(0x428a2f98), UINT32_C(0x71374491), UINT32_C(0xb5c0fbcf),
    UINT32_C(0xe9b5dba5), UINT32_C(0x3956c25b), UINT32_C(0x59f111f1),
    UINT32_C(0x923f82a4), UINT32_C(0xab1c5ed5), UINT32_C(0xd807aa98),
    UINT32_C(0x12835b01), UINT32_C(0x243185be), UINT32_C(0x550c7dc3),
    UINT32_C(0x72be5d74), UINT32_C(0x80deb1fe), UINT32_C(0x9bdc06a7),
    UINT32_C(0xc19bf174), UINT32_C(0xe49b69c1), UINT32_C(0xefbe4786),
    UINT32_C(0x0fc19dc6), UINT32_C(0x240ca1cc), UINT32_C(0x2de92c6f),
    UINT32_C(0x4a7484aa), UINT32_C(0x5cb0a9dc), UINT32_C(0x76f988da),
    UINT32_C(0x983e5152), UINT32_C(0xa831c66d), UINT32_C(0xb00327c8),
    UINT32_C(0xbf597fc7), UINT32_C(0xc6e00bf3), UINT32_C(0xd5a79147),
    UINT32_C(0x06ca6351), UINT32_C(0x14292967), UINT32_C(0x27b70a85),
    UINT32_C(0x2e1b2138), UINT32_C(0x4d2c6dfc), UINT32_C(0x53380d13),
    UINT32_C(0x650a7354), UINT32_C(0x766a0abb), UINT32_C(0x81c2c92e),
    UINT32_C(0x92722c85), UINT32_C(0xa2bfe8a1), UINT32_C(0xa81a664b),
    UINT32_C(0xc24b8b70), UINT32_C(0xc76c51a3), UINT32_C(0xd192e819),
    UINT32_C(0xd6990624), UINT32_C(0xf40e3585), UINT32_C(0x106aa070),
    UINT32_C(0x19a4c116), UINT32_C(0x1e376c08), UINT32_C(0x2748774c),
    UINT32_C(0x34b0bcb5), UINT32_C(0x391c0cb3), UINT32_C(0x4ed8aa4a),
    UINT32_C(0x5b9cca4f), UINT32_C(0x682e6ff3), UINT32_C(0x748f82ee),
    UINT32_C(0x78a5636f), UINT32_C(0x84c87814), UINT32_C(0x8cc70208),
    UINT32_C(0x90befffa), UINT32_C(0xa4506ceb), UINT32_C(0xbef9a3f7),
    UINT32_C(0xc67178f2)};

static uint32_t rotate_right(uint32_t value, uint32_t amount) {
  return (value >> amount) | (value << (32U - amount));
}

static uint32_t load_be32(const uint8_t *bytes) {
  return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
         ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
}

static void store_be32(uint8_t *bytes, uint32_t value) {
  bytes[0] = (uint8_t)(value >> 24);
  bytes[1] = (uint8_t)(value >> 16);
  bytes[2] = (uint8_t)(value >> 8);
  bytes[3] = (uint8_t)value;
}

static void transform(xaios_engine_sha256_context_t *context,
                      const uint8_t block[64]) {
  uint32_t words[64];
  for (uint32_t i = 0; i < 16U; ++i) {
    words[i] = load_be32(block + (i * 4U));
  }
  for (uint32_t i = 16U; i < 64U; ++i) {
    uint32_t s0 = rotate_right(words[i - 15U], 7U) ^
                  rotate_right(words[i - 15U], 18U) ^
                  (words[i - 15U] >> 3U);
    uint32_t s1 = rotate_right(words[i - 2U], 17U) ^
                  rotate_right(words[i - 2U], 19U) ^
                  (words[i - 2U] >> 10U);
    words[i] = words[i - 16U] + s0 + words[i - 7U] + s1;
  }

  uint32_t a = context->state[0];
  uint32_t b = context->state[1];
  uint32_t c = context->state[2];
  uint32_t d = context->state[3];
  uint32_t e = context->state[4];
  uint32_t f = context->state[5];
  uint32_t g = context->state[6];
  uint32_t h = context->state[7];

  for (uint32_t i = 0; i < 64U; ++i) {
    uint32_t sum1 = rotate_right(e, 6U) ^ rotate_right(e, 11U) ^
                    rotate_right(e, 25U);
    uint32_t choice = (e & f) ^ ((~e) & g);
    uint32_t temporary1 = h + sum1 + choice + k_round[i] + words[i];
    uint32_t sum0 = rotate_right(a, 2U) ^ rotate_right(a, 13U) ^
                    rotate_right(a, 22U);
    uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
    uint32_t temporary2 = sum0 + majority;
    h = g;
    g = f;
    f = e;
    e = d + temporary1;
    d = c;
    c = b;
    b = a;
    a = temporary1 + temporary2;
  }

  context->state[0] += a;
  context->state[1] += b;
  context->state[2] += c;
  context->state[3] += d;
  context->state[4] += e;
  context->state[5] += f;
  context->state[6] += g;
  context->state[7] += h;
}

/* The compressor in use, or null for the scalar reference below.
 *
 * A plain pointer with no locking. It is installed once during start-up, from
 * one thread, before anything hashes; making it atomic would suggest it can be
 * changed while hashes are in flight, and it cannot. */
static xaios_engine_sha256_compress_fn g_compress = 0;

void xaios_engine_sha256_install_compressor(
    xaios_engine_sha256_compress_fn compress) {
  g_compress = compress;
}

static void compress(xaios_engine_sha256_context_t *context,
                     const uint8_t *blocks, size_t count) {
  if (g_compress != 0) {
    g_compress(context->state, blocks, count);
    return;
  }
  for (size_t index = 0U; index < count; ++index) {
    transform(context, blocks + (index * 64U));
  }
}

void xaios_engine_sha256_init(xaios_engine_sha256_context_t *context) {
  static const uint32_t initial[8] = {
      UINT32_C(0x6a09e667), UINT32_C(0xbb67ae85), UINT32_C(0x3c6ef372),
      UINT32_C(0xa54ff53a), UINT32_C(0x510e527f), UINT32_C(0x9b05688c),
      UINT32_C(0x1f83d9ab), UINT32_C(0x5be0cd19)};
  memcpy(context->state, initial, sizeof(initial));
  context->total_bytes = 0;
  context->block_size = 0;
}

void xaios_engine_sha256_update(xaios_engine_sha256_context_t *context, const void *data,
                         size_t length) {
  const uint8_t *bytes = (const uint8_t *)data;
  context->total_bytes += (uint64_t)length;
  while (length > 0U) {
    /* Whole blocks straight out of the caller's buffer once the partial block
       is drained. Everything used to be copied into `block` one 64-byte
       instalment at a time, which meant every byte of a two mebibyte chunk was
       copied before it was hashed, for no reason -- the compression function
       reads the block and does not keep it. */
    if (context->block_size == 0U && length >= sizeof(context->block)) {
      size_t blocks = length / sizeof(context->block);
      compress(context, bytes, blocks);
      size_t consumed = blocks * sizeof(context->block);
      bytes += consumed;
      length -= consumed;
      continue;
    }
    size_t available = sizeof(context->block) - context->block_size;
    size_t count = length < available ? length : available;
    memcpy(context->block + context->block_size, bytes, count);
    context->block_size += count;
    bytes += count;
    length -= count;
    if (context->block_size == sizeof(context->block)) {
      compress(context, context->block, 1U);
      context->block_size = 0;
    }
  }
}

void xaios_engine_sha256_final(xaios_engine_sha256_context_t *context, uint8_t digest[32]) {
  uint64_t bit_length = context->total_bytes * UINT64_C(8);
  uint8_t one = UINT8_C(0x80);
  uint8_t zero = 0;
  xaios_engine_sha256_update(context, &one, 1U);
  while (context->block_size != 56U) {
    xaios_engine_sha256_update(context, &zero, 1U);
  }
  uint8_t length_bytes[8];
  for (uint32_t i = 0; i < 8U; ++i) {
    length_bytes[7U - i] = (uint8_t)(bit_length >> (i * 8U));
  }
  xaios_engine_sha256_update(context, length_bytes, sizeof(length_bytes));
  for (uint32_t i = 0; i < 8U; ++i) {
    store_be32(digest + (i * 4U), context->state[i]);
  }
}
