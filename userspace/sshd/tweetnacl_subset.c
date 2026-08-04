/*
 * Curve25519 and Ed25519 field arithmetic derived from TweetNaCl 20140427.
 * TweetNaCl was released into the public domain by its authors. This subset
 * keeps the original formulas while using XAIOS's SHA-512 implementation.
 */
#include "tweetnacl_subset.h"
#include "ssh_crypto.h"
#include "ssh_utils.h"

typedef int64_t tn_i64;
typedef tn_i64 tn_gf[16];

static const uint8_t tn_base9[32] = {9};
static const tn_gf tn_gf0;
static const tn_gf tn_gf1 = {1};
static const tn_gf tn_121665 = {0xdb41, 1};
static const tn_gf tn_d = {
    0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
    0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203};
static const tn_gf tn_d2 = {
    0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
    0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406};
static const tn_gf tn_x = {
    0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
    0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169};
static const tn_gf tn_y = {
    0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
    0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666};
static const tn_gf tn_i = {
    0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
    0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83};
static const uint8_t tn_l[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};

static int tn_verify32(const uint8_t *x, const uint8_t *y) {
  uint32_t different = 0;
  for (uint32_t index = 0; index < 32U; ++index) {
    different |= (uint32_t)(x[index] ^ y[index]);
  }
  return different == 0U ? 0 : -1;
}

static void tn_set25519(tn_gf out, const tn_gf in) {
  for (uint32_t index = 0; index < 16U; ++index) out[index] = in[index];
}

static void tn_carry(tn_gf value) {
  for (uint32_t index = 0; index < 16U; ++index) {
    value[index] += (INT64_C(1) << 16);
    tn_i64 carry = value[index] >> 16;
    uint32_t next = (index + 1U) * (index < 15U);
    value[next] += carry - 1 + 37 * (carry - 1) * (index == 15U);
    value[index] -= carry * INT64_C(65536);
  }
}

static void tn_select(tn_gf lhs, tn_gf rhs, uint32_t swap) {
  tn_i64 mask = ~((tn_i64)swap - 1);
  for (uint32_t index = 0; index < 16U; ++index) {
    tn_i64 value = mask & (lhs[index] ^ rhs[index]);
    lhs[index] ^= value;
    rhs[index] ^= value;
  }
}

static void tn_pack25519(uint8_t out[32], const tn_gf input) {
  tn_gf reduced;
  tn_gf candidate;
  tn_set25519(reduced, input);
  tn_carry(reduced);
  tn_carry(reduced);
  tn_carry(reduced);
  for (uint32_t round = 0; round < 2U; ++round) {
    candidate[0] = reduced[0] - 0xffed;
    for (uint32_t index = 1; index < 15U; ++index) {
      candidate[index] = reduced[index] - 0xffff -
                         ((candidate[index - 1U] >> 16) & 1);
      candidate[index - 1U] &= 0xffff;
    }
    candidate[15] = reduced[15] - 0x7fff -
                    ((candidate[14] >> 16) & 1);
    uint32_t borrow = (uint32_t)((candidate[15] >> 16) & 1);
    candidate[14] &= 0xffff;
    tn_select(reduced, candidate, 1U - borrow);
  }
  for (uint32_t index = 0; index < 16U; ++index) {
    out[2U * index] = (uint8_t)reduced[index];
    out[2U * index + 1U] = (uint8_t)(reduced[index] >> 8);
  }
}

static int tn_not_equal(const tn_gf lhs, const tn_gf rhs) {
  uint8_t lhs_bytes[32];
  uint8_t rhs_bytes[32];
  tn_pack25519(lhs_bytes, lhs);
  tn_pack25519(rhs_bytes, rhs);
  return tn_verify32(lhs_bytes, rhs_bytes);
}

static uint8_t tn_parity(const tn_gf value) {
  uint8_t packed[32];
  tn_pack25519(packed, value);
  return packed[0] & 1U;
}

static void tn_unpack25519(tn_gf out, const uint8_t input[32]) {
  for (uint32_t index = 0; index < 16U; ++index) {
    out[index] = input[2U * index] +
                 ((tn_i64)input[2U * index + 1U] << 8);
  }
  out[15] &= 0x7fff;
}

static void tn_add_field(tn_gf out, const tn_gf lhs, const tn_gf rhs) {
  for (uint32_t index = 0; index < 16U; ++index) out[index] = lhs[index] + rhs[index];
}

static void tn_sub_field(tn_gf out, const tn_gf lhs, const tn_gf rhs) {
  for (uint32_t index = 0; index < 16U; ++index) out[index] = lhs[index] - rhs[index];
}

static void tn_mul_field(tn_gf out, const tn_gf lhs, const tn_gf rhs) {
  tn_i64 product[31];
  for (uint32_t index = 0; index < 31U; ++index) product[index] = 0;
  for (uint32_t lhs_index = 0; lhs_index < 16U; ++lhs_index) {
    for (uint32_t rhs_index = 0; rhs_index < 16U; ++rhs_index) {
      product[lhs_index + rhs_index] += lhs[lhs_index] * rhs[rhs_index];
    }
  }
  for (uint32_t index = 0; index < 15U; ++index) {
    product[index] += 38 * product[index + 16U];
  }
  for (uint32_t index = 0; index < 16U; ++index) out[index] = product[index];
  tn_carry(out);
  tn_carry(out);
}

static void tn_square(tn_gf out, const tn_gf value) {
  tn_mul_field(out, value, value);
}

static void tn_inverse(tn_gf out, const tn_gf input) {
  tn_gf value;
  tn_set25519(value, input);
  for (int32_t exponent = 253; exponent >= 0; --exponent) {
    tn_square(value, value);
    if (exponent != 2 && exponent != 4) tn_mul_field(value, value, input);
  }
  tn_set25519(out, value);
}

static void tn_pow2523(tn_gf out, const tn_gf input) {
  tn_gf value;
  tn_set25519(value, input);
  for (int32_t exponent = 250; exponent >= 0; --exponent) {
    tn_square(value, value);
    if (exponent != 1) tn_mul_field(value, value, input);
  }
  tn_set25519(out, value);
}

int xaios_x25519(uint8_t out[32], const uint8_t scalar[32],
                 const uint8_t point[32]) {
  uint8_t clamped[32];
  tn_i64 coordinates[80];
  tn_gf a, b, c, d, e, f;
  for (uint32_t index = 0; index < 31U; ++index) clamped[index] = scalar[index];
  clamped[31] = (scalar[31] & 127U) | 64U;
  clamped[0] &= 248U;
  tn_unpack25519(coordinates, point);
  for (uint32_t index = 0; index < 16U; ++index) {
    b[index] = coordinates[index];
    d[index] = a[index] = c[index] = 0;
  }
  a[0] = d[0] = 1;
  for (int32_t bit = 254; bit >= 0; --bit) {
    uint32_t selected = (clamped[(uint32_t)bit >> 3U] >> (bit & 7)) & 1U;
    tn_select(a, b, selected);
    tn_select(c, d, selected);
    tn_add_field(e, a, c);
    tn_sub_field(a, a, c);
    tn_add_field(c, b, d);
    tn_sub_field(b, b, d);
    tn_square(d, e);
    tn_square(f, a);
    tn_mul_field(a, c, a);
    tn_mul_field(c, b, e);
    tn_add_field(e, a, c);
    tn_sub_field(a, a, c);
    tn_square(b, a);
    tn_sub_field(c, d, f);
    tn_mul_field(a, c, tn_121665);
    tn_add_field(a, a, d);
    tn_mul_field(c, c, a);
    tn_mul_field(a, d, f);
    tn_mul_field(d, b, coordinates);
    tn_square(b, e);
    tn_select(a, b, selected);
    tn_select(c, d, selected);
  }
  for (uint32_t index = 0; index < 16U; ++index) {
    coordinates[index + 16U] = a[index];
    coordinates[index + 32U] = c[index];
  }
  tn_inverse(coordinates + 32U, coordinates + 32U);
  tn_mul_field(coordinates + 16U, coordinates + 16U, coordinates + 32U);
  tn_pack25519(out, coordinates + 16U);
  return 0;
}

int xaios_x25519_base(uint8_t out[32], const uint8_t scalar[32]) {
  return xaios_x25519(out, scalar, tn_base9);
}

static void tn_add_point(tn_gf point[4], tn_gf other[4]) {
  tn_gf a, b, c, d, t, e, f, g, h;
  tn_sub_field(a, point[1], point[0]);
  tn_sub_field(t, other[1], other[0]);
  tn_mul_field(a, a, t);
  tn_add_field(b, point[0], point[1]);
  tn_add_field(t, other[0], other[1]);
  tn_mul_field(b, b, t);
  tn_mul_field(c, point[3], other[3]);
  tn_mul_field(c, c, tn_d2);
  tn_mul_field(d, point[2], other[2]);
  tn_add_field(d, d, d);
  tn_sub_field(e, b, a);
  tn_sub_field(f, d, c);
  tn_add_field(g, d, c);
  tn_add_field(h, b, a);
  tn_mul_field(point[0], e, f);
  tn_mul_field(point[1], h, g);
  tn_mul_field(point[2], g, f);
  tn_mul_field(point[3], e, h);
}

static void tn_swap_point(tn_gf lhs[4], tn_gf rhs[4], uint8_t swap) {
  for (uint32_t index = 0; index < 4U; ++index) tn_select(lhs[index], rhs[index], swap);
}

static void tn_pack_point(uint8_t out[32], tn_gf point[4]) {
  tn_gf x, y, inverse;
  tn_inverse(inverse, point[2]);
  tn_mul_field(x, point[0], inverse);
  tn_mul_field(y, point[1], inverse);
  tn_pack25519(out, y);
  out[31] ^= (uint8_t)(tn_parity(x) << 7U);
}

static void tn_scalar_mult(tn_gf out[4], tn_gf point[4], const uint8_t scalar[32]) {
  tn_set25519(out[0], tn_gf0);
  tn_set25519(out[1], tn_gf1);
  tn_set25519(out[2], tn_gf1);
  tn_set25519(out[3], tn_gf0);
  for (int32_t bit = 255; bit >= 0; --bit) {
    uint8_t selected = (scalar[(uint32_t)bit / 8U] >> (bit & 7)) & 1U;
    tn_swap_point(out, point, selected);
    tn_add_point(point, out);
    tn_add_point(out, out);
    tn_swap_point(out, point, selected);
  }
}

static void tn_scalar_base(tn_gf out[4], const uint8_t scalar[32]) {
  tn_gf base[4];
  tn_set25519(base[0], tn_x);
  tn_set25519(base[1], tn_y);
  tn_set25519(base[2], tn_gf1);
  tn_mul_field(base[3], tn_x, tn_y);
  tn_scalar_mult(out, base, scalar);
}

static void tn_mod_l(uint8_t out[32], tn_i64 value[64]) {
  tn_i64 carry;
  for (int32_t index = 63; index >= 32; --index) {
    carry = 0;
    int32_t inner;
    for (inner = index - 32; inner < index - 12; ++inner) {
      value[inner] += carry - 16 * value[index] * tn_l[inner - (index - 32)];
      carry = (value[inner] + 128) >> 8;
      value[inner] -= carry * INT64_C(256);
    }
    value[inner] += carry;
    value[index] = 0;
  }
  carry = 0;
  for (uint32_t index = 0; index < 32U; ++index) {
    value[index] += carry - (value[31] >> 4) * tn_l[index];
    carry = value[index] >> 8;
    value[index] &= 255;
  }
  for (uint32_t index = 0; index < 32U; ++index) value[index] -= carry * tn_l[index];
  for (uint32_t index = 0; index < 32U; ++index) {
    value[index + 1U] += value[index] >> 8;
    out[index] = (uint8_t)(value[index] & 255);
  }
}

static void tn_reduce(uint8_t scalar[64]) {
  tn_i64 value[64];
  for (uint32_t index = 0; index < 64U; ++index) value[index] = scalar[index];
  ssh_mem_zero(scalar, 64);
  tn_mod_l(scalar, value);
}

static void tn_hash3(uint8_t out[64], const uint8_t *first, uint32_t first_len,
                     const uint8_t *second, uint32_t second_len,
                     const uint8_t *third, uint32_t third_len) {
  sha512_ctx_t context;
  sha512_init(&context);
  if (first_len != 0U) sha512_update(&context, first, first_len);
  if (second_len != 0U) sha512_update(&context, second, second_len);
  if (third_len != 0U) sha512_update(&context, third, third_len);
  sha512_final(&context, out);
}

void xaios_ed25519_public_key(uint8_t public_key[32], const uint8_t seed[32]) {
  uint8_t digest[64];
  tn_gf point[4];
  sha512_hash(seed, 32, digest);
  digest[0] &= 248U;
  digest[31] &= 127U;
  digest[31] |= 64U;
  tn_scalar_base(point, digest);
  tn_pack_point(public_key, point);
  ssh_mem_zero(digest, sizeof(digest));
}

int xaios_ed25519_sign(uint8_t signature[64], const uint8_t *message,
                       uint32_t message_len, const uint8_t public_key[32],
                       const uint8_t seed[32]) {
  if (signature == 0 || public_key == 0 || seed == 0 ||
      (message == 0 && message_len != 0U)) return -1;
  uint8_t secret_digest[64];
  uint8_t nonce[64];
  uint8_t challenge[64];
  tn_i64 product[64];
  tn_gf point[4];
  sha512_hash(seed, 32, secret_digest);
  secret_digest[0] &= 248U;
  secret_digest[31] &= 127U;
  secret_digest[31] |= 64U;
  tn_hash3(nonce, secret_digest + 32U, 32U, message, message_len, 0, 0);
  tn_reduce(nonce);
  tn_scalar_base(point, nonce);
  tn_pack_point(signature, point);
  tn_hash3(challenge, signature, 32U, public_key, 32U, message, message_len);
  tn_reduce(challenge);
  for (uint32_t index = 0; index < 64U; ++index) product[index] = 0;
  for (uint32_t index = 0; index < 32U; ++index) product[index] = nonce[index];
  for (uint32_t lhs = 0; lhs < 32U; ++lhs) {
    for (uint32_t rhs = 0; rhs < 32U; ++rhs) {
      product[lhs + rhs] += challenge[lhs] * (tn_i64)secret_digest[rhs];
    }
  }
  tn_mod_l(signature + 32U, product);
  ssh_mem_zero(secret_digest, sizeof(secret_digest));
  ssh_mem_zero(nonce, sizeof(nonce));
  ssh_mem_zero(challenge, sizeof(challenge));
  ssh_mem_zero(product, sizeof(product));
  return 0;
}

static int tn_unpack_negative(tn_gf out[4], const uint8_t packed[32]) {
  tn_gf temporary, check, numerator, denominator, denominator2, denominator4,
      denominator6;
  tn_set25519(out[2], tn_gf1);
  tn_unpack25519(out[1], packed);
  tn_square(numerator, out[1]);
  tn_mul_field(denominator, numerator, tn_d);
  tn_sub_field(numerator, numerator, out[2]);
  tn_add_field(denominator, out[2], denominator);
  tn_square(denominator2, denominator);
  tn_square(denominator4, denominator2);
  tn_mul_field(denominator6, denominator4, denominator2);
  tn_mul_field(temporary, denominator6, numerator);
  tn_mul_field(temporary, temporary, denominator);
  tn_pow2523(temporary, temporary);
  tn_mul_field(temporary, temporary, numerator);
  tn_mul_field(temporary, temporary, denominator);
  tn_mul_field(temporary, temporary, denominator);
  tn_mul_field(out[0], temporary, denominator);
  tn_square(check, out[0]);
  tn_mul_field(check, check, denominator);
  if (tn_not_equal(check, numerator) != 0) tn_mul_field(out[0], out[0], tn_i);
  tn_square(check, out[0]);
  tn_mul_field(check, check, denominator);
  if (tn_not_equal(check, numerator) != 0) return -1;
  if (tn_parity(out[0]) == (packed[31] >> 7U)) {
    tn_sub_field(out[0], tn_gf0, out[0]);
  }
  tn_mul_field(out[3], out[0], out[1]);
  return 0;
}

static int tn_scalar_is_canonical(const uint8_t scalar[32]) {
  for (int32_t index = 31; index >= 0; --index) {
    if (scalar[index] < tn_l[index]) return 1;
    if (scalar[index] > tn_l[index]) return 0;
  }
  return 0;
}

int xaios_ed25519_verify(const uint8_t signature[64], const uint8_t *message,
                         uint32_t message_len,
                         const uint8_t public_key[32]) {
  if (signature == 0 || public_key == 0 ||
      (message == 0 && message_len != 0U) ||
      !tn_scalar_is_canonical(signature + 32U)) return -1;
  tn_gf point[4];
  tn_gf base[4];
  uint8_t challenge[64];
  uint8_t encoded[32];
  if (tn_unpack_negative(point, public_key) != 0) return -1;
  tn_hash3(challenge, signature, 32U, public_key, 32U, message, message_len);
  tn_reduce(challenge);
  tn_scalar_mult(base, point, challenge);
  tn_scalar_base(point, signature + 32U);
  tn_add_point(base, point);
  tn_pack_point(encoded, base);
  return tn_verify32(encoded, signature);
}
