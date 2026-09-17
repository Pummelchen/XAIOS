/* Curve25519 field arithmetic (RFC 7748) and the Ed25519 entry points
   (RFC 8032), split out of ssh_crypto.c. Definitions are verbatim. */

#include "ssh_crypto.h"
#include "ssh_utils.h"
#include "tweetnacl_subset.h"

#if !defined(XAIOS_CRYPTO_HASHES_ONLY)
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
    if (crypto_random_bytes(private_key, 32) != 0) {
      ssh_mem_zero(private_key, 32);
      ssh_mem_zero(public_key, 32);
      return;
    }
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
#endif
