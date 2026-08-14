#include <bearssl.h>

#include <xaios/dns.h>
#include <xaios/dnssec.h>

#include "../../userspace/sshd/ssh_crypto.h"

#define DNSSEC_TYPE_DS 43U
#define DNSSEC_TYPE_DNSKEY 48U
#define DNSSEC_TYPE_RRSIG 46U
#define DNSSEC_TYPE_NSEC 47U
#define DNSSEC_MIN_WALL_TIME UINT64_C(946684800000000000)
#define DNSSEC_MAX_RECORDS 96U
#define DNSSEC_MAX_RRSET 16U
#define DNSSEC_MAX_SIGNED 8192U

typedef struct dnssec_rr {
  char owner[XAIOS_DNS_MAX_NAME];
  uint16_t type;
  uint16_t rr_class;
  uint32_t ttl;
  const uint8_t *rdata;
  uint16_t rdata_length;
} dnssec_rr_t;

static dnssec_rr_t g_records[DNSSEC_MAX_RECORDS];
static uint32_t g_record_count;
static dnssec_ds_t g_anchors[2];
static uint32_t g_anchor_count;
static uint8_t g_signed[DNSSEC_MAX_SIGNED];

static const uint8_t k_root_20326_ds[] = {
  0xe0U, 0x6dU, 0x44U, 0xb8U, 0x0bU, 0x8fU, 0x1dU, 0x39U,
  0xa9U, 0x5cU, 0x0bU, 0x0dU, 0x7cU, 0x65U, 0xd0U, 0x84U,
  0x58U, 0xe8U, 0x80U, 0x40U, 0x9bU, 0xbcU, 0x68U, 0x34U,
  0x57U, 0x10U, 0x42U, 0x37U, 0xc7U, 0xf8U, 0xecU, 0x8dU};
static const uint8_t k_root_38696_ds[] = {
  0x68U, 0x3dU, 0x2dU, 0x0aU, 0xcbU, 0x8cU, 0x9bU, 0x71U,
  0x2aU, 0x19U, 0x48U, 0xb2U, 0x7fU, 0x74U, 0x12U, 0x19U,
  0x29U, 0x8dU, 0x0aU, 0x45U, 0x0dU, 0x61U, 0x2cU, 0x48U,
  0x3aU, 0xf4U, 0x44U, 0xa4U, 0xc0U, 0xfbU, 0x2bU, 0x16U};

static uint16_t get_be16(const uint8_t *p) {
  return (uint16_t)(((uint16_t)p[0] << 8U) | p[1]);
}
static uint32_t get_be32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24U) | ((uint32_t)p[1] << 16U) |
         ((uint32_t)p[2] << 8U) | p[3];
}
static void put_be16(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)(v >> 8U); p[1] = (uint8_t)v;
}
static void put_be32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24U); p[1] = (uint8_t)(v >> 16U);
  p[2] = (uint8_t)(v >> 8U); p[3] = (uint8_t)v;
}
static void copy_bytes(void *dst, const void *src, uint32_t n) {
  uint8_t *d = dst; const uint8_t *s = src;
  for (uint32_t i = 0; i < n; ++i) d[i] = s[i];
}
static void zero_bytes(void *dst, uint32_t n) {
  uint8_t *d = dst; for (uint32_t i = 0; i < n; ++i) d[i] = 0U;
}
static uint8_t lower(uint8_t c) {
  return c >= 'A' && c <= 'Z' ? (uint8_t)(c + 32U) : c;
}
static int name_equal(const char *a, const char *b) {
  for (uint32_t i = 0; i < XAIOS_DNS_MAX_NAME; ++i) {
    if (lower((uint8_t)a[i]) != lower((uint8_t)b[i])) return 0;
    if (a[i] == '\0') return 1;
  }
  return 0;
}
static uint32_t name_labels(const char *name) {
  if (name[0] == '\0') return 0U;
  uint32_t count = 1U;
  for (uint32_t i = 0; name[i] != '\0'; ++i) if (name[i] == '.') ++count;
  return count;
}
static int canonical_name(const char *name, uint8_t *out, uint32_t cap,
                          uint32_t *out_len) {
  uint32_t wi = 0U, si = 0U;
  if (name[0] == '\0') { if (cap == 0U) return -1; out[0] = 0U; *out_len = 1U; return 0; }
  while (name[si] != '\0') {
    uint32_t start = wi++;
    if (start >= cap) return -1;
    while (name[si] != '\0' && name[si] != '.') {
      if (wi >= cap || wi - start - 1U >= 63U) return -1;
      out[wi++] = lower((uint8_t)name[si++]);
    }
    out[start] = (uint8_t)(wi - start - 1U);
    if (name[si] == '.') ++si;
  }
  if (wi >= cap || wi > 255U) return -1;
  out[wi++] = 0U; *out_len = wi; return 0;
}
static int append(uint32_t *pos, const void *data, uint32_t n) {
  if (*pos > DNSSEC_MAX_SIGNED || n > DNSSEC_MAX_SIGNED - *pos) return -1;
  copy_bytes(g_signed + *pos, data, n); *pos += n; return 0;
}

static int parse_records(const uint8_t *message, uint32_t length) {
  if (message == 0 || length < 12U) return -1;
  uint32_t position = 12U;
  uint16_t qd = get_be16(message + 4U);
  uint32_t total = (uint32_t)get_be16(message + 6U) + get_be16(message + 8U) + get_be16(message + 10U);
  if (qd != 1U || total > DNSSEC_MAX_RECORDS) return -1;
  char ignored[XAIOS_DNS_MAX_NAME];
  int next = dns_decode_name(message, length, position, ignored, sizeof(ignored));
  if (next < 0 || (uint32_t)next > length || length - (uint32_t)next < 4U) return -1;
  position = (uint32_t)next + 4U;
  for (uint32_t i = 0; i < total; ++i) {
    next = dns_decode_name(message, length, position, g_records[i].owner, sizeof(g_records[i].owner));
    if (next < 0 || (uint32_t)next > length || length - (uint32_t)next < 10U) return -1;
    position = (uint32_t)next;
    g_records[i].type = get_be16(message + position);
    g_records[i].rr_class = get_be16(message + position + 2U);
    g_records[i].ttl = get_be32(message + position + 4U);
    g_records[i].rdata_length = get_be16(message + position + 8U);
    position += 10U;
    if (g_records[i].rdata_length > length - position) return -1;
    g_records[i].rdata = message + position;
    position += g_records[i].rdata_length;
  }
  if (position != length) return -1;
  g_record_count = total;
  return 0;
}

static uint16_t dnskey_tag(const uint8_t *rdata, uint16_t length) {
  uint32_t ac = 0U;
  for (uint32_t i = 0; i < length; ++i) ac += (i & 1U) ? rdata[i] : (uint32_t)rdata[i] << 8U;
  ac += (ac >> 16U) & 0xffffU;
  return (uint16_t)ac;
}
static int digest_dnskey(const char *owner, const uint8_t *rdata, uint16_t len,
                         uint8_t digest_type, uint8_t *out) {
  uint8_t wire[256]; uint32_t wire_len = 0U;
  if (canonical_name(owner, wire, sizeof(wire), &wire_len) != 0) return -1;
  if (digest_type == 2U) {
    sha256_ctx_t ctx; sha256_init(&ctx); sha256_update(&ctx, wire, wire_len);
    sha256_update(&ctx, rdata, len); sha256_final(&ctx, out); return 32;
  }
  if (digest_type == 4U) {
    br_sha384_context ctx; br_sha384_init(&ctx); br_sha384_update(&ctx, wire, wire_len);
    br_sha384_update(&ctx, rdata, len); br_sha384_out(&ctx, out); return 48;
  }
  return -1;
}
static int key_matches_ds(const char *owner, const dnssec_key_t *key,
                          const dnssec_dsset_t *ds) {
  if (ds == 0 || !name_equal(owner, ds->owner)) return 0;
  for (uint32_t i = 0; i < ds->count; ++i) {
    const dnssec_ds_t *d = &ds->records[i];
    if (d->key_tag != key->key_tag || d->algorithm != key->algorithm) continue;
    uint8_t digest[64]; int length = digest_dnskey(owner, key->rdata, key->rdata_length, d->digest_type, digest);
    if (length > 0 && (uint32_t)length == d->digest_length) {
      uint32_t j = 0U; while (j < d->digest_length && digest[j] == d->digest[j]) ++j;
      if (j == d->digest_length) return 1;
    }
  }
  return 0;
}

static int canonical_rdata(const uint8_t *message, uint32_t length,
                           const dnssec_rr_t *rr, uint8_t *out,
                           uint32_t capacity, uint32_t *out_length) {
  if (rr->type != DNSSEC_TYPE_NSEC) {
    if (rr->rdata_length > capacity) return -1;
    copy_bytes(out, rr->rdata, rr->rdata_length); *out_length = rr->rdata_length; return 0;
  }
  int next = dns_decode_name(message, length, (uint32_t)(rr->rdata - message), (char *)out, capacity);
  if (next < 0) return -1;
  char name[XAIOS_DNS_MAX_NAME];
  if (dns_decode_name(message, length, (uint32_t)(rr->rdata - message), name, sizeof(name)) < 0) return -1;
  uint32_t wire_len = 0U;
  if (canonical_name(name, out, capacity, &wire_len) != 0) return -1;
  uint32_t consumed = (uint32_t)next - (uint32_t)(rr->rdata - message);
  if (consumed > rr->rdata_length || rr->rdata_length - consumed > capacity - wire_len) return -1;
  copy_bytes(out + wire_len, rr->rdata + consumed, rr->rdata_length - consumed);
  *out_length = wire_len + rr->rdata_length - consumed; return 0;
}
static int rdata_compare(const uint8_t *a, uint32_t an, const uint8_t *b, uint32_t bn) {
  uint32_t n = an < bn ? an : bn;
  for (uint32_t i = 0; i < n; ++i) if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
  return an == bn ? 0 : (an < bn ? -1 : 1);
}
static const dnssec_key_t *find_key(const dnssec_keyset_t *keys, uint16_t tag, uint8_t algorithm) {
  if (keys == 0) return 0;
  for (uint32_t i = 0; i < keys->count; ++i)
    if (keys->keys[i].key_tag == tag && keys->keys[i].algorithm == algorithm) return &keys->keys[i];
  return 0;
}
static int verify_signature(const dnssec_key_t *key, uint8_t algorithm,
                            const uint8_t *signed_data, uint32_t signed_length,
                            const uint8_t *signature, uint32_t signature_length) {
  if (key == 0 || key->rdata_length < 5U || key->rdata[3] != algorithm) return 0;
  if (algorithm == 8U) {
    uint32_t exponent_length = key->rdata[4]; uint32_t offset = 5U;
    if (exponent_length == 0U) { if (key->rdata_length < 7U) return 0; exponent_length = get_be16(key->rdata + 5U); offset = 7U; }
    if (exponent_length == 0U || offset + exponent_length >= key->rdata_length) return 0;
    br_rsa_public_key pk = {(unsigned char *)(key->rdata + offset + exponent_length), key->rdata_length - offset - exponent_length,
                            (unsigned char *)(key->rdata + offset), exponent_length};
    /* BearSSL's low-level PKCS#1 helper consumes a length-prefixed OID. */
    static const unsigned char oid[] = {9U,0x60U,0x86U,0x48U,0x01U,0x65U,0x03U,0x04U,0x02U,0x01U};
    uint8_t expected[32], actual[32]; sha256_hash(signed_data, signed_length, expected);
    if (br_rsa_i31_pkcs1_vrfy(signature, signature_length, oid, sizeof(expected), &pk, actual) == 0U) return 0;
    for (uint32_t i = 0; i < sizeof(expected); ++i) if (expected[i] != actual[i]) return 0;
    return 1;
  }
  if (algorithm == 13U || algorithm == 14U) {
    uint32_t point_len = algorithm == 13U ? 64U : 96U;
    uint32_t hash_len = algorithm == 13U ? 32U : 48U;
    if (key->rdata_length != 4U + point_len || signature_length != point_len) return 0;
    uint8_t point[97], hash[48]; point[0] = 0x04U; copy_bytes(point + 1U, key->rdata + 4U, point_len);
    br_ec_public_key pk = {algorithm == 13U ? BR_EC_secp256r1 : BR_EC_secp384r1, point, point_len + 1U};
    if (algorithm == 13U) sha256_hash(signed_data, signed_length, hash);
    else { br_sha384_context ctx; br_sha384_init(&ctx); br_sha384_update(&ctx, signed_data, signed_length); br_sha384_out(&ctx, hash); }
    return br_ecdsa_i31_vrfy_raw(&br_ec_prime_i31, hash, hash_len, &pk, signature, signature_length) != 0U;
  }
  if (algorithm == 15U) {
    return key->rdata_length == 36U && signature_length == 64U && signed_length <= UINT32_MAX &&
        ed25519_verify(signature, signed_data, signed_length, key->rdata + 4U) == 0;
  }
  return 0;
}

static int verify_rrset(const uint8_t *message, uint32_t length,
                        const char *owner, uint16_t type,
                        const dnssec_keyset_t *keys, uint64_t wall_time_ns) {
  if (wall_time_ns < DNSSEC_MIN_WALL_TIME) return 0;
  uint32_t now = (uint32_t)(wall_time_ns / UINT64_C(1000000000));
  for (uint32_t si = 0; si < g_record_count; ++si) {
    const dnssec_rr_t *sig_rr = &g_records[si];
    if (sig_rr->type != DNSSEC_TYPE_RRSIG || !name_equal(sig_rr->owner, owner) || sig_rr->rdata_length < 19U) continue;
    const uint8_t *r = sig_rr->rdata; uint16_t covered = get_be16(r);
    uint8_t algorithm = r[2], labels = r[3]; uint32_t expiration = get_be32(r + 8U), inception = get_be32(r + 12U); uint16_t key_tag = get_be16(r + 16U);
    if (covered != type || labels != name_labels(owner) || (int32_t)(now - inception) < 0 || (int32_t)(expiration - now) < 0) continue;
    char signer[XAIOS_DNS_MAX_NAME]; int signature_offset = dns_decode_name(message, length, (uint32_t)(r + 18U - message), signer, sizeof(signer));
    if (signature_offset < 0 || !name_equal(signer, keys->owner)) continue;
    const dnssec_key_t *key = find_key(keys, key_tag, algorithm); if (key == 0) continue;
    uint32_t position = 0U, signer_wire = 0U; uint8_t owner_wire[256], signer_buf[256];
    if (canonical_name(owner, owner_wire, sizeof(owner_wire), &signer_wire) != 0 || append(&position, r, 18U) != 0 ||
        canonical_name(signer, signer_buf, sizeof(signer_buf), &signer_wire) != 0 || append(&position, signer_buf, signer_wire) != 0) continue;
    uint32_t selected[DNSSEC_MAX_RRSET], selected_count = 0U;
    for (uint32_t i = 0; i < g_record_count; ++i) if (g_records[i].type == type && g_records[i].rr_class == XAIOS_DNS_CLASS_IN && name_equal(g_records[i].owner, owner)) {
      if (selected_count == DNSSEC_MAX_RRSET) { selected_count = 0U; break; } selected[selected_count++] = i;
    }
    if (selected_count == 0U) continue;
    for (uint32_t i = 0; i < selected_count; ++i) for (uint32_t j = i + 1U; j < selected_count; ++j) {
      uint8_t a[2048], b[2048]; uint32_t an = 0U, bn = 0U;
      if (canonical_rdata(message, length, &g_records[selected[i]], a, sizeof(a), &an) != 0 || canonical_rdata(message, length, &g_records[selected[j]], b, sizeof(b), &bn) != 0) { selected_count = 0U; break; }
      if (rdata_compare(a, an, b, bn) > 0) { uint32_t t = selected[i]; selected[i] = selected[j]; selected[j] = t; }
    }
    if (selected_count == 0U) continue;
    for (uint32_t i = 0; i < selected_count; ++i) {
      const dnssec_rr_t *rr = &g_records[selected[i]]; uint8_t rdata[2048]; uint32_t rdata_len = 0U, owner_len = 0U, fixed = 0U;
      if (canonical_rdata(message, length, rr, rdata, sizeof(rdata), &rdata_len) != 0 || canonical_name(owner, owner_wire, sizeof(owner_wire), &owner_len) != 0) { position = DNSSEC_MAX_SIGNED + 1U; break; }
      uint8_t header[10]; put_be16(header, type); put_be16(header + 2U, XAIOS_DNS_CLASS_IN); put_be32(header + 4U, get_be32(r + 4U)); put_be16(header + 8U, (uint16_t)rdata_len); fixed = sizeof(header);
      if (append(&position, owner_wire, owner_len) != 0 || append(&position, header, fixed) != 0 || append(&position, rdata, rdata_len) != 0) break;
    }
    if (position > DNSSEC_MAX_SIGNED) continue;
    uint32_t sig_pos = (uint32_t)signature_offset;
    if (sig_pos > length || sig_pos < (uint32_t)(r - message) || sig_pos - (uint32_t)(r - message) > sig_rr->rdata_length ||
        sig_rr->rdata_length - (sig_pos - (uint32_t)(r - message)) == 0U) continue;
    if (verify_signature(key, algorithm, g_signed, position, message + sig_pos, sig_rr->rdata_length - (sig_pos - (uint32_t)(r - message)))) return 1;
  }
  return 0;
}

void dnssec_init(void) {
  zero_bytes(g_anchors, sizeof(g_anchors));
  g_anchor_count = 2U;
  g_anchors[0].key_tag = 20326U; g_anchors[0].algorithm = 8U; g_anchors[0].digest_type = 2U; g_anchors[0].digest_length = sizeof(k_root_20326_ds); copy_bytes(g_anchors[0].digest, k_root_20326_ds, sizeof(k_root_20326_ds));
  g_anchors[1].key_tag = 38696U; g_anchors[1].algorithm = 8U; g_anchors[1].digest_type = 2U; g_anchors[1].digest_length = sizeof(k_root_38696_ds); copy_bytes(g_anchors[1].digest, k_root_38696_ds, sizeof(k_root_38696_ds));
}
xaios_status_t dnssec_set_trust_anchors(const dnssec_ds_t *anchors, uint32_t count) {
  if (anchors == 0 || count == 0U || count > sizeof(g_anchors) / sizeof(g_anchors[0])) return XAIOS_ERR_INVALID;
  for (uint32_t i = 0; i < count; ++i) if (anchors[i].digest_length == 0U || anchors[i].digest_length > XAIOS_DNSSEC_MAX_DS_DIGEST) return XAIOS_ERR_INVALID;
  copy_bytes(g_anchors, anchors, count * sizeof(g_anchors[0])); g_anchor_count = count; return XAIOS_OK;
}

xaios_status_t dnssec_verify_dnskey(const uint8_t *message, uint32_t length, const char *zone, const dnssec_dsset_t *parent_ds, uint64_t wall_time_ns, dnssec_keyset_t *out) {
  if (zone == 0 || out == 0 || parse_records(message, length) != 0) return XAIOS_ERR_INVALID;
  zero_bytes(out, sizeof(*out)); uint32_t oi = 0U; while (oi + 1U < sizeof(out->owner) && zone[oi]) { out->owner[oi] = zone[oi]; ++oi; } out->owner[oi] = '\0';
  for (uint32_t i = 0; i < g_record_count; ++i) { const dnssec_rr_t *rr = &g_records[i]; if (rr->type != DNSSEC_TYPE_DNSKEY || rr->rr_class != XAIOS_DNS_CLASS_IN || !name_equal(rr->owner, zone) || rr->rdata_length < 5U) continue; if (out->count == XAIOS_DNSSEC_MAX_KEYS || rr->rdata_length > XAIOS_DNSSEC_MAX_KEY_RDATA) return XAIOS_ERR_INVALID; dnssec_key_t *key = &out->keys[out->count++]; key->key_tag = dnskey_tag(rr->rdata, rr->rdata_length); key->algorithm = rr->rdata[3]; key->rdata_length = rr->rdata_length; copy_bytes(key->rdata, rr->rdata, rr->rdata_length); }
  if (out->count == 0U || !verify_rrset(message, length, zone, DNSSEC_TYPE_DNSKEY, out, wall_time_ns)) return XAIOS_ERR_INVALID;
  if (parent_ds != 0) { for (uint32_t i = 0; i < out->count; ++i) if (key_matches_ds(zone, &out->keys[i], parent_ds)) return XAIOS_OK; return XAIOS_ERR_INVALID; }
  dnssec_dsset_t anchors; zero_bytes(&anchors, sizeof(anchors)); anchors.count = (uint8_t)g_anchor_count;
  anchors.owner[0] = '\0';
  for (uint32_t i = 0; i < g_anchor_count; ++i) anchors.records[i] = g_anchors[i];
  for (uint32_t i = 0; i < out->count; ++i) if (key_matches_ds(zone, &out->keys[i], &anchors)) return XAIOS_OK;
  return XAIOS_ERR_INVALID;
}
xaios_status_t dnssec_verify_ds(const uint8_t *message, uint32_t length, const char *child, const dnssec_keyset_t *parent, uint64_t wall_time_ns, dnssec_dsset_t *out) {
  if (child == 0 || parent == 0 || out == 0 || parse_records(message, length) != 0 || !verify_rrset(message, length, child, DNSSEC_TYPE_DS, parent, wall_time_ns)) return XAIOS_ERR_INVALID;
  zero_bytes(out, sizeof(*out)); uint32_t oi = 0U; while (oi + 1U < sizeof(out->owner) && child[oi]) { out->owner[oi] = child[oi]; ++oi; } out->owner[oi] = '\0';
  for (uint32_t i = 0; i < g_record_count; ++i) { const dnssec_rr_t *rr = &g_records[i]; if (rr->type != DNSSEC_TYPE_DS || !name_equal(rr->owner, child) || rr->rdata_length < 4U) continue; uint32_t digest_len = rr->rdata_length - 4U; if (out->count == XAIOS_DNSSEC_MAX_DS || digest_len > XAIOS_DNSSEC_MAX_DS_DIGEST) return XAIOS_ERR_INVALID; dnssec_ds_t *d = &out->records[out->count++]; d->key_tag = get_be16(rr->rdata); d->algorithm = rr->rdata[2]; d->digest_type = rr->rdata[3]; d->digest_length = (uint8_t)digest_len; copy_bytes(d->digest, rr->rdata + 4U, digest_len); }
  return out->count ? XAIOS_OK : XAIOS_ERR_INVALID;
}
xaios_status_t dnssec_verify_address(const uint8_t *message, uint32_t length, const char *hostname, uint16_t type, const dnssec_keyset_t *keys, uint64_t wall_time_ns, uint8_t *out_address, uint32_t *out_ttl) {
  uint32_t need = type == XAIOS_DNS_TYPE_A ? 4U : type == XAIOS_DNS_TYPE_AAAA ? 16U : 0U;
  if (hostname == 0 || keys == 0 || out_address == 0 || out_ttl == 0 || need == 0U || parse_records(message, length) != 0 || !verify_rrset(message, length, hostname, type, keys, wall_time_ns)) return XAIOS_ERR_INVALID;
  for (uint32_t i = 0; i < g_record_count; ++i) if (g_records[i].type == type && name_equal(g_records[i].owner, hostname) && g_records[i].rdata_length == need) { copy_bytes(out_address, g_records[i].rdata, need); *out_ttl = g_records[i].ttl; return XAIOS_OK; }
  return XAIOS_ERR_INVALID;
}
xaios_status_t dnssec_verify_nodata(const uint8_t *message, uint32_t length, const char *hostname, uint16_t type, const dnssec_keyset_t *keys, uint64_t wall_time_ns) {
  if (hostname == 0 || keys == 0 || parse_records(message, length) != 0) return XAIOS_ERR_INVALID;
  for (uint32_t i = 0; i < g_record_count; ++i) { const dnssec_rr_t *rr = &g_records[i]; if (rr->type != DNSSEC_TYPE_NSEC || !name_equal(rr->owner, hostname) || rr->rdata_length < 2U || !verify_rrset(message, length, rr->owner, DNSSEC_TYPE_NSEC, keys, wall_time_ns)) continue; char next[XAIOS_DNS_MAX_NAME]; int off = dns_decode_name(message, length, (uint32_t)(rr->rdata - message), next, sizeof(next)); if (off < 0) continue; uint32_t consumed = (uint32_t)off - (uint32_t)(rr->rdata - message); if (consumed >= rr->rdata_length) continue; uint32_t p = consumed; int present = 0; while (p < rr->rdata_length) { uint8_t window = rr->rdata[p++]; if (p >= rr->rdata_length) break; uint8_t bitmap_len = rr->rdata[p++]; if (bitmap_len == 0U || bitmap_len > 32U || bitmap_len > rr->rdata_length - p) { present = 1; break; } if ((uint32_t)(type >> 8U) == window) { uint32_t bit = type & 0xffU; if (bit / 8U < bitmap_len && (rr->rdata[p + bit / 8U] & (uint8_t)(0x80U >> (bit & 7U))) != 0U) present = 1; } p += bitmap_len; } if (!present) return XAIOS_OK; }
  return XAIOS_ERR_INVALID;
}
