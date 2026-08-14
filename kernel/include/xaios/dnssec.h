#ifndef XAIOS_DNSSEC_H
#define XAIOS_DNSSEC_H

#include <xaios/status.h>
#include <xaios/types.h>

#define XAIOS_DNSSEC_MAX_KEYS 8U
#define XAIOS_DNSSEC_MAX_KEY_RDATA 1024U
#define XAIOS_DNSSEC_MAX_DS 8U
#define XAIOS_DNSSEC_MAX_DS_DIGEST 64U

typedef struct dnssec_key {
  uint16_t key_tag;
  uint8_t algorithm;
  uint16_t rdata_length;
  uint8_t rdata[XAIOS_DNSSEC_MAX_KEY_RDATA];
} dnssec_key_t;

typedef struct dnssec_keyset {
  char owner[256];
  uint8_t count;
  dnssec_key_t keys[XAIOS_DNSSEC_MAX_KEYS];
} dnssec_keyset_t;

typedef struct dnssec_ds {
  uint16_t key_tag;
  uint8_t algorithm;
  uint8_t digest_type;
  uint8_t digest[XAIOS_DNSSEC_MAX_DS_DIGEST];
  uint8_t digest_length;
} dnssec_ds_t;

typedef struct dnssec_dsset {
  char owner[256];
  uint8_t count;
  dnssec_ds_t records[XAIOS_DNSSEC_MAX_DS];
} dnssec_dsset_t;

/* The built-in root DS anchors are compiled from IANA root-anchors.xml. */
void dnssec_init(void);

/* Test and future signed-update hook. The caller owns the supplied records. */
xaios_status_t dnssec_set_trust_anchors(const dnssec_ds_t *anchors,
                                        uint32_t anchor_count);

/* Verify and extract a DNSKEY RRset. A root keyset is matched against the
 * configured trust anchors; child keysets are matched against parent DS data.
 * All functions fail closed for malformed data, unsupported algorithms, an
 * invalid signature, or an untrusted wall clock. */
xaios_status_t dnssec_verify_dnskey(const uint8_t *message, uint32_t length,
                                    const char *zone,
                                    const dnssec_dsset_t *parent_ds,
                                    uint64_t wall_time_ns,
                                    dnssec_keyset_t *out_keyset);

xaios_status_t dnssec_verify_ds(const uint8_t *message, uint32_t length,
                                const char *child_zone,
                                const dnssec_keyset_t *parent_keys,
                                uint64_t wall_time_ns,
                                dnssec_dsset_t *out_ds);

xaios_status_t dnssec_verify_address(const uint8_t *message, uint32_t length,
                                     const char *hostname, uint16_t type,
                                     const dnssec_keyset_t *keys,
                                     uint64_t wall_time_ns,
                                     uint8_t *out_address,
                                     uint32_t *out_ttl);

/* Verify a signed exact-owner NSEC NODATA proof. NXDOMAIN, NSEC3, and
 * wildcard synthesis are intentionally unsupported and fail closed. */
xaios_status_t dnssec_verify_nodata(const uint8_t *message, uint32_t length,
                                    const char *hostname, uint16_t type,
                                    const dnssec_keyset_t *keys,
                                    uint64_t wall_time_ns);

#endif
