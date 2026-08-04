#include <xaios/assert.h>
#include <xaios/icmpv6.h>
#include <xaios/ip_addr.h>
#include <xaios/ipv4.h> /* reuse ipv4_checksum() for ones-complement fold */
#include <xaios/ipv6.h>
#include <xaios/klog.h>
#include <xaios/timer.h>

#define XAIOS_IPV6_FRAG_BUCKETS 8U

typedef struct ipv6_frag_bucket {
  uint32_t active;
  uint32_t identification;
  uint8_t next_header;
  uint8_t have_first;
  uint16_t reserved;
  uint64_t first_arrival_ns;
  uint32_t total_len;
  uint32_t received_count;
  uint8_t source[16];
  uint8_t destination[16];
  uint8_t ethernet_header[14];
  uint8_t ipv6_header[XAIOS_IPV6_HEADER_SIZE];
  uint8_t payload[XAIOS_IPV6_MAX_REASSEMBLED_PAYLOAD];
  uint8_t received[XAIOS_IPV6_MAX_REASSEMBLED_PAYLOAD];
} ipv6_frag_bucket_t;

static ipv6_frag_bucket_t g_ipv6_frag_buckets[XAIOS_IPV6_FRAG_BUCKETS];
static uint32_t g_ipv6_fragment_identification = 1U;

static void put_be16(uint8_t *dst, uint16_t value) {
  dst[0] = (uint8_t)(value >> 8U);
  dst[1] = (uint8_t)value;
}

static void put_be32(uint8_t *dst, uint32_t value) {
  dst[0] = (uint8_t)(value >> 24U);
  dst[1] = (uint8_t)(value >> 16U);
  dst[2] = (uint8_t)(value >> 8U);
  dst[3] = (uint8_t)value;
}

static uint16_t get_be16(const uint8_t *src) {
  return (uint16_t)(((uint16_t)src[0] << 8U) | src[1]);
}

static uint32_t get_be32(const uint8_t *src) {
  return ((uint32_t)src[0] << 24U) | ((uint32_t)src[1] << 16U) |
         ((uint32_t)src[2] << 8U) | src[3];
}

static void bytes_copy(void *dst, const void *src, uint64_t size) {
  uint8_t *out = (uint8_t *)dst;
  const uint8_t *in = (const uint8_t *)src;
  for (uint64_t i = 0U; i < size; ++i) out[i] = in[i];
}

static void bytes_zero(void *dst, uint64_t size) {
  uint8_t *out = (uint8_t *)dst;
  for (uint64_t i = 0U; i < size; ++i) out[i] = 0U;
}

void ipv6_build_header(uint8_t *hdr, uint16_t payload_length,
                       uint8_t next_header,
                       const xaios_ip_addr_t *src,
                       const xaios_ip_addr_t *dst) {
  if (hdr == 0 || src == 0 || dst == 0) {
    return;
  }
  /* Version (4 bits) = 6, Traffic Class (8 bits) = 0, Flow Label (20 bits) = 0 */
  put_be32(hdr, XAIOS_IPV6_VERSION_TC_FLOW);
  /* Payload length (excludes the 40-byte header) */
  put_be16(hdr + 4, payload_length);
  /* Next header (protocol) */
  hdr[6] = next_header;
  /* Hop limit */
  hdr[7] = XAIOS_IPV6_DEFAULT_HOP_LIMIT;
  /* Source address (16 bytes) */
  for (uint32_t i = 0; i < 16; ++i) {
    hdr[8 + i] = src->addr[i];
  }
  /* Destination address (16 bytes) */
  for (uint32_t i = 0; i < 16; ++i) {
    hdr[24 + i] = dst->addr[i];
  }
}

int ipv6_parse_header(const uint8_t *hdr, uint64_t hdr_len,
                      uint16_t *payload_length, uint8_t *next_header,
                      xaios_ip_addr_t *src, xaios_ip_addr_t *dst) {
  if (hdr == 0 || hdr_len < XAIOS_IPV6_HEADER_SIZE) {
    return -1;
  }
  /* Verify version nibble = 6 */
  if ((hdr[0] >> 4U) != 6U) {
    return -1;
  }
  if (payload_length != 0) {
    *payload_length = get_be16(hdr + 4);
  }
  if (next_header != 0) {
    *next_header = hdr[6];
  }
  if (src != 0) {
    xaios_ip_addr_from_raw_ipv6(src, hdr + 8);
  }
  if (dst != 0) {
    xaios_ip_addr_from_raw_ipv6(dst, hdr + 24);
  }
  return 0;
}

uint16_t ipv6_pseudo_checksum(const xaios_ip_addr_t *src,
                               const xaios_ip_addr_t *dst,
                               uint8_t next_header,
                               uint32_t upper_layer_length,
                               const uint8_t *payload,
                               uint32_t payload_len) {
  /*
   * IPv6 pseudo-header (RFC 8200 Section 8.1):
   *   16 bytes source address
   *   16 bytes destination address
   *   4 bytes  upper-layer packet length (big-endian)
   *   3 bytes  zero
   *   1 byte   next header
   *   then the upper-layer payload
   */
  uint8_t pseudo[40]; /* 16+16+4+3+1 = 40 */
  for (uint32_t i = 0; i < 16; ++i) {
    pseudo[i] = src->addr[i];
  }
  for (uint32_t i = 0; i < 16; ++i) {
    pseudo[16 + i] = dst->addr[i];
  }
  put_be32(pseudo + 32, upper_layer_length);
  pseudo[36] = 0;
  pseudo[37] = 0;
  pseudo[38] = 0;
  pseudo[39] = next_header;

  uint64_t sum = 0;
  for (uint32_t i = 0; i < 40; i += 2U) {
    sum += ((uint64_t)pseudo[i] << 8U) | (uint64_t)pseudo[i + 1U];
  }
  if (payload != 0) {
    for (uint32_t i = 0; i + 1U < payload_len; i += 2U) {
      sum += ((uint64_t)payload[i] << 8U) | (uint64_t)payload[i + 1U];
    }
    if ((payload_len & 1U) != 0U) {
      sum += ((uint64_t)payload[payload_len - 1U] << 8U);
    }
  }
  while ((sum >> 16U) != 0U) {
    sum = (sum & 0xFFFFU) + (sum >> 16U);
  }
  return (uint16_t)(~sum & 0xFFFFU);
}

void ipv6_link_local_from_mac(xaios_ip_addr_t *addr, const uint8_t mac[6]) {
  if (addr == 0 || mac == 0) {
    return;
  }
  addr->family = XAIOS_IP_FAMILY_V6;
  addr->addr[0] = 0xFE;
  addr->addr[1] = 0x80;
  for (uint32_t i = 2; i < 8; ++i) {
    addr->addr[i] = 0;
  }
  /* EUI-64: insert ff:fe in the middle, flip bit 1 of byte 0 */
  addr->addr[8]  = mac[0] ^ 0x02U;
  addr->addr[9]  = mac[1];
  addr->addr[10] = mac[2];
  addr->addr[11] = 0xFF;
  addr->addr[12] = 0xFE;
  addr->addr[13] = mac[3];
  addr->addr[14] = mac[4];
  addr->addr[15] = mac[5];
}

/* ---- C1: IPv6 Extension Header Parsing ---- */
/*
 * Walk the IPv6 extension header chain starting at ip6_hdr (which must
 * point to the fixed 40-byte IPv6 header). The chain begins at offset 40.
 *
 * Returns 0 on success with out_next_hdr set to the final (non-extension)
 *   protocol number and out_upper_layer pointing to the start of that
 *   upper-layer payload.
 * Returns -1 on any parse error (truncated packet, unsupported extension, etc.).
 */
int ipv6_walk_extension_headers(const uint8_t *ip6_hdr, uint64_t hdr_len,
                                 uint8_t *out_next_hdr,
                                 const uint8_t **out_upper_layer,
                                 uint32_t *out_upper_len) {
  if (ip6_hdr == 0 || hdr_len < XAIOS_IPV6_HEADER_SIZE ||
      out_next_hdr == 0 || out_upper_layer == 0) {
    return -1;
  }

  uint64_t offset = XAIOS_IPV6_HEADER_SIZE; /* 40 bytes past the fixed header */
  uint8_t next_hdr = ip6_hdr[6];            /* first extension or transport */

  for (uint32_t depth = 0; depth < XAIOS_IPV6_MAX_EXTENSION_CHAIN_DEPTH; ++depth) {
    /* Check if we have found the real upper-layer protocol */
    if (next_hdr != XAIOS_IPV6_NEXT_HOP_BY_HOP &&
        next_hdr != XAIOS_IPV6_NEXT_ROUTING &&
        next_hdr != XAIOS_IPV6_NEXT_FRAGMENT &&
        next_hdr != XAIOS_IPV6_NEXT_AH &&
        next_hdr != XAIOS_IPV6_NEXT_ESP &&
        next_hdr != XAIOS_IPV6_NEXT_DEST) {
      /* Not an extension header — this is the upper layer protocol */
      if (offset > hdr_len) {
        return -1;
      }
      *out_next_hdr = next_hdr;
      *out_upper_layer = ip6_hdr + offset;
      if (out_upper_len != 0) {
        *out_upper_len = (uint32_t)(hdr_len - offset);
      }
      return 0;
    }

    /* Ensure we can read at least 2 bytes of the current extension header */
    if (offset + 2 > hdr_len) {
      return -1;
    }

    uint8_t ext_next    = ip6_hdr[offset];     /* next header after this ext */
    uint8_t ext_len_byte = ip6_hdr[offset + 1]; /* length field */
    uint64_t ext_size = 0;

    if (next_hdr == XAIOS_IPV6_NEXT_FRAGMENT) {
      /* Fragment header: always 8 bytes */
      ext_size = XAIOS_IPV6_FRAG_HEADER_SIZE;
    } else if (next_hdr == XAIOS_IPV6_NEXT_AH) {
      /* AH (RFC 4302): Payload_Len = total/4 - 2 */
      ext_size = (uint64_t)(ext_len_byte + 2) * 4;
    } else if (next_hdr == XAIOS_IPV6_NEXT_ESP) {
      /* ESP (RFC 4303): no parseable length; cannot skip without decrypting */
      return -1;
    } else {
      /* Hop-by-Hop (0), Routing (43), Destination (60):
       * Hdr Ext Len in 8-octet units, not counting first 8 octets.
       * Total = (ext_len_byte + 1) * 8 */
      ext_size = (uint64_t)(ext_len_byte + 1) * 8;
    }

    if (offset + ext_size > hdr_len || ext_size == 0) {
      return -1; /* truncated or invalid */
    }

    offset += ext_size;
    next_hdr = ext_next; /* next header comes from the extension's own first byte */
  }

  return -1; /* exceeded max extension chain depth */
}

/* ---- C2: IPv6 Fragmentation ---- */
int ipv6_is_fragment_v6(const uint8_t *frame, uint64_t frame_len) {
  if (frame == 0 || frame_len < XAIOS_IPV6_HEADER_SIZE + 14U) {
    return 0;
  }
  /* Check ethertype */
  if (get_be16(frame + 12) != XAIOS_IPV6_ETHERTYPE) {
    return 0;
  }
  const uint8_t *ip6 = frame + 14;
  uint64_t ip6_len = frame_len - 14;
  if (ip6_len < XAIOS_IPV6_HEADER_SIZE) {
    return 0;
  }
  uint8_t nh = ip6[6];
  uint64_t offset = XAIOS_IPV6_HEADER_SIZE;

  for (uint32_t depth = 0; depth < XAIOS_IPV6_MAX_EXTENSION_CHAIN_DEPTH; ++depth) {
    if (nh == XAIOS_IPV6_NEXT_FRAGMENT) {
      return 1; /* found fragment header */
    }
    if (nh != XAIOS_IPV6_NEXT_HOP_BY_HOP && nh != XAIOS_IPV6_NEXT_ROUTING &&
        nh != XAIOS_IPV6_NEXT_AH && nh != XAIOS_IPV6_NEXT_ESP &&
        nh != XAIOS_IPV6_NEXT_DEST) {
      return 0; /* no fragment header in chain */
    }
    if (offset + 2 > ip6_len) return 0;

    uint8_t ext_next = ip6[offset];
    uint8_t ext_len  = ip6[offset + 1];
    uint64_t skip;

    if (nh == XAIOS_IPV6_NEXT_AH) {
      skip = (uint64_t)(ext_len + 2) * 4;
    } else if (nh == XAIOS_IPV6_NEXT_ESP) {
      return 0; /* can't parse through ESP */
    } else {
      skip = (uint64_t)(ext_len + 1) * 8;
    }
    if (offset + skip > ip6_len) return 0;
    offset += skip;
    nh = ext_next;
  }
  return 0;
}

xaios_status_t ipv6_fragment_v6(const uint8_t *frame, uint64_t frame_len,
                                 uint8_t *out_buf, uint64_t *out_len,
                                 uint64_t out_capacity) {
  if (frame == 0 || out_buf == 0 || out_len == 0 || frame_len < 54U ||
      get_be16(frame + 12U) != XAIOS_IPV6_ETHERTYPE ||
      (frame[14U] >> 4U) != 6U) {
    return XAIOS_ERR_INVALID;
  }
  const uint8_t *ip6 = frame + 14U;
  uint16_t payload_len = get_be16(ip6 + 4U);
  uint64_t exact_len = 14U + XAIOS_IPV6_HEADER_SIZE + payload_len;
  if (exact_len > frame_len ||
      payload_len > XAIOS_IPV6_MAX_REASSEMBLED_PAYLOAD) {
    return XAIOS_ERR_INVALID;
  }
  const uint32_t fragment_payload =
      XAIOS_IPV6_MIN_MTU - XAIOS_IPV6_HEADER_SIZE -
      XAIOS_IPV6_FRAG_HEADER_SIZE;
  if (payload_len <= fragment_payload) {
    if (out_capacity < exact_len) return XAIOS_ERR_NO_MEMORY;
    bytes_copy(out_buf, frame, exact_len);
    *out_len = exact_len;
    return XAIOS_OK;
  }
  if (ip6[6U] == XAIOS_IPV6_NEXT_FRAGMENT) return XAIOS_ERR_INVALID;

  uint32_t identification =
      __atomic_fetch_add(&g_ipv6_fragment_identification, 1U,
                         __ATOMIC_RELAXED);
  if (identification == 0U) {
    identification = __atomic_fetch_add(&g_ipv6_fragment_identification, 1U,
                                         __ATOMIC_RELAXED);
  }
  uint64_t written = 0U;
  uint32_t offset = 0U;
  while (offset < payload_len) {
    uint32_t chunk = payload_len - offset;
    if (chunk > fragment_payload) chunk = fragment_payload;
    uint32_t more = offset + chunk < payload_len;
    uint64_t frame_bytes = 14U + XAIOS_IPV6_HEADER_SIZE +
                           XAIOS_IPV6_FRAG_HEADER_SIZE + chunk;
    if (written + frame_bytes > out_capacity) return XAIOS_ERR_NO_MEMORY;
    bytes_copy(out_buf + written, frame, 14U + XAIOS_IPV6_HEADER_SIZE);
    uint8_t *fragment_ip6 = out_buf + written + 14U;
    put_be16(fragment_ip6 + 4U,
             (uint16_t)(XAIOS_IPV6_FRAG_HEADER_SIZE + chunk));
    fragment_ip6[6U] = XAIOS_IPV6_NEXT_FRAGMENT;
    uint8_t *fragment_header = fragment_ip6 + XAIOS_IPV6_HEADER_SIZE;
    fragment_header[0] = ip6[6U];
    fragment_header[1] = 0U;
    put_be16(fragment_header + 2U,
             (uint16_t)((offset & UINT32_C(0xfff8)) | more));
    put_be32(fragment_header + 4U, identification);
    bytes_copy(fragment_header + XAIOS_IPV6_FRAG_HEADER_SIZE,
               ip6 + XAIOS_IPV6_HEADER_SIZE + offset, chunk);
    written += frame_bytes;
    offset += chunk;
  }
  *out_len = written;
  return XAIOS_OK;
}

static int ipv6_address_equal_raw(const uint8_t *left, const uint8_t *right) {
  for (uint32_t i = 0U; i < 16U; ++i) {
    if (left[i] != right[i]) return 0;
  }
  return 1;
}

static void clear_ipv6_bucket(ipv6_frag_bucket_t *bucket) {
  bytes_zero(bucket, sizeof(*bucket));
}

static ipv6_frag_bucket_t *find_or_allocate_ipv6_bucket(
    const uint8_t source[16], const uint8_t destination[16],
    uint32_t identification, uint8_t next_header, uint64_t now_ns) {
  ipv6_frag_bucket_t *free_bucket = 0;
  ipv6_frag_bucket_t *oldest = 0;
  for (uint32_t i = 0U; i < XAIOS_IPV6_FRAG_BUCKETS; ++i) {
    ipv6_frag_bucket_t *bucket = &g_ipv6_frag_buckets[i];
    if (bucket->active != 0U && now_ns != 0U &&
        now_ns - bucket->first_arrival_ns >= XAIOS_IPV6_FRAG_TIMEOUT_NS) {
      clear_ipv6_bucket(bucket);
    }
    if (bucket->active != 0U &&
        bucket->identification == identification &&
        bucket->next_header == next_header &&
        ipv6_address_equal_raw(bucket->source, source) &&
        ipv6_address_equal_raw(bucket->destination, destination)) {
      return bucket;
    }
    if (bucket->active == 0U && free_bucket == 0) free_bucket = bucket;
    if (bucket->active != 0U &&
        (oldest == 0 || bucket->first_arrival_ns < oldest->first_arrival_ns)) {
      oldest = bucket;
    }
  }
  ipv6_frag_bucket_t *bucket = free_bucket != 0 ? free_bucket : oldest;
  if (bucket == 0) return 0;
  clear_ipv6_bucket(bucket);
  bucket->active = 1U;
  bucket->identification = identification;
  bucket->next_header = next_header;
  bucket->first_arrival_ns = now_ns;
  bytes_copy(bucket->source, source, 16U);
  bytes_copy(bucket->destination, destination, 16U);
  return bucket;
}

xaios_status_t ipv6_reassemble_v6(uint8_t *frame, uint64_t *frame_len) {
  if (frame == 0 || frame_len == 0 || *frame_len < 54U ||
      get_be16(frame + 12U) != XAIOS_IPV6_ETHERTYPE ||
      (frame[14U] >> 4U) != 6U) {
    return XAIOS_ERR_INVALID;
  }
  if (!ipv6_is_fragment_v6(frame, *frame_len)) return XAIOS_OK;
  uint8_t *ip6 = frame + 14U;
  if (ip6[6U] != XAIOS_IPV6_NEXT_FRAGMENT) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  uint16_t payload_len = get_be16(ip6 + 4U);
  if (payload_len < XAIOS_IPV6_FRAG_HEADER_SIZE ||
      14U + XAIOS_IPV6_HEADER_SIZE + payload_len > *frame_len) {
    return XAIOS_ERR_INVALID;
  }
  uint8_t *fh = ip6 + XAIOS_IPV6_HEADER_SIZE;
  uint16_t offset_flags = get_be16(fh + 2U);
  uint32_t offset = offset_flags & UINT16_C(0xfff8);
  uint32_t more = offset_flags & 1U;
  uint32_t fragment_len = payload_len - XAIOS_IPV6_FRAG_HEADER_SIZE;
  uint32_t end = offset + fragment_len;
  if ((offset_flags & UINT16_C(0x0006)) != 0U || fragment_len == 0U ||
      (more != 0U && (fragment_len & 7U) != 0U) || end < offset ||
      end > XAIOS_IPV6_MAX_REASSEMBLED_PAYLOAD) {
    return XAIOS_ERR_INVALID;
  }

  ipv6_frag_bucket_t *bucket = find_or_allocate_ipv6_bucket(
      ip6 + 8U, ip6 + 24U, get_be32(fh + 4U), fh[0], timer_now_ns());
  if (bucket == 0) return XAIOS_ERR_NO_MEMORY;
  if (more == 0U) {
    if (bucket->total_len != 0U && bucket->total_len != end) {
      clear_ipv6_bucket(bucket);
      return XAIOS_ERR_INVALID;
    }
    bucket->total_len = end;
  }
  if (bucket->total_len != 0U && end > bucket->total_len) {
    clear_ipv6_bucket(bucket);
    return XAIOS_ERR_INVALID;
  }

  const uint8_t *fragment_data = fh + XAIOS_IPV6_FRAG_HEADER_SIZE;
  for (uint32_t i = 0U; i < fragment_len; ++i) {
    uint32_t position = offset + i;
    if (bucket->received[position] != 0U &&
        bucket->payload[position] != fragment_data[i]) {
      clear_ipv6_bucket(bucket);
      return XAIOS_ERR_INVALID;
    }
  }
  for (uint32_t i = 0U; i < fragment_len; ++i) {
    uint32_t position = offset + i;
    if (bucket->received[position] == 0U) {
      bucket->received[position] = 1U;
      bucket->payload[position] = fragment_data[i];
      ++bucket->received_count;
    }
  }
  if (offset == 0U) {
    bytes_copy(bucket->ethernet_header, frame, 14U);
    bytes_copy(bucket->ipv6_header, ip6, XAIOS_IPV6_HEADER_SIZE);
    bucket->have_first = 1U;
  }
  if (bucket->total_len == 0U || bucket->have_first == 0U ||
      bucket->received_count < bucket->total_len) {
    return XAIOS_ERR_BUSY;
  }
  for (uint32_t i = 0U; i < bucket->total_len; ++i) {
    if (bucket->received[i] == 0U) return XAIOS_ERR_BUSY;
  }

  bytes_copy(frame, bucket->ethernet_header, 14U);
  bytes_copy(frame + 14U, bucket->ipv6_header, XAIOS_IPV6_HEADER_SIZE);
  frame[20U] = bucket->next_header;
  put_be16(frame + 18U, (uint16_t)bucket->total_len);
  bytes_copy(frame + 54U, bucket->payload, bucket->total_len);
  *frame_len = 54U + bucket->total_len;
  clear_ipv6_bucket(bucket);
  return XAIOS_OK;
}

void ipv6_frag_init(void) {
  bytes_zero(g_ipv6_frag_buckets, sizeof(g_ipv6_frag_buckets));
}

void ipv6_self_test(void) {
  /* Test header build */
  uint8_t hdr[40];
  xaios_ip_addr_t src;
  src.family = XAIOS_IP_FAMILY_V6;
  for (uint32_t i = 0; i < 16; ++i) {
    src.addr[i] = 0;
  }
  src.addr[0] = 0xFE;
  src.addr[1] = 0x80;
  src.addr[15] = 0x01;

  xaios_ip_addr_t dst;
  dst.family = XAIOS_IP_FAMILY_V6;
  for (uint32_t i = 0; i < 16; ++i) {
    dst.addr[i] = 0;
  }
  dst.addr[0] = 0xFE;
  dst.addr[1] = 0x80;
  dst.addr[15] = 0x02;

  ipv6_build_header(hdr, 8, XAIOS_IPV6_NEXT_ICMPV6, &src, &dst);

  /* Verify version nibble = 6 */
  kassert((hdr[0] >> 4U) == 6U);
  /* Payload length = 8 */
  kassert(get_be16(hdr + 4) == 8);
  /* Next header = 58 (ICMPv6) */
  kassert(hdr[6] == 58);
  /* Hop limit = 64 */
  kassert(hdr[7] == 64);
  /* Source address: fe80::1 */
  kassert(hdr[8] == 0xFE && hdr[9] == 0x80);
  kassert(hdr[23] == 0x01);
  /* Destination address: fe80::2 */
  kassert(hdr[24] == 0xFE && hdr[25] == 0x80);
  kassert(hdr[39] == 0x02);

  /* Test parse round-trip */
  uint16_t plen = 0;
  uint8_t nh = 0;
  xaios_ip_addr_t parsed_src;
  xaios_ip_addr_t parsed_dst;
  kassert(ipv6_parse_header(hdr, 40, &plen, &nh, &parsed_src, &parsed_dst) == 0);
  kassert(plen == 8);
  kassert(nh == 58);
  kassert(xaios_ip_addr_equal(&parsed_src, &src));
  kassert(xaios_ip_addr_equal(&parsed_dst, &dst));

  /* Test pseudo-header checksum */
  uint8_t payload[8] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01};
  uint16_t cksum = ipv6_pseudo_checksum(&src, &dst, XAIOS_IPV6_NEXT_ICMPV6,
                                          8, payload, 8);
  kassert(cksum != 0);
  put_be16(payload + 2, cksum);
  uint16_t verify = ipv6_pseudo_checksum(&src, &dst, XAIOS_IPV6_NEXT_ICMPV6,
                                           8, payload, 8);
  kassert(verify == 0);

  /* Test link-local from MAC */
  uint8_t mac[6] = {0x52, 0x54, 0x00, 0x12, 0x34, 0x56};
  xaios_ip_addr_t ll;
  ipv6_link_local_from_mac(&ll, mac);
  kassert(ll.family == XAIOS_IP_FAMILY_V6);
  kassert(ll.addr[0] == 0xFE && ll.addr[1] == 0x80);
  kassert(ll.addr[8] == (0x52 ^ 0x02));
  kassert(ll.addr[11] == 0xFF && ll.addr[12] == 0xFE);
  kassert(ll.addr[15] == 0x56);

  /* ---- C1 Test: Extension header walk ---- */
  {
    /* Build a packet with: IPv6 -> Hop-by-Hop -> Routing -> ICMPv6
     * IPv6 header: next_header = 0 (HBH)
     * HBH: next_header = 43 (Routing), Hdr Ext Len = 0 (8 bytes)
     * Routing: next_header = 58 (ICMPv6), Hdr Ext Len = 0 (8 bytes)
     * Total IPv6 area = 40 + 8 + 8 = 56 bytes
     * ICMPv6 follows at offset 56
     */
    uint8_t pkt[80];
    xaios_ip_addr_t pkt_src, pkt_dst;
    pkt_src.family = XAIOS_IP_FAMILY_V6;
    for (uint32_t i = 0; i < 16; ++i) pkt_src.addr[i] = 0;
    pkt_dst.family = XAIOS_IP_FAMILY_V6;
    for (uint32_t i = 0; i < 16; ++i) pkt_dst.addr[i] = 0;
    pkt_src.addr[15] = 0x01;
    pkt_dst.addr[15] = 0x02;

    ipv6_build_header(pkt, 40, XAIOS_IPV6_NEXT_HOP_BY_HOP, &pkt_src, &pkt_dst);

    /* HBH extension at offset 40 */
    pkt[40] = XAIOS_IPV6_NEXT_ROUTING; /* next = 43 */
    pkt[41] = 0;                       /* Hdr Ext Len = 0 => 8 bytes */

    /* Routing extension at offset 48 */
    pkt[48] = XAIOS_IPV6_NEXT_ICMPV6; /* next = 58 */
    pkt[49] = 0;                      /* Hdr Ext Len = 0 => 8 bytes */

    /* ICMPv6 echo request at offset 56 (rest zeroed) */
    pkt[56] = XAIOS_ICMPV6_ECHO_REQUEST;

    uint64_t ip6_total = 40U + 8U + 8U + 4U; /* 60 bytes total IP area */
    uint8_t out_nh = 0;
    const uint8_t *out_ul = 0;
    uint32_t out_ul_len = 0;

    int ret = ipv6_walk_extension_headers(pkt, ip6_total,
                                           &out_nh, &out_ul, &out_ul_len);
    kassert(ret == 0);
    kassert(out_nh == XAIOS_IPV6_NEXT_ICMPV6);
    kassert(out_ul == pkt + 56);
    kassert(out_ul_len == 4);

    /* Test with Fragment header in the chain */
    pkt[40] = XAIOS_IPV6_NEXT_FRAGMENT;  /* HBH -> Fragment */
    pkt[48] = XAIOS_IPV6_NEXT_ICMPV6;     /* Fragment -> ICMPv6 */

    ret = ipv6_walk_extension_headers(pkt, ip6_total,
                                       &out_nh, &out_ul, &out_ul_len);
    kassert(ret == 0);
    kassert(out_nh == XAIOS_IPV6_NEXT_ICMPV6);
    kassert(out_ul == pkt + 56); /* HBH(8) + Frag(8) at offset 40+16=56 */

    klog("ipv6: ext-header-walk passed\n");
  }

  /* ---- C2 Test: out-of-order fragmentation/reassembly ---- */
  {
    uint8_t fbuf[1514];
    bytes_zero(fbuf, sizeof(fbuf));
    xaios_ip_addr_t f_src, f_dst;
    f_src.family = XAIOS_IP_FAMILY_V6;
    for (uint32_t i = 0; i < 16; ++i) f_src.addr[i] = 0;
    f_dst.family = XAIOS_IP_FAMILY_V6;
    for (uint32_t i = 0; i < 16; ++i) f_dst.addr[i] = 0;
    f_src.addr[15] = 0x01;
    f_dst.addr[15] = 0x02;

    for (uint32_t i = 0; i < 6; ++i) {
      fbuf[i] = (uint8_t)(0x60U + i);
      fbuf[6 + i] = (uint8_t)(0x30U + i);
    }
    put_be16(fbuf + 12, XAIOS_IPV6_ETHERTYPE);
    const uint32_t large_payload_len = 1300U;
    ipv6_build_header(fbuf + 14U, large_payload_len, XAIOS_IPV6_NEXT_UDP,
                      &f_src, &f_dst);
    for (uint32_t i = 0U; i < large_payload_len; ++i) {
      fbuf[54U + i] = (uint8_t)(i ^ UINT32_C(0x5a));
    }
    uint8_t fragments[4096];
    uint64_t fragments_len = 0U;
    kassert(ipv6_fragment_v6(fbuf, 54U + large_payload_len, fragments,
                             &fragments_len, sizeof(fragments)) == XAIOS_OK);
    uint64_t first_len = 14U + XAIOS_IPV6_HEADER_SIZE +
                         get_be16(fragments + 18U);
    kassert(first_len < fragments_len);
    uint64_t second_len = fragments_len - first_len;
    uint8_t reassembled[1514];
    bytes_copy(reassembled, fragments + first_len, second_len);
    uint64_t reassembled_len = second_len;
    kassert(ipv6_reassemble_v6(reassembled, &reassembled_len) ==
            XAIOS_ERR_BUSY);
    bytes_copy(reassembled, fragments, first_len);
    reassembled_len = first_len;
    kassert(ipv6_reassemble_v6(reassembled, &reassembled_len) == XAIOS_OK);
    kassert(reassembled_len == 54U + large_payload_len);
    kassert(reassembled[20U] == XAIOS_IPV6_NEXT_UDP);
    for (uint32_t i = 0U; i < large_payload_len; ++i) {
      kassert(reassembled[54U + i] == (uint8_t)(i ^ UINT32_C(0x5a)));
    }
    klog("ipv6: fragmentation/reassembly passed frame=%lu wire=%lu out_of_order=1\n",
         reassembled_len, fragments_len);
  }

  klog("ipv6: self-test passed header=40B plen=%u nh=%u cksum=0x%04x\n",
       plen, nh, cksum);
}
