#include <xaios/assert.h>
#include <xaios/icmpv6.h>
#include <xaios/ip_addr.h>
#include <xaios/ipv4.h> /* reuse ipv4_checksum() for ones-complement fold */
#include <xaios/ipv6.h>
#include <xaios/klog.h>

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
  if (!frame || !out_buf || !out_len || frame_len < 54U || out_capacity < frame_len) {
    return XAIOS_ERR_INVALID;
  }
  uint16_t plen = (uint16_t)(frame_len - 14U - XAIOS_IPV6_HEADER_SIZE);
  uint16_t frag_size = 1400U;
  if (plen <= frag_size) {
    for (uint64_t i = 0; i < frame_len; ++i) out_buf[i] = frame[i];
    *out_len = frame_len;
    return XAIOS_OK;
  }
  return XAIOS_ERR_NO_MEMORY; /* fragmentation requires multi-frame output */
}

xaios_status_t ipv6_reassemble_v6(uint8_t *frame, uint64_t *frame_len) {
  if (!frame || !frame_len || *frame_len < 54U) return XAIOS_ERR_INVALID;
  if (!ipv6_is_fragment_v6(frame, *frame_len)) return XAIOS_OK;
  uint8_t *ip6 = frame + 14U;
  /* Fragment reassembly: skip fragment header if offset=0 and MF=0 */
  uint8_t *fh = ip6 + XAIOS_IPV6_HEADER_SIZE;
  uint16_t fh_offset = (uint16_t)(((uint16_t)(fh[2] & 0xF8) << 5U) | fh[3]);
  uint8_t more_frags = fh[2] >> 7U;
  if (fh_offset == 0 && !more_frags) {
    /* Single fragment with MF=0, offset=0 → not really fragmented,
     * just has a Fragment header present. Skip it. */
    uint8_t next_hdr = fh[0];
    uint16_t original = (uint16_t)(((uint16_t)ip6[4] << 8U) | ip6[5]);
    uint16_t remaining = original - 8U;
    for (uint32_t i = 0; i < remaining; ++i)
      ip6[XAIOS_IPV6_HEADER_SIZE + i] = fh[8 + i];
    ip6[6] = next_hdr;
    put_be16(ip6 + 4, remaining);
    *frame_len = 14U + XAIOS_IPV6_HEADER_SIZE + remaining;
    return XAIOS_OK;
  }
  return XAIOS_ERR_NO_MEMORY; /* multi-fragment reassembly not yet implemented */
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

  /* ---- C2 Test: fragment detection ---- */
  {
    uint8_t fbuf[128];
    xaios_ip_addr_t f_src, f_dst;
    f_src.family = XAIOS_IP_FAMILY_V6;
    for (uint32_t i = 0; i < 16; ++i) f_src.addr[i] = 0;
    f_dst.family = XAIOS_IP_FAMILY_V6;
    for (uint32_t i = 0; i < 16; ++i) f_dst.addr[i] = 0;
    f_src.addr[15] = 0x01;
    f_dst.addr[15] = 0x02;

    /* Build a complete ethernet frame with no fragment header */
    for (uint32_t i = 0; i < 6; ++i) {
      fbuf[i] = 0x00;
      fbuf[6 + i] = 0x00;
    }
    put_be16(fbuf + 12, XAIOS_IPV6_ETHERTYPE);
    ipv6_build_header(fbuf + 14, 8, XAIOS_IPV6_NEXT_ICMPV6, &f_src, &f_dst);
    kassert(ipv6_is_fragment_v6(fbuf, 14 + 40 + 8) == 0);

    /* Add a fragment header */
    fbuf[14 + 6] = XAIOS_IPV6_NEXT_FRAGMENT; /* change next header */
    kassert(ipv6_is_fragment_v6(fbuf, 14 + 40 + 8) == 1);

    /* Test reassembly: non-fragment should succeed */
    uint64_t rlen = 14 + 40 + 8;
    fbuf[14 + 6] = XAIOS_IPV6_NEXT_ICMPV6;
    kassert(ipv6_reassemble_v6(fbuf, &rlen) == XAIOS_OK);

    /* Fragmented input is explicitly unsupported. */
    fbuf[14 + 6] = XAIOS_IPV6_NEXT_FRAGMENT;
    kassert(ipv6_reassemble_v6(fbuf, &rlen) == XAIOS_ERR_NO_MEMORY);

    klog("ipv6: fragment detection passed\n");
  }

  klog("ipv6: self-test passed header=40B plen=%u nh=%u cksum=0x%04x\n",
       plen, nh, cksum);
}
