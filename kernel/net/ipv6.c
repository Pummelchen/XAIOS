#include <xaios/assert.h>
#include <xaios/icmpv6.h>
#include <xaios/ip_addr.h>
#include <xaios/ipv4.h> /* reuse ipv4_checksum() for ones-complement fold */
#include <xaios/ipv6.h>
#include <xaios/klog.h>
#include <xaios/timer.h>

#include "ipv6_internal.h"

void ipv6_put_be16(uint8_t *dst, uint16_t value) {
  dst[0] = (uint8_t)(value >> 8U);
  dst[1] = (uint8_t)value;
}

void ipv6_put_be32(uint8_t *dst, uint32_t value) {
  dst[0] = (uint8_t)(value >> 24U);
  dst[1] = (uint8_t)(value >> 16U);
  dst[2] = (uint8_t)(value >> 8U);
  dst[3] = (uint8_t)value;
}

uint16_t ipv6_get_be16(const uint8_t *src) {
  return (uint16_t)(((uint16_t)src[0] << 8U) | src[1]);
}

uint32_t ipv6_get_be32(const uint8_t *src) {
  return ((uint32_t)src[0] << 24U) | ((uint32_t)src[1] << 16U) |
         ((uint32_t)src[2] << 8U) | src[3];
}

void ipv6_bytes_copy(void *dst, const void *src, uint64_t size) {
  uint8_t *out = (uint8_t *)dst;
  const uint8_t *in = (const uint8_t *)src;
  for (uint64_t i = 0U; i < size; ++i) out[i] = in[i];
}

void ipv6_bytes_zero(void *dst, uint64_t size) {
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
  ipv6_put_be32(hdr, XAIOS_IPV6_VERSION_TC_FLOW);
  /* Payload length (excludes the 40-byte header) */
  ipv6_put_be16(hdr + 4, payload_length);
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
    *payload_length = ipv6_get_be16(hdr + 4);
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
  ipv6_put_be32(pseudo + 32, upper_layer_length);
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
  kassert(ipv6_get_be16(hdr + 4) == 8);
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
  ipv6_put_be16(payload + 2, cksum);
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
    ipv6_bytes_zero(fbuf, sizeof(fbuf));
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
    ipv6_put_be16(fbuf + 12, XAIOS_IPV6_ETHERTYPE);
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
                         ipv6_get_be16(fragments + 18U);
    kassert(first_len < fragments_len);
    uint64_t second_len = fragments_len - first_len;
    uint8_t reassembled[1514];
    ipv6_bytes_copy(reassembled, fragments + first_len, second_len);
    uint64_t reassembled_len = second_len;
    kassert(ipv6_reassemble_v6(reassembled, &reassembled_len) ==
            XAIOS_ERR_BUSY);
    ipv6_bytes_copy(reassembled, fragments, first_len);
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
