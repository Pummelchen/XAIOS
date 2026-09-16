/*
 * Wire-format helpers for the network stack. See network_stack_wire.h.
 */

#include "network_stack_wire.h"

#include <xaios/assert.h>
#include <xaios/timer.h>
#include <xaios/entropy.h>
#include <xaios/ip_addr.h>
#include <xaios/ipv4.h>
#include <xaios/ipv6.h>

int net_wire_tcp_seq_before(uint32_t left, uint32_t right) {
  return (int32_t)(left - right) < 0;
}

int net_wire_tcp_seq_after(uint32_t left, uint32_t right) {
  return net_wire_tcp_seq_before(right, left);
}

uint16_t net_wire_read_u16_be(const uint8_t *bytes) {
  return (uint16_t)(((uint16_t)bytes[0] << 8U) | (uint16_t)bytes[1]);
}

uint32_t net_wire_read_u32_be(const uint8_t *bytes) {
  return ((uint32_t)bytes[0] << 24U) | ((uint32_t)bytes[1] << 16U) |
         ((uint32_t)bytes[2] << 8U) | (uint32_t)bytes[3];
}

void net_wire_write_be16(uint8_t *dst, uint16_t value) {
  dst[0] = (uint8_t)(value >> 8U);
  dst[1] = (uint8_t)(value);
}

void net_wire_write_be32(uint8_t *dst, uint32_t value) {
  dst[0] = (uint8_t)(value >> 24U);
  dst[1] = (uint8_t)(value >> 16U);
  dst[2] = (uint8_t)(value >> 8U);
  dst[3] = (uint8_t)value;
}

uint32_t net_wire_tcp_generate_isn(uint32_t flow_id) {
  uint32_t sequence = 0;
  if (entropy_read(&sequence, sizeof(sequence)) == XAIOS_OK) {
    return sequence;
  }
  return (uint32_t)(timer_now_ns() ^ ((uint64_t)flow_id << 16U));
}

uint32_t net_wire_tcp_scaled_window(uint16_t window, uint8_t shift) {
  if (shift > 14U) shift = 14U;
  return (uint32_t)window << shift;
}

int net_wire_parse_tcp_options(const uint8_t *tcp_hdr, uint32_t hdr_bytes,
                             tcp_parsed_options_t *options) {
  net_wire_bytes_zero(options, sizeof(*options));
  if (tcp_hdr == 0 || hdr_bytes < 20U || hdr_bytes > 60U) return 0;
  uint32_t offset = 20; /* skip fixed header */
  while (offset + 1U <= hdr_bytes) {
    uint8_t kind = tcp_hdr[offset];
    if (kind == TCP_OPT_END) break;
    if (kind == TCP_OPT_NOP) { offset += 1; continue; }
    if (offset + 2U > hdr_bytes) return 0;
    uint8_t len = tcp_hdr[offset + 1U];
    if (len < 2U || offset + (uint32_t)len > hdr_bytes) return 0;
    if (kind == TCP_OPT_MSS && len == 4U && offset + 4U <= hdr_bytes) {
      options->mss = net_wire_read_u16_be(tcp_hdr + offset + 2U);
    } else if (kind == TCP_OPT_WSCALE && len == 3U) {
      uint8_t shift = tcp_hdr[offset + 2U];
      options->window_scale = shift > 14U ? 14U : shift;
    } else if (kind == TCP_OPT_SACK_PERMITTED && len == 2U) {
      options->sack_permitted = 1U;
    } else if (kind == TCP_OPT_SACK) {
      if (len < 10U || ((uint32_t)len - 2U) % 8U != 0U) return 0;
      uint32_t count = ((uint32_t)len - 2U) / 8U;
      if (count > TCP_OOO_BUF_ENTRIES) count = TCP_OOO_BUF_ENTRIES;
      for (uint32_t i = 0U; i < count; ++i) {
        options->sack_left[i] =
            net_wire_read_u32_be(tcp_hdr + offset + 2U + i * 8U);
        options->sack_right[i] =
            net_wire_read_u32_be(tcp_hdr + offset + 6U + i * 8U);
      }
      options->sack_count = (uint8_t)count;
    }
    offset += (uint32_t)len;
  }
  return 1;
}

uint64_t net_wire_percentile(uint64_t *samples, uint32_t count, uint32_t p) {
  if (count == 0U) {
    return 0;
  }
  uint64_t sorted[NETWORK_MAX_SAMPLES];
  for (uint32_t i = 0; i < count; ++i) {
    sorted[i] = samples[i];
  }

  for (uint32_t i = 0; i < count; ++i) {
    for (uint32_t j = i + 1U; j < count; ++j) {
      if (sorted[j] < sorted[i]) {
        uint64_t tmp = sorted[i];
        sorted[i] = sorted[j];
        sorted[j] = tmp;
      }
    }
  }

  uint32_t divisor = (p > 100U) ? 1000U : 100U;
  uint32_t index = (count * p) / divisor;
  if (index >= count) {
    index = count - 1U;
  }

  return sorted[index];
}

void net_wire_bytes_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0; i < size; ++i) {
    bytes[i] = 0;
  }
}

uint32_t net_wire_ip4_addr_host_order(uint32_t network_order_address) {
  const uint8_t *src = (const uint8_t *)&network_order_address;
  return (uint32_t)src[0] | ((uint32_t)src[1] << 8U) |
         ((uint32_t)src[2] << 16U) | ((uint32_t)src[3] << 24U);
}

int net_wire_eth_frame_has_ipv4(const uint8_t *frame, uint64_t frame_len) {
  const network_ip4_header_t *ip = (const network_ip4_header_t *)(frame + 14U);
  if (frame_len < (14U + 20U)) {
    return 0;
  }
  if (net_wire_read_u16_be(frame + 12U) != NETWORK_ETHERTYPE_IPV4) {
    return 0;
  }
  if ((ip->version_ihl >> 4U) != 4U) {
    return 0;
  }
  return 1;
}

int net_wire_parse_udp(const uint8_t *frame, uint64_t frame_len,
                     uint16_t *src_port, uint16_t *dst_port,
                     uint16_t *payload_len, uint32_t *src_address,
                     uint32_t *dst_address) {
  if (!net_wire_eth_frame_has_ipv4(frame, frame_len)) {
    return 0;
  }
  if (!ipv4_validate_incoming(frame, frame_len) ||
      ipv4_is_fragment(frame, frame_len)) {
    return 0;
  }

  const network_ip4_header_t *ip = (const network_ip4_header_t *)(frame + 14U);
  const uint16_t ip_header_words = (uint16_t)(ip->version_ihl & 0x0fU);
  const uint64_t ip_len = (uint64_t)net_wire_read_u16_be((const uint8_t *)&ip->total_length);
  const uint32_t ip_header_bytes = (uint32_t)ip_header_words * 4U;
  if (ip->protocol != NETWORK_IP_PROTO_UDP) {
    return 0;
  }
  if (ip_header_bytes < 20U || ip_len < ip_header_bytes) {
    return 0;
  }

  const network_udp_header_t *udp =
      (const network_udp_header_t *)((const uint8_t *)ip + ip_header_bytes);
  const uint64_t udp_start = 14U + (uint64_t)ip_header_bytes;
  const uint64_t udp_end = 14U + ip_len;
  if (udp_end > frame_len || ip_len < ip_header_bytes + 8U) {
    return 0;
  }

  const uint16_t udp_length = net_wire_read_u16_be((const uint8_t *)&udp->length);
  if (udp_length < 8U || udp_start + 8U > udp_end || udp_start + (uint64_t)udp_length > udp_end) {
    return 0;
  }

  uint16_t wire_checksum = net_wire_read_u16_be((const uint8_t *)&udp->checksum);
  if (wire_checksum != 0U) {
    uint32_t source = net_wire_read_u32_be((const uint8_t *)&ip->source);
    uint32_t destination = net_wire_read_u32_be((const uint8_t *)&ip->destination);
    if (ipv4_pseudo_checksum(source, destination, NETWORK_IP_PROTO_UDP,
                             udp_length, (const uint8_t *)udp,
                             udp_length) != 0U) return 0;
  }

  *src_port = net_wire_read_u16_be((const uint8_t *)&udp->source_port);
  *dst_port = net_wire_read_u16_be((const uint8_t *)&udp->dest_port);
  *payload_len = udp_length;
  *src_address = net_wire_ip4_addr_host_order(ip->source);
  *dst_address = net_wire_ip4_addr_host_order(ip->destination);
  return 1;
}

int net_wire_parse_tcp(const uint8_t *frame, uint64_t frame_len, uint16_t *src_port,
                    uint16_t *dst_port, uint32_t *seq, uint32_t *ack,
                    uint8_t *flags) {
  if (!net_wire_eth_frame_has_ipv4(frame, frame_len)) {
    return 0;
  }
  if (!ipv4_validate_incoming(frame, frame_len) ||
      ipv4_is_fragment(frame, frame_len)) {
    return 0;
  }

  const network_ip4_header_t *ip = (const network_ip4_header_t *)(frame + 14U);
  const uint16_t ip_header_words = (uint16_t)(ip->version_ihl & 0x0fU);
  const uint64_t ip_len = (uint64_t)net_wire_read_u16_be((const uint8_t *)&ip->total_length);
  const uint64_t ip_header_bytes = (uint64_t)ip_header_words * 4U;
  if (ip->protocol != NETWORK_IP_PROTO_TCP) {
    return 0;
  }
  if (ip_header_bytes < 20U || ip_len < ip_header_bytes + 20U) {
    return 0;
  }
  if (14U + ip_len > frame_len) {
    return 0;
  }

  const network_tcp_header_t *tcp =
      (const network_tcp_header_t *)((const uint8_t *)ip + ip_header_bytes);
  const uint16_t data_offset_words = (uint16_t)(tcp->data_offset_reserved >> 4U);
  
  /* TCP options are bounded by both the protocol and the IP payload. */
  if (data_offset_words < 5U) {
    return 0;  /* TCP header too small */
  }
  if (data_offset_words > 15U) {
    return 0;  /* TCP header too large (max 60 bytes) */
  }
  
  const uint64_t tcp_header_bytes = (uint64_t)data_offset_words * 4U;
  
  if (tcp_header_bytes > ip_len - ip_header_bytes) {
    return 0;  /* TCP header extends beyond IP payload */
  }
  
  if (tcp_header_bytes > 60) {
    return 0;  /* TCP options exceed 40 byte limit */
  }
  
  const uint64_t tcp_payload_len =
      ip_len - ip_header_bytes - (uint64_t)tcp_header_bytes;
  const uint16_t tcp_len = (uint16_t)(tcp_header_bytes + tcp_payload_len);

  if (tcp_header_bytes > ip_len) {
    return 0;
  }

  /* TCP checksums are mandatory on this receive path. */
  uint32_t src_ip_be = net_wire_read_u32_be((const uint8_t *)&ip->source);
  uint32_t dst_ip_be = net_wire_read_u32_be((const uint8_t *)&ip->destination);
  uint16_t wire_cksum = net_wire_read_u16_be((const uint8_t *)&tcp->checksum);
  if (wire_cksum == 0U ||
      ipv4_pseudo_checksum(src_ip_be, dst_ip_be, NETWORK_IP_PROTO_TCP,
                           tcp_len, (const uint8_t *)tcp, tcp_len) != 0U) {
    return 0;
  }

  *src_port = net_wire_read_u16_be((const uint8_t *)&tcp->source_port);
  *dst_port = net_wire_read_u16_be((const uint8_t *)&tcp->dest_port);
  *seq = net_wire_read_u32_be((const uint8_t *)&tcp->seq);
  *ack = net_wire_read_u32_be((const uint8_t *)&tcp->ack);
  *flags = tcp->flags;
  return 1;
}

int net_wire_eth_frame_has_ipv6(const uint8_t *frame, uint64_t frame_len) {
  if (frame_len < (14U + XAIOS_IPV6_HEADER_SIZE)) {
    return 0;
  }
  if (net_wire_read_u16_be(frame + 12U) != NETWORK_ETHERTYPE_IPV6) {
    return 0;
  }
  if ((frame[14U] >> 4U) != 6U) {
    return 0;
  }
  return 1;
}

int net_wire_parse_udp_v6(const uint8_t *frame, uint64_t frame_len,
                        uint16_t *src_port, uint16_t *dst_port,
                        uint16_t *payload_len,
                        xaios_ip_addr_t *src_addr, xaios_ip_addr_t *dst_addr) {
  if (!net_wire_eth_frame_has_ipv6(frame, frame_len)) {
    return 0;
  }
  const uint8_t *ip6 = frame + 14U;
  uint16_t plen = net_wire_read_u16_be(ip6 + 4U);
  uint8_t next_hdr = ip6[6U];
  if (next_hdr != NETWORK_IP_PROTO_UDP) {
    return 0;
  }
  if (14U + XAIOS_IPV6_HEADER_SIZE + 8U > frame_len) {
    return 0;
  }
  if (14U + XAIOS_IPV6_HEADER_SIZE + plen > frame_len) {
    return 0;
  }
  const uint8_t *udp = ip6 + XAIOS_IPV6_HEADER_SIZE;
  uint16_t udp_len = net_wire_read_u16_be(udp + 4U);
  if (udp_len < 8U || udp_len > plen) {
    return 0;
  }
  *src_port = net_wire_read_u16_be(udp);
  *dst_port = net_wire_read_u16_be(udp + 2U);
  *payload_len = udp_len;

  /* IPv6 UDP checksums are mandatory. */
  uint16_t wire_udp_cksum = net_wire_read_u16_be(udp + 6U);
  if (wire_udp_cksum != 0) {
    xaios_ip_addr_t usrc, udst;
    xaios_ip_addr_from_raw_ipv6(&usrc, ip6 + 8U);
    xaios_ip_addr_from_raw_ipv6(&udst, ip6 + 24U);
    uint16_t computed_cksum = ipv6_pseudo_checksum(&usrc, &udst,
                                  NETWORK_IP_PROTO_UDP, udp_len,
                                  udp, udp_len);
    if (computed_cksum != 0) {
      return 0; /* bad checksum */
    }
  } else {
    return 0; /* RFC 2460: IPv6 UDP must have non-zero checksum */
  }

  xaios_ip_addr_from_raw_ipv6(src_addr, ip6 + 8U);
  xaios_ip_addr_from_raw_ipv6(dst_addr, ip6 + 24U);
  return 1;
}

int net_wire_parse_tcp_v6(const uint8_t *frame, uint64_t frame_len,
                        uint16_t *src_port, uint16_t *dst_port,
                        uint32_t *seq, uint32_t *ack_val, uint8_t *flags,
                        xaios_ip_addr_t *src_addr, xaios_ip_addr_t *dst_addr) {
  if (!net_wire_eth_frame_has_ipv6(frame, frame_len)) {
    return 0;
  }
  const uint8_t *ip6 = frame + 14U;
  uint16_t plen = net_wire_read_u16_be(ip6 + 4U);
  uint8_t next_hdr = ip6[6U];
  if (next_hdr != NETWORK_IP_PROTO_TCP) {
    return 0;
  }
  if (14U + XAIOS_IPV6_HEADER_SIZE + 20U > frame_len) {
    return 0;
  }
  if (14U + XAIOS_IPV6_HEADER_SIZE + plen > frame_len) {
    return 0;
  }
  const uint8_t *tcp = ip6 + XAIOS_IPV6_HEADER_SIZE;
  uint16_t data_offset_words = (uint16_t)(tcp[12U] >> 4U);
  if (data_offset_words < 5U || data_offset_words > 15U) {
    return 0;
  }
  uint32_t tcp_hdr_bytes = (uint32_t)data_offset_words * 4U;
  if (tcp_hdr_bytes > (uint32_t)plen) {
    return 0;
  }
  *src_port = net_wire_read_u16_be(tcp);
  *dst_port = net_wire_read_u16_be(tcp + 2U);
  *seq = net_wire_read_u32_be(tcp + 4U);
  *ack_val = net_wire_read_u32_be(tcp + 8U);
  *flags = tcp[13U];

  /* TCP checksums are mandatory for IPv6. */
  uint32_t tcp_total = tcp_hdr_bytes + ((uint32_t)plen - tcp_hdr_bytes);
  uint16_t wire_cksum = net_wire_read_u16_be(tcp + 16U);
  xaios_ip_addr_t src, dst;
  xaios_ip_addr_from_raw_ipv6(&src, ip6 + 8U);
  xaios_ip_addr_from_raw_ipv6(&dst, ip6 + 24U);
  if (wire_cksum == 0U ||
      ipv6_pseudo_checksum(&src, &dst, NETWORK_IP_PROTO_TCP, tcp_total,
                           tcp, tcp_total) != 0U) return 0;

  xaios_ip_addr_from_raw_ipv6(src_addr, ip6 + 8U);
  xaios_ip_addr_from_raw_ipv6(dst_addr, ip6 + 24U);
  return 1;
}
