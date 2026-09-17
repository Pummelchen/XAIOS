/*
 * The TCP segment builder and the per-flow transmit path: option writing, the
 * IPv4 and IPv6 segment builders, next-hop and next-hop-MAC resolution, and
 * the one function that turns a flow into a segment on the wire.
 *
 * This is the other half of the cut network_stack_tcp.h describes. Every
 * function takes its flow from the caller; the one piece of file-scope state
 * the moved code read, g_local_mac, is now read through the existing public
 * copy-out accessor network_stack_local_mac() into a caller-owned local, so
 * this file keeps no pointer into the stack's state.
 *
 * Locking. The caller holds the stack's guard, g_network_guard, through
 * network_stack_lock()/network_stack_unlock(); nothing here takes a lock of
 * its own, and the guard's coverage at each call site is unchanged.
 */

#include "network_stack_tcp.h"

#include <xaios/arp.h>
#include <xaios/ipv4.h>
#include <xaios/ipv6.h>
#include <xaios/net_device.h>
#include <xaios/network_config.h>
#include <xaios/routing.h>

#include "network_stack_wire.h"

uint32_t net_tcp_build_options(const network_tcp_flow_t *flow,
                                  uint8_t flags, uint8_t options[40]) {
  net_wire_bytes_zero(options, 40U);
  if ((flags & NETWORK_TCP_FLAG_SYN) != 0U) {
    options[0] = TCP_OPT_MSS;
    options[1] = 4U;
    net_wire_write_be16(options + 2U,
               flow != 0 && flow->local_addr.family == XAIOS_IP_FAMILY_V6
                   ? NETWORK_TCP_IPV6_MSS : NETWORK_TCP_MSS);
    options[4] = TCP_OPT_SACK_PERMITTED;
    options[5] = 2U;
    options[6] = TCP_OPT_NOP;
    options[7] = TCP_OPT_WSCALE;
    options[8] = 3U;
    options[9] = 0U;
    options[10] = TCP_OPT_END;
    return 12U;
  }
  if ((flags & NETWORK_TCP_FLAG_ACK) == 0U || flow == 0 ||
      flow->peer_sack_permitted == 0U) {
    return 0U;
  }
  uint32_t count = 0U;
  for (uint32_t i = 0U; i < TCP_OOO_BUF_ENTRIES; ++i) {
    if (flow->ooo_buf[i].in_use != 0U) ++count;
  }
  if (count == 0U) return 0U;
  options[0] = TCP_OPT_SACK;
  options[1] = (uint8_t)(2U + count * 8U);
  uint32_t written = 0U;
  for (uint32_t i = 0U; i < TCP_OOO_BUF_ENTRIES; ++i) {
    if (flow->ooo_buf[i].in_use == 0U) continue;
    net_wire_write_be32(options + 2U + written * 8U, flow->ooo_buf[i].seq);
    net_wire_write_be32(options + 6U + written * 8U,
               flow->ooo_buf[i].seq + flow->ooo_buf[i].len);
    ++written;
  }
  return 2U + count * 8U;
}

/* ================================================================
 * TCP Segment Builder and Data Plane Functions
 * ================================================================ */

static xaios_status_t tcp_build_and_send_segment(
    const network_tcp_flow_t *flow,
    const uint8_t src_mac[6], const uint8_t dst_mac[6],
    uint32_t src_ip, uint32_t dst_ip,
    uint16_t src_port, uint16_t dst_port,
    uint32_t seq, uint32_t ack_val,
    uint8_t flags, uint16_t window,
    const uint8_t *payload, uint32_t payload_len) {
  uint8_t tcp_opts[40];
  uint32_t tcp_opt_len = net_tcp_build_options(flow, flags, tcp_opts);
  /* Align options to 4-byte boundary */
  uint32_t opt_padded = (tcp_opt_len + 3U) & ~3U;
  uint8_t tcp_hdr_bytes = (uint8_t)(20U + opt_padded);
  uint8_t data_offset_val = (uint8_t)((tcp_hdr_bytes >> 2U) << 4U);

  uint8_t frame[NETWORK_BUFFER_SIZE];
  uint64_t frame_len = 14U + 20U + tcp_hdr_bytes + payload_len;
  if (frame_len > NETWORK_BUFFER_SIZE) {
    return XAIOS_ERR_INVALID;
  }
  /* Ethernet header */
  for (uint32_t i = 0; i < 6; ++i) { frame[i] = dst_mac[i]; }
  for (uint32_t i = 0; i < 6; ++i) { frame[6U + i] = src_mac[i]; }
  net_wire_write_be16(frame + 12, 0x0800U);
  /* IPv4 header */
  uint16_t ip_total = (uint16_t)(20U + tcp_hdr_bytes + payload_len);
  ipv4_build_header(frame + 14, ip_total, 6, src_ip, dst_ip);
  /* TCP header */
  uint8_t *tcp = frame + 34U;
  net_wire_write_be16(tcp, src_port);
  net_wire_write_be16(tcp + 2, dst_port);
  net_wire_write_be32(tcp + 4, seq);
  net_wire_write_be32(tcp + 8, ack_val);
  tcp[12] = data_offset_val;
  tcp[13] = flags;
  net_wire_write_be16(tcp + 14, window);
  net_wire_write_be16(tcp + 16, 0);
  net_wire_write_be16(tcp + 18, 0); /* urgent pointer */
  /* Copy options */
  for (uint32_t i = 0; i < tcp_opt_len; ++i) {
    tcp[20U + i] = tcp_opts[i];
  }
  /* Zero padding between options and payload */
  for (uint32_t i = tcp_opt_len; i < opt_padded; ++i) {
    tcp[20U + i] = 0;
  }
  /* Copy payload */
  if (payload != 0 && payload_len > 0) {
    uint64_t data_off = 34U + tcp_hdr_bytes;
    for (uint32_t i = 0; i < payload_len; ++i) {
      frame[data_off + i] = payload[i];
    }
  }
  /* Compute TCP checksum */
  uint16_t tcp_seg_len = (uint16_t)(tcp_hdr_bytes + payload_len);
  uint16_t cksum = ipv4_pseudo_checksum(src_ip, dst_ip, 6, tcp_seg_len,
                                           tcp, (uint32_t)tcp_seg_len);
  net_wire_write_be16(tcp + 16, cksum);
  return network_device_tx(frame, frame_len);
}

int net_tcp_resolve_mac(uint32_t dest_ip_net_order, uint8_t out_mac[6],
                            const uint8_t local_mac[6]) {
  uint32_t next_hop = routing_lookup(dest_ip_net_order);
  if (next_hop == 0) {
    return 0; /* no route */
  }
  if (arp_cache_lookup(next_hop, out_mac) == XAIOS_OK) {
    return 1;
  }
  /* Send ARP request and retry later */
  uint8_t arp_frame[42];
  uint64_t arp_len = 0;
  if (arp_build_request(arp_frame, &arp_len, local_mac,
                         network_config_local_ipv4(), next_hop) == XAIOS_OK) {
    network_device_tx(arp_frame, arp_len);
  }
  return 0;
}

/* Build and send a TCP segment over IPv6 */
static xaios_status_t tcp_build_and_send_segment_v6(
    const network_tcp_flow_t *flow,
    const uint8_t src_mac[6], const uint8_t dst_mac[6],
    const xaios_ip_addr_t *src_ip, const xaios_ip_addr_t *dst_ip,
    uint16_t src_port, uint16_t dst_port,
    uint32_t seq, uint32_t ack_val,
    uint8_t flags, uint16_t window,
    const uint8_t *payload, uint32_t payload_len) {
  uint8_t tcp_opts[40];
  uint32_t tcp_opt_len = net_tcp_build_options(flow, flags, tcp_opts);
  uint32_t opt_padded = (tcp_opt_len + 3U) & ~3U;
  uint8_t tcp_hdr_bytes = (uint8_t)(20U + opt_padded);
  uint8_t data_offset_val = (uint8_t)((tcp_hdr_bytes >> 2U) << 4U);

  uint8_t frame[NETWORK_BUFFER_SIZE];
  uint64_t frame_len = 14U + 40U + tcp_hdr_bytes + payload_len;
  if (frame_len > NETWORK_BUFFER_SIZE) {
    return XAIOS_ERR_INVALID;
  }
  /* Ethernet header */
  for (uint32_t i = 0; i < 6; ++i) { frame[i] = dst_mac[i]; }
  for (uint32_t i = 0; i < 6; ++i) { frame[6U + i] = src_mac[i]; }
  net_wire_write_be16(frame + 12, 0x86DDU); /* IPv6 ethertype */
  /* IPv6 header (40 bytes) */
  uint8_t *ip6 = frame + 14U;
  net_wire_write_be32(ip6, 0x60000000U); /* version=6, TC=0, flow=0 */
  net_wire_write_be16(ip6 + 4, (uint16_t)(tcp_hdr_bytes + payload_len)); /* payload length */
  ip6[6] = 6U; /* next header = TCP */
  ip6[7] = 64U; /* hop limit */
  for (uint32_t i = 0; i < 16; ++i) { ip6[8U + i] = src_ip->addr[i]; }
  for (uint32_t i = 0; i < 16; ++i) { ip6[24U + i] = dst_ip->addr[i]; }
  /* TCP header */
  uint8_t *tcp = frame + 54U;
  net_wire_write_be16(tcp, src_port);
  net_wire_write_be16(tcp + 2, dst_port);
  net_wire_write_be32(tcp + 4, seq);
  net_wire_write_be32(tcp + 8, ack_val);
  tcp[12] = data_offset_val;
  tcp[13] = flags;
  net_wire_write_be16(tcp + 14, window);
  net_wire_write_be16(tcp + 16, 0);
  net_wire_write_be16(tcp + 18, 0); /* urgent */
  /* Copy options */
  for (uint32_t i = 0; i < tcp_opt_len; ++i) {
    tcp[20U + i] = tcp_opts[i];
  }
  for (uint32_t i = tcp_opt_len; i < opt_padded; ++i) {
    tcp[20U + i] = 0;
  }
  /* Copy payload */
  if (payload != 0 && payload_len > 0) {
    uint64_t data_off = 54U + tcp_hdr_bytes;
    for (uint32_t i = 0; i < payload_len; ++i) {
      frame[data_off + i] = payload[i];
    }
  }
  /* Compute TCP checksum over IPv6 pseudo-header + TCP + payload */
  uint16_t tcp_total = (uint16_t)(tcp_hdr_bytes + payload_len);
  uint16_t cksum = ipv6_pseudo_checksum(src_ip, dst_ip, 6, tcp_total,
                                           tcp, (uint32_t)tcp_total);
  net_wire_write_be16(tcp + 16, cksum);
  return network_device_tx(frame, frame_len);
}

xaios_status_t net_tcp_send_flow_segment(network_tcp_flow_t *flow,
                                            uint32_t seq, uint8_t flags,
                                            const uint8_t *payload,
                                            uint16_t payload_len) {
  uint8_t local_mac[6];
  (void)network_stack_local_mac(local_mac);
  if (flow->local_addr.family == XAIOS_IP_FAMILY_V6) {
    return tcp_build_and_send_segment_v6(
        flow, local_mac, flow->remote_mac, &flow->local_addr, &flow->remote_addr,
        flow->local_port, flow->remote_port, seq, flow->expected_seq, flags,
        flow->window_size, payload, payload_len);
  }
  uint32_t destination = flow->remote_address;
  uint32_t destination_be = ((destination & 0xFFU) << 24U) |
                            (((destination >> 8U) & 0xFFU) << 16U) |
                            (((destination >> 16U) & 0xFFU) << 8U) |
                            ((destination >> 24U) & 0xFFU);
  return tcp_build_and_send_segment(
      flow, local_mac, flow->remote_mac, network_config_local_ipv4(), destination_be,
      flow->local_port, flow->remote_port, seq, flow->expected_seq, flags,
      flow->window_size, payload, payload_len);
}
