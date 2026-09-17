/*
 * The IPv6 TCP receive classifier, moved out of network_stack.c.
 *
 * The exact twin of network_stack_tcp_frame.c, and separate for the same
 * reason: the two handlers together are longer than the file limit. This one
 * also bumps the IPv6 receive counter twice in place; network_stack.c keeps
 * that counter, so the increments cross through the existing
 * net_stack_note_ipv6_rx(), which is the same `++` the old code wrote.
 *
 * Locking. It runs with the stack guard already held, exactly as before, and
 * takes no lock of its own; the early returns and the packet marks are in the
 * same order.
 */

#include <xaios/arp.h>

#include "network_stack_app.h"
#include "network_stack_icmp.h"
#include "network_stack_listener.h"
#include "network_stack_packet.h"
#include "network_stack_poll.h"
#include "network_stack_selftest.h"
#include "network_stack_tcp_stats.h"
#include "network_stack_lifecycle.h"
#include "network_stack_udp.h"
#include "network_stack_udp_rx.h"
#include "network_stack_v6.h"
#include "network_stack_wire.h"
#include "network_stack_tcp.h"
#include "network_stack_tcp_table.h"
#include <xaios/assert.h>
#include <xaios/dns.h>
#include <xaios/entropy.h>
#include <xaios/icmp.h>
#include <xaios/icmpv6.h>
#include <xaios/ip_addr.h>
#include <xaios/ipv4.h>
#include <xaios/ipv6.h>
#include <xaios/klog.h>
#include <xaios/ndp.h>
#include <xaios/ntp.h>
#include <xaios/operations.h>
#include <xaios/network_stack.h>
#include <xaios/smp.h>
#include <xaios/spinlock.h>
#include <xaios/routing.h>
#include <xaios/socket_buffer.h>
#include <xaios/timer.h>
#include <xaios/net_device.h>
#include <xaios/network_config.h>

xaios_status_t net_tcp_frame_process_v6(network_tcp_flow_t *flows,
                                        const uint8_t *frame,
                                        uint64_t frame_len) {
  if (frame == 0 || frame_len < 74U) { /* 14 + 40 + 20 minimum */
    net_tcp_note_reset();
    net_note_packet_drop();
    return XAIOS_ERR_INVALID;
  }

  uint64_t start = timer_now_ns();
  uint16_t src_port = 0;
  uint16_t dst_port = 0;
  uint32_t seq = 0;
  uint32_t ack_v = 0;
  uint8_t flags = 0;
  xaios_ip_addr_t src_addr;
  xaios_ip_addr_t dst_addr;
  xaios_ip_addr_zero(&src_addr);
  xaios_ip_addr_zero(&dst_addr);

  if (net_wire_parse_tcp_v6(frame, frame_len, &src_port, &dst_port, &seq, &ack_v,
                   &flags, &src_addr, &dst_addr) == 0) {
    net_tcp_note_reset();
    net_note_packet_drop();
    return XAIOS_ERR_INVALID;
  }
  if (src_port == 0U || dst_port == 0U) {
    net_tcp_note_reset();
    net_note_packet_drop();
    return XAIOS_ERR_INVALID;
  }

  const uint8_t *parsed_tcp_header = frame + 14U + XAIOS_IPV6_HEADER_SIZE;
  uint16_t peer_window_raw = net_wire_read_u16_be(parsed_tcp_header + 14U);

  network_tcp_flow_t *flow =
      net_tcp_table_find_v6(flows, dst_port, src_port, &src_addr);
  network_queue_binding_t binding;
  int have_binding =
      flow != 0
          ? net_queue_binding_find(flow->queue_id, &binding)
          : net_queue_binding_select(dst_port, src_port,
                                     xaios_ip_addr_hash(&dst_addr),
                                     xaios_ip_addr_hash(&src_addr), &binding);
  if (have_binding == 0) {
    net_tcp_note_reset();
    net_note_packet_drop();
    return XAIOS_ERR_NOT_FOUND;
  }

  uint32_t packet =
      net_packet_alloc(binding.queue_id, frame_len, start, src_port, dst_port,
                       0, 0, &src_addr, &dst_addr);
  if (packet == 0) {
    net_tcp_note_reset();
    return XAIOS_ERR_NO_MEMORY;
  }

  if (flow != 0 && flow->state == XAIOS_NETWORK_FLOW_SYN_SENT &&
      (flags & (NETWORK_TCP_FLAG_SYN | NETWORK_TCP_FLAG_ACK)) ==
          (NETWORK_TCP_FLAG_SYN | NETWORK_TCP_FLAG_ACK) &&
      (flags & (NETWORK_TCP_FLAG_FIN | NETWORK_TCP_FLAG_RST)) == 0U) {
    if (ack_v != flow->next_send_seq) {
      net_packet_mark_dropped(packet);
      return XAIOS_ERR_INVALID;
    }
    uint32_t tcp_header_bytes =
        (uint32_t)(parsed_tcp_header[12U] >> 4U) * 4U;
    tcp_parsed_options_t options;
    if (!net_wire_parse_tcp_options(parsed_tcp_header, tcp_header_bytes, &options)) {
      net_packet_mark_dropped(packet);
      return XAIOS_ERR_INVALID;
    }
    flow->remote_seq = seq;
    flow->expected_seq = seq + 1U;
    flow->local_seq = ack_v;
    flow->next_send_seq = ack_v;
    flow->peer_mss = options.mss > 0U && options.mss < NETWORK_TCP_IPV6_MSS
                         ? options.mss
                         : NETWORK_TCP_IPV6_MSS;
    flow->mss_parsed = 1U;
    flow->peer_ws = options.window_scale;
    flow->ws_parsed = options.window_scale > 0U ? 1U : 0U;
    flow->peer_sack_permitted = options.sack_permitted;
    flow->peer_window = net_wire_tcp_scaled_window(peer_window_raw, flow->peer_ws);
    for (uint32_t i = 0U; i < 6U; ++i) flow->remote_mac[i] = frame[6U + i];
    flow->remote_mac_valid = 1U;
    flow->pending_syn = 0U;
    flow->pending_ack = 1U;
    flow->state = XAIOS_NETWORK_FLOW_ESTABLISHED;
    flow->last_seen_ns = start;
    flow->keepalive_last_rx_ns = start;
    net_tcp_half_open_release();
    ++flow->packets_rx;
    net_tcp_note_handshake();
    net_tcp_note_established();
    net_stack_note_ipv6_rx();
    net_packet_mark_tx(packet);
    net_packet_mark_complete(packet);
    net_tcp_record_latency(timer_now_ns() - start);
    return XAIOS_OK;
  }

  if ((flags & NETWORK_TCP_FLAG_RST) != 0U) {
    if (flow != 0) {
      if (seq != flow->expected_seq) {
        net_packet_mark_dropped(packet);
        return XAIOS_ERR_INVALID;
      }
      xaios_network_flow_state_t prev_state = flow->state;
      net_tcp_note_reset();
      net_tcp_note_closed();
      if (prev_state == XAIOS_NETWORK_FLOW_SYN_RECV) {
        net_tcp_half_open_release();
      }
      net_tcp_release_flow(flow);
    }
    net_packet_mark_dropped(packet);
    return XAIOS_ERR_INVALID;
  }

  if (flow == 0 &&
      ((flags & NETWORK_TCP_FLAG_SYN) == 0U ||
       (flags & (NETWORK_TCP_FLAG_ACK | NETWORK_TCP_FLAG_FIN)) != 0U)) {
    net_packet_mark_dropped(packet);
    return XAIOS_ERR_INVALID;
  }

  if (flow == 0 && (flags & NETWORK_TCP_FLAG_SYN) != 0U) {
    /* Check if there's a listener for this port */
    if (!network_stack_has_listener(dst_port)) {
      net_tcp_note_reset();
      net_packet_mark_dropped(packet);
      return XAIOS_ERR_NOT_FOUND;
    }
    flow = net_tcp_table_alloc(flows, dst_port, src_port, 0, &src_addr);
    if (flow == 0) {
      net_tcp_note_reset();
      net_packet_mark_dropped(packet);
      return XAIOS_ERR_NO_MEMORY;
    }
    flow->flow_id = net_stack_alloc_flow_id();
    flow->local_port = dst_port;
    flow->remote_port = src_port;
    flow->queue_id = binding.queue_id;
    flow->cell_id = binding.cell_id;
    flow->remote_addr = src_addr;
    flow->local_addr = dst_addr;
    flow->remote_seq = seq;
    flow->expected_seq = seq + 1U;
    flow->local_seq = net_wire_tcp_generate_isn(flow->flow_id);
    flow->next_send_seq = flow->local_seq + 1U;
    flow->window_size = (uint16_t)SOCKET_BUFFER_SIZE;
    flow->pending_synack = 1;
    flow->pending_fin = 0;
    flow->pending_ack = 0;
    flow->close_requested = 0;
    for (uint32_t i = 0; i < 6U; ++i) {
      flow->remote_mac[i] = frame[6U + i];
    }
    flow->remote_mac_valid = 1;
    flow->rx_buf = sockbuf_alloc();
    flow->tx_buf = sockbuf_alloc();
    if (flow->rx_buf == 0 || flow->tx_buf == 0) {
      net_tcp_half_open_release();
      net_tcp_release_flow(flow);
      net_packet_mark_dropped(packet);
      return XAIOS_ERR_NO_MEMORY;
    }
    flow->last_seen_ns = start;
    flow->state = XAIOS_NETWORK_FLOW_SYN_RECV;
    flow->retransmits = 0;
    flow->packets_rx = 1;
    flow->packets_tx = 0;
    {
      uint32_t header_bytes = (uint32_t)(parsed_tcp_header[12U] >> 4U) * 4U;
      tcp_parsed_options_t options;
      if (!net_wire_parse_tcp_options(parsed_tcp_header, header_bytes, &options)) {
        net_tcp_release_flow(flow);
        net_packet_mark_dropped(packet);
        return XAIOS_ERR_INVALID;
      }
      flow->peer_mss = options.mss > 0U && options.mss < NETWORK_TCP_IPV6_MSS ?
                           options.mss : NETWORK_TCP_IPV6_MSS;
      flow->mss_parsed = 1U;
      flow->peer_ws = options.window_scale;
      flow->ws_parsed = options.window_scale > 0U ? 1U : 0U;
      flow->peer_sack_permitted = options.sack_permitted;
      flow->our_ws = 0U;
      flow->peer_window = peer_window_raw;
    }
    net_tcp_note_handshake();
    net_stack_note_ipv6_rx();
    net_packet_mark_tx(packet);
    net_packet_mark_complete(packet);
    net_tcp_record_latency(timer_now_ns() - start);
    return XAIOS_OK;
  }

  if (flow != 0 && flow->state == XAIOS_NETWORK_FLOW_SYN_RECV &&
      (flags & NETWORK_TCP_FLAG_ACK) != 0U) {
    if (ack_v != flow->next_send_seq || seq != flow->expected_seq) {
      net_packet_mark_dropped(packet);
      return XAIOS_ERR_INVALID;
    }
    net_tcp_half_open_release();
    if (!accept_queue_enqueue(flow->flow_id, 0, src_port, dst_port,
                              &src_addr)) {
      net_tcp_release_flow(flow);
      net_packet_mark_dropped(packet);
      return XAIOS_ERR_BUSY;
    }
    flow->state = XAIOS_NETWORK_FLOW_ESTABLISHED;
    flow->pending_synack = 0;
    flow->local_seq = ack_v;
    flow->next_send_seq = ack_v;
    flow->last_seen_ns = start;
    flow->keepalive_last_rx_ns = start;
    flow->peer_window = net_wire_tcp_scaled_window(peer_window_raw, flow->peer_ws);
    ++flow->packets_rx;
    net_tcp_note_handshake();
    net_tcp_note_established();
    net_packet_mark_tx(packet);
    net_packet_mark_complete(packet);
    net_tcp_record_latency(timer_now_ns() - start);
    return XAIOS_OK;
  }

  if (flow != 0 && (flow->state == XAIOS_NETWORK_FLOW_ESTABLISHED ||
                     flow->state == XAIOS_NETWORK_FLOW_CLOSE_WAIT ||
                     flow->state == XAIOS_NETWORK_FLOW_FIN_WAIT ||
                     flow->state == XAIOS_NETWORK_FLOW_FIN_WAIT_2 ||
                     flow->state == XAIOS_NETWORK_FLOW_LAST_ACK ||
                     flow->state == XAIOS_NETWORK_FLOW_TIME_WAIT)) {
    if ((flags & NETWORK_TCP_FLAG_ACK) != 0U &&
        net_wire_tcp_seq_after(ack_v, flow->next_send_seq)) {
      net_packet_mark_dropped(packet);
      return XAIOS_ERR_INVALID;
    }
    flow->last_seen_ns = start;
    flow->peer_window = net_wire_tcp_scaled_window(peer_window_raw, flow->peer_ws);
    ++flow->packets_rx;

    /* Extract TCP payload from IPv6 frame */
    /* IPv6 header is 40 bytes at offset 14, TCP header starts after that */
    const uint8_t *ip6 = frame + 14U;
    const uint8_t *tcp_hdr = ip6 + 40U;
    uint64_t tcp_hdr_bytes = (uint64_t)(tcp_hdr[12] >> 4U) * 4U;
    uint16_t ip6_payload_len = net_wire_read_u16_be(ip6 + 4U);
    uint32_t payload_len_v6 = (uint32_t)ip6_payload_len - (uint32_t)tcp_hdr_bytes;

    if (payload_len_v6 > NETWORK_TCP_IPV6_RX_MAX) {
      net_packet_mark_dropped(packet);
      return XAIOS_ERR_INVALID;
    }
    if (payload_len_v6 > 0U && flow->rx_buf != 0) {
      const uint8_t *payload = tcp_hdr + tcp_hdr_bytes;
      uint32_t payload_seq = seq;
      uint32_t deliver_len = payload_len_v6;
      if (net_wire_tcp_seq_before(payload_seq, flow->expected_seq)) {
        uint32_t overlap = flow->expected_seq - payload_seq;
        if (overlap >= deliver_len) deliver_len = 0U;
        else {
          payload += overlap;
          payload_seq += overlap;
          deliver_len -= overlap;
        }
      }
      if (deliver_len != 0U && payload_seq == flow->expected_seq) {
        uint32_t written = sockbuf_write(flow->rx_buf, payload, deliver_len);
        flow->expected_seq += written;
        flow->pending_ack = 1U;
        flow->window_size = (uint16_t)sockbuf_available(flow->rx_buf);
        net_tcp_ooo_buffer_drain(flow);
      } else if (deliver_len != 0U &&
                 net_wire_tcp_seq_after(payload_seq, flow->expected_seq)) {
        net_tcp_ooo_buffer_store(flow, payload_seq, payload, deliver_len,
                         flow->expected_seq);
      } else {
        flow->pending_ack = 1U;
      }
    }

    if ((flags & NETWORK_TCP_FLAG_FIN) != 0U) {
      uint32_t fin_seq = seq + payload_len_v6;
      flow->pending_ack = 1U;
      if (!net_wire_tcp_seq_before(fin_seq, flow->expected_seq)) {
        flow->peer_fin_seq = fin_seq;
        flow->peer_fin_pending = 1U;
        net_tcp_accept_peer_fin(flow, start);
      }
    }
    flow->keepalive_last_rx_ns = start;
    flow->keepalive_probes_sent = 0U;
    flow->pending_keepalive = 0U;
    net_tcp_accept_peer_fin(flow, start);

    if ((flags & NETWORK_TCP_FLAG_ACK) != 0U) {
      tcp_parsed_options_t options;
      if (!net_wire_parse_tcp_options(tcp_hdr, (uint32_t)tcp_hdr_bytes, &options)) {
        net_packet_mark_dropped(packet);
        return XAIOS_ERR_INVALID;
      }
      (void)net_tcp_apply_sack_blocks(flow, &options);
      int ack_result = net_tcp_acknowledge(flow, ack_v, start);
      if (ack_result < 0) {
        net_packet_mark_dropped(packet);
        return XAIOS_ERR_INVALID;
      }
      if (ack_result > 0) {
        net_packet_mark_tx(packet);
        net_packet_mark_complete(packet);
        net_tcp_record_latency(timer_now_ns() - start);
        return XAIOS_OK;
      }
    }

    if (flow->close_requested && flow->fin_outstanding == 0U &&
        (flow->state == XAIOS_NETWORK_FLOW_ESTABLISHED ||
         flow->state == XAIOS_NETWORK_FLOW_CLOSE_WAIT) &&
        (flow->tx_buf == 0 || sockbuf_used(flow->tx_buf) == 0)) {
      flow->pending_fin = 1;
    }

    net_packet_mark_tx(packet);
    net_packet_mark_complete(packet);
    net_tcp_record_latency(timer_now_ns() - start);
    return XAIOS_OK;
  }

  net_tcp_note_reset();
  net_packet_mark_dropped(packet);
  return XAIOS_ERR_INVALID;
}
