/*
 * The IPv4 TCP receive classifier, moved out of network_stack.c.
 *
 * This is one half of the cut network_stack.c's note said had to wait: the
 * handler holds a live pointer into the flow table across its whole body, and
 * a row is about 17 KB against a 16 KB secondary stack, so it cannot take a
 * copy. It now takes the caller's table -- network_stack.c's public
 * network_stack_process_tcp_frame() wrapper supplies it -- and indexes it in
 * place, so no row copy is made on the receive path. The scalar state it
 * touched directly crosses through net_stack_alloc_flow_id() and the
 * net_tcp_half_open_release() helper.
 *
 * The IPv6 handler is the exact twin in network_stack_tcp_frame_v6.c; the two
 * stayed separate because together they are longer than the limit, not because
 * they are cohesive apart.
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

xaios_status_t net_tcp_frame_process_v4(network_tcp_flow_t *flows,
                                        const uint8_t *frame,
                                        uint64_t frame_len) {
  if (frame == 0 || frame_len < 54U) {
    net_tcp_note_reset();
    net_note_packet_drop();
    return XAIOS_ERR_INVALID;
  }

  uint64_t start = timer_now_ns();
  uint16_t src_port = 0;
  uint16_t dst_port = 0;
  uint32_t seq = 0;
  uint32_t ack = 0;
  uint8_t flags = 0;

  if (net_wire_parse_tcp(frame, frame_len, &src_port, &dst_port, &seq, &ack, &flags) ==
      0) {
    net_tcp_note_reset();
    net_note_packet_drop();
    return XAIOS_ERR_INVALID;
  }
  if (src_port == 0U || dst_port == 0U) {
    net_tcp_note_reset();
    net_note_packet_drop();
    return XAIOS_ERR_INVALID;
  }

  const network_ip4_header_t *ip =
      (const network_ip4_header_t *)(frame + 14U);
  uint32_t parsed_ip_header_bytes = (uint32_t)(ip->version_ihl & 0x0fU) * 4U;
  const uint8_t *parsed_tcp_header = frame + 14U + parsed_ip_header_bytes;
  uint16_t peer_window_raw = net_wire_read_u16_be(parsed_tcp_header + 14U);
  uint32_t remote_address = net_wire_ip4_addr_host_order(ip->source);
  uint32_t local_address = net_wire_ip4_addr_host_order(ip->destination);

  network_tcp_flow_t *flow =
      net_tcp_table_find_v4(flows, dst_port, src_port, remote_address);
  network_queue_binding_t binding;
  int have_binding =
      flow != 0 ? net_queue_binding_find(flow->queue_id, &binding)
                : net_queue_binding_select(dst_port, src_port, local_address,
                                           remote_address, &binding);
  if (have_binding == 0) {
    net_tcp_note_reset();
    net_note_packet_drop();
    return XAIOS_ERR_NOT_FOUND;
  }

  uint32_t packet =
      net_packet_alloc(binding.queue_id, frame_len, start, src_port, dst_port,
                       remote_address, local_address, 0, 0);
  if (packet == 0) {
    net_tcp_note_reset();
    return XAIOS_ERR_NO_MEMORY;
  }

  if (flow != 0 && flow->state == XAIOS_NETWORK_FLOW_SYN_SENT &&
      (flags & (NETWORK_TCP_FLAG_SYN | NETWORK_TCP_FLAG_ACK)) ==
          (NETWORK_TCP_FLAG_SYN | NETWORK_TCP_FLAG_ACK) &&
      (flags & (NETWORK_TCP_FLAG_FIN | NETWORK_TCP_FLAG_RST)) == 0U) {
    if (ack != flow->next_send_seq) {
      net_packet_mark_dropped(packet);
      return XAIOS_ERR_INVALID;
    }
    uint32_t tcp_header_bytes = (uint32_t)(parsed_tcp_header[12U] >> 4U) * 4U;
    tcp_parsed_options_t options;
    if (!net_wire_parse_tcp_options(parsed_tcp_header, tcp_header_bytes, &options)) {
      net_packet_mark_dropped(packet);
      return XAIOS_ERR_INVALID;
    }
    flow->remote_seq = seq;
    flow->expected_seq = seq + 1U;
    flow->local_seq = ack;
    flow->next_send_seq = ack;
    flow->peer_mss = options.mss > 0U && options.mss < NETWORK_TCP_MSS
                         ? options.mss
                         : NETWORK_TCP_MSS;
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
      if (prev_state == XAIOS_NETWORK_FLOW_SYN_RECV ||
          prev_state == XAIOS_NETWORK_FLOW_SYN_SENT) {
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
    flow = net_tcp_table_alloc(flows, dst_port, src_port, remote_address, 0);
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
    flow->remote_address = remote_address;
    flow->local_address = local_address;
    flow->remote_seq = seq;
    /* Data plane: set expected_seq (SYN consumes 1 seq number) */
    flow->expected_seq = seq + 1U;
    /* Generate ISN from timer and flow ID */
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
    /* Allocate socket buffers */
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

    /* Parse MSS and window scale from the peer SYN. */
    {
      const network_ip4_header_t *iph4 =
          (const network_ip4_header_t *)(frame + 14U);
      uint32_t ip_hdr_b = (uint32_t)(iph4->version_ihl & 0x0fU) * 4U;
      const uint8_t *thdr = frame + 14U + ip_hdr_b;
      uint32_t thdr_b = (uint32_t)(thdr[12] >> 4U) * 4U;
      tcp_parsed_options_t options;
      if (!net_wire_parse_tcp_options(thdr, thdr_b, &options)) {
        net_tcp_release_flow(flow);
        net_packet_mark_dropped(packet);
        return XAIOS_ERR_INVALID;
      }
      flow->peer_mss = options.mss > 0U && options.mss < NETWORK_TCP_MSS ?
                           options.mss : NETWORK_TCP_MSS;
      flow->mss_parsed = 1;
      flow->peer_ws = options.window_scale;
      flow->ws_parsed = options.window_scale > 0U ? 1U : 0U;
      flow->peer_sack_permitted = options.sack_permitted;
      flow->our_ws = 0;
      flow->peer_window = peer_window_raw;
    }

    net_tcp_note_handshake();
    net_packet_mark_tx(packet);
    net_packet_mark_complete(packet);
    net_tcp_record_latency(timer_now_ns() - start);
    return XAIOS_OK;
  }

  if (flow != 0 && flow->state == XAIOS_NETWORK_FLOW_SYN_RECV &&
      (flags & NETWORK_TCP_FLAG_ACK) != 0U) {
    if (ack != flow->next_send_seq || seq != flow->expected_seq) {
      net_packet_mark_dropped(packet);
      return XAIOS_ERR_INVALID;
    }
    uint32_t peer_ip_be = ((remote_address & 0xFFU) << 24U) |
                           (((remote_address >> 8U) & 0xFFU) << 16U) |
                           (((remote_address >> 16U) & 0xFFU) << 8U) |
                           ((remote_address >> 24U) & 0xFFU);
    net_tcp_half_open_release();
    if (!accept_queue_enqueue(flow->flow_id, peer_ip_be, src_port, dst_port,
                              0)) {
      net_tcp_release_flow(flow);
      net_packet_mark_dropped(packet);
      return XAIOS_ERR_BUSY;
    }
    flow->state = XAIOS_NETWORK_FLOW_ESTABLISHED;
    flow->pending_synack = 0;
    flow->local_seq = ack;
    flow->next_send_seq = ack; /* peer confirmed our ISN+1 */
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
        net_wire_tcp_seq_after(ack, flow->next_send_seq)) {
      net_packet_mark_dropped(packet);
      return XAIOS_ERR_INVALID;
    }
    flow->last_seen_ns = start;
    flow->peer_window = net_wire_tcp_scaled_window(peer_window_raw, flow->peer_ws);
    ++flow->packets_rx;

    /* Extract TCP payload */
    const network_ip4_header_t *iph =
        (const network_ip4_header_t *)(frame + 14U);
    uint64_t ip_hdr_bytes = (uint64_t)(iph->version_ihl & 0x0FU) * 4U;
    uint16_t ip_total = net_wire_read_u16_be((const uint8_t *)&iph->total_length);
    const uint8_t *tcp_hdr = frame + 14U + ip_hdr_bytes;
    uint64_t tcp_hdr_bytes = (uint64_t)(tcp_hdr[12] >> 4U) * 4U;
    uint32_t payload_len = (uint32_t)(ip_total) - (uint32_t)ip_hdr_bytes -
                            (uint32_t)tcp_hdr_bytes;

    if (payload_len > NETWORK_TCP_IPV4_RX_MAX) {
      net_packet_mark_dropped(packet);
      return XAIOS_ERR_INVALID;
    }
    if (payload_len > 0U && flow->rx_buf != 0) {
      const uint8_t *payload = tcp_hdr + tcp_hdr_bytes;
      uint32_t payload_seq = seq;
      uint32_t deliver_len = payload_len;
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
        /* Drain any newly contiguous out-of-order data. */
        net_tcp_ooo_buffer_drain(flow);
      } else if (deliver_len != 0U &&
                 net_wire_tcp_seq_after(payload_seq, flow->expected_seq)) {
        /* Retain future data for bounded reordering recovery. */
        net_tcp_ooo_buffer_store(flow, payload_seq, payload, deliver_len,
                         flow->expected_seq);
      } else {
        flow->pending_ack = 1U;
      }
    }

    if ((flags & NETWORK_TCP_FLAG_FIN) != 0U) {
      uint32_t fin_seq = seq + payload_len;
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
      int ack_result = net_tcp_acknowledge(flow, ack, start);
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

    /* If close was requested and all data sent, mark FIN pending */
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
