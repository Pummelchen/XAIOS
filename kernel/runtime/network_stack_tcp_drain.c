/*
 * The pending-transmit drain, moved out of network_stack.c.
 *
 * network_stack.c's own note had this function stay behind when the rest of
 * the poll plane left: it walks the TCP flow table, and a row is about 17 KB
 * against a 16 KB secondary stack, so it cannot be copied. It now takes the
 * caller's table and indexes it in place. The drain cursor and the interface
 * MAC it used to read directly cross through net_tcp_drain_cursor_take() and
 * the existing net_stack_local_mac() copy-out accessor.
 *
 * Locking. It runs with the stack guard already held, exactly as before, and
 * takes no lock of its own; the cursor is advanced before the loop in the same
 * order the old code advanced it.
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

void net_tcp_drain_pending(network_tcp_flow_t *flows) {
  uint32_t start_index = net_tcp_drain_cursor_take();
  uint8_t local_mac[6];
  net_stack_local_mac(local_mac);
  for (uint32_t offset = 0; offset < NETWORK_TCP_CONNECTIONS; ++offset) {
    uint32_t index = (start_index + offset) % NETWORK_TCP_CONNECTIONS;
    network_tcp_flow_t *flow = &flows[index];
    if (flow->state == XAIOS_NETWORK_FLOW_FREE ||
        flow->state == XAIOS_NETWORK_FLOW_CLOSED) {
      continue;
    }
    /* Resolve MAC if needed */
    if (!flow->remote_mac_valid) {
      if (flow->local_addr.family == XAIOS_IP_FAMILY_V6) {
        /* IPv6: use NDP cache for MAC resolution */
        xaios_ip_addr_t hop;
        net_v6_next_hop(&flow->remote_addr, timer_now_ns(), &hop);
        if (ndp_cache_lookup(&hop, flow->remote_mac) != XAIOS_OK) {
          /* Ask for it. An off-link destination resolves to the router, and
             nothing else on this path would ever solicit the router. */
          uint8_t solicitation[128];
          uint64_t solicitation_length = 0U;
          if (ndp_build_neighbor_solicitation(
                  solicitation, &solicitation_length, local_mac,
                  &flow->local_addr, &hop) == XAIOS_OK) {
            (void)network_device_tx(solicitation, solicitation_length);
          }
          continue; /* link-layer address not yet known */
        }
        flow->remote_mac_valid = 1;
      } else {
        /* IPv4: use ARP */
        uint32_t dest_net = flow->remote_address;
        uint32_t dest_ip_be = ((dest_net & 0xFFU) << 24U) |
                               (((dest_net >> 8U) & 0xFFU) << 16U) |
                               (((dest_net >> 16U) & 0xFFU) << 8U) |
                               ((dest_net >> 24U) & 0xFFU);
        if (!net_tcp_resolve_mac(dest_ip_be, flow->remote_mac, local_mac)) {
          continue;
        }
        flow->remote_mac_valid = 1;
      }
    }
    uint64_t now_ns = timer_now_ns();
    if (flow->pending_syn != 0U) {
      xaios_status_t syn_status = net_tcp_send_flow_segment(
          flow, flow->local_seq, NETWORK_TCP_FLAG_SYN, 0, 0);
      if (syn_status == XAIOS_OK) {
        flow->pending_syn = 0U;
        ++flow->packets_tx;
      } else if (flow->packets_tx == 0U) {
        klog("network: active TCP flow id=%u SYN send failed status=%d\n",
             flow->flow_id, syn_status);
      }
    }
    if (flow->pending_synack != 0U) {
      xaios_status_t synack_status = net_tcp_send_flow_segment(
          flow, flow->local_seq,
          NETWORK_TCP_FLAG_SYN | NETWORK_TCP_FLAG_ACK, 0, 0);
      if (synack_status == XAIOS_OK) {
        flow->pending_synack = 0U;
        ++flow->packets_tx;
      } else if (flow->packets_tx == 0U) {
        klog("network: tcp flow id=%u SYN-ACK send failed status=%d\n",
             flow->flow_id, synack_status);
      }
    }

    if (flow->state == XAIOS_NETWORK_FLOW_ESTABLISHED ||
        flow->state == XAIOS_NETWORK_FLOW_CLOSE_WAIT) {
      net_tcp_queue_send_window(flow);
    }

    for (uint32_t tx = 0U; tx < TCP_TX_WINDOW_SEGMENTS; ++tx) {
      if (flow->tx_segments[tx].in_use == 0U ||
          flow->tx_segments[tx].pending == 0U) {
        continue;
      }
      if (net_tcp_send_flow_segment(flow, flow->tx_segments[tx].seq,
                                NETWORK_TCP_FLAG_ACK | NETWORK_TCP_FLAG_PSH,
                                flow->tx_segments[tx].data,
                                flow->tx_segments[tx].len) == XAIOS_OK) {
        if (flow->tx_segments[tx].first_tx_ns == 0U) {
          flow->tx_segments[tx].first_tx_ns = now_ns;
        }
        flow->tx_segments[tx].last_tx_ns = now_ns;
        flow->tx_segments[tx].pending = 0U;
        flow->pending_ack = 0U;
        flow->pending_keepalive = 0U;
        ++flow->packets_tx;
      }
    }

    if ((flow->pending_ack != 0U || flow->pending_keepalive != 0U) &&
        net_tcp_tx_has_pending(flow) == 0) {
      uint32_t ack_seq = flow->pending_keepalive != 0U ?
                             flow->next_send_seq - 1U : flow->next_send_seq;
      if (net_tcp_send_flow_segment(flow, ack_seq, NETWORK_TCP_FLAG_ACK,
                                0, 0) == XAIOS_OK) {
        flow->pending_ack = 0U;
        flow->pending_keepalive = 0U;
        ++flow->packets_tx;
      }
    }

    if (flow->pending_fin != 0U &&
        (flow->tx_buf == 0 || sockbuf_used(flow->tx_buf) == 0U) &&
        flow->in_flight == 0U && net_tcp_tx_segment_count(flow) == 0U) {
      uint32_t fin_seq = flow->fin_outstanding != 0U ?
                             flow->fin_seq : flow->next_send_seq;
      if (net_tcp_send_flow_segment(flow, fin_seq,
                                NETWORK_TCP_FLAG_FIN | NETWORK_TCP_FLAG_ACK,
                                0, 0) == XAIOS_OK) {
        if (flow->fin_outstanding == 0U) {
          flow->fin_seq = fin_seq;
          flow->fin_outstanding = 1U;
          flow->fin_retries = 0U;
          flow->next_send_seq++;
          if (flow->state == XAIOS_NETWORK_FLOW_ESTABLISHED) {
            flow->state = XAIOS_NETWORK_FLOW_FIN_WAIT;
          } else if (flow->state == XAIOS_NETWORK_FLOW_CLOSE_WAIT) {
            flow->state = XAIOS_NETWORK_FLOW_LAST_ACK;
          }
        }
        flow->fin_last_tx_ns = now_ns;
        flow->pending_fin = 0U;
        ++flow->packets_tx;
      }
    }
  }
}
