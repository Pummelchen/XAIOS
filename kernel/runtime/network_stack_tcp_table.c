/*
 * The TCP flow table's find and allocation helpers, moved out of
 * network_stack.c.
 *
 * The table itself did not move: a network_tcp_flow_t row is about 17 KB
 * against a 16 KB secondary stack, so the row-copying cursor/commit pattern
 * that carried the listener and UDP tables across is not available here. Each
 * function takes the caller's table and returns a pointer into it, which is
 * the same discipline the TCP data plane already uses. The two callers -- the
 * frame handlers in network_stack_tcp_frame.c/_v6.c and the connection API in
 * network_stack_tcp_api.c -- receive the table from network_stack.c.
 *
 * Locking. Every function here runs with the stack guard already held; none
 * takes a lock of its own, so no critical section is widened, narrowed or
 * split.
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

network_tcp_flow_t *net_tcp_table_find_v6(
    network_tcp_flow_t *flows, uint16_t local_port, uint16_t remote_port,
    const xaios_ip_addr_t *remote_addr) {
  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    if (flows[i].state != XAIOS_NETWORK_FLOW_FREE &&
        flows[i].local_port == local_port &&
        flows[i].remote_port == remote_port &&
        xaios_ip_addr_equal(&flows[i].remote_addr, remote_addr)) {
      return &flows[i];
    }
  }
  return 0;
}

network_tcp_flow_t *net_tcp_table_find_v4(network_tcp_flow_t *flows,
                                          uint16_t local_port,
                                          uint16_t remote_port,
                                          uint32_t remote_address) {
  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    if (flows[i].state != XAIOS_NETWORK_FLOW_FREE &&
        flows[i].local_port == local_port &&
        flows[i].remote_port == remote_port &&
        flows[i].remote_address == remote_address) {
      return &flows[i];
    }
  }
  return 0;
}

static int tcp_flow_has_remote_tuple(const network_tcp_flow_t *flow,
                                     uint16_t local_port,
                                     uint16_t remote_port,
                                     uint32_t remote_address,
                                     const xaios_ip_addr_t *remote_addr) {
  if (flow->local_port != local_port || flow->remote_port != remote_port) {
    return 0;
  }
  if (remote_addr != 0) {
    return xaios_ip_addr_equal(&flow->remote_addr, remote_addr);
  }
  return flow->remote_address == remote_address;
}

network_tcp_flow_t *net_tcp_table_alloc(
    network_tcp_flow_t *flows, uint16_t local_port, uint16_t remote_port,
    uint32_t remote_address, const xaios_ip_addr_t *remote_addr) {
  /* Limit half-open connections before reserving a flow slot. */
  if (net_tcp_half_open_count() >= NETWORK_TCP_MAX_HALF_OPEN) {
    klog("network: SYN flood protection: rejecting connection (half-open: %u)\n", net_tcp_half_open_count());
    return 0;
  }

  uint32_t has_free = 0U;
  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    if (flows[i].state == XAIOS_NETWORK_FLOW_FREE) {
      has_free = 1U;
      break;
    }
  }
  if (has_free == 0U) {
    network_tcp_flow_t *oldest = 0;
    for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
      network_tcp_flow_t *candidate = &flows[i];
      if (candidate->state != XAIOS_NETWORK_FLOW_TIME_WAIT ||
          tcp_flow_has_remote_tuple(candidate, local_port, remote_port,
                                    remote_address, remote_addr)) {
        continue;
      }
      if (oldest == 0 || candidate->last_seen_ns < oldest->last_seen_ns) {
        oldest = candidate;
      }
    }
    if (oldest != 0) {
      klog("network: recycling TIME_WAIT flow id=%u for new tuple\n",
           oldest->flow_id);
      net_tcp_release_flow(oldest);
    }
  }

  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    if (flows[i].state == XAIOS_NETWORK_FLOW_FREE) {
      flows[i].state = XAIOS_NETWORK_FLOW_SYN_RECV;
      flows[i].retransmits = 0;
      flows[i].packets_rx = 0;
      flows[i].packets_tx = 0;
      /* Zero data plane fields */
      flows[i].rx_buf = 0;
      flows[i].tx_buf = 0;
      flows[i].expected_seq = 0;
      flows[i].next_send_seq = 0;
      flows[i].window_size = 0;
      flows[i].pending_synack = 0;
      flows[i].pending_syn = 0;
      flows[i].pending_fin = 0;
      flows[i].pending_ack = 0;
      flows[i].close_requested = 0;
      flows[i].remote_mac_valid = 0;
      flows[i].remote_address = 0;
      flows[i].local_address = 0;
      xaios_ip_addr_zero(&flows[i].remote_addr);
      xaios_ip_addr_zero(&flows[i].local_addr);
      /* Retransmission state. */
      flows[i].rto_ns = NETWORK_TCP_RETRANSMIT_NS;
      flows[i].in_retransmit = 0;
      /* Out-of-order receive state. */
      for (uint32_t j = 0; j < TCP_OOO_BUF_ENTRIES; ++j) {
        flows[i].ooo_buf[j].in_use = 0;
        flows[i].ooo_buf[j].seq = 0;
        flows[i].ooo_buf[j].len = 0;
      }
      /* MSS negotiation. */
      flows[i].peer_mss = 0;
      flows[i].mss_parsed = 0;
      /* Window scaling. */
      flows[i].ws_parsed = 0;
      flows[i].peer_sack_permitted = 0;
      flows[i].peer_ws = 0;
      flows[i].our_ws = 0;
      flows[i].peer_window = 0;
      /* Congestion control. */
      flows[i].cwnd = TCP_INIT_CWND * NETWORK_TCP_MSS;
      flows[i].ssthresh = TCP_INIT_SSTHRESH * NETWORK_TCP_MSS;
      flows[i].dup_ack_count = 0;
      flows[i].highest_acked = 0;
      flows[i].in_flight = 0;
      flows[i].zero_window_probe = 0;
      for (uint32_t j = 0U; j < TCP_TX_WINDOW_SEGMENTS; ++j) {
        flows[i].tx_segments[j].seq = 0U;
        flows[i].tx_segments[j].len = 0U;
        flows[i].tx_segments[j].in_use = 0U;
        flows[i].tx_segments[j].pending = 0U;
        flows[i].tx_segments[j].retransmitted = 0U;
        flows[i].tx_segments[j].retries = 0U;
        flows[i].tx_segments[j].first_tx_ns = 0U;
        flows[i].tx_segments[j].last_tx_ns = 0U;
      }
      flows[i].srtt_ns = 0;
      flows[i].rttvar_ns = 0;
      /* Keepalive. */
      flows[i].keepalive_last_rx_ns = 0;
      flows[i].keepalive_last_tx_ns = 0;
      flows[i].keepalive_probes_sent = 0;
      flows[i].pending_keepalive = 0;
      flows[i].fin_seq = 0;
      flows[i].peer_fin_seq = 0;
      flows[i].fin_last_tx_ns = 0;
      flows[i].fin_retries = 0;
      flows[i].fin_outstanding = 0;
      flows[i].peer_fin_pending = 0;
      flows[i].peer_fin_received = 0;
      net_tcp_half_open_acquire();
      return &flows[i];
    }
  }
  return 0;
}

uint64_t net_tcp_table_connections(const network_tcp_flow_t *flows) {
  uint64_t active = 0;
  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    if (flows[i].state == XAIOS_NETWORK_FLOW_ESTABLISHED) {
      ++active;
    }
  }
  return active;
}
