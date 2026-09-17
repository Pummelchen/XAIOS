/*
 * The TCP timers -- SYN/SYN-ACK retransmission and flow expiry -- moved out of
 * network_stack.c.
 *
 * These two entry points were the periodic tail of the poll path. They walk
 * the table, so they cannot copy a row (a network_tcp_flow_t is about 17 KB
 * against a 16 KB secondary stack); they take the caller's table and index it
 * in place, exactly as the functions they replace did. The only scalar they
 * touched directly is g_half_open_count, which network_stack.c keeps; the
 * guarded decrement crosses as net_tcp_half_open_release(), which is the same
 * `if (count > 0U) --count` that stood at that site.
 *
 * Locking. Both run with the stack guard already held; neither takes a lock of
 * its own, so no critical section is widened, narrowed or split.
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

uint64_t net_tcp_table_retransmit(network_tcp_flow_t *flows, uint64_t now_ns) {
  uint64_t retransmitted = 0;
  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    if ((flows[i].state == XAIOS_NETWORK_FLOW_SYN_RECV ||
         flows[i].state == XAIOS_NETWORK_FLOW_SYN_SENT) &&
        now_ns > flows[i].last_seen_ns &&
        now_ns - flows[i].last_seen_ns >= NETWORK_TCP_RETRANSMIT_NS &&
        flows[i].retransmits < NETWORK_TCP_MAX_RETRANSMITS) {
      ++flows[i].retransmits;
      ++flows[i].packets_tx;
      flows[i].last_seen_ns = now_ns;
      if (flows[i].state == XAIOS_NETWORK_FLOW_SYN_SENT)
        flows[i].pending_syn = 1U;
      else
        flows[i].pending_synack = 1U;
      net_tcp_note_retransmit();
      ++retransmitted;
      klog("network: tcp flow id=%u retransmit=%u queue=%u cell=%u\n",
           flows[i].flow_id, flows[i].retransmits,
           flows[i].queue_id, flows[i].cell_id);
    }
  }
  return retransmitted;
}

uint64_t net_tcp_table_expire(network_tcp_flow_t *flows, uint64_t now_ns) {
  uint64_t expired = 0;
  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    network_tcp_flow_t *flow = &flows[i];

    /* TIME_WAIT expires after 2MSL and returns the slot to the pool. */
    if (flow->state == XAIOS_NETWORK_FLOW_TIME_WAIT &&
        now_ns > flow->last_seen_ns &&
        now_ns - flow->last_seen_ns >= UINT64_C(60000000000)) {
      net_tcp_note_closed();
      ++expired;
      klog("network: tcp flow id=%u TIME_WAIT expired\n", flow->flow_id);
      net_tcp_release_flow(flow);
      continue;
    }

    /* Closing states cannot hold a finite flow slot indefinitely. */
    if ((flow->state == XAIOS_NETWORK_FLOW_FIN_WAIT ||
         flow->state == XAIOS_NETWORK_FLOW_FIN_WAIT_2 ||
         flow->state == XAIOS_NETWORK_FLOW_LAST_ACK) &&
        now_ns > flow->last_seen_ns &&
        now_ns - flow->last_seen_ns >= UINT64_C(60000000000)) {
      net_tcp_note_closed();
      ++expired;
      klog("network: tcp flow id=%u close timeout\n", flow->flow_id);
      net_tcp_release_flow(flow);
      continue;
    }

    /* Passive and active handshake timeout. */
    if ((flow->state == XAIOS_NETWORK_FLOW_SYN_RECV ||
         flow->state == XAIOS_NETWORK_FLOW_SYN_SENT) &&
        now_ns > flow->last_seen_ns &&
        now_ns - flow->last_seen_ns >= NETWORK_TCP_SYN_TIMEOUT_NS) {
      net_tcp_note_timeout();
      net_tcp_note_closed();
      net_note_packet_drop();
      ++expired;
      net_tcp_half_open_release();
      klog("network: tcp flow id=%u timeout queue=%u cell=%u\n",
           flow->flow_id, flow->queue_id, flow->cell_id);
      net_tcp_release_flow(flow);
      continue;
    }

    /* Data retransmission for established or peer-closed flows. */
    if ((flow->state == XAIOS_NETWORK_FLOW_ESTABLISHED ||
         flow->state == XAIOS_NETWORK_FLOW_CLOSE_WAIT) &&
        flow->in_flight > 0U) {
      uint32_t oldest = net_tcp_tx_oldest_index(flow);
      if (oldest != TCP_TX_WINDOW_SEGMENTS &&
          flow->tx_segments[oldest].last_tx_ns > 0U &&
          now_ns > flow->tx_segments[oldest].last_tx_ns &&
          now_ns - flow->tx_segments[oldest].last_tx_ns >= flow->rto_ns) {
      if (flow->tx_segments[oldest].retries >= NETWORK_TCP_MAX_RETRANSMITS) {
        net_tcp_note_timeout();
        net_tcp_note_closed();
        ++expired;
        klog("network: tcp flow id=%u data retransmit limit\n",
             flow->flow_id);
        net_tcp_release_flow(flow);
        continue;
      }
      flow->retransmits++;
      flow->tx_segments[oldest].retries++;
      /* Retain and resend the authoritative outstanding segment. */
      flow->in_retransmit = 1;
      flow->tx_segments[oldest].pending = 1U;
      flow->tx_segments[oldest].retransmitted = 1U;
      net_tcp_backoff_rto(flow);
      net_tcp_note_retransmit();
      ++expired;
      klog("network: tcp flow id=%u retransmit=%u rto=%lu\n",
           flow->flow_id, flow->retransmits, flow->rto_ns);
      }
    }

    if ((flow->state == XAIOS_NETWORK_FLOW_FIN_WAIT ||
         flow->state == XAIOS_NETWORK_FLOW_LAST_ACK) &&
        flow->fin_outstanding != 0U && flow->fin_last_tx_ns != 0U &&
        now_ns > flow->fin_last_tx_ns &&
        now_ns - flow->fin_last_tx_ns >= flow->rto_ns) {
      if (flow->fin_retries >= NETWORK_TCP_MAX_RETRANSMITS) {
        net_tcp_note_timeout();
        net_tcp_note_closed();
        ++expired;
        klog("network: tcp flow id=%u FIN retransmit limit\n",
             flow->flow_id);
        net_tcp_release_flow(flow);
        continue;
      }
      ++flow->fin_retries;
      ++flow->retransmits;
      net_tcp_note_retransmit();
      ++expired;
      flow->fin_last_tx_ns = now_ns;
      flow->pending_fin = 1U;
    }

    /* Keepalive is idle-based; subsequent unanswered probes use the interval. */
    uint64_t keepalive_base = flow->keepalive_probes_sent == 0U ?
                                  flow->keepalive_last_rx_ns :
                                  flow->keepalive_last_tx_ns;
    uint64_t keepalive_delay = flow->keepalive_probes_sent == 0U ?
                                   TCP_KEEPALIVE_IDLE_NS :
                                   TCP_KEEPALIVE_INTERVAL_NS;
    if (flow->state == XAIOS_NETWORK_FLOW_ESTABLISHED &&
        keepalive_base != 0U && now_ns > keepalive_base &&
        now_ns - keepalive_base >= keepalive_delay) {
      if (flow->keepalive_probes_sent < TCP_KEEPALIVE_PROBES) {
        flow->keepalive_probes_sent++;
        flow->keepalive_last_tx_ns = now_ns;
        flow->pending_keepalive = 1U;
      } else {
        /* No response to keepalive probes — close connection */
        net_tcp_note_closed();
        ++expired;
        klog("network: tcp flow id=%u keepalive timeout\n", flow->flow_id);
        net_tcp_release_flow(flow);
        continue;
      }
    }
  }
  return expired;
}
