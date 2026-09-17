/*
 * The IPv4/IPv6 network stack: flows, listeners, sockets and the poll path.
 *
 * This file is large, and it has been measured rather than eyeballed before
 * being left that way. Cutting it anywhere past its state block produces a
 * worse interface than it solves:
 *
 *   cut after the declarations (line ~300)   11 symbols cross the boundary
 *   cut before the TCP data plane            88 symbols cross
 *   cut out the self-test                    50 symbols cross
 *
 * The reason was visible directly below this comment. Every counter, both flow
 * tables and the listener registry are file-scope state, and every layer
 * touches all of it, so a split relocates the coupling into a shared header
 * without reducing it. Splitting this file usefully means first putting that
 * state behind accessors -- a refactor with real risk, and one that wants
 * doing deliberately rather than alongside something else. It is tracked.
 *
 * Three of those cuts have landed. The listener registry, the accept queue and
 * the socket-to-flow map live in network_stack_listener.c, reached through the
 * row-copying accessors declared in network_stack_listener.h. The IPv6 address
 * state -- link-local, SLAAC, the public address, the default router and the
 * on-link prefix, with the router-advertisement handler that fills them in --
 * lives in network_stack_v6.c, reached through the copy-in/copy-out accessors
 * declared in network_stack_v6.h. The TCP data plane -- the per-flow state
 * machine in network_stack_tcp_flow.c and the segment builder and transmit
 * path in network_stack_tcp_segment.c, joined by the declarations in
 * network_stack_tcp.h -- needed no table accessor at all: every function takes
 * the flow row from the caller that already owns it. The receive dispatch was
 * the other candidate and still waits: it is interleaved with the poll tail
 * and reaches both flow tables, the packet descriptors, the queue rings and
 * the ping state, so it wants many more accessors than the address path or the
 * data plane did.
 *
 * The rest of this file -- the TCP/UDP flow tables and the counters -- is still
 * file-scope state, and the row-copying accessors are the pattern the next cut
 * should follow.
 *
 * The layout, for navigation:
 *
 *   constants and types            declarations, sizes, protocol numbers
 *   shared state                   counters, flow tables
 *   guard                          see xaios_reentrant_lock; C-01
 *   helpers                        byte order, checksums, frame construction
 *   receive path                   frame classification and dispatch
 *   TCP flow state machine         moved to network_stack_tcp_flow.c
 *   TCP segment builder/transmit   moved to network_stack_tcp_segment.c
 *   listener, accept, socket map   moved to network_stack_listener.c
 *   IPv6 address state             moved to network_stack_v6.c
 *   public API                     the entry points a syscall reaches
 *   self-test                      the boot-time network self-test
 */

#include <xaios/arp.h>

#include "network_stack_listener.h"
#include "network_stack_v6.h"
#include "network_stack_wire.h"
#include "network_stack_tcp.h"
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

/* Janeway — “Break off your pursuit or we'll open fire.” */

/* Twice the receive ring depth, so one poll can clear a full ring and the
   refills that land while it works. */
#define NETWORK_POLL_RX_BUDGET 16U

#define NETWORK_PACKET_DESCRIPTORS 32U
#define NETWORK_QUEUE_RING_SIZE 8U
#define NETWORK_UDP_IDLE_TIMEOUT_NS UINT64_C(30000000000)
#define NETWORK_TCP_SYN_TIMEOUT_NS UINT64_C(10000000000)
#define NETWORK_TCP_MAX_RETRANSMITS 5U

/* TCP options kind bytes */

#define NETWORK_TCP_IPV6_RX_MAX 1440U
#define NETWORK_TCP_WSCALE_OK 1U

/* Congestion control constants */
#define TCP_INIT_CWND     1U
#define TCP_INIT_SSTHRESH 16U

/* Keepalive defaults (in seconds, converted to ns elsewhere) */
#define TCP_KEEPALIVE_IDLE_NS     UINT64_C(7200000000000)  /* 2 hours */
#define TCP_KEEPALIVE_INTERVAL_NS UINT64_C(10000000000)    /* 10 seconds */
#define TCP_KEEPALIVE_PROBES     3U

typedef struct network_queue_binding {
  uint32_t queue_id;
  uint32_t cell_id;
  uint32_t core_mask;
  uint32_t in_use;
} network_queue_binding_t;

typedef struct network_queue_ring {
  uint32_t queue_id;
  uint32_t rx_depth;
  uint32_t tx_depth;
  uint64_t completed;
  uint64_t drops;
} network_queue_ring_t;

typedef enum network_packet_state {
  NETWORK_PACKET_FREE = 0,
  NETWORK_PACKET_RX_OWNED = 1,
  NETWORK_PACKET_TX_QUEUED = 2,
  NETWORK_PACKET_COMPLETE = 3,
  NETWORK_PACKET_DROPPED = 4,
} network_packet_state_t;

typedef struct network_packet_desc {
  network_packet_state_t state;
  uint32_t queue_id;
  uint32_t cell_id;
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t src_address;
  uint32_t dst_address;
  xaios_ip_addr_t src_addr;
  xaios_ip_addr_t dst_addr;
  uint64_t length;
  uint64_t created_ns;
} network_packet_desc_t;

static network_queue_binding_t g_queue_bindings[XAIOS_NETWORK_MAX_QUEUE_BINDINGS];
static network_queue_ring_t g_queue_rings[XAIOS_NETWORK_MAX_QUEUE_BINDINGS];
static uint64_t g_next_flow_id = 1U;
static network_packet_desc_t g_packet_descs[NETWORK_PACKET_DESCRIPTORS];
static network_udp_flow_t g_udp_flows[NETWORK_UDP_FLOWS];
static network_tcp_flow_t g_tcp_flows[NETWORK_TCP_CONNECTIONS];

/* VirtIO RX/TX and the TCP table are shared by service and child CPUs. */

/* C-01: this stack's tables are mutated in about a hundred and seventy places
   with almost no serialisation, and ten of its exported functions call other
   exported ones. See xaios_reentrant_lock for why that combination needs a
   depth-counting guard rather than a plain lock at each entry point. */
static xaios_reentrant_lock_t g_network_guard =
    XAIOS_REENTRANT_LOCK_INIT("network guard");

static void network_lock(void) {
  xaios_reentrant_lock(&g_network_guard, smp_cpu_id());
}

static void network_unlock(void) { xaios_reentrant_unlock(&g_network_guard); }

/* The listener registry had its own guard for a while. Measurement on a quiet
   machine says it bought nothing: socket bind and close cost the same at four
   and eight threads with one guard or two, and the "socket path does not
   scale" finding that justified the split turned out to be contention with an
   unrelated process on the host rather than anything in this stack. A second
   lock order is a real cost -- it produced an inversion during the work -- so
   the registry is back under the stack's own guard, and the readers keep the
   coverage the split gave them. */
static void listener_lock(void) { network_lock(); }

static void listener_unlock(void) { network_unlock(); }

/* The resolver lives inside this stack and must share its guard; see the
   declaration in network_stack.h. */
void network_stack_lock(void) { network_lock(); }
void network_stack_unlock(void) { network_unlock(); }

/* Bound half-open state so SYN floods cannot exhaust the flow table. */
#define NETWORK_TCP_MAX_HALF_OPEN 16U

static uint32_t g_half_open_count = 0;

static uint8_t g_local_mac[6];
static uint32_t g_persistent_initialized;
static uint64_t g_poll_tick_count;
/* Polls taken by the CPU carrying the network tick, counted apart from the
   ones a syscall makes. See network_tick_poll_count() in the header. */
static uint64_t g_tick_poll_count;
#define NETWORK_POLL_GAP_OUTAGE_NS UINT64_C(1000000000)
#define NETWORK_POLL_GAP_RECORD_LINES 32U

static uint64_t g_poll_last_ns;
static uint64_t g_poll_gap_max_ns;
static uint64_t g_poll_gap_outage_count;
static uint32_t g_poll_gap_record_lines;
static uint32_t g_tcp_drain_cursor;
static uint64_t g_icmp_reply_count;
static uint64_t g_arp_reply_count;
static uint64_t g_icmpv6_reply_count;
static uint64_t g_ndp_reply_count;
static uint64_t g_ipv6_rx_count;
/* The IPv6 address state -- the link-local, SLAAC and public addresses, the
   default router and the on-link prefix -- now lives in network_stack_v6.c
   behind the accessors declared in network_stack_v6.h. Nothing here hands out
   a pointer into it; every reader gets a copy. */

static xaios_network_ping_status_t g_ping;
static uint64_t g_ping_sent_ns;
static uint16_t g_ping_sequence;

#define NETWORK_PING_IDENTIFIER UINT16_C(0x5841)
#define NETWORK_PING_TIMEOUT_NS UINT64_C(3000000000)

static uint64_t g_udp_tx_count;
static uint64_t g_udp_rx_count;
static uint64_t g_udp_malformed_count;
static uint64_t g_udp_dropped_count;
static uint64_t g_udp_flow_hit_count;
static uint64_t g_udp_expired_count;
static uint64_t g_tcp_handshake_count;
static uint64_t g_tcp_reset_count;
static uint64_t g_tcp_timeout_count;
static uint64_t g_tcp_retransmit_count;
static uint64_t g_tcp_established_count;
static uint64_t g_tcp_closed_count;

/* The two increments the TCP flow module makes, kept beside the counters it
   writes and declared in network_stack_tcp.h. Caller holds the stack guard;
   each is the plain increment the moved code made in place of these. */
void net_tcp_note_closed(void) { ++g_tcp_closed_count; }
void net_tcp_note_retransmit(void) { ++g_tcp_retransmit_count; }
static uint64_t g_queue_binding_count;
static uint64_t g_rx_packet_count;
static uint64_t g_tx_packet_count;
static uint64_t g_packet_drop_count;
static uint64_t g_packet_lifecycle_count;
static uint64_t g_queue_rx_enqueue_count;
static uint64_t g_queue_tx_enqueue_count;
static uint64_t g_queue_completion_count;
static uint64_t g_queue_backpressure_drop_count;
static uint64_t g_flow_core_mismatch_count;

static uint64_t g_udp_latency_samples[NETWORK_MAX_SAMPLES];
static uint64_t g_tcp_latency_samples[NETWORK_MAX_SAMPLES];
static uint32_t g_udp_latency_count;
static uint32_t g_tcp_latency_count;


/* The listener registry and the socket-to-flow map now live in
   network_stack_listener.c; network_stack_listener.h declares the accessors
   the rest of this file uses and the row types they speak. */


xaios_status_t network_stack_adopt_dhcpv6(const xaios_ip_addr_t *address,
                                          uint32_t valid_lifetime_s) {
  if (address == 0 || address->family != XAIOS_IP_FAMILY_V6) {
    return XAIOS_ERR_INVALID;
  }
  if (valid_lifetime_s == 0U) return XAIOS_ERR_INVALID;
  uint64_t now_ns = timer_now_ns();
  uint64_t lifetime_ns = (uint64_t)valid_lifetime_s * UINT64_C(1000000000);
  uint64_t valid_until_ns =
      lifetime_ns > UINT64_MAX - now_ns ? UINT64_MAX : now_ns + lifetime_ns;
  network_lock();
  /* The lease, and the public address it becomes when it is globally
     routable, are written together under the guard the moved code used. */
  net_v6_adopt_dhcpv6(address, valid_until_ns);
  network_unlock();
  klog("network: IPv6 address configured by DHCPv6 valid_s=%u (%s)\n",
       valid_lifetime_s,
       net_v6_is_global_unicast(address) != 0 ? "global" : "local");
  return XAIOS_OK;
}

static void record_latency(uint64_t *samples, uint32_t *count, uint64_t value) {
  if (*count < NETWORK_MAX_SAMPLES) {
    samples[*count] = value;
    ++(*count);
  }
}

static network_queue_binding_t *find_binding(uint32_t queue_id) {
  for (uint32_t i = 0; i < XAIOS_NETWORK_MAX_QUEUE_BINDINGS; ++i) {
    if (g_queue_bindings[i].in_use != 0 &&
        g_queue_bindings[i].queue_id == queue_id) {
      return &g_queue_bindings[i];
    }
  }
  return 0;
}

static network_queue_ring_t *find_queue_ring(uint32_t queue_id) {
  for (uint32_t i = 0; i < XAIOS_NETWORK_MAX_QUEUE_BINDINGS; ++i) {
    if (g_queue_rings[i].queue_id == queue_id) {
      return &g_queue_rings[i];
    }
  }
  return 0;
}

static uint32_t active_binding_count(void) {
  uint32_t active = 0;
  for (uint32_t i = 0; i < XAIOS_NETWORK_MAX_QUEUE_BINDINGS; ++i) {
    if (g_queue_bindings[i].in_use != 0) {
      ++active;
    }
  }
  return active;
}

static network_queue_binding_t *binding_by_active_index(uint32_t index) {
  for (uint32_t i = 0; i < XAIOS_NETWORK_MAX_QUEUE_BINDINGS; ++i) {
    if (g_queue_bindings[i].in_use != 0) {
      if (index == 0U) {
        return &g_queue_bindings[i];
      }
      --index;
    }
  }
  return 0;
}

static network_queue_binding_t *select_binding_for_flow(uint16_t local_port,
                                                        uint16_t remote_port,
                                                        uint32_t local_address,
                                                        uint32_t remote_address) {
  uint32_t active = active_binding_count();
  if (active == 0U) {
    return 0;
  }
  uint32_t hash = (uint32_t)local_port ^ ((uint32_t)remote_port << 3U) ^
                  local_address ^ (remote_address >> 8U);
  return binding_by_active_index(hash % active);
}

static void queue_ring_reset(uint32_t queue_id) {
  network_queue_ring_t *ring = find_queue_ring(queue_id);
  if (ring == 0) {
    return;
  }
  ring->rx_depth = 0;
  ring->tx_depth = 0;
  ring->completed = 0;
  ring->drops = 0;
}

static int queue_ring_rx_enqueue(uint32_t queue_id) {
  network_queue_ring_t *ring = find_queue_ring(queue_id);
  if (ring == 0 || ring->rx_depth >= NETWORK_QUEUE_RING_SIZE) {
    ++g_queue_backpressure_drop_count;
    if (ring != 0) {
      ++ring->drops;
    }
    return 0;
  }
  ++ring->rx_depth;
  ++g_queue_rx_enqueue_count;
  return 1;
}

static void queue_ring_rx_complete(uint32_t queue_id) {
  network_queue_ring_t *ring = find_queue_ring(queue_id);
  if (ring != 0 && ring->rx_depth > 0U) {
    --ring->rx_depth;
  }
}

static int queue_ring_tx_enqueue(uint32_t queue_id) {
  network_queue_ring_t *ring = find_queue_ring(queue_id);
  if (ring == 0 || ring->tx_depth >= NETWORK_QUEUE_RING_SIZE) {
    ++g_queue_backpressure_drop_count;
    if (ring != 0) {
      ++ring->drops;
    }
    return 0;
  }
  ++ring->tx_depth;
  ++g_queue_tx_enqueue_count;
  return 1;
}

static void queue_ring_tx_complete(uint32_t queue_id) {
  network_queue_ring_t *ring = find_queue_ring(queue_id);
  if (ring != 0) {
    if (ring->tx_depth > 0U) {
      --ring->tx_depth;
    }
    ++ring->completed;
    ++g_queue_completion_count;
  }
}

static network_packet_desc_t *alloc_packet_desc(uint32_t queue_id,
                                                uint64_t length,
                                                uint64_t now_ns) {
  network_queue_binding_t *binding = find_binding(queue_id);
  if (binding == 0 || length == 0 || length > NETWORK_BUFFER_SIZE) {
    ++g_packet_drop_count;
    return 0;
  }
  if (queue_ring_rx_enqueue(queue_id) == 0) {
    ++g_packet_drop_count;
    return 0;
  }

  for (uint32_t i = 0; i < NETWORK_PACKET_DESCRIPTORS; ++i) {
    if (g_packet_descs[i].state == NETWORK_PACKET_FREE ||
        g_packet_descs[i].state == NETWORK_PACKET_COMPLETE ||
        g_packet_descs[i].state == NETWORK_PACKET_DROPPED) {
      g_packet_descs[i].state = NETWORK_PACKET_RX_OWNED;
      g_packet_descs[i].queue_id = queue_id;
      g_packet_descs[i].cell_id = binding->cell_id;
      g_packet_descs[i].src_port = 0;
      g_packet_descs[i].dst_port = 0;
      g_packet_descs[i].src_address = 0;
      g_packet_descs[i].dst_address = 0;
      g_packet_descs[i].length = length;
      g_packet_descs[i].created_ns = now_ns;
      ++g_rx_packet_count;
      ++g_packet_lifecycle_count;
      return &g_packet_descs[i];
    }
  }

  queue_ring_rx_complete(queue_id);
  ++g_packet_drop_count;
  return 0;
}

static void packet_mark_dropped(network_packet_desc_t *packet);

static void packet_mark_tx(network_packet_desc_t *packet) {
  if (packet != 0 && packet->state == NETWORK_PACKET_RX_OWNED) {
    if (queue_ring_tx_enqueue(packet->queue_id) == 0) {
      packet_mark_dropped(packet);
      return;
    }
    queue_ring_rx_complete(packet->queue_id);
    packet->state = NETWORK_PACKET_TX_QUEUED;
    ++g_tx_packet_count;
    ++g_packet_lifecycle_count;
  }
}

static void packet_mark_complete(network_packet_desc_t *packet) {
  if (packet != 0 && packet->state == NETWORK_PACKET_TX_QUEUED) {
    queue_ring_tx_complete(packet->queue_id);
    packet->state = NETWORK_PACKET_COMPLETE;
    ++g_packet_lifecycle_count;
  }
}

static void packet_mark_dropped(network_packet_desc_t *packet) {
  if (packet != 0 && packet->state != NETWORK_PACKET_DROPPED) {
    if (packet->state == NETWORK_PACKET_RX_OWNED) {
      queue_ring_rx_complete(packet->queue_id);
    } else if (packet->state == NETWORK_PACKET_TX_QUEUED) {
      queue_ring_tx_complete(packet->queue_id);
    }
    packet->state = NETWORK_PACKET_DROPPED;
    ++g_packet_drop_count;
    ++g_packet_lifecycle_count;
  }
}

static network_tcp_flow_t *find_flow_by_ports_v6(
    uint16_t local_port, uint16_t remote_port,
    const xaios_ip_addr_t *remote_addr) {
  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    if (g_tcp_flows[i].state != XAIOS_NETWORK_FLOW_FREE &&
        g_tcp_flows[i].local_port == local_port &&
        g_tcp_flows[i].remote_port == remote_port &&
        xaios_ip_addr_equal(&g_tcp_flows[i].remote_addr, remote_addr)) {
      return &g_tcp_flows[i];
    }
  }
  return 0;
}

static network_udp_flow_t *find_udp_flow_v6(
    uint16_t local_port, uint16_t remote_port,
    const xaios_ip_addr_t *local_addr, const xaios_ip_addr_t *remote_addr) {
  for (uint32_t i = 0; i < NETWORK_UDP_FLOWS; ++i) {
    if (g_udp_flows[i].active != 0 &&
        g_udp_flows[i].local_port == local_port &&
        g_udp_flows[i].remote_port == remote_port &&
        xaios_ip_addr_equal(&g_udp_flows[i].local_addr, local_addr) &&
        xaios_ip_addr_equal(&g_udp_flows[i].remote_addr, remote_addr)) {
      return &g_udp_flows[i];
    }
  }
  return 0;
}

static network_tcp_flow_t *find_flow_by_ports(uint16_t local_port,
                                              uint16_t remote_port,
                                              uint32_t remote_address) {
  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    if (g_tcp_flows[i].state != XAIOS_NETWORK_FLOW_FREE &&
        g_tcp_flows[i].local_port == local_port &&
        g_tcp_flows[i].remote_port == remote_port &&
        g_tcp_flows[i].remote_address == remote_address) {
      return &g_tcp_flows[i];
    }
  }
  return 0;
}

static network_udp_flow_t *find_udp_flow(uint16_t local_port,
                                         uint16_t remote_port,
                                         uint32_t local_address,
                                         uint32_t remote_address) {
  for (uint32_t i = 0; i < NETWORK_UDP_FLOWS; ++i) {
    if (g_udp_flows[i].active != 0 &&
        g_udp_flows[i].local_port == local_port &&
        g_udp_flows[i].remote_port == remote_port &&
        g_udp_flows[i].local_address == local_address &&
        g_udp_flows[i].remote_address == remote_address) {
      return &g_udp_flows[i];
    }
  }
  return 0;
}

static network_udp_flow_t *alloc_udp_flow(uint32_t queue_id, uint32_t cell_id,
                                          uint16_t local_port,
                                          uint16_t remote_port,
                                          uint32_t local_address,
                                          uint32_t remote_address,
                                          uint64_t now_ns) {
  network_udp_flow_t *flow = find_udp_flow(local_port, remote_port,
                                           local_address, remote_address);
  if (flow != 0) {
    ++g_udp_flow_hit_count;
    flow->last_seen_ns = now_ns;
    return flow;
  }
  for (uint32_t i = 0; i < NETWORK_UDP_FLOWS; ++i) {
    if (g_udp_flows[i].active == 0) {
      g_udp_flows[i].active = 1;
      g_udp_flows[i].flow_id = (uint32_t)(g_next_flow_id++);
      if (g_udp_flows[i].flow_id == 0U) {
        g_udp_flows[i].flow_id = 1U;
        g_next_flow_id = 2U;
      }
      g_udp_flows[i].queue_id = queue_id;
      g_udp_flows[i].cell_id = cell_id;
      g_udp_flows[i].local_port = local_port;
      g_udp_flows[i].remote_port = remote_port;
      g_udp_flows[i].local_address = local_address;
      g_udp_flows[i].remote_address = remote_address;
      g_udp_flows[i].packets_rx = 0;
      g_udp_flows[i].packets_tx = 0;
      g_udp_flows[i].rx_buf = sockbuf_alloc();
      if (g_udp_flows[i].rx_buf == 0) {
        g_udp_flows[i].flow_id = 0U;
        g_udp_flows[i].active = 0U;
        return 0;
      }
      g_udp_flows[i].last_seen_ns = now_ns;
      g_udp_flows[i].remote_mac_valid = 0;
      xaios_ip_addr_zero(&g_udp_flows[i].local_addr);
      xaios_ip_addr_zero(&g_udp_flows[i].remote_addr);
      klog("network: udp flow id=%u queue=%u cell=%u local=%u remote=%u\n",
           g_udp_flows[i].flow_id, queue_id, cell_id, local_port, remote_port);
      return &g_udp_flows[i];
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

static network_tcp_flow_t *alloc_tcp_flow(
    uint16_t local_port, uint16_t remote_port, uint32_t remote_address,
    const xaios_ip_addr_t *remote_addr) {
  /* Limit half-open connections before reserving a flow slot. */
  if (g_half_open_count >= NETWORK_TCP_MAX_HALF_OPEN) {
    klog("network: SYN flood protection: rejecting connection (half-open: %u)\n", g_half_open_count);
    return 0;
  }

  uint32_t has_free = 0U;
  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    if (g_tcp_flows[i].state == XAIOS_NETWORK_FLOW_FREE) {
      has_free = 1U;
      break;
    }
  }
  if (has_free == 0U) {
    network_tcp_flow_t *oldest = 0;
    for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
      network_tcp_flow_t *candidate = &g_tcp_flows[i];
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
    if (g_tcp_flows[i].state == XAIOS_NETWORK_FLOW_FREE) {
      g_tcp_flows[i].state = XAIOS_NETWORK_FLOW_SYN_RECV;
      g_tcp_flows[i].retransmits = 0;
      g_tcp_flows[i].packets_rx = 0;
      g_tcp_flows[i].packets_tx = 0;
      /* Zero data plane fields */
      g_tcp_flows[i].rx_buf = 0;
      g_tcp_flows[i].tx_buf = 0;
      g_tcp_flows[i].expected_seq = 0;
      g_tcp_flows[i].next_send_seq = 0;
      g_tcp_flows[i].window_size = 0;
      g_tcp_flows[i].pending_synack = 0;
      g_tcp_flows[i].pending_syn = 0;
      g_tcp_flows[i].pending_fin = 0;
      g_tcp_flows[i].pending_ack = 0;
      g_tcp_flows[i].close_requested = 0;
      g_tcp_flows[i].remote_mac_valid = 0;
      g_tcp_flows[i].remote_address = 0;
      g_tcp_flows[i].local_address = 0;
      xaios_ip_addr_zero(&g_tcp_flows[i].remote_addr);
      xaios_ip_addr_zero(&g_tcp_flows[i].local_addr);
      /* Retransmission state. */
      g_tcp_flows[i].rto_ns = NETWORK_TCP_RETRANSMIT_NS;
      g_tcp_flows[i].in_retransmit = 0;
      /* Out-of-order receive state. */
      for (uint32_t j = 0; j < TCP_OOO_BUF_ENTRIES; ++j) {
        g_tcp_flows[i].ooo_buf[j].in_use = 0;
        g_tcp_flows[i].ooo_buf[j].seq = 0;
        g_tcp_flows[i].ooo_buf[j].len = 0;
      }
      /* MSS negotiation. */
      g_tcp_flows[i].peer_mss = 0;
      g_tcp_flows[i].mss_parsed = 0;
      /* Window scaling. */
      g_tcp_flows[i].ws_parsed = 0;
      g_tcp_flows[i].peer_sack_permitted = 0;
      g_tcp_flows[i].peer_ws = 0;
      g_tcp_flows[i].our_ws = 0;
      g_tcp_flows[i].peer_window = 0;
      /* Congestion control. */
      g_tcp_flows[i].cwnd = TCP_INIT_CWND * NETWORK_TCP_MSS;
      g_tcp_flows[i].ssthresh = TCP_INIT_SSTHRESH * NETWORK_TCP_MSS;
      g_tcp_flows[i].dup_ack_count = 0;
      g_tcp_flows[i].highest_acked = 0;
      g_tcp_flows[i].in_flight = 0;
      g_tcp_flows[i].zero_window_probe = 0;
      for (uint32_t j = 0U; j < TCP_TX_WINDOW_SEGMENTS; ++j) {
        g_tcp_flows[i].tx_segments[j].seq = 0U;
        g_tcp_flows[i].tx_segments[j].len = 0U;
        g_tcp_flows[i].tx_segments[j].in_use = 0U;
        g_tcp_flows[i].tx_segments[j].pending = 0U;
        g_tcp_flows[i].tx_segments[j].retransmitted = 0U;
        g_tcp_flows[i].tx_segments[j].retries = 0U;
        g_tcp_flows[i].tx_segments[j].first_tx_ns = 0U;
        g_tcp_flows[i].tx_segments[j].last_tx_ns = 0U;
      }
      g_tcp_flows[i].srtt_ns = 0;
      g_tcp_flows[i].rttvar_ns = 0;
      /* Keepalive. */
      g_tcp_flows[i].keepalive_last_rx_ns = 0;
      g_tcp_flows[i].keepalive_last_tx_ns = 0;
      g_tcp_flows[i].keepalive_probes_sent = 0;
      g_tcp_flows[i].pending_keepalive = 0;
      g_tcp_flows[i].fin_seq = 0;
      g_tcp_flows[i].peer_fin_seq = 0;
      g_tcp_flows[i].fin_last_tx_ns = 0;
      g_tcp_flows[i].fin_retries = 0;
      g_tcp_flows[i].fin_outstanding = 0;
      g_tcp_flows[i].peer_fin_pending = 0;
      g_tcp_flows[i].peer_fin_received = 0;
      g_half_open_count++;
      return &g_tcp_flows[i];
    }
  }
  return 0;
}

static xaios_status_t network_stack_tcp_open_unlocked(const xaios_ip_addr_t *remote_addr,
                                      uint16_t remote_port,
                                      uint16_t local_port,
                                      uint32_t *out_flow_id) {
  xaios_status_t status = XAIOS_ERR_INVALID;
  if (remote_addr == 0 || out_flow_id == 0 || remote_port == 0U ||
      local_port == 0U ||
      (remote_addr->family != XAIOS_IP_FAMILY_V4 &&
       remote_addr->family != XAIOS_IP_FAMILY_V6))
    return XAIOS_ERR_INVALID;
  network_lock();
  uint32_t remote_address = 0U;
  uint32_t local_address = 0U;
  if (remote_addr->family == XAIOS_IP_FAMILY_V4) {
    remote_address = (uint32_t)remote_addr->addr[0] |
                     ((uint32_t)remote_addr->addr[1] << 8U) |
                     ((uint32_t)remote_addr->addr[2] << 16U) |
                     ((uint32_t)remote_addr->addr[3] << 24U);
    local_address = network_config_local_ipv4();
    if (find_flow_by_ports(local_port, remote_port, remote_address) != 0)
      goto busy;
  } else if (find_flow_by_ports_v6(local_port, remote_port, remote_addr) != 0) {
    goto busy;
  }
  xaios_ip_addr_t link_local_v6;
  net_v6_link_local(&link_local_v6);
  network_queue_binding_t *binding = select_binding_for_flow(
      local_port, remote_port,
      remote_addr->family == XAIOS_IP_FAMILY_V4
          ? local_address : xaios_ip_addr_hash(&link_local_v6),
      remote_addr->family == XAIOS_IP_FAMILY_V4
          ? remote_address : xaios_ip_addr_hash(remote_addr));
  if (binding == 0) {
    status = XAIOS_ERR_NOT_FOUND;
    goto out;
  }
  network_tcp_flow_t *flow = alloc_tcp_flow(local_port, remote_port,
                                            remote_address, remote_addr);
  if (flow == 0) {
    status = XAIOS_ERR_NO_MEMORY;
    goto out;
  }
  flow->flow_id = (uint32_t)(g_next_flow_id++);
  if (flow->flow_id == 0U) {
    flow->flow_id = 1U;
    g_next_flow_id = 2U;
  }
  flow->local_port = local_port;
  flow->remote_port = remote_port;
  flow->queue_id = binding->queue_id;
  flow->cell_id = binding->cell_id;
  flow->remote_address = remote_address;
  flow->local_address = local_address;
  flow->remote_addr = *remote_addr;
  if (remote_addr->family == XAIOS_IP_FAMILY_V4) {
    flow->local_addr = xaios_ip_addr_from_ipv4(network_config_local_ipv4());
  } else {
    net_v6_flow_local_address(remote_addr, g_local_mac, &flow->local_addr);
  }
  flow->local_seq = net_wire_tcp_generate_isn(flow->flow_id);
  flow->next_send_seq = flow->local_seq + 1U;
  flow->expected_seq = 0U;
  flow->window_size = (uint16_t)SOCKET_BUFFER_SIZE;
  flow->pending_syn = 1U;
  flow->last_seen_ns = timer_now_ns();
  flow->rx_buf = sockbuf_alloc();
  flow->tx_buf = sockbuf_alloc();
  if (flow->rx_buf == 0 || flow->tx_buf == 0) {
    if (g_half_open_count > 0U) --g_half_open_count;
    net_tcp_release_flow(flow);
    status = XAIOS_ERR_NO_MEMORY;
    goto out;
  }
  flow->state = XAIOS_NETWORK_FLOW_SYN_SENT;
  if (remote_addr->family == XAIOS_IP_FAMILY_V6) {
    uint8_t solicitation[128];
    uint64_t solicitation_length = 0U;
    /* Solicit the first hop, not the far end. For an on-link peer they are
       the same address; for anything else the far end is on somebody else's
       network and no neighbour here will ever answer for it. */
    xaios_ip_addr_t next_hop;
    net_v6_next_hop(remote_addr, timer_now_ns(), &next_hop);
    if (ndp_build_neighbor_solicitation(
            solicitation, &solicitation_length, g_local_mac,
            &flow->local_addr, &next_hop) != XAIOS_OK ||
        network_device_tx(solicitation, solicitation_length) != XAIOS_OK) {
      if (g_half_open_count > 0U) --g_half_open_count;
      net_tcp_release_flow(flow);
      status = XAIOS_ERR_IO;
      goto out;
    }
  }
  *out_flow_id = flow->flow_id;
  klog("network: active TCP open flow=%u local=%u remote=%u\n",
       flow->flow_id, local_port, remote_port);
  status = XAIOS_OK;
  goto out;

busy:
  status = XAIOS_ERR_BUSY;
out:
  network_unlock();
  return status;
}

xaios_status_t network_stack_tcp_open(const xaios_ip_addr_t *remote_addr,
                                      uint16_t remote_port,
                                      uint16_t local_port,
                                      uint32_t *out_flow_id) {
  network_lock();
  xaios_status_t result = network_stack_tcp_open_unlocked(remote_addr, remote_port, local_port, out_flow_id);
  network_unlock();
  return result;
}

static xaios_status_t network_stack_tcp_open_status_unlocked(uint32_t flow_id) {
  xaios_status_t status = XAIOS_ERR_NOT_FOUND;
  network_lock();
  for (uint32_t i = 0U; i < NETWORK_TCP_CONNECTIONS; ++i) {
    if (g_tcp_flows[i].flow_id != flow_id) continue;
    if (g_tcp_flows[i].state == XAIOS_NETWORK_FLOW_ESTABLISHED) {
      status = XAIOS_OK;
    } else if (g_tcp_flows[i].state == XAIOS_NETWORK_FLOW_SYN_SENT) {
      status = XAIOS_ERR_BUSY;
    } else {
      status = XAIOS_ERR_IO;
    }
    break;
  }
  network_unlock();
  return status;
}

xaios_status_t network_stack_tcp_open_status(uint32_t flow_id) {
  network_lock();
  xaios_status_t result = network_stack_tcp_open_status_unlocked(flow_id);
  network_unlock();
  return result;
}

static xaios_status_t network_stack_tcp_abort_flow_unlocked(uint32_t flow_id) {
  for (uint32_t i = 0U; i < NETWORK_TCP_CONNECTIONS; ++i) {
    network_tcp_flow_t *flow = &g_tcp_flows[i];
    if (flow->flow_id != flow_id) continue;
    if ((flow->state == XAIOS_NETWORK_FLOW_SYN_RECV ||
         flow->state == XAIOS_NETWORK_FLOW_SYN_SENT) &&
        g_half_open_count > 0U) {
      --g_half_open_count;
    }
    ++g_tcp_closed_count;
    net_tcp_release_flow(flow);
    return XAIOS_OK;
  }
  return XAIOS_ERR_NOT_FOUND;
}

xaios_status_t network_stack_tcp_abort_flow(uint32_t flow_id) {
  network_lock();
  xaios_status_t result = network_stack_tcp_abort_flow_unlocked(flow_id);
  network_unlock();
  return result;
}

void network_stack_init(void) {
  g_tcp_drain_cursor = 0U;
  socket_map_reset_exhausted();
  g_poll_last_ns = 0U;
  g_poll_gap_max_ns = 0U;
  g_poll_gap_outage_count = 0U;
  g_poll_gap_record_lines = 0U;
  for (uint32_t i = 0; i < XAIOS_NETWORK_MAX_QUEUE_BINDINGS; ++i) {
    g_queue_bindings[i].cell_id = 0;
    g_queue_bindings[i].queue_id = XAIOS_NETWORK_QUEUE_ID_INVALID;
    g_queue_bindings[i].core_mask = 0;
    g_queue_bindings[i].in_use = 0;
    g_queue_rings[i].queue_id = i;
    g_queue_rings[i].rx_depth = 0;
    g_queue_rings[i].tx_depth = 0;
    g_queue_rings[i].completed = 0;
    g_queue_rings[i].drops = 0;
  }

  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    g_tcp_flows[i].state = XAIOS_NETWORK_FLOW_FREE;
    g_tcp_flows[i].flow_id = 0;
    g_tcp_flows[i].queue_id = XAIOS_NETWORK_QUEUE_ID_INVALID;
    g_tcp_flows[i].cell_id = 0;
    g_tcp_flows[i].local_port = 0;
    g_tcp_flows[i].remote_port = 0;
    g_tcp_flows[i].remote_address = 0;
    g_tcp_flows[i].local_address = 0;
    g_tcp_flows[i].remote_seq = 0;
    g_tcp_flows[i].local_seq = 0;
    g_tcp_flows[i].last_seen_ns = 0;
    g_tcp_flows[i].retransmits = 0;
    g_tcp_flows[i].packets_rx = 0;
    g_tcp_flows[i].packets_tx = 0;
  }

  for (uint32_t i = 0; i < NETWORK_UDP_FLOWS; ++i) {
    g_udp_flows[i].active = 0;
    g_udp_flows[i].flow_id = 0;
    g_udp_flows[i].queue_id = XAIOS_NETWORK_QUEUE_ID_INVALID;
    g_udp_flows[i].cell_id = 0;
    g_udp_flows[i].local_port = 0;
    g_udp_flows[i].remote_port = 0;
    g_udp_flows[i].local_address = 0;
    g_udp_flows[i].remote_address = 0;
    g_udp_flows[i].packets_rx = 0;
    g_udp_flows[i].packets_tx = 0;
    g_udp_flows[i].last_seen_ns = 0;
  }

  for (uint32_t i = 0; i < NETWORK_PACKET_DESCRIPTORS; ++i) {
    g_packet_descs[i].state = NETWORK_PACKET_FREE;
    g_packet_descs[i].queue_id = XAIOS_NETWORK_QUEUE_ID_INVALID;
    g_packet_descs[i].cell_id = 0;
    g_packet_descs[i].src_port = 0;
    g_packet_descs[i].dst_port = 0;
    g_packet_descs[i].src_address = 0;
    g_packet_descs[i].dst_address = 0;
    g_packet_descs[i].length = 0;
    g_packet_descs[i].created_ns = 0;
  }

  for (uint32_t i = 0; i < network_listener_slot_count(); ++i) {
    network_listener_ex_t row;
    net_wire_bytes_zero(&row, sizeof(row));
    network_listener_slot_write(i, &row);
  }

  g_next_flow_id = 1U;
  g_udp_tx_count = 0;
  g_udp_rx_count = 0;
  g_udp_malformed_count = 0;
  g_udp_dropped_count = 0;
  g_udp_flow_hit_count = 0;
  g_udp_expired_count = 0;
  g_tcp_handshake_count = 0;
  g_tcp_reset_count = 0;
  g_tcp_timeout_count = 0;
  g_tcp_retransmit_count = 0;
  g_tcp_established_count = 0;
  g_tcp_closed_count = 0;
  g_udp_latency_count = 0;
  g_tcp_latency_count = 0;
  g_queue_binding_count = 0;
  g_rx_packet_count = 0;
  g_tx_packet_count = 0;
  g_packet_drop_count = 0;
  g_packet_lifecycle_count = 0;
  g_queue_rx_enqueue_count = 0;
  g_queue_tx_enqueue_count = 0;
  g_queue_completion_count = 0;
  g_queue_backpressure_drop_count = 0;
  g_flow_core_mismatch_count = 0;

  for (uint32_t i = 0; i < NETWORK_MAX_SAMPLES; ++i) {
    g_udp_latency_samples[i] = 0;
    g_tcp_latency_samples[i] = 0;
  }

  klog("network: stack initialized\n");
}

xaios_status_t network_stack_bind_queue(uint32_t cell_id, uint32_t queue_id,
                                       uint32_t core_mask) {
  if (queue_id >= XAIOS_NETWORK_MAX_QUEUE_BINDINGS || core_mask == 0 ||
      cell_id == UINT32_C(0xffffffff)) {
    return XAIOS_ERR_INVALID;
  }

  for (uint32_t i = 0; i < XAIOS_NETWORK_MAX_QUEUE_BINDINGS; ++i) {
    if (g_queue_bindings[i].in_use != 0 &&
        g_queue_bindings[i].queue_id == queue_id) {
      return XAIOS_ERR_BUSY;
    }
  }

  for (uint32_t i = 0; i < XAIOS_NETWORK_MAX_QUEUE_BINDINGS; ++i) {
    if (g_queue_bindings[i].in_use == 0) {
      g_queue_bindings[i].in_use = 1;
      g_queue_bindings[i].cell_id = cell_id;
      g_queue_bindings[i].queue_id = queue_id;
      g_queue_bindings[i].core_mask = core_mask;
      queue_ring_reset(queue_id);
      ++g_queue_binding_count;
      klog("network: bound queue=%u cell=%u core_mask=0x%x\n", queue_id,
           cell_id, core_mask);
      return XAIOS_OK;
    }
  }

  return XAIOS_ERR_NO_MEMORY;
}

xaios_status_t network_stack_release_queue(uint32_t queue_id, uint32_t cell_id) {
  for (uint32_t i = 0; i < XAIOS_NETWORK_MAX_QUEUE_BINDINGS; ++i) {
    if (g_queue_bindings[i].in_use != 0 &&
        g_queue_bindings[i].queue_id == queue_id &&
        g_queue_bindings[i].cell_id == cell_id) {
      g_queue_bindings[i].in_use = 0;
      g_queue_bindings[i].cell_id = 0;
      g_queue_bindings[i].queue_id = XAIOS_NETWORK_QUEUE_ID_INVALID;
      g_queue_bindings[i].core_mask = 0;
      queue_ring_reset(queue_id);
      g_queue_binding_count =
          (g_queue_binding_count == 0U) ? 0U : (g_queue_binding_count - 1U);
      klog("network: released queue=%u cell=%u\n", queue_id, cell_id);
      return XAIOS_OK;
    }
  }
  return XAIOS_ERR_NOT_FOUND;
}

xaios_status_t network_stack_process_udp_frame(const uint8_t *frame,
                                            uint64_t frame_len) {
  if (frame == 0 || frame_len < 34U) {
    ++g_udp_dropped_count;
    ++g_udp_malformed_count;
    ++g_packet_drop_count;
    return XAIOS_ERR_INVALID;
  }

  uint64_t start = timer_now_ns();
  uint16_t src_port = 0;
  uint16_t dst_port = 0;
  uint16_t payload_len = 0;
  uint32_t src_address = 0;
  uint32_t dst_address = 0;

  if (net_wire_parse_udp(frame, frame_len, &src_port, &dst_port, &payload_len,
                &src_address, &dst_address) == 0) {
    ++g_udp_dropped_count;
    ++g_udp_malformed_count;
    ++g_packet_drop_count;
    return XAIOS_ERR_INVALID;
  }

  if (src_port == 0 || dst_port == 0 || payload_len == 0) {
    ++g_udp_dropped_count;
    ++g_packet_drop_count;
    return XAIOS_ERR_INVALID;
  }

  network_udp_flow_t *existing =
      find_udp_flow(dst_port, src_port, dst_address, src_address);
  network_queue_binding_t *binding =
      existing != 0 ? find_binding(existing->queue_id)
                    : select_binding_for_flow(dst_port, src_port, dst_address,
                                              src_address);
  if (binding == 0) {
    ++g_udp_dropped_count;
    ++g_packet_drop_count;
    return XAIOS_ERR_NOT_FOUND;
  }

  network_packet_desc_t *packet =
      alloc_packet_desc(binding->queue_id, frame_len, start);
  if (packet == 0) {
    ++g_udp_dropped_count;
    return XAIOS_ERR_NO_MEMORY;
  }

  packet->src_port = src_port;
  packet->dst_port = dst_port;
  packet->src_address = src_address;
  packet->dst_address = dst_address;
  network_udp_flow_t *flow =
      alloc_udp_flow(binding->queue_id, binding->cell_id, dst_port, src_port,
                     dst_address, src_address, start);
  if (flow == 0) {
    ++g_udp_dropped_count;
    packet_mark_dropped(packet);
    return XAIOS_ERR_NO_MEMORY;
  }
  if (flow->queue_id != binding->queue_id || flow->cell_id != binding->cell_id) {
    ++g_flow_core_mismatch_count;
    packet_mark_dropped(packet);
    return XAIOS_ERR_BUSY;
  }
  ++flow->packets_rx;
  ++g_udp_rx_count;
  for (uint32_t i = 0; i < 6U; ++i) {
    flow->remote_mac[i] = frame[6U + i];
  }
  flow->remote_mac_valid = 1;
  
  /* Deliver UDP payload to flow rx_buf */
  if (flow->rx_buf != 0 && payload_len > 8) {
    const network_ip4_header_t *ip4 =
        (const network_ip4_header_t *)(frame + 14U);
    uint64_t ip_hdr_bytes = (uint64_t)(ip4->version_ihl & 0x0FU) * 4U;
    const uint8_t *udp_payload = frame + 14U + ip_hdr_bytes + 8U;
    uint32_t data_len = (uint32_t)(payload_len - 8U);
    xaios_ip_addr_t peer_addr;
    peer_addr.family = XAIOS_IP_FAMILY_V4;
    for (uint32_t i = 0; i < 4U; ++i) {
      peer_addr.addr[i] = frame[26U + i];
    }
    for (uint32_t i = 4U; i < 16U; ++i) {
      peer_addr.addr[i] = 0;
    }
    /* The row is copied out under the guard, so no pointer into the registry
       is held across udp_listener_enqueue(), which takes the same reentrant
       guard again. */
    listener_lock();
    network_listener_ex_t listener_row;
    uint32_t listener_backlog = 0U;
    int listener_found = 0;
    for (uint32_t i = 0; i < network_listener_slot_count(); ++i) {
      if (!network_listener_slot_read(i, &listener_row)) continue;
      if (listener_row.port == dst_port &&
          listener_row.protocol == NETWORK_IP_PROTO_UDP) {
        listener_backlog = listener_row.backlog_count;
        listener_found = 1;
        break;
      }
    }
    if (listener_found != 0) {
      /* A datagram that does not fit is dropped here, whole, and counted; it is
         never queued in part. The test is against `sockbuf_available`, the flow
         ring's *free space*, so this is backpressure as much as a size policy:
         a large datagram is admitted on an empty ring and refused once the ring
         is partly full. It is not the check that bounds how large a datagram
         can be.
       *
         The frame is what bounds that. `network_device_rx_poll` reads into a
         `NETWORK_BUFFER_SIZE` (1520) buffer and this function's caller rejects
         a reassembled frame longer than that, so `net_wire_parse_udp` can only ever see
         a UDP length inside a 1520-byte frame and the largest deliverable
         datagram is 1520 - 14 - 20 - 8 = 1478 bytes of payload.
       *
         The receive path below is therefore safe for a caller that asks for a
         full-size buffer: admission is against free space (at most
         SOCKET_BUFFER_SIZE) and the syscall caps a read at SOCKET_BUFFER_SIZE,
         both of which are at or above the 1478 the frame can produce, so no
         clamp can occur. A caller that asks for less than the datagram's length
         is truncated silently and told nothing. A truncation flag is what would
         make that last case honest, and it is a syscall change rather than a
         stack one. */
      if (listener_backlog >= NETWORK_LISTENER_BACKLOG ||
          data_len > sockbuf_available(flow->rx_buf) ||
          sockbuf_write(flow->rx_buf, udp_payload, data_len) != data_len ||
          !udp_listener_enqueue(dst_port, flow->flow_id, src_port, &peer_addr,
                                (uint16_t)data_len)) {
        listener_unlock();
        ++g_udp_dropped_count;
        packet_mark_dropped(packet);
        return XAIOS_ERR_BUSY;
      }
    }
    listener_unlock();
  }
  
  packet_mark_tx(packet);
  ++flow->packets_tx;
  ++g_udp_tx_count;
  packet_mark_complete(packet);
  record_latency(g_udp_latency_samples, &g_udp_latency_count, timer_now_ns() - start);
  return XAIOS_OK;
}

static void tcp_drain_pending(void) {
  uint32_t start_index = g_tcp_drain_cursor;
  g_tcp_drain_cursor =
      (g_tcp_drain_cursor + 1U) % NETWORK_TCP_CONNECTIONS;
  for (uint32_t offset = 0; offset < NETWORK_TCP_CONNECTIONS; ++offset) {
    uint32_t index = (start_index + offset) % NETWORK_TCP_CONNECTIONS;
    network_tcp_flow_t *flow = &g_tcp_flows[index];
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
                  solicitation, &solicitation_length, g_local_mac,
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
        if (!net_tcp_resolve_mac(dest_ip_be, flow->remote_mac, g_local_mac)) {
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

/* ---- TCP Send / Close API ---- */

static xaios_status_t network_stack_tcp_send_unlocked(uint32_t flow_id, const uint8_t *data,
                                       uint32_t len, uint32_t *bytes_written) {
  if (data == 0 || bytes_written == 0 || len == 0U) return XAIOS_ERR_INVALID;
  *bytes_written = 0U;
  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    if (g_tcp_flows[i].flow_id == flow_id &&
        (g_tcp_flows[i].state == XAIOS_NETWORK_FLOW_ESTABLISHED ||
         g_tcp_flows[i].state == XAIOS_NETWORK_FLOW_CLOSE_WAIT)) {
      if (g_tcp_flows[i].tx_buf == 0) {
        return XAIOS_ERR_INVALID;
      }
      *bytes_written = sockbuf_write(g_tcp_flows[i].tx_buf, data, len);
      return XAIOS_OK;
    }
  }
  return XAIOS_ERR_NOT_FOUND;
}

xaios_status_t network_stack_tcp_send(uint32_t flow_id, const uint8_t *data,
                                       uint32_t len, uint32_t *bytes_written) {
  network_lock();
  xaios_status_t result = network_stack_tcp_send_unlocked(flow_id, data, len, bytes_written);
  network_unlock();
  return result;
}

static xaios_status_t network_stack_tcp_close_flow_unlocked(uint32_t flow_id) {
  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    if (g_tcp_flows[i].flow_id == flow_id) {
      if (g_tcp_flows[i].state == XAIOS_NETWORK_FLOW_SYN_RECV ||
          g_tcp_flows[i].state == XAIOS_NETWORK_FLOW_SYN_SENT) {
        return network_stack_tcp_abort_flow(flow_id);
      }
      g_tcp_flows[i].close_requested = 1;
      g_tcp_flows[i].pending_fin = 1;
      return XAIOS_OK;
    }
  }
  return XAIOS_ERR_NOT_FOUND;
}

xaios_status_t network_stack_tcp_close_flow(uint32_t flow_id) {
  network_lock();
  xaios_status_t result = network_stack_tcp_close_flow_unlocked(flow_id);
  network_unlock();
  return result;
}

static xaios_status_t network_stack_udp_send_unlocked(uint32_t flow_id, const uint8_t *data,
                                       uint32_t len, uint32_t *bytes_written) {
  if (data == 0 || bytes_written == 0 || len == 0U) return XAIOS_ERR_INVALID;
  *bytes_written = 0U;
  for (uint32_t i = 0; i < NETWORK_UDP_FLOWS; ++i) {
    if (g_udp_flows[i].flow_id == flow_id && g_udp_flows[i].active != 0) {
      uint8_t frame[NETWORK_BUFFER_SIZE];
      if (g_udp_flows[i].remote_addr.family == XAIOS_IP_FAMILY_V6) {
        if (len > NETWORK_BUFFER_SIZE - 62U) return XAIOS_ERR_INVALID;
        uint16_t udp_len = (uint16_t)(8U + len);
        uint64_t frame_len = 14U + 40U + (uint64_t)udp_len;
        if (g_udp_flows[i].remote_mac_valid == 0U) return XAIOS_ERR_BUSY;
        for (uint32_t j = 0; j < 6U; ++j) {
          frame[j] = g_udp_flows[i].remote_mac[j];
          frame[6U + j] = g_local_mac[j];
        }
        net_wire_write_be16(frame + 12U, NETWORK_ETHERTYPE_IPV6);
        uint8_t *ip6 = frame + 14U;
        for (uint32_t j = 0; j < 40U; ++j) ip6[j] = 0U;
        ip6[0] = 0x60U;
        net_wire_write_be16(ip6 + 4U, udp_len);
        ip6[6] = NETWORK_IP_PROTO_UDP;
        ip6[7] = 64U;
        for (uint32_t j = 0; j < 16U; ++j) {
          ip6[8U + j] = g_udp_flows[i].local_addr.addr[j];
          ip6[24U + j] = g_udp_flows[i].remote_addr.addr[j];
        }
        uint8_t *udp = ip6 + 40U;
        net_wire_write_be16(udp, g_udp_flows[i].local_port);
        net_wire_write_be16(udp + 2U, g_udp_flows[i].remote_port);
        net_wire_write_be16(udp + 4U, udp_len);
        net_wire_write_be16(udp + 6U, 0U);
        for (uint32_t j = 0; j < len; ++j) udp[8U + j] = data[j];
        uint16_t checksum = ipv6_pseudo_checksum(
            &g_udp_flows[i].local_addr, &g_udp_flows[i].remote_addr,
            NETWORK_IP_PROTO_UDP, udp_len, udp, udp_len);
        net_wire_write_be16(udp + 6U, checksum == 0U ? UINT16_MAX : checksum);
        *bytes_written = len;
        return network_device_tx(frame, frame_len);
      }

      /* Build Ethernet + IPv4 + UDP frame. */
      if (len > NETWORK_BUFFER_SIZE - 42U) return XAIOS_ERR_INVALID;
      uint16_t udp_len = (uint16_t)(8U + len);
      uint16_t ip_total = (uint16_t)(20U + udp_len);
      uint64_t frame_len = 14U + (uint64_t)ip_total;
      if (frame_len > NETWORK_BUFFER_SIZE) {
        return XAIOS_ERR_INVALID;
      }
      uint32_t dst_ip_be = ((g_udp_flows[i].remote_address & 0xFFU) << 24U) |
                            (((g_udp_flows[i].remote_address >> 8U) & 0xFFU) << 16U) |
                            (((g_udp_flows[i].remote_address >> 16U) & 0xFFU) << 8U) |
                            ((g_udp_flows[i].remote_address >> 24U) & 0xFFU);
      uint8_t dst_mac[6];
      if (g_udp_flows[i].remote_mac_valid != 0) {
        for (uint32_t j = 0; j < 6U; ++j) {
          dst_mac[j] = g_udp_flows[i].remote_mac[j];
        }
      } else if (!net_tcp_resolve_mac(dst_ip_be, dst_mac, g_local_mac)) {
        return XAIOS_ERR_BUSY;
      }
      /* Ethernet */
      for (uint32_t j = 0; j < 6; ++j) { frame[j] = dst_mac[j]; }
      for (uint32_t j = 0; j < 6; ++j) { frame[6U + j] = g_local_mac[j]; }
      net_wire_write_be16(frame + 12, 0x0800U);
      /* IPv4 */
      ipv4_build_header(frame + 14, ip_total, 17,
                         network_config_local_ipv4(), dst_ip_be);
      /* UDP header */
      uint8_t *udp = frame + 34U;
      net_wire_write_be16(udp, g_udp_flows[i].local_port);
      net_wire_write_be16(udp + 2, g_udp_flows[i].remote_port);
      net_wire_write_be16(udp + 4, udp_len);
      net_wire_write_be16(udp + 6, 0U);
      /* Payload */
      for (uint32_t j = 0; j < len; ++j) {
        frame[42U + j] = data[j];
      }
      uint16_t checksum = ipv4_pseudo_checksum(
          network_config_local_ipv4(), dst_ip_be, NETWORK_IP_PROTO_UDP, udp_len,
          udp, udp_len);
      net_wire_write_be16(udp + 6U, checksum == 0U ? UINT16_MAX : checksum);
      *bytes_written = len;
      return network_device_tx(frame, frame_len);
    }
  }
  return XAIOS_ERR_NOT_FOUND;
}

xaios_status_t network_stack_udp_send(uint32_t flow_id, const uint8_t *data,
                                       uint32_t len, uint32_t *bytes_written) {
  network_lock();
  xaios_status_t result = network_stack_udp_send_unlocked(flow_id, data, len, bytes_written);
  network_unlock();
  return result;
}

static xaios_status_t network_stack_udp_sendto_unlocked(
    uint16_t local_port, const xaios_ip_addr_t *remote_addr,
    uint16_t remote_port, const uint8_t *data, uint32_t len,
    uint32_t *bytes_written, uint32_t *out_flow_id) {
  if (remote_addr == 0 || data == 0 || bytes_written == 0 || len == 0U ||
      local_port == 0U || remote_port == 0U) {
    return XAIOS_ERR_INVALID;
  }
  if (remote_addr->family != XAIOS_IP_FAMILY_V4) {
    /* See the header: the v6 transmit branch needs state this path does not
       fill, so it is refused rather than half-built. */
    return XAIOS_ERR_UNSUPPORTED;
  }
  /* Both address fields are stored the way the receive path stores them, and
     that is not the way network_config_local_ipv4() holds an address.
     net_wire_parse_udp runs the wire bytes through net_wire_ip4_addr_host_order, which yields
     the byte-reversed integer -- 10.0.2.2 becomes 0x0202000a, not 0x0a000202
     -- and network_stack_udp_send_unlocked reverses remote_address again on
     its way back out to the wire. A flow created here with the natural order
     would transmit to the wrong host, and would additionally fail to match
     find_udp_flow when the peer replied, so the reply would allocate a second
     flow for the same four-tuple. The user's octets already arrive in the
     reversed order when read low byte first, which is why the expression
     below looks backwards and is not; the local address has to be swapped
     explicitly. */
  uint32_t remote_address = (uint32_t)remote_addr->addr[0] |
                            ((uint32_t)remote_addr->addr[1] << 8U) |
                            ((uint32_t)remote_addr->addr[2] << 16U) |
                            ((uint32_t)remote_addr->addr[3] << 24U);
  uint32_t configured_local = network_config_local_ipv4();
  uint32_t local_address = ((configured_local & 0xFFU) << 24U) |
                           (((configured_local >> 8U) & 0xFFU) << 16U) |
                           (((configured_local >> 16U) & 0xFFU) << 8U) |
                           ((configured_local >> 24U) & 0xFFU);
  network_udp_flow_t *flow =
      find_udp_flow(local_port, remote_port, local_address, remote_address);
  if (flow == 0) {
    /* A queue binding if the machine has one, and no flow refused if it does
       not. The binding decides which receive queue a flow's inbound frames
       are steered to, so it is required on the receive path and is genuinely
       optional here: transmit picks its queue pair from the sending CPU
       inside the driver and never consults this. Refusing to send because no
       AI cell happens to hold a queue would make an ordinary socket depend on
       an unrelated subsystem. What it costs, honestly: a flow created with no
       binding cannot receive -- process_udp_frame looks the binding up from
       the flow and drops the frame when it finds none -- so a reply to a
       datagram sent before any binding exists is dropped, exactly as it is
       today for a peer nobody has bound a queue for. */
    network_queue_binding_t *binding = select_binding_for_flow(
        local_port, remote_port, local_address, remote_address);
    flow = alloc_udp_flow(
        binding != 0 ? binding->queue_id : XAIOS_NETWORK_QUEUE_ID_INVALID,
        binding != 0 ? binding->cell_id : 0U, local_port, remote_port,
        local_address, remote_address, timer_now_ns());
    if (flow == 0) {
      return XAIOS_ERR_NO_MEMORY;
    }
  }
  if (out_flow_id != 0) {
    *out_flow_id = flow->flow_id;
  }
  return network_stack_udp_send_unlocked(flow->flow_id, data, len,
                                         bytes_written);
}

xaios_status_t network_stack_udp_sendto(uint16_t local_port,
                                        const xaios_ip_addr_t *remote_addr,
                                        uint16_t remote_port,
                                        const uint8_t *data, uint32_t len,
                                        uint32_t *bytes_written,
                                        uint32_t *out_flow_id) {
  network_lock();
  xaios_status_t result =
      network_stack_udp_sendto_unlocked(local_port, remote_addr, remote_port,
                                        data, len, bytes_written, out_flow_id);
  network_unlock();
  return result;
}

static uint32_t network_stack_tcp_recv_unlocked(uint32_t flow_id, uint8_t *buffer,
                                  uint32_t buffer_size) {
  if (buffer == 0 || buffer_size == 0U) return 0U;
  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    if (g_tcp_flows[i].flow_id == flow_id &&
        g_tcp_flows[i].rx_buf != 0) {
      uint32_t bytes_read = sockbuf_read(g_tcp_flows[i].rx_buf,
                                            buffer, buffer_size);
      g_tcp_flows[i].window_size =
          (uint16_t)sockbuf_available(g_tcp_flows[i].rx_buf);
      if (bytes_read != 0U) {
        g_tcp_flows[i].pending_ack = 1;
      }
      return bytes_read;
    }
  }
  return 0;
}

uint32_t network_stack_tcp_recv(uint32_t flow_id, uint8_t *buffer,
                                  uint32_t buffer_size) {
  network_lock();
  uint32_t result = network_stack_tcp_recv_unlocked(flow_id, buffer, buffer_size);
  network_unlock();
  return result;
}

static int network_stack_tcp_peer_closed_unlocked(uint32_t flow_id) {
  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    if (g_tcp_flows[i].flow_id == flow_id) {
      return g_tcp_flows[i].state == XAIOS_NETWORK_FLOW_CLOSE_WAIT ||
             g_tcp_flows[i].state == XAIOS_NETWORK_FLOW_CLOSED ||
             g_tcp_flows[i].state == XAIOS_NETWORK_FLOW_TIME_WAIT;
    }
  }
  return 1;
}

static volatile uint64_t g_readiness_generation;

void network_readiness_note(void) {
  __atomic_add_fetch(&g_readiness_generation, 1U, __ATOMIC_RELAXED);
}

uint64_t network_readiness_generation(void) {
  return __atomic_load_n(&g_readiness_generation, __ATOMIC_RELAXED);
}

int network_stack_tcp_peer_closed(uint32_t flow_id) {
  network_lock();
  int result = network_stack_tcp_peer_closed_unlocked(flow_id);
  network_unlock();
  return result;
}

int network_stack_socket_ready(uint64_t sockfd, uint8_t protocol,
                               uint16_t port, uint32_t listening) {
  int ready = 0;
  network_lock();
  if (listening != 0U) {
    for (uint32_t i = 0; i < network_listener_slot_count(); ++i) {
      network_listener_ex_t row;
      if (!network_listener_slot_read(i, &row)) continue;
      const int match =
          protocol == NETWORK_IP_PROTO_UDP
              ? (row.sockfd == sockfd && row.protocol == NETWORK_IP_PROTO_UDP)
              : (row.port == port && row.protocol == NETWORK_IP_PROTO_TCP);
      if (match) {
        ready = row.backlog_count != 0U;
        break;
      }
    }
  } else {
    socket_flow_mapping_t mapping;
    if (network_stack_get_socket_mapping_unlocked(sockfd, &mapping) != 0 &&
        mapping.protocol == XAIOS_NETWORK_PROTOCOL_TCP) {
      int found = 0;
      for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
        if (g_tcp_flows[i].flow_id != mapping.flow_id) continue;
        found = 1;
        if (g_tcp_flows[i].rx_buf != 0 && g_tcp_flows[i].rx_buf->count != 0U) {
          ready = 1;
        }
        break;
      }
      if (ready == 0 &&
          (found == 0 ||
           network_stack_tcp_peer_closed_unlocked(mapping.flow_id) != 0)) {
        ready = 1;
      }
    }
  }
  network_unlock();
  return ready;
}

static uint32_t network_stack_udp_recv_unlocked(uint64_t sockfd, uint8_t *buffer,
                                uint32_t buffer_size,
                                xaios_ip_addr_t *source_addr,
                                uint16_t *source_port,
                                uint32_t *flow_id) {
  listener_lock();
  network_listener_ex_t listener_row;
  uint32_t listener_index = 0U;
  int listener_found = 0;
  for (uint32_t i = 0; i < network_listener_slot_count(); ++i) {
    if (!network_listener_slot_read(i, &listener_row)) continue;
    if (listener_row.sockfd == sockfd &&
        listener_row.protocol == NETWORK_IP_PROTO_UDP) {
      listener_index = i;
      listener_found = 1;
      break;
    }
  }
  if (listener_found == 0 || listener_row.backlog_count == 0 || buffer == 0 ||
      buffer_size == 0) {
    { listener_unlock(); return 0; }
  }

  listener_accept_entry_t entry = listener_row.backlog[0];
  for (uint32_t i = 1; i < listener_row.backlog_count; ++i) {
    listener_row.backlog[i - 1U] = listener_row.backlog[i];
  }
  --listener_row.backlog_count;
  network_listener_slot_write(listener_index, &listener_row);

  for (uint32_t i = 0; i < NETWORK_UDP_FLOWS; ++i) {
    network_udp_flow_t *udp_flow = &g_udp_flows[i];
    if (udp_flow->active != 0 && udp_flow->flow_id == entry.flow_id &&
        udp_flow->rx_buf != 0) {
      uint32_t read_limit = entry.payload_len;
      if (read_limit > buffer_size) {
        read_limit = buffer_size;
      }
      uint32_t bytes_read = sockbuf_read(udp_flow->rx_buf, buffer, read_limit);
      if (entry.payload_len > bytes_read) {
        sockbuf_discard(udp_flow->rx_buf,
                        (uint32_t)entry.payload_len - bytes_read);
      }
      if (source_addr != 0) {
        *source_addr = entry.peer_addr;
      }
      if (source_port != 0) {
        *source_port = entry.peer_port;
      }
      if (flow_id != 0) {
        *flow_id = entry.flow_id;
      }
      /* The unlocked variant: this function already runs under the network
         guard, and calling the public wrapper from here would take that guard
         from inside a listener-guard section, inverting the order the two
         guards are documented to keep. Reentrancy hid this while there was
         only one guard. */
      /* The datagram has already been handed to the caller, so there is
         nothing to refuse here; an exhausted table costs this socket its
         reply path and says so in the log (B-47). */
      (void)network_stack_map_socket_unlocked(sockfd, entry.flow_id,
                                              NETWORK_IP_PROTO_UDP);
      { listener_unlock(); return bytes_read; }
    }
  }
  { listener_unlock(); return 0; }
  listener_unlock();
}

uint32_t network_stack_udp_recv(uint64_t sockfd, uint8_t *buffer,
                                uint32_t buffer_size,
                                xaios_ip_addr_t *source_addr,
                                uint16_t *source_port,
                                uint32_t *flow_id) {
  network_lock();
  uint32_t result = network_stack_udp_recv_unlocked(sockfd, buffer, buffer_size, source_addr, source_port, flow_id);
  network_unlock();
  return result;
}

xaios_status_t network_stack_process_tcp_frame(const uint8_t *frame,
                                            uint64_t frame_len) {
  if (frame == 0 || frame_len < 54U) {
    ++g_tcp_reset_count;
    ++g_packet_drop_count;
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
    ++g_tcp_reset_count;
    ++g_packet_drop_count;
    return XAIOS_ERR_INVALID;
  }
  if (src_port == 0U || dst_port == 0U) {
    ++g_tcp_reset_count;
    ++g_packet_drop_count;
    return XAIOS_ERR_INVALID;
  }

  const network_ip4_header_t *ip =
      (const network_ip4_header_t *)(frame + 14U);
  uint32_t parsed_ip_header_bytes = (uint32_t)(ip->version_ihl & 0x0fU) * 4U;
  const uint8_t *parsed_tcp_header = frame + 14U + parsed_ip_header_bytes;
  uint16_t peer_window_raw = net_wire_read_u16_be(parsed_tcp_header + 14U);
  uint32_t remote_address = net_wire_ip4_addr_host_order(ip->source);
  uint32_t local_address = net_wire_ip4_addr_host_order(ip->destination);

  network_tcp_flow_t *flow = find_flow_by_ports(dst_port, src_port, remote_address);
  network_queue_binding_t *binding =
      flow != 0 ? find_binding(flow->queue_id)
                : select_binding_for_flow(dst_port, src_port, local_address,
                                          remote_address);
  if (binding == 0) {
    ++g_tcp_reset_count;
    ++g_packet_drop_count;
    return XAIOS_ERR_NOT_FOUND;
  }

  network_packet_desc_t *packet =
      alloc_packet_desc(binding->queue_id, frame_len, start);
  if (packet == 0) {
    ++g_tcp_reset_count;
    return XAIOS_ERR_NO_MEMORY;
  }

  packet->src_port = src_port;
  packet->dst_port = dst_port;
  packet->src_address = remote_address;
  packet->dst_address = local_address;

  if (flow != 0 && flow->state == XAIOS_NETWORK_FLOW_SYN_SENT &&
      (flags & (NETWORK_TCP_FLAG_SYN | NETWORK_TCP_FLAG_ACK)) ==
          (NETWORK_TCP_FLAG_SYN | NETWORK_TCP_FLAG_ACK) &&
      (flags & (NETWORK_TCP_FLAG_FIN | NETWORK_TCP_FLAG_RST)) == 0U) {
    if (ack != flow->next_send_seq) {
      packet_mark_dropped(packet);
      return XAIOS_ERR_INVALID;
    }
    uint32_t tcp_header_bytes = (uint32_t)(parsed_tcp_header[12U] >> 4U) * 4U;
    tcp_parsed_options_t options;
    if (!net_wire_parse_tcp_options(parsed_tcp_header, tcp_header_bytes, &options)) {
      packet_mark_dropped(packet);
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
    if (g_half_open_count > 0U) --g_half_open_count;
    ++flow->packets_rx;
    ++g_tcp_handshake_count;
    ++g_tcp_established_count;
    packet_mark_tx(packet);
    packet_mark_complete(packet);
    record_latency(g_tcp_latency_samples, &g_tcp_latency_count,
                   timer_now_ns() - start);
    return XAIOS_OK;
  }

  if ((flags & NETWORK_TCP_FLAG_RST) != 0U) {
    if (flow != 0) {
      if (seq != flow->expected_seq) {
        packet_mark_dropped(packet);
        return XAIOS_ERR_INVALID;
      }
      xaios_network_flow_state_t prev_state = flow->state;
      ++g_tcp_reset_count;
      ++g_tcp_closed_count;
      if ((prev_state == XAIOS_NETWORK_FLOW_SYN_RECV ||
           prev_state == XAIOS_NETWORK_FLOW_SYN_SENT) &&
          g_half_open_count > 0) {
        g_half_open_count--;
      }
      net_tcp_release_flow(flow);
    }
    packet_mark_dropped(packet);
    return XAIOS_ERR_INVALID;
  }

  if (flow == 0 &&
      ((flags & NETWORK_TCP_FLAG_SYN) == 0U ||
       (flags & (NETWORK_TCP_FLAG_ACK | NETWORK_TCP_FLAG_FIN)) != 0U)) {
    packet_mark_dropped(packet);
    return XAIOS_ERR_INVALID;
  }

  if (flow == 0 && (flags & NETWORK_TCP_FLAG_SYN) != 0U) {
    /* Check if there's a listener for this port */
    if (!network_stack_has_listener(dst_port)) {
      ++g_tcp_reset_count;
      packet_mark_dropped(packet);
      return XAIOS_ERR_NOT_FOUND;
    }
    flow = alloc_tcp_flow(dst_port, src_port, remote_address, 0);
    if (flow == 0) {
      ++g_tcp_reset_count;
      packet_mark_dropped(packet);
      return XAIOS_ERR_NO_MEMORY;
    }
    flow->flow_id = (uint32_t)(g_next_flow_id++);
    if (flow->flow_id == 0U) {
      flow->flow_id = 1U;
      g_next_flow_id = 2U;
    }
    flow->local_port = dst_port;
    flow->remote_port = src_port;
    flow->queue_id = binding->queue_id;
    flow->cell_id = binding->cell_id;
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
      if (g_half_open_count > 0U) --g_half_open_count;
      net_tcp_release_flow(flow);
      packet_mark_dropped(packet);
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
        packet_mark_dropped(packet);
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

    ++g_tcp_handshake_count;
    packet_mark_tx(packet);
    packet_mark_complete(packet);
    record_latency(g_tcp_latency_samples, &g_tcp_latency_count,
                  timer_now_ns() - start);
    return XAIOS_OK;
  }

  if (flow != 0 && flow->state == XAIOS_NETWORK_FLOW_SYN_RECV &&
      (flags & NETWORK_TCP_FLAG_ACK) != 0U) {
    if (ack != flow->next_send_seq || seq != flow->expected_seq) {
      packet_mark_dropped(packet);
      return XAIOS_ERR_INVALID;
    }
    uint32_t peer_ip_be = ((remote_address & 0xFFU) << 24U) |
                           (((remote_address >> 8U) & 0xFFU) << 16U) |
                           (((remote_address >> 16U) & 0xFFU) << 8U) |
                           ((remote_address >> 24U) & 0xFFU);
    if (g_half_open_count > 0U) --g_half_open_count;
    if (!accept_queue_enqueue(flow->flow_id, peer_ip_be, src_port, dst_port,
                              0)) {
      net_tcp_release_flow(flow);
      packet_mark_dropped(packet);
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
    ++g_tcp_handshake_count;
    ++g_tcp_established_count;
    packet_mark_tx(packet);
    packet_mark_complete(packet);
    record_latency(g_tcp_latency_samples, &g_tcp_latency_count,
                  timer_now_ns() - start);
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
      packet_mark_dropped(packet);
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
      packet_mark_dropped(packet);
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
        packet_mark_dropped(packet);
        return XAIOS_ERR_INVALID;
      }
      (void)net_tcp_apply_sack_blocks(flow, &options);
      int ack_result = net_tcp_acknowledge(flow, ack, start);
      if (ack_result < 0) {
        packet_mark_dropped(packet);
        return XAIOS_ERR_INVALID;
      }
      if (ack_result > 0) {
        packet_mark_tx(packet);
        packet_mark_complete(packet);
        record_latency(g_tcp_latency_samples, &g_tcp_latency_count,
                       timer_now_ns() - start);
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

    packet_mark_tx(packet);
    packet_mark_complete(packet);
    record_latency(g_tcp_latency_samples, &g_tcp_latency_count,
                  timer_now_ns() - start);
    return XAIOS_OK;
  }

  ++g_tcp_reset_count;
  packet_mark_dropped(packet);
  return XAIOS_ERR_INVALID;
}

xaios_status_t network_stack_process_udp_frame_v6(const uint8_t *frame,
                                                  uint64_t frame_len) {
  if (frame == 0 || frame_len < 62U) {
    ++g_udp_dropped_count;
    ++g_udp_malformed_count;
    ++g_packet_drop_count;
    return XAIOS_ERR_INVALID;
  }

  uint64_t start = timer_now_ns();
  uint16_t src_port = 0;
  uint16_t dst_port = 0;
  uint16_t payload_len = 0;
  xaios_ip_addr_t src_addr;
  xaios_ip_addr_t dst_addr;
  xaios_ip_addr_zero(&src_addr);
  xaios_ip_addr_zero(&dst_addr);

  if (net_wire_parse_udp_v6(frame, frame_len, &src_port, &dst_port, &payload_len,
                   &src_addr, &dst_addr) == 0) {
    ++g_udp_dropped_count;
    ++g_udp_malformed_count;
    ++g_packet_drop_count;
    return XAIOS_ERR_INVALID;
  }
  if (src_port == 0 || dst_port == 0 || payload_len == 0) {
    ++g_udp_dropped_count;
    ++g_packet_drop_count;
    return XAIOS_ERR_INVALID;
  }

  network_udp_flow_t *existing =
      find_udp_flow_v6(dst_port, src_port, &dst_addr, &src_addr);
  network_queue_binding_t *binding =
      existing != 0 ? find_binding(existing->queue_id)
                    : select_binding_for_flow(dst_port, src_port,
                                              xaios_ip_addr_hash(&dst_addr),
                                              xaios_ip_addr_hash(&src_addr));
  if (binding == 0) {
    ++g_udp_dropped_count;
    ++g_packet_drop_count;
    return XAIOS_ERR_NOT_FOUND;
  }

  network_packet_desc_t *packet =
      alloc_packet_desc(binding->queue_id, frame_len, start);
  if (packet == 0) {
    ++g_udp_dropped_count;
    return XAIOS_ERR_NO_MEMORY;
  }

  packet->src_port = src_port;
  packet->dst_port = dst_port;
  packet->src_addr = src_addr;
  packet->dst_addr = dst_addr;
  /* Also set legacy fields for backward compat */
  if (src_addr.family == XAIOS_IP_FAMILY_V4) {
    packet->src_address = xaios_ip_addr_to_ipv4(&src_addr);
    packet->dst_address = xaios_ip_addr_to_ipv4(&dst_addr);
  }

  network_udp_flow_t *flow =
      alloc_udp_flow(binding->queue_id, binding->cell_id, dst_port, src_port,
                     packet->dst_address, packet->src_address, start);
  if (flow == 0) {
    ++g_udp_dropped_count;
    packet_mark_dropped(packet);
    return XAIOS_ERR_NO_MEMORY;
  }
  /* Set IPv6 address fields on the flow */
  flow->local_addr = dst_addr;
  flow->remote_addr = src_addr;

  if (flow->queue_id != binding->queue_id || flow->cell_id != binding->cell_id) {
    ++g_flow_core_mismatch_count;
    packet_mark_dropped(packet);
    return XAIOS_ERR_BUSY;
  }
  ++flow->packets_rx;
  ++g_udp_rx_count;
  ++g_ipv6_rx_count;
  for (uint32_t i = 0; i < 6U; ++i) {
    flow->remote_mac[i] = frame[6U + i];
  }
  flow->remote_mac_valid = 1;
  
  /* Deliver UDP payload to flow rx_buf */
  if (flow->rx_buf != 0 && payload_len > 8) {
    /* IPv6 header is 40 bytes at offset 14 */
    const uint8_t *udp_payload = frame + 14U + 40U + 8U;
    uint32_t data_len = (uint32_t)(payload_len - 8U);
    /* Same as the IPv4 path: the row is copied out under the guard, so no
       pointer into the registry crosses udp_listener_enqueue(). */
    listener_lock();
    network_listener_ex_t listener_row;
    uint32_t listener_backlog = 0U;
    int listener_found = 0;
    for (uint32_t i = 0; i < network_listener_slot_count(); ++i) {
      if (!network_listener_slot_read(i, &listener_row)) continue;
      if (listener_row.port == dst_port &&
          listener_row.protocol == NETWORK_IP_PROTO_UDP) {
        listener_backlog = listener_row.backlog_count;
        listener_found = 1;
        break;
      }
    }
    if (listener_found != 0) {
      if (listener_backlog >= NETWORK_LISTENER_BACKLOG ||
          data_len > sockbuf_available(flow->rx_buf) ||
          sockbuf_write(flow->rx_buf, udp_payload, data_len) != data_len ||
          !udp_listener_enqueue(dst_port, flow->flow_id, src_port, &src_addr,
                                (uint16_t)data_len)) {
        listener_unlock();
        ++g_udp_dropped_count;
        packet_mark_dropped(packet);
        return XAIOS_ERR_BUSY;
      }
    }
    listener_unlock();
  }
  
  packet_mark_tx(packet);
  ++flow->packets_tx;
  ++g_udp_tx_count;
  packet_mark_complete(packet);
  record_latency(g_udp_latency_samples, &g_udp_latency_count,
                timer_now_ns() - start);
  return XAIOS_OK;
}

xaios_status_t network_stack_process_tcp_frame_v6(const uint8_t *frame,
                                                  uint64_t frame_len) {
  if (frame == 0 || frame_len < 74U) { /* 14 + 40 + 20 minimum */
    ++g_tcp_reset_count;
    ++g_packet_drop_count;
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
    ++g_tcp_reset_count;
    ++g_packet_drop_count;
    return XAIOS_ERR_INVALID;
  }
  if (src_port == 0U || dst_port == 0U) {
    ++g_tcp_reset_count;
    ++g_packet_drop_count;
    return XAIOS_ERR_INVALID;
  }

  const uint8_t *parsed_tcp_header = frame + 14U + XAIOS_IPV6_HEADER_SIZE;
  uint16_t peer_window_raw = net_wire_read_u16_be(parsed_tcp_header + 14U);

  network_tcp_flow_t *flow =
      find_flow_by_ports_v6(dst_port, src_port, &src_addr);
  network_queue_binding_t *binding =
      flow != 0 ? find_binding(flow->queue_id)
                : select_binding_for_flow(dst_port, src_port,
                                          xaios_ip_addr_hash(&dst_addr),
                                          xaios_ip_addr_hash(&src_addr));
  if (binding == 0) {
    ++g_tcp_reset_count;
    ++g_packet_drop_count;
    return XAIOS_ERR_NOT_FOUND;
  }

  network_packet_desc_t *packet =
      alloc_packet_desc(binding->queue_id, frame_len, start);
  if (packet == 0) {
    ++g_tcp_reset_count;
    return XAIOS_ERR_NO_MEMORY;
  }

  packet->src_port = src_port;
  packet->dst_port = dst_port;
  packet->src_addr = src_addr;
  packet->dst_addr = dst_addr;

  if (flow != 0 && flow->state == XAIOS_NETWORK_FLOW_SYN_SENT &&
      (flags & (NETWORK_TCP_FLAG_SYN | NETWORK_TCP_FLAG_ACK)) ==
          (NETWORK_TCP_FLAG_SYN | NETWORK_TCP_FLAG_ACK) &&
      (flags & (NETWORK_TCP_FLAG_FIN | NETWORK_TCP_FLAG_RST)) == 0U) {
    if (ack_v != flow->next_send_seq) {
      packet_mark_dropped(packet);
      return XAIOS_ERR_INVALID;
    }
    uint32_t tcp_header_bytes =
        (uint32_t)(parsed_tcp_header[12U] >> 4U) * 4U;
    tcp_parsed_options_t options;
    if (!net_wire_parse_tcp_options(parsed_tcp_header, tcp_header_bytes, &options)) {
      packet_mark_dropped(packet);
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
    if (g_half_open_count > 0U) --g_half_open_count;
    ++flow->packets_rx;
    ++g_tcp_handshake_count;
    ++g_tcp_established_count;
    ++g_ipv6_rx_count;
    packet_mark_tx(packet);
    packet_mark_complete(packet);
    record_latency(g_tcp_latency_samples, &g_tcp_latency_count,
                   timer_now_ns() - start);
    return XAIOS_OK;
  }

  if ((flags & NETWORK_TCP_FLAG_RST) != 0U) {
    if (flow != 0) {
      if (seq != flow->expected_seq) {
        packet_mark_dropped(packet);
        return XAIOS_ERR_INVALID;
      }
      xaios_network_flow_state_t prev_state = flow->state;
      ++g_tcp_reset_count;
      ++g_tcp_closed_count;
      if (prev_state == XAIOS_NETWORK_FLOW_SYN_RECV && g_half_open_count > 0) {
        g_half_open_count--;
      }
      net_tcp_release_flow(flow);
    }
    packet_mark_dropped(packet);
    return XAIOS_ERR_INVALID;
  }

  if (flow == 0 &&
      ((flags & NETWORK_TCP_FLAG_SYN) == 0U ||
       (flags & (NETWORK_TCP_FLAG_ACK | NETWORK_TCP_FLAG_FIN)) != 0U)) {
    packet_mark_dropped(packet);
    return XAIOS_ERR_INVALID;
  }

  if (flow == 0 && (flags & NETWORK_TCP_FLAG_SYN) != 0U) {
    /* Check if there's a listener for this port */
    if (!network_stack_has_listener(dst_port)) {
      ++g_tcp_reset_count;
      packet_mark_dropped(packet);
      return XAIOS_ERR_NOT_FOUND;
    }
    flow = alloc_tcp_flow(dst_port, src_port, 0, &src_addr);
    if (flow == 0) {
      ++g_tcp_reset_count;
      packet_mark_dropped(packet);
      return XAIOS_ERR_NO_MEMORY;
    }
    flow->flow_id = (uint32_t)(g_next_flow_id++);
    if (flow->flow_id == 0U) {
      flow->flow_id = 1U;
      g_next_flow_id = 2U;
    }
    flow->local_port = dst_port;
    flow->remote_port = src_port;
    flow->queue_id = binding->queue_id;
    flow->cell_id = binding->cell_id;
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
      if (g_half_open_count > 0U) --g_half_open_count;
      net_tcp_release_flow(flow);
      packet_mark_dropped(packet);
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
        packet_mark_dropped(packet);
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
    ++g_tcp_handshake_count;
    ++g_ipv6_rx_count;
    packet_mark_tx(packet);
    packet_mark_complete(packet);
    record_latency(g_tcp_latency_samples, &g_tcp_latency_count,
                  timer_now_ns() - start);
    return XAIOS_OK;
  }

  if (flow != 0 && flow->state == XAIOS_NETWORK_FLOW_SYN_RECV &&
      (flags & NETWORK_TCP_FLAG_ACK) != 0U) {
    if (ack_v != flow->next_send_seq || seq != flow->expected_seq) {
      packet_mark_dropped(packet);
      return XAIOS_ERR_INVALID;
    }
    if (g_half_open_count > 0U) --g_half_open_count;
    if (!accept_queue_enqueue(flow->flow_id, 0, src_port, dst_port,
                              &src_addr)) {
      net_tcp_release_flow(flow);
      packet_mark_dropped(packet);
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
    ++g_tcp_handshake_count;
    ++g_tcp_established_count;
    packet_mark_tx(packet);
    packet_mark_complete(packet);
    record_latency(g_tcp_latency_samples, &g_tcp_latency_count,
                  timer_now_ns() - start);
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
      packet_mark_dropped(packet);
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
      packet_mark_dropped(packet);
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
        packet_mark_dropped(packet);
        return XAIOS_ERR_INVALID;
      }
      (void)net_tcp_apply_sack_blocks(flow, &options);
      int ack_result = net_tcp_acknowledge(flow, ack_v, start);
      if (ack_result < 0) {
        packet_mark_dropped(packet);
        return XAIOS_ERR_INVALID;
      }
      if (ack_result > 0) {
        packet_mark_tx(packet);
        packet_mark_complete(packet);
        record_latency(g_tcp_latency_samples, &g_tcp_latency_count,
                       timer_now_ns() - start);
        return XAIOS_OK;
      }
    }

    if (flow->close_requested && flow->fin_outstanding == 0U &&
        (flow->state == XAIOS_NETWORK_FLOW_ESTABLISHED ||
         flow->state == XAIOS_NETWORK_FLOW_CLOSE_WAIT) &&
        (flow->tx_buf == 0 || sockbuf_used(flow->tx_buf) == 0)) {
      flow->pending_fin = 1;
    }

    packet_mark_tx(packet);
    packet_mark_complete(packet);
    record_latency(g_tcp_latency_samples, &g_tcp_latency_count,
                  timer_now_ns() - start);
    return XAIOS_OK;
  }

  ++g_tcp_reset_count;
  packet_mark_dropped(packet);
  return XAIOS_ERR_INVALID;
}

uint64_t network_stack_expire_udp_flows(uint64_t now_ns) {
  uint64_t expired = 0;
  for (uint32_t i = 0; i < NETWORK_UDP_FLOWS; ++i) {
    if (g_udp_flows[i].active != 0 &&
        now_ns > g_udp_flows[i].last_seen_ns &&
        now_ns - g_udp_flows[i].last_seen_ns >= NETWORK_UDP_IDLE_TIMEOUT_NS) {
      uint32_t flow_id = g_udp_flows[i].flow_id;
      uint32_t queue_id = g_udp_flows[i].queue_id;
      uint32_t cell_id = g_udp_flows[i].cell_id;
      uint64_t packets_rx = g_udp_flows[i].packets_rx;
      uint64_t packets_tx = g_udp_flows[i].packets_tx;
      net_tcp_release_udp_flow(&g_udp_flows[i]);
      ++g_udp_expired_count;
      ++expired;
      klog("network: udp flow id=%u expired queue=%u cell=%u rx=%lu tx=%lu\n",
           flow_id, queue_id, cell_id, packets_rx, packets_tx);
    }
  }
  return expired;
}

uint64_t network_stack_retransmit_tcp_flows(uint64_t now_ns) {
  uint64_t retransmitted = 0;
  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    if ((g_tcp_flows[i].state == XAIOS_NETWORK_FLOW_SYN_RECV ||
         g_tcp_flows[i].state == XAIOS_NETWORK_FLOW_SYN_SENT) &&
        now_ns > g_tcp_flows[i].last_seen_ns &&
        now_ns - g_tcp_flows[i].last_seen_ns >= NETWORK_TCP_RETRANSMIT_NS &&
        g_tcp_flows[i].retransmits < NETWORK_TCP_MAX_RETRANSMITS) {
      ++g_tcp_flows[i].retransmits;
      ++g_tcp_flows[i].packets_tx;
      g_tcp_flows[i].last_seen_ns = now_ns;
      if (g_tcp_flows[i].state == XAIOS_NETWORK_FLOW_SYN_SENT)
        g_tcp_flows[i].pending_syn = 1U;
      else
        g_tcp_flows[i].pending_synack = 1U;
      ++g_tcp_retransmit_count;
      ++retransmitted;
      klog("network: tcp flow id=%u retransmit=%u queue=%u cell=%u\n",
           g_tcp_flows[i].flow_id, g_tcp_flows[i].retransmits,
           g_tcp_flows[i].queue_id, g_tcp_flows[i].cell_id);
    }
  }
  return retransmitted;
}

uint64_t network_stack_expire_tcp_flows(uint64_t now_ns) {
  uint64_t expired = 0;
  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    network_tcp_flow_t *flow = &g_tcp_flows[i];

    /* TIME_WAIT expires after 2MSL and returns the slot to the pool. */
    if (flow->state == XAIOS_NETWORK_FLOW_TIME_WAIT &&
        now_ns > flow->last_seen_ns &&
        now_ns - flow->last_seen_ns >= UINT64_C(60000000000)) {
      ++g_tcp_closed_count;
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
      ++g_tcp_closed_count;
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
      ++g_tcp_timeout_count;
      ++g_tcp_closed_count;
      ++g_packet_drop_count;
      ++expired;
      if (g_half_open_count > 0) {
        g_half_open_count--;
      }
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
        ++g_tcp_timeout_count;
        ++g_tcp_closed_count;
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
      ++g_tcp_retransmit_count;
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
        ++g_tcp_timeout_count;
        ++g_tcp_closed_count;
        ++expired;
        klog("network: tcp flow id=%u FIN retransmit limit\n",
             flow->flow_id);
        net_tcp_release_flow(flow);
        continue;
      }
      ++flow->fin_retries;
      ++flow->retransmits;
      ++g_tcp_retransmit_count;
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
        ++g_tcp_closed_count;
        ++expired;
        klog("network: tcp flow id=%u keepalive timeout\n", flow->flow_id);
        net_tcp_release_flow(flow);
        continue;
      }
    }
  }
  return expired;
}

uint64_t network_stack_udp_tx_count(void) {
  return g_udp_tx_count;
}

uint64_t network_stack_udp_rx_count(void) {
  return g_udp_rx_count;
}

uint64_t network_stack_udp_malformed_count(void) {
  return g_udp_malformed_count;
}

uint64_t network_stack_udp_dropped_count(void) {
  return g_udp_dropped_count;
}

uint64_t network_stack_udp_flow_count(void) {
  uint64_t active = 0;
  for (uint32_t i = 0; i < NETWORK_UDP_FLOWS; ++i) {
    if (g_udp_flows[i].active != 0) {
      ++active;
    }
  }
  return active;
}

uint64_t network_stack_udp_flow_hit_count(void) {
  return g_udp_flow_hit_count;
}

uint64_t network_stack_udp_expired_count(void) {
  return g_udp_expired_count;
}

uint64_t network_stack_tcp_connections(void) {
  uint64_t active = 0;
  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    if (g_tcp_flows[i].state == XAIOS_NETWORK_FLOW_ESTABLISHED) {
      ++active;
    }
  }
  return active;
}

uint64_t network_stack_tcp_handshake_count(void) {
  return g_tcp_handshake_count;
}

uint64_t network_stack_tcp_reset_count(void) {
  return g_tcp_reset_count;
}

uint64_t network_stack_tcp_timeout_count(void) {
  return g_tcp_timeout_count;
}

uint64_t network_stack_tcp_retransmit_count(void) {
  return g_tcp_retransmit_count;
}

uint64_t network_stack_tcp_established_count(void) {
  return g_tcp_established_count;
}

uint64_t network_stack_tcp_closed_count(void) {
  return g_tcp_closed_count;
}

uint64_t network_stack_queue_bindings(void) {
  return g_queue_binding_count;
}

uint64_t network_stack_rx_packet_count(void) {
  return g_rx_packet_count;
}

uint64_t network_stack_tx_packet_count(void) {
  return g_tx_packet_count;
}

uint64_t network_stack_packet_drop_count(void) {
  return g_packet_drop_count;
}

uint64_t network_stack_packet_lifecycle_count(void) {
  return g_packet_lifecycle_count;
}

uint64_t network_stack_queue_rx_enqueue_count(void) {
  return g_queue_rx_enqueue_count;
}

uint64_t network_stack_queue_tx_enqueue_count(void) {
  return g_queue_tx_enqueue_count;
}

uint64_t network_stack_queue_completion_count(void) {
  return g_queue_completion_count;
}

uint64_t network_stack_queue_backpressure_drop_count(void) {
  return g_queue_backpressure_drop_count;
}

uint64_t network_stack_flow_core_mismatch_count(void) {
  return g_flow_core_mismatch_count;
}

uint64_t network_stack_udp_latency_p50_ns(void) {
  return net_wire_percentile(g_udp_latency_samples, g_udp_latency_count, 50U);
}

uint64_t network_stack_udp_latency_p95_ns(void) {
  return net_wire_percentile(g_udp_latency_samples, g_udp_latency_count, 95U);
}

uint64_t network_stack_udp_latency_p99_ns(void) {
  return net_wire_percentile(g_udp_latency_samples, g_udp_latency_count, 99U);
}

uint64_t network_stack_udp_latency_p999_ns(void) {
  return net_wire_percentile(g_udp_latency_samples, g_udp_latency_count, 999U);
}

uint64_t network_stack_tcp_latency_p50_ns(void) {
  return net_wire_percentile(g_tcp_latency_samples, g_tcp_latency_count, 50U);
}

uint64_t network_stack_tcp_latency_p95_ns(void) {
  return net_wire_percentile(g_tcp_latency_samples, g_tcp_latency_count, 95U);
}

uint64_t network_stack_tcp_latency_p99_ns(void) {
  return net_wire_percentile(g_tcp_latency_samples, g_tcp_latency_count, 99U);
}

uint64_t network_stack_tcp_latency_p999_ns(void) {
  return net_wire_percentile(g_tcp_latency_samples, g_tcp_latency_count, 999U);
}

static void emit_latency_snapshot(uint64_t *udp50, uint64_t *udp95,
                                 uint64_t *udp99, uint64_t *udp999,
                                 uint64_t *tcp50, uint64_t *tcp95,
                                 uint64_t *tcp99, uint64_t *tcp999) {
  *udp50 = network_stack_udp_latency_p50_ns();
  *udp95 = network_stack_udp_latency_p95_ns();
  *udp99 = network_stack_udp_latency_p99_ns();
  *udp999 = network_stack_udp_latency_p999_ns();
  *tcp50 = network_stack_tcp_latency_p50_ns();
  *tcp95 = network_stack_tcp_latency_p95_ns();
  *tcp99 = network_stack_tcp_latency_p99_ns();
  *tcp999 = network_stack_tcp_latency_p999_ns();
}

static void build_app_udp_frame(uint8_t *frame, uint64_t payload_len) {
  net_wire_bytes_zero(frame, NETWORK_BUFFER_SIZE);
  frame[12U] = 0x08;
  frame[13U] = 0x00;
  frame[14U] = 0x45;
  frame[15U] = 0x00;
  const uint16_t total = (uint16_t)(20U + 8U + payload_len);
  frame[16U] = (uint8_t)(total >> 8U);
  frame[17U] = (uint8_t)total;
  frame[22U] = 64;
  frame[23U] = NETWORK_IP_PROTO_UDP;
  frame[26U] = 10;
  frame[27U] = 0;
  frame[28U] = 2;
  frame[29U] = 15;
  frame[30U] = 10;
  frame[31U] = 0;
  frame[32U] = 2;
  frame[33U] = 2;
  frame[34U] = 0x60;
  frame[35U] = 0x01;
  frame[36U] = 0x22;
  frame[37U] = 0xB8;
  const uint16_t udp_len = (uint16_t)(8U + payload_len);
  frame[38U] = (uint8_t)(udp_len >> 8U);
  frame[39U] = (uint8_t)udp_len;
  net_wire_write_be16(frame + 24U, ipv4_checksum(frame + 14U, 20U));
}

static void build_app_tcp_frame(uint8_t *frame, uint8_t flags,
                                uint16_t remote_port) {
  net_wire_bytes_zero(frame, NETWORK_BUFFER_SIZE);
  frame[12U] = 0x08;
  frame[13U] = 0x00;
  frame[14U] = 0x45;
  frame[15U] = 0x00;
  frame[16U] = 0x00;
  frame[17U] = 0x2c;
  frame[22U] = 64;
  frame[23U] = NETWORK_IP_PROTO_TCP;
  frame[26U] = 10;
  frame[27U] = 0;
  frame[28U] = 2;
  frame[29U] = 15;
  frame[30U] = 10;
  frame[31U] = 0;
  frame[32U] = 2;
  frame[33U] = 2;
  frame[34U] = (uint8_t)(remote_port >> 8U);
  frame[35U] = (uint8_t)remote_port;
  frame[36U] = 0x00;
  frame[37U] = 0x16;
  frame[41U] = 1;
  frame[46U] = 0x60;
  frame[47U] = flags;
}

static void finalize_app_tcp_frame(uint8_t *frame) {
  frame[50U] = 0U;
  frame[51U] = 0U;
  uint16_t checksum =
      ipv4_pseudo_checksum(UINT32_C(0x0a00020f), UINT32_C(0x0a000202),
                           NETWORK_IP_PROTO_TCP, 24U, frame + 34U, 24U);
  net_wire_write_be16(frame + 50U, checksum == 0U ? UINT16_MAX : checksum);
  frame[24U] = 0U;
  frame[25U] = 0U;
  net_wire_write_be16(frame + 24U, ipv4_checksum(frame + 14U, 20U));
}

static void tcp_sliding_window_self_test(void) {
  network_tcp_flow_t flow;
  uint8_t payload[10];
  net_wire_bytes_zero(&flow, sizeof(flow));
  for (uint32_t i = 0U; i < sizeof(payload); ++i) {
    payload[i] = (uint8_t)(i + 1U);
  }
  flow.state = XAIOS_NETWORK_FLOW_ESTABLISHED;
  flow.tx_buf = sockbuf_alloc();
  kassert(flow.tx_buf != 0);
  flow.local_seq = 100U;
  flow.next_send_seq = 100U;
  flow.highest_acked = 100U;
  flow.peer_mss = 4U;
  flow.peer_window = 12U;
  flow.cwnd = 12U;
  flow.rto_ns = NETWORK_TCP_RETRANSMIT_NS;
  kassert(sockbuf_write(flow.tx_buf, payload, sizeof(payload)) ==
          sizeof(payload));

  net_tcp_queue_send_window(&flow);
  kassert(net_tcp_tx_segment_count(&flow) == 3U);
  kassert(flow.in_flight == 10U && flow.next_send_seq == 110U);
  kassert(flow.tx_segments[0].seq == 100U &&
          flow.tx_segments[0].len == 4U);
  kassert(flow.tx_segments[1].seq == 104U &&
          flow.tx_segments[1].len == 4U);
  kassert(flow.tx_segments[2].seq == 108U &&
          flow.tx_segments[2].len == 2U);

  kassert(net_tcp_acknowledge(&flow, 106U, 1U) == 0);
  kassert(net_tcp_tx_segment_count(&flow) == 2U);
  kassert(flow.in_flight == 4U && flow.local_seq == 106U);
  kassert(flow.tx_segments[1].seq == 106U &&
          flow.tx_segments[1].len == 2U &&
          flow.tx_segments[1].data[0] == 7U);
  kassert(net_tcp_acknowledge(&flow, 110U, 2U) == 0);
  kassert(net_tcp_tx_segment_count(&flow) == 0U && flow.in_flight == 0U);
  sockbuf_free(flow.tx_buf);

  uint8_t option_header[60];
  tcp_parsed_options_t options;
  net_wire_bytes_zero(option_header, sizeof(option_header));
  option_header[20] = TCP_OPT_SACK_PERMITTED;
  option_header[21] = 2U;
  option_header[22] = TCP_OPT_SACK;
  option_header[23] = 10U;
  net_wire_write_be32(option_header + 24U, 204U);
  net_wire_write_be32(option_header + 28U, 208U);
  kassert(net_wire_parse_tcp_options(option_header, 32U, &options) != 0);
  kassert(options.sack_permitted == 1U && options.sack_count == 1U);

  net_wire_bytes_zero(&flow, sizeof(flow));
  flow.state = XAIOS_NETWORK_FLOW_ESTABLISHED;
  flow.local_seq = 200U;
  flow.next_send_seq = 212U;
  flow.in_flight = 12U;
  flow.cwnd = 12U;
  flow.ssthresh = 12U;
  for (uint32_t i = 0U; i < 3U; ++i) {
    flow.tx_segments[i].seq = 200U + i * 4U;
    flow.tx_segments[i].len = 4U;
    flow.tx_segments[i].in_use = 1U;
  }
  kassert(net_tcp_apply_sack_blocks(&flow, &options) == 4U);
  kassert(flow.tx_segments[1].in_use == 0U && flow.in_flight == 8U);
  uint64_t retransmits_before = g_tcp_retransmit_count;
  kassert(net_tcp_acknowledge(&flow, 200U, 10U) == 0);
  kassert(net_tcp_acknowledge(&flow, 200U, 11U) == 0);
  kassert(net_tcp_acknowledge(&flow, 200U, 12U) == 0);
  kassert(flow.in_retransmit == 1U &&
          flow.tx_segments[0].retransmitted == 1U);
  g_tcp_retransmit_count = retransmits_before;

  net_wire_bytes_zero(&flow, sizeof(flow));
  flow.state = XAIOS_NETWORK_FLOW_ESTABLISHED;
  flow.tx_buf = sockbuf_alloc();
  kassert(flow.tx_buf != 0);
  flow.next_send_seq = 300U;
  flow.peer_mss = 8U;
  flow.peer_window = 0U;
  flow.cwnd = 8U;
  kassert(sockbuf_write(flow.tx_buf, payload, 4U) == 4U);
  net_tcp_queue_send_window(&flow);
  kassert(flow.zero_window_probe == 1U && flow.in_flight == 1U &&
          flow.tx_segments[0].len == 1U);
  sockbuf_free(flow.tx_buf);

  net_wire_bytes_zero(&flow, sizeof(flow));
  flow.rx_buf = sockbuf_alloc();
  kassert(flow.rx_buf != 0);
  flow.expected_seq = 400U;
  flow.window_size = 32U;
  flow.peer_sack_permitted = 1U;
  kassert(net_tcp_ooo_buffer_store(&flow, 404U, payload + 4U, 4U,
                           flow.expected_seq) == 4U);
  uint8_t generated[40];
  uint32_t generated_len =
      net_tcp_build_options(&flow, NETWORK_TCP_FLAG_ACK, generated);
  net_wire_bytes_zero(option_header, sizeof(option_header));
  for (uint32_t i = 0U; i < generated_len; ++i) {
    option_header[20U + i] = generated[i];
  }
  kassert(net_wire_parse_tcp_options(option_header, 20U + generated_len, &options) != 0);
  kassert(options.sack_count == 1U && options.sack_left[0] == 404U &&
          options.sack_right[0] == 408U);
  kassert(sockbuf_write(flow.rx_buf, payload, 4U) == 4U);
  flow.expected_seq += 4U;
  kassert(net_tcp_ooo_buffer_drain(&flow) == 4U && flow.expected_seq == 408U);
  uint8_t reordered[8];
  kassert(sockbuf_read(flow.rx_buf, reordered, sizeof(reordered)) ==
          sizeof(reordered));
  for (uint32_t i = 0U; i < sizeof(reordered); ++i) {
    kassert(reordered[i] == payload[i]);
  }
  sockbuf_free(flow.rx_buf);

  net_wire_bytes_zero(&flow, sizeof(flow));
  flow.rto_ns = NETWORK_TCP_RETRANSMIT_NS;
  flow.cwnd = NETWORK_TCP_MSS * 8U;
  net_tcp_backoff_rto(&flow);
  kassert(flow.rto_ns == NETWORK_TCP_RETRANSMIT_NS * 2U &&
          flow.cwnd == NETWORK_TCP_MSS);
  net_tcp_backoff_rto(&flow);
  kassert(flow.rto_ns == NETWORK_TCP_RETRANSMIT_NS * 4U);

  option_header[20] = TCP_OPT_SACK;
  option_header[21] = 9U;
  kassert(net_wire_parse_tcp_options(option_header, 29U, &options) == 0);
  klog("network: TCP sliding-window self-test passed segments=3 cumulative_ack=1 partial_ack=1 sack=1 fast_retransmit=1 zero_window=1 reorder=1 rto_backoff=1\n");
}

static xaios_status_t network_stack_app_udp_echo_unlocked(const uint8_t *payload,
                                         uint64_t payload_len,
                                         uint64_t *echoed_bytes) {
  if (payload == 0 || echoed_bytes == 0 || payload_len == 0 ||
      payload_len > 64U) {
    return XAIOS_ERR_INVALID;
  }

  uint8_t frame[NETWORK_BUFFER_SIZE];
  build_app_udp_frame(frame, payload_len);
  for (uint64_t i = 0; i < payload_len; ++i) {
    frame[42U + i] = payload[i];
  }

  const uint32_t queue_id = 3U;
  const uint32_t cell_id = 3U;
  if (network_stack_bind_queue(cell_id, queue_id, 0x8U) != XAIOS_OK) {
    return XAIOS_ERR_BUSY;
  }
  xaios_status_t status = network_stack_process_udp_frame(frame, 42U + payload_len);
  kassert(network_stack_release_queue(queue_id, cell_id) == XAIOS_OK);
  if (status != XAIOS_OK) {
    return status;
  }
  *echoed_bytes = payload_len;
  klog("network: app udp echo payload=%lu queue=%u cell=%u\n",
       payload_len, queue_id, cell_id);
  return XAIOS_OK;
}

xaios_status_t network_stack_app_udp_echo(const uint8_t *payload,
                                         uint64_t payload_len,
                                         uint64_t *echoed_bytes) {
  network_lock();
  xaios_status_t result = network_stack_app_udp_echo_unlocked(payload, payload_len, echoed_bytes);
  network_unlock();
  return result;
}

static xaios_status_t network_stack_app_tcp_connect_unlocked(uint64_t *round_trips) {
  if (round_trips == 0) {
    return XAIOS_ERR_INVALID;
  }

  const uint32_t queue_id = 3U;
  const uint32_t cell_id = 3U;
  uint8_t syn[NETWORK_BUFFER_SIZE];
  uint8_t ack[NETWORK_BUFFER_SIZE];
  uint8_t rst[NETWORK_BUFFER_SIZE];
  const uint16_t remote_port = 0x6010U;
  const uint16_t local_port = 22U;
  int temporary_listener = 0;

  if (!network_stack_has_listener(local_port)) {
    if (network_stack_register_listener(local_port, UINT64_MAX) != XAIOS_OK) {
      return XAIOS_ERR_NO_MEMORY;
    }
    temporary_listener = 1;
  }

  if (network_stack_bind_queue(cell_id, queue_id, 0x8U) != XAIOS_OK) {
    if (temporary_listener != 0) {
      network_stack_unregister_listener(local_port);
    }
    return XAIOS_ERR_BUSY;
  }
  build_app_tcp_frame(syn, NETWORK_TCP_FLAG_SYN, remote_port);
  build_app_tcp_frame(ack, NETWORK_TCP_FLAG_ACK, remote_port);
  build_app_tcp_frame(rst, NETWORK_TCP_FLAG_RST, remote_port);
  ack[48U] = 0x40U;
  rst[48U] = 0x40U;
  finalize_app_tcp_frame(syn);

  xaios_status_t status = network_stack_process_tcp_frame(syn, 58U);
  if (status == XAIOS_OK) {
    network_tcp_flow_t *flow = 0;
    for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
      if (g_tcp_flows[i].local_port == local_port &&
          g_tcp_flows[i].remote_port == remote_port &&
          g_tcp_flows[i].state == XAIOS_NETWORK_FLOW_SYN_RECV) {
        flow = &g_tcp_flows[i];
        break;
      }
    }
    if (flow == 0 || flow->state != XAIOS_NETWORK_FLOW_SYN_RECV) {
      status = XAIOS_ERR_NOT_FOUND;
    } else {
      net_wire_write_be32(ack + 38U, flow->expected_seq);
      net_wire_write_be32(ack + 42U, flow->next_send_seq);
      net_wire_write_be32(rst + 38U, flow->expected_seq);
      net_wire_write_be32(rst + 42U, flow->next_send_seq);
      finalize_app_tcp_frame(ack);
      finalize_app_tcp_frame(rst);
    }
  }
  if (status == XAIOS_OK) {
    status = network_stack_process_tcp_frame(ack, 58U);
  }
  if (status == XAIOS_OK) {
    if (network_stack_process_tcp_frame(rst, 58U) == XAIOS_ERR_INVALID) {
      status = XAIOS_OK;
    } else {
      status = XAIOS_ERR_IO;
    }
  }
  kassert(network_stack_release_queue(queue_id, cell_id) == XAIOS_OK);
  if (temporary_listener != 0) {
    network_stack_unregister_listener(local_port);
  }
  if (status != XAIOS_OK) return status;
  *round_trips = 2U;
  klog("network: app tcp connect-close queue=%u cell=%u round_trips=%lu\n",
       queue_id, cell_id, *round_trips);
  return XAIOS_OK;
}

xaios_status_t network_stack_app_tcp_connect(uint64_t *round_trips) {
  network_lock();
  xaios_status_t result = network_stack_app_tcp_connect_unlocked(round_trips);
  network_unlock();
  return result;
}

static void network_append(char *output, uint64_t capacity, uint64_t *offset,
                           const char *text) {
  if (output == 0 || offset == 0 || text == 0 || capacity == 0) {
    return;
  }
  for (uint64_t i = 0; text[i] != '\0' && *offset + 1U < capacity; ++i) {
    output[*offset] = text[i];
    ++(*offset);
  }
  output[*offset] = '\0';
}

static void network_append_u64(char *output, uint64_t capacity,
                               uint64_t *offset, uint64_t value) {
  char digits[20];
  uint64_t count = 0;
  if (value == 0) {
    network_append(output, capacity, offset, "0");
    return;
  }
  while (value != 0 && count < sizeof(digits)) {
    digits[count++] = (char)('0' + (value % 10U));
    value /= 10U;
  }
  while (count > 0) {
    char one[2];
    --count;
    one[0] = digits[count];
    one[1] = '\0';
    network_append(output, capacity, offset, one);
  }
}

static xaios_status_t network_stack_external_session_unlocked(uint64_t protocol, uint64_t port,
                                             const uint8_t *payload,
                                             uint64_t payload_len,
                                             char *output,
                                             uint64_t output_capacity,
                                             uint64_t *output_bytes) {
  if (payload == 0 || payload_len == 0 || payload_len > 64U ||
      output == 0 || output_capacity < 16U || output_bytes == 0 ||
      port == 0 || port > 65535U) {
    return XAIOS_ERR_INVALID;
  }

  output[0] = '\0';
  uint64_t offset = 0;
  if (protocol == XAIOS_NETWORK_PROTOCOL_UDP) {
    uint64_t echoed = 0;
    if (network_stack_app_udp_echo(payload, payload_len, &echoed) != XAIOS_OK) {
      return XAIOS_ERR_IO;
    }
    network_append(output, output_capacity, &offset, "udp:");
    network_append_u64(output, output_capacity, &offset, port);
    network_append(output, output_capacity, &offset, ":echo:");
    network_append_u64(output, output_capacity, &offset, echoed);
    network_append(output, output_capacity, &offset, "\n");
    *output_bytes = offset;
    klog("network: external host udp session port=%lu bytes=%lu echoed=%lu\n",
         port, payload_len, echoed);
    return XAIOS_OK;
  }

  if (protocol == XAIOS_NETWORK_PROTOCOL_TCP) {
    uint64_t round_trips = 0;
    if (network_stack_app_tcp_connect(&round_trips) != XAIOS_OK) {
      return XAIOS_ERR_IO;
    }
    network_append(output, output_capacity, &offset, "tcp:");
    network_append_u64(output, output_capacity, &offset, port);
    network_append(output, output_capacity, &offset, ":established:");
    network_append_u64(output, output_capacity, &offset, round_trips);
    network_append(output, output_capacity, &offset, "\n");
    *output_bytes = offset;
    klog("network: external host tcp session port=%lu bytes=%lu round_trips=%lu\n",
         port, payload_len, round_trips);
    return XAIOS_OK;
  }

  return XAIOS_ERR_INVALID;
}

xaios_status_t network_stack_external_session(uint64_t protocol, uint64_t port,
                                             const uint8_t *payload,
                                             uint64_t payload_len,
                                             char *output,
                                             uint64_t output_capacity,
                                             uint64_t *output_bytes) {
  network_lock();
  xaios_status_t result = network_stack_external_session_unlocked(protocol, port, payload, payload_len, output, output_capacity, output_bytes);
  network_unlock();
  return result;
}

/* WT-39: the two listener pools are separate and each still refuses at its own
   capacity. Fills both at once -- the case a single shared table could not
   express, because whichever filled first took the other's rows -- and asserts
   acceptance up to each bound and a refusal one past it. Hands every row back
   so the rest of the self-test sees the empty registry it expects. */
static void listener_pool_capacity_self_test(void) {
  uint64_t sockfd = 1000U;
  for (uint32_t i = 0; i < NETWORK_MAX_UDP_LISTENERS; ++i) {
    kassert(network_stack_register_udp_listener((uint16_t)(0x6000U + i),
                                                sockfd++) == XAIOS_OK);
  }
  kassert(network_stack_register_udp_listener(UINT16_C(0x7000), sockfd++) ==
          XAIOS_ERR_NO_MEMORY);
  /* The UDP pool is full and the TCP pool has not noticed: all sixteen rows
     are still there, and TCP refuses only at sixteen of its own. */
  for (uint32_t i = 0; i < NETWORK_MAX_TCP_LISTENERS; ++i) {
    kassert(network_stack_register_listener((uint16_t)(0x7001U + i),
                                            sockfd++) == XAIOS_OK);
  }
  kassert(network_stack_register_listener(UINT16_C(0x7100), sockfd++) ==
          XAIOS_ERR_NO_MEMORY);
  for (uint32_t i = 0; i < NETWORK_MAX_UDP_LISTENERS; ++i) {
    network_stack_unregister_udp_listener((uint16_t)(0x6000U + i));
  }
  for (uint32_t i = 0; i < NETWORK_MAX_TCP_LISTENERS; ++i) {
    network_stack_unregister_listener((uint16_t)(0x7001U + i));
  }
}

void network_stack_self_test(void) {
  uint8_t frame_udp[NETWORK_BUFFER_SIZE];
  uint8_t frame_udp_bad[NETWORK_BUFFER_SIZE];
  uint8_t frame_tcp_syn[NETWORK_BUFFER_SIZE];
  uint8_t frame_tcp_syn_ack[NETWORK_BUFFER_SIZE];
  uint8_t frame_tcp_timeout[NETWORK_BUFFER_SIZE];
  net_wire_bytes_zero(frame_udp, sizeof(frame_udp));
  net_wire_bytes_zero(frame_udp_bad, sizeof(frame_udp_bad));
  net_wire_bytes_zero(frame_tcp_syn, sizeof(frame_tcp_syn));
  net_wire_bytes_zero(frame_tcp_syn_ack, sizeof(frame_tcp_syn_ack));
  net_wire_bytes_zero(frame_tcp_timeout, sizeof(frame_tcp_timeout));

  network_stack_init();
  listener_pool_capacity_self_test();
  tcp_sliding_window_self_test();

  kassert(network_stack_bind_queue(0, 1, 0x2U) == XAIOS_OK);
  kassert(network_stack_bind_queue(0, 1, 0x2U) == XAIOS_ERR_BUSY);
  kassert(network_stack_bind_queue(1, 2, 0x4U) == XAIOS_OK);
  kassert(network_stack_bind_queue(2, 2, 0x8U) == XAIOS_ERR_BUSY);

  kassert(network_stack_release_queue(2, 1) == XAIOS_OK);
  kassert(network_stack_bind_queue(1, 2, 0x4U) == XAIOS_OK);

  kassert(network_stack_queue_bindings() == 2U);
  kassert(network_stack_register_listener(80U, 1U) == XAIOS_OK);
  kassert(network_stack_register_udp_listener(UINT16_C(0x5678), 2U) == XAIOS_OK);

  frame_udp[12U] = 0x08;
  frame_udp[13U] = 0x00;
  frame_udp[14U] = 0x45;
  frame_udp[15U] = 0x00;
  frame_udp[16U] = 0x00;
  frame_udp[17U] = 0x20;
  frame_udp[18U] = 0x00;
  frame_udp[19U] = 0x00;
  frame_udp[20U] = 0x00;
  frame_udp[21U] = 0x00;
  frame_udp[22U] = 64;
  frame_udp[23U] = NETWORK_IP_PROTO_UDP;
  frame_udp[24U] = 0x00;
  frame_udp[25U] = 0x00;
  frame_udp[26U] = 10;
  frame_udp[27U] = 0;
  frame_udp[28U] = 2;
  frame_udp[29U] = 15;
  frame_udp[30U] = 10;
  frame_udp[31U] = 0;
  frame_udp[32U] = 2;
  frame_udp[33U] = 2;
  frame_udp[34U] = 0x12;
  frame_udp[35U] = 0x34;
  frame_udp[36U] = 0x56;
  frame_udp[37U] = 0x78;
  frame_udp[38U] = 0x00;
  frame_udp[39U] = 0x0C;
  frame_udp[40U] = 0x00;
  frame_udp[41U] = 0x00;
  frame_udp[42U] = 1;
  frame_udp[43U] = 2;
  frame_udp[44U] = 3;
  frame_udp[45U] = 4;
  net_wire_write_be16(frame_udp + 24U, ipv4_checksum(frame_udp + 14U, 20U));

  kassert(network_stack_process_udp_frame(frame_udp, 46U) == XAIOS_OK);
  kassert(network_stack_process_udp_frame(frame_udp, 46U) == XAIOS_OK);
  {
    uint8_t short_datagram[4];
    kassert(network_stack_udp_recv(2U, short_datagram, 2U, 0, 0, 0) == 2U);
    kassert(short_datagram[0] == 1U && short_datagram[1] == 2U);
    kassert(network_stack_udp_recv(2U, short_datagram, sizeof(short_datagram),
                                   0, 0, 0) == sizeof(short_datagram));
    kassert(short_datagram[0] == 1U && short_datagram[1] == 2U &&
            short_datagram[2] == 3U && short_datagram[3] == 4U);
  }
  {
    /* The refusals on the send-to-a-named-peer path, which is the half of
       B-29 that no boot exercises.
   
       The positive half of that fix is demonstrated by /bin/netmqtest and by
       the driver's own transmit counters, and it cannot be demonstrated here:
       a real datagram needs a device, and this self-test runs against frames
       it builds itself. What can be pinned here is that the path refuses what
       it must refuse, which is the control the positive result needs -- a
       send that returned XAIOS_OK for every set of arguments would make
       frames_sent=16 meaningless. None of these calls allocates a flow or
       touches a counter, deliberately, so the figures asserted below still
       describe the receive path alone. */
    xaios_ip_addr_t probe_v4 = xaios_ip_addr_from_ipv4(XAIOS_IPV4_GATEWAY);
    xaios_ip_addr_t probe_v6;
    xaios_ip_addr_zero(&probe_v6);
    probe_v6.family = XAIOS_IP_FAMILY_V6;
    const uint8_t probe_payload[4] = {9U, 8U, 7U, 6U};
    uint32_t probe_written = 0xffffffffU;
    kassert(network_stack_udp_sendto(0U, &probe_v4, 9U, probe_payload,
                                     sizeof(probe_payload), &probe_written,
                                     0) == XAIOS_ERR_INVALID);
    kassert(network_stack_udp_sendto(24000U, &probe_v4, 0U, probe_payload,
                                     sizeof(probe_payload), &probe_written,
                                     0) == XAIOS_ERR_INVALID);
    kassert(network_stack_udp_sendto(24000U, 0, 9U, probe_payload,
                                     sizeof(probe_payload), &probe_written,
                                     0) == XAIOS_ERR_INVALID);
    kassert(network_stack_udp_sendto(24000U, &probe_v4, 9U, probe_payload, 0U,
                                     &probe_written, 0) == XAIOS_ERR_INVALID);
    /* IPv6 is refused rather than attempted: see network_stack_udp_sendto. A
       machine that grows the v6 transmit path will fail this line, which is
       the right place to be reminded that the refusal was deliberate. */
    kassert(network_stack_udp_sendto(24000U, &probe_v6, 9U, probe_payload,
                                     sizeof(probe_payload), &probe_written,
                                     0) == XAIOS_ERR_UNSUPPORTED);
    kassert(network_stack_udp_flow_count() == 1U);
  }
  kassert(g_udp_rx_count == 2U);
  kassert(network_stack_udp_flow_hit_count() == 1U);
  kassert(network_stack_udp_flow_count() == 1U);
  kassert(network_stack_expire_udp_flows(timer_now_ns() +
                                         NETWORK_UDP_IDLE_TIMEOUT_NS + 1U) ==
          1U);
  kassert(network_stack_udp_expired_count() == 1U);
  kassert(network_stack_udp_flow_count() == 0U);
  kassert(network_stack_process_udp_frame(frame_udp, 46U) == XAIOS_OK);
  kassert(g_udp_rx_count == 3U);
  kassert(network_stack_udp_flow_count() == 1U);
  frame_udp_bad[13] = 0x06;
  kassert(network_stack_process_udp_frame(frame_udp_bad, 4U) == XAIOS_ERR_INVALID);
  kassert(g_udp_dropped_count == 1U);
  kassert(g_udp_malformed_count == 1U);

  frame_tcp_syn[12] = 0x08;
  frame_tcp_syn[13] = 0x00;
  frame_tcp_syn[14] = 0x45;
  frame_tcp_syn[15] = 0x00;
  frame_tcp_syn[16] = 0x00;
  frame_tcp_syn[17] = 0x2c;
  frame_tcp_syn[18] = 0x00;
  frame_tcp_syn[19] = 0x00;
  frame_tcp_syn[20] = 0x40;
  frame_tcp_syn[21] = 0x00;
  frame_tcp_syn[22] = 64;
  frame_tcp_syn[23] = NETWORK_IP_PROTO_TCP;
  frame_tcp_syn[26] = 10;
  frame_tcp_syn[27] = 0;
  frame_tcp_syn[28] = 2;
  frame_tcp_syn[29] = 15;
  frame_tcp_syn[30] = 10;
  frame_tcp_syn[31] = 0;
  frame_tcp_syn[32] = 2;
  frame_tcp_syn[33] = 2;

  frame_tcp_syn[34] = 0x1f;
  frame_tcp_syn[35] = 0x90;
  frame_tcp_syn[36] = 0x00;
  frame_tcp_syn[37] = 0x50;
  frame_tcp_syn[38] = 0;
  frame_tcp_syn[39] = 0;
  frame_tcp_syn[40] = 0;
  frame_tcp_syn[41] = 1;
  frame_tcp_syn[42] = 0;
  frame_tcp_syn[43] = 0;
  frame_tcp_syn[44] = 0;
  frame_tcp_syn[45] = 0;
  frame_tcp_syn[46] = 0x60; /* offset 6 words */
  frame_tcp_syn[47] = NETWORK_TCP_FLAG_SYN;
  {
    uint16_t tcp_checksum =
        ipv4_pseudo_checksum(0x0a00020fU, 0x0a000202U,
                             NETWORK_IP_PROTO_TCP, 24U,
                             frame_tcp_syn + 34U, 24U);
    frame_tcp_syn[50] = (uint8_t)(tcp_checksum >> 8U);
    frame_tcp_syn[51] = (uint8_t)tcp_checksum;
  }
  net_wire_write_be16(frame_tcp_syn + 24U,
             ipv4_checksum(frame_tcp_syn + 14U, 20U));

  frame_tcp_timeout[0] = 0U;
  for (uint32_t i = 0; i < 58U; ++i) frame_tcp_timeout[i] = frame_tcp_syn[i];
  frame_tcp_timeout[50U] = 0U;
  frame_tcp_timeout[51U] = 0U;
  kassert(net_wire_parse_tcp(frame_tcp_timeout, 58U, &(uint16_t){0}, &(uint16_t){0},
                    &(uint32_t){0}, &(uint32_t){0}, &(uint8_t){0}) == 0);

  kassert(network_stack_process_tcp_frame(frame_tcp_syn, 58U) == XAIOS_OK);
  kassert(network_stack_tcp_handshake_count() == 1U);
  kassert(network_stack_tcp_connections() == 0U);

  frame_tcp_syn_ack[14] = 0x45;
  for (uint32_t i = 0; i < 58U; ++i) {
    frame_tcp_syn_ack[i] = frame_tcp_syn[i];
  }
  frame_tcp_syn_ack[14] = frame_tcp_syn[14];
  frame_tcp_syn_ack[23] = NETWORK_IP_PROTO_TCP;
  frame_tcp_syn_ack[34] = 0x1f;
  frame_tcp_syn_ack[35] = 0x90;
  frame_tcp_syn_ack[36] = 0x00;
  frame_tcp_syn_ack[37] = 0x50;
  frame_tcp_syn_ack[38] = 0;
  frame_tcp_syn_ack[39] = 0;
  frame_tcp_syn_ack[40] = 0;
  frame_tcp_syn_ack[41] = 0;
  net_wire_write_be32(frame_tcp_syn_ack + 38U, g_tcp_flows[0].expected_seq);
  net_wire_write_be32(frame_tcp_syn_ack + 42U, g_tcp_flows[0].next_send_seq);
  frame_tcp_syn_ack[46] = 0x60; /* offset 6 words */
  frame_tcp_syn_ack[47] = NETWORK_TCP_FLAG_ACK;
  frame_tcp_syn_ack[48] = 0x40;
  frame_tcp_syn_ack[49] = 0x00;
  frame_tcp_syn_ack[50] = 0;
  frame_tcp_syn_ack[51] = 0;
  {
    uint16_t tcp_checksum =
        ipv4_pseudo_checksum(0x0a00020fU, 0x0a000202U,
                             NETWORK_IP_PROTO_TCP, 24U,
                             frame_tcp_syn_ack + 34U, 24U);
    net_wire_write_be16(frame_tcp_syn_ack + 50U,
               tcp_checksum == 0U ? UINT16_MAX : tcp_checksum);
  }

  kassert(network_stack_process_tcp_frame(frame_tcp_syn_ack, 58U) == XAIOS_OK);
  kassert(network_stack_tcp_connections() == 1U);
  kassert(network_stack_tcp_established_count() == 1U);

  for (uint32_t i = 0; i < 58U; ++i) {
    frame_tcp_timeout[i] = frame_tcp_syn[i];
  }
  frame_tcp_timeout[35] = 0x91;
  frame_tcp_timeout[50] = 0;
  frame_tcp_timeout[51] = 0;
  {
    uint16_t tcp_checksum =
        ipv4_pseudo_checksum(0x0a00020fU, 0x0a000202U,
                             NETWORK_IP_PROTO_TCP, 24U,
                             frame_tcp_timeout + 34U, 24U);
    net_wire_write_be16(frame_tcp_timeout + 50U,
               tcp_checksum == 0U ? UINT16_MAX : tcp_checksum);
  }
  kassert(network_stack_process_tcp_frame(frame_tcp_timeout, 58U) == XAIOS_OK);
  kassert(network_stack_retransmit_tcp_flows(timer_now_ns() +
                                             NETWORK_TCP_RETRANSMIT_NS + 1U) ==
          1U);
  kassert(network_stack_tcp_retransmit_count() == 1U);
  kassert(network_stack_expire_tcp_flows(timer_now_ns() +
                                         NETWORK_TCP_RETRANSMIT_NS +
                                         NETWORK_TCP_SYN_TIMEOUT_NS + 2U) ==
          1U);
  kassert(network_stack_tcp_timeout_count() == 1U);
  kassert(network_stack_tcp_closed_count() == 1U);
  kassert(network_stack_tcp_connections() == 1U);

  kassert(network_stack_release_queue(1, 0) == XAIOS_OK);
  kassert(network_stack_release_queue(2, 1) == XAIOS_OK);
  network_stack_unregister_udp_listener(UINT16_C(0x5678));
  kassert(network_stack_queue_bindings() == 0U);

  {
    uint8_t ra_frame[14U + 40U + 16U + 32U] = {0};
    uint8_t saved_mac[6];
    const uint8_t test_mac[6] = {0x02U, 0x11U, 0x22U,
                                 0x33U, 0x44U, 0x55U};
    for (uint32_t i = 0U; i < 6U; ++i) {
      saved_mac[i] = g_local_mac[i];
      g_local_mac[i] = test_mac[i];
    }
    net_wire_write_be16(ra_frame + 18U, 48U);
    uint8_t *ra_icmpv6 = ra_frame + XAIOS_ICMPV6_OFFSET;
    ra_icmpv6[0] = XAIOS_ICMPV6_ROUTER_ADVERT;
    ra_icmpv6[16] = 3U; /* Prefix Information option */
    ra_icmpv6[17] = 4U; /* 32 bytes */
    ra_icmpv6[18] = 64U;
    ra_icmpv6[19] = UINT8_C(0x40); /* Autonomous address configuration */
    net_wire_write_be32(ra_icmpv6 + 20U, 60U);
    ra_icmpv6[32] = UINT8_C(0x20);
    ra_icmpv6[33] = UINT8_C(0x01);
    ra_icmpv6[34] = UINT8_C(0x0d);
    ra_icmpv6[35] = UINT8_C(0xb8);
    xaios_ip_addr_t public_v6;
    uint64_t public_v6_valid_until_ns = 0U;
    net_v6_reset_public();
    net_v6_apply_router_advertisement(ra_frame, sizeof(ra_frame), 10U,
                                      g_local_mac);
    net_v6_public_read(&public_v6, &public_v6_valid_until_ns);
    kassert(net_v6_is_global_unicast(&public_v6));
    kassert(public_v6.addr[0] == UINT8_C(0x20));
    kassert(public_v6.addr[8] == 0U);
    kassert(public_v6.addr[11] == UINT8_C(0xff));
    kassert(public_v6.addr[12] == UINT8_C(0xfe));
    kassert(public_v6.addr[15] == UINT8_C(0x55));
    kassert(public_v6_valid_until_ns == UINT64_C(60000000010));
    ra_icmpv6[17] = 0U;
    net_v6_reset_public();
    net_v6_apply_router_advertisement(ra_frame, sizeof(ra_frame), 10U,
                                      g_local_mac);
    net_v6_public_read(&public_v6, &public_v6_valid_until_ns);
    kassert(!net_v6_is_global_unicast(&public_v6));
    for (uint32_t i = 0U; i < 6U; ++i) g_local_mac[i] = saved_mac[i];
    klog("network: public IPv6 SLAAC self-test passed\n");
  }

  kassert(network_stack_udp_tx_count() == 3U);
  kassert(network_stack_udp_rx_count() == 3U);
  kassert(network_stack_tcp_reset_count() == 0U);
  kassert(network_stack_rx_packet_count() == 6U);
  kassert(network_stack_tx_packet_count() == 6U);
  kassert(network_stack_packet_drop_count() == 2U);
  kassert(network_stack_packet_lifecycle_count() == 18U);
  kassert(network_stack_queue_rx_enqueue_count() == 6U);
  kassert(network_stack_queue_tx_enqueue_count() == 6U);
  kassert(network_stack_queue_completion_count() == 6U);
  kassert(network_stack_queue_backpressure_drop_count() == 0U);
  kassert(network_stack_flow_core_mismatch_count() == 0U);

  {
    /* B-47: fill the socket-to-flow table and watch it refuse.
   
       Nothing in a boot fills this table, and nothing in the syscall paths
       could see it full, because the failure was a void return. So the only
       honest gate is to fill it here -- every row, from whatever the tests
       above left behind -- and then ask for one more. The probe descriptor is
       above anything the kernel socket allocator hands out, so it cannot
       collide with a real row.
   
       Three things are asserted, and they fail for three different reasons:
       the table really is full (a fill that quietly reused one row would
       prove nothing), the extra mapping is refused with a status the caller
       can act on (this is the line that goes red if the refusal is removed),
       and the probe descriptor genuinely has no mapping afterwards -- which
       is what the accept path used to hand to userspace without a word. */
    const uint64_t probe_base = UINT64_C(0x5841494f53000000);
    uint32_t capacity = network_stack_socket_map_capacity();
    uint32_t before = network_stack_socket_map_count();
    uint64_t exhausted_before = network_stack_socket_map_exhausted_count();
    uint32_t filled = 0U;
    kassert(before < capacity);
    for (uint32_t i = before; i < capacity; ++i) {
      kassert(network_stack_map_socket(probe_base + i, 0x4000U + i,
                                       NETWORK_IP_PROTO_TCP) == XAIOS_OK);
      ++filled;
    }
    kassert(network_stack_socket_map_count() == capacity);
    kassert(network_stack_socket_map_exhausted_count() == exhausted_before);

    socket_flow_mapping_t overflow_mapping;
    const uint64_t overflow_fd = probe_base + capacity;
    kassert(network_stack_map_socket(overflow_fd, 0x9999U,
                                     NETWORK_IP_PROTO_TCP) ==
            XAIOS_ERR_NO_MEMORY);
    kassert(network_stack_socket_map_exhausted_count() ==
            exhausted_before + 1U);
    kassert(network_stack_get_socket_mapping(overflow_fd,
                                             &overflow_mapping) == 0);
    /* A descriptor already in the table is still updated when the table is
       full -- the first scan matches before the second one runs out. Without
       this the refusal would break every established socket the moment one
       new one could not be admitted. */
    socket_flow_mapping_t rebind_mapping;
    kassert(network_stack_map_socket(probe_base + before, 0x7777U,
                                     NETWORK_IP_PROTO_TCP) == XAIOS_OK);
    kassert(network_stack_get_socket_mapping(probe_base + before,
                                             &rebind_mapping) != 0);
    kassert(rebind_mapping.flow_id == 0x7777U);
    kassert(network_stack_socket_map_exhausted_count() ==
            exhausted_before + 1U);

    for (uint32_t i = before; i < capacity; ++i) {
      network_stack_unmap_socket(probe_base + i);
    }
    kassert(network_stack_socket_map_count() == before);
    klog("network: socket-flow map exhaustion self-test passed capacity=%u "
         "filled=%u refused=%lu\n",
         capacity, filled,
         network_stack_socket_map_exhausted_count() - exhausted_before);
  }

  uint64_t udp50;
  uint64_t udp95;
  uint64_t udp99;
  uint64_t udp999;
  uint64_t tcp50;
  uint64_t tcp95;
  uint64_t tcp99;
  uint64_t tcp999;
  emit_latency_snapshot(&udp50, &udp95, &udp99, &udp999, &tcp50, &tcp95,
                        &tcp99, &tcp999);

  klog(
      "network: queue-backed udp/tcp self-test passed rx=%lu tx=%lu drops=%lu "
      "lifecycle=%lu udp_flows=%lu udp_hits=%lu udp_expired=%lu "
      "tcp_timeouts=%lu tcp_retransmits=%lu queue_rx=%lu queue_tx=%lu "
      "queue_done=%lu backpressure=%lu flow_mismatch=%lu udp_p50=%lu p95=%lu "
      "p99=%lu p999=%lu tcp_p50=%lu p95=%lu p99=%lu p999=%lu\n",
      network_stack_rx_packet_count(), network_stack_tx_packet_count(),
      network_stack_packet_drop_count(), network_stack_packet_lifecycle_count(),
      network_stack_udp_flow_count(), network_stack_udp_flow_hit_count(),
      network_stack_udp_expired_count(), network_stack_tcp_timeout_count(),
      network_stack_tcp_retransmit_count(),
      network_stack_queue_rx_enqueue_count(),
      network_stack_queue_tx_enqueue_count(),
      network_stack_queue_completion_count(),
      network_stack_queue_backpressure_drop_count(),
      network_stack_flow_core_mismatch_count(),
      udp50, udp95, udp99, udp999, tcp50, tcp95, tcp99, tcp999);
}

void network_init_persistent(void) {
  if (g_persistent_initialized != 0) {
    return;
  }
  if (network_device_get_mac(g_local_mac) == XAIOS_OK) {
    klog("network: local mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
         g_local_mac[0], g_local_mac[1], g_local_mac[2],
         g_local_mac[3], g_local_mac[4], g_local_mac[5]);
  }
  arp_init();
  ndp_init();
  ntp_init();
  ipv4_frag_init();
  ipv6_frag_init();
  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    g_tcp_flows[i].state = XAIOS_NETWORK_FLOW_FREE;
    g_tcp_flows[i].flow_id = 0;
    g_tcp_flows[i].rx_buf = 0;
    g_tcp_flows[i].tx_buf = 0;
    g_tcp_flows[i].pending_synack = 0;
    g_tcp_flows[i].pending_ack = 0;
    g_tcp_flows[i].pending_fin = 0;
  }
  for (uint32_t i = 0; i < NETWORK_UDP_FLOWS; ++i) {
    g_udp_flows[i].active = 0;
    g_udp_flows[i].flow_id = 0;
    g_udp_flows[i].rx_buf = 0;
  }
  for (uint32_t i = 0; i < network_listener_slot_count(); ++i) {
    network_listener_ex_t row;
    net_wire_bytes_zero(&row, sizeof(row));
    network_listener_slot_write(i, &row);
  }
  for (uint32_t i = 0; i < socket_map_slot_count(); ++i) {
    socket_flow_mapping_t row;
    net_wire_bytes_zero(&row, sizeof(row));
    socket_map_slot_write(i, &row);
  }
  /* The boot self-test fills this table on purpose and leaves its refusals
     counted. Zero them here so a non-zero figure in a running machine means
     a running machine ran out. */
  socket_map_reset_exhausted();
  g_poll_last_ns = 0U;
  g_poll_gap_max_ns = 0U;
  g_poll_gap_outage_count = 0U;
  g_poll_gap_record_lines = 0U;
  g_half_open_count = 0;
  g_tcp_drain_cursor = 0U;
  sockbuf_pool_init();
  routing_init();
  if (network_stack_queue_bindings() == 0U) {
    kassert(network_stack_bind_queue(0, 1, 1U) == XAIOS_OK);
  }
  net_v6_init(g_local_mac);
  g_persistent_initialized = 1;
  g_poll_tick_count = 0;
  g_tick_poll_count = 0;
  g_icmp_reply_count = 0;
  g_arp_reply_count = 0;
  g_icmpv6_reply_count = 0;
  g_ndp_reply_count = 0;
  g_ipv6_rx_count = 0;
  g_ping.state = XAIOS_NETWORK_PING_IDLE;
  g_ping.target_ip = 0U;
  g_ping.attempts = 0U;
  g_ping.round_trip_ns = 0U;
  g_ping.last_error = XAIOS_OK;
  g_ping_sent_ns = 0U;
  g_ping_sequence = 0U;
  /* RFC 4861 has a host solicit a router on startup rather than wait for the
     next unsolicited advertisement, which may be minutes away or never come.
     Without this the stack has a link-local address and no global one, and
     IPv6 works only on the local link. */
  xaios_ip_addr_t link_local_v6;
  net_v6_link_local(&link_local_v6);
  if (ndp_send_router_solicitation(g_local_mac, &link_local_v6) !=
      XAIOS_OK) {
    klog("network: router solicitation could not be sent\n");
  }
  klog("network: persistent mode initialized (dual-stack)\n");
}

xaios_status_t network_stack_local_ipv6(xaios_ip_addr_t *address) {
  if (address == 0) return XAIOS_ERR_INVALID;
  if (g_persistent_initialized == 0U) {
    xaios_ip_addr_zero(address);
    return XAIOS_ERR_NOT_FOUND;
  }
  net_v6_local_address(address, timer_now_ns());
  return XAIOS_OK;
}

xaios_status_t network_wait_for_ipv6_slaac(uint64_t timeout_ns) {
  if (g_persistent_initialized == 0U || timeout_ns == 0U) {
    return XAIOS_ERR_INVALID;
  }
  /* A router advertisement answers the solicitation within milliseconds, but
     nothing polls the interface between bringing it up and starting services,
     so the reply would sit unread in the receive ring and the machine would
     come up with a link-local address only. Poll for it here, re-soliciting
     the way RFC 4861 does rather than waiting on one packet. */
  xaios_ip_addr_t address;
  uint64_t started = timer_now_ns();
  uint64_t next_solicit = started + UINT64_C(500000000);
  uint32_t solicits = 1U;
  for (;;) {
    network_poll_tick();
    if (net_v6_slaac_configured() != 0 &&
        network_stack_local_ipv6(&address) == XAIOS_OK) {
      return XAIOS_OK;
    }
    uint64_t now = timer_now_ns();
    if (now - started >= timeout_ns) break;
    if (now >= next_solicit && solicits < 3U) {
      xaios_ip_addr_t link_local_v6;
      net_v6_link_local(&link_local_v6);
      (void)ndp_send_router_solicitation(g_local_mac, &link_local_v6);
      ++solicits;
      next_solicit = now + UINT64_C(500000000);
    }
  }
  klog("network: no usable IPv6 prefix after %u solicitations; link-local "
       "only\n",
       solicits);
  return XAIOS_ERR_NOT_FOUND;
}

uint32_t network_stack_local_ipv4(void) { return network_config_local_ipv4(); }

xaios_status_t network_stack_local_mac(uint8_t mac[6]) {
  if (mac == 0 || g_persistent_initialized == 0U) return XAIOS_ERR_NOT_FOUND;
  for (uint32_t i = 0U; i < 6U; ++i) mac[i] = g_local_mac[i];
  return XAIOS_OK;
}

xaios_status_t network_stack_local_public_ipv6(xaios_ip_addr_t *address) {
  if (address == 0) return XAIOS_ERR_INVALID;
  if (g_persistent_initialized == 0U ||
      net_v6_public_address(address, timer_now_ns()) == 0) {
    xaios_ip_addr_zero(address);
    return XAIOS_ERR_NOT_FOUND;
  }
  return XAIOS_OK;
}

xaios_status_t network_stack_ping_start(uint32_t target_ip) {
  uint8_t frame[50];
  uint8_t gateway_mac[6];
  if (g_persistent_initialized == 0U || target_ip == 0U)
    return XAIOS_ERR_INVALID;
  if (g_ping.state == XAIOS_NETWORK_PING_PENDING) return XAIOS_ERR_BUSY;
  network_config_gateway_mac(gateway_mac);
  for (uint32_t i = 0U; i < sizeof(frame); ++i) frame[i] = 0U;
  for (uint32_t i = 0U; i < 6U; ++i) {
    frame[i] = gateway_mac[i];
    frame[6U + i] = g_local_mac[i];
  }
  net_wire_write_be16(frame + 12U, NETWORK_ETHERTYPE_IPV4);
  ipv4_build_header(frame + 14U, 36U, XAIOS_IPV4_PROTO_ICMP,
                    network_config_local_ipv4(), target_ip);
  uint8_t *icmp = frame + 34U;
  icmp[0] = XAIOS_ICMP_ECHO_REQUEST;
  icmp[1] = 0U;
  net_wire_write_be16(icmp + 4U, NETWORK_PING_IDENTIFIER);
  ++g_ping_sequence;
  net_wire_write_be16(icmp + 6U, g_ping_sequence);
  icmp[8] = 'X'; icmp[9] = 'A'; icmp[10] = 'I'; icmp[11] = 'O';
  icmp[12] = 'S'; icmp[13] = 'P'; icmp[14] = 'N'; icmp[15] = 'G';
  net_wire_write_be16(icmp + 2U, ipv4_checksum(icmp, 16U));
  xaios_status_t status = network_device_tx(frame, sizeof(frame));
  g_ping.state = status == XAIOS_OK ? XAIOS_NETWORK_PING_PENDING
                                     : XAIOS_NETWORK_PING_FAILED;
  g_ping.target_ip = target_ip;
  g_ping.attempts = 1U;
  g_ping.round_trip_ns = 0U;
  g_ping.last_error = status;
  g_ping_sent_ns = timer_now_ns();
  return status == XAIOS_OK ? XAIOS_ERR_BUSY : status;
}

xaios_network_ping_status_t network_stack_ping_status(void) { return g_ping; }

static int network_reassemble_incoming(uint8_t *frame, uint32_t *frame_len,
                                       uint16_t ethertype) {
  uint64_t completed_len = *frame_len;
  xaios_status_t status;

  if (ethertype == NETWORK_ETHERTYPE_IPV4) {
    if (!ipv4_validate_incoming(frame, completed_len)) {
      return 0;
    }
    if (!ipv4_is_fragment(frame, completed_len)) {
      return 1;
    }
    status = ipv4_reassemble(frame, &completed_len);
  } else if (ethertype == NETWORK_ETHERTYPE_IPV6) {
    if (!ipv6_is_fragment_v6(frame, completed_len)) {
      return 1;
    }
    status = ipv6_reassemble_v6(frame, &completed_len);
  } else {
    return 0;
  }

  if (status != XAIOS_OK || completed_len > NETWORK_BUFFER_SIZE) {
    return 0;
  }
  *frame_len = (uint32_t)completed_len;
  return 1;
}

/* B-44: how long the stack went undriven, and saying so.

   Most of this poll comes from the network syscalls a process makes and from
   wait_events, and on a booted machine the process making those calls is sshd
   -- which the kernel starts as its last act, on the boot CPU, after switching
   preemption and the periodic timer off (kmain.c). One secondary CPU carries a
   network tick (OD-011) whose interrupt wakes it so its idle loop polls this
   stack, and that is what bounds the window a blocking call in that loop
   opens. Before the tick, a pause anywhere in the
   loop was a total network outage: nothing came off the receive ring, no ACK
   left, no retransmit fired, no flow expired.

   Whether the arrangement should change was a design question and is argued
   in wiki/Architecture.md; the timer was chosen and is landed. What was
   indefensible is that it was invisible:
   from inside, a stack that has not run for ten seconds is indistinguishable
   from a quiet network, and from outside it is indistinguishable from the
   machine having gone away. So the gap between consecutive polls is measured
   here, the longest one is kept, and a gap long enough to be an outage says
   so on the console.

   Measured only while a listener is registered. With no listener there is
   nothing the poll is late for, and a machine with no network service would
   otherwise report enormous gaps that mean nothing -- a metric that fires on
   an idle machine is a metric nobody reads. */
static uint32_t listeners_active_unlocked(void) {
  /* The registry counts its own live rows now; this keeps the name the
     poll-gap code below reads. */
  return network_listener_active_count();
}

static void network_note_poll_gap(uint64_t now_ns) {
  uint32_t listeners = listeners_active_unlocked();
  if (listeners == 0U) {
    /* Nothing is waiting on this stack. Forget when it last ran, so the first
       poll after a listener appears is not charged with the idle stretch
       before it. */
    g_poll_last_ns = 0U;
    return;
  }
  uint64_t previous = g_poll_last_ns;
  g_poll_last_ns = now_ns;
  if (previous == 0U || now_ns <= previous) return;
  uint64_t gap_ns = now_ns - previous;
  if (gap_ns >= NETWORK_POLL_GAP_OUTAGE_NS) {
    ++g_poll_gap_outage_count;
    /* Rate-limited for the reason every log on this path is: a machine that
       is stalling repeatedly must not turn its own diagnosis into the next
       stall. First, then every sixty-fourth. */
    if (g_poll_gap_outage_count == 1U ||
        (g_poll_gap_outage_count % 64U) == 0U) {
      klog("network: stack was not polled for ms=%lu outages=%lu listeners=%u "
           "(nothing drives this poll but the processes calling into it)\n",
           gap_ns / UINT64_C(1000000), g_poll_gap_outage_count, listeners);
    }
  }
  if (gap_ns <= g_poll_gap_max_ns) return;
  g_poll_gap_max_ns = gap_ns;
  /* Every new maximum, which is a short and self-limiting sequence: it climbs
     to the cadence of whatever is driving the poll and then stops. Capped all
     the same, so a machine that degrades steadily cannot fill the console. */
  if (g_poll_gap_record_lines >= NETWORK_POLL_GAP_RECORD_LINES) return;
  ++g_poll_gap_record_lines;
  klog("network: longest gap between polls us=%lu polls=%lu tick=%lu "
       "listeners=%u\n",
       g_poll_gap_max_ns / UINT64_C(1000), g_poll_tick_count,
       __atomic_load_n(&g_tick_poll_count, __ATOMIC_RELAXED), listeners);
}

uint64_t network_poll_gap_max_ns(void) { return g_poll_gap_max_ns; }
uint64_t network_poll_gap_outage_count(void) {
  return g_poll_gap_outage_count;
}

/* The network's own work, under the guard. `operations_tick()` is deliberately
   not here: it is the power path, it quiesces storage and it can stop the
   machine, and it belongs to whichever caller is in a position to do that. Both
   public entry points call it first -- `network_poll_tick` for a syscall and
   `network_poll_tick_from_carrier` for the tick CPU's idle loop, both in thread
   context -- so this function stays the network's work and nothing else. */
static void network_poll_tick_locked(void) {
  if (g_persistent_initialized == 0) {
    return;
  }
  uint64_t now_ns = timer_now_ns();
  network_note_poll_gap(now_ns);
  ntp_tick(now_ns);
  net_v6_expire_public(now_ns);
  if (g_ping.state == XAIOS_NETWORK_PING_PENDING && now_ns >= g_ping_sent_ns &&
      now_ns - g_ping_sent_ns >= NETWORK_PING_TIMEOUT_NS) {
    g_ping.state = XAIOS_NETWORK_PING_TIMEOUT;
    g_ping.last_error = XAIOS_ERR_IO;
  }
  uint8_t rx_buf[NETWORK_BUFFER_SIZE];
  ++g_poll_tick_count;
  /* Take everything the device has queued rather than one frame per call. The
     receive ring holds a handful of buffers, so draining only the head leaves
     a link with steady inbound traffic permanently full: the device then drops
     what arrives, and the guest answers nothing it was not already holding.
     An interrupt hides this by draining promptly; a platform with none, and a
     poll that runs only inside network syscalls, does not. Bounded so a busy
     link cannot hold the poll lock indefinitely. */
  for (uint32_t drained = 0U; drained < NETWORK_POLL_RX_BUDGET; ++drained) {
    uint32_t frame_len = network_device_rx_poll(rx_buf, sizeof(rx_buf));
    if (frame_len == 0) {
      break;
    }
    /* A frame is the only way an external peer makes a socket readable, so
       this is where a waiter is told its answer has expired. Before the
       frame is parsed rather than after: what it turns into -- data, a
       connection, a close -- all change readiness, and none of them are
       worth distinguishing here. */
    network_readiness_note();
  if (frame_len < 14U) {
    return;
  }
  uint16_t ethertype = net_wire_read_u16_be(rx_buf + 12U);
  if (ethertype == 0x0806U) {
    if (frame_len >= 42U && net_wire_read_u16_be(rx_buf + 20U) == XAIOS_ARP_OP_REPLY) {
      arp_process_reply(rx_buf, frame_len);
    } else if (frame_len >= 42U &&
               net_wire_read_u16_be(rx_buf + 20U) == XAIOS_ARP_OP_REQUEST) {
      uint32_t target_ip = net_wire_read_u32_be(rx_buf + 38U);
      if (target_ip == network_config_local_ipv4()) {
        uint8_t reply_frame[64];
        uint64_t reply_len = 0;
        if (arp_build_reply(reply_frame, &reply_len, g_local_mac,
                            network_config_local_ipv4(), rx_buf + 6,
                            net_wire_read_u32_be(rx_buf + 28U)) == XAIOS_OK) {
          network_device_tx(reply_frame, reply_len);
          ++g_arp_reply_count;
        }
      }
    }
  } else if (ethertype == NETWORK_ETHERTYPE_IPV4) {
    if (frame_len < 34U ||
        !network_reassemble_incoming(rx_buf, &frame_len, ethertype)) {
      return;
    }
    uint8_t protocol = rx_buf[23U];
    if (protocol == NETWORK_IP_PROTO_UDP &&
        ntp_process_ipv4_frame(rx_buf, frame_len, now_ns) == XAIOS_OK) {
      return;
    }
    if (protocol == NETWORK_IP_PROTO_UDP &&
        dns_process_ipv4_frame(rx_buf, frame_len, now_ns) == XAIOS_OK) {
      dns_tick(now_ns);
      return;
    }
    if (protocol == XAIOS_IPV4_PROTO_ICMP) {
      const uint8_t *icmp = rx_buf + 34U;
      if (frame_len >= 42U && icmp[0] == XAIOS_ICMP_ECHO_REPLY &&
          net_wire_read_u16_be(icmp + 4U) == NETWORK_PING_IDENTIFIER &&
          net_wire_read_u16_be(icmp + 6U) == g_ping_sequence &&
          net_wire_read_u32_be(rx_buf + 26U) == g_ping.target_ip &&
          ipv4_checksum(icmp, net_wire_read_u16_be(rx_buf + 16U) - 20U) == 0U &&
          g_ping.state == XAIOS_NETWORK_PING_PENDING) {
        g_ping.state = XAIOS_NETWORK_PING_REPLIED;
        g_ping.round_trip_ns = now_ns >= g_ping_sent_ns
                                  ? now_ns - g_ping_sent_ns : 0U;
        g_ping.last_error = XAIOS_OK;
        return;
      }
      uint16_t identifier = 0;
      uint16_t sequence = 0;
      if (icmp_process_echo_request(rx_buf, frame_len, &identifier,
                                     &sequence) == XAIOS_OK) {
        uint8_t reply_buf[NETWORK_BUFFER_SIZE];
        uint64_t reply_len = 0;
        if (icmp_build_echo_reply(reply_buf, &reply_len, g_local_mac,
                                   rx_buf + 6, network_config_local_ipv4(),
                                   net_wire_read_u32_be(rx_buf + 26U), rx_buf,
                                   frame_len) == XAIOS_OK) {
          network_device_tx(reply_buf, reply_len);
          ++g_icmp_reply_count;
        }
      }
    } else if (protocol == NETWORK_IP_PROTO_UDP) {
      network_stack_process_udp_frame(rx_buf, frame_len);
    } else if (protocol == NETWORK_IP_PROTO_TCP) {
      (void)network_stack_process_tcp_frame(rx_buf, frame_len);
    }
  } else if (ethertype == NETWORK_ETHERTYPE_IPV6) {
    ++g_ipv6_rx_count;
    if (frame_len < 54U ||
        !network_reassemble_incoming(rx_buf, &frame_len, ethertype)) {
      return;
    }
    uint8_t next_header = rx_buf[20U]; /* byte 6 of IPv6 at offset 14 */
    if (next_header == XAIOS_IPV6_NEXT_ICMPV6) {
      if (frame_len >= XAIOS_ICMPV6_MIN_FRAME) {
        uint8_t icmpv6_type = rx_buf[XAIOS_ICMPV6_OFFSET];
        if (icmpv6_type == XAIOS_ICMPV6_ECHO_REQUEST) {
          xaios_ip_addr_t echo_src;
          xaios_ip_addr_t echo_dst;
          uint16_t identifier = 0;
          uint16_t sequence = 0;
          if (icmpv6_process_echo_request(rx_buf, frame_len, &identifier,
                                           &sequence, &echo_src,
                                           &echo_dst) == XAIOS_OK) {
            uint8_t reply_buf[NETWORK_BUFFER_SIZE];
            uint64_t reply_len = 0;
            xaios_ip_addr_t echo_source;
            net_v6_source_for(&echo_dst, &echo_source);
            if (icmpv6_build_echo_reply(reply_buf, &reply_len, g_local_mac,
                                         rx_buf + 6,
                                         &echo_source,
                                         &echo_src, rx_buf,
                                         frame_len) == XAIOS_OK) {
              network_device_tx(reply_buf, reply_len);
              ++g_icmpv6_reply_count;
            }
          }
        } else if (icmpv6_type == XAIOS_ICMPV6_NEIGHBOR_SOLICIT) {
          /* Extract target address from NS (bytes 8-23 of ICMPv6 payload) */
          xaios_ip_addr_t ns_target;
          xaios_ip_addr_from_raw_ipv6(&ns_target, rx_buf + XAIOS_ICMPV6_OFFSET + 8);
          /* Build NA: source = our link-local, dest = NS source */
          xaios_ip_addr_t na_src;
          net_v6_source_for(&ns_target, &na_src);
          xaios_ip_addr_t na_dst;
          xaios_ip_addr_from_raw_ipv6(&na_dst, rx_buf + 22); /* IPv6 src */
          uint8_t na_frame[128];
          uint64_t na_len = 0;
          if (icmpv6_build_neighbor_advertisement(na_frame, &na_len,
                g_local_mac, rx_buf + 6, &na_src, &na_dst, &ns_target,
                rx_buf, frame_len) == XAIOS_OK) {
            network_device_tx(na_frame, na_len);
            ++g_ndp_reply_count;
          }
        } else if (icmpv6_type == XAIOS_ICMPV6_NEIGHBOR_ADVERT) {
          ndp_process_neighbor_advertisement(rx_buf, frame_len);
        } else if (icmpv6_type == XAIOS_ICMPV6_ROUTER_ADVERT &&
                   ndp_process_router_advertisement(rx_buf, frame_len) == XAIOS_OK) {
          net_v6_apply_router_advertisement(rx_buf, frame_len, now_ns,
                                            g_local_mac);
        }
      }
    } else if (next_header == NETWORK_IP_PROTO_UDP) {
      network_stack_process_udp_frame_v6(rx_buf, frame_len);
    } else if (next_header == NETWORK_IP_PROTO_TCP) {
      (void)network_stack_process_tcp_frame_v6(rx_buf, frame_len);
    }
  }
  }
  /* Drain pending TCP transmissions (SYN-ACK, data, ACK, FIN) */
  dns_tick(now_ns);
  network_stack_retransmit_tcp_flows(now_ns);
  network_stack_expire_tcp_flows(now_ns);
  tcp_drain_pending();
}

void network_poll_tick(void) {
  network_lock();
  /* The power path runs here and only here, which is where a shutdown is
     asked for from. Called before the network's own work, as it always was. */
  operations_tick();
  network_poll_tick_locked();
  /* The resolver's transport tick belongs inside this guard, not after it. It
     mutates the pending query and drives the TCP flow carrying it, and dns.c's
     own comment says the resolver shares this guard rather than holding one of
     its own precisely because the poll calls back into it. Called after the
     unlock it raced every dns_resolve_address on another CPU -- and once a tick
     can arrive in interrupt context, which is what OD-011 adds, it would
     re-enter a resolver call already in progress on this one. */
  dns_transport_tick(timer_now_ns());
  network_unlock();
}

void network_poll_tick_from_carrier(void) {
  /* Thread context, so this is the whole poll: `operations_tick()` is the
     power path and belongs here and on the syscall path, and nowhere else. */
  network_poll_tick();
  __atomic_add_fetch(&g_tick_poll_count, 1U, __ATOMIC_RELAXED);
}

uint64_t network_tick_poll_count(void) {
  return __atomic_load_n(&g_tick_poll_count, __ATOMIC_RELAXED);
}

uint64_t network_poll_tick_count(void) {
  return g_poll_tick_count;
}

uint64_t network_icmp_reply_count(void) {
  return g_icmp_reply_count;
}

uint64_t network_arp_reply_sent_count(void) {
  return g_arp_reply_count;
}

uint64_t network_icmpv6_reply_count(void) {
  return g_icmpv6_reply_count;
}

uint64_t network_ndp_reply_count(void) {
  return g_ndp_reply_count;
}

uint64_t network_ipv6_rx_count(void) {
  return g_ipv6_rx_count;
}
