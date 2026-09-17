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
 * Seven of those cuts have landed. The listener registry, the accept queue and
 * the socket-to-flow map live in network_stack_listener.c, reached through the
 * row-copying accessors declared in network_stack_listener.h. The IPv6 address
 * state -- link-local, SLAAC, the public address, the default router and the
 * on-link prefix, with the router-advertisement handler that fills them in --
 * lives in network_stack_v6.c, reached through the copy-in/copy-out accessors
 * declared in network_stack_v6.h. The TCP data plane -- the per-flow state
 * machine in network_stack_tcp_flow.c and the segment builder and transmit
 * path in network_stack_tcp_segment.c, joined by the declarations in
 * network_stack_tcp.h -- needed no table accessor at all: every function takes
 * the flow row from the caller that already owns it.
 *
 * The last two are the pair this file's note named next. The
 * queue-binding registry, the queue rings and the packet-descriptor pool live
 * in network_stack_packet.c, reached through the copy-out binding accessors
 * and a packet *lease* (an index, not a pointer) declared in
 * network_stack_packet.h, so a caller fixes a descriptor's whole tuple at
 * allocation and never holds a pointer into the pool. The UDP flow table and
 * the UDP transmit/expire data plane -- find, allocate, expire and transmit --
 * live in network_stack_udp.c, reached through the cursor-plus-commit accessors
 * declared in network_stack_udp.h. The two UDP receive handlers and the receive
 * syscall stayed here: the syscall is mostly listener-backlog work, and the
 * handlers mutate a table row through the cursor the header describes. The
 * receive dispatch inside
 * network_poll_tick_locked() still waits: it is interleaved with the poll tail
 * and reaches both flow tables, the descriptors, the rings and the ping state
 * from inside the loop, so it wants more accessors than either of these cuts
 * did.
 *
 * The two cuts after those are leaves of that state block. The
 * application/external-session plane -- the synthetic IPv4 frames the loopback
 * echo and connect tests build, the echo and connect entry points, and the
 * session dispatcher that formats their result -- lives in
 * network_stack_app.c and owns no state at all: it reaches this file once,
 * through net_stack_tcp_flow_read_syn_recv_seqs(), the copy-out sequence pair
 * it needs to finish the loopback handshake, declared in network_stack_app.h.
 * The boot-time self-test -- the latency snapshot, the listener-pool capacity
 * check and network_stack_self_test() -- lives in network_stack_selftest.c,
 * reached through network_stack_selftest.h. It drives the stack through its
 * exported entry points; the three things it cannot reach without a pointer
 * into state are the local MAC it rewrites for the router-advertisement case
 * (net_stack_local_mac_set()), the sliding-window check that asserts on this
 * file's retransmit counter (net_stack_tcp_sliding_window_self_test(), which
 * therefore stayed here), and the same sequence accessor.
 *
 * The rest of this file -- the TCP flow table, its counters, the receive
 * dispatch and the poll tail -- is still file-scope state, and the
 * row-copying accessors are the pattern the next cut should follow.
 *
 * The layout, for navigation:
 *
 *   constants and types            declarations, sizes, protocol numbers
 *   shared state                   counters, TCP flow table
 *   guard                          see xaios_reentrant_lock; C-01
 *   helpers                        byte order, checksums, frame construction
 *   receive path                   frame classification and dispatch
 *   TCP flow state machine         moved to network_stack_tcp_flow.c
 *   TCP segment builder/transmit   moved to network_stack_tcp_segment.c
 *   listener, accept, socket map   moved to network_stack_listener.c
 *   IPv6 address state             moved to network_stack_v6.c
 *   queue bindings, packet pool    moved to network_stack_packet.c
 *   UDP table and data plane       moved to network_stack_udp.c
 *   app/external session plane     moved to network_stack_app.c
 *   boot self-test                 moved to network_stack_selftest.c
 *   public API                     the entry points a syscall reaches
 */

#include <xaios/arp.h>

#include "network_stack_app.h"
#include "network_stack_listener.h"
#include "network_stack_packet.h"
#include "network_stack_selftest.h"
#include "network_stack_udp.h"
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

static uint64_t g_next_flow_id = 1U;
static network_tcp_flow_t g_tcp_flows[NETWORK_TCP_CONNECTIONS];

/* The one flow-id counter the UDP and TCP tables share. The moved UDP
   allocation calls this; the TCP allocations in this file still take the
   counter directly, so the increment below is the one they make. Caller
   holds the guard. */
uint32_t net_stack_alloc_flow_id(void) {
  uint32_t flow_id = (uint32_t)(g_next_flow_id++);
  if (flow_id == 0U) {
    flow_id = 1U;
    g_next_flow_id = 2U;
  }
  return flow_id;
}

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

/* The moved UDP transmit path stamps the interface MAC into every frame. This
   is the raw read it made, with no "persistent mode has started" test, and it
   is what the accessor declared in network_stack_udp.h names. Caller holds the
   guard. */
void net_stack_local_mac(uint8_t out[6]) {
  for (uint32_t i = 0U; i < 6U; ++i) out[i] = g_local_mac[i];
}

/* The one write the moved boot self-test needs into the interface MAC: its
   router-advertisement case overwrites the MAC to make the EUI-64 address it
   asserts on, then restores the saved value through this same call. This file
   owns g_local_mac, so the setter lives here; the value is copied in rather
   than a pointer being handed out. */
void net_stack_local_mac_set(const uint8_t mac[6]) {
  if (mac == 0) return;
  for (uint32_t i = 0U; i < 6U; ++i) g_local_mac[i] = mac[i];
}

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
static uint64_t g_flow_core_mismatch_count;

static uint64_t g_tcp_latency_samples[NETWORK_MAX_SAMPLES];
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

/* The queue-binding registry, the queue rings and the packet-descriptor pool
   now live in network_stack_packet.c; network_stack_packet.h declares the
   copy-out binding accessors and the packet lease the code below calls. The
   UDP flow table and its find/allocate helpers moved to network_stack_udp.c;
   network_stack_udp.h declares the cursor-plus-commit accessors the receive
   handlers below use. */

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

/* The extracted app and self-test modules cannot reach the flow table, and
   must not point into it. Both only need the two sequence numbers of a
   half-open row: the app plane to finish the loopback handshake it drives,
   the boot self-test to seed the matching SYN-ACK. The numbers are copied
   into caller-owned locals; no pointer leaves. Caller holds the stack guard. */
int net_stack_tcp_flow_read_syn_recv_seqs(uint16_t local_port,
                                          uint16_t remote_port,
                                          uint32_t *expected_seq,
                                          uint32_t *next_send_seq) {
  if (expected_seq == 0 || next_send_seq == 0) return 0;
  for (uint32_t i = 0U; i < NETWORK_TCP_CONNECTIONS; ++i) {
    if (g_tcp_flows[i].state == XAIOS_NETWORK_FLOW_SYN_RECV &&
        g_tcp_flows[i].local_port == local_port &&
        g_tcp_flows[i].remote_port == remote_port) {
      *expected_seq = g_tcp_flows[i].expected_seq;
      *next_send_seq = g_tcp_flows[i].next_send_seq;
      return 1;
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
  network_queue_binding_t binding;
  if (!net_queue_binding_select(local_port, remote_port,
                                remote_addr->family == XAIOS_IP_FAMILY_V4
                                    ? local_address
                                    : xaios_ip_addr_hash(&link_local_v6),
                                remote_addr->family == XAIOS_IP_FAMILY_V4
                                    ? remote_address
                                    : xaios_ip_addr_hash(remote_addr),
                                &binding)) {
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
  flow->queue_id = binding.queue_id;
  flow->cell_id = binding.cell_id;
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
  net_packet_reset();

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

  net_udp_reset();

  for (uint32_t i = 0; i < network_listener_slot_count(); ++i) {
    network_listener_ex_t row;
    net_wire_bytes_zero(&row, sizeof(row));
    network_listener_slot_write(i, &row);
  }

  g_next_flow_id = 1U;
  g_tcp_handshake_count = 0;
  g_tcp_reset_count = 0;
  g_tcp_timeout_count = 0;
  g_tcp_retransmit_count = 0;
  g_tcp_established_count = 0;
  g_tcp_closed_count = 0;
  g_tcp_latency_count = 0;
  g_flow_core_mismatch_count = 0;

  for (uint32_t i = 0; i < NETWORK_MAX_SAMPLES; ++i) {
    g_tcp_latency_samples[i] = 0;
  }

  klog("network: stack initialized\n");
}

/* network_stack_bind_queue() and network_stack_release_queue() moved to
   network_stack_packet.c with the binding table they own. */

xaios_status_t network_stack_process_udp_frame(const uint8_t *frame,
                                            uint64_t frame_len) {
  if (frame == 0 || frame_len < 34U) {
    net_udp_note_dropped();
    net_udp_note_malformed();
    net_note_packet_drop();
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
    net_udp_note_dropped();
    net_udp_note_malformed();
    net_note_packet_drop();
    return XAIOS_ERR_INVALID;
  }

  if (src_port == 0 || dst_port == 0 || payload_len == 0) {
    net_udp_note_dropped();
    net_note_packet_drop();
    return XAIOS_ERR_INVALID;
  }

  network_udp_flow_t existing_row;
  int have_existing = net_udp_flow_find_v4(dst_port, src_port, dst_address,
                                           src_address, &existing_row);
  network_queue_binding_t binding;
  int have_binding =
      have_existing != 0
          ? net_queue_binding_find(existing_row.queue_id, &binding)
          : net_queue_binding_select(dst_port, src_port, dst_address,
                                     src_address, &binding);
  if (have_binding == 0) {
    net_udp_note_dropped();
    net_note_packet_drop();
    return XAIOS_ERR_NOT_FOUND;
  }

  uint32_t packet =
      net_packet_alloc(binding.queue_id, frame_len, start, src_port, dst_port,
                       src_address, dst_address, 0, 0);
  if (packet == 0) {
    net_udp_note_dropped();
    return XAIOS_ERR_NO_MEMORY;
  }

  network_udp_flow_t flow_row;
  uint32_t flow_index = 0U;
  if (!net_udp_flow_alloc(binding.queue_id, binding.cell_id, dst_port, src_port,
                          dst_address, src_address, 0, 0, start, &flow_row,
                          &flow_index)) {
    net_udp_note_dropped();
    net_packet_mark_dropped(packet);
    return XAIOS_ERR_NO_MEMORY;
  }
  if (flow_row.queue_id != binding.queue_id ||
      flow_row.cell_id != binding.cell_id) {
    ++g_flow_core_mismatch_count;
    net_packet_mark_dropped(packet);
    return XAIOS_ERR_BUSY;
  }
  ++flow_row.packets_rx;
  net_udp_note_rx();
  for (uint32_t i = 0; i < 6U; ++i) {
    flow_row.remote_mac[i] = frame[6U + i];
  }
  flow_row.remote_mac_valid = 1;
  /* The row is written back here, before the listener block below can return
     early: the old code held a pointer into the table, so these increments
     were visible on every path out of the function. */
  net_udp_flow_commit(flow_index, &flow_row);
  
  /* Deliver UDP payload to flow rx_buf */
  if (flow_row.rx_buf != 0 && payload_len > 8) {
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
          data_len > sockbuf_available(flow_row.rx_buf) ||
          sockbuf_write(flow_row.rx_buf, udp_payload, data_len) != data_len ||
          !udp_listener_enqueue(dst_port, flow_row.flow_id, src_port, &peer_addr,
                                (uint16_t)data_len)) {
        listener_unlock();
        net_udp_note_dropped();
        net_packet_mark_dropped(packet);
        return XAIOS_ERR_BUSY;
      }
    }
    listener_unlock();
  }
  
  net_packet_mark_tx(packet);
  ++flow_row.packets_tx;
  net_udp_note_tx();
  net_udp_flow_commit(flow_index, &flow_row);
  net_packet_mark_complete(packet);
  net_udp_record_latency(timer_now_ns() - start);
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

/* The receive syscall stayed here while the rest of the UDP data plane moved
   to network_stack_udp.c: it is mostly the listener backlog, which the
   listener module owns, and it only needs the flow's rx_buf, which
   net_udp_flow_find_by_id() copies out. */
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

  network_udp_flow_t udp_flow;
  if (net_udp_flow_find_by_id(entry.flow_id, &udp_flow) &&
      udp_flow.rx_buf != 0) {
    uint32_t read_limit = entry.payload_len;
    if (read_limit > buffer_size) {
      read_limit = buffer_size;
    }
    uint32_t bytes_read = sockbuf_read(udp_flow.rx_buf, buffer, read_limit);
    if (entry.payload_len > bytes_read) {
      sockbuf_discard(udp_flow.rx_buf,
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
    ++g_tcp_reset_count;
    net_note_packet_drop();
    return XAIOS_ERR_INVALID;
  }
  if (src_port == 0U || dst_port == 0U) {
    ++g_tcp_reset_count;
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

  network_tcp_flow_t *flow = find_flow_by_ports(dst_port, src_port, remote_address);
  network_queue_binding_t binding;
  int have_binding =
      flow != 0 ? net_queue_binding_find(flow->queue_id, &binding)
                : net_queue_binding_select(dst_port, src_port, local_address,
                                           remote_address, &binding);
  if (have_binding == 0) {
    ++g_tcp_reset_count;
    net_note_packet_drop();
    return XAIOS_ERR_NOT_FOUND;
  }

  uint32_t packet =
      net_packet_alloc(binding.queue_id, frame_len, start, src_port, dst_port,
                       remote_address, local_address, 0, 0);
  if (packet == 0) {
    ++g_tcp_reset_count;
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
    if (g_half_open_count > 0U) --g_half_open_count;
    ++flow->packets_rx;
    ++g_tcp_handshake_count;
    ++g_tcp_established_count;
    net_packet_mark_tx(packet);
    net_packet_mark_complete(packet);
    record_latency(g_tcp_latency_samples, &g_tcp_latency_count,
                   timer_now_ns() - start);
    return XAIOS_OK;
  }

  if ((flags & NETWORK_TCP_FLAG_RST) != 0U) {
    if (flow != 0) {
      if (seq != flow->expected_seq) {
        net_packet_mark_dropped(packet);
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
      ++g_tcp_reset_count;
      net_packet_mark_dropped(packet);
      return XAIOS_ERR_NOT_FOUND;
    }
    flow = alloc_tcp_flow(dst_port, src_port, remote_address, 0);
    if (flow == 0) {
      ++g_tcp_reset_count;
      net_packet_mark_dropped(packet);
      return XAIOS_ERR_NO_MEMORY;
    }
    flow->flow_id = (uint32_t)(g_next_flow_id++);
    if (flow->flow_id == 0U) {
      flow->flow_id = 1U;
      g_next_flow_id = 2U;
    }
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
      if (g_half_open_count > 0U) --g_half_open_count;
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

    ++g_tcp_handshake_count;
    net_packet_mark_tx(packet);
    net_packet_mark_complete(packet);
    record_latency(g_tcp_latency_samples, &g_tcp_latency_count,
                  timer_now_ns() - start);
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
    if (g_half_open_count > 0U) --g_half_open_count;
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
    ++g_tcp_handshake_count;
    ++g_tcp_established_count;
    net_packet_mark_tx(packet);
    net_packet_mark_complete(packet);
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

    net_packet_mark_tx(packet);
    net_packet_mark_complete(packet);
    record_latency(g_tcp_latency_samples, &g_tcp_latency_count,
                  timer_now_ns() - start);
    return XAIOS_OK;
  }

  ++g_tcp_reset_count;
  net_packet_mark_dropped(packet);
  return XAIOS_ERR_INVALID;
}

xaios_status_t network_stack_process_udp_frame_v6(const uint8_t *frame,
                                                  uint64_t frame_len) {
  if (frame == 0 || frame_len < 62U) {
    net_udp_note_dropped();
    net_udp_note_malformed();
    net_note_packet_drop();
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
    net_udp_note_dropped();
    net_udp_note_malformed();
    net_note_packet_drop();
    return XAIOS_ERR_INVALID;
  }
  if (src_port == 0 || dst_port == 0 || payload_len == 0) {
    net_udp_note_dropped();
    net_note_packet_drop();
    return XAIOS_ERR_INVALID;
  }

  network_udp_flow_t existing_row;
  int have_existing = net_udp_flow_find_v6(dst_port, src_port, &dst_addr,
                                           &src_addr, &existing_row);
  network_queue_binding_t binding;
  int have_binding =
      have_existing != 0
          ? net_queue_binding_find(existing_row.queue_id, &binding)
          : net_queue_binding_select(dst_port, src_port,
                                     xaios_ip_addr_hash(&dst_addr),
                                     xaios_ip_addr_hash(&src_addr), &binding);
  if (have_binding == 0) {
    net_udp_note_dropped();
    net_note_packet_drop();
    return XAIOS_ERR_NOT_FOUND;
  }

  /* The legacy IPv4 projections the old code copied out of the packet
     descriptor: 0 for a v6 packet, exactly the value the descriptor held. */
  uint32_t legacy_src_address = 0U;
  uint32_t legacy_dst_address = 0U;
  if (src_addr.family == XAIOS_IP_FAMILY_V4) {
    legacy_src_address = xaios_ip_addr_to_ipv4(&src_addr);
    legacy_dst_address = xaios_ip_addr_to_ipv4(&dst_addr);
  }

  uint32_t packet =
      net_packet_alloc(binding.queue_id, frame_len, start, src_port, dst_port,
                       legacy_src_address, legacy_dst_address, &src_addr,
                       &dst_addr);
  if (packet == 0) {
    net_udp_note_dropped();
    return XAIOS_ERR_NO_MEMORY;
  }

  network_udp_flow_t flow_row;
  uint32_t flow_index = 0U;
  if (!net_udp_flow_alloc(binding.queue_id, binding.cell_id, dst_port, src_port,
                          legacy_dst_address, legacy_src_address, &dst_addr,
                          &src_addr, start, &flow_row, &flow_index)) {
    net_udp_note_dropped();
    net_packet_mark_dropped(packet);
    return XAIOS_ERR_NO_MEMORY;
  }
  /* The IPv6 address fields are set by net_udp_flow_alloc(), before the
     queue/core mismatch test below, exactly where the old handler wrote them
     onto the table row. */
  if (flow_row.queue_id != binding.queue_id ||
      flow_row.cell_id != binding.cell_id) {
    ++g_flow_core_mismatch_count;
    net_packet_mark_dropped(packet);
    return XAIOS_ERR_BUSY;
  }
  ++flow_row.packets_rx;
  net_udp_note_rx();
  ++g_ipv6_rx_count;
  for (uint32_t i = 0; i < 6U; ++i) {
    flow_row.remote_mac[i] = frame[6U + i];
  }
  flow_row.remote_mac_valid = 1;
  net_udp_flow_commit(flow_index, &flow_row);
  
  /* Deliver UDP payload to flow rx_buf */
  if (flow_row.rx_buf != 0 && payload_len > 8) {
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
          data_len > sockbuf_available(flow_row.rx_buf) ||
          sockbuf_write(flow_row.rx_buf, udp_payload, data_len) != data_len ||
          !udp_listener_enqueue(dst_port, flow_row.flow_id, src_port, &src_addr,
                                (uint16_t)data_len)) {
        listener_unlock();
        net_udp_note_dropped();
        net_packet_mark_dropped(packet);
        return XAIOS_ERR_BUSY;
      }
    }
    listener_unlock();
  }
  
  net_packet_mark_tx(packet);
  ++flow_row.packets_tx;
  net_udp_note_tx();
  net_udp_flow_commit(flow_index, &flow_row);
  net_packet_mark_complete(packet);
  net_udp_record_latency(timer_now_ns() - start);
  return XAIOS_OK;
}

xaios_status_t network_stack_process_tcp_frame_v6(const uint8_t *frame,
                                                  uint64_t frame_len) {
  if (frame == 0 || frame_len < 74U) { /* 14 + 40 + 20 minimum */
    ++g_tcp_reset_count;
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
    ++g_tcp_reset_count;
    net_note_packet_drop();
    return XAIOS_ERR_INVALID;
  }
  if (src_port == 0U || dst_port == 0U) {
    ++g_tcp_reset_count;
    net_note_packet_drop();
    return XAIOS_ERR_INVALID;
  }

  const uint8_t *parsed_tcp_header = frame + 14U + XAIOS_IPV6_HEADER_SIZE;
  uint16_t peer_window_raw = net_wire_read_u16_be(parsed_tcp_header + 14U);

  network_tcp_flow_t *flow =
      find_flow_by_ports_v6(dst_port, src_port, &src_addr);
  network_queue_binding_t binding;
  int have_binding =
      flow != 0
          ? net_queue_binding_find(flow->queue_id, &binding)
          : net_queue_binding_select(dst_port, src_port,
                                     xaios_ip_addr_hash(&dst_addr),
                                     xaios_ip_addr_hash(&src_addr), &binding);
  if (have_binding == 0) {
    ++g_tcp_reset_count;
    net_note_packet_drop();
    return XAIOS_ERR_NOT_FOUND;
  }

  uint32_t packet =
      net_packet_alloc(binding.queue_id, frame_len, start, src_port, dst_port,
                       0, 0, &src_addr, &dst_addr);
  if (packet == 0) {
    ++g_tcp_reset_count;
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
    if (g_half_open_count > 0U) --g_half_open_count;
    ++flow->packets_rx;
    ++g_tcp_handshake_count;
    ++g_tcp_established_count;
    ++g_ipv6_rx_count;
    net_packet_mark_tx(packet);
    net_packet_mark_complete(packet);
    record_latency(g_tcp_latency_samples, &g_tcp_latency_count,
                   timer_now_ns() - start);
    return XAIOS_OK;
  }

  if ((flags & NETWORK_TCP_FLAG_RST) != 0U) {
    if (flow != 0) {
      if (seq != flow->expected_seq) {
        net_packet_mark_dropped(packet);
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
      ++g_tcp_reset_count;
      net_packet_mark_dropped(packet);
      return XAIOS_ERR_NOT_FOUND;
    }
    flow = alloc_tcp_flow(dst_port, src_port, 0, &src_addr);
    if (flow == 0) {
      ++g_tcp_reset_count;
      net_packet_mark_dropped(packet);
      return XAIOS_ERR_NO_MEMORY;
    }
    flow->flow_id = (uint32_t)(g_next_flow_id++);
    if (flow->flow_id == 0U) {
      flow->flow_id = 1U;
      g_next_flow_id = 2U;
    }
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
      if (g_half_open_count > 0U) --g_half_open_count;
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
    ++g_tcp_handshake_count;
    ++g_ipv6_rx_count;
    net_packet_mark_tx(packet);
    net_packet_mark_complete(packet);
    record_latency(g_tcp_latency_samples, &g_tcp_latency_count,
                  timer_now_ns() - start);
    return XAIOS_OK;
  }

  if (flow != 0 && flow->state == XAIOS_NETWORK_FLOW_SYN_RECV &&
      (flags & NETWORK_TCP_FLAG_ACK) != 0U) {
    if (ack_v != flow->next_send_seq || seq != flow->expected_seq) {
      net_packet_mark_dropped(packet);
      return XAIOS_ERR_INVALID;
    }
    if (g_half_open_count > 0U) --g_half_open_count;
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
    ++g_tcp_handshake_count;
    ++g_tcp_established_count;
    net_packet_mark_tx(packet);
    net_packet_mark_complete(packet);
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

    net_packet_mark_tx(packet);
    net_packet_mark_complete(packet);
    record_latency(g_tcp_latency_samples, &g_tcp_latency_count,
                  timer_now_ns() - start);
    return XAIOS_OK;
  }

  ++g_tcp_reset_count;
  net_packet_mark_dropped(packet);
  return XAIOS_ERR_INVALID;
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
      net_note_packet_drop();
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

/* The UDP counter and latency accessors moved to network_stack_udp.c with the
   state they read; the queue and packet counter accessors moved to
   network_stack_packet.c. */

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

uint64_t network_stack_flow_core_mismatch_count(void) {
  return g_flow_core_mismatch_count;
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

void net_stack_tcp_sliding_window_self_test(void) {
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
  net_udp_clear_active();
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
