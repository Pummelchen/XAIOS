/*
 * The IPv4/IPv6 network stack: the TCP flow table and the entry points that
 * walk it.
 *
 * This file was 1849 lines. It has been cut fifteen ways before this one, and
 * the note that used to stand here named what was left: the TCP flow table,
 * its allocation, the connection lifecycle that walks it and the TCP frame
 * handlers. The frame handlers were the hard part. They hold a live pointer
 * into the flow table across hundreds of lines, and a network_tcp_flow_t row
 * is about 17 KB against a 16 KB secondary stack, so neither a row copy per
 * receive nor the copy-out/copy-in cursor the listener and UDP tables use was
 * available: both would put a 17 KB copy on the receive stack.
 *
 * The cut that landed keeps the table here and moves everything that walks it
 * behind a caller-owned table pointer. Each moved function takes
 * `network_tcp_flow_t *flows` from this file, indexes it in place and returns
 * a pointer into the caller's table -- the same "the caller already owns the
 * row" discipline network_stack_tcp_flow.c already used. No frame path copies
 * a row. What crosses back is a small amount of scalar state, behind helpers:
 *
 *   half-open count      net_tcp_half_open_count/acquire/release
 *   drain cursor         net_tcp_drain_cursor_take
 *   flow-id counter      the existing net_stack_alloc_flow_id()
 *   interface MAC        the existing net_stack_local_mac()
 *   IPv6 receive count   the existing net_stack_note_ipv6_rx()
 *
 * The table itself, the two zeroing seeds the boot lifecycle calls, the
 * copy-out sequence accessor the app and self-test modules call, the remaining
 * counters and the public wrappers stay here, beside the state they own.
 *
 * The layout, for navigation:
 *
 *   shared state, guard, helpers    the table and the scalars left behind
 *   TCP seeds and sequence read     called by the moved boot/self-test code
 *   TCP table helpers              moved to network_stack_tcp_table.c
 *   TCP timers                     moved to network_stack_tcp_timers.c
 *   pending-transmit drain         moved to network_stack_tcp_drain.c
 *   connection API, socket ready   moved to network_stack_tcp_api.c
 *   TCP frame handler, IPv4        moved to network_stack_tcp_frame.c
 *   TCP frame handler, IPv6        moved to network_stack_tcp_frame_v6.c
 *   every other layer              moved by the fifteen earlier cuts
 *   public API                     the wrappers a syscall or poll reaches
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

/* Janeway — “Break off your pursuit or we'll open fire.” */

static uint64_t g_next_flow_id = 1U;
static network_tcp_flow_t g_tcp_flows[NETWORK_TCP_CONNECTIONS];

/* The one flow-id counter the UDP and TCP tables share. The moved frame
   handlers and the moved connection API call this; the TCP allocations used to
   take the counter directly, and network_stack_alloc_flow_id() is the exact
   `++` with the wrap they wrote. Caller holds the guard. */
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

/* The resolver lives inside this stack and must share its guard; see the
   declaration in network_stack.h. */
void network_stack_lock(void) { network_lock(); }
void network_stack_unlock(void) { network_unlock(); }

static uint32_t g_half_open_count = 0;

/* The half-open ceiling the moved allocation and expiry code applies, kept
   beside the counter they used to read directly. Caller holds the guard; each
   is the plain read, `++` or guarded `--` the moved code wrote in place, so no
   critical section changes shape. Declared in network_stack_tcp_table.h. */
uint32_t net_tcp_half_open_count(void) { return g_half_open_count; }

void net_tcp_half_open_acquire(void) { ++g_half_open_count; }

void net_tcp_half_open_release(void) {
  if (g_half_open_count > 0U) --g_half_open_count;
}

static uint8_t g_local_mac[6];

/* The moved UDP transmit path and the moved TCP open path stamp the interface
   MAC into every frame. This is the raw read they made, with no "persistent
   mode has started" test, and it is what the accessor declared in
   network_stack_udp.h and network_stack_tcp_table.h names. Caller holds the
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

/* The moved ping code cannot see the flag above, so it asks for the value.
   This is the same plain read it made in place; it is read-only, so it takes
   no lock and changes no critical section. Declared in
   network_stack_icmp.h. */
uint32_t net_stack_persistent_ready(void) { return g_persistent_initialized; }

static uint32_t g_tcp_drain_cursor;
static uint64_t g_ipv6_rx_count;

/* The drain cursor the moved pending-transmit drain advances. This is the
   cursor read and advance net_stack_tcp_drain_pending() wrote in place, in the
   same order; caller holds the guard. Declared in
   network_stack_tcp_table.h. */
uint32_t net_tcp_drain_cursor_take(void) {
  uint32_t start_index = g_tcp_drain_cursor;
  g_tcp_drain_cursor =
      (g_tcp_drain_cursor + 1U) % NETWORK_TCP_CONNECTIONS;
  return start_index;
}

/* The IPv6 receive increment the moved UDP and TCP receive handlers make.
   Caller holds the guard; this is the plain `++` it replaced. Declared in
   network_stack_udp_rx.h. */
void net_stack_note_ipv6_rx(void) { ++g_ipv6_rx_count; }

/* The TCP counters, the queue/core mismatch counter and the TCP latency
   samples live in network_stack_tcp_stats.c; the IPv6 address state, the
   listener registry, the queue bindings, the packet pool and the UDP table and
   receive plane live in their own modules. The TCP flow plane that walks the
   table below lives in network_stack_tcp_table.c, network_stack_tcp_timers.c,
   network_stack_tcp_drain.c, network_stack_tcp_api.c and the two frame
   modules, all reached through network_stack_tcp_table.h. */

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

/* The seeds the moved lifecycle module (network_stack_lifecycle.c) calls into:
   the TCP flow table's two zeroing loops and the five scalars around it. They
   stay with the state they touch, so the moved boot code never names
   g_tcp_flows, g_next_flow_id, g_tcp_drain_cursor, g_half_open_count,
   g_ipv6_rx_count or g_persistent_initialized. Each replaces a direct write
   that ran single-threaded at boot, at the same point and in the same order;
   none of them takes a lock, exactly as before. Declared in
   network_stack_lifecycle.h. */

void net_tcp_table_init(void) {
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
}

void net_tcp_table_clear_active(void) {
  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    g_tcp_flows[i].state = XAIOS_NETWORK_FLOW_FREE;
    g_tcp_flows[i].flow_id = 0;
    g_tcp_flows[i].rx_buf = 0;
    g_tcp_flows[i].tx_buf = 0;
    g_tcp_flows[i].pending_synack = 0;
    g_tcp_flows[i].pending_ack = 0;
    g_tcp_flows[i].pending_fin = 0;
  }
}

void net_stack_flow_id_reset(void) { g_next_flow_id = 1U; }

void net_tcp_drain_cursor_reset(void) { g_tcp_drain_cursor = 0U; }

void net_tcp_half_open_reset(void) { g_half_open_count = 0; }

void net_stack_reset_ipv6_rx(void) { g_ipv6_rx_count = 0; }

void net_stack_mark_persistent_ready(void) { g_persistent_initialized = 1; }

/* ---- public entry points ----
   Each keeps the signature and the guard shape the callers already had; the
   body is the moved implementation with this file's table handed to it. */

xaios_status_t network_stack_tcp_open(const xaios_ip_addr_t *remote_addr,
                                      uint16_t remote_port,
                                      uint16_t local_port,
                                      uint32_t *out_flow_id) {
  network_lock();
  xaios_status_t result = net_tcp_api_open(g_tcp_flows, remote_addr, remote_port, local_port, out_flow_id);
  network_unlock();
  return result;
}

xaios_status_t network_stack_tcp_open_status(uint32_t flow_id) {
  network_lock();
  xaios_status_t result = net_tcp_api_open_status(g_tcp_flows, flow_id);
  network_unlock();
  return result;
}

xaios_status_t network_stack_tcp_abort_flow(uint32_t flow_id) {
  network_lock();
  xaios_status_t result = net_tcp_api_abort_flow(g_tcp_flows, flow_id);
  network_unlock();
  return result;
}

xaios_status_t network_stack_tcp_send(uint32_t flow_id, const uint8_t *data,
                                       uint32_t len, uint32_t *bytes_written) {
  network_lock();
  xaios_status_t result = net_tcp_api_send(g_tcp_flows, flow_id, data, len, bytes_written);
  network_unlock();
  return result;
}

xaios_status_t network_stack_tcp_close_flow(uint32_t flow_id) {
  network_lock();
  xaios_status_t result = net_tcp_api_close_flow(g_tcp_flows, flow_id);
  network_unlock();
  return result;
}

uint32_t network_stack_tcp_recv(uint32_t flow_id, uint8_t *buffer,
                                  uint32_t buffer_size) {
  network_lock();
  uint32_t result = net_tcp_api_recv(g_tcp_flows, flow_id, buffer, buffer_size);
  network_unlock();
  return result;
}

int network_stack_tcp_peer_closed(uint32_t flow_id) {
  network_lock();
  int result = net_tcp_api_peer_closed(g_tcp_flows, flow_id);
  network_unlock();
  return result;
}

int network_stack_socket_ready(uint64_t sockfd, uint8_t protocol,
                               uint16_t port, uint32_t listening) {
  return net_tcp_api_socket_ready(g_tcp_flows, sockfd, protocol, port,
                                  listening);
}

xaios_status_t network_stack_process_tcp_frame(const uint8_t *frame,
                                            uint64_t frame_len) {
  return net_tcp_frame_process_v4(g_tcp_flows, frame, frame_len);
}

xaios_status_t network_stack_process_tcp_frame_v6(const uint8_t *frame,
                                                  uint64_t frame_len) {
  return net_tcp_frame_process_v6(g_tcp_flows, frame, frame_len);
}

uint64_t network_stack_retransmit_tcp_flows(uint64_t now_ns) {
  return net_tcp_table_retransmit(g_tcp_flows, now_ns);
}

uint64_t network_stack_expire_tcp_flows(uint64_t now_ns) {
  return net_tcp_table_expire(g_tcp_flows, now_ns);
}

void net_stack_tcp_drain_pending(void) { net_tcp_drain_pending(g_tcp_flows); }

uint64_t network_stack_tcp_connections(void) {
  return net_tcp_table_connections(g_tcp_flows);
}

/* The TCP and mismatch counter accessors, the latency percentiles and the
   sliding-window self-check live in network_stack_tcp_stats.c with the
   counters and samples they read; the self-check followed the retransmit
   counter it saves and restores. Declared in network_stack.h and, for the
   self-check, network_stack_selftest.h. */

/* network_stack_init() and network_init_persistent() live in
   network_stack_lifecycle.c; the local-address accessors live in
   network_stack_local.c; the receive dispatch, its fragment reassembly and
   the poll-gap accounting live in network_stack_poll.c. */

uint64_t network_ipv6_rx_count(void) {
  return g_ipv6_rx_count;
}
