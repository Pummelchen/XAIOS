/*
 * The UDP flow table and the UDP data plane, moved out of network_stack.c.
 *
 * This is the cut network_stack.c's own note named first: "the UDP data plane
 * (works on a caller-owned flow row, like the TCP one did)". The TCP data
 * plane crossed with no table accessor because every function took the flow
 * row from the caller that already owned it. The UDP table is different from
 * the TCP one in exactly one way: the receive handlers that stayed behind --
 * network_stack_process_udp_frame() and its IPv6 twin -- also mutate a row, so
 * the table needs a cursor plus a commit rather than a plain copy-out. That is
 * the shape the listener module established and this header keeps it:
 *
 *   net_udp_flow_find_v4()/find_v6()   read a row into a caller-owned local
 *   net_udp_flow_alloc()               create or find, then read the row out
 *   net_udp_flow_commit()              write a caller-owned row back
 *
 * Nothing below hands back a pointer into g_udp_flows. The index the find and
 * alloc calls report is an index into the table, not a pointer, and it is
 * stable only while the caller holds the guard -- which is the whole contract.
 *
 * The receive handlers that stayed in network_stack.c also bump the UDP
 * counters and append to the UDP latency samples, so those six counters, the
 * samples and the two `record_latency` increments are owned here and reached
 * through the small notes below. The TCP counters and the TCP latency samples
 * stay where they were.
 *
 * Locking. The stack's guard is g_network_guard, held through
 * network_stack_lock()/network_stack_unlock(); the old file reached the same
 * two functions through its network_lock() and listener_lock() aliases, which
 * is what the moved code calls now. Every accessor here is lock-free on
 * purpose: the caller must already hold that guard. The exported entry points
 * take it themselves exactly where the functions they replace took it, so no
 * critical section is widened, narrowed or split. The unlocked variants are
 * called with the guard already held and keep taking it again through the
 * reentrant lock, exactly as before.
 */

#ifndef XAIOS_KERNEL_RUNTIME_NETWORK_STACK_UDP_H
#define XAIOS_KERNEL_RUNTIME_NETWORK_STACK_UDP_H

#include <xaios/ip_addr.h>
#include <xaios/network_stack.h>

#include "network_stack_tcp.h"

/* How long an idle flow lives. Defined here rather than in
   network_stack_udp.c because the boot self-test in network_stack.c advances
   the clock past it to expire a flow. */
#define NETWORK_UDP_IDLE_TIMEOUT_NS UINT64_C(30000000000)

/* ---- flow-id allocation, owned by network_stack.c ----
   The UDP and TCP flow tables draw from one counter, so the counter stays in
   network_stack.c and this is the increment the UDP table makes. Caller holds
   the guard. */
uint32_t net_stack_alloc_flow_id(void);

/* ---- the raw interface MAC, owned by network_stack.c ----
   The UDP transmit path stamps it into every frame. Caller holds the guard;
   unlike network_stack_local_mac() this has no "persistent mode has started"
   test, because the moved code read the array directly. */
void net_stack_local_mac(uint8_t out[6]);

/* ---- flow rows (caller holds the stack guard) ---- */

/* Copy a live flow matching the four-tuple out. Returns 0 and writes nothing
   when there is none. */
int net_udp_flow_find_v4(uint16_t local_port, uint16_t remote_port,
                         uint32_t local_address, uint32_t remote_address,
                         network_udp_flow_t *out);
int net_udp_flow_find_v6(uint16_t local_port, uint16_t remote_port,
                         const xaios_ip_addr_t *local_addr,
                         const xaios_ip_addr_t *remote_addr,
                         network_udp_flow_t *out);

/* Find the flow for the four-tuple or allocate one, exactly as
   alloc_udp_flow() did: a hit refreshes last_seen_ns and counts the hit, a
   miss takes a free row. `local_addr`/`remote_addr` are the full IPv6
   addresses when the caller has them -- the old v6 handler wrote them into the
   row immediately after allocation, before its queue/core mismatch test, so
   they are set here to keep that row state identical. Pass null for an IPv4
   flow. Returns 1 with the row copied out and `out_index` set, or 0 when the
   table is full or the receive buffer cannot be allocated. */
int net_udp_flow_alloc(uint32_t queue_id, uint32_t cell_id,
                       uint16_t local_port, uint16_t remote_port,
                       uint32_t local_address, uint32_t remote_address,
                       const xaios_ip_addr_t *local_addr,
                       const xaios_ip_addr_t *remote_addr, uint64_t now_ns,
                       network_udp_flow_t *out, uint32_t *out_index);

/* Write a caller-owned row back into the slot `index` names. */
void net_udp_flow_commit(uint32_t index, const network_udp_flow_t *row);

/* Copy a live flow out by its flow id; returns 0 and writes nothing when there
   is none. The receive syscall in network_stack.c reads a flow's rx_buf
   through this, which is why the flow table stayed here. */
int net_udp_flow_find_by_id(uint32_t flow_id, network_udp_flow_t *out);

/* ---- counters and latency samples owned here ----
   Caller holds the guard; each is the plain `++` the moved code made. */
void net_udp_note_rx(void);
void net_udp_note_tx(void);
void net_udp_note_dropped(void);
void net_udp_note_malformed(void);
void net_udp_record_latency(uint64_t value);

/* ---- lifecycle ---- */

/* Zero the flow table, the UDP counters and the UDP latency samples, the way
   network_stack_init() used to. */
void net_udp_reset(void);

/* Clear the active flags the way network_init_persistent() used to: active,
   flow_id and rx_buf only. */
void net_udp_clear_active(void);

#endif /* XAIOS_KERNEL_RUNTIME_NETWORK_STACK_UDP_H */
