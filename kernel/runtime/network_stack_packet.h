/*
 * The queue-binding registry and the receive packet-descriptor pool, now their
 * own translation unit.
 *
 * This is the pair network_stack.c's own note named as remaining candidates:
 * the queue/packet-descriptor pool beside the UDP data plane. They go
 * together because they are one mechanism. A binding fixes which receive queue
 * an inbound frame is steered to; the packet descriptor records that frame;
 * the queue ring is the depth accounting both update; and none of the three is
 * touched by anything that does not touch the other two.
 *
 * The interface keeps the cursor-plus-commit shape the listener module
 * established, with one addition the descriptor needs. A binding is read out
 * into a caller-owned row -- never a pointer into the table -- because a
 * concurrent release could clear a row between a lookup and a dereference. A
 * packet descriptor is a *lease*: net_packet_alloc() hands back a 1-based
 * index, not a pointer, and the caller fixes the whole tuple at allocation
 * time. It releases the lease by calling exactly one of net_packet_mark_tx()
 * + net_packet_mark_complete() or net_packet_mark_dropped() before it
 * returns. Because the tuple is fixed at allocation, no caller ever holds a
 * pointer into the pool, and the failure value 0 is the same value
 * alloc_packet_desc() used to return, so every `packet == 0` test in the code
 * that stayed reads unchanged.
 *
 * Locking. The stack's guard is g_network_guard, held through
 * network_stack_lock()/network_stack_unlock(). Every function below is
 * lock-free on purpose: the caller must already hold that guard, and taking a
 * second lock, in a different order, or widening any critical section would
 * each be a bug rather than a detail. The two counter notes and
 * net_packet_reset() replace direct writes the old code made in place, so they
 * neither widen nor narrow a section. net_packet_reset() is called from
 * network_stack_init() where the tables were zeroed before the guard existed,
 * and keeps that call site; it takes no lock of its own.
 */

#ifndef XAIOS_KERNEL_RUNTIME_NETWORK_STACK_PACKET_H
#define XAIOS_KERNEL_RUNTIME_NETWORK_STACK_PACKET_H

#include <xaios/ip_addr.h>
#include <xaios/network_stack.h>

/* The binding row as the rest of the stack sees it. The queue rings and the
   packet descriptors are private to network_stack_packet.c: nothing outside
   wants either, only the binding a frame is steered to and the lease it is
   recorded in. */
typedef struct network_queue_binding {
  uint32_t queue_id;
  uint32_t cell_id;
  uint32_t core_mask;
  uint32_t in_use;
} network_queue_binding_t;

/* ---- binding rows (caller holds the stack guard) ---- */

/* Copy the live row bound to `queue_id` out; returns 0 and writes nothing when
   there is none. */
int net_queue_binding_find(uint32_t queue_id, network_queue_binding_t *out);

/* The binding a new flow is steered to by its four-tuple hash; same copy-out
   contract as net_queue_binding_find, returns 0 when the machine has no
   binding at all. */
int net_queue_binding_select(uint16_t local_port, uint16_t remote_port,
                             uint32_t local_address, uint32_t remote_address,
                             network_queue_binding_t *out);

/* ---- packet descriptors (caller holds the stack guard) ---- */

/* Start a receive lease on `queue_id`, fixing the ports and addresses so no
   caller ever needs a pointer into the pool. Both `src_addr` and `dst_addr`
   may be null: the IPv4 callers pass plain addresses and null pointers, the
   IPv6 callers pass the full addresses (and their IPv4 projections, or 0 for a
   v6 packet). Returns a 1-based lease index, or 0 when the binding is missing,
   the length is impossible, or the ring is full -- the same refusals and the
   same drop accounting as before. The caller must release the lease before
   returning. */
uint32_t net_packet_alloc(uint32_t queue_id, uint64_t length, uint64_t now_ns,
                          uint16_t src_port, uint16_t dst_port,
                          uint32_t src_address, uint32_t dst_address,
                          const xaios_ip_addr_t *src_addr,
                          const xaios_ip_addr_t *dst_addr);

/* Move a lease to the transmit ring and count it; on backpressure it is
   dropped instead, which is what packet_mark_tx() did. */
void net_packet_mark_tx(uint32_t packet);
/* Complete a transmitted lease. */
void net_packet_mark_complete(uint32_t packet);
/* Release a lease from any state, counting the drop. Safe on 0. */
void net_packet_mark_dropped(uint32_t packet);

/* ---- counters owned by network_stack_packet.c ----
   The rest of the stack bumps these through the two notes rather than owning
   the counters. Caller holds the guard; each is the plain `++` it replaced. */

void net_note_packet_drop(void);

/* ---- lifecycle ---- */

/* Zero the bindings, the queue rings, the descriptors and the counters the
   pool owns. Called from network_stack_init(). */
void net_packet_reset(void);

#endif /* XAIOS_KERNEL_RUNTIME_NETWORK_STACK_PACKET_H */
