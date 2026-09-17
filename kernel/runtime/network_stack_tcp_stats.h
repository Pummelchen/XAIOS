/*
 * The TCP counters, the TCP latency samples and the sliding-window self-check,
 * moved out of network_stack.c.
 *
 * The counters were the last thing pinning the sliding-window self-test to
 * network_stack.c: it saves, restores and asserts on the retransmit counter, so
 * where that counter went the test follows. The UDP counters and samples live
 * with the UDP data plane in network_stack_udp.c; the queue and packet counters
 * live with the pool in network_stack_packet.c; these are the TCP ones, plus
 * the queue/core mismatch counter the UDP receive handlers bump, which had
 * nowhere else to be.
 *
 * The two increments the TCP flow module already calls, net_tcp_note_closed()
 * and net_tcp_note_retransmit(), are declared in network_stack_tcp.h and are
 * defined here now; net_stack_note_flow_core_mismatch() keeps its declaration
 * in network_stack_udp_rx.h and is defined here for the same reason.
 *
 * Locking. The stack's guard is g_network_guard, held through
 * network_stack_lock()/network_stack_unlock(). Every note and accessor below is
 * lock-free on purpose: the caller must already hold that guard, exactly as the
 * plain `++` and the plain read each replaces did. No critical section is
 * widened, narrowed or split. net_tcp_stats_reset() is called from
 * network_stack_init(), which ran before the guard was needed and still does.
 */

#ifndef XAIOS_KERNEL_RUNTIME_NETWORK_STACK_TCP_STATS_H
#define XAIOS_KERNEL_RUNTIME_NETWORK_STACK_TCP_STATS_H

#include <xaios/types.h>

/* ---- the increments the code that stayed in network_stack.c makes ----
   Caller holds the guard; each is the plain `++` it replaced. */

void net_tcp_note_handshake(void);
void net_tcp_note_reset(void);
void net_tcp_note_timeout(void);
void net_tcp_note_established(void);
void net_tcp_record_latency(uint64_t value);

/* ---- lifecycle ---- */

/* Zero the six TCP counters, the queue/core mismatch counter and the latency
   samples and their count, exactly the block network_stack_init() used to run
   in the same order. */
void net_tcp_stats_reset(void);

#endif /* XAIOS_KERNEL_RUNTIME_NETWORK_STACK_TCP_STATS_H */
