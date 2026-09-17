/*
 * The poll plane of the network stack, moved out of network_stack.c: the
 * receive dispatch with its IPv4/IPv6 fragment reassembly, the B-44 poll-gap
 * accounting that says when the stack went undriven, and the poll-tick entry
 * points and counters a syscall, a carrier CPU and the telemetry accessors
 * reach.
 *
 * The receive dispatch moved with the loop rather than being left behind. It
 * reads only things network_stack.c already lends or exports: the interface
 * MAC (net_stack_local_mac(), network_stack_udp.h), the "persistent mode has
 * started" flag (net_stack_persistent_ready(), network_stack_icmp.h), one
 * IPv6 receive counter increment (net_stack_note_ipv6_rx(),
 * network_stack_udp_rx.h), the link-reply handlers network_stack_icmp.c
 * exports, and the public frame entry points. Nothing here points into that
 * file's state, and its early `return`s still leave this whole function, so
 * the poll tail -- dns_tick, the TCP retransmit/expire calls and the drain --
 * is skipped in exactly the cases it was skipped before. Splitting the loop
 * from the tail would have changed that.
 *
 * The one thing the loop reaches that stayed with its table is the TCP drain
 * cursor. tcp_drain_pending() walks g_tcp_flows across the whole table, so it
 * remains in network_stack.c and is reached through the single declaration
 * below. Caller holds the stack guard, as it did.
 *
 * Locking. The stack's guard is g_network_guard, held through
 * network_stack_lock()/network_stack_unlock(); the old file reached the same
 * two functions through its static network_lock()/network_unlock() aliases,
 * which the moved entry point calls directly here. No critical section is
 * widened, narrowed or split. The poll-gap state moved with the accounting
 * that owns it; the two resets below replace the direct writes the two init
 * paths made, in the same order and at the same points.
 */

#ifndef XAIOS_KERNEL_RUNTIME_NETWORK_STACK_POLL_H
#define XAIOS_KERNEL_RUNTIME_NETWORK_STACK_POLL_H

/* Drain the pending TCP transmissions (SYN-ACK, data, ACK, FIN) over the flow
   table. Defined in network_stack.c, which owns g_tcp_flows; caller holds the
   stack guard. */
void net_stack_tcp_drain_pending(void);

/* ---- poll-gap state owned here ----
   These replace the direct zeroing network_stack_init() and
   network_init_persistent() did. No lock changes shape: both init paths ran
   before the guard was needed and still do. */

/* g_poll_last_ns, g_poll_gap_max_ns, g_poll_gap_outage_count and
   g_poll_gap_record_lines. Called from both init paths where those four were
   zeroed. */
void net_poll_reset_gap(void);

/* g_poll_tick_count and g_tick_poll_count, which network_init_persistent()
   zeroes in addition to the four above. Called where it did, so the order of
   the two init paths is untouched. */
void net_poll_reset_ticks(void);

#endif /* XAIOS_KERNEL_RUNTIME_NETWORK_STACK_POLL_H */
