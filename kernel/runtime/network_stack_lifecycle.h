/*
 * The stack lifecycle -- network_stack_init() and network_init_persistent() --
 * and the readiness generation, moved out of network_stack.c.
 *
 * These two entry points were the last pieces of boot orchestration in
 * network_stack.c. Everything they reset had already been moved behind an
 * accessor by the modules that own it (the packet pool, the UDP table, the
 * poll-gap accounting, the IPv6 address state, the boot self-test); what
 * remained were direct writes into network_stack.c's own state. Those stay
 * behind the seeds declared below, so the moved code never names g_tcp_flows,
 * g_next_flow_id, g_tcp_drain_cursor, g_half_open_count, g_ipv6_rx_count or
 * g_persistent_initialized. The one exception is the interface MAC: the
 * existing net_stack_local_mac()/net_stack_local_mac_set() pair (declared in
 * network_stack_udp.h and network_stack_selftest.h) already copies it in and
 * out, and the moved code reads it into a caller-owned local exactly as the
 * boot self-test does.
 *
 * The readiness generation lives here with its counter because nothing else in
 * network_stack.c touched it; the poll loop and the listener registry reach it
 * through the public declarations in network_stack.h.
 *
 * Locking. Both init paths run single-threaded from kmain before any service
 * starts; they took no lock before and take none now, so no critical section
 * changes shape. The readiness counter is only ever nudged atomically, exactly
 * as before.
 */

#ifndef XAIOS_KERNEL_RUNTIME_NETWORK_STACK_LIFECYCLE_H
#define XAIOS_KERNEL_RUNTIME_NETWORK_STACK_LIFECYCLE_H

#include <xaios/types.h>

/* ---- seeds owned by network_stack.c, called by the moved boot code ----
   Caller runs single-threaded at boot, where the direct writes they replace
   ran. None of them takes a lock. */

/* Zero the TCP flow table the way network_stack_init() did. */
void net_tcp_table_init(void);

/* Clear the seven per-flow fields network_init_persistent() cleared. */
void net_tcp_table_clear_active(void);

/* Reset the shared flow-id counter, the drain cursor and the half-open count,
   each where the init paths used to write it directly. */
void net_stack_flow_id_reset(void);
void net_tcp_drain_cursor_reset(void);
void net_tcp_half_open_reset(void);

/* Zero the IPv6 receive counter, where network_init_persistent() did. */
void net_stack_reset_ipv6_rx(void);

/* Set g_persistent_initialized, where network_init_persistent() did; the read
   side is the existing net_stack_persistent_ready() in network_stack_icmp.h. */
void net_stack_mark_persistent_ready(void);

#endif /* XAIOS_KERNEL_RUNTIME_NETWORK_STACK_LIFECYCLE_H */
