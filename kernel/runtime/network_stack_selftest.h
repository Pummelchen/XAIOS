/*
 * The boot-time network self-test, moved out of network_stack.c: the latency
 * snapshot, the listener-pool capacity check and network_stack_self_test().
 *
 * The test drives the stack through its exported entry points and owns no
 * state. Three things it cannot reach without a pointer into
 * network_stack.c's own state are lent from there, and declared below: the
 * local MAC it overwrites for the router-advertisement case
 * (net_stack_local_mac_set()), the TCP sliding-window check that asserts on
 * the retransmit counter beside the rest of the counters
 * (net_stack_tcp_sliding_window_self_test(), which stayed in network_stack.c
 * for exactly that reason), and network_stack_app.h's flow-sequence accessor.
 *
 * It runs single-threaded from kmain before any service starts; the moved code
 * took no lock and takes none now, so no critical section changes shape.
 */

#ifndef XAIOS_KERNEL_RUNTIME_NETWORK_STACK_SELFTEST_H
#define XAIOS_KERNEL_RUNTIME_NETWORK_STACK_SELFTEST_H

#include <xaios/network_stack.h>

#include "network_stack_app.h"

/* How long a half-open handshake may sit before it is expired.
   network_stack.c uses it in network_stack_expire_tcp_flows() and this test
   advances the clock past it. It was defined in network_stack.c and is defined
   here now so both halves share one definition. */
#define NETWORK_TCP_SYN_TIMEOUT_NS UINT64_C(10000000000)

/* Overwrite the interface MAC this file cannot see. Defined in
   network_stack.c, which owns g_local_mac; the value is copied in. The test
   saves the old value with the existing net_stack_local_mac() read (declared
   in network_stack_udp.h) and restores it through this call. */
void net_stack_local_mac_set(const uint8_t mac[6]);

/* The TCP sliding-window self-check. It saves, restores and asserts on
   g_tcp_retransmit_count, which network_stack.c owns, so it stayed there;
   the boot self-test calls it through this declaration. */
void net_stack_tcp_sliding_window_self_test(void);

#endif /* XAIOS_KERNEL_RUNTIME_NETWORK_STACK_SELFTEST_H */
