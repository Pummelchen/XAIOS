/*
 * The declarations that join the link-reply/ping plane in
 * network_stack_icmp.c to network_stack.c, which owns the poll loop that
 * calls it and the "persistent mode has started" flag it tests.
 *
 * The three frame handlers take the caller's copy of the interface MAC
 * (net_stack_local_mac() in network_stack_udp.h reads it out) because
 * network_stack.c owns g_local_mac and nothing here may point into it.
 * net_icmp_handle_ipv4() returns non-zero only for the one case that made the
 * old dispatch return from the whole poll: an ICMP echo reply matching the
 * outstanding ping. Every other path returns 0 and the dispatch falls through
 * exactly as it did.
 *
 * None of these takes a lock; the poll already holds the stack guard, and the
 * public ping entry points took none before or after. net_stack_persistent_ready()
 * is the plain read the moved ping code made of g_persistent_initialized, which
 * network_stack.c still owns.
 */

#ifndef XAIOS_KERNEL_RUNTIME_NETWORK_STACK_ICMP_H
#define XAIOS_KERNEL_RUNTIME_NETWORK_STACK_ICMP_H

#include <xaios/network_stack.h>

/* ---- flag owned by network_stack.c ---- */

/* The value of g_persistent_initialized: 0 until network_init_persistent()
   has run. Read, never written, from here. */
uint32_t net_stack_persistent_ready(void);

/* ---- the receive branches, moved out of the poll dispatch ---- */

/* ARP reply and request handling; answers a request for this host's IPv4
   address. No early exit. */
void net_arp_handle_frame(const uint8_t *rx_buf, uint32_t frame_len,
                          const uint8_t local_mac[6]);

/* ICMPv4: finish an outstanding ping, or answer an echo request. Returns
   non-zero when the ping reply case made the old dispatch return from the
   whole poll; the caller must `return` then. */
int net_icmp_handle_ipv4(const uint8_t *rx_buf, uint32_t frame_len,
                         uint64_t now_ns, const uint8_t local_mac[6]);

/* ICMPv6: echo replies, neighbour advertisements, and the router
   advertisement that fills in the IPv6 address state. No early exit. */
void net_icmpv6_handle_frame(const uint8_t *rx_buf, uint32_t frame_len,
                             uint64_t now_ns, const uint8_t local_mac[6]);

/* ---- ping/link state owned here ---- */

/* Expire an unanswered ping, exactly where network_poll_tick_locked() did. */
void net_ping_expire(uint64_t now_ns);

/* Zero the four reply counters and the ping state, exactly where
   network_init_persistent() did. */
void net_icmp_reset(void);

#endif /* XAIOS_KERNEL_RUNTIME_NETWORK_STACK_ICMP_H */
