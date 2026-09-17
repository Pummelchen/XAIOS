/*
 * The declarations that join the UDP receive plane in network_stack_udp_rx.c
 * to the counters network_stack.c still owns beside the rest of the stack's
 * state.
 *
 * The receive handlers and the receive call moved whole: they only ever
 * wanted a copied-out flow row (network_stack_udp.h), a copied-out listener
 * row (network_stack_listener.h) and a packet lease (network_stack_packet.h),
 * so no table crosses with them. The two counters they write -- the queue/core
 * mismatch count and the IPv6 receive count -- were never state they owned;
 * they sit with the TCP counters in network_stack.c, so the moved code writes
 * them through the two plain increments below, which are exactly the `++` the
 * old code made in place.
 *
 * Caller holds the stack guard for both, as it did for the increments. Neither
 * takes a lock of its own, so no critical section changes shape.
 */

#ifndef XAIOS_KERNEL_RUNTIME_NETWORK_STACK_UDP_RX_H
#define XAIOS_KERNEL_RUNTIME_NETWORK_STACK_UDP_RX_H

/* ---- counters owned by network_stack.c ---- */

void net_stack_note_flow_core_mismatch(void);
void net_stack_note_ipv6_rx(void);

#endif /* XAIOS_KERNEL_RUNTIME_NETWORK_STACK_UDP_RX_H */
