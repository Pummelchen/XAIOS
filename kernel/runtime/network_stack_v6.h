/*
 * The IPv6 address state and the router-advertisement path: the link-local
 * address, the address derived from a router advertisement (SLAAC), the
 * address leased by DHCPv6, the default router and the on-link prefix.
 *
 * This is the second cut out of network_stack.c, after the stateless wire
 * helpers and the listener registry. The note at the top of that file named
 * two candidates -- this address path and the IPv4/IPv6 receive dispatch --
 * and this one needs the fewer accessors by a wide margin. The dispatch is
 * interleaved with the poll tail and reaches both flow tables, the packet
 * descriptors, the queue rings and the ping state; this path is ten
 * address-and-timer objects, mutated by exactly the code that moved here.
 *
 * Row-copying was the listener module's answer to a shared table. Here the
 * shared state is a handful of scalars and one 16-byte address, so the answer
 * is the same in miniature: every accessor copies a value into a caller-owned
 * local and none hands back a pointer into the file-scope state. The two
 * functions that used to return `const xaios_ip_addr_t *` -- the answering
 * address and the next hop -- now write that copy, which is what their
 * callers did with the pointer anyway, and which a concurrent router
 * advertisement can no longer pull out from under them.
 *
 * Locking. The stack's guard is g_network_guard, held through
 * network_stack_lock()/network_stack_unlock(). Nothing below takes a lock of
 * its own: each accessor replaces a direct read or write, so it neither
 * widens nor narrows any critical section. net_v6_apply_router_advertisement()
 * and net_v6_init() ran without the guard and still do; net_v6_adopt_dhcpv6()
 * is called with the guard already held, by the public entry point that took
 * it before. Splitting or resizing any of those sections would turn atomic
 * work into lost updates.
 */

#ifndef XAIOS_KERNEL_RUNTIME_NETWORK_STACK_V6_H
#define XAIOS_KERNEL_RUNTIME_NETWORK_STACK_V6_H

#include <xaios/ip_addr.h>

/* ---- reads and writes the rest of the stack makes ---- */

/* Initialise from the interface MAC: derive the link-local address and clear
   the addresses a router or a lease has yet to supply. */
void net_v6_init(const uint8_t mac[6]);

/* Copy the link-local address out. */
void net_v6_link_local(xaios_ip_addr_t *out);

/* The address a new IPv6 flow should be sent from, given its peer: the
   link-local address for a link-local peer, the SLAAC address when one is
   live, and otherwise one derived from the peer's own prefix. */
void net_v6_flow_local_address(const xaios_ip_addr_t *remote_addr,
                               const uint8_t mac[6], xaios_ip_addr_t *out);

/* The address to answer `wanted` from. Returns 1 when `wanted` is one of ours
   and 0 when it is not, in which case the link-local address is copied. */
int net_v6_source_for(const xaios_ip_addr_t *wanted, xaios_ip_addr_t *out);

/* The first hop a frame to `destination` belongs to: itself when on-link, the
   default router otherwise. Returns 0 and writes nothing for a null
   destination. */
int net_v6_next_hop(const xaios_ip_addr_t *destination, uint64_t now_ns,
                    xaios_ip_addr_t *out);

/* The address this host sends IPv6 from: the live SLAAC address when there is
   one, the link-local address otherwise. */
void net_v6_local_address(xaios_ip_addr_t *out, uint64_t now_ns);

/* Whether a router advertisement has configured a prefix at all, live or not.
   This is the raw flag the wait loop tests, not an expiry check. */
int net_v6_slaac_configured(void);

/* The live public address. Returns 0 and writes nothing when there is none. */
int net_v6_public_address(xaios_ip_addr_t *out, uint64_t now_ns);

/* Raw public-address state, for the boot self-test that asserts the timer. */
void net_v6_public_read(xaios_ip_addr_t *out, uint64_t *valid_until_ns);

/* Zero the public address, the way the self-test resets it between cases. */
void net_v6_reset_public(void);

/* Drop the public address once its lifetime has run out. */
void net_v6_expire_public(uint64_t now_ns);

/* Install a DHCPv6 lease. Called with the stack guard held. */
void net_v6_adopt_dhcpv6(const xaios_ip_addr_t *address,
                         uint64_t valid_until_ns);

/* Apply a router advertisement: the default router, and any prefix that
   configures an address. Called with the stack guard held where the receive
   path held it, and without it from the boot self-test, exactly as before. */
void net_v6_apply_router_advertisement(const uint8_t *frame, uint32_t frame_len,
                                       uint64_t now_ns, const uint8_t mac[6]);

/* ---- predicates ---- */

int net_v6_is_global_unicast(const xaios_ip_addr_t *address);

#endif /* XAIOS_KERNEL_RUNTIME_NETWORK_STACK_V6_H */
