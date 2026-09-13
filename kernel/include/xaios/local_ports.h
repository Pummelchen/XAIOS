#ifndef XAIOS_LOCAL_PORTS_H
#define XAIOS_LOCAL_PORTS_H

#include <stdint.h>

/*
 * Who owns which local port.
 *
 * A port is one number in one namespace, and the kernel has three claimants
 * for the ones it sends from: the ephemeral allocator behind `net_open_udp`,
 * the DNS resolver, and NTP.
 *
 * They were three private constants in three files that happened to collide.
 * The allocator hands out from `XAIOS_EPHEMERAL_PORT_MIN` upward one at a
 * time, the resolver chose uniformly across the same range, and NTP sent from
 * a fixed port inside it -- so the fourth ephemeral draw was NTP's port, the
 * first was a port the resolver could also choose, and nothing anywhere said
 * so (B-77). Both subsystems match on the receive path before the socket table
 * does, which is why a reply still lands somewhere rather than nowhere: the
 * two owners are told apart by which matcher runs first, not by either of them
 * knowing the port has two.
 *
 * The partition is stated once, here, so that it cannot drift apart again:
 * the dynamic range belongs to the allocator alone, and the kernel's own
 * protocols source from the block immediately below it. That range is
 * `XAIOS_DNS_SOURCE_PORT_MIN..XAIOS_DNS_SOURCE_PORT_MAX` for the resolver,
 * which randomises within it, and `XAIOS_NTP_SOURCE_PORT` for NTP, which does
 * not. They are disjoint from each other and from the allocator, by
 * construction rather than by a lookup that could be forgotten.
 *
 * RFC 6335 puts the dynamic range at 49152..65535 and reserves it for exactly
 * the allocator's purpose. A resolver sending from just below it is ordinary
 * client behaviour, and a kernel that owns the machine can say which of the
 * registered ports are its own; what it cannot do is let three subsystems each
 * believe the whole range is theirs.
 */

/* RFC 6335's dynamic range, and the allocator's alone. */
#define XAIOS_EPHEMERAL_PORT_MIN UINT16_C(49152)
#define XAIOS_EPHEMERAL_PORT_MAX UINT16_C(65535)

/* The DNS resolver's source ports. It picks one at random per query, so the
   block has to be more than one port or two concurrent queries would share
   one; every port in it is below the allocator's floor. */
#define XAIOS_DNS_SOURCE_PORT_MIN UINT16_C(49140)
#define XAIOS_DNS_SOURCE_PORT_MAX UINT16_C(49150)

/* NTP's source port, fixed because the server's reply is matched on it. The
   last port below the allocator's floor, and outside the resolver's block. */
#define XAIOS_NTP_SOURCE_PORT UINT16_C(49151)

/*
 * The partition is checked here rather than trusted. Every one of these was
 * true by accident before it was written down, which is how the three
 * claimants came to overlap in the first place.
 */
#if XAIOS_DNS_SOURCE_PORT_MIN > XAIOS_DNS_SOURCE_PORT_MAX
#error "the DNS resolver's source port block is empty"
#endif
#if XAIOS_DNS_SOURCE_PORT_MAX >= XAIOS_EPHEMERAL_PORT_MIN
#error "the DNS resolver must source from below the ephemeral range"
#endif
#if XAIOS_NTP_SOURCE_PORT >= XAIOS_EPHEMERAL_PORT_MIN
#error "NTP must source from below the ephemeral range"
#endif
#if XAIOS_NTP_SOURCE_PORT >= XAIOS_DNS_SOURCE_PORT_MIN && \
    XAIOS_NTP_SOURCE_PORT <= XAIOS_DNS_SOURCE_PORT_MAX
#error "NTP's source port must not lie inside the DNS resolver's block"
#endif
#if XAIOS_EPHEMERAL_PORT_MIN > XAIOS_EPHEMERAL_PORT_MAX
#error "the ephemeral range is empty"
#endif

#endif
