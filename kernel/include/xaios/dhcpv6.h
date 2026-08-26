#ifndef XAIOS_DHCPV6_H
#define XAIOS_DHCPV6_H

#include <xaios/ip_addr.h>
#include <xaios/status.h>
#include <xaios/types.h>

/*
 * A stateful DHCPv6 client, RFC 8415.
 *
 * XAIOS already configures IPv6 from router advertisements, which is a
 * different mechanism answering a different question: SLAAC lets a host derive
 * an address from a prefix the router announces, while DHCPv6 asks a server to
 * assign one and record that it did. A network that runs DHCPv6 generally does
 * so because it wants that record -- the lease is what ties an address to a
 * host for as long as it holds it. Both are supported because a guest does not
 * choose which one its network offers.
 */

typedef struct xaios_dhcpv6_lease {
  xaios_ip_addr_t address;
  xaios_ip_addr_t dns;
  uint32_t preferred_lifetime_s;
  uint32_t valid_lifetime_s;
  uint32_t have_address;
  uint32_t have_dns;
  /* Whether the server answered the SOLICIT with a REPLY directly rather than
     an ADVERTISE, which it may do when it honours Rapid Commit. Recorded
     because it says the exchange took two messages rather than four, and a
     gate that cares about either can tell them apart. */
  uint32_t rapid_commit;
} xaios_dhcpv6_lease_t;

/*
 * Run one exchange and return a lease, or an error if none arrived inside the
 * budget. Absence of a server is not a failure of this function's caller: a
 * network that offers only SLAAC will never answer, and that must stay a
 * survivable outcome rather than a halt.
 */
xaios_status_t dhcpv6_acquire(uint64_t timeout_ns, xaios_dhcpv6_lease_t *lease);

/* Message and option encoding, checked without a network. */
void dhcpv6_self_test(void);

#endif
