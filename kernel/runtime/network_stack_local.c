/*
 * The local-address accessors and the DHCPv6 lease adoption, moved verbatim
 * out of network_stack.c.
 *
 * These are the entry points that answer "what address and MAC does this host
 * present" -- the SLAAC/link-local IPv6 address, the public IPv6 address, the
 * configured IPv4 address and the interface MAC -- plus the one call that
 * installs a DHCPv6 lease. They owned no state in network_stack.c and own none
 * here: the flags and the MAC array they read still live there.
 *
 * network_stack.c owns g_persistent_initialized and g_local_mac. The moved
 * code reads the flag through net_stack_persistent_ready() and the MAC through
 * net_stack_local_mac(), both of which are the existing copy-out accessors
 * declared in network_stack_icmp.h and network_stack_udp.h. Neither returns a
 * pointer into that file's state, and neither is a critical section: the flag
 * is a plain read and the MAC is an unguarded six-byte copy, exactly as
 * before.
 *
 * Locking. network_stack_adopt_dhcpv6() wrapped its write in the stack guard
 * and still does; the old file reached that guard through its static
 * network_lock()/network_unlock() aliases, so the moved code calls
 * network_stack_lock()/network_stack_unlock() directly. It is the same
 * reentrant lock, held across the same single statement, so no critical
 * section is widened, narrowed or split. The accessors take no lock, before
 * or after.
 *
 * This module defines only functions declared in <xaios/network_stack.h> and
 * introduces no cross-module symbol, so it needs no private header of its own.
 */

#include <xaios/ip_addr.h>
#include <xaios/klog.h>
#include <xaios/ndp.h>
#include <xaios/network_config.h>
#include <xaios/network_stack.h>
#include <xaios/timer.h>

#include "network_stack_icmp.h"
#include "network_stack_udp.h"
#include "network_stack_v6.h"

xaios_status_t network_stack_adopt_dhcpv6(const xaios_ip_addr_t *address,
                                          uint32_t valid_lifetime_s) {
  if (address == 0 || address->family != XAIOS_IP_FAMILY_V6) {
    return XAIOS_ERR_INVALID;
  }
  if (valid_lifetime_s == 0U) return XAIOS_ERR_INVALID;
  uint64_t now_ns = timer_now_ns();
  uint64_t lifetime_ns = (uint64_t)valid_lifetime_s * UINT64_C(1000000000);
  uint64_t valid_until_ns =
      lifetime_ns > UINT64_MAX - now_ns ? UINT64_MAX : now_ns + lifetime_ns;
  network_stack_lock();
  /* The lease, and the public address it becomes when it is globally
     routable, are written together under the guard the moved code used. */
  net_v6_adopt_dhcpv6(address, valid_until_ns);
  network_stack_unlock();
  klog("network: IPv6 address configured by DHCPv6 valid_s=%u (%s)\n",
       valid_lifetime_s,
       net_v6_is_global_unicast(address) != 0 ? "global" : "local");
  return XAIOS_OK;
}

xaios_status_t network_stack_local_ipv6(xaios_ip_addr_t *address) {
  if (address == 0) return XAIOS_ERR_INVALID;
  if (net_stack_persistent_ready() == 0U) {
    xaios_ip_addr_zero(address);
    return XAIOS_ERR_NOT_FOUND;
  }
  net_v6_local_address(address, timer_now_ns());
  return XAIOS_OK;
}

xaios_status_t network_wait_for_ipv6_slaac(uint64_t timeout_ns) {
  if (net_stack_persistent_ready() == 0U || timeout_ns == 0U) {
    return XAIOS_ERR_INVALID;
  }
  /* A router advertisement answers the solicitation within milliseconds, but
     nothing polls the interface between bringing it up and starting services,
     so the reply would sit unread in the receive ring and the machine would
     come up with a link-local address only. Poll for it here, re-soliciting
     the way RFC 4861 does rather than waiting on one packet. */
  uint8_t local_mac[6];
  net_stack_local_mac(local_mac);
  xaios_ip_addr_t address;
  uint64_t started = timer_now_ns();
  uint64_t next_solicit = started + UINT64_C(500000000);
  uint32_t solicits = 1U;
  for (;;) {
    network_poll_tick();
    if (net_v6_slaac_configured() != 0 &&
        network_stack_local_ipv6(&address) == XAIOS_OK) {
      return XAIOS_OK;
    }
    uint64_t now = timer_now_ns();
    if (now - started >= timeout_ns) break;
    if (now >= next_solicit && solicits < 3U) {
      xaios_ip_addr_t link_local_v6;
      net_v6_link_local(&link_local_v6);
      (void)ndp_send_router_solicitation(local_mac, &link_local_v6);
      ++solicits;
      next_solicit = now + UINT64_C(500000000);
    }
  }
  klog("network: no usable IPv6 prefix after %u solicitations; link-local "
       "only\n",
       solicits);
  return XAIOS_ERR_NOT_FOUND;
}

uint32_t network_stack_local_ipv4(void) { return network_config_local_ipv4(); }

xaios_status_t network_stack_local_mac(uint8_t mac[6]) {
  if (mac == 0 || net_stack_persistent_ready() == 0U)
    return XAIOS_ERR_NOT_FOUND;
  net_stack_local_mac(mac);
  return XAIOS_OK;
}

xaios_status_t network_stack_local_public_ipv6(xaios_ip_addr_t *address) {
  if (address == 0) return XAIOS_ERR_INVALID;
  if (net_stack_persistent_ready() == 0U ||
      net_v6_public_address(address, timer_now_ns()) == 0) {
    xaios_ip_addr_zero(address);
    return XAIOS_ERR_NOT_FOUND;
  }
  return XAIOS_OK;
}
