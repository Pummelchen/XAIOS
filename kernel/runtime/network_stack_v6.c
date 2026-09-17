/*
 * The IPv6 address state and the router-advertisement path.
 * See network_stack_v6.h for why this is the cut and what crosses it.
 */

#include "network_stack_v6.h"

#include "network_stack_wire.h"
#include <xaios/icmpv6.h>
#include <xaios/ipv6.h>
#include <xaios/klog.h>
#include <xaios/timer.h>

static xaios_ip_addr_t g_link_local_v6;
static xaios_ip_addr_t g_public_v6;
static uint64_t g_public_v6_valid_until_ns;
/* The address actually configured from a router advertisement, which may be a
   unique-local prefix rather than a globally routable one. A host on such a
   network still has working IPv6 within it, so this is what packets are sent
   from; g_public_v6 stays reserved for genuinely global addresses. */
static xaios_ip_addr_t g_slaac_v6;
static uint64_t g_slaac_valid_until_ns;
/* The router that advertised the prefix, and the prefix itself.
 *
 * Configuring an address from a router advertisement and then ignoring the
 * router that sent it leaves a host that can speak to its own link and
 * nowhere else. Everything off-link needs a first hop, and for IPv6 that hop
 * is this router -- resolved by neighbour discovery like any other neighbour,
 * because it is one. Without it the transmit path looks up the destination
 * itself in the neighbour cache, which for an address on another network no
 * neighbour will ever answer for, so the flow waits forever rather than
 * failing: exactly the symptom of an outbound connection that hangs. */
static xaios_ip_addr_t g_ipv6_router;
static uint64_t g_ipv6_router_valid_until_ns;
static uint8_t g_ipv6_onlink_prefix[8];
static uint32_t g_ipv6_onlink_prefix_valid;
/* An address assigned by a DHCPv6 server rather than derived from a router
   advertisement. Kept apart from the SLAAC address because the two are not
   interchangeable: a lease is held on this host's behalf and has to be given
   back, where a SLAAC address is derived and simply expires. Both feed the
   same send path, and a lease wins when both exist -- a network that runs
   DHCPv6 has expressed a preference about which address a host should use. */
static uint64_t g_dhcpv6_valid_until_ns;

int net_v6_is_global_unicast(const xaios_ip_addr_t *address) {
  return address != 0 && address->family == XAIOS_IP_FAMILY_V6 &&
         (address->addr[0] & UINT8_C(0xe0)) == UINT8_C(0x20);
}

static int net_v6_is_unique_local(const xaios_ip_addr_t *address) {
  return address != 0 && address->family == XAIOS_IP_FAMILY_V6 &&
         (address->addr[0] & UINT8_C(0xfe)) == UINT8_C(0xfc);
}

static void net_v6_slaac_from_prefix(xaios_ip_addr_t *address,
                                     const uint8_t prefix[16],
                                     const uint8_t mac[6]) {
  address->family = XAIOS_IP_FAMILY_V6;
  for (uint32_t i = 0U; i < 8U; ++i) address->addr[i] = prefix[i];
  address->addr[8] = mac[0] ^ UINT8_C(0x02);
  address->addr[9] = mac[1];
  address->addr[10] = mac[2];
  address->addr[11] = UINT8_C(0xff);
  address->addr[12] = UINT8_C(0xfe);
  address->addr[13] = mac[3];
  address->addr[14] = mac[4];
  address->addr[15] = mac[5];
}

/* Whether an address is reachable without going through the router: our own
   /64, or link-local, or multicast. Anything else is off-link. */
static int net_v6_is_onlink(const xaios_ip_addr_t *address) {
  if (address == 0 || address->family != XAIOS_IP_FAMILY_V6) return 0;
  if (address->addr[0] == 0xfeU && (address->addr[1] & 0xc0U) == 0x80U) return 1;
  if (address->addr[0] == 0xffU) return 1;
  if (g_ipv6_onlink_prefix_valid == 0U) return 1;
  for (uint32_t i = 0U; i < 8U; ++i) {
    if (address->addr[i] != g_ipv6_onlink_prefix[i]) return 0;
  }
  return 1;
}

void net_v6_init(const uint8_t mac[6]) {
  ipv6_link_local_from_mac(&g_link_local_v6, mac);
  xaios_ip_addr_zero(&g_public_v6);
  g_public_v6_valid_until_ns = 0U;
  xaios_ip_addr_zero(&g_slaac_v6);
  g_slaac_valid_until_ns = 0U;
}

void net_v6_link_local(xaios_ip_addr_t *out) { *out = g_link_local_v6; }

void net_v6_local_address(xaios_ip_addr_t *out, uint64_t now_ns) {
  if (g_slaac_valid_until_ns != 0U && now_ns < g_slaac_valid_until_ns &&
      g_slaac_v6.family == XAIOS_IP_FAMILY_V6) {
    *out = g_slaac_v6;
    return;
  }
  *out = g_link_local_v6;
}

int net_v6_slaac_configured(void) { return g_slaac_valid_until_ns != 0U; }

int net_v6_public_address(xaios_ip_addr_t *out, uint64_t now_ns) {
  if (net_v6_is_global_unicast(&g_public_v6) == 0 ||
      g_public_v6_valid_until_ns == 0U ||
      now_ns >= g_public_v6_valid_until_ns) {
    return 0;
  }
  *out = g_public_v6;
  return 1;
}

void net_v6_public_read(xaios_ip_addr_t *out, uint64_t *valid_until_ns) {
  *out = g_public_v6;
  *valid_until_ns = g_public_v6_valid_until_ns;
}

void net_v6_reset_public(void) {
  xaios_ip_addr_zero(&g_public_v6);
  g_public_v6_valid_until_ns = 0U;
}

void net_v6_expire_public(uint64_t now_ns) {
  if (g_public_v6_valid_until_ns != 0U && now_ns >= g_public_v6_valid_until_ns) {
    xaios_ip_addr_zero(&g_public_v6);
    g_public_v6_valid_until_ns = 0U;
  }
}

void net_v6_adopt_dhcpv6(const xaios_ip_addr_t *address,
                         uint64_t valid_until_ns) {
  g_dhcpv6_valid_until_ns = valid_until_ns;
  /* A leased address that is globally routable is the public one, on the same
     terms a SLAAC address would be. */
  if (net_v6_is_global_unicast(address) != 0) {
    g_public_v6 = *address;
    g_public_v6_valid_until_ns = g_dhcpv6_valid_until_ns;
  }
}

void net_v6_flow_local_address(const xaios_ip_addr_t *remote_addr,
                               const uint8_t mac[6], xaios_ip_addr_t *out) {
  if (remote_addr->addr[0] == 0xfeU &&
      (remote_addr->addr[1] & 0xc0U) == 0x80U) {
    *out = g_link_local_v6;
  } else if (g_slaac_valid_until_ns != 0U &&
             timer_now_ns() < g_slaac_valid_until_ns) {
    /* Send from the address a router actually gave us. */
    *out = g_slaac_v6;
  } else {
    /* No advertisement has been accepted, so assume the peer's prefix is ours
       and derive an interface identifier. That is a guess, and only right when
       the peer is on the same link. */
    xaios_ip_addr_zero(out);
    out->family = XAIOS_IP_FAMILY_V6;
    for (uint32_t i = 0U; i < 8U; ++i) out->addr[i] = remote_addr->addr[i];
    out->addr[8] = mac[0] ^ 0x02U;
    out->addr[9] = mac[1];
    out->addr[10] = mac[2];
    out->addr[11] = 0xffU;
    out->addr[12] = 0xfeU;
    out->addr[13] = mac[3];
    out->addr[14] = mac[4];
    out->addr[15] = mac[5];
  }
}

/* Answer from the address that was asked for.
 *
 * An ICMPv6 reply and a neighbour advertisement both have to be sourced from
 * the address the peer addressed, not from whichever address the stack
 * happens to keep first. RFC 4861 is explicit for the solicited
 * advertisement -- its source is the solicited target -- and a host that
 * asked about a global address discards an advertisement arriving from a
 * link-local one, because as far as it can tell that answer is about a
 * different machine. Ping behaves the same way: a reply from an address the
 * request was not sent to does not match the request.
 *
 * That is why this guest could hold a globally routable address and still be
 * unreachable on it. It replied, correctly formed, from the wrong address,
 * every time. Copies the matching local address, or the link-local one when
 * the peer asked about something that is not ours to answer for. */
int net_v6_source_for(const xaios_ip_addr_t *wanted, xaios_ip_addr_t *out) {
  if (wanted != 0) {
    if (xaios_ip_addr_equal(wanted, &g_link_local_v6) != 0) {
      *out = g_link_local_v6;
      return 1;
    }
    if (g_slaac_v6.family == XAIOS_IP_FAMILY_V6 &&
        xaios_ip_addr_equal(wanted, &g_slaac_v6) != 0) {
      *out = g_slaac_v6;
      return 1;
    }
    /* Checked as well as the SLAAC address, not instead of it. The two hold
       the same value when a router advertisement carries a globally routable
       prefix, but they are set independently -- a DHCPv6 lease reaches
       g_public_v6 without going near g_slaac_v6 -- and an address this stack
       answers on is one it must answer *from*. */
    if (g_public_v6.family == XAIOS_IP_FAMILY_V6 &&
        xaios_ip_addr_equal(wanted, &g_public_v6) != 0) {
      *out = g_public_v6;
      return 1;
    }
  }
  *out = g_link_local_v6;
  return 0;
}

/* The address whose link-layer address a frame to `destination` should be
   sent to. Itself when on-link, otherwise the default router. */
int net_v6_next_hop(const xaios_ip_addr_t *destination, uint64_t now_ns,
                    xaios_ip_addr_t *out) {
  if (destination == 0) return 0;
  if (net_v6_is_onlink(destination) != 0) {
    *out = *destination;
    return 1;
  }
  if (g_ipv6_router.family == XAIOS_IP_FAMILY_V6 &&
      (g_ipv6_router_valid_until_ns == UINT64_MAX ||
       now_ns < g_ipv6_router_valid_until_ns)) {
    *out = g_ipv6_router;
    return 1;
  }
  /* No router known. Copying the destination keeps the previous behaviour
     -- the neighbour lookup fails and the frame is not sent -- rather than
     inventing a hop that does not exist. */
  *out = *destination;
  return 1;
}

void net_v6_apply_router_advertisement(const uint8_t *frame, uint32_t frame_len,
                                       uint64_t now_ns, const uint8_t mac[6]) {
  if (frame == 0 || frame_len < XAIOS_ICMPV6_OFFSET + 16U) return;
  uint32_t payload_len = net_wire_read_u16_be(frame + 18U);
  if (payload_len < 16U || payload_len > frame_len - XAIOS_ICMPV6_OFFSET) return;

  const uint8_t *icmpv6 = frame + XAIOS_ICMPV6_OFFSET;
  /* The advertising router, taken from the frame's own source address, and
     kept for as long as the Router Lifetime field says. A lifetime of zero
     means "not a default router" and withdraws it. */
  {
    uint16_t router_lifetime_s = net_wire_read_u16_be(icmpv6 + 6U);
    if (router_lifetime_s != 0U) {
      xaios_ip_addr_t router;
      xaios_ip_addr_from_raw_ipv6(&router, frame + 22U);
      uint64_t lifetime_ns =
          (uint64_t)router_lifetime_s * UINT64_C(1000000000);
      if (g_ipv6_router.family != XAIOS_IP_FAMILY_V6 ||
          xaios_ip_addr_equal(&g_ipv6_router, &router) == 0) {
        klog("network: IPv6 default router learned lifetime=%us\n",
             (unsigned)router_lifetime_s);
      }
      g_ipv6_router = router;
      g_ipv6_router_valid_until_ns =
          lifetime_ns > UINT64_MAX - now_ns ? UINT64_MAX : now_ns + lifetime_ns;
    } else if (g_ipv6_router.family == XAIOS_IP_FAMILY_V6) {
      klog("network: IPv6 default router withdrawn (lifetime=0)\n");
      g_ipv6_router.family = 0U; /* no family constant for "unset" */
      g_ipv6_router_valid_until_ns = 0U;
    }
  }
  for (uint32_t offset = 16U; offset + 2U <= payload_len;) {
    uint32_t option_len = (uint32_t)icmpv6[offset + 1U] * 8U;
    if (option_len == 0U || option_len > payload_len - offset) return;
    if (icmpv6[offset] == 3U && option_len == 32U &&
        icmpv6[offset + 2U] == 64U &&
        (icmpv6[offset + 3U] & UINT8_C(0x40)) != 0U) {
      uint32_t valid_lifetime_s = net_wire_read_u32_be(icmpv6 + offset + 4U);
      xaios_ip_addr_t candidate;
      net_v6_slaac_from_prefix(&candidate, icmpv6 + offset + 16U, mac);
      int global = net_v6_is_global_unicast(&candidate);
      int unique_local = net_v6_is_unique_local(&candidate);
      if (valid_lifetime_s != 0U && (global != 0 || unique_local != 0)) {
        uint64_t lifetime_ns = (uint64_t)valid_lifetime_s * UINT64_C(1000000000);
        uint64_t valid_until =
            lifetime_ns > UINT64_MAX - now_ns ? UINT64_MAX : now_ns + lifetime_ns;
        if (xaios_ip_addr_equal(&g_slaac_v6, &candidate) == 0) {
          klog("network: IPv6 address configured from advertised %x%x:%x%x::/64"
               " (%s)\n",
               candidate.addr[0], candidate.addr[1], candidate.addr[2],
               candidate.addr[3], global != 0 ? "global" : "unique-local");
        }
        g_slaac_v6 = candidate;
        g_slaac_valid_until_ns = valid_until;
        /* The /64 this address sits in is what "on-link" means here, so a
           destination inside it is reached directly and everything else via
           the router. */
        for (uint32_t i = 0U; i < 8U; ++i) {
          g_ipv6_onlink_prefix[i] = icmpv6[offset + 16U + i];
        }
        g_ipv6_onlink_prefix_valid = 1U;
        if (global != 0) {
          g_public_v6 = candidate;
          g_public_v6_valid_until_ns = valid_until;
          klog("network: public IPv6 SLAAC address configured\n");
        }
      }
      return;
    }
    offset += option_len;
  }
}
