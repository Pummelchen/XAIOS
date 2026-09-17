#include <xaios/assert.h>
#include <xaios/icmpv6.h>
#include <xaios/ip_addr.h>
#include <xaios/ipv6.h>
#include <xaios/klog.h>
#include <xaios/ndp.h>
#include <xaios/net_device.h>

#include "ndp_internal.h"

/* Default gateway from RA */
xaios_ip_addr_t ndp_default_gateway;
int g_ndp_has_default_gateway = 0;

/* DAD state array (one per tentative address) */
xaios_dad_state_t g_ndp_dad_state;
int g_ndp_dad_active = 0;

static void solicited_node_mcast(const xaios_ip_addr_t *target,
                                  xaios_ip_addr_t *mcast) {
  mcast->family = XAIOS_IP_FAMILY_V6;
  for (uint32_t i = 0; i < 16; ++i) {
    mcast->addr[i] = 0;
  }
  mcast->addr[0] = 0xFF;
  mcast->addr[1] = 0x02;
  mcast->addr[11] = 0x01;
  mcast->addr[12] = 0xFF;
  mcast->addr[13] = target->addr[13];
  mcast->addr[14] = target->addr[14];
  mcast->addr[15] = target->addr[15];
}

static void mcast_eth_from_ipv6(const xaios_ip_addr_t *ip6, uint8_t mac[6]) {
  mac[0] = 0x33;
  mac[1] = 0x33;
  mac[2] = ip6->addr[12];
  mac[3] = ip6->addr[13];
  mac[4] = ip6->addr[14];
  mac[5] = ip6->addr[15];
}

/* ---- C5: Hop-limit validation ---- */
int ndp_hop_limit_is_valid(const uint8_t *frame) {
  /* IPv6 hop_limit is at byte 21 (frame + 14 + 7) */
  if (frame == 0) return 0;
  return (frame[14 + 7] == 255);
}

xaios_status_t ndp_build_neighbor_solicitation(
    uint8_t *frame, uint64_t *frame_len,
    const uint8_t src_mac[6],
    const xaios_ip_addr_t *src_ip,
    const xaios_ip_addr_t *target_ip) {
  if (frame == 0 || frame_len == 0 || src_mac == 0 ||
      src_ip == 0 || target_ip == 0) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t icmpv6_len = 28U;
  uint64_t total = 14U + XAIOS_IPV6_HEADER_SIZE + icmpv6_len;
  ndp_bytes_zero(frame, total);

  xaios_ip_addr_t mcast_dst;
  solicited_node_mcast(target_ip, &mcast_dst);

  uint8_t dst_mac[6];
  mcast_eth_from_ipv6(&mcast_dst, dst_mac);

  for (uint32_t i = 0; i < 6; ++i) {
    frame[i] = dst_mac[i];
    frame[6 + i] = src_mac[i];
  }
  ndp_put_be16(frame + 12, XAIOS_IPV6_ETHERTYPE);

  uint8_t *ipv6_hdr = frame + 14;
  ipv6_build_header(ipv6_hdr, (uint16_t)icmpv6_len,
                    XAIOS_IPV6_NEXT_ICMPV6, src_ip, &mcast_dst);
  ipv6_hdr[7] = 255U;

  uint8_t *icmpv6 = frame + XAIOS_ICMPV6_OFFSET;
  icmpv6[0] = XAIOS_ICMPV6_NEIGHBOR_SOLICIT;
  icmpv6[1] = 0;
  ndp_put_be16(icmpv6 + 2, 0);
  for (uint32_t i = 0; i < 16; ++i) {
    icmpv6[8 + i] = target_ip->addr[i];
  }
  icmpv6[24] = 1;
  icmpv6[25] = 1;
  for (uint32_t i = 0; i < 6; ++i) {
    icmpv6[26 + i] = src_mac[i];
  }

  uint16_t cksum = ipv6_pseudo_checksum(src_ip, &mcast_dst,
                                         XAIOS_IPV6_NEXT_ICMPV6,
                                         (uint32_t)icmpv6_len,
                                         icmpv6, (uint32_t)icmpv6_len);
  ndp_put_be16(icmpv6 + 2, cksum);

  *frame_len = total;
  return XAIOS_OK;
}

/* ---- C5: NS processing with hop-limit validation ---- */
xaios_status_t ndp_process_neighbor_solicitation(
    const uint8_t *frame, uint64_t frame_len) {
  if (frame == 0 || frame_len < XAIOS_ICMPV6_MIN_FRAME) {
    return XAIOS_ERR_INVALID;
  }
  if (!ndp_hop_limit_is_valid(frame)) {
    klog("ndp: drop NS with hop_limit != 255\n");
    return XAIOS_ERR_INVALID;
  }
  if (ndp_get_be16(frame + 12) != XAIOS_IPV6_ETHERTYPE) {
    return XAIOS_ERR_INVALID;
  }
  uint16_t payload_length = 0;
  uint8_t next_header = 0;
  xaios_ip_addr_t src_ip;
  if (ipv6_parse_header(frame + 14, frame_len - 14, &payload_length,
                        &next_header, &src_ip, 0) != 0) {
    return XAIOS_ERR_INVALID;
  }
  if (next_header != XAIOS_IPV6_NEXT_ICMPV6) {
    return XAIOS_ERR_INVALID;
  }
  const uint8_t *icmpv6 = frame + XAIOS_ICMPV6_OFFSET;
  if (icmpv6[0] != XAIOS_ICMPV6_NEIGHBOR_SOLICIT) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t icmpv6_len = (uint64_t)payload_length;
  if (icmpv6_len < 24U) {
    return XAIOS_ERR_INVALID;
  }

  xaios_ip_addr_t target;
  xaios_ip_addr_from_raw_ipv6(&target, icmpv6 + 8);

  /* Extract source link-layer address from options (type=1) */
  uint8_t src_mac[6] = {0, 0, 0, 0, 0, 0};
  uint32_t offset = 24U;
  while (offset + 8U <= icmpv6_len) {
    uint8_t opt_type = icmpv6[offset];
    uint8_t opt_len = icmpv6[offset + 1U];
    if (opt_len == 0) break;
    if (opt_type == 1 && opt_len == 1) {
      for (uint32_t i = 0; i < 6; ++i) {
        src_mac[i] = icmpv6[offset + 2 + i];
      }
      break;
    }
    offset += (uint32_t)opt_len * 8U;
  }

  /* On receiving a valid NS, add source to our NDP cache */
  if (src_ip.family == XAIOS_IP_FAMILY_V6 && src_mac[0] != 0) {
    ndp_cache_insert(&src_ip, src_mac);
  }

  /* We could respond with NA here, but that is typically handled at a higher layer */
  return XAIOS_OK;
}

/* ---- C5, C6: NA processing with hop-limit validation and DAD check ---- */
xaios_status_t ndp_process_neighbor_advertisement(
    const uint8_t *frame, uint64_t frame_len) {
  if (frame == 0 || frame_len < XAIOS_ICMPV6_MIN_FRAME) {
    return XAIOS_ERR_INVALID;
  }
  if (!ndp_hop_limit_is_valid(frame)) {
    klog("ndp: drop NA with hop_limit != 255\n");
    return XAIOS_ERR_INVALID;
  }
  if (ndp_get_be16(frame + 12) != XAIOS_IPV6_ETHERTYPE) {
    return XAIOS_ERR_INVALID;
  }
  uint16_t payload_length = 0;
  uint8_t next_header = 0;
  if (ipv6_parse_header(frame + 14, frame_len - 14, &payload_length,
                        &next_header, 0, 0) != 0) {
    return XAIOS_ERR_INVALID;
  }
  if (next_header != XAIOS_IPV6_NEXT_ICMPV6) {
    return XAIOS_ERR_INVALID;
  }
  const uint8_t *icmpv6 = frame + XAIOS_ICMPV6_OFFSET;
  if (icmpv6[0] != XAIOS_ICMPV6_NEIGHBOR_ADVERT) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t icmpv6_len = (uint64_t)payload_length;
  if (icmpv6_len < 24U) {
    return XAIOS_ERR_INVALID;
  }
  xaios_ip_addr_t target;
  xaios_ip_addr_from_raw_ipv6(&target, icmpv6 + 8);

  /* ---- C6: DAD check ---- */
  if (g_ndp_dad_active &&
      xaios_ip_addr_equal(&target, &g_ndp_dad_state.tentative_addr)) {
    g_ndp_dad_state.duplicate_found = 1;
    klog("ndp: DAD detected duplicate address!\n");
    return XAIOS_OK;
  }

  uint32_t offset = 24U;
  while (offset + 8U <= icmpv6_len) {
    uint8_t opt_type = icmpv6[offset];
    uint8_t opt_len = icmpv6[offset + 1U];
    if (opt_len == 0) break;
    if (opt_type == 2 && opt_len == 1) {
      return ndp_cache_insert(&target, icmpv6 + offset + 2);
    }
    offset += (uint32_t)opt_len * 8U;
  }
  uint8_t zero_mac[6] = {0, 0, 0, 0, 0, 0};
  return ndp_cache_insert(&target, zero_mac);
}

/* ---- C6: DAD ---- */
void ndp_dad_init(xaios_dad_state_t *dad, const xaios_ip_addr_t *addr) {
  if (dad == 0 || addr == 0) return;

  dad->tentative_addr = *addr;
  dad->start_ns = g_ndp_last_tick_ns;
  dad->active = 1;
  dad->duplicate_found = 0;

  /* Set global DAD state for checking in NA processing */
  g_ndp_dad_active = 1;
  g_ndp_dad_state = *dad;

  /* Build and "send" NS for DAD:
   * For DAD, the source IP must be the unspecified address (::)
   * and the target is the tentative address. */
  xaios_ip_addr_t unspecified;
  unspecified.family = XAIOS_IP_FAMILY_V6;
  for (uint32_t i = 0; i < 16; ++i) unspecified.addr[i] = 0;

  xaios_ip_addr_t mcast_dst;
  solicited_node_mcast(addr, &mcast_dst);

  uint8_t zero_mac[6] = {0, 0, 0, 0, 0, 0};
  uint8_t dad_frame[128];
  uint64_t dad_len = 0;

  /* Use ndp_build_neighbor_solicitation with unspecified source */
  uint64_t icmpv6_len = 28U;
  uint64_t total = 14U + XAIOS_IPV6_HEADER_SIZE + icmpv6_len;
  ndp_bytes_zero(dad_frame, total);

  uint8_t dst_mac[6];
  mcast_eth_from_ipv6(&mcast_dst, dst_mac);

  for (uint32_t i = 0; i < 6; ++i) {
    dad_frame[i] = dst_mac[i];
    dad_frame[6 + i] = zero_mac[i];
  }
  ndp_put_be16(dad_frame + 12, XAIOS_IPV6_ETHERTYPE);

  uint8_t *ipv6_hdr = dad_frame + 14;
  ipv6_build_header(ipv6_hdr, (uint16_t)icmpv6_len,
                    XAIOS_IPV6_NEXT_ICMPV6, &unspecified, &mcast_dst);
  ipv6_hdr[7] = 255U;

  uint8_t *icmpv6 = dad_frame + XAIOS_ICMPV6_OFFSET;
  icmpv6[0] = XAIOS_ICMPV6_NEIGHBOR_SOLICIT;
  icmpv6[1] = 0;
  ndp_put_be16(icmpv6 + 2, 0);
  for (uint32_t i = 0; i < 16; ++i) {
    icmpv6[8 + i] = addr->addr[i];
  }
  /* No source link-layer option for DAD (unspecified source) */

  uint16_t cksum = ipv6_pseudo_checksum(&unspecified, &mcast_dst,
                                         XAIOS_IPV6_NEXT_ICMPV6,
                                         (uint32_t)icmpv6_len,
                                         icmpv6, (uint32_t)icmpv6_len);
  ndp_put_be16(icmpv6 + 2, cksum);
  dad_len = total;

  (void)dad_frame;
  (void)dad_len;

  klog("ndp: DAD started for ");
  for (uint32_t i = 0; i < 16; ++i) klog("%02x", addr->addr[i]);
  klog("\n");
}

int ndp_dad_tick(xaios_dad_state_t *dad, uint64_t now_ns) {
  if (dad == 0 || dad->active == 0) {
    return 1; /* not checking – treat as unique */
  }

  if (g_ndp_dad_active &&
      xaios_ip_addr_equal(&dad->tentative_addr, &g_ndp_dad_state.tentative_addr)) {
    dad->duplicate_found = g_ndp_dad_state.duplicate_found;
  }

  /* Check if duplicate was detected by NA processing */
  if (dad->duplicate_found) {
    dad->active = 0;
    g_ndp_dad_active = 0;
    klog("ndp: DAD -> DUPLICATE\n");
    return -1;
  }

  /* After 1 second, address is considered unique */
  if (now_ns - dad->start_ns >= XAIOS_NDP_RETRANS_TIMER_NS) {
    dad->active = 0;
    g_ndp_dad_active = 0;
    klog("ndp: DAD -> UNIQUE\n");
    return 1;
  }

  return 0; /* still probing */
}

/* ---- C7: Router Solicitation ---- */
/* Construction is separated from transmission so the self-test can check the
   frame this builds without needing a network device, which does not exist
   when the self-tests run. */
xaios_status_t ndp_build_router_solicitation(uint8_t *rs_frame,
                                                uint64_t capacity,
                                                uint64_t *out_len,
                                                const uint8_t src_mac[6],
                                                const xaios_ip_addr_t *src_ip) {
  if (rs_frame == 0 || out_len == 0 || src_mac == 0 || src_ip == 0) {
    return XAIOS_ERR_INVALID;
  }

  /* Build RS to ff02::2 (all-routers multicast) */
  xaios_ip_addr_t all_routers;
  all_routers.family = XAIOS_IP_FAMILY_V6;
  for (uint32_t i = 0; i < 16; ++i) all_routers.addr[i] = 0;
  all_routers.addr[0] = 0xFF;
  all_routers.addr[1] = 0x02;
  all_routers.addr[15] = 0x02;

  uint8_t dst_mac[6];
  mcast_eth_from_ipv6(&all_routers, dst_mac);

  /* RS: ICMPv6 type=133, code=0, checksum, reserved(4), options */
  uint64_t icmpv6_len = 12U; /* 4 + 8 (source link-layer option) */
  uint64_t total = 14U + XAIOS_IPV6_HEADER_SIZE + icmpv6_len;

  if (total > capacity) return XAIOS_ERR_INVALID;
  ndp_bytes_zero(rs_frame, total);

  for (uint32_t i = 0; i < 6; ++i) {
    rs_frame[i] = dst_mac[i];
    rs_frame[6 + i] = src_mac[i];
  }
  ndp_put_be16(rs_frame + 12, XAIOS_IPV6_ETHERTYPE);

  uint8_t *ipv6_hdr = rs_frame + 14;
  ipv6_build_header(ipv6_hdr, (uint16_t)icmpv6_len,
                    XAIOS_IPV6_NEXT_ICMPV6, src_ip, &all_routers);
  ipv6_hdr[7] = 255U;

  uint8_t *icmpv6 = rs_frame + XAIOS_ICMPV6_OFFSET;
  icmpv6[0] = XAIOS_ICMPV6_ROUTER_SOLICIT; /* type=133 */
  icmpv6[1] = 0;                            /* code */
  ndp_put_be16(icmpv6 + 2, 0);                  /* checksum (later) */
  /* reserved = 0 (already zeroed) */
  /* Source Link-Layer Address option */
  icmpv6[4] = 1; /* type = Source Link-Layer Address */
  icmpv6[5] = 1; /* length in units of 8 octets */
  for (uint32_t i = 0; i < 6; ++i) {
    icmpv6[6 + i] = src_mac[i];
  }

  uint16_t cksum = ipv6_pseudo_checksum(src_ip, &all_routers,
                                         XAIOS_IPV6_NEXT_ICMPV6,
                                         (uint32_t)icmpv6_len,
                                         icmpv6, (uint32_t)icmpv6_len);
  ndp_put_be16(icmpv6 + 2, cksum);

  *out_len = total;
  return XAIOS_OK;
}

xaios_status_t ndp_send_router_solicitation(const uint8_t src_mac[6],
                                            const xaios_ip_addr_t *src_ip) {
  /* This used to build a correct solicitation, discard it and report success,
     so no router was ever asked and a global address only ever appeared in
     the self-test that fabricates an advertisement. Put it on the wire. */
  uint8_t rs_frame[128];
  uint64_t total = 0U;
  xaios_status_t status =
      ndp_build_router_solicitation(rs_frame, sizeof(rs_frame), &total, src_mac,
                                src_ip);
  if (status != XAIOS_OK) return status;
  status = network_device_tx(rs_frame, total);
  if (status != XAIOS_OK) {
    klog("ndp: router solicitation not transmitted status=%d\n", (int)status);
    return status;
  }
  klog("ndp: sent RS to ff02::2\n");
  return XAIOS_OK;
}

/* ---- C7: Router Advertisement processing ---- */
xaios_status_t ndp_process_router_advertisement(const uint8_t *frame,
                                                 uint64_t frame_len) {
  if (frame == 0 || frame_len < XAIOS_ICMPV6_MIN_FRAME) {
    return XAIOS_ERR_INVALID;
  }
  if (!ndp_hop_limit_is_valid(frame)) {
    klog("ndp: drop RA with hop_limit != 255\n");
    return XAIOS_ERR_INVALID;
  }
  if (ndp_get_be16(frame + 12) != XAIOS_IPV6_ETHERTYPE) {
    return XAIOS_ERR_INVALID;
  }

  uint16_t payload_length = 0;
  uint8_t next_header = 0;
  xaios_ip_addr_t src_ip;
  if (ipv6_parse_header(frame + 14, frame_len - 14, &payload_length,
                        &next_header, &src_ip, 0) != 0) {
    return XAIOS_ERR_INVALID;
  }
  if (next_header != XAIOS_IPV6_NEXT_ICMPV6) {
    return XAIOS_ERR_INVALID;
  }
  if (src_ip.family != XAIOS_IP_FAMILY_V6 || src_ip.addr[0] != UINT8_C(0xfe) ||
      (src_ip.addr[1] & UINT8_C(0xc0)) != UINT8_C(0x80)) {
    return XAIOS_ERR_INVALID;
  }

  const uint8_t *icmpv6 = frame + XAIOS_ICMPV6_OFFSET;
  if (icmpv6[0] != XAIOS_ICMPV6_ROUTER_ADVERT || icmpv6[1] != 0U) {
    return XAIOS_ERR_INVALID;
  }

  uint64_t icmpv6_len = (uint64_t)payload_length;
  if (icmpv6_len < 16U || icmpv6_len > frame_len - XAIOS_ICMPV6_OFFSET) {
    return XAIOS_ERR_INVALID;
  }
  xaios_ip_addr_t dst_ip;
  xaios_ip_addr_from_raw_ipv6(&dst_ip, frame + 38U);
  if (ipv6_pseudo_checksum(&src_ip, &dst_ip, XAIOS_IPV6_NEXT_ICMPV6,
                           payload_length, icmpv6, payload_length) != 0U) {
    return XAIOS_ERR_INVALID;
  }

  /* RA fields: CurHopLimit(1) + M/O(1) + RouterLifetime(2) + ReachableTime(4) + RetransTimer(4) */
  /* Followed by options starting at offset 16 */

  /* Extract source link-layer address */
  uint32_t offset = 16U;
  while (offset + 2U <= icmpv6_len) {
    uint8_t opt_type = icmpv6[offset];
    uint8_t opt_len = icmpv6[offset + 1U];
    uint32_t option_bytes = (uint32_t)opt_len * 8U;
    if (opt_len == 0 || option_bytes > icmpv6_len - offset) {
      return XAIOS_ERR_INVALID;
    }
    if (opt_type == 1 && opt_len == 1) {
      /* Source Link-Layer Address: cache the source */
      ndp_cache_insert(&src_ip, icmpv6 + offset + 2);
    }
    offset += option_bytes;
  }

  /* Store default gateway from RA source */
  ndp_default_gateway = src_ip;
  g_ndp_has_default_gateway = 1;

  klog("ndp: RA processed from ");
  for (uint32_t i = 0; i < 16; ++i) klog("%02x", src_ip.addr[i]);
  klog("\n");

  return XAIOS_OK;
}
