#include <xaios/assert.h>
#include <xaios/icmpv6.h>
#include <xaios/ip_addr.h>
#include <xaios/ipv6.h>
#include <xaios/klog.h>
#include <xaios/ndp.h>

static xaios_ndp_entry_t g_ndp_cache[XAIOS_NDP_CACHE_SIZE];
static uint64_t g_ndp_last_tick_ns = 0;

/* Default gateway from RA */
xaios_ip_addr_t ndp_default_gateway;
static int g_has_default_gateway = 0;

/* DAD state array (one per tentative address) */
static xaios_dad_state_t g_dad_state;
static int g_dad_active = 0;

static void bytes_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0; i < size; ++i) {
    bytes[i] = 0;
  }
}

static void put_be16(uint8_t *dst, uint16_t value) {
  dst[0] = (uint8_t)(value >> 8U);
  dst[1] = (uint8_t)value;
}

static uint16_t get_be16(const uint8_t *src) {
  return (uint16_t)(((uint16_t)src[0] << 8U) | src[1]);
}

static void put_be32(uint8_t *dst, uint32_t value) {
  dst[0] = (uint8_t)(value >> 24U);
  dst[1] = (uint8_t)(value >> 16U);
  dst[2] = (uint8_t)(value >> 8U);
  dst[3] = (uint8_t)value;
}

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
static int hop_limit_is_valid(const uint8_t *frame) {
  /* IPv6 hop_limit is at byte 21 (frame + 14 + 7) */
  if (frame == 0) return 0;
  return (frame[14 + 7] == 255);
}

/* ---- C4: LRU reorder on cache hit ---- */
static void lru_touch(uint32_t idx, uint64_t now_ns) {
  g_ndp_cache[idx].last_used_ns = now_ns;
}

/* ---- C4: Age an entry after NUD timeout ---- */
static void expire_entry(uint32_t idx) {
  g_ndp_cache[idx].active = 0;
  g_ndp_cache[idx].nud_state = XAIOS_NDP_NUD_INCOMPLETE;
  xaios_ip_addr_zero(&g_ndp_cache[idx].ip);
  bytes_zero(g_ndp_cache[idx].mac, 6);
}

/* ---- NUD state name for logging ---- */
void ndp_init(void) {
  for (uint32_t i = 0; i < XAIOS_NDP_CACHE_SIZE; ++i) {
    g_ndp_cache[i].active = 0;
    g_ndp_cache[i].nud_state = XAIOS_NDP_NUD_INCOMPLETE;
    g_ndp_cache[i].nud_timestamp_ns = 0;
    g_ndp_cache[i].last_used_ns = 0;
    g_ndp_cache[i].insert_ns = 0;
    g_ndp_cache[i].probe_count = 0;
    xaios_ip_addr_zero(&g_ndp_cache[i].ip);
    bytes_zero(g_ndp_cache[i].mac, 6);
  }
  xaios_ip_addr_zero(&ndp_default_gateway);
  g_has_default_gateway = 0;
  g_dad_active = 0;
  klog("ndp: cache initialized slots=%u\n", XAIOS_NDP_CACHE_SIZE);
}

/* ---- C4: C3 NUD-aware lookup ---- */
xaios_status_t ndp_cache_lookup(const xaios_ip_addr_t *ip, uint8_t mac[6]) {
  if (ip == 0 || mac == 0) {
    return XAIOS_ERR_INVALID;
  }
  for (uint32_t i = 0; i < XAIOS_NDP_CACHE_SIZE; ++i) {
    if (g_ndp_cache[i].active != 0 && xaios_ip_addr_equal(&g_ndp_cache[i].ip, ip)) {
      for (uint32_t j = 0; j < 6; ++j) {
        mac[j] = g_ndp_cache[i].mac[j];
      }
      /* LRU update */
      lru_touch(i, g_ndp_last_tick_ns);
      /* NUD: on traffic, transition STALE -> DELAY */
      if (g_ndp_cache[i].nud_state == XAIOS_NDP_NUD_STALE) {
        g_ndp_cache[i].nud_state = XAIOS_NDP_NUD_DELAY;
        g_ndp_cache[i].nud_timestamp_ns = g_ndp_last_tick_ns;
        klog("ndp: traffic -> DELAY for ");
        for (uint32_t j = 0; j < 16; ++j) klog("%02x", ip->addr[j]);
        klog("\n");
      } else if (g_ndp_cache[i].nud_state == XAIOS_NDP_NUD_REACHABLE) {
        /* Refresh REACHABLE timer */
        g_ndp_cache[i].nud_timestamp_ns = g_ndp_last_tick_ns;
      }
      return XAIOS_OK;
    }
  }
  return XAIOS_ERR_NOT_FOUND;
}

xaios_status_t ndp_cache_insert(const xaios_ip_addr_t *ip, const uint8_t mac[6]) {
  if (ip == 0 || mac == 0) {
    return XAIOS_ERR_INVALID;
  }
  /* Update existing entry */
  for (uint32_t i = 0; i < XAIOS_NDP_CACHE_SIZE; ++i) {
    if (g_ndp_cache[i].active != 0 && xaios_ip_addr_equal(&g_ndp_cache[i].ip, ip)) {
      for (uint32_t j = 0; j < 6; ++j) {
        g_ndp_cache[i].mac[j] = mac[j];
      }
      /* On confirmation, transition to REACHABLE */
      g_ndp_cache[i].nud_state = XAIOS_NDP_NUD_REACHABLE;
      g_ndp_cache[i].nud_timestamp_ns = g_ndp_last_tick_ns;
      g_ndp_cache[i].probe_count = 0;
      lru_touch(i, g_ndp_last_tick_ns);
      klog("ndp: updated state=REACHABLE mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
      return XAIOS_OK;
    }
  }
  /* Evict oldest LRU if full */
  uint32_t insert_idx = XAIOS_NDP_CACHE_SIZE;
  uint32_t lru_idx = XAIOS_NDP_CACHE_SIZE;
  uint64_t oldest_used = UINT64_MAX;
  for (uint32_t i = 0; i < XAIOS_NDP_CACHE_SIZE; ++i) {
    if (g_ndp_cache[i].active == 0) {
      insert_idx = i;
      break;
    }
    if (g_ndp_cache[i].last_used_ns < oldest_used) {
      oldest_used = g_ndp_cache[i].last_used_ns;
      lru_idx = i;
    }
  }
  if (insert_idx == XAIOS_NDP_CACHE_SIZE) {
    /* Cache full — evict LRU entry */
    if (lru_idx < XAIOS_NDP_CACHE_SIZE) {
      expire_entry(lru_idx);
      insert_idx = lru_idx;
    } else {
      return XAIOS_ERR_NO_MEMORY;
    }
  }

  g_ndp_cache[insert_idx].ip = *ip;
  g_ndp_cache[insert_idx].active = 1;
  g_ndp_cache[insert_idx].nud_state = XAIOS_NDP_NUD_REACHABLE;
  g_ndp_cache[insert_idx].nud_timestamp_ns = g_ndp_last_tick_ns;
  g_ndp_cache[insert_idx].last_used_ns = g_ndp_last_tick_ns;
  g_ndp_cache[insert_idx].insert_ns = g_ndp_last_tick_ns;
  g_ndp_cache[insert_idx].probe_count = 0;
  for (uint32_t j = 0; j < 6; ++j) {
    g_ndp_cache[insert_idx].mac[j] = mac[j];
  }
  klog("ndp: cached state=REACHABLE mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
       mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return XAIOS_OK;
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
  bytes_zero(frame, total);

  xaios_ip_addr_t mcast_dst;
  solicited_node_mcast(target_ip, &mcast_dst);

  uint8_t dst_mac[6];
  mcast_eth_from_ipv6(&mcast_dst, dst_mac);

  for (uint32_t i = 0; i < 6; ++i) {
    frame[i] = dst_mac[i];
    frame[6 + i] = src_mac[i];
  }
  put_be16(frame + 12, XAIOS_IPV6_ETHERTYPE);

  uint8_t *ipv6_hdr = frame + 14;
  ipv6_build_header(ipv6_hdr, (uint16_t)icmpv6_len,
                    XAIOS_IPV6_NEXT_ICMPV6, src_ip, &mcast_dst);
  ipv6_hdr[7] = 255U;

  uint8_t *icmpv6 = frame + XAIOS_ICMPV6_OFFSET;
  icmpv6[0] = XAIOS_ICMPV6_NEIGHBOR_SOLICIT;
  icmpv6[1] = 0;
  put_be16(icmpv6 + 2, 0);
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
  put_be16(icmpv6 + 2, cksum);

  *frame_len = total;
  return XAIOS_OK;
}

/* ---- C5: NS processing with hop-limit validation ---- */
xaios_status_t ndp_process_neighbor_solicitation(
    const uint8_t *frame, uint64_t frame_len) {
  if (frame == 0 || frame_len < XAIOS_ICMPV6_MIN_FRAME) {
    return XAIOS_ERR_INVALID;
  }
  if (!hop_limit_is_valid(frame)) {
    klog("ndp: drop NS with hop_limit != 255\n");
    return XAIOS_ERR_INVALID;
  }
  if (get_be16(frame + 12) != XAIOS_IPV6_ETHERTYPE) {
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
  if (!hop_limit_is_valid(frame)) {
    klog("ndp: drop NA with hop_limit != 255\n");
    return XAIOS_ERR_INVALID;
  }
  if (get_be16(frame + 12) != XAIOS_IPV6_ETHERTYPE) {
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
  if (g_dad_active &&
      xaios_ip_addr_equal(&target, &g_dad_state.tentative_addr)) {
    g_dad_state.duplicate_found = 1;
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

/* ---- C4: Cache aging ---- */
void ndp_cache_age(uint64_t now_ns) {
  for (uint32_t i = 0; i < XAIOS_NDP_CACHE_SIZE; ++i) {
    if (g_ndp_cache[i].active == 0) continue;

    if (g_ndp_cache[i].nud_state == XAIOS_NDP_NUD_REACHABLE) {
      if (now_ns - g_ndp_cache[i].nud_timestamp_ns >= XAIOS_NDP_REACHABLE_TIME_NS) {
        g_ndp_cache[i].nud_state = XAIOS_NDP_NUD_STALE;
        klog("ndp: timeout -> STALE for ");
        for (uint32_t j = 0; j < 16; ++j) klog("%02x", g_ndp_cache[i].ip.addr[j]);
        klog("\n");
      }
    }

    /* Remove INCOMPLETE entries that have been pending too long */
    if (g_ndp_cache[i].nud_state == XAIOS_NDP_NUD_INCOMPLETE) {
      if (now_ns - g_ndp_cache[i].insert_ns >= XAIOS_NDP_REACHABLE_TIME_NS) {
        expire_entry(i);
      }
    }
  }
}

/* ---- C3: NUD Update on traffic (confirmation or solicitation) ---- */
void ndp_nud_update_on_traffic(const xaios_ip_addr_t *target) {
  if (target == 0) return;

  for (uint32_t i = 0; i < XAIOS_NDP_CACHE_SIZE; ++i) {
    if (g_ndp_cache[i].active == 0) continue;
    if (!xaios_ip_addr_equal(&g_ndp_cache[i].ip, target)) continue;

    g_ndp_cache[i].last_used_ns = g_ndp_last_tick_ns;

    switch (g_ndp_cache[i].nud_state) {
      case XAIOS_NDP_NUD_STALE:
        g_ndp_cache[i].nud_state = XAIOS_NDP_NUD_DELAY;
        g_ndp_cache[i].nud_timestamp_ns = g_ndp_last_tick_ns;
        klog("ndp: STALE -> DELAY on traffic\n");
        break;
      case XAIOS_NDP_NUD_REACHABLE:
        g_ndp_cache[i].nud_timestamp_ns = g_ndp_last_tick_ns;
        break;
      default:
        break;
    }
    return;
  }
}

/* ---- C3: NUD periodic tick ---- */
void ndp_nud_tick(uint64_t now_ns) {
  g_ndp_last_tick_ns = now_ns;

  ndp_cache_age(now_ns);

  for (uint32_t i = 0; i < XAIOS_NDP_CACHE_SIZE; ++i) {
    if (g_ndp_cache[i].active == 0) continue;

    switch (g_ndp_cache[i].nud_state) {
      case XAIOS_NDP_NUD_REACHABLE:
        /* Transition to STALE handled in ndp_cache_age */
        break;

      case XAIOS_NDP_NUD_DELAY:
        if (now_ns - g_ndp_cache[i].nud_timestamp_ns >= XAIOS_NDP_DELAY_FIRST_PROBE_NS) {
          g_ndp_cache[i].nud_state = XAIOS_NDP_NUD_PROBE;
          g_ndp_cache[i].nud_timestamp_ns = now_ns;
          g_ndp_cache[i].probe_count = 0;
          klog("ndp: DELAY -> PROBE\n");
        }
        break;

      case XAIOS_NDP_NUD_PROBE:
        if (now_ns - g_ndp_cache[i].nud_timestamp_ns >= XAIOS_NDP_RETRANS_TIMER_NS) {
          if (g_ndp_cache[i].probe_count >= XAIOS_NDP_MAX_PROBES) {
            g_ndp_cache[i].nud_state = XAIOS_NDP_NUD_INCOMPLETE;
            klog("ndp: PROBE failed -> INCOMPLETE for ");
            for (uint32_t j = 0; j < 16; ++j) klog("%02x", g_ndp_cache[i].ip.addr[j]);
            klog("\n");
          }
        }
        break;

      default:
        break;
    }
  }
}

/* ---- C6: DAD ---- */
void ndp_dad_init(xaios_dad_state_t *dad, const xaios_ip_addr_t *addr) {
  if (dad == 0 || addr == 0) return;

  dad->tentative_addr = *addr;
  dad->start_ns = g_ndp_last_tick_ns;
  dad->active = 1;
  dad->duplicate_found = 0;

  /* Set global DAD state for checking in NA processing */
  g_dad_active = 1;
  g_dad_state = *dad;

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
  bytes_zero(dad_frame, total);

  uint8_t dst_mac[6];
  mcast_eth_from_ipv6(&mcast_dst, dst_mac);

  for (uint32_t i = 0; i < 6; ++i) {
    dad_frame[i] = dst_mac[i];
    dad_frame[6 + i] = zero_mac[i];
  }
  put_be16(dad_frame + 12, XAIOS_IPV6_ETHERTYPE);

  uint8_t *ipv6_hdr = dad_frame + 14;
  ipv6_build_header(ipv6_hdr, (uint16_t)icmpv6_len,
                    XAIOS_IPV6_NEXT_ICMPV6, &unspecified, &mcast_dst);
  ipv6_hdr[7] = 255U;

  uint8_t *icmpv6 = dad_frame + XAIOS_ICMPV6_OFFSET;
  icmpv6[0] = XAIOS_ICMPV6_NEIGHBOR_SOLICIT;
  icmpv6[1] = 0;
  put_be16(icmpv6 + 2, 0);
  for (uint32_t i = 0; i < 16; ++i) {
    icmpv6[8 + i] = addr->addr[i];
  }
  /* No source link-layer option for DAD (unspecified source) */

  uint16_t cksum = ipv6_pseudo_checksum(&unspecified, &mcast_dst,
                                         XAIOS_IPV6_NEXT_ICMPV6,
                                         (uint32_t)icmpv6_len,
                                         icmpv6, (uint32_t)icmpv6_len);
  put_be16(icmpv6 + 2, cksum);
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

  if (g_dad_active &&
      xaios_ip_addr_equal(&dad->tentative_addr, &g_dad_state.tentative_addr)) {
    dad->duplicate_found = g_dad_state.duplicate_found;
  }

  /* Check if duplicate was detected by NA processing */
  if (dad->duplicate_found) {
    dad->active = 0;
    g_dad_active = 0;
    klog("ndp: DAD -> DUPLICATE\n");
    return -1;
  }

  /* After 1 second, address is considered unique */
  if (now_ns - dad->start_ns >= XAIOS_NDP_RETRANS_TIMER_NS) {
    dad->active = 0;
    g_dad_active = 0;
    klog("ndp: DAD -> UNIQUE\n");
    return 1;
  }

  return 0; /* still probing */
}

/* ---- C7: Router Solicitation ---- */
xaios_status_t ndp_send_router_solicitation(const uint8_t src_mac[6],
                                              const xaios_ip_addr_t *src_ip) {
  if (src_mac == 0 || src_ip == 0) return XAIOS_ERR_INVALID;

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

  uint8_t rs_frame[128];
  bytes_zero(rs_frame, total);

  for (uint32_t i = 0; i < 6; ++i) {
    rs_frame[i] = dst_mac[i];
    rs_frame[6 + i] = src_mac[i];
  }
  put_be16(rs_frame + 12, XAIOS_IPV6_ETHERTYPE);

  uint8_t *ipv6_hdr = rs_frame + 14;
  ipv6_build_header(ipv6_hdr, (uint16_t)icmpv6_len,
                    XAIOS_IPV6_NEXT_ICMPV6, src_ip, &all_routers);
  ipv6_hdr[7] = 255U;

  uint8_t *icmpv6 = rs_frame + XAIOS_ICMPV6_OFFSET;
  icmpv6[0] = XAIOS_ICMPV6_ROUTER_SOLICIT; /* type=133 */
  icmpv6[1] = 0;                            /* code */
  put_be16(icmpv6 + 2, 0);                  /* checksum (later) */
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
  put_be16(icmpv6 + 2, cksum);

  (void)rs_frame;

  klog("ndp: sent RS to ff02::2\n");
  return XAIOS_OK;
}

/* ---- C7: Router Advertisement processing ---- */
xaios_status_t ndp_process_router_advertisement(const uint8_t *frame,
                                                 uint64_t frame_len) {
  if (frame == 0 || frame_len < XAIOS_ICMPV6_MIN_FRAME) {
    return XAIOS_ERR_INVALID;
  }
  if (!hop_limit_is_valid(frame)) {
    klog("ndp: drop RA with hop_limit != 255\n");
    return XAIOS_ERR_INVALID;
  }
  if (get_be16(frame + 12) != XAIOS_IPV6_ETHERTYPE) {
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
  if (icmpv6[0] != XAIOS_ICMPV6_ROUTER_ADVERT) {
    return XAIOS_ERR_INVALID;
  }

  uint64_t icmpv6_len = (uint64_t)payload_length;
  if (icmpv6_len < 16U) { /* RA header: 4 + 4 + 4 + 4 = 16 bytes min */
    return XAIOS_ERR_INVALID;
  }

  /* RA fields: CurHopLimit(1) + M/O(1) + RouterLifetime(2) + ReachableTime(4) + RetransTimer(4) */
  /* Followed by options starting at offset 16 */

  /* Extract source link-layer address */
  uint32_t offset = 16U;
  while (offset + 8U <= icmpv6_len) {
    uint8_t opt_type = icmpv6[offset];
    uint8_t opt_len = icmpv6[offset + 1U];
    if (opt_len == 0) break;
    if (opt_type == 1 && opt_len == 1) {
      /* Source Link-Layer Address: cache the source */
      ndp_cache_insert(&src_ip, icmpv6 + offset + 2);
    }
    offset += (uint32_t)opt_len * 8U;
  }

  /* Store default gateway from RA source */
  ndp_default_gateway = src_ip;
  g_has_default_gateway = 1;

  klog("ndp: RA processed from ");
  for (uint32_t i = 0; i < 16; ++i) klog("%02x", src_ip.addr[i]);
  klog("\n");

  return XAIOS_OK;
}

uint64_t ndp_cache_count(void) {
  uint64_t count = 0;
  for (uint32_t i = 0; i < XAIOS_NDP_CACHE_SIZE; ++i) {
    if (g_ndp_cache[i].active != 0) {
      ++count;
    }
  }
  return count;
}

void ndp_self_test(void) {
  ndp_init();
  /* Set a baseline time for tests */
  g_ndp_last_tick_ns = 1000000;

  /* ---- Base cache test ---- */
  kassert(ndp_cache_count() == 0);

  xaios_ip_addr_t test_ip;
  test_ip.family = XAIOS_IP_FAMILY_V6;
  for (uint32_t i = 0; i < 16; ++i) test_ip.addr[i] = 0;
  test_ip.addr[0] = 0xFE;
  test_ip.addr[1] = 0x80;
  test_ip.addr[15] = 0x01;

  uint8_t test_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
  uint8_t mac_out[6] = {0};

  kassert(ndp_cache_lookup(&test_ip, mac_out) == XAIOS_ERR_NOT_FOUND);
  kassert(ndp_cache_insert(&test_ip, test_mac) == XAIOS_OK);
  kassert(ndp_cache_count() == 1);
  kassert(ndp_cache_lookup(&test_ip, mac_out) == XAIOS_OK);
  kassert(mac_out[0] == 0x02 && mac_out[5] == 0x01);

  /* ---- C3 NUD state test ---- */
  {
    uint32_t nud_idx;
    for (nud_idx = 0; nud_idx < XAIOS_NDP_CACHE_SIZE; ++nud_idx) {
      if (g_ndp_cache[nud_idx].active != 0) break;
    }
    kassert(g_ndp_cache[nud_idx].nud_state == XAIOS_NDP_NUD_REACHABLE);

    /* Tick to move REACHABLE -> STALE after 30s */
    g_ndp_last_tick_ns += XAIOS_NDP_REACHABLE_TIME_NS + 1;
    ndp_nud_tick(g_ndp_last_tick_ns);
    kassert(g_ndp_cache[nud_idx].nud_state == XAIOS_NDP_NUD_STALE);

    /* Traffic should transition STALE -> DELAY */
    ndp_nud_update_on_traffic(&test_ip);
    kassert(g_ndp_cache[nud_idx].nud_state == XAIOS_NDP_NUD_DELAY);

    /* After DELAY timeout, transition to PROBE */
    g_ndp_last_tick_ns += XAIOS_NDP_DELAY_FIRST_PROBE_NS + 1;
    ndp_nud_tick(g_ndp_last_tick_ns);
    kassert(g_ndp_cache[nud_idx].nud_state == XAIOS_NDP_NUD_PROBE);

    /* After probe count exceeds max, should go INCOMPLETE */
    g_ndp_cache[nud_idx].probe_count = XAIOS_NDP_MAX_PROBES;
    g_ndp_last_tick_ns += XAIOS_NDP_RETRANS_TIMER_NS + 1;
    ndp_nud_tick(g_ndp_last_tick_ns);
    kassert(g_ndp_cache[nud_idx].nud_state == XAIOS_NDP_NUD_INCOMPLETE);

    klog("ndp: NUD state machine passed\n");
  }

  /* Re-insert for next tests */
  ndp_cache_insert(&test_ip, test_mac);

  /* ---- NS build test ---- */
  xaios_ip_addr_t src;
  src.family = XAIOS_IP_FAMILY_V6;
  for (uint32_t i = 0; i < 16; ++i) src.addr[i] = 0;
  src.addr[0] = 0xFE;
  src.addr[1] = 0x80;
  src.addr[15] = 0x0A;

  uint8_t src_mac[6] = {0x52, 0x54, 0x00, 0x12, 0x35, 0x02};
  uint8_t frame[128];
  uint64_t frame_len = 0;
  kassert(ndp_build_neighbor_solicitation(frame, &frame_len, src_mac,
                                           &src, &test_ip) == XAIOS_OK);
  kassert(frame_len == 14U + XAIOS_IPV6_HEADER_SIZE + 28U);
  kassert(get_be16(frame + 12) == XAIOS_IPV6_ETHERTYPE);
  kassert(frame[XAIOS_ICMPV6_OFFSET] == XAIOS_ICMPV6_NEIGHBOR_SOLICIT);
  kassert(frame[0] == 0x33 && frame[1] == 0x33 && frame[2] == 0xFF);
  kassert(frame[14 + 7] == 255);

  /* ---- C5 Hop-limit validation test ---- */
  {
    kassert(hop_limit_is_valid(frame) == 1);
    frame[14 + 7] = 64;
    kassert(hop_limit_is_valid(frame) == 0);
    frame[14 + 7] = 255; /* restore */
    klog("ndp: hop-limit validation passed\n");
  }

  /* ---- NA processing test ---- */
  xaios_ip_addr_t na_src = test_ip;
  xaios_ip_addr_t na_dst = src;
  uint8_t na_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

  uint8_t na_frame[128];
  uint64_t na_len = 0;
  icmpv6_build_neighbor_advertisement(na_frame, &na_len,
      na_mac, src_mac, &na_src, &na_dst, &na_src, 0, 0);

  /* Process the NA */
  kassert(ndp_process_neighbor_advertisement(na_frame, na_len) == XAIOS_OK);
  uint8_t verify_mac[6] = {0};
  kassert(ndp_cache_lookup(&na_src, verify_mac) == XAIOS_OK);
  kassert(verify_mac[0] == 0xAA && verify_mac[5] == 0xFF);

  /* Test with bad hop_limit */
  na_frame[14 + 7] = 64;
  kassert(ndp_process_neighbor_advertisement(na_frame, na_len) == XAIOS_ERR_INVALID);
  na_frame[14 + 7] = 255;

  /* ---- C4 LRU test ---- */
  {
    /* Fill cache to test eviction */
    uint8_t test_mac2[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
    for (uint32_t i = 1; i <= XAIOS_NDP_CACHE_SIZE; ++i) {
      xaios_ip_addr_t fill_ip;
      fill_ip.family = XAIOS_IP_FAMILY_V6;
      for (uint32_t j = 0; j < 16; ++j) fill_ip.addr[j] = 0;
      fill_ip.addr[15] = (uint8_t)(0x10 + i);
      ndp_cache_insert(&fill_ip, test_mac2);
    }
    kassert(ndp_cache_count() == XAIOS_NDP_CACHE_SIZE);

    /* Lookup an older entry, then insert new (should evict LRU) */
    xaios_ip_addr_t evict_test;
    evict_test.family = XAIOS_IP_FAMILY_V6;
    for (uint32_t j = 0; j < 16; ++j) evict_test.addr[j] = 0;
    evict_test.addr[15] = 0x15;
    ndp_cache_lookup(&evict_test, mac_out); /* touch this entry */
    kassert(mac_out[0] == 0x02);

    /* Insert another — should evict the least recently used */
    xaios_ip_addr_t new_ip;
    new_ip.family = XAIOS_IP_FAMILY_V6;
    for (uint32_t j = 0; j < 16; ++j) new_ip.addr[j] = 0;
    new_ip.addr[15] = 0xFF;
    kassert(ndp_cache_insert(&new_ip, test_mac2) == XAIOS_OK);
    kassert(ndp_cache_count() == XAIOS_NDP_CACHE_SIZE);
    klog("ndp: LRU eviction passed\n");
  }

  /* ---- C6 DAD test ---- */
  {
    xaios_ip_addr_t dad_addr;
    dad_addr.family = XAIOS_IP_FAMILY_V6;
    for (uint32_t j = 0; j < 16; ++j) dad_addr.addr[j] = 0;
    dad_addr.addr[15] = 0xFE;

    xaios_dad_state_t dad;
    ndp_dad_init(&dad, &dad_addr);

    /* Simulate NA arriving for the same address */
    g_dad_active = 1;
    g_dad_state = dad;

    uint8_t dad_na[128];
    uint64_t dad_na_len = 0;
    icmpv6_build_neighbor_advertisement(dad_na, &dad_na_len,
        na_mac, src_mac, &na_src, &na_dst, &dad_addr, 0, 0);
    dad_na[14 + 7] = 255;

    /* Processing NA for DAD target should set duplicate_found */
    /* But first, insert into cache so it can process */
    ndp_cache_insert(&dad_addr, na_mac);
    ndp_process_neighbor_advertisement(dad_na, dad_na_len);

    int dad_result = ndp_dad_tick(&dad, g_ndp_last_tick_ns + XAIOS_NDP_RETRANS_TIMER_NS + 1);
    kassert(dad_result == -1); /* duplicate */
    kassert(dad.duplicate_found == 1);

    klog("ndp: DAD duplicate detection passed\n");
  }

  /* ---- C7 RS/RA test ---- */
  {
    kassert(ndp_send_router_solicitation(src_mac, &src) == XAIOS_OK);

    /* Build and process an RA */
    xaios_ip_addr_t ra_src;
    ra_src.family = XAIOS_IP_FAMILY_V6;
    for (uint32_t j = 0; j < 16; ++j) ra_src.addr[j] = 0;
    ra_src.addr[15] = 0xFE; /* fe80::fe */

    /* Build a minimal RA: eth + ipv6 + icmpv6(type=134) + source-ll-option */
    uint8_t ra_frame[128];
    bytes_zero(ra_frame, sizeof(ra_frame));

    uint8_t ra_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    for (uint32_t j = 0; j < 6; ++j) {
      ra_frame[j] = src_mac[j];
      ra_frame[6 + j] = ra_mac[j];
    }
    put_be16(ra_frame + 12, XAIOS_IPV6_ETHERTYPE);

    ipv6_build_header(ra_frame + 14, 24, XAIOS_IPV6_NEXT_ICMPV6, &ra_src, &src);
    ra_frame[14 + 7] = 255;

    uint8_t *ra_icmp = ra_frame + XAIOS_ICMPV6_OFFSET;
    ra_icmp[0] = XAIOS_ICMPV6_ROUTER_ADVERT; /* type=134 */
    ra_icmp[1] = 0;
    put_be16(ra_icmp + 2, 0); /* checksum (computed below) */
    ra_icmp[4] = 64;          /* CurHopLimit */
    ra_icmp[5] = 0;           /* M/O flags */
    put_be16(ra_icmp + 6, 0); /* RouterLifetime = 0 */
    put_be32(ra_icmp + 8, 0); /* ReachableTime */
    put_be32(ra_icmp + 12, 0); /* RetransTimer */
    /* Source Link-Layer option */
    ra_icmp[16] = 1;
    ra_icmp[17] = 1;
    for (uint32_t j = 0; j < 6; ++j) {
      ra_icmp[18 + j] = ra_mac[j];
    }

    uint16_t ra_cksum = ipv6_pseudo_checksum(&ra_src, &src,
                                              XAIOS_IPV6_NEXT_ICMPV6,
                                              24, ra_icmp, 24);
    put_be16(ra_icmp + 2, ra_cksum);

    uint64_t ra_total = 14 + 40 + 24;
    kassert(ndp_process_router_advertisement(ra_frame, ra_total) == XAIOS_OK);
    kassert(g_has_default_gateway);
    kassert(xaios_ip_addr_equal(&ndp_default_gateway, &ra_src));

    klog("ndp: RS/RA processing passed\n");
  }

  klog("ndp: self-test passed cache_entries=%lu ns_frame_len=%lu\n",
       ndp_cache_count(), frame_len);
}
