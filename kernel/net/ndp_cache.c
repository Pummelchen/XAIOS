#include <xaios/assert.h>
#include <xaios/icmpv6.h>
#include <xaios/ip_addr.h>
#include <xaios/ipv6.h>
#include <xaios/klog.h>
#include <xaios/ndp.h>
#include <xaios/net_device.h>

#include "ndp_internal.h"

xaios_ndp_entry_t g_ndp_cache[XAIOS_NDP_CACHE_SIZE];
uint64_t g_ndp_last_tick_ns = 0;

void ndp_bytes_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0; i < size; ++i) {
    bytes[i] = 0;
  }
}

void ndp_put_be16(uint8_t *dst, uint16_t value) {
  dst[0] = (uint8_t)(value >> 8U);
  dst[1] = (uint8_t)value;
}

uint16_t ndp_get_be16(const uint8_t *src) {
  return (uint16_t)(((uint16_t)src[0] << 8U) | src[1]);
}

void ndp_put_be32(uint8_t *dst, uint32_t value) {
  dst[0] = (uint8_t)(value >> 24U);
  dst[1] = (uint8_t)(value >> 16U);
  dst[2] = (uint8_t)(value >> 8U);
  dst[3] = (uint8_t)value;
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
  ndp_bytes_zero(g_ndp_cache[idx].mac, 6);
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
    ndp_bytes_zero(g_ndp_cache[i].mac, 6);
  }
  xaios_ip_addr_zero(&ndp_default_gateway);
  g_ndp_has_default_gateway = 0;
  g_ndp_dad_active = 0;
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

uint64_t ndp_cache_count(void) {
  uint64_t count = 0;
  for (uint32_t i = 0; i < XAIOS_NDP_CACHE_SIZE; ++i) {
    if (g_ndp_cache[i].active != 0) {
      ++count;
    }
  }
  return count;
}

xaios_status_t ndp_cache_snapshot(uint32_t index, xaios_ndp_entry_t *entry) {
  uint32_t ordinal = 0U;
  if (entry == 0) return XAIOS_ERR_INVALID;
  for (uint32_t i = 0U; i < XAIOS_NDP_CACHE_SIZE; ++i) {
    if (g_ndp_cache[i].active == 0U) continue;
    if (ordinal++ == index) {
      *entry = g_ndp_cache[i];
      return XAIOS_OK;
    }
  }
  return XAIOS_ERR_NOT_FOUND;
}
