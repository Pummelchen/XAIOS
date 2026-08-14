#include <xaios/arp.h>
#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/net_device.h>
#include <xaios/ipv4.h>

static xaios_arp_entry_t g_arp_cache[XAIOS_ARP_CACHE_SIZE];

static void bytes_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0; i < size; ++i) { bytes[i] = 0; }
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

static uint32_t get_be32(const uint8_t *src) {
  return ((uint32_t)src[0] << 24U) | ((uint32_t)src[1] << 16U) |
         ((uint32_t)src[2] << 8U) | (uint32_t)src[3];
}

void arp_init(void) {
  for (uint32_t i = 0; i < XAIOS_ARP_CACHE_SIZE; ++i) {
    g_arp_cache[i].active = 0;
    g_arp_cache[i].ip = 0;
    g_arp_cache[i].age_ns = 0;
    g_arp_cache[i].last_use_ns = 0;
    bytes_zero(g_arp_cache[i].mac, 6);
  }
  klog("arp: cache initialized slots=%u\n", XAIOS_ARP_CACHE_SIZE);
}

/* B3-B4: Lookup with LRU update (touch last_use_ns) */
xaios_status_t arp_cache_lookup(uint32_t ip, uint8_t mac[6]) {
  extern uint64_t timer_now_ns(void);
  if (mac == 0) { return XAIOS_ERR_INVALID; }

  uint32_t found_idx = XAIOS_ARP_CACHE_SIZE;
  for (uint32_t i = 0; i < XAIOS_ARP_CACHE_SIZE; ++i) {
    if (g_arp_cache[i].active != 0 && g_arp_cache[i].ip == ip) {
      found_idx = i;
      break;
    }
  }

  if (found_idx >= XAIOS_ARP_CACHE_SIZE) {
    return XAIOS_ERR_NOT_FOUND;
  }

  for (uint32_t j = 0; j < 6; ++j) {
    mac[j] = g_arp_cache[found_idx].mac[j];
  }

  /* Update LRU timestamp and move to front */
  g_arp_cache[found_idx].last_use_ns = timer_now_ns();

  /* Move this entry to index 0 (most recently used) */
  xaios_arp_entry_t tmp;
  for (uint32_t j = 0; j < 6; ++j) { tmp.mac[j] = g_arp_cache[found_idx].mac[j]; }
  tmp.ip = g_arp_cache[found_idx].ip;
  tmp.active = g_arp_cache[found_idx].active;
  tmp.age_ns = g_arp_cache[found_idx].age_ns;
  tmp.last_use_ns = g_arp_cache[found_idx].last_use_ns;

  /* Shift entries up to fill the gap */
  for (uint32_t i = found_idx; i > 0; --i) {
    g_arp_cache[i] = g_arp_cache[i - 1U];
  }

  g_arp_cache[0] = tmp;

  return XAIOS_OK;
}

xaios_status_t arp_cache_insert(uint32_t ip, const uint8_t mac[6]) {
  extern uint64_t timer_now_ns(void);
  if (mac == 0) { return XAIOS_ERR_INVALID; }

  uint64_t now = timer_now_ns();

  /* Update existing */
  for (uint32_t i = 0; i < XAIOS_ARP_CACHE_SIZE; ++i) {
    if (g_arp_cache[i].active != 0 && g_arp_cache[i].ip == ip) {
      for (uint32_t j = 0; j < 6; ++j) { g_arp_cache[i].mac[j] = mac[j]; }
      g_arp_cache[i].age_ns = now;
      g_arp_cache[i].last_use_ns = now;
      return XAIOS_OK;
    }
  }

  /* Find free slot or LRU victim */
  uint32_t slot = XAIOS_ARP_CACHE_SIZE;
  for (uint32_t i = 0; i < XAIOS_ARP_CACHE_SIZE; ++i) {
    if (g_arp_cache[i].active == 0) {
      slot = i;
      break;
    }
  }

  if (slot >= XAIOS_ARP_CACHE_SIZE) {
    /* Evict LRU */
    uint64_t oldest = UINT64_MAX;
    for (uint32_t i = 0; i < XAIOS_ARP_CACHE_SIZE; ++i) {
      if (g_arp_cache[i].active != 0 && g_arp_cache[i].last_use_ns < oldest) {
        oldest = g_arp_cache[i].last_use_ns;
        slot = i;
      }
    }
  }

  g_arp_cache[slot].ip = ip;
  g_arp_cache[slot].active = 1;
  g_arp_cache[slot].age_ns = now;
  g_arp_cache[slot].last_use_ns = now;
  for (uint32_t j = 0; j < 6; ++j) { g_arp_cache[slot].mac[j] = mac[j]; }

  klog("arp: cached ip=%u.%u.%u.%u mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
       (ip >> 24U) & 0xff, (ip >> 16U) & 0xff, (ip >> 8U) & 0xff,
       ip & 0xff, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return XAIOS_OK;
}

/* B3-B4: Age cache — remove entries older than XAIOS_ARP_TIMEOUT_SEC */
void arp_cache_age(void) {
  extern uint64_t timer_now_ns(void);
  uint64_t now = timer_now_ns();
  uint64_t timeout_ns = (uint64_t)XAIOS_ARP_TIMEOUT_SEC * UINT64_C(1000000000);
  uint32_t removed = 0;

  for (uint32_t i = 0; i < XAIOS_ARP_CACHE_SIZE; ++i) {
    if (g_arp_cache[i].active != 0) {
      uint64_t age = now - g_arp_cache[i].age_ns;
      if (age > timeout_ns) {
        g_arp_cache[i].active = 0;
        ++removed;
      }
    }
  }

  if (removed > 0) {
    klog("arp: aged %u stale entries\n", removed);
  }
}

/* B3-B4: Send gratuitous ARP for our IP */
xaios_status_t arp_send_gratuitous(const uint8_t local_mac[6], uint32_t local_ip) {
  if (local_mac == 0) { return XAIOS_ERR_INVALID; }

  uint8_t frame[42];
  uint64_t frame_len = 0;

  bytes_zero(frame, 42);
  for (uint32_t i = 0; i < 6; ++i) {
    frame[i] = 0xff;
    frame[6 + i] = local_mac[i];
  }
  put_be16(frame + 12, 0x0806);
  put_be16(frame + 14, XAIOS_ARP_ETHERNET);
  put_be16(frame + 16, XAIOS_ARP_IPV4);
  frame[18] = 6;
  frame[19] = 4;
  put_be16(frame + 20, XAIOS_ARP_OP_REQUEST);
  for (uint32_t i = 0; i < 6; ++i) { frame[22 + i] = local_mac[i]; }
  put_be32(frame + 28, local_ip);
  for (uint32_t i = 0; i < 6; ++i) { frame[32 + i] = local_mac[i]; }
  put_be32(frame + 38, local_ip);
  frame_len = 42;

  /* Insert self into cache */
  arp_cache_insert(local_ip, local_mac);

  return network_device_tx(frame, frame_len);
}

xaios_status_t arp_build_request(uint8_t *frame, uint64_t *frame_len,
                                 const uint8_t src_mac[6], uint32_t src_ip,
                                 uint32_t target_ip) {
  if (frame == 0 || frame_len == 0 || src_mac == 0) {
    return XAIOS_ERR_INVALID;
  }
  bytes_zero(frame, 42);
  for (uint32_t i = 0; i < 6; ++i) {
    frame[i] = 0xff;
    frame[6 + i] = src_mac[i];
  }
  put_be16(frame + 12, 0x0806);
  put_be16(frame + 14, XAIOS_ARP_ETHERNET);
  put_be16(frame + 16, XAIOS_ARP_IPV4);
  frame[18] = 6;
  frame[19] = 4;
  put_be16(frame + 20, XAIOS_ARP_OP_REQUEST);
  for (uint32_t i = 0; i < 6; ++i) { frame[22 + i] = src_mac[i]; }
  put_be32(frame + 28, src_ip);
  put_be32(frame + 38, target_ip);
  *frame_len = 42;
  return XAIOS_OK;
}

xaios_status_t arp_process_reply(const uint8_t *frame, uint64_t frame_len) {
  if (frame == 0 || frame_len < 42) { return XAIOS_ERR_INVALID; }
  if (get_be16(frame + 12) != 0x0806) { return XAIOS_ERR_INVALID; }
  if (get_be16(frame + 20) != XAIOS_ARP_OP_REPLY) { return XAIOS_ERR_INVALID; }
  uint32_t sender_ip = get_be32(frame + 28);
  const uint8_t *sender_mac = frame + 22;
  return arp_cache_insert(sender_ip, sender_mac);
}

xaios_status_t arp_build_reply(uint8_t *frame, uint64_t *frame_len,
                               const uint8_t src_mac[6], uint32_t src_ip,
                               const uint8_t dst_mac[6], uint32_t dst_ip) {
  if (frame == 0 || frame_len == 0 || src_mac == 0 || dst_mac == 0) {
    return XAIOS_ERR_INVALID;
  }
  bytes_zero(frame, 42);
  for (uint32_t i = 0; i < 6; ++i) {
    frame[i] = dst_mac[i];
    frame[6 + i] = src_mac[i];
  }
  put_be16(frame + 12, 0x0806);
  put_be16(frame + 14, XAIOS_ARP_ETHERNET);
  put_be16(frame + 16, XAIOS_ARP_IPV4);
  frame[18] = 6;
  frame[19] = 4;
  put_be16(frame + 20, XAIOS_ARP_OP_REPLY);
  for (uint32_t i = 0; i < 6; ++i) { frame[22 + i] = src_mac[i]; }
  put_be32(frame + 28, src_ip);
  for (uint32_t i = 0; i < 6; ++i) { frame[32 + i] = dst_mac[i]; }
  put_be32(frame + 38, dst_ip);
  *frame_len = 42;
  return XAIOS_OK;
}

uint64_t arp_cache_count(void) {
  uint64_t count = 0;
  for (uint32_t i = 0; i < XAIOS_ARP_CACHE_SIZE; ++i) {
    if (g_arp_cache[i].active != 0) { ++count; }
  }
  return count;
}

xaios_status_t arp_cache_snapshot(uint32_t index, xaios_arp_entry_t *entry) {
  uint32_t ordinal = 0U;
  if (entry == 0) return XAIOS_ERR_INVALID;
  for (uint32_t i = 0U; i < XAIOS_ARP_CACHE_SIZE; ++i) {
    if (g_arp_cache[i].active == 0U) continue;
    if (ordinal++ == index) {
      *entry = g_arp_cache[i];
      return XAIOS_OK;
    }
  }
  return XAIOS_ERR_NOT_FOUND;
}

void arp_self_test(void) {
  arp_init();
  kassert(arp_cache_count() == 0);

  uint8_t mac1[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
  uint8_t mac_out[6] = {0};

  kassert(arp_cache_lookup(0x0a000202, mac_out) == XAIOS_ERR_NOT_FOUND);
  kassert(arp_cache_insert(0x0a000202, mac1) == XAIOS_OK);
  kassert(arp_cache_count() == 1);
  kassert(arp_cache_lookup(0x0a000202, mac_out) == XAIOS_OK);
  kassert(mac_out[0] == 0x02 && mac_out[5] == 0x01);

  uint8_t frame[64];
  uint64_t frame_len = 0;
  kassert(arp_build_request(frame, &frame_len, mac1, 0x0a00020f,
                             0x0a000202) == XAIOS_OK);
  kassert(frame_len == 42);
  kassert(get_be16(frame + 12) == 0x0806);
  kassert(get_be16(frame + 20) == XAIOS_ARP_OP_REQUEST);

  uint8_t reply[42];
  bytes_zero(reply, 42);
  put_be16(reply + 12, 0x0806);
  put_be16(reply + 14, XAIOS_ARP_ETHERNET);
  put_be16(reply + 16, XAIOS_ARP_IPV4);
  reply[18] = 6;
  reply[19] = 4;
  put_be16(reply + 20, XAIOS_ARP_OP_REPLY);
  uint8_t gw_mac[6] = {0x52, 0x54, 0x00, 0x12, 0x35, 0x02};
  for (uint32_t i = 0; i < 6; ++i) { reply[22 + i] = gw_mac[i]; }
  put_be32(reply + 28, 0x0a000202);
  kassert(arp_process_reply(reply, 42) == XAIOS_OK);
  kassert(arp_cache_count() == 1);

  uint8_t gw_out[6] = {0};
  kassert(arp_cache_lookup(0x0a000202, gw_out) == XAIOS_OK);
  kassert(gw_out[0] == 0x52 && gw_out[5] == 0x02);

  uint8_t rep_frame[64];
  uint64_t rep_len = 0;
  kassert(arp_build_reply(rep_frame, &rep_len, mac1, 0x0a00020f, gw_mac,
                           0x0a000202) == XAIOS_OK);
  kassert(rep_len == 42);
  kassert(get_be16(rep_frame + 20) == XAIOS_ARP_OP_REPLY);

  /* B3-B4: Test aging */
  arp_cache_age();
  kassert(arp_cache_count() >= 1); /* entries are fresh */

  /* B3-B4: Test gratuitous ARP build (can't test tx without virtio) */
  uint8_t gratuitous[42];
  uint64_t grat_len = 0;
  kassert(arp_build_request(gratuitous, &grat_len, mac1, 0x0a00020f,
                             0x0a00020f) == XAIOS_OK);
  kassert(grat_len == 42);

  klog("arp: self-test passed cache_entries=%lu\n", arp_cache_count());
}
