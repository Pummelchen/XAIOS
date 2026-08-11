#include <xaios/assert.h>
#include <xaios/ipv4.h>
#include <xaios/klog.h>
#include <xaios/routing.h>

static routing_entry_t g_routing_table[ROUTING_TABLE_SIZE];

void routing_init(void) {
  for (uint32_t i = 0; i < ROUTING_TABLE_SIZE; ++i) {
    g_routing_table[i].active = 0;
    g_routing_table[i].dest_network = 0;
    g_routing_table[i].netmask = 0;
    g_routing_table[i].gateway = 0;
  }

  uint32_t local_net = 0x0a000200U;   /* 10.0.2.0 network byte order */
  uint32_t local_mask = 0xffffff00U;  /* 255.255.255.0 */
  routing_add(local_net, local_mask, 0);

  uint32_t gateway = XAIOS_IPV4_GATEWAY;
  routing_add(0x00000000U, 0x00000000U, gateway);

  klog("routing: initialized (local=%08x/24 gw=%08x)\n",
       local_net, gateway);
}

xaios_status_t routing_add(uint32_t dest_network, uint32_t netmask,
                            uint32_t gateway) {
  for (uint32_t i = 0; i < ROUTING_TABLE_SIZE; ++i) {
    if (g_routing_table[i].active == 0) {
      g_routing_table[i].dest_network = dest_network & netmask;
      g_routing_table[i].netmask = netmask;
      g_routing_table[i].gateway = gateway;
      g_routing_table[i].active = 1;
      return XAIOS_OK;
    }
  }
  return XAIOS_ERR_NO_MEMORY;
}

/* B5: Remove route by matching destination network */
xaios_status_t routing_remove(uint32_t dest_ip_net_order) {
  for (uint32_t i = 0; i < ROUTING_TABLE_SIZE; ++i) {
    if (g_routing_table[i].active != 0) {
      uint32_t masked = dest_ip_net_order & g_routing_table[i].netmask;
      if (masked == g_routing_table[i].dest_network) {
        g_routing_table[i].active = 0;
        return XAIOS_OK;
      }
    }
  }
  return XAIOS_ERR_NOT_FOUND;
}

/* B5: Remove all routes */
void routing_clear(void) {
  for (uint32_t i = 0; i < ROUTING_TABLE_SIZE; ++i) {
    g_routing_table[i].active = 0;
    g_routing_table[i].dest_network = 0;
    g_routing_table[i].netmask = 0;
    g_routing_table[i].gateway = 0;
  }
  klog("routing: table cleared\n");
}

uint32_t routing_lookup(uint32_t dest_ip) {
  uint32_t best_match = UINT32_MAX;
  uint32_t best_prefix_len = 0;
  int found = 0;

  for (uint32_t i = 0; i < ROUTING_TABLE_SIZE; ++i) {
    if (g_routing_table[i].active == 0) { continue; }
    uint32_t masked = dest_ip & g_routing_table[i].netmask;
    if (masked == g_routing_table[i].dest_network) {
      uint32_t mask = g_routing_table[i].netmask;
      uint32_t prefix_len = 0;
      while (mask != 0) {
        prefix_len += (mask & 1U);
        mask >>= 1U;
      }
      if (prefix_len > best_prefix_len || !found) {
        best_match = i;
        best_prefix_len = prefix_len;
        found = 1;
      }
    }
  }

  if (!found) { return 0; }
  if (g_routing_table[best_match].gateway == 0) {
    return dest_ip;
  }
  return g_routing_table[best_match].gateway;
}

uint32_t routing_count(void) {
  uint32_t count = 0U;
  for (uint32_t i = 0U; i < ROUTING_TABLE_SIZE; ++i) {
    if (g_routing_table[i].active != 0U) ++count;
  }
  return count;
}

xaios_status_t routing_snapshot(uint32_t index, routing_entry_t *entry) {
  uint32_t ordinal = 0U;
  if (entry == 0) return XAIOS_ERR_INVALID;
  for (uint32_t i = 0U; i < ROUTING_TABLE_SIZE; ++i) {
    if (g_routing_table[i].active == 0U) continue;
    if (ordinal++ == index) {
      *entry = g_routing_table[i];
      return XAIOS_OK;
    }
  }
  return XAIOS_ERR_NOT_FOUND;
}

void routing_self_test(void) {
  routing_init();

  uint32_t local_host = 0x0a000205U;
  uint32_t next_hop = routing_lookup(local_host);
  kassert(next_hop == local_host);

  uint32_t external = 0x08080808U;
  next_hop = routing_lookup(external);
  kassert(next_hop == XAIOS_IPV4_GATEWAY);

  next_hop = routing_lookup(XAIOS_IPV4_GUEST_IP);
  kassert(next_hop == XAIOS_IPV4_GUEST_IP);

  /* B5: Test routing_remove */
  kassert(routing_remove(0x0a000200U) == XAIOS_OK);
  next_hop = routing_lookup(local_host);
  kassert(next_hop == XAIOS_IPV4_GATEWAY); /* falls back to default */

  /* B5: Test routing_clear */
  routing_clear();
  next_hop = routing_lookup(external);
  kassert(next_hop == 0); /* no more routes */

  klog("routing: self-test passed\n");
}
