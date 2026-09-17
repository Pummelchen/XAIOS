#include <xaios/assert.h>
#include <xaios/icmpv6.h>
#include <xaios/ip_addr.h>
#include <xaios/ipv6.h>
#include <xaios/klog.h>
#include <xaios/ndp.h>
#include <xaios/net_device.h>

#include "ndp_internal.h"

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
  kassert(ndp_get_be16(frame + 12) == XAIOS_IPV6_ETHERTYPE);
  kassert(frame[XAIOS_ICMPV6_OFFSET] == XAIOS_ICMPV6_NEIGHBOR_SOLICIT);
  kassert(frame[0] == 0x33 && frame[1] == 0x33 && frame[2] == 0xFF);
  kassert(frame[14 + 7] == 255);

  /* ---- C5 Hop-limit validation test ---- */
  {
    kassert(ndp_hop_limit_is_valid(frame) == 1);
    frame[14 + 7] = 64;
    kassert(ndp_hop_limit_is_valid(frame) == 0);
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
    g_ndp_dad_active = 1;
    g_ndp_dad_state = dad;

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
    uint8_t rs_probe[128];
    uint64_t rs_len = 0U;
    kassert(ndp_build_router_solicitation(rs_probe, sizeof(rs_probe), &rs_len,
                                      src_mac, &src) == XAIOS_OK);
    kassert(rs_len == 14U + XAIOS_IPV6_HEADER_SIZE + 12U);
    kassert(rs_probe[0] == 0x33U && rs_probe[1] == 0x33U &&
            rs_probe[5] == 0x02U);
    kassert(rs_probe[XAIOS_ICMPV6_OFFSET] == XAIOS_ICMPV6_ROUTER_SOLICIT);
    kassert(rs_probe[XAIOS_ICMPV6_OFFSET + 4U] == 1U);

    /* Build and process an RA */
    xaios_ip_addr_t ra_src;
    ra_src.family = XAIOS_IP_FAMILY_V6;
    for (uint32_t j = 0; j < 16; ++j) ra_src.addr[j] = 0;
    ra_src.addr[0] = 0xFE;
    ra_src.addr[1] = 0x80;
    ra_src.addr[15] = 0xFE; /* fe80::fe */

    /* Build a minimal RA: eth + ipv6 + icmpv6(type=134) + source-ll-option */
    uint8_t ra_frame[128];
    ndp_bytes_zero(ra_frame, sizeof(ra_frame));

    uint8_t ra_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    for (uint32_t j = 0; j < 6; ++j) {
      ra_frame[j] = src_mac[j];
      ra_frame[6 + j] = ra_mac[j];
    }
    ndp_put_be16(ra_frame + 12, XAIOS_IPV6_ETHERTYPE);

    ipv6_build_header(ra_frame + 14, 24, XAIOS_IPV6_NEXT_ICMPV6, &ra_src, &src);
    ra_frame[14 + 7] = 255;

    uint8_t *ra_icmp = ra_frame + XAIOS_ICMPV6_OFFSET;
    ra_icmp[0] = XAIOS_ICMPV6_ROUTER_ADVERT; /* type=134 */
    ra_icmp[1] = 0;
    ndp_put_be16(ra_icmp + 2, 0); /* checksum (computed below) */
    ra_icmp[4] = 64;          /* CurHopLimit */
    ra_icmp[5] = 0;           /* M/O flags */
    ndp_put_be16(ra_icmp + 6, 0); /* RouterLifetime = 0 */
    ndp_put_be32(ra_icmp + 8, 0); /* ReachableTime */
    ndp_put_be32(ra_icmp + 12, 0); /* RetransTimer */
    /* Source Link-Layer option */
    ra_icmp[16] = 1;
    ra_icmp[17] = 1;
    for (uint32_t j = 0; j < 6; ++j) {
      ra_icmp[18 + j] = ra_mac[j];
    }

    uint16_t ra_cksum = ipv6_pseudo_checksum(&ra_src, &src,
                                              XAIOS_IPV6_NEXT_ICMPV6,
                                              24, ra_icmp, 24);
    ndp_put_be16(ra_icmp + 2, ra_cksum);

    uint64_t ra_total = 14 + 40 + 24;
    kassert(ndp_process_router_advertisement(ra_frame, ra_total) == XAIOS_OK);
    kassert(g_ndp_has_default_gateway);
    kassert(xaios_ip_addr_equal(&ndp_default_gateway, &ra_src));

    klog("ndp: RS/RA processing passed\n");
  }

  klog("ndp: self-test passed cache_entries=%lu ns_frame_len=%lu\n",
       ndp_cache_count(), frame_len);
}
