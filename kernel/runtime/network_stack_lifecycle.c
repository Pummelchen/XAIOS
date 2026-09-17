/*
 * The stack lifecycle and the readiness generation, moved out of
 * network_stack.c. See network_stack_lifecycle.h: the boot entry points run
 * single-threaded from kmain, they took no lock before and take none now, and
 * every seed they call into network_stack.c replaces a direct write that was
 * made at the same point in the same order.
 */

#include "network_stack_lifecycle.h"

#include "network_stack_icmp.h"
#include "network_stack_listener.h"
#include "network_stack_packet.h"
#include "network_stack_poll.h"
#include "network_stack_selftest.h"
#include "network_stack_tcp_stats.h"
#include "network_stack_udp.h"
#include "network_stack_v6.h"
#include "network_stack_wire.h"

#include <xaios/arp.h>
#include <xaios/assert.h>
#include <xaios/ip_addr.h>
#include <xaios/ipv4.h>
#include <xaios/ipv6.h>
#include <xaios/klog.h>
#include <xaios/ndp.h>
#include <xaios/net_device.h>
#include <xaios/network_stack.h>
#include <xaios/ntp.h>
#include <xaios/routing.h>
#include <xaios/socket_buffer.h>

void network_stack_init(void) {
  net_tcp_drain_cursor_reset();
  socket_map_reset_exhausted();
  net_poll_reset_gap();
  net_packet_reset();

  net_tcp_table_init();

  net_udp_reset();

  for (uint32_t i = 0; i < network_listener_slot_count(); ++i) {
    network_listener_ex_t row;
    net_wire_bytes_zero(&row, sizeof(row));
    network_listener_slot_write(i, &row);
  }

  net_stack_flow_id_reset();
  net_tcp_stats_reset();

  klog("network: stack initialized\n");
}

void network_init_persistent(void) {
  if (net_stack_persistent_ready() != 0) {
    return;
  }
  uint8_t mac[6];
  net_stack_local_mac(mac);
  if (network_device_get_mac(mac) == XAIOS_OK) {
    klog("network: local mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
         mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  }
  /* The driver wrote g_local_mac in place before; a driver that refuses may
     still have touched only part of the buffer, so the copy goes back
     unconditionally, exactly as the direct write would have left it. */
  net_stack_local_mac_set(mac);
  arp_init();
  ndp_init();
  ntp_init();
  ipv4_frag_init();
  ipv6_frag_init();
  net_tcp_table_clear_active();
  net_udp_clear_active();
  for (uint32_t i = 0; i < network_listener_slot_count(); ++i) {
    network_listener_ex_t row;
    net_wire_bytes_zero(&row, sizeof(row));
    network_listener_slot_write(i, &row);
  }
  for (uint32_t i = 0; i < socket_map_slot_count(); ++i) {
    socket_flow_mapping_t row;
    net_wire_bytes_zero(&row, sizeof(row));
    socket_map_slot_write(i, &row);
  }
  /* The boot self-test fills this table on purpose and leaves its refusals
     counted. Zero them here so a non-zero figure in a running machine means
     a running machine ran out. */
  socket_map_reset_exhausted();
  net_poll_reset_gap();
  net_tcp_half_open_reset();
  net_tcp_drain_cursor_reset();
  sockbuf_pool_init();
  routing_init();
  if (network_stack_queue_bindings() == 0U) {
    kassert(network_stack_bind_queue(0, 1, 1U) == XAIOS_OK);
  }
  net_v6_init(mac);
  net_stack_mark_persistent_ready();
  net_poll_reset_ticks();
  net_icmp_reset();
  net_stack_reset_ipv6_rx();
  /* RFC 4861 has a host solicit a router on startup rather than wait for the
     next unsolicited advertisement, which may be minutes away or never come.
     Without this the stack has a link-local address and no global one, and
     IPv6 works only on the local link. */
  xaios_ip_addr_t link_local_v6;
  net_v6_link_local(&link_local_v6);
  if (ndp_send_router_solicitation(mac, &link_local_v6) !=
      XAIOS_OK) {
    klog("network: router solicitation could not be sent\n");
  }
  klog("network: persistent mode initialized (dual-stack)\n");
}

/* The readiness generation: one counter the poll loop and the listener
   registry nudge when something a waiter could be waiting on has changed. The
   only operation is the relaxed atomic bump the old code made in place. */
static volatile uint64_t g_readiness_generation;

void network_readiness_note(void) {
  __atomic_add_fetch(&g_readiness_generation, 1U, __ATOMIC_RELAXED);
}

uint64_t network_readiness_generation(void) {
  return __atomic_load_n(&g_readiness_generation, __ATOMIC_RELAXED);
}
