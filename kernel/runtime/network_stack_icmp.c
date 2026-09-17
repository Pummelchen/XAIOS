/*
 * The link-reply and ping plane -- ARP replies, the ICMP and ICMPv6 echo and
 * neighbour replies, and the ping request/status/expiry state that the ICMPv4
 * half serves -- moved verbatim out of network_stack.c.
 *
 * The three frame handlers were the branches of network_poll_tick_locked()'s
 * receive dispatch that answer a peer rather than feed a flow. They read the
 * interface MAC, which network_stack.c owns, so the caller passes its copy in
 * as `local_mac`; none of them takes a lock, exactly as before, because the
 * poll already holds the stack guard. The ping state and the four reply
 * counters came with them; the one counter accessor that did not,
 * network_ipv6_rx_count(), counts every IPv6 frame rather than a reply and
 * stays in network_stack.c.
 *
 * The one early exit these branches had: when an ICMP echo reply matches the
 * outstanding ping, the old code returned from the whole poll, skipping that
 * tick's retransmit/expire/drain tail. net_icmp_handle_ipv4() reports the same
 * case as its non-zero return and the caller returns, so the tail is skipped
 * exactly where it was skipped before. Everything else falls through as it
 * did.
 *
 * network_stack_ping_start() read the "persistent mode has started" flag
 * directly; it is network_stack.c's flag, so this file asks for it through
 * net_stack_persistent_ready(), which is the same test. The ping entry points
 * are public and take no lock, before and after.
 */

#include "network_stack_icmp.h"

#include <xaios/arp.h>
#include <xaios/icmp.h>
#include <xaios/icmpv6.h>
#include <xaios/ip_addr.h>
#include <xaios/ipv4.h>
#include <xaios/ndp.h>
#include <xaios/net_device.h>
#include <xaios/network_config.h>
#include <xaios/network_stack.h>
#include <xaios/timer.h>

#include "network_stack_udp.h"
#include "network_stack_v6.h"
#include "network_stack_wire.h"

#define NETWORK_PING_IDENTIFIER UINT16_C(0x5841)
#define NETWORK_PING_TIMEOUT_NS UINT64_C(3000000000)

static xaios_network_ping_status_t g_ping;
static uint64_t g_ping_sent_ns;
static uint16_t g_ping_sequence;

static uint64_t g_icmp_reply_count;
static uint64_t g_arp_reply_count;
static uint64_t g_icmpv6_reply_count;
static uint64_t g_ndp_reply_count;

xaios_status_t network_stack_ping_start(uint32_t target_ip) {
  uint8_t frame[50];
  uint8_t gateway_mac[6];
  uint8_t local_mac[6];
  if (net_stack_persistent_ready() == 0U || target_ip == 0U)
    return XAIOS_ERR_INVALID;
  if (g_ping.state == XAIOS_NETWORK_PING_PENDING) return XAIOS_ERR_BUSY;
  network_config_gateway_mac(gateway_mac);
  net_stack_local_mac(local_mac);
  for (uint32_t i = 0U; i < sizeof(frame); ++i) frame[i] = 0U;
  for (uint32_t i = 0U; i < 6U; ++i) {
    frame[i] = gateway_mac[i];
    frame[6U + i] = local_mac[i];
  }
  net_wire_write_be16(frame + 12U, NETWORK_ETHERTYPE_IPV4);
  ipv4_build_header(frame + 14U, 36U, XAIOS_IPV4_PROTO_ICMP,
                    network_config_local_ipv4(), target_ip);
  uint8_t *icmp = frame + 34U;
  icmp[0] = XAIOS_ICMP_ECHO_REQUEST;
  icmp[1] = 0U;
  net_wire_write_be16(icmp + 4U, NETWORK_PING_IDENTIFIER);
  ++g_ping_sequence;
  net_wire_write_be16(icmp + 6U, g_ping_sequence);
  icmp[8] = 'X'; icmp[9] = 'A'; icmp[10] = 'I'; icmp[11] = 'O';
  icmp[12] = 'S'; icmp[13] = 'P'; icmp[14] = 'N'; icmp[15] = 'G';
  net_wire_write_be16(icmp + 2U, ipv4_checksum(icmp, 16U));
  xaios_status_t status = network_device_tx(frame, sizeof(frame));
  g_ping.state = status == XAIOS_OK ? XAIOS_NETWORK_PING_PENDING
                                     : XAIOS_NETWORK_PING_FAILED;
  g_ping.target_ip = target_ip;
  g_ping.attempts = 1U;
  g_ping.round_trip_ns = 0U;
  g_ping.last_error = status;
  g_ping_sent_ns = timer_now_ns();
  return status == XAIOS_OK ? XAIOS_ERR_BUSY : status;
}

xaios_network_ping_status_t network_stack_ping_status(void) { return g_ping; }

void net_ping_expire(uint64_t now_ns) {
  if (g_ping.state == XAIOS_NETWORK_PING_PENDING && now_ns >= g_ping_sent_ns &&
      now_ns - g_ping_sent_ns >= NETWORK_PING_TIMEOUT_NS) {
    g_ping.state = XAIOS_NETWORK_PING_TIMEOUT;
    g_ping.last_error = XAIOS_ERR_IO;
  }
}

void net_icmp_reset(void) {
  g_icmp_reply_count = 0;
  g_arp_reply_count = 0;
  g_icmpv6_reply_count = 0;
  g_ndp_reply_count = 0;
  g_ping.state = XAIOS_NETWORK_PING_IDLE;
  g_ping.target_ip = 0U;
  g_ping.attempts = 0U;
  g_ping.round_trip_ns = 0U;
  g_ping.last_error = XAIOS_OK;
  g_ping_sent_ns = 0U;
  g_ping_sequence = 0U;
}

void net_arp_handle_frame(const uint8_t *rx_buf, uint32_t frame_len,
                          const uint8_t local_mac[6]) {
  if (frame_len >= 42U && net_wire_read_u16_be(rx_buf + 20U) == XAIOS_ARP_OP_REPLY) {
    arp_process_reply(rx_buf, frame_len);
  } else if (frame_len >= 42U &&
             net_wire_read_u16_be(rx_buf + 20U) == XAIOS_ARP_OP_REQUEST) {
    uint32_t target_ip = net_wire_read_u32_be(rx_buf + 38U);
    if (target_ip == network_config_local_ipv4()) {
      uint8_t reply_frame[64];
      uint64_t reply_len = 0;
      if (arp_build_reply(reply_frame, &reply_len, local_mac,
                          network_config_local_ipv4(), rx_buf + 6,
                          net_wire_read_u32_be(rx_buf + 28U)) == XAIOS_OK) {
        network_device_tx(reply_frame, reply_len);
        ++g_arp_reply_count;
      }
    }
  }
}

int net_icmp_handle_ipv4(const uint8_t *rx_buf, uint32_t frame_len,
                         uint64_t now_ns, const uint8_t local_mac[6]) {
  const uint8_t *icmp = rx_buf + 34U;
  if (frame_len >= 42U && icmp[0] == XAIOS_ICMP_ECHO_REPLY &&
      net_wire_read_u16_be(icmp + 4U) == NETWORK_PING_IDENTIFIER &&
      net_wire_read_u16_be(icmp + 6U) == g_ping_sequence &&
      net_wire_read_u32_be(rx_buf + 26U) == g_ping.target_ip &&
      ipv4_checksum(icmp, net_wire_read_u16_be(rx_buf + 16U) - 20U) == 0U &&
      g_ping.state == XAIOS_NETWORK_PING_PENDING) {
    g_ping.state = XAIOS_NETWORK_PING_REPLIED;
    g_ping.round_trip_ns = now_ns >= g_ping_sent_ns
                              ? now_ns - g_ping_sent_ns : 0U;
    g_ping.last_error = XAIOS_OK;
    return 1;
  }
  uint16_t identifier = 0;
  uint16_t sequence = 0;
  if (icmp_process_echo_request(rx_buf, frame_len, &identifier,
                                 &sequence) == XAIOS_OK) {
    uint8_t reply_buf[NETWORK_BUFFER_SIZE];
    uint64_t reply_len = 0;
    if (icmp_build_echo_reply(reply_buf, &reply_len, local_mac,
                               rx_buf + 6, network_config_local_ipv4(),
                               net_wire_read_u32_be(rx_buf + 26U), rx_buf,
                               frame_len) == XAIOS_OK) {
      network_device_tx(reply_buf, reply_len);
      ++g_icmp_reply_count;
    }
  }
  return 0;
}

void net_icmpv6_handle_frame(const uint8_t *rx_buf, uint32_t frame_len,
                             uint64_t now_ns, const uint8_t local_mac[6]) {
  if (frame_len >= XAIOS_ICMPV6_MIN_FRAME) {
    uint8_t icmpv6_type = rx_buf[XAIOS_ICMPV6_OFFSET];
    if (icmpv6_type == XAIOS_ICMPV6_ECHO_REQUEST) {
      xaios_ip_addr_t echo_src;
      xaios_ip_addr_t echo_dst;
      uint16_t identifier = 0;
      uint16_t sequence = 0;
      if (icmpv6_process_echo_request(rx_buf, frame_len, &identifier,
                                       &sequence, &echo_src,
                                       &echo_dst) == XAIOS_OK) {
        uint8_t reply_buf[NETWORK_BUFFER_SIZE];
        uint64_t reply_len = 0;
        xaios_ip_addr_t echo_source;
        net_v6_source_for(&echo_dst, &echo_source);
        if (icmpv6_build_echo_reply(reply_buf, &reply_len, local_mac,
                                     rx_buf + 6,
                                     &echo_source,
                                     &echo_src, rx_buf,
                                     frame_len) == XAIOS_OK) {
          network_device_tx(reply_buf, reply_len);
          ++g_icmpv6_reply_count;
        }
      }
    } else if (icmpv6_type == XAIOS_ICMPV6_NEIGHBOR_SOLICIT) {
      /* Extract target address from NS (bytes 8-23 of ICMPv6 payload) */
      xaios_ip_addr_t ns_target;
      xaios_ip_addr_from_raw_ipv6(&ns_target, rx_buf + XAIOS_ICMPV6_OFFSET + 8);
      /* Build NA: source = our link-local, dest = NS source */
      xaios_ip_addr_t na_src;
      net_v6_source_for(&ns_target, &na_src);
      xaios_ip_addr_t na_dst;
      xaios_ip_addr_from_raw_ipv6(&na_dst, rx_buf + 22); /* IPv6 src */
      uint8_t na_frame[128];
      uint64_t na_len = 0;
      if (icmpv6_build_neighbor_advertisement(na_frame, &na_len,
            local_mac, rx_buf + 6, &na_src, &na_dst, &ns_target,
            rx_buf, frame_len) == XAIOS_OK) {
        network_device_tx(na_frame, na_len);
        ++g_ndp_reply_count;
      }
    } else if (icmpv6_type == XAIOS_ICMPV6_NEIGHBOR_ADVERT) {
      ndp_process_neighbor_advertisement(rx_buf, frame_len);
    } else if (icmpv6_type == XAIOS_ICMPV6_ROUTER_ADVERT &&
               ndp_process_router_advertisement(rx_buf, frame_len) == XAIOS_OK) {
      net_v6_apply_router_advertisement(rx_buf, frame_len, now_ns,
                                        local_mac);
    }
  }
}

uint64_t network_icmp_reply_count(void) {
  return g_icmp_reply_count;
}

uint64_t network_arp_reply_sent_count(void) {
  return g_arp_reply_count;
}

uint64_t network_icmpv6_reply_count(void) {
  return g_icmpv6_reply_count;
}

uint64_t network_ndp_reply_count(void) {
  return g_ndp_reply_count;
}
