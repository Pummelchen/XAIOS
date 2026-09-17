/*
 * DHCPv6 client, RFC 8415.
 *
 * Built the same way the DHCPv4 client is: whole frames assembled by hand and
 * handed to the device, replies polled off the receive ring. That is not how a
 * general-purpose stack would do it, but address configuration runs before
 * there is a configured address to bind a socket to, so it cannot use the
 * socket layer it is a precondition for.
 *
 * The exchange is four messages -- SOLICIT, ADVERTISE, REQUEST, REPLY -- and
 * this client asks for the two-message form as well by including the Rapid
 * Commit option. A server that honours it answers the SOLICIT with a REPLY and
 * the address is configured in one round trip; a server that ignores it sends
 * an ADVERTISE and the full exchange proceeds. Both are handled because RFC
 * 8415 permits either and a client does not get to insist.
 *
 * Everything is sent to ff02::1:2, the All_DHCP_Relay_Agents_and_Servers
 * multicast group, from the link-local address: a host doing this does not yet
 * have a routable address, which is the whole point of asking.
 *
 * This file is the state machine: when to send, how long to wait, and what to
 * do with what comes back. The bytes themselves -- the option walk, the DUID,
 * the IA_NA -- and the self-test that drives them live in dhcpv6_codec.c,
 * behind dhcpv6_internal.h.
 */

#include <xaios/dhcpv6.h>

#include <xaios/klog.h>
#include <xaios/net_device.h>
#include <xaios/timer.h>

#include "dhcpv6_internal.h"

static xaios_status_t wait_for_response(uint8_t expected_a, uint8_t expected_b,
                                        uint64_t deadline, const uint8_t mac[6],
                                        dhcpv6_response_t *response) {
  static uint8_t buffer[DHCPV6_RX_CAPACITY];
  while (timer_now_ns() < deadline) {
    uint32_t length = network_device_rx_poll(buffer, sizeof(buffer));
    if (length == 0U) continue;
    if (dhcpv6_parse_response(buffer, length, mac, response) == 0) continue;
    if (response->message_type != expected_a &&
        response->message_type != expected_b) {
      continue;
    }
    if (response->status != DHCPV6_STATUS_SUCCESS) return XAIOS_ERR_IO;
    return XAIOS_OK;
  }
  return XAIOS_ERR_IO;
}

static xaios_status_t exchange(uint8_t message_type, uint8_t expected_a,
                               uint8_t expected_b, const uint8_t mac[6],
                               const uint8_t *server_duid,
                               uint32_t server_duid_len,
                               const xaios_ip_addr_t *requested,
                               uint64_t started, uint64_t deadline,
                               dhcpv6_response_t *response) {
  uint8_t frame[DHCPV6_FRAME_CAPACITY];
  uint32_t attempts = 0U;
  uint64_t interval = DHCPV6_RETRY_INTERVAL_NS;
  while (timer_now_ns() < deadline) {
    uint64_t now = timer_now_ns();
    uint32_t size = dhcpv6_build_message(frame, message_type, mac, server_duid,
                                         server_duid_len, requested,
                                         now - started);
    if (size == 0U) return XAIOS_ERR_INVALID;
    ++attempts;
    xaios_status_t status = network_device_tx(frame, size);
    if (status == XAIOS_OK) {
      now = timer_now_ns();
      uint64_t attempt_deadline = now + interval + (now % (interval / 4U + 1U));
      if (interval < DHCPV6_RETRY_MAX_INTERVAL_NS) interval *= 2U;
      if (attempt_deadline < now || attempt_deadline > deadline) {
        attempt_deadline = deadline;
      }
      status = wait_for_response(expected_a, expected_b, attempt_deadline, mac,
                                 response);
      if (status == XAIOS_OK) return XAIOS_OK;
    }
    klog("dhcpv6: retry message=%u attempt=%u status=%d\n", message_type,
         attempts, (int)status);
  }
  return XAIOS_ERR_IO;
}

xaios_status_t dhcpv6_acquire(uint64_t timeout_ns,
                              xaios_dhcpv6_lease_t *lease) {
  uint8_t mac[6];
  if (lease == 0 || timeout_ns == 0U) return XAIOS_ERR_INVALID;
  if (network_device_get_mac(mac) != XAIOS_OK) return XAIOS_ERR_INVALID;

  dhcpv6_build_client_duid(mac);
  dhcpv6_new_transaction_id();
  dhcpv6_zero_bytes((uint8_t *)lease, sizeof(*lease));

  uint64_t started = timer_now_ns();
  uint64_t solicit_deadline = started + timeout_ns / 2U;
  if (solicit_deadline < started) return XAIOS_ERR_INVALID;

  dhcpv6_response_t response;
  xaios_status_t status =
      exchange(DHCPV6_SOLICIT, DHCPV6_ADVERTISE, DHCPV6_REPLY, mac, 0, 0U, 0,
               started, solicit_deadline, &response);
  if (status != XAIOS_OK) {
    klog("dhcpv6: no server answered the solicit status=%d\n", (int)status);
    return status;
  }

  if (response.message_type == DHCPV6_REPLY) {
    /* Rapid Commit honoured: the address in this message is the lease. */
    if (response.have_address == 0U) return XAIOS_ERR_IO;
    lease->address = response.address;
    lease->dns = response.dns;
    lease->preferred_lifetime_s = response.preferred_lifetime_s;
    lease->valid_lifetime_s = response.valid_lifetime_s;
    lease->have_address = 1U;
    lease->have_dns = response.have_dns;
    lease->rapid_commit = 1U;
    klog("dhcpv6: lease by rapid commit valid_s=%u\n",
         lease->valid_lifetime_s);
    return XAIOS_OK;
  }

  if (response.have_address == 0U) {
    klog("dhcpv6: advertise carried no address\n");
    return XAIOS_ERR_IO;
  }

  /* The transaction id stays the same across SOLICIT and the REQUEST that
     follows it: RFC 8415 treats them as one exchange. */
  uint8_t server_duid[DHCPV6_MAX_DUID];
  uint32_t server_duid_len = response.server_duid_len;
  dhcpv6_copy_bytes(server_duid, response.server_duid, server_duid_len);
  xaios_ip_addr_t offered = response.address;

  uint64_t reply_deadline = started + timeout_ns;
  status = exchange(DHCPV6_REQUEST, DHCPV6_REPLY, DHCPV6_REPLY, mac,
                    server_duid, server_duid_len, &offered, started,
                    reply_deadline, &response);
  if (status != XAIOS_OK) {
    klog("dhcpv6: request unanswered status=%d\n", (int)status);
    return status;
  }
  if (response.have_address == 0U) return XAIOS_ERR_IO;

  lease->address = response.address;
  lease->dns = response.dns;
  lease->preferred_lifetime_s = response.preferred_lifetime_s;
  lease->valid_lifetime_s = response.valid_lifetime_s;
  lease->have_address = 1U;
  lease->have_dns = response.have_dns;
  lease->rapid_commit = 0U;
  klog("dhcpv6: lease by four-message exchange valid_s=%u\n",
       lease->valid_lifetime_s);
  return XAIOS_OK;
}
