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
 */

#include <xaios/dhcpv6.h>

#include <xaios/assert.h>
#include <xaios/entropy.h>
#include <xaios/ipv4.h>
#include <xaios/ipv6.h>
#include <xaios/klog.h>
#include <xaios/net_device.h>
#include <xaios/timer.h>

#define DHCPV6_CLIENT_PORT UINT16_C(546)
#define DHCPV6_SERVER_PORT UINT16_C(547)

#define DHCPV6_SOLICIT UINT8_C(1)
#define DHCPV6_ADVERTISE UINT8_C(2)
#define DHCPV6_REQUEST UINT8_C(3)
#define DHCPV6_REPLY UINT8_C(7)

#define DHCPV6_OPT_CLIENTID UINT16_C(1)
#define DHCPV6_OPT_SERVERID UINT16_C(2)
#define DHCPV6_OPT_IA_NA UINT16_C(3)
#define DHCPV6_OPT_IAADDR UINT16_C(5)
#define DHCPV6_OPT_ORO UINT16_C(6)
#define DHCPV6_OPT_ELAPSED_TIME UINT16_C(8)
#define DHCPV6_OPT_STATUS_CODE UINT16_C(13)
#define DHCPV6_OPT_RAPID_COMMIT UINT16_C(14)
#define DHCPV6_OPT_DNS_SERVERS UINT16_C(23)

#define DHCPV6_DUID_LL UINT16_C(3)
#define DHCPV6_HWTYPE_ETHERNET UINT16_C(1)

#define DHCPV6_STATUS_SUCCESS UINT16_C(0)

#define DHCPV6_ETHERNET_BYTES 14U
#define DHCPV6_IPV6_BYTES 40U
#define DHCPV6_UDP_BYTES 8U
#define DHCPV6_HEADER_BYTES (DHCPV6_ETHERNET_BYTES + DHCPV6_IPV6_BYTES + \
                             DHCPV6_UDP_BYTES)
#define DHCPV6_FRAME_CAPACITY 512U
#define DHCPV6_RX_CAPACITY 2048U

/* A server identifier is opaque and variable length; RFC 8415 caps a DUID at
   128 octets, and one longer than that is malformed rather than interesting. */
#define DHCPV6_MAX_DUID 128U

#define DHCPV6_RETRY_INTERVAL_NS UINT64_C(1000000000)
#define DHCPV6_RETRY_MAX_INTERVAL_NS UINT64_C(4000000000)

static uint8_t g_transaction_id[3];
static uint8_t g_client_duid[10];
static uint32_t g_client_duid_len;
static uint32_t g_iaid;

static void put_be16(uint8_t *out, uint16_t value) {
  out[0] = (uint8_t)(value >> 8U);
  out[1] = (uint8_t)value;
}

static void put_be32(uint8_t *out, uint32_t value) {
  out[0] = (uint8_t)(value >> 24U);
  out[1] = (uint8_t)(value >> 16U);
  out[2] = (uint8_t)(value >> 8U);
  out[3] = (uint8_t)value;
}

static uint16_t get_be16(const uint8_t *in) {
  return (uint16_t)(((uint16_t)in[0] << 8U) | in[1]);
}

static uint32_t get_be32(const uint8_t *in) {
  return ((uint32_t)in[0] << 24U) | ((uint32_t)in[1] << 16U) |
         ((uint32_t)in[2] << 8U) | in[3];
}

static void copy_bytes(uint8_t *out, const uint8_t *in, uint32_t length) {
  for (uint32_t i = 0U; i < length; ++i) out[i] = in[i];
}

static void zero_bytes(uint8_t *out, uint32_t length) {
  for (uint32_t i = 0U; i < length; ++i) out[i] = 0U;
}

static int bytes_equal(const uint8_t *a, const uint8_t *b, uint32_t length) {
  for (uint32_t i = 0U; i < length; ++i)
    if (a[i] != b[i]) return 0;
  return 1;
}

/* ff02::1:2 -- every DHCPv6 server and relay on the link. */
static void all_servers_address(xaios_ip_addr_t *address) {
  zero_bytes((uint8_t *)address, sizeof(*address));
  address->family = XAIOS_IP_FAMILY_V6;
  address->addr[0] = 0xffU;
  address->addr[1] = 0x02U;
  address->addr[13] = 0x01U;
  address->addr[15] = 0x02U;
}

/* An IPv6 multicast address is delivered to the Ethernet group 33:33 followed
   by the last four octets of the address, so no neighbour lookup is needed --
   which matters, because there is no address to do one from yet. */
static void multicast_mac(uint8_t mac[6], const xaios_ip_addr_t *address) {
  mac[0] = 0x33U;
  mac[1] = 0x33U;
  copy_bytes(mac + 2U, address->addr + 12U, 4U);
}

/* DUID-LL: type, hardware type, link-layer address. Chosen over DUID-LLT
   because it carries no timestamp, and a guest whose clock starts at the epoch
   every boot would otherwise mint a new identity on each one -- which is the
   opposite of what a stable client identifier is for. */
static void build_client_duid(const uint8_t mac[6]) {
  put_be16(g_client_duid, DHCPV6_DUID_LL);
  put_be16(g_client_duid + 2U, DHCPV6_HWTYPE_ETHERNET);
  copy_bytes(g_client_duid + 4U, mac, 6U);
  g_client_duid_len = 10U;
  /* The IAID names which interface the address belongs to. XAIOS configures
     one, so any stable value serves; deriving it from the MAC keeps it stable
     across boots without storing anything. */
  g_iaid = get_be32(mac + 2U);
}

static void new_transaction_id(void) {
  uint32_t value = 0U;
  if (entropy_read(&value, sizeof(value)) != XAIOS_OK || value == 0U) {
    uint64_t now = timer_now_ns();
    value = (uint32_t)(now ^ (now >> 32));
  }
  g_transaction_id[0] = (uint8_t)(value >> 16U);
  g_transaction_id[1] = (uint8_t)(value >> 8U);
  g_transaction_id[2] = (uint8_t)value;
}

static uint32_t append_option(uint8_t *out, uint32_t offset, uint16_t code,
                              const uint8_t *data, uint16_t length) {
  if (offset + 4U + length > DHCPV6_FRAME_CAPACITY) return 0U;
  put_be16(out + offset, code);
  put_be16(out + offset + 2U, length);
  if (length != 0U && data != 0) copy_bytes(out + offset + 4U, data, length);
  return offset + 4U + length;
}

/*
 * Assemble one client message. server_duid is the Server Identifier to echo
 * back, which a REQUEST must carry and a SOLICIT must not.
 */
static uint32_t build_message(uint8_t frame[DHCPV6_FRAME_CAPACITY],
                              uint8_t message_type, const uint8_t mac[6],
                              const uint8_t *server_duid,
                              uint32_t server_duid_len,
                              const xaios_ip_addr_t *requested,
                              uint64_t elapsed_ns) {
  zero_bytes(frame, DHCPV6_FRAME_CAPACITY);

  xaios_ip_addr_t source;
  xaios_ip_addr_t destination;
  ipv6_link_local_from_mac(&source, mac);
  all_servers_address(&destination);

  uint8_t destination_mac[6];
  multicast_mac(destination_mac, &destination);
  copy_bytes(frame, destination_mac, 6U);
  copy_bytes(frame + 6U, mac, 6U);
  put_be16(frame + 12U, UINT16_C(0x86dd));

  uint8_t *message = frame + DHCPV6_HEADER_BYTES;
  message[0] = message_type;
  copy_bytes(message + 1U, g_transaction_id, 3U);

  uint32_t offset = 4U;
  offset = append_option(message, offset, DHCPV6_OPT_CLIENTID, g_client_duid,
                         (uint16_t)g_client_duid_len);
  if (offset == 0U) return 0U;

  if (server_duid_len != 0U) {
    offset = append_option(message, offset, DHCPV6_OPT_SERVERID, server_duid,
                           (uint16_t)server_duid_len);
    if (offset == 0U) return 0U;
  }

  /* Elapsed time is hundredths of a second since the exchange began, and it is
     how a server learns a client has been waiting -- capped at the field it
     has to fit in rather than wrapping. */
  uint64_t hundredths = elapsed_ns / UINT64_C(10000000);
  if (hundredths > UINT64_C(0xffff)) hundredths = UINT64_C(0xffff);
  uint8_t elapsed[2];
  put_be16(elapsed, (uint16_t)hundredths);
  offset = append_option(message, offset, DHCPV6_OPT_ELAPSED_TIME, elapsed, 2U);
  if (offset == 0U) return 0U;

  /* IA_NA: which identity association, and how long before the client should
     renew. Zero for T1 and T2 leaves the timing to the server, which is the
     correct thing for a client with no policy of its own. */
  uint8_t ia_na[40];
  uint32_t ia_len = 12U;
  put_be32(ia_na, g_iaid);
  put_be32(ia_na + 4U, 0U);
  put_be32(ia_na + 8U, 0U);
  if (requested != 0) {
    /* A REQUEST names the address the ADVERTISE offered, so the server binds
       the one it already chose rather than picking again. */
    put_be16(ia_na + 12U, DHCPV6_OPT_IAADDR);
    put_be16(ia_na + 14U, 24U);
    copy_bytes(ia_na + 16U, requested->addr, 16U);
    put_be32(ia_na + 32U, 0U);
    put_be32(ia_na + 36U, 0U);
    ia_len = 40U;
  }
  offset = append_option(message, offset, DHCPV6_OPT_IA_NA, ia_na,
                         (uint16_t)ia_len);
  if (offset == 0U) return 0U;

  uint8_t oro[2];
  put_be16(oro, DHCPV6_OPT_DNS_SERVERS);
  offset = append_option(message, offset, DHCPV6_OPT_ORO, oro, 2U);
  if (offset == 0U) return 0U;

  if (message_type == DHCPV6_SOLICIT) {
    offset = append_option(message, offset, DHCPV6_OPT_RAPID_COMMIT, 0, 0U);
    if (offset == 0U) return 0U;
  }

  uint32_t udp_length = DHCPV6_UDP_BYTES + offset;
  uint8_t *udp = frame + DHCPV6_ETHERNET_BYTES + DHCPV6_IPV6_BYTES;
  put_be16(udp, DHCPV6_CLIENT_PORT);
  put_be16(udp + 2U, DHCPV6_SERVER_PORT);
  put_be16(udp + 4U, (uint16_t)udp_length);
  put_be16(udp + 6U, 0U);

  ipv6_build_header(frame + DHCPV6_ETHERNET_BYTES, (uint16_t)udp_length,
                    XAIOS_IPV4_PROTO_UDP, &source, &destination);

  /* UDP checksums are not optional over IPv6: a datagram with a zero checksum
     is discarded rather than accepted, so this has to be right or nothing
     answers and the failure looks like an absent server. */
  uint16_t checksum = ipv6_pseudo_checksum(&source, &destination,
                                           XAIOS_IPV4_PROTO_UDP, udp_length,
                                           udp, udp_length);
  put_be16(udp + 6U, checksum);

  return DHCPV6_HEADER_BYTES + offset;
}

typedef struct dhcpv6_response {
  uint8_t message_type;
  uint8_t server_duid[DHCPV6_MAX_DUID];
  uint32_t server_duid_len;
  xaios_ip_addr_t address;
  xaios_ip_addr_t dns;
  uint32_t preferred_lifetime_s;
  uint32_t valid_lifetime_s;
  uint32_t have_address;
  uint32_t have_dns;
  uint16_t status;
} dhcpv6_response_t;

/* Walk the options inside an IA_NA for the address the server assigned. A
   status code here reports failure for this association specifically, which is
   not the same as failure of the message that carried it. */
static void parse_ia_na(const uint8_t *data, uint32_t length,
                        dhcpv6_response_t *response) {
  if (length < 12U || get_be32(data) != g_iaid) return;
  uint32_t offset = 12U;
  while (offset + 4U <= length) {
    uint16_t code = get_be16(data + offset);
    uint16_t option_length = get_be16(data + offset + 2U);
    if (option_length > length - offset - 4U) return;
    const uint8_t *value = data + offset + 4U;
    if (code == DHCPV6_OPT_IAADDR && option_length >= 24U) {
      response->address.family = XAIOS_IP_FAMILY_V6;
      copy_bytes(response->address.addr, value, 16U);
      response->preferred_lifetime_s = get_be32(value + 16U);
      response->valid_lifetime_s = get_be32(value + 20U);
      /* A zero valid lifetime is the server withdrawing the address, not
         offering one for no time at all. */
      response->have_address = response->valid_lifetime_s != 0U ? 1U : 0U;
    } else if (code == DHCPV6_OPT_STATUS_CODE && option_length >= 2U) {
      response->status = get_be16(value);
    }
    offset += 4U + option_length;
  }
}

static int parse_response(const uint8_t *frame, uint32_t length,
                          const uint8_t mac[6], dhcpv6_response_t *response) {
  if (length < DHCPV6_HEADER_BYTES + 4U) return 0;
  if (get_be16(frame + 12U) != UINT16_C(0x86dd)) return 0;
  /* No extension-header walk: a server answering a client on-link sends UDP
     directly, and anything else is not this exchange. */
  if (frame[DHCPV6_ETHERNET_BYTES + 6U] != XAIOS_IPV4_PROTO_UDP) return 0;
  const uint8_t *udp = frame + DHCPV6_ETHERNET_BYTES + DHCPV6_IPV6_BYTES;
  if (get_be16(udp) != DHCPV6_SERVER_PORT ||
      get_be16(udp + 2U) != DHCPV6_CLIENT_PORT) {
    return 0;
  }

  const uint8_t *message = frame + DHCPV6_HEADER_BYTES;
  if (bytes_equal(message + 1U, g_transaction_id, 3U) == 0) return 0;

  uint32_t message_length = length - DHCPV6_HEADER_BYTES;
  uint16_t udp_length = get_be16(udp + 4U);
  if (udp_length >= DHCPV6_UDP_BYTES &&
      (uint32_t)(udp_length - DHCPV6_UDP_BYTES) < message_length) {
    /* Trust the length the sender declared over whatever padding the device
       handed up with the frame. */
    message_length = (uint32_t)(udp_length - DHCPV6_UDP_BYTES);
  }

  zero_bytes((uint8_t *)response, sizeof(*response));
  response->message_type = message[0];

  uint32_t offset = 4U;
  uint32_t client_id_matched = 0U;
  while (offset + 4U <= message_length) {
    uint16_t code = get_be16(message + offset);
    uint16_t option_length = get_be16(message + offset + 2U);
    if (option_length > message_length - offset - 4U) return 0;
    const uint8_t *value = message + offset + 4U;
    if (code == DHCPV6_OPT_CLIENTID) {
      if (option_length == g_client_duid_len &&
          bytes_equal(value, g_client_duid, g_client_duid_len) != 0) {
        client_id_matched = 1U;
      }
    } else if (code == DHCPV6_OPT_SERVERID) {
      if (option_length != 0U && option_length <= DHCPV6_MAX_DUID) {
        copy_bytes(response->server_duid, value, option_length);
        response->server_duid_len = option_length;
      }
    } else if (code == DHCPV6_OPT_IA_NA) {
      parse_ia_na(value, option_length, response);
    } else if (code == DHCPV6_OPT_DNS_SERVERS && option_length >= 16U) {
      response->dns.family = XAIOS_IP_FAMILY_V6;
      copy_bytes(response->dns.addr, value, 16U);
      response->have_dns = 1U;
    } else if (code == DHCPV6_OPT_RAPID_COMMIT) {
      /* Presence alone is the answer; it carries no data. */
      response->status = response->status;
    } else if (code == DHCPV6_OPT_STATUS_CODE && option_length >= 2U) {
      response->status = get_be16(value);
    }
    offset += 4U + option_length;
  }

  /* A reply that does not name this client, or names no server, is somebody
     else's exchange overheard on a shared link. */
  if (client_id_matched == 0U || response->server_duid_len == 0U) return 0;
  (void)mac;
  return 1;
}

static xaios_status_t wait_for_response(uint8_t expected_a, uint8_t expected_b,
                                        uint64_t deadline, const uint8_t mac[6],
                                        dhcpv6_response_t *response) {
  static uint8_t buffer[DHCPV6_RX_CAPACITY];
  while (timer_now_ns() < deadline) {
    uint32_t length = network_device_rx_poll(buffer, sizeof(buffer));
    if (length == 0U) continue;
    if (parse_response(buffer, length, mac, response) == 0) continue;
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
    uint32_t size = build_message(frame, message_type, mac, server_duid,
                                  server_duid_len, requested, now - started);
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

  build_client_duid(mac);
  new_transaction_id();
  zero_bytes((uint8_t *)lease, sizeof(*lease));

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
  copy_bytes(server_duid, response.server_duid, server_duid_len);
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

void dhcpv6_self_test(void) {
  static const uint8_t mac[6] = {0x52U, 0x54U, 0x00U, 0x12U, 0x34U, 0x56U};
  uint8_t frame[DHCPV6_FRAME_CAPACITY];

  build_client_duid(mac);
  g_transaction_id[0] = 0xa1U;
  g_transaction_id[1] = 0xb2U;
  g_transaction_id[2] = 0xc3U;

  uint32_t size = build_message(frame, DHCPV6_SOLICIT, mac, 0, 0U, 0, 0U);
  kassert(size > DHCPV6_HEADER_BYTES);
  kassert(frame[0] == 0x33U && frame[1] == 0x33U);
  kassert(frame[2] == 0x00U && frame[3] == 0x01U);
  kassert(frame[4] == 0x00U && frame[5] == 0x02U);
  kassert(get_be16(frame + 12U) == UINT16_C(0x86dd));

  const uint8_t *udp = frame + DHCPV6_ETHERNET_BYTES + DHCPV6_IPV6_BYTES;
  kassert(get_be16(udp) == DHCPV6_CLIENT_PORT);
  kassert(get_be16(udp + 2U) == DHCPV6_SERVER_PORT);
  /* A zero checksum would be discarded by every conforming receiver, so its
     absence is a real failure rather than a cosmetic one. */
  kassert(get_be16(udp + 6U) != 0U);

  const uint8_t *message = frame + DHCPV6_HEADER_BYTES;
  kassert(message[0] == DHCPV6_SOLICIT);
  kassert(message[1] == 0xa1U && message[2] == 0xb2U && message[3] == 0xc3U);

  /* Walk what was built and confirm the options a SOLICIT must carry are
     present, that no Server Identifier crept in, and that the option lengths
     tile the message exactly rather than merely fitting inside it. */
  uint32_t offset = 4U;
  uint32_t saw_clientid = 0U;
  uint32_t saw_ia_na = 0U;
  uint32_t saw_rapid_commit = 0U;
  uint32_t saw_elapsed = 0U;
  uint32_t saw_serverid = 0U;
  uint32_t message_length = size - DHCPV6_HEADER_BYTES;
  while (offset + 4U <= message_length) {
    uint16_t code = get_be16(message + offset);
    uint16_t option_length = get_be16(message + offset + 2U);
    kassert(option_length <= message_length - offset - 4U);
    if (code == DHCPV6_OPT_CLIENTID) {
      kassert(option_length == 10U);
      kassert(get_be16(message + offset + 4U) == DHCPV6_DUID_LL);
      kassert(bytes_equal(message + offset + 8U, mac, 6U) != 0);
      saw_clientid = 1U;
    } else if (code == DHCPV6_OPT_IA_NA) {
      kassert(option_length == 12U);
      saw_ia_na = 1U;
    } else if (code == DHCPV6_OPT_RAPID_COMMIT) {
      kassert(option_length == 0U);
      saw_rapid_commit = 1U;
    } else if (code == DHCPV6_OPT_ELAPSED_TIME) {
      kassert(option_length == 2U);
      saw_elapsed = 1U;
    } else if (code == DHCPV6_OPT_SERVERID) {
      saw_serverid = 1U;
    }
    offset += 4U + option_length;
  }
  kassert(offset == message_length);
  kassert(saw_clientid == 1U && saw_ia_na == 1U);
  kassert(saw_rapid_commit == 1U && saw_elapsed == 1U);
  kassert(saw_serverid == 0U);

  /* A REQUEST must echo the server's identifier and name the offered address,
     and must not ask for rapid commit -- that option belongs to the SOLICIT. */
  static const uint8_t server_duid[6] = {0x00U, 0x03U, 0x00U,
                                         0x01U, 0xaaU, 0xbbU};
  xaios_ip_addr_t offered;
  zero_bytes((uint8_t *)&offered, sizeof(offered));
  offered.family = XAIOS_IP_FAMILY_V6;
  offered.addr[0] = 0x20U;
  offered.addr[1] = 0x01U;
  offered.addr[15] = 0x42U;
  size = build_message(frame, DHCPV6_REQUEST, mac, server_duid, 6U, &offered,
                       UINT64_C(2500000000));
  kassert(size > DHCPV6_HEADER_BYTES);
  message_length = size - DHCPV6_HEADER_BYTES;
  offset = 4U;
  saw_serverid = 0U;
  saw_rapid_commit = 0U;
  uint32_t saw_address = 0U;
  uint32_t elapsed_hundredths = 0U;
  while (offset + 4U <= message_length) {
    uint16_t code = get_be16(message + offset);
    uint16_t option_length = get_be16(message + offset + 2U);
    kassert(option_length <= message_length - offset - 4U);
    if (code == DHCPV6_OPT_SERVERID) {
      kassert(option_length == 6U);
      kassert(bytes_equal(message + offset + 4U, server_duid, 6U) != 0);
      saw_serverid = 1U;
    } else if (code == DHCPV6_OPT_IA_NA) {
      kassert(option_length == 40U);
      kassert(get_be16(message + offset + 16U) == DHCPV6_OPT_IAADDR);
      kassert(get_be16(message + offset + 18U) == 24U);
      kassert(bytes_equal(message + offset + 20U, offered.addr, 16U) != 0);
      saw_address = 1U;
    } else if (code == DHCPV6_OPT_RAPID_COMMIT) {
      saw_rapid_commit = 1U;
    } else if (code == DHCPV6_OPT_ELAPSED_TIME) {
      elapsed_hundredths = get_be16(message + offset + 4U);
    }
    offset += 4U + option_length;
  }
  kassert(offset == message_length);
  kassert(saw_serverid == 1U && saw_address == 1U);
  kassert(saw_rapid_commit == 0U);
  /* 2.5 seconds is 250 hundredths, and getting the unit wrong here is exactly
     the kind of thing a server tolerates silently. */
  kassert(elapsed_hundredths == 250U);

  klog("dhcpv6: message and option encoding self-test passed\n");
}
