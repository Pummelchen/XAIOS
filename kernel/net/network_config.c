#include <xaios/arch_cpu.h>
#include <xaios/ipv4.h>
#include <xaios/klog.h>
#include <xaios/net_device.h>
#include <xaios/network_config.h>
#include <xaios/timer.h>

#define DHCP_FRAME_CAPACITY 320U
#define DHCP_RX_CAPACITY 2048U
#define DHCP_ETHERNET_BYTES 14U
#define DHCP_IPV4_BYTES 20U
#define DHCP_UDP_BYTES 8U
#define DHCP_BOOTP_BYTES 236U
#define DHCP_COOKIE UINT32_C(0x63825363)
#define DHCP_CLIENT_PORT UINT16_C(68)
#define DHCP_SERVER_PORT UINT16_C(67)
#define DHCP_XID UINT32_C(0x5841494f)
#define DHCP_DISCOVER UINT8_C(1)
#define DHCP_OFFER UINT8_C(2)
#define DHCP_REQUEST UINT8_C(3)
#define DHCP_ACK UINT8_C(5)
#define DHCP_RETRY_INTERVAL_NS UINT64_C(1000000000)

typedef struct network_config_state {
  uint32_t local_ipv4;
  uint32_t gateway_ipv4;
  uint32_t netmask;
  uint32_t dns_server;
  uint8_t gateway_mac[6];
  uint32_t dynamic;
} network_config_state_t;

static network_config_state_t g_network_config;

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

void network_config_reset_defaults(void) {
  g_network_config.local_ipv4 = XAIOS_IPV4_GUEST_IP;
  g_network_config.gateway_ipv4 = XAIOS_IPV4_GATEWAY;
  g_network_config.netmask = XAIOS_IPV4_NETMASK;
  g_network_config.dns_server = UINT32_C(0x08080808);
  static const uint8_t qemu_gateway[6] = {0x52U, 0x55U, 0x0aU,
                                          0x00U, 0x02U, 0x02U};
  copy_bytes(g_network_config.gateway_mac, qemu_gateway, 6U);
  g_network_config.dynamic = 0U;
}

static uint32_t build_request(uint8_t frame[DHCP_FRAME_CAPACITY],
                              uint8_t message_type, uint32_t requested_ip,
                              uint32_t server_ip, const uint8_t mac[6]) {
  uint32_t options = DHCP_ETHERNET_BYTES + DHCP_IPV4_BYTES + DHCP_UDP_BYTES +
                     DHCP_BOOTP_BYTES;
  zero_bytes(frame, DHCP_FRAME_CAPACITY);
  for (uint32_t i = 0U; i < 6U; ++i) {
    frame[i] = UINT8_MAX;
    frame[6U + i] = mac[i];
  }
  put_be16(frame + 12U, UINT16_C(0x0800));
  uint8_t *bootp = frame + DHCP_ETHERNET_BYTES + DHCP_IPV4_BYTES + DHCP_UDP_BYTES;
  bootp[0] = 1U;
  bootp[1] = 1U;
  bootp[2] = 6U;
  put_be32(bootp + 4U, DHCP_XID);
  put_be16(bootp + 10U, UINT16_C(0x8000));
  copy_bytes(bootp + 28U, mac, 6U);
  put_be32(bootp + DHCP_BOOTP_BYTES, DHCP_COOKIE);
  options += 4U;
  frame[options++] = 53U;
  frame[options++] = 1U;
  frame[options++] = message_type;
  frame[options++] = 61U;
  frame[options++] = 7U;
  frame[options++] = 1U;
  copy_bytes(frame + options, mac, 6U);
  options += 6U;
  if (requested_ip != 0U) {
    frame[options++] = 50U;
    frame[options++] = 4U;
    put_be32(frame + options, requested_ip);
    options += 4U;
  }
  if (server_ip != 0U) {
    frame[options++] = 54U;
    frame[options++] = 4U;
    put_be32(frame + options, server_ip);
    options += 4U;
  }
  frame[options++] = 55U;
  frame[options++] = 3U;
  frame[options++] = 1U;
  frame[options++] = 3U;
  frame[options++] = 6U;
  frame[options++] = UINT8_MAX;

  uint16_t udp_length = (uint16_t)(DHCP_UDP_BYTES + options -
      (DHCP_ETHERNET_BYTES + DHCP_IPV4_BYTES + DHCP_UDP_BYTES));
  ipv4_build_header(frame + DHCP_ETHERNET_BYTES,
                    (uint16_t)(DHCP_IPV4_BYTES + udp_length),
                    XAIOS_IPV4_PROTO_UDP, 0U, UINT32_MAX);
  put_be16(frame + DHCP_ETHERNET_BYTES + DHCP_IPV4_BYTES, DHCP_CLIENT_PORT);
  put_be16(frame + DHCP_ETHERNET_BYTES + DHCP_IPV4_BYTES + 2U,
           DHCP_SERVER_PORT);
  put_be16(frame + DHCP_ETHERNET_BYTES + DHCP_IPV4_BYTES + 4U, udp_length);
  return options;
}

typedef struct dhcp_reply {
  uint32_t address;
  uint32_t server;
  uint32_t gateway;
  uint32_t netmask;
  uint32_t dns;
  uint8_t server_mac[6];
  uint8_t message_type;
} dhcp_reply_t;

static int parse_reply(const uint8_t *frame, uint32_t length,
                       const uint8_t mac[6], dhcp_reply_t *reply) {
  const uint32_t bootp_offset = DHCP_ETHERNET_BYTES + DHCP_IPV4_BYTES + DHCP_UDP_BYTES;
  if (length < bootp_offset + DHCP_BOOTP_BYTES + 4U ||
      get_be16(frame + 12U) != UINT16_C(0x0800) || frame[23U] != XAIOS_IPV4_PROTO_UDP ||
      get_be16(frame + DHCP_ETHERNET_BYTES + DHCP_IPV4_BYTES) != DHCP_SERVER_PORT ||
      get_be16(frame + DHCP_ETHERNET_BYTES + DHCP_IPV4_BYTES + 2U) != DHCP_CLIENT_PORT ||
      frame[bootp_offset] != 2U || get_be32(frame + bootp_offset + 4U) != DHCP_XID ||
      get_be32(frame + bootp_offset + DHCP_BOOTP_BYTES) != DHCP_COOKIE) {
    return 0;
  }
  for (uint32_t i = 0U; i < 6U; ++i)
    if (frame[bootp_offset + 28U + i] != mac[i]) return 0;
  zero_bytes((uint8_t *)reply, sizeof(*reply));
  reply->address = get_be32(frame + bootp_offset + 16U);
  copy_bytes(reply->server_mac, frame + 6U, 6U);
  uint32_t option = bootp_offset + DHCP_BOOTP_BYTES + 4U;
  while (option < length) {
    uint8_t code = frame[option++];
    if (code == UINT8_MAX) break;
    if (code == 0U) continue;
    if (option >= length) return 0;
    uint8_t option_length = frame[option++];
    if (option_length > length - option) return 0;
    if (code == 53U && option_length == 1U) reply->message_type = frame[option];
    if (code == 1U && option_length == 4U) reply->netmask = get_be32(frame + option);
    if (code == 3U && option_length >= 4U) reply->gateway = get_be32(frame + option);
    if (code == 6U && option_length >= 4U) reply->dns = get_be32(frame + option);
    if (code == 54U && option_length == 4U) reply->server = get_be32(frame + option);
    option += option_length;
  }
  return reply->address != 0U && reply->server != 0U && reply->message_type != 0U;
}

static xaios_status_t wait_for_reply(uint8_t wanted_type, uint64_t deadline,
                                     const uint8_t mac[6], dhcp_reply_t *reply) {
  uint8_t frame[DHCP_RX_CAPACITY];
  while (timer_now_ns() < deadline) {
    uint32_t length = network_device_rx_poll(frame, sizeof(frame));
    if (length != 0U && parse_reply(frame, length, mac, reply) != 0) {
      if (reply->message_type == wanted_type) return XAIOS_OK;
      klog("network: DHCP ignored message type=%u wanted=%u\n",
           reply->message_type, wanted_type);
    }
    xaios_cpu_relax();
  }
  return XAIOS_ERR_IO;
}

static xaios_status_t exchange_request(uint8_t request_type,
                                       uint8_t expected_reply,
                                       uint32_t requested_ip,
                                       uint32_t server_ip,
                                       uint64_t deadline,
                                       const uint8_t mac[6],
                                       dhcp_reply_t *reply) {
  uint8_t frame[DHCP_FRAME_CAPACITY];
  uint32_t attempts = 0U;
  while (timer_now_ns() < deadline) {
    uint32_t request_size = build_request(frame, request_type, requested_ip,
                                          server_ip, mac);
    if (request_size == 0U) return XAIOS_ERR_INVALID;
    ++attempts;
    xaios_status_t status = network_device_tx(frame, request_size);
    if (status == XAIOS_OK) {
      uint64_t now = timer_now_ns();
      uint64_t attempt_deadline = now + DHCP_RETRY_INTERVAL_NS;
      if (attempt_deadline < now || attempt_deadline > deadline) {
        attempt_deadline = deadline;
      }
      status = wait_for_reply(expected_reply, attempt_deadline, mac, reply);
      if (status == XAIOS_OK) return XAIOS_OK;
    }
    klog("network: DHCP retry request=%u attempt=%u status=%d\n",
         request_type, attempts, (int)status);
  }
  return XAIOS_ERR_IO;
}

xaios_status_t network_config_dhcp(uint64_t timeout_ns) {
  uint8_t mac[6];
  dhcp_reply_t offer;
  dhcp_reply_t ack;
  if (network_device_get_mac(mac) != XAIOS_OK || timeout_ns == 0U) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t started = timer_now_ns();
  uint64_t offer_deadline = started + timeout_ns / 2U;
  if (offer_deadline < started) return XAIOS_ERR_INVALID;
  xaios_status_t status = exchange_request(DHCP_DISCOVER, DHCP_OFFER, 0U, 0U,
                                            offer_deadline, mac, &offer);
  if (status != XAIOS_OK) {
    klog("network: DHCP offer not received status=%d\n", (int)status);
    return XAIOS_ERR_IO;
  }
  uint64_t ack_deadline = started + timeout_ns;
  if (ack_deadline < started) return XAIOS_ERR_INVALID;
  status = exchange_request(DHCP_REQUEST, DHCP_ACK, offer.address,
                            offer.server, ack_deadline, mac, &ack);
  if (status != XAIOS_OK) {
    klog("network: DHCP acknowledgement not received status=%d\n", (int)status);
    return XAIOS_ERR_IO;
  }
  g_network_config.local_ipv4 = ack.address;
  g_network_config.gateway_ipv4 = ack.gateway == 0U ? offer.gateway : ack.gateway;
  g_network_config.netmask = ack.netmask == 0U ? XAIOS_IPV4_NETMASK : ack.netmask;
  g_network_config.dns_server = ack.dns == 0U ? UINT32_C(0x08080808) : ack.dns;
  copy_bytes(g_network_config.gateway_mac, ack.server_mac, 6U);
  g_network_config.dynamic = 1U;
  klog("network: DHCP lease ip=%08x mask=%08x gw=%08x dns=%08x\n",
       g_network_config.local_ipv4, g_network_config.netmask,
       g_network_config.gateway_ipv4, g_network_config.dns_server);
  return XAIOS_OK;
}

uint32_t network_config_local_ipv4(void) { return g_network_config.local_ipv4; }
uint32_t network_config_gateway_ipv4(void) { return g_network_config.gateway_ipv4; }
uint32_t network_config_netmask(void) { return g_network_config.netmask; }
uint32_t network_config_dns_server(void) { return g_network_config.dns_server; }
void network_config_gateway_mac(uint8_t mac[6]) {
  if (mac != 0) copy_bytes(mac, g_network_config.gateway_mac, 6U);
}
uint32_t network_config_is_dynamic(void) { return g_network_config.dynamic; }
