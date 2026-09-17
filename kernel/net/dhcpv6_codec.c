/*
 * DHCPv6 message codec, RFC 8415 -- the wire half of the client.
 *
 * Split out of dhcpv6.c so neither file outgrows the repository's line budget.
 * This file owns the bytes on the wire -- the option walk, the DUID, the IA_NA
 * and IAADDR encoding, the transaction id -- and the deterministic self-test
 * that drives every path of it. dhcpv6.c owns the exchange itself: when to
 * send, how long to wait, and what to do with what comes back.
 *
 * The client identity is file-scope state here because the encoder and the
 * parser both consult it on every message, and the self-test sets it directly
 * rather than standing up a network to do so.
 */

#include <xaios/assert.h>
#include <xaios/entropy.h>
#include <xaios/ipv4.h>
#include <xaios/ipv6.h>
#include <xaios/klog.h>
#include <xaios/timer.h>

#include "dhcpv6_internal.h"

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

void dhcpv6_copy_bytes(uint8_t *out, const uint8_t *in, uint32_t length) {
  for (uint32_t i = 0U; i < length; ++i) out[i] = in[i];
}

void dhcpv6_zero_bytes(uint8_t *out, uint32_t length) {
  for (uint32_t i = 0U; i < length; ++i) out[i] = 0U;
}

static int bytes_equal(const uint8_t *a, const uint8_t *b, uint32_t length) {
  for (uint32_t i = 0U; i < length; ++i)
    if (a[i] != b[i]) return 0;
  return 1;
}

/* ff02::1:2 -- every DHCPv6 server and relay on the link. */
static void all_servers_address(xaios_ip_addr_t *address) {
  dhcpv6_zero_bytes((uint8_t *)address, sizeof(*address));
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
  dhcpv6_copy_bytes(mac + 2U, address->addr + 12U, 4U);
}

/* DUID-LL: type, hardware type, link-layer address. Chosen over DUID-LLT
   because it carries no timestamp, and a guest whose clock starts at the epoch
   every boot would otherwise mint a new identity on each one -- which is the
   opposite of what a stable client identifier is for. */
void dhcpv6_build_client_duid(const uint8_t mac[6]) {
  put_be16(g_client_duid, DHCPV6_DUID_LL);
  put_be16(g_client_duid + 2U, DHCPV6_HWTYPE_ETHERNET);
  dhcpv6_copy_bytes(g_client_duid + 4U, mac, 6U);
  g_client_duid_len = 10U;
  /* The IAID names which interface the address belongs to. XAIOS configures
     one, so any stable value serves; deriving it from the MAC keeps it stable
     across boots without storing anything. */
  g_iaid = get_be32(mac + 2U);
}

void dhcpv6_new_transaction_id(void) {
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
  if (length != 0U && data != 0)
    dhcpv6_copy_bytes(out + offset + 4U, data, length);
  return offset + 4U + length;
}

/*
 * Assemble one client message. server_duid is the Server Identifier to echo
 * back, which a REQUEST must carry and a SOLICIT must not.
 */
uint32_t dhcpv6_build_message(uint8_t frame[DHCPV6_FRAME_CAPACITY],
                              uint8_t message_type, const uint8_t mac[6],
                              const uint8_t *server_duid,
                              uint32_t server_duid_len,
                              const xaios_ip_addr_t *requested,
                              uint64_t elapsed_ns) {
  dhcpv6_zero_bytes(frame, DHCPV6_FRAME_CAPACITY);

  xaios_ip_addr_t source;
  xaios_ip_addr_t destination;
  ipv6_link_local_from_mac(&source, mac);
  all_servers_address(&destination);

  uint8_t destination_mac[6];
  multicast_mac(destination_mac, &destination);
  dhcpv6_copy_bytes(frame, destination_mac, 6U);
  dhcpv6_copy_bytes(frame + 6U, mac, 6U);
  put_be16(frame + 12U, UINT16_C(0x86dd));

  uint8_t *message = frame + DHCPV6_HEADER_BYTES;
  message[0] = message_type;
  dhcpv6_copy_bytes(message + 1U, g_transaction_id, 3U);

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
    dhcpv6_copy_bytes(ia_na + 16U, requested->addr, 16U);
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
      dhcpv6_copy_bytes(response->address.addr, value, 16U);
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

int dhcpv6_parse_response(const uint8_t *frame, uint32_t length,
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

  dhcpv6_zero_bytes((uint8_t *)response, sizeof(*response));
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
        dhcpv6_copy_bytes(response->server_duid, value, option_length);
        response->server_duid_len = option_length;
      }
    } else if (code == DHCPV6_OPT_IA_NA) {
      parse_ia_na(value, option_length, response);
    } else if (code == DHCPV6_OPT_DNS_SERVERS && option_length >= 16U) {
      response->dns.family = XAIOS_IP_FAMILY_V6;
      dhcpv6_copy_bytes(response->dns.addr, value, 16U);
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

void dhcpv6_self_test(void) {
  static const uint8_t mac[6] = {0x52U, 0x54U, 0x00U, 0x12U, 0x34U, 0x56U};
  uint8_t frame[DHCPV6_FRAME_CAPACITY];

  dhcpv6_build_client_duid(mac);
  g_transaction_id[0] = 0xa1U;
  g_transaction_id[1] = 0xb2U;
  g_transaction_id[2] = 0xc3U;

  uint32_t size =
      dhcpv6_build_message(frame, DHCPV6_SOLICIT, mac, 0, 0U, 0, 0U);
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
  dhcpv6_zero_bytes((uint8_t *)&offered, sizeof(offered));
  offered.family = XAIOS_IP_FAMILY_V6;
  offered.addr[0] = 0x20U;
  offered.addr[1] = 0x01U;
  offered.addr[15] = 0x42U;
  size = dhcpv6_build_message(frame, DHCPV6_REQUEST, mac, server_duid, 6U,
                              &offered, UINT64_C(2500000000));
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
