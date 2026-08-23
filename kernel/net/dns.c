#include <xaios/assert.h>
#include <xaios/dns.h>
#include <xaios/dnssec.h>
#include <xaios/ipv4.h>
#include <xaios/klog.h>
#include <xaios/network_stack.h>
#include <xaios/timer.h>
#include <xaios/net_device.h>
#include <xaios/network_config.h>
#include <xaios/virtio_rng.h>

#define DNS_UDP_FRAME_SIZE 512U
#define DNS_TCP_MESSAGE_SIZE 4096U
#define DNS_MAX_HOSTNAME 64U
#define DNS_RETRANSMIT_NS UINT64_C(5000000000)
#define DNS_QUERY_TIMEOUT_NS UINT64_C(15000000000)
#define DNS_MAX_RETRANSMITS 2U
#define DNS_MAX_POINTER_JUMPS 32U
#define DNS_EPHEMERAL_PORT_MIN UINT16_C(49152)
#define DNS_EDNS_UDP_SIZE UINT16_C(1232)
#define DNS_FLAG_QR UINT16_C(0x8000)
#define DNS_FLAG_TC UINT16_C(0x0200)
#define DNS_FLAG_RD UINT16_C(0x0100)
#define DNS_FLAG_CD UINT16_C(0x0010)
#define DNS_EDNS_DO UINT32_C(0x00008000)
#define DNS_TYPE_OPT UINT16_C(41)
#define DNS_TYPE_DS UINT16_C(43)
#define DNS_TYPE_DNSKEY UINT16_C(48)

enum dns_pending_state {
  DNS_PENDING_NONE = 0U,
  DNS_PENDING_UDP = 1U,
  DNS_PENDING_TCP_CONNECT = 2U,
  DNS_PENDING_TCP_REPLY = 3U,
  DNS_PENDING_COMPLETE = 4U,
};

enum dnssec_stage {
  DNSSEC_STAGE_ROOT_DNSKEY = 1U,
  DNSSEC_STAGE_CHILD_DS = 2U,
  DNSSEC_STAGE_CHILD_DNSKEY = 3U,
  DNSSEC_STAGE_ADDRESS = 4U,
};

typedef struct dns_cache_entry {
  uint8_t valid;
  uint8_t family;
  char hostname[DNS_MAX_HOSTNAME];
  xaios_ip_addr_t address;
  uint64_t expiry_ns;
} dns_cache_entry_t;

typedef struct dns_pending {
  uint8_t state;
  uint8_t family;
  uint8_t retransmits;
  uint8_t dnssec_stage;
  uint8_t zone_labels;
  uint8_t hostname_labels;
  uint16_t id;
  uint16_t query_type;
  uint16_t udp_port;
  uint16_t tcp_port;
  uint16_t udp_frame_len;
  uint16_t query_len;
  uint32_t tcp_flow_id;
  uint32_t tcp_received;
  xaios_status_t result;
  char hostname[DNS_MAX_HOSTNAME];
  char query_name[DNS_MAX_HOSTNAME];
  char child_zone[DNS_MAX_HOSTNAME];
  dnssec_keyset_t validated_keys;
  dnssec_dsset_t child_ds;
  uint64_t started_ns;
  uint64_t sent_ns;
  uint8_t udp_frame[DNS_UDP_FRAME_SIZE];
  uint8_t query[DNS_UDP_FRAME_SIZE];
  uint8_t tcp_reply[DNS_TCP_MESSAGE_SIZE + 2U];
} dns_pending_t;

static uint32_t g_dns_server_ip = UINT32_C(0x08080808);
static uint16_t g_next_dns_id = 1U;
static dns_cache_entry_t g_cache[XAIOS_DNS_CACHE_SIZE];
static dns_pending_t g_pending;
static uint64_t g_query_count;
static uint64_t g_response_count;
static uint64_t g_reject_count;
static uint64_t g_timeout_count;
static uint64_t g_tcp_fallback_count;
static uint64_t g_authenticated_count;

static void complete_pending(xaios_status_t status) {
  g_pending.state = DNS_PENDING_COMPLETE;
  g_pending.result = status;
  if (g_pending.tcp_flow_id != 0U)
    (void)network_stack_tcp_abort_flow(g_pending.tcp_flow_id);
  g_pending.tcp_flow_id = 0U;
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
         ((uint32_t)src[2] << 8U) | src[3];
}

static uint32_t str_len(const char *value) {
  uint32_t length = 0U;
  while (value[length] != '\0') ++length;
  return length;
}

static uint8_t ascii_lower(uint8_t value) {
  return value >= 'A' && value <= 'Z' ? (uint8_t)(value + ('a' - 'A')) : value;
}

static int str_case_equal(const char *a, const char *b, uint32_t capacity) {
  for (uint32_t i = 0U; i < capacity; ++i) {
    if (ascii_lower((uint8_t)a[i]) != ascii_lower((uint8_t)b[i])) return 0;
    if (a[i] == '\0') return 1;
  }
  return 0;
}

static void str_copy(char *dst, const char *src, uint32_t capacity) {
  uint32_t i = 0U;
  while (i + 1U < capacity && src[i] != '\0') {
    dst[i] = src[i];
    ++i;
  }
  dst[i] = '\0';
}

static void bytes_zero(void *buffer, uint32_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint32_t i = 0U; i < size; ++i) bytes[i] = 0U;
}

static void bytes_copy(void *output, const void *input, uint32_t size) {
  uint8_t *dst = (uint8_t *)output;
  const uint8_t *src = (const uint8_t *)input;
  for (uint32_t i = 0U; i < size; ++i) dst[i] = src[i];
}

static uint16_t random_u16(uint16_t fallback) {
  uint16_t value = 0U;
  if (virtio_rng_read(&value, sizeof(value)) != XAIOS_OK) value = fallback;
  return value;
}

static uint16_t random_ephemeral_port(uint16_t fallback) {
  return (uint16_t)(DNS_EPHEMERAL_PORT_MIN |
                    (random_u16(fallback) & UINT16_C(0x3fff)));
}

void dns_init(void) {
  bytes_zero(g_cache, sizeof(g_cache));
  bytes_zero(&g_pending, sizeof(g_pending));
  g_next_dns_id = 1U;
  g_query_count = 0U;
  g_response_count = 0U;
  g_reject_count = 0U;
  g_timeout_count = 0U;
  g_tcp_fallback_count = 0U;
  g_authenticated_count = 0U;
  dnssec_init();
}

void dns_configure(uint32_t server_ip) {
  g_dns_server_ip = server_ip;
  klog("dns: configured validating resolver %u.%u.%u.%u\n",
       (unsigned)(server_ip >> 24U), (unsigned)((server_ip >> 16U) & 0xffU),
       (unsigned)((server_ip >> 8U) & 0xffU), (unsigned)(server_ip & 0xffU));
}

uint32_t dns_encode_name(uint8_t *buf, uint32_t buf_size, const char *name) {
  if (buf == 0 || name == 0 || buf_size == 0U) return 0U;
  if (name[0] == '\0') {
    buf[0] = 0U;
    return 1U;
  }
  uint32_t wi = 0U;
  uint32_t si = 0U;
  while (name[si] != '\0') {
    if (name[si] == '.') return 0U;
    uint32_t label_start = wi;
    if (wi >= buf_size || wi >= 255U) return 0U;
    buf[wi++] = 0U;
    while (name[si] != '\0' && name[si] != '.') {
      if (wi >= buf_size || wi >= 255U) return 0U;
      buf[wi++] = (uint8_t)name[si++];
    }
    uint32_t label_length = wi - label_start - 1U;
    if (label_length == 0U || label_length > 63U) return 0U;
    buf[label_start] = (uint8_t)label_length;
    if (name[si] == '.') {
      ++si;
      if (name[si] == '\0') break;
    }
  }
  if (wi >= buf_size || wi >= 255U) return 0U;
  buf[wi] = 0U;
  return wi + 1U;
}

int dns_decode_name(const uint8_t *message, uint32_t message_length,
                    uint32_t offset, char *output, uint32_t output_size) {
  if (message == 0 || output == 0 || output_size == 0U ||
      offset >= message_length) return -1;
  uint32_t output_position = 0U;
  uint32_t position = offset;
  uint32_t next_offset = 0U;
  uint32_t pointer_jumps = 0U;
  while (position < message_length) {
    uint8_t label_length = message[position];
    if (label_length == 0U) {
      if (next_offset == 0U) next_offset = position + 1U;
      if (output_position >= output_size) return -1;
      output[output_position] = '\0';
      return next_offset <= (uint32_t)INT32_MAX ? (int)next_offset : -1;
    }
    if ((label_length & 0xc0U) == 0xc0U) {
      if (position + 1U >= message_length) return -1;
      uint16_t pointer = (uint16_t)(
          ((uint16_t)(label_length & 0x3fU) << 8U) | message[position + 1U]);
      if ((uint32_t)pointer >= message_length ||
          ++pointer_jumps > DNS_MAX_POINTER_JUMPS) return -1;
      if (next_offset == 0U) next_offset = position + 2U;
      position = pointer;
      continue;
    }
    if ((label_length & 0xc0U) != 0U || label_length > 63U ||
        position + 1U + label_length > message_length) return -1;
    if (output_position != 0U) {
      if (output_position + 1U >= output_size) return -1;
      output[output_position++] = '.';
    }
    for (uint8_t i = 0U; i < label_length; ++i) {
      if (output_position + 1U >= output_size) return -1;
      output[output_position++] =
          (char)message[position + 1U + (uint32_t)i];
    }
    position += 1U + label_length;
  }
  return -1;
}

static int cache_lookup(const char *hostname, uint8_t family,
                        xaios_ip_addr_t *address, uint64_t now_ns) {
  for (uint32_t i = 0U; i < XAIOS_DNS_CACHE_SIZE; ++i) {
    if (g_cache[i].valid != 0U && g_cache[i].family == family &&
        str_case_equal(g_cache[i].hostname, hostname, DNS_MAX_HOSTNAME) &&
        now_ns < g_cache[i].expiry_ns) {
      *address = g_cache[i].address;
      return 1;
    }
  }
  return 0;
}

static void cache_insert(const char *hostname, const xaios_ip_addr_t *address,
                         uint32_t ttl_seconds, uint64_t now_ns) {
  uint32_t replace = 0U;
  uint64_t oldest = UINT64_MAX;
  for (uint32_t i = 0U; i < XAIOS_DNS_CACHE_SIZE; ++i) {
    if (g_cache[i].valid == 0U) {
      replace = i;
      break;
    }
    if (g_cache[i].family == address->family &&
        str_case_equal(g_cache[i].hostname, hostname, DNS_MAX_HOSTNAME)) {
      replace = i;
      break;
    }
    if (g_cache[i].expiry_ns < oldest) {
      oldest = g_cache[i].expiry_ns;
      replace = i;
    }
  }
  g_cache[replace].valid = 1U;
  g_cache[replace].family = address->family;
  str_copy(g_cache[replace].hostname, hostname, DNS_MAX_HOSTNAME);
  g_cache[replace].address = *address;
  uint64_t ttl_ns = (uint64_t)ttl_seconds * UINT64_C(1000000000);
  g_cache[replace].expiry_ns =
      ttl_ns > UINT64_MAX - now_ns ? UINT64_MAX : now_ns + ttl_ns;
}

static uint32_t build_query(uint8_t *output, uint32_t capacity,
                            const char *hostname, uint16_t id,
                            uint16_t query_type) {
  if (capacity < 32U) return 0U;
  put_be16(output, id);
  /* RFC 4035: request DNSSEC records and perform validation locally. CD
   * prevents an upstream recursive resolver's AD decision becoming our trust
   * decision. */
  put_be16(output + 2U, DNS_FLAG_RD | DNS_FLAG_CD);
  put_be16(output + 4U, 1U);
  put_be16(output + 6U, 0U);
  put_be16(output + 8U, 0U);
  put_be16(output + 10U, 1U);
  uint32_t position = 12U;
  uint32_t encoded = dns_encode_name(output + position, capacity - position,
                                     hostname);
  if (encoded == 0U || capacity - position < encoded + 15U) return 0U;
  position += encoded;
  put_be16(output + position, query_type);
  position += 2U;
  put_be16(output + position, XAIOS_DNS_CLASS_IN);
  position += 2U;
  output[position++] = 0U;
  put_be16(output + position, DNS_TYPE_OPT);
  position += 2U;
  put_be16(output + position, DNS_EDNS_UDP_SIZE);
  position += 2U;
  put_be32(output + position, DNS_EDNS_DO);
  position += 4U;
  put_be16(output + position, 0U);
  position += 2U;
  return position;
}

static xaios_status_t send_udp_query(dns_pending_t *pending) {
  uint8_t *frame = pending->udp_frame;
  network_config_gateway_mac(frame);
  uint8_t local_mac[6];
  if (network_device_get_mac(local_mac) != XAIOS_OK) {
    static const uint8_t fallback[6] = {0x02U, 0U, 0U, 0U, 0U, 1U};
    bytes_copy(local_mac, fallback, sizeof(fallback));
  }
  bytes_copy(frame + 6U, local_mac, sizeof(local_mac));
  put_be16(frame + 12U, UINT16_C(0x0800));
  uint32_t ip_offset = 14U;
  uint32_t udp_offset = ip_offset + XAIOS_IPV4_HEADER_SIZE;
  uint32_t dns_offset = udp_offset + 8U;
  if (dns_offset + pending->query_len > DNS_UDP_FRAME_SIZE)
    return XAIOS_ERR_INVALID;
  bytes_copy(frame + dns_offset, pending->query, pending->query_len);
  uint16_t udp_length = (uint16_t)(8U + pending->query_len);
  put_be16(frame + udp_offset, pending->udp_port);
  put_be16(frame + udp_offset + 2U, XAIOS_DNS_PORT);
  put_be16(frame + udp_offset + 4U, udp_length);
  put_be16(frame + udp_offset + 6U, 0U);
  uint16_t ip_total = (uint16_t)(XAIOS_IPV4_HEADER_SIZE + udp_length);
  ipv4_build_header(frame + ip_offset, ip_total, XAIOS_IPV4_PROTO_UDP,
                    network_config_local_ipv4(), g_dns_server_ip);
  pending->udp_frame_len = (uint16_t)(14U + ip_total);
  return network_device_tx(frame, pending->udp_frame_len);
}

static uint8_t hostname_label_count(const char *hostname) {
  uint8_t count = hostname[0] == '\0' ? 0U : 1U;
  for (uint32_t i = 0U; hostname[i] != '\0'; ++i)
    if (hostname[i] == '.') ++count;
  return count;
}

/* Write the zone formed by the last `labels` labels of `hostname`.

   That zone starts just after the dot with `labels` labels to its right, so
   the search needs one fewer dot than it might look. When the zone is the
   hostname itself there is no such dot at all, which is the ordinary case for
   any name whose apex is the name being resolved, such as example.com. */
static int child_zone_name(const char *hostname, uint8_t labels,
                           char *out, uint32_t capacity) {
  if (labels == 0U || capacity == 0U) return -1;
  uint8_t total = hostname_label_count(hostname);
  if (labels > total) return -1;
  uint32_t start = 0U;
  if (labels < total) {
    uint8_t seen = 0U;
    for (uint32_t i = str_len(hostname); i > 0U; --i) {
      if (hostname[i - 1U] == '.' && ++seen == labels) {
        start = i;
        break;
      }
    }
    if (seen != labels) return -1;
  }
  if (str_len(hostname + start) + 1U > capacity) return -1;
  str_copy(out, hostname + start, capacity);
  return 0;
}

static xaios_status_t start_query(dns_pending_t *pending, const char *name,
                                  uint16_t type, uint64_t now_ns) {
  str_copy(pending->query_name, name, sizeof(pending->query_name));
  pending->query_type = type;
  pending->id = random_u16(g_next_dns_id++);
  if (pending->id == 0U) pending->id = g_next_dns_id;
  if (g_next_dns_id == 0U) g_next_dns_id = 1U;
  pending->retransmits = 0U;
  pending->udp_port = random_ephemeral_port((uint16_t)(UINT16_C(0xc001) ^ pending->id));
  pending->tcp_port = random_ephemeral_port((uint16_t)(UINT16_C(0xc002) ^ pending->id));
  if (pending->tcp_port == pending->udp_port) ++pending->tcp_port;
  pending->query_len = (uint16_t)build_query(pending->query,
      sizeof(pending->query), name, pending->id, type);
  if (pending->query_len == 0U) return XAIOS_ERR_INVALID;
  pending->state = DNS_PENDING_UDP;
  if (send_udp_query(pending) != XAIOS_OK) return XAIOS_ERR_IO;
  pending->sent_ns = now_ns;
  ++g_query_count;
  return XAIOS_OK;
}

xaios_status_t dns_resolve_address(const char *hostname, uint8_t family,
                                   xaios_ip_addr_t *out_address) {
  if (hostname == 0 || out_address == 0 ||
      (family != XAIOS_IP_FAMILY_V4 && family != XAIOS_IP_FAMILY_V6)) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t now_ns = timer_now_ns();
  if (cache_lookup(hostname, family, out_address, now_ns)) return XAIOS_OK;
  if (g_pending.state == DNS_PENDING_COMPLETE) {
    if (g_pending.family == family &&
        str_case_equal(g_pending.hostname, hostname, DNS_MAX_HOSTNAME)) {
      xaios_status_t result = g_pending.result;
      bytes_zero(&g_pending, sizeof(g_pending));
      return result;
    }
    bytes_zero(&g_pending, sizeof(g_pending));
  }
  uint32_t hostname_length = str_len(hostname);
  if (hostname_length == 0U || hostname_length >= DNS_MAX_HOSTNAME)
    return XAIOS_ERR_INVALID;
  if (g_pending.state != DNS_PENDING_NONE) return XAIOS_ERR_BUSY;
  bytes_zero(&g_pending, sizeof(g_pending));
  g_pending.family = family;
  str_copy(g_pending.hostname, hostname, DNS_MAX_HOSTNAME);
  g_pending.hostname_labels = hostname_label_count(hostname);
  if (g_pending.hostname_labels == 0U) return XAIOS_ERR_INVALID;
  g_pending.dnssec_stage = DNSSEC_STAGE_ROOT_DNSKEY;
  g_pending.started_ns = now_ns;
  if (start_query(&g_pending, "", DNS_TYPE_DNSKEY, now_ns) != XAIOS_OK) {
    bytes_zero(&g_pending, sizeof(g_pending));
    ++g_reject_count;
    return XAIOS_ERR_IO;
  }
  klog("dns: resolve %s type=%u dnssec=local-chain\n", hostname,
       family == XAIOS_IP_FAMILY_V4 ? XAIOS_DNS_TYPE_A : XAIOS_DNS_TYPE_AAAA);
  return XAIOS_ERR_BUSY;
}

xaios_status_t dns_resolve(const char *hostname, uint32_t *out_ip) {
  if (out_ip == 0) return XAIOS_ERR_INVALID;
  xaios_ip_addr_t address;
  xaios_status_t status = dns_resolve_address(
      hostname, XAIOS_IP_FAMILY_V4, &address);
  if (status == XAIOS_OK) *out_ip = xaios_ip_addr_to_ipv4(&address);
  return status;
}

xaios_status_t dns_process_message(const uint8_t *message, uint32_t length,
                                   uint64_t now_ns, uint32_t from_tcp) {
  if (message == 0 || length < 12U || g_pending.state == DNS_PENDING_NONE ||
      get_be16(message) != g_pending.id) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }
  uint16_t flags = get_be16(message + 2U);
  if ((flags & UINT16_C(0xf800)) != DNS_FLAG_QR) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }
  if ((flags & DNS_FLAG_TC) != 0U && from_tcp == 0U) {
    g_pending.state = DNS_PENDING_TCP_CONNECT;
    g_pending.tcp_flow_id = 0U;
    g_pending.tcp_received = 0U;
    ++g_tcp_fallback_count;
    return XAIOS_ERR_BUSY;
  }
  if ((flags & DNS_FLAG_TC) != 0U || (flags & 0x000fU) != 0U) {
    complete_pending(XAIOS_ERR_NOT_FOUND);
    ++g_response_count;
    return XAIOS_ERR_NOT_FOUND;
  }
  uint16_t question_count = get_be16(message + 4U);
  if (question_count != 1U) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }
  uint32_t position = 12U;
  char question[XAIOS_DNS_MAX_NAME];
  int decoded = dns_decode_name(message, length, position, question,
                                sizeof(question));
  if (decoded < 0 || !str_case_equal(question, g_pending.query_name,
                                     DNS_MAX_HOSTNAME)) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }
  position = (uint32_t)decoded;
  if (position > length || length - position < 4U ||
      get_be16(message + position) != g_pending.query_type ||
      get_be16(message + position + 2U) != XAIOS_DNS_CLASS_IN) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }
  position += 4U;
  xaios_status_t status = XAIOS_ERR_INVALID;
  uint64_t wall_ns = wall_time_now_ns();
  if (g_pending.dnssec_stage == DNSSEC_STAGE_ROOT_DNSKEY) {
    status = dnssec_verify_dnskey(message, length, "", 0, wall_ns,
                                  &g_pending.validated_keys);
    if (status == XAIOS_OK) {
      g_pending.zone_labels = 1U;
      if (child_zone_name(g_pending.hostname, g_pending.zone_labels,
                          g_pending.child_zone, sizeof(g_pending.child_zone)) == 0)
        status = start_query(&g_pending, g_pending.child_zone, DNS_TYPE_DS, now_ns);
      else status = XAIOS_ERR_INVALID;
      g_pending.dnssec_stage = DNSSEC_STAGE_CHILD_DS;
    }
  } else if (g_pending.dnssec_stage == DNSSEC_STAGE_CHILD_DS) {
    status = dnssec_verify_ds(message, length, g_pending.child_zone,
                             &g_pending.validated_keys, wall_ns,
                             &g_pending.child_ds);
    if (status == XAIOS_OK) {
      status = start_query(&g_pending, g_pending.child_zone, DNS_TYPE_DNSKEY, now_ns);
      g_pending.dnssec_stage = DNSSEC_STAGE_CHILD_DNSKEY;
    } else if (dnssec_verify_nodata(message, length, g_pending.child_zone,
                                    DNS_TYPE_DS, &g_pending.validated_keys,
                                    wall_ns) == XAIOS_OK) {
      status = start_query(&g_pending, g_pending.hostname,
                           g_pending.family == XAIOS_IP_FAMILY_V4 ? XAIOS_DNS_TYPE_A : XAIOS_DNS_TYPE_AAAA, now_ns);
      g_pending.dnssec_stage = DNSSEC_STAGE_ADDRESS;
    }
  } else if (g_pending.dnssec_stage == DNSSEC_STAGE_CHILD_DNSKEY) {
    dnssec_keyset_t child_keys;
    status = dnssec_verify_dnskey(message, length, g_pending.child_zone,
                                  &g_pending.child_ds, wall_ns, &child_keys);
    if (status == XAIOS_OK) {
      g_pending.validated_keys = child_keys;
      if (g_pending.zone_labels == g_pending.hostname_labels) {
        status = start_query(&g_pending, g_pending.hostname,
                             g_pending.family == XAIOS_IP_FAMILY_V4 ? XAIOS_DNS_TYPE_A : XAIOS_DNS_TYPE_AAAA, now_ns);
        g_pending.dnssec_stage = DNSSEC_STAGE_ADDRESS;
      } else {
        ++g_pending.zone_labels;
        if (child_zone_name(g_pending.hostname, g_pending.zone_labels,
                            g_pending.child_zone, sizeof(g_pending.child_zone)) == 0)
          status = start_query(&g_pending, g_pending.child_zone, DNS_TYPE_DS, now_ns);
        else status = XAIOS_ERR_INVALID;
        g_pending.dnssec_stage = DNSSEC_STAGE_CHILD_DS;
      }
    }
  } else if (g_pending.dnssec_stage == DNSSEC_STAGE_ADDRESS) {
    uint8_t bytes[16]; uint32_t ttl = 0U;
    uint16_t type = g_pending.family == XAIOS_IP_FAMILY_V4 ? XAIOS_DNS_TYPE_A : XAIOS_DNS_TYPE_AAAA;
    status = dnssec_verify_address(message, length, g_pending.hostname, type,
                                   &g_pending.validated_keys, wall_ns, bytes, &ttl);
    if (status == XAIOS_OK) {
      xaios_ip_addr_t answer; xaios_ip_addr_zero(&answer); answer.family = g_pending.family;
      bytes_copy(answer.addr, bytes, g_pending.family == XAIOS_IP_FAMILY_V4 ? 4U : 16U);
      cache_insert(g_pending.hostname, &answer, ttl, now_ns);
      ++g_authenticated_count; ++g_response_count;
      if (g_pending.tcp_flow_id != 0U) (void)network_stack_tcp_close_flow(g_pending.tcp_flow_id);
      bytes_zero(&g_pending, sizeof(g_pending)); return XAIOS_OK;
    }
    if (dnssec_verify_nodata(message, length, g_pending.hostname, type,
                             &g_pending.validated_keys, wall_ns) == XAIOS_OK)
      status = XAIOS_ERR_NOT_FOUND;
  }
  if (status == XAIOS_OK && g_pending.state == DNS_PENDING_UDP)
    return XAIOS_ERR_BUSY;
  if (status == XAIOS_OK || status == XAIOS_ERR_BUSY) return status;
  complete_pending(status); ++g_reject_count; return status;
}

xaios_status_t dns_process_ipv4_frame(const uint8_t *frame,
                                      uint32_t frame_length,
                                      uint64_t now_ns) {
  if (frame == 0 || frame_length < 42U ||
      g_pending.state != DNS_PENDING_UDP) return XAIOS_ERR_NOT_FOUND;
  if (get_be16(frame + 12U) != UINT16_C(0x0800) ||
      !ipv4_validate_incoming(frame, frame_length) ||
      ipv4_is_fragment(frame, frame_length)) return XAIOS_ERR_INVALID;
  const uint8_t *ip = frame + 14U;
  uint32_t ip_header_length = (uint32_t)(ip[0] & 0x0fU) * 4U;
  uint16_t ip_total = get_be16(ip + 2U);
  if (ip[9U] != XAIOS_IPV4_PROTO_UDP || ip_header_length < 20U ||
      get_be32(ip + 12U) != g_dns_server_ip ||
      ip_total < ip_header_length + 8U || 14U + ip_total > frame_length)
    return XAIOS_ERR_NOT_FOUND;
  const uint8_t *udp = ip + ip_header_length;
  uint16_t udp_length = get_be16(udp + 4U);
  if (get_be16(udp) != XAIOS_DNS_PORT ||
      get_be16(udp + 2U) != g_pending.udp_port) return XAIOS_ERR_NOT_FOUND;
  if (udp_length < 8U || udp_length > ip_total - ip_header_length) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }
  uint16_t checksum = get_be16(udp + 6U);
  if (checksum != 0U &&
      ipv4_pseudo_checksum(get_be32(ip + 12U), get_be32(ip + 16U),
                           XAIOS_IPV4_PROTO_UDP, udp_length, udp,
                           udp_length) != 0U) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }
  return dns_process_message(udp + 8U, udp_length - 8U, now_ns, 0U);
}

void dns_transport_tick(uint64_t now_ns) {
  if (g_pending.state == DNS_PENDING_TCP_CONNECT) {
    if (g_pending.tcp_flow_id == 0U) {
      xaios_ip_addr_t server = xaios_ip_addr_from_ipv4(g_dns_server_ip);
      xaios_status_t status = network_stack_tcp_open(
          &server, XAIOS_DNS_PORT, g_pending.tcp_port,
          &g_pending.tcp_flow_id);
      if (status != XAIOS_OK) return;
    }
    xaios_status_t status =
        network_stack_tcp_open_status(g_pending.tcp_flow_id);
    if (status == XAIOS_ERR_BUSY) return;
    if (status != XAIOS_OK) {
      complete_pending(XAIOS_ERR_IO);
      ++g_reject_count;
      return;
    }
    uint8_t framed[DNS_UDP_FRAME_SIZE + 2U];
    put_be16(framed, g_pending.query_len);
    bytes_copy(framed + 2U, g_pending.query, g_pending.query_len);
    uint32_t written = 0U;
    if (network_stack_tcp_send(g_pending.tcp_flow_id, framed,
                               g_pending.query_len + 2U, &written) != XAIOS_OK ||
        written != g_pending.query_len + 2U) return;
    g_pending.state = DNS_PENDING_TCP_REPLY;
    g_pending.sent_ns = now_ns;
  }
  if (g_pending.state != DNS_PENDING_TCP_REPLY) return;
  uint32_t available = sizeof(g_pending.tcp_reply) - g_pending.tcp_received;
  uint32_t received = network_stack_tcp_recv(
      g_pending.tcp_flow_id, g_pending.tcp_reply + g_pending.tcp_received,
      available);
  g_pending.tcp_received += received;
  if (g_pending.tcp_received < 2U) return;
  uint32_t message_length = get_be16(g_pending.tcp_reply);
  if (message_length < 12U || message_length > DNS_TCP_MESSAGE_SIZE) {
    complete_pending(XAIOS_ERR_INVALID);
    ++g_reject_count;
    return;
  }
  if (g_pending.tcp_received < message_length + 2U) return;
  (void)dns_process_message(g_pending.tcp_reply + 2U, message_length, now_ns,
                            1U);
}

void dns_tick(uint64_t now_ns) {
  if (g_pending.state == DNS_PENDING_NONE ||
      g_pending.state == DNS_PENDING_COMPLETE) return;
  if (now_ns > g_pending.started_ns &&
      now_ns - g_pending.started_ns >= DNS_QUERY_TIMEOUT_NS) {
    klog("dns: query timeout id=%u host=%s\n", g_pending.id,
         g_pending.hostname);
    complete_pending(XAIOS_ERR_CANCELLED);
    ++g_timeout_count;
    return;
  }
  if (g_pending.state == DNS_PENDING_UDP &&
      g_pending.retransmits < DNS_MAX_RETRANSMITS &&
      now_ns > g_pending.sent_ns &&
      now_ns - g_pending.sent_ns >= DNS_RETRANSMIT_NS) {
    if (network_device_tx(g_pending.udp_frame, g_pending.udp_frame_len) != XAIOS_OK) {
      ++g_reject_count;
      return;
    }
    g_pending.sent_ns = now_ns;
    ++g_pending.retransmits;
  }
}

uint64_t dns_query_count(void) { return g_query_count; }
uint64_t dns_response_count(void) { return g_response_count; }
uint64_t dns_reject_count(void) { return g_reject_count; }
uint64_t dns_timeout_count(void) { return g_timeout_count; }
uint64_t dns_tcp_fallback_count(void) { return g_tcp_fallback_count; }
uint64_t dns_authenticated_count(void) { return g_authenticated_count; }
uint32_t dns_pending_count(void) {
  return g_pending.state != DNS_PENDING_NONE &&
                 g_pending.state != DNS_PENDING_COMPLETE
             ? 1U
             : 0U;
}

void dns_self_test(void) {
  dns_init();
  uint8_t encoded[64];
  uint32_t encoded_length = dns_encode_name(
      encoded, sizeof(encoded), "www.google.com");
  kassert(encoded_length == 16U && encoded[15] == 0U);
  char decoded[64];
  kassert(dns_decode_name(encoded, encoded_length, 0U, decoded,
                          sizeof(decoded)) > 0);
  kassert(str_case_equal(decoded, "www.google.com", sizeof(decoded)));
  uint8_t loop[2] = {0xc0U, 0x00U};
  kassert(dns_decode_name(loop, sizeof(loop), 0U, decoded,
                          sizeof(decoded)) < 0);
  uint8_t reserved[2] = {0x40U, 0U};
  kassert(dns_decode_name(reserved, sizeof(reserved), 0U, decoded,
                          sizeof(decoded)) < 0);
  kassert(dns_encode_name(encoded, sizeof(encoded), ".bad") == 0U);
  kassert(dns_encode_name(encoded, sizeof(encoded), "bad..name") == 0U);
  xaios_ip_addr_t address = xaios_ip_addr_from_ipv4(UINT32_C(0x01020304));
  cache_insert("cache.test", &address, 60U, UINT64_C(1000000));
  xaios_ip_addr_t result;
  kassert(cache_lookup("CACHE.TEST", XAIOS_IP_FAMILY_V4, &result,
                       UINT64_C(1000000)) == 1);
  kassert(xaios_ip_addr_to_ipv4(&result) == UINT32_C(0x01020304));
  kassert(cache_lookup("cache.test", XAIOS_IP_FAMILY_V6, &result,
                       UINT64_C(1000000)) == 0);
  klog("dns: self-test passed dnssec=local-chain tcp-fallback=enabled aaaa=enabled\n");
}
