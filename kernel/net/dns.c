#include <xaios/assert.h>
#include <xaios/dns.h>
#include <xaios/dnssec.h>
#include <xaios/ipv4.h>
#include <xaios/klog.h>
#include <xaios/spinlock.h>
#include <xaios/smp.h>
#include <xaios/network_stack.h>
#include <xaios/timer.h>
#include <xaios/net_device.h>
#include <xaios/network_config.h>
#include <xaios/virtio_rng.h>

#include "dns_selftest_chain.h"

#define DNS_UDP_FRAME_SIZE 512U
#define DNS_TCP_MESSAGE_SIZE 4096U
#define DNS_MAX_HOSTNAME XAIOS_DNS_MAX_HOSTNAME
#define DNS_RETRANSMIT_NS UINT64_C(5000000000)
#define DNS_MAX_RETRANSMITS 2U
/* B-35. Two deadlines, because there are two different ways to fail to get an
   answer and they need different budgets.

   DNS_QUERY_TIMEOUT_NS is one query's own deadline and is sized to the
   retransmit schedule it has to contain: the first transmit at t=0 and two
   retransmits at 5 s and 10 s, leaving the last one a full retransmit interval
   to be answered in. It used to be the budget for the entire DNSKEY -> DS ->
   DNSKEY -> address walk, because started_ns was set once per resolve and
   never reset by start_query -- so a chain whose every hop answered promptly
   still ran out of time at the third or fourth hop and was reported as if the
   name had gone unanswered. start_query now stamps query_started_ns, so each
   query gets this budget of its own.

   DNS_WALK_TIMEOUT_NS is what stops per-query deadlines from composing into an
   unbounded wait: a name of N labels costs 2N + 2 queries, and at 15 s each a
   deep name could keep a caller waiting for minutes. Budgeting the walk
   explicitly is the point -- an implicit budget that happens to fall out of
   one query's timer is exactly the defect above.

   Both expire as XAIOS_ERR_CANCELLED, never as XAIOS_ERR_INVALID: the
   difference a caller has to be able to see is "we never reached a verdict"
   against "we reached one and refused", and a timeout is always the former. */
#define DNS_QUERY_TIMEOUT_NS UINT64_C(15000000000)
#define DNS_WALK_TIMEOUT_NS UINT64_C(45000000000)
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
  /* DNSSEC has three outcomes. Set once a delegation is proven to carry no
     DS: everything below it is unsigned, so the address answer arrives with
     no RRSIG and must be accepted on the strength of that proof instead. */
  uint8_t dnssec_insecure;
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
  /* When the whole chain walk began, and when the query in flight began.
     sent_ns cannot serve as the latter: a retransmit moves it, so a query
     that is retransmitted twice would never reach its own deadline. */
  uint64_t walk_started_ns;
  uint64_t query_started_ns;
  uint64_t sent_ns;
  uint8_t udp_frame[DNS_UDP_FRAME_SIZE];
  uint8_t query[DNS_UDP_FRAME_SIZE];
  uint8_t tcp_reply[DNS_TCP_MESSAGE_SIZE + 2U];
} dns_pending_t;

/* C-01: the resolver cache is reached from the NET_RESOLVE syscall, which runs
   on the calling thread's CPU. It takes the network stack's guard rather than
   one of its own: this code calls tcp_open, send, recv and close, and
   network_poll_tick calls back into dns_tick, so a separate guard would invert
   the two orders the moment anyone added a call. */
static void dns_lock(void) { network_stack_lock(); }
static void dns_unlock(void) { network_stack_unlock(); }

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
static uint64_t g_insecure_count;

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
  g_insecure_count = 0U;
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
  pending->query_started_ns = now_ns;
  pending->sent_ns = now_ns;
  ++g_query_count;
  return XAIOS_OK;
}

static xaios_status_t dns_resolve_address_unlocked(const char *hostname, uint8_t family,
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
  g_pending.walk_started_ns = now_ns;
  if (start_query(&g_pending, "", DNS_TYPE_DNSKEY, now_ns) != XAIOS_OK) {
    bytes_zero(&g_pending, sizeof(g_pending));
    ++g_reject_count;
    return XAIOS_ERR_IO;
  }
  klog("dns: resolve %s type=%u dnssec=local-chain\n", hostname,
       family == XAIOS_IP_FAMILY_V4 ? XAIOS_DNS_TYPE_A : XAIOS_DNS_TYPE_AAAA);
  return XAIOS_ERR_BUSY;
}

xaios_status_t dns_resolve_address(const char *hostname, uint8_t family,
                                   xaios_ip_addr_t *out_address) {
  dns_lock();
  xaios_status_t result = dns_resolve_address_unlocked(hostname, family, out_address);
  dns_unlock();
  return result;
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
  /* The stage verifiers re-parse the whole message themselves, so nothing
     consumes an offset past the question section here. */
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
                                    wall_ns) == XAIOS_OK ||
               dnssec_verify_no_ds(message, length, g_pending.child_zone,
                                   &g_pending.validated_keys,
                                   wall_ns) == XAIOS_OK) {
      /* No DS at this delegation: the child is insecure, not bogus. Ask for
         the address directly rather than walking further down a chain that
         has no keys to offer. */
      g_pending.dnssec_insecure = 1U;
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
    status = g_pending.dnssec_insecure != 0U
                 ? dnssec_extract_address_insecure(message, length,
                                                   g_pending.hostname, type,
                                                   bytes, &ttl)
                 : dnssec_verify_address(message, length, g_pending.hostname,
                                         type, &g_pending.validated_keys,
                                         wall_ns, bytes, &ttl);
    if (status == XAIOS_OK) {
      xaios_ip_addr_t answer; xaios_ip_addr_zero(&answer); answer.family = g_pending.family;
      bytes_copy(answer.addr, bytes, g_pending.family == XAIOS_IP_FAMILY_V4 ? 4U : 16U);
      cache_insert(g_pending.hostname, &answer, ttl, now_ns);
      /* Only a validated chain counts as authenticated. An insecure answer
         is a separate, weaker result and is counted separately so the two
         can never be read as the same thing. */
      if (g_pending.dnssec_insecure != 0U) ++g_insecure_count;
      else ++g_authenticated_count;
      ++g_response_count;
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
  if (now_ns > g_pending.walk_started_ns &&
      now_ns - g_pending.walk_started_ns >= DNS_WALK_TIMEOUT_NS) {
    klog("dns: walk timeout id=%u host=%s stage=%u queries_unanswered=1\n",
         g_pending.id, g_pending.hostname, (unsigned)g_pending.dnssec_stage);
    complete_pending(XAIOS_ERR_CANCELLED);
    ++g_timeout_count;
    return;
  }
  if (now_ns > g_pending.query_started_ns &&
      now_ns - g_pending.query_started_ns >= DNS_QUERY_TIMEOUT_NS) {
    klog("dns: query timeout id=%u host=%s name=%s stage=%u\n", g_pending.id,
         g_pending.hostname, g_pending.query_name,
         (unsigned)g_pending.dnssec_stage);
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
uint64_t dns_insecure_count(void) { return g_insecure_count; }
uint32_t dns_pending_count(void) {
  return g_pending.state != DNS_PENDING_NONE &&
                 g_pending.state != DNS_PENDING_COMPLETE
             ? 1U
             : 0U;
}

/* B-34. This used to print "dnssec=local-chain tcp-fallback=enabled
   aaaa=enabled" after exercising the name codec and the cache and nothing
   else. It now walks a signed chain to an address, refuses a forged signature
   and an expired one, drives the truncation fallback in both directions,
   validates a AAAA RRset, and checks that each query is judged against its own
   deadline. The marker reports the counts those steps produced, so a step that
   stops running takes its own evidence with it.

   Two deliberate absences. The wall clock is not read: every verifier takes
   its validity time as an argument, and at this point in boot
   wall_time_now_ns() may still be the raw monotonic counter, which would make
   a genuine DNSSEC check fail on a machine whose RTC has not been read yet.
   And nothing is transmitted: the pending record is built in place rather than
   through dns_resolve_address, so a machine with no NIC still runs all of it.

   The chain in dns_selftest_chain.h is rooted at its own anchor, not at the
   real root; dns_init() at the end puts the IANA anchors back. */
#define DNS_SELFTEST_WALL_NS UINT64_C(1900000000000000000)
#define DNS_SELFTEST_EXPIRED_WALL_NS UINT64_C(2530000000000000000)

static uint32_t dns_self_test_chain(uint32_t *out_aaaa_validated) {
  dnssec_ds_t anchor;
  uint8_t address[16];
  uint8_t forged[sizeof(k_selftest_a)];
  uint32_t ttl = 0U;
  uint32_t links = 0U;
  /* The keyset and DS set live in the pending record rather than on the
     stack: a dnssec_keyset_t is several kilobytes and this runs on the boot
     stack. dns_init() above has already zeroed the record, and dns_init() at
     the end of the self-test clears it again. */
  dnssec_keyset_t *keys = &g_pending.validated_keys;
  dnssec_dsset_t *ds = &g_pending.child_ds;

  bytes_zero(&anchor, sizeof(anchor));
  anchor.key_tag = DNS_SELFTEST_ROOT_TAG;
  anchor.algorithm = 8U;
  anchor.digest_type = 2U;
  anchor.digest_length = (uint8_t)sizeof(k_selftest_anchor_digest);
  bytes_copy(anchor.digest, k_selftest_anchor_digest,
             sizeof(k_selftest_anchor_digest));
  kassert(dnssec_set_trust_anchors(&anchor, 1U) == XAIOS_OK);

  kassert(dnssec_verify_dnskey(k_selftest_root_dnskey,
                               (uint32_t)sizeof(k_selftest_root_dnskey), "", 0,
                               DNS_SELFTEST_WALL_NS, keys) == XAIOS_OK);
  ++links;
  kassert(dnssec_verify_ds(k_selftest_ds, (uint32_t)sizeof(k_selftest_ds),
                           DNS_SELFTEST_ZONE, keys, DNS_SELFTEST_WALL_NS,
                           ds) == XAIOS_OK);
  ++links;
  kassert(dnssec_verify_dnskey(k_selftest_dnskey,
                               (uint32_t)sizeof(k_selftest_dnskey),
                               DNS_SELFTEST_ZONE, ds, DNS_SELFTEST_WALL_NS,
                               keys) == XAIOS_OK);
  ++links;
  kassert(dnssec_verify_address(k_selftest_a, (uint32_t)sizeof(k_selftest_a),
                                DNS_SELFTEST_ZONE, XAIOS_DNS_TYPE_A, keys,
                                DNS_SELFTEST_WALL_NS, address,
                                &ttl) == XAIOS_OK);
  kassert(ttl == 60U);
  for (uint32_t i = 0U; i < sizeof(k_selftest_a_rdata); ++i)
    kassert(address[i] == k_selftest_a_rdata[i]);

  /* The control. A signature that has been tampered with must not validate:
     without this, every assertion above would still pass against a verifier
     that returned XAIOS_OK unconditionally. */
  bytes_copy(forged, k_selftest_a, sizeof(forged));
  forged[sizeof(forged) - 1U] ^= 0x01U;
  kassert(dnssec_verify_address(forged, (uint32_t)sizeof(forged),
                                DNS_SELFTEST_ZONE, XAIOS_DNS_TYPE_A, keys,
                                DNS_SELFTEST_WALL_NS, address,
                                &ttl) == XAIOS_ERR_INVALID);
  /* ...and neither must a signature that was valid and has expired. */
  kassert(dnssec_verify_address(k_selftest_a, (uint32_t)sizeof(k_selftest_a),
                                DNS_SELFTEST_ZONE, XAIOS_DNS_TYPE_A, keys,
                                DNS_SELFTEST_EXPIRED_WALL_NS, address,
                                &ttl) == XAIOS_ERR_INVALID);

  /* AAAA, validated through the same chain rather than asserted to exist. */
  kassert(dnssec_verify_address(k_selftest_aaaa,
                                (uint32_t)sizeof(k_selftest_aaaa),
                                DNS_SELFTEST_ZONE, XAIOS_DNS_TYPE_AAAA, keys,
                                DNS_SELFTEST_WALL_NS, address,
                                &ttl) == XAIOS_OK);
  for (uint32_t i = 0U; i < sizeof(k_selftest_aaaa_rdata); ++i)
    kassert(address[i] == k_selftest_aaaa_rdata[i]);
  *out_aaaa_validated = 1U;
  /* An A answer is not a AAAA answer however well it is signed. */
  kassert(dnssec_verify_address(k_selftest_a, (uint32_t)sizeof(k_selftest_a),
                                DNS_SELFTEST_ZONE, XAIOS_DNS_TYPE_AAAA, keys,
                                DNS_SELFTEST_WALL_NS, address,
                                &ttl) == XAIOS_ERR_INVALID);
  return links;
}

static void dns_self_test_pending(uint16_t id, uint8_t stage) {
  bytes_zero(&g_pending, sizeof(g_pending));
  g_pending.state = DNS_PENDING_UDP;
  g_pending.family = XAIOS_IP_FAMILY_V4;
  g_pending.query_type = XAIOS_DNS_TYPE_A;
  g_pending.dnssec_stage = stage;
  g_pending.hostname_labels = 1U;
  g_pending.id = id;
  /* Already out of retransmits, so dns_tick reaches its deadlines without
     asking a network device that may not exist to send anything. */
  g_pending.retransmits = DNS_MAX_RETRANSMITS;
  str_copy(g_pending.hostname, DNS_SELFTEST_ZONE, DNS_MAX_HOSTNAME);
  str_copy(g_pending.query_name, DNS_SELFTEST_ZONE, DNS_MAX_HOSTNAME);
}

static uint32_t dns_self_test_truncation(void) {
  /* A truncated UDP reply moves the query to TCP; a reply that is still
     truncated after the TCP attempt is a dead end, not another retry. Both
     decisions are taken on the twelve-byte header, before any validation, so
     neither needs a signature, a clock, or a NIC. */
  uint8_t reply[12];
  uint64_t before = g_tcp_fallback_count;
  dns_self_test_pending(UINT16_C(0xbeef), DNSSEC_STAGE_ADDRESS);
  bytes_zero(reply, sizeof(reply));
  put_be16(reply, g_pending.id);
  put_be16(reply + 2U, (uint16_t)(DNS_FLAG_QR | DNS_FLAG_TC));
  kassert(dns_process_message(reply, sizeof(reply), 0U, 0U) == XAIOS_ERR_BUSY);
  kassert(g_pending.state == DNS_PENDING_TCP_CONNECT);
  kassert(g_tcp_fallback_count == before + 1U);
  kassert(dns_process_message(reply, sizeof(reply), 0U, 1U) ==
          XAIOS_ERR_NOT_FOUND);
  kassert(g_pending.state == DNS_PENDING_COMPLETE);
  kassert(g_pending.result == XAIOS_ERR_NOT_FOUND);
  return (uint32_t)(g_tcp_fallback_count - before);
}

static void dns_self_test_deadlines(void) {
  /* B-35, in the kernel that has to honour it. The clock is supplied, so this
     is exact rather than timing-dependent.

     The first tick is the control that fails on the defect: the walk is 21 s
     old, past the 15 s that used to cover all of it, while the query in flight
     is 1 s old. A resolver that judges a query by when the walk began ends the
     resolution here. */
  uint64_t timeouts = g_timeout_count;
  klog("dns: self-test exercising resolver deadlines; the two timeout lines "
       "below are the test, not a fault\n");
  dns_self_test_pending(UINT16_C(0x0d15), DNSSEC_STAGE_CHILD_DS);
  g_pending.walk_started_ns = 0U;
  g_pending.query_started_ns = UINT64_C(20000000000);
  g_pending.sent_ns = g_pending.query_started_ns;
  dns_tick(UINT64_C(21000000000));
  kassert(g_pending.state == DNS_PENDING_UDP);
  kassert(g_timeout_count == timeouts);
  /* Its own deadline still ends it, and ends it as "no verdict". */
  dns_tick(g_pending.query_started_ns + DNS_QUERY_TIMEOUT_NS);
  kassert(g_pending.state == DNS_PENDING_COMPLETE);
  kassert(g_pending.result == XAIOS_ERR_CANCELLED);
  kassert(g_timeout_count == timeouts + 1U);

  /* And the walk budget ends a walk whose query in flight is young, which is
     what stops per-query deadlines composing without bound. */
  dns_self_test_pending(UINT16_C(0x0d16), DNSSEC_STAGE_CHILD_DNSKEY);
  g_pending.walk_started_ns = 0U;
  g_pending.query_started_ns = DNS_WALK_TIMEOUT_NS - UINT64_C(5000000000);
  g_pending.sent_ns = g_pending.query_started_ns;
  dns_tick(DNS_WALK_TIMEOUT_NS);
  kassert(g_pending.state == DNS_PENDING_COMPLETE);
  kassert(g_pending.result == XAIOS_ERR_CANCELLED);
  kassert(g_timeout_count == timeouts + 2U);
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
  uint32_t aaaa_validated = 0U;
  uint32_t links = dns_self_test_chain(&aaaa_validated);
  uint32_t truncations = dns_self_test_truncation();
  dns_self_test_deadlines();
  /* Put the real root anchors back and drop everything the test left behind:
     the test anchor, the fake pending record, and the test's counter values. */
  dns_init();
  klog("dns: self-test passed dnssec=local-chain tcp-fallback=enabled "
       "aaaa=enabled chain_links=%u forged_signature=rejected "
       "expired_signature=rejected truncated_reply=%u validated_aaaa=%u\n",
       (unsigned)links, (unsigned)truncations, (unsigned)aaaa_validated);
}
