#include <xaios/assert.h>
#include <xaios/dns.h>
#include <xaios/dnssec.h>
#include <xaios/ipv4.h>
#include <xaios/klog.h>
#include <xaios/local_ports.h>
#include <xaios/spinlock.h>
#include <xaios/smp.h>
#include <xaios/network_stack.h>
#include <xaios/timer.h>
#include <xaios/net_device.h>
#include <xaios/network_config.h>
#include <xaios/virtio_rng.h>

#include "dns_internal.h"

typedef struct dns_cache_entry {
  uint8_t valid;
  uint8_t family;
  char hostname[DNS_MAX_HOSTNAME];
  xaios_ip_addr_t address;
  uint64_t expiry_ns;
} dns_cache_entry_t;

uint32_t g_dns_server_ip = UINT32_C(0x08080808);
uint16_t g_dns_next_id = 1U;
static dns_cache_entry_t g_cache[XAIOS_DNS_CACHE_SIZE];
dns_pending_t g_dns_pending;
uint64_t g_dns_query_count;
uint64_t g_dns_response_count;
uint64_t g_dns_reject_count;
uint64_t g_dns_timeout_count;
uint64_t g_dns_tcp_fallback_count;
uint64_t g_dns_authenticated_count;
uint64_t g_dns_insecure_count;

void dns_put_be16(uint8_t *dst, uint16_t value) {
  dst[0] = (uint8_t)(value >> 8U);
  dst[1] = (uint8_t)value;
}

uint16_t dns_get_be16(const uint8_t *src) {
  return (uint16_t)(((uint16_t)src[0] << 8U) | src[1]);
}

static void put_be32(uint8_t *dst, uint32_t value) {
  dst[0] = (uint8_t)(value >> 24U);
  dst[1] = (uint8_t)(value >> 16U);
  dst[2] = (uint8_t)(value >> 8U);
  dst[3] = (uint8_t)value;
}

uint32_t dns_get_be32(const uint8_t *src) {
  return ((uint32_t)src[0] << 24U) | ((uint32_t)src[1] << 16U) |
         ((uint32_t)src[2] << 8U) | src[3];
}

uint32_t dns_str_len(const char *value) {
  uint32_t length = 0U;
  while (value[length] != '\0') ++length;
  return length;
}

static uint8_t ascii_lower(uint8_t value) {
  return value >= 'A' && value <= 'Z' ? (uint8_t)(value + ('a' - 'A')) : value;
}

int dns_str_case_equal(const char *a, const char *b, uint32_t capacity) {
  for (uint32_t i = 0U; i < capacity; ++i) {
    if (ascii_lower((uint8_t)a[i]) != ascii_lower((uint8_t)b[i])) return 0;
    if (a[i] == '\0') return 1;
  }
  return 0;
}

void dns_str_copy(char *dst, const char *src, uint32_t capacity) {
  uint32_t i = 0U;
  while (i + 1U < capacity && src[i] != '\0') {
    dst[i] = src[i];
    ++i;
  }
  dst[i] = '\0';
}

void dns_bytes_zero(void *buffer, uint32_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint32_t i = 0U; i < size; ++i) bytes[i] = 0U;
}

void dns_bytes_copy(void *output, const void *input, uint32_t size) {
  uint8_t *dst = (uint8_t *)output;
  const uint8_t *src = (const uint8_t *)input;
  for (uint32_t i = 0U; i < size; ++i) dst[i] = src[i];
}

uint16_t dns_random_u16(uint16_t fallback) {
  uint16_t value = 0U;
  if (virtio_rng_read(&value, sizeof(value)) != XAIOS_OK) value = fallback;
  return value;
}

/* One of the resolver's own ports, drawn at random so that two queries in
   flight are not both answered on one number.
 *
 * This used to draw across 49152..65535, which is the range the socket
 * allocator hands out from, so a query could be answered on a port a
 * `net_open_udp` socket had also been given and nothing held both facts
 * (B-77). The block it draws from now is below that range and disjoint from
 * NTP's, and the span is a compile-time constant, so the modulo is exact and
 * cannot divide by zero. */
uint16_t dns_random_ephemeral_port(uint16_t fallback) {
  const uint16_t span = (uint16_t)(XAIOS_DNS_SOURCE_PORT_MAX -
                                   XAIOS_DNS_SOURCE_PORT_MIN + 1U);
  return (uint16_t)(XAIOS_DNS_SOURCE_PORT_MIN +
                    (uint16_t)(dns_random_u16(fallback) % span));
}

void dns_init(void) {
  dns_bytes_zero(g_cache, sizeof(g_cache));
  dns_bytes_zero(&g_dns_pending, sizeof(g_dns_pending));
  g_dns_next_id = 1U;
  g_dns_query_count = 0U;
  g_dns_response_count = 0U;
  g_dns_reject_count = 0U;
  g_dns_timeout_count = 0U;
  g_dns_tcp_fallback_count = 0U;
  g_dns_authenticated_count = 0U;
  g_dns_insecure_count = 0U;
  dnssec_init();
}

/* B-42. The anchors in force, on the boot log, from the table rather than
   from the source. The boot self-test walks a chain rooted at its own anchor
   and installs that anchor to do it, so "the real anchors are back by the time
   anything can resolve a name" is a claim about a global that a reader cannot
   check by reading either function alone -- and it is the claim that decides
   whether a shipping machine validates the internet or a committed test key.
   Printed here, where the resolver is handed its server and becomes usable,
   it is the same statement on a release image as on a boot-test one. */
void dns_log_trust_anchors(void) {
  uint16_t tags[XAIOS_DNSSEC_MAX_ANCHORS];
  uint32_t count = dnssec_trust_anchor_tags(tags, XAIOS_DNSSEC_MAX_ANCHORS);
  if (count == 0U) {
    klog("dns: trust anchors count=0 (no root anchor installed; every secure "
         "zone fails closed)\n");
    return;
  }
  /* The count comes from the table and the tags from the buffer, and the two
     are printed separately rather than the count being inferred from what
     fitted: an anchor set larger than this buffer then reads as a count with
     fewer tags beside it, which is a visible disagreement rather than a
     silent truncation. Five digits and a separator per tag. */
  char tag_list[XAIOS_DNSSEC_MAX_ANCHORS * 8U];
  uint32_t shown = count < XAIOS_DNSSEC_MAX_ANCHORS ? count
                                                    : XAIOS_DNSSEC_MAX_ANCHORS;
  uint32_t used = 0U;
  for (uint32_t i = 0U; i < shown; ++i) {
    if (i != 0U && used + 1U < sizeof(tag_list)) tag_list[used++] = ',';
    char digits[6];
    uint32_t digit_count = 0U;
    uint16_t value = tags[i];
    do {
      digits[digit_count++] = (char)('0' + (value % 10U));
      value = (uint16_t)(value / 10U);
    } while (value != 0U && digit_count < sizeof(digits));
    while (digit_count > 0U && used + 1U < sizeof(tag_list))
      tag_list[used++] = digits[--digit_count];
  }
  tag_list[used] = '\0';
  klog("dns: trust anchors count=%u tags=%s\n", (unsigned)count, tag_list);
}

void dns_configure(uint32_t server_ip) {
  g_dns_server_ip = server_ip;
  klog("dns: configured validating resolver %u.%u.%u.%u\n",
       (unsigned)(server_ip >> 24U), (unsigned)((server_ip >> 16U) & 0xffU),
       (unsigned)((server_ip >> 8U) & 0xffU), (unsigned)(server_ip & 0xffU));
  dns_log_trust_anchors();
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

int dns_cache_lookup(const char *hostname, uint8_t family,
                     xaios_ip_addr_t *address, uint64_t now_ns) {
  for (uint32_t i = 0U; i < XAIOS_DNS_CACHE_SIZE; ++i) {
    if (g_cache[i].valid != 0U && g_cache[i].family == family &&
        dns_str_case_equal(g_cache[i].hostname, hostname, DNS_MAX_HOSTNAME) &&
        now_ns < g_cache[i].expiry_ns) {
      *address = g_cache[i].address;
      return 1;
    }
  }
  return 0;
}

void dns_cache_insert(const char *hostname, const xaios_ip_addr_t *address,
                      uint32_t ttl_seconds, uint64_t now_ns) {
  uint32_t replace = 0U;
  uint64_t oldest = UINT64_MAX;
  for (uint32_t i = 0U; i < XAIOS_DNS_CACHE_SIZE; ++i) {
    if (g_cache[i].valid == 0U) {
      replace = i;
      break;
    }
    if (g_cache[i].family == address->family &&
        dns_str_case_equal(g_cache[i].hostname, hostname, DNS_MAX_HOSTNAME)) {
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
  dns_str_copy(g_cache[replace].hostname, hostname, DNS_MAX_HOSTNAME);
  g_cache[replace].address = *address;
  uint64_t ttl_ns = (uint64_t)ttl_seconds * UINT64_C(1000000000);
  g_cache[replace].expiry_ns =
      ttl_ns > UINT64_MAX - now_ns ? UINT64_MAX : now_ns + ttl_ns;
}

uint32_t dns_build_query(uint8_t *output, uint32_t capacity,
                         const char *hostname, uint16_t id,
                         uint16_t query_type) {
  if (capacity < 32U) return 0U;
  dns_put_be16(output, id);
  /* RFC 4035: request DNSSEC records and perform validation locally. CD
   * prevents an upstream recursive resolver's AD decision becoming our trust
   * decision. */
  dns_put_be16(output + 2U, DNS_FLAG_RD | DNS_FLAG_CD);
  dns_put_be16(output + 4U, 1U);
  dns_put_be16(output + 6U, 0U);
  dns_put_be16(output + 8U, 0U);
  dns_put_be16(output + 10U, 1U);
  uint32_t position = 12U;
  uint32_t encoded = dns_encode_name(output + position, capacity - position,
                                     hostname);
  if (encoded == 0U || capacity - position < encoded + 15U) return 0U;
  position += encoded;
  dns_put_be16(output + position, query_type);
  position += 2U;
  dns_put_be16(output + position, XAIOS_DNS_CLASS_IN);
  position += 2U;
  output[position++] = 0U;
  dns_put_be16(output + position, DNS_TYPE_OPT);
  position += 2U;
  dns_put_be16(output + position, DNS_EDNS_UDP_SIZE);
  position += 2U;
  put_be32(output + position, DNS_EDNS_DO);
  position += 4U;
  dns_put_be16(output + position, 0U);
  position += 2U;
  return position;
}

xaios_status_t dns_resolve(const char *hostname, uint32_t *out_ip) {
  if (out_ip == 0) return XAIOS_ERR_INVALID;
  xaios_ip_addr_t address;
  xaios_status_t status = dns_resolve_address(
      hostname, XAIOS_IP_FAMILY_V4, &address);
  if (status == XAIOS_OK) *out_ip = xaios_ip_addr_to_ipv4(&address);
  return status;
}

uint64_t dns_query_count(void) { return g_dns_query_count; }
uint64_t dns_response_count(void) { return g_dns_response_count; }
uint64_t dns_reject_count(void) { return g_dns_reject_count; }
uint64_t dns_timeout_count(void) { return g_dns_timeout_count; }
uint64_t dns_tcp_fallback_count(void) { return g_dns_tcp_fallback_count; }
uint64_t dns_authenticated_count(void) { return g_dns_authenticated_count; }
uint64_t dns_insecure_count(void) { return g_dns_insecure_count; }
uint32_t dns_pending_count(void) {
  return g_dns_pending.state != DNS_PENDING_NONE &&
                 g_dns_pending.state != DNS_PENDING_COMPLETE
             ? 1U
             : 0U;
}
