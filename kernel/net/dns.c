#include <xaios/assert.h>
#include <xaios/dns.h>
#include <xaios/ipv4.h>
#include <xaios/klog.h>
#include <xaios/timer.h>
#include <xaios/virtio_net.h>

#define DNS_BUFFER_SIZE 512U
#define DNS_MAX_HOSTNAME 64U
#define DNS_RETRANSMIT_NS UINT64_C(5000000000)
#define DNS_QUERY_TIMEOUT_NS UINT64_C(15000000000)
#define DNS_MAX_RETRANSMITS 2U
#define DNS_MAX_POINTER_JUMPS 32U
#define DNS_EPHEMERAL_PORT UINT16_C(0xC001)
#define DNS_GATEWAY_MAC0 0x52U
#define DNS_GATEWAY_MAC1 0x55U
#define DNS_GATEWAY_MAC2 0x0aU
#define DNS_GATEWAY_MAC3 0x00U
#define DNS_GATEWAY_MAC4 0x02U
#define DNS_GATEWAY_MAC5 0x02U

static uint32_t g_dns_server_ip = 0x08080808U;
static uint16_t g_next_dns_id = 1U;

typedef struct dns_cache_entry {
  uint8_t valid;
  char hostname[DNS_MAX_HOSTNAME];
  uint32_t ip;
  uint64_t expiry_ns;
} dns_cache_entry_t;

static dns_cache_entry_t g_cache[XAIOS_DNS_CACHE_SIZE];

typedef struct dns_pending {
  uint8_t active;
  uint16_t id;
  char hostname[DNS_MAX_HOSTNAME];
  uint64_t started_ns;
  uint64_t sent_ns;
  uint8_t retransmits;
  uint8_t frame[DNS_BUFFER_SIZE];
  uint16_t frame_len;
} dns_pending_t;

static dns_pending_t g_pending;
static uint64_t g_query_count;
static uint64_t g_response_count;
static uint64_t g_reject_count;
static uint64_t g_timeout_count;

static void put_be16(uint8_t *dst, uint16_t value) {
  dst[0] = (uint8_t)(value >> 8U);
  dst[1] = (uint8_t)value;
}

static uint16_t get_be16(const uint8_t *src) {
  return (uint16_t)(((uint16_t)src[0] << 8U) | src[1]);
}

static uint32_t get_be32(const uint8_t *src) {
  return ((uint32_t)src[0] << 24U) | ((uint32_t)src[1] << 16U) |
         ((uint32_t)src[2] << 8U) | src[3];
}

static uint32_t str_len(const char *s) {
  uint32_t n = 0;
  while (s[n] != '\0') ++n;
  return n;
}

static int str_n_cmp(const char *a, const char *b, uint32_t n) {
  for (uint32_t i = 0; i < n; ++i) {
    if (a[i] != b[i]) return (int)(unsigned char)a[i] - (int)(unsigned char)b[i];
    if (a[i] == '\0') break;
  }
  return 0;
}

static void str_cpy(char *dst, const char *src, uint32_t max) {
  uint32_t i;
  for (i = 0; i + 1U < max && src[i] != '\0'; ++i) dst[i] = src[i];
  dst[i] = '\0';
}

static void bytes_zero(void *buffer, uint32_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint32_t i = 0; i < size; ++i) bytes[i] = 0U;
}

void dns_init(void) {
  bytes_zero(g_cache, sizeof(g_cache));
  bytes_zero(&g_pending, sizeof(g_pending));
  g_next_dns_id = 1U;
  g_query_count = 0U;
  g_response_count = 0U;
  g_reject_count = 0U;
  g_timeout_count = 0U;
}

void dns_configure(uint32_t server_ip) {
  g_dns_server_ip = server_ip;
  klog("dns: configured server %u.%u.%u.%u\n",
       (unsigned)(server_ip >> 24U), (unsigned)((server_ip >> 16U) & 0xFFU),
       (unsigned)((server_ip >> 8U) & 0xFFU), (unsigned)(server_ip & 0xFFU));
}

uint32_t dns_encode_name(uint8_t *buf, uint32_t buf_size, const char *name) {
  if (buf == 0 || name == 0 || buf_size == 0U) return 0U;
  if (name[0] == '\0') {
    buf[0] = 0U;
    return 1U;
  }
  uint32_t wi = 0;
  uint32_t si = 0;
  while (name[si] != '\0') {
    if (name[si] == '.') return 0U;
    uint32_t label_start = wi;
    if (wi >= buf_size || wi >= 255U) return 0U;
    buf[wi] = 0;
    ++wi;
    while (name[si] != '\0' && name[si] != '.') {
      if (wi >= buf_size || wi >= 255U) return 0U;
      buf[wi] = (uint8_t)name[si];
      ++wi;
      ++si;
    }
    uint32_t label_len = wi - label_start - 1U;
    if (label_len == 0U || label_len > 63U) return 0U;
    buf[label_start] = (uint8_t)label_len;
    if (name[si] == '.') {
      ++si;
      if (name[si] == '\0') break;
    }
  }
  if (wi >= buf_size || wi >= 255U) return 0U;
  buf[wi] = 0;
  return wi + 1U;
}

int dns_decode_name(const uint8_t *msg, uint32_t msg_len,
                    uint32_t offset, char *out, uint32_t out_size) {
  if (msg == 0 || out == 0 || out_size == 0U || offset >= msg_len) return -1;
  uint32_t oi = 0;
  uint32_t pos = offset;
  uint32_t next_offset = 0U;
  uint32_t pointer_jumps = 0U;

  while (pos < msg_len) {
    uint8_t len = msg[pos];
    if (len == 0) {
      if (next_offset == 0U) next_offset = pos + 1U;
      if (oi >= out_size) return -1;
      out[oi] = '\0';
      return next_offset <= (uint32_t)INT32_MAX ? (int)next_offset : -1;
    }
    if ((len & 0xC0U) == 0xC0U) {
      if (pos + 1U >= msg_len) return -1;
      uint16_t ptr = (uint16_t)(((uint16_t)(len & 0x3FU) << 8U) | msg[pos + 1U]);
      if ((uint32_t)ptr >= msg_len || ++pointer_jumps > DNS_MAX_POINTER_JUMPS) {
        return -1;
      }
      if (next_offset == 0U) next_offset = pos + 2U;
      pos = ptr;
      continue;
    }
    if ((len & 0xC0U) != 0U || len > 63U) return -1;
    uint8_t label_len = len;
    if (pos + 1U + label_len > msg_len) return -1;
    if (oi > 0) {
      if (oi + 1U >= out_size) return -1;
      out[oi] = '.';
      ++oi;
    }
    for (uint8_t i = 0; i < label_len; ++i) {
      if (oi + 1U >= out_size) return -1;
      out[oi] = (char)msg[pos + 1U + i];
      ++oi;
    }
    pos += 1U + label_len;
  }
  return -1;
}

static int cache_lookup(const char *hostname, uint32_t *out_ip, uint64_t now_ns) {
  for (uint32_t i = 0; i < XAIOS_DNS_CACHE_SIZE; ++i) {
    if (g_cache[i].valid &&
        str_n_cmp(g_cache[i].hostname, hostname, DNS_MAX_HOSTNAME) == 0 &&
        now_ns < g_cache[i].expiry_ns) {
      *out_ip = g_cache[i].ip;
      return 1;
    }
  }
  return 0;
}

static void cache_insert(const char *hostname, uint32_t ip, uint32_t ttl_secs,
                          uint64_t now_ns) {
  uint32_t oldest_idx = 0;
  uint64_t oldest_time = now_ns;
  for (uint32_t i = 0; i < XAIOS_DNS_CACHE_SIZE; ++i) {
    if (!g_cache[i].valid) {
      oldest_idx = i;
      break;
    }
    if (g_cache[i].expiry_ns < oldest_time) {
      oldest_time = g_cache[i].expiry_ns;
      oldest_idx = i;
    }
  }
  g_cache[oldest_idx].valid = 1;
  str_cpy(g_cache[oldest_idx].hostname, hostname, DNS_MAX_HOSTNAME);
  g_cache[oldest_idx].ip = ip;
  uint64_t ttl_ns = (uint64_t)ttl_secs * UINT64_C(1000000000);
  g_cache[oldest_idx].expiry_ns =
      ttl_ns > UINT64_MAX - now_ns ? UINT64_MAX : now_ns + ttl_ns;
}

xaios_status_t dns_resolve(const char *hostname, uint32_t *out_ip) {
  if (hostname == 0 || out_ip == 0) return XAIOS_ERR_INVALID;
  uint64_t now = timer_now_ns();
  if (cache_lookup(hostname, out_ip, now)) return XAIOS_OK;

  uint32_t nlen = str_len(hostname);
  if (nlen == 0 || nlen >= DNS_MAX_HOSTNAME) return XAIOS_ERR_INVALID;
  if (g_pending.active != 0U) return XAIOS_ERR_BUSY;

  uint16_t id = g_next_dns_id;
  ++g_next_dns_id;

  uint8_t buf[DNS_BUFFER_SIZE];
  uint32_t wi = 0;

  /* Ethernet header (dst MAC = gateway MAC) */
  buf[0] = DNS_GATEWAY_MAC0; buf[1] = DNS_GATEWAY_MAC1;
  buf[2] = DNS_GATEWAY_MAC2; buf[3] = DNS_GATEWAY_MAC3;
  buf[4] = DNS_GATEWAY_MAC4; buf[5] = DNS_GATEWAY_MAC5;
  uint8_t local_mac[6];
  if (virtio_net_get_mac(local_mac) != XAIOS_OK) {
    local_mac[0] = 0x02; local_mac[1] = 0x00;
    local_mac[2] = 0x00; local_mac[3] = 0x00;
    local_mac[4] = 0x00; local_mac[5] = 0x01;
  }
  for (uint32_t i = 0; i < 6; ++i) buf[6U + i] = local_mac[i];
  wi = 12; put_be16(buf + wi, 0x0800); wi += 2;

  /* Build IPv4 header */
  uint32_t ip_hdr_off = wi;
  wi += XAIOS_IPV4_HEADER_SIZE;

  /* Build UDP header (src port ephemeral, dst port 53) */
  uint32_t udp_hdr_off = wi;
  wi += 8;

  /* DNS header */
  put_be16(buf + wi, id); wi += 2;
  put_be16(buf + wi, 0x0100); wi += 2; /* flags: RD=1 */
  put_be16(buf + wi, 1); wi += 2;      /* QDCOUNT = 1 */
  put_be16(buf + wi, 0); wi += 2;      /* ANCOUNT = 0 */
  put_be16(buf + wi, 0); wi += 2;      /* NSCOUNT = 0 */
  put_be16(buf + wi, 0); wi += 2;      /* ARCOUNT = 0 */

  /* Question */
  uint32_t enc_len = dns_encode_name(buf + wi, DNS_BUFFER_SIZE - wi, hostname);
  if (enc_len == 0) return XAIOS_ERR_INVALID;
  wi += enc_len;
  put_be16(buf + wi, XAIOS_DNS_TYPE_A);    wi += 2;
  put_be16(buf + wi, XAIOS_DNS_CLASS_IN);  wi += 2;

  /* Fill UDP header */
  uint16_t udp_len = (uint16_t)(wi - udp_hdr_off);
  put_be16(buf + udp_hdr_off, DNS_EPHEMERAL_PORT);
  put_be16(buf + udp_hdr_off + 2, XAIOS_DNS_PORT);
  put_be16(buf + udp_hdr_off + 4, udp_len);
  put_be16(buf + udp_hdr_off + 6, 0);

  /* Fill IPv4 header */
  uint16_t ip_total = (uint16_t)(wi - ip_hdr_off);
  ipv4_build_header(buf + ip_hdr_off, ip_total, XAIOS_IPV4_PROTO_UDP,
                     XAIOS_IPV4_GUEST_IP, g_dns_server_ip);

  g_pending.active = 1;
  g_pending.id = id;
  str_cpy(g_pending.hostname, hostname, DNS_MAX_HOSTNAME);
  g_pending.started_ns = now;
  g_pending.sent_ns = 0;
  g_pending.retransmits = 0;
  g_pending.frame_len = (uint16_t)wi;
  for (uint32_t i = 0; i < wi; ++i) g_pending.frame[i] = buf[i];

  xaios_status_t st = virtio_net_tx(buf, wi);
  if (st != XAIOS_OK) {
    bytes_zero(&g_pending, sizeof(g_pending));
    ++g_reject_count;
    return st;
  }
  g_pending.sent_ns = now;
  ++g_query_count;

  klog("dns: resolve %s id=%u len=%u\n", hostname, (unsigned)id, (unsigned)wi);
  return XAIOS_ERR_BUSY;
}

static void process_dns_response(const uint8_t *payload, uint32_t len,
                                  uint64_t now_ns) {
  if (g_pending.active == 0U || len < 12U) {
    ++g_reject_count;
    return;
  }
  uint16_t rcv_id = get_be16(payload);
  if (rcv_id != g_pending.id) {
    ++g_reject_count;
    return;
  }

  uint16_t flags = get_be16(payload + 2);
  if ((flags & 0xF800U) != 0x8000U) {
    ++g_reject_count;
    return;
  }
  uint8_t rcode = (uint8_t)(flags & 0x0FU);
  if (rcode != 0) {
    klog("dns: server error for %s rcode=%u\n", g_pending.hostname, rcode);
    g_pending.active = 0;
    ++g_response_count;
    return;
  }

  uint16_t qdcount = get_be16(payload + 4);
  uint16_t ancount = get_be16(payload + 6);
  if (qdcount != 1U || ancount == 0U) {
    ++g_reject_count;
    return;
  }

  /* Skip question section */
  uint32_t pos = 12;
  char tmp[XAIOS_DNS_MAX_NAME];
  int res = dns_decode_name(payload, len, pos, tmp, sizeof(tmp));
  if (res < 0) {
    ++g_reject_count;
    return;
  }
  pos = (uint32_t)res;
  if (pos > len || len - pos < 4U) {
    ++g_reject_count;
    return;
  }
  pos += 4U;

  /* Parse answers */
  for (uint16_t ai = 0; ai < ancount; ++ai) {
    if (pos >= len) break;
    res = dns_decode_name(payload, len, pos, tmp, sizeof(tmp));
    if (res < 0) break;
    pos = (uint32_t)res;
    if (pos + 10 > len) break;
    uint16_t rtype = get_be16(payload + pos);
    pos += 2;
    uint16_t rclass = get_be16(payload + pos);
    pos += 2;
    uint32_t ttl = get_be32(payload + pos);
    pos += 4;
    uint16_t rdlength = get_be16(payload + pos);
    pos += 2;
    if (pos + rdlength > len) break;

    if (rtype == XAIOS_DNS_TYPE_A && rclass == XAIOS_DNS_CLASS_IN &&
        rdlength == 4) {
      uint32_t ip = ((uint32_t)payload[pos] << 24U) |
                    ((uint32_t)payload[pos + 1U] << 16U) |
                    ((uint32_t)payload[pos + 2U] << 8U) |
                    payload[pos + 3U];
      cache_insert(g_pending.hostname, ip, ttl, now_ns);
      klog("dns: resolved %s -> %u.%u.%u.%u ttl=%u\n",
           g_pending.hostname,
           (unsigned)(ip >> 24U), (unsigned)((ip >> 16U) & 0xFFU),
           (unsigned)((ip >> 8U) & 0xFFU), (unsigned)(ip & 0xFFU),
           (unsigned)ttl);
      g_pending.active = 0;
      ++g_response_count;
      return;
    }
    pos += rdlength;
  }
  ++g_reject_count;
}

xaios_status_t dns_process_ipv4_frame(const uint8_t *frame,
                                      uint32_t frame_len,
                                      uint64_t now_ns) {
  if (frame == 0 || frame_len < 42U || g_pending.active == 0U) {
    return XAIOS_ERR_NOT_FOUND;
  }
  if (get_be16(frame + 12U) != 0x0800U ||
      !ipv4_validate_incoming(frame, frame_len) ||
      ipv4_is_fragment(frame, frame_len)) {
    return XAIOS_ERR_INVALID;
  }
  const uint8_t *ip = frame + 14U;
  uint32_t ip_header_bytes = (uint32_t)(ip[0] & 0x0FU) * 4U;
  uint16_t ip_total = get_be16(ip + 2U);
  if (ip[9U] != XAIOS_IPV4_PROTO_UDP || ip_header_bytes < 20U ||
      ip_total < ip_header_bytes + 8U || 14U + ip_total > frame_len) {
    return XAIOS_ERR_NOT_FOUND;
  }
  const uint8_t *udp = ip + ip_header_bytes;
  uint16_t source_port = get_be16(udp);
  uint16_t destination_port = get_be16(udp + 2U);
  uint16_t udp_len = get_be16(udp + 4U);
  if (source_port != XAIOS_DNS_PORT || destination_port != DNS_EPHEMERAL_PORT) {
    return XAIOS_ERR_NOT_FOUND;
  }
  if (udp_len < 8U || udp_len > ip_total - ip_header_bytes) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }
  uint16_t wire_checksum = get_be16(udp + 6U);
  if (wire_checksum != 0U &&
      ipv4_pseudo_checksum(get_be32(ip + 12U), get_be32(ip + 16U),
                           XAIOS_IPV4_PROTO_UDP, udp_len, udp, udp_len) != 0U) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }
  uint64_t before = g_response_count;
  process_dns_response(udp + 8U, udp_len - 8U, now_ns);
  return g_response_count != before ? XAIOS_OK : XAIOS_ERR_INVALID;
}

void dns_tick(uint64_t now_ns) {
  if (!g_pending.active) return;

  if (now_ns > g_pending.started_ns &&
      now_ns - g_pending.started_ns >= DNS_QUERY_TIMEOUT_NS) {
    klog("dns: query timeout id=%u host=%s\n", g_pending.id,
         g_pending.hostname);
    bytes_zero(&g_pending, sizeof(g_pending));
    ++g_timeout_count;
    return;
  }

  if (g_pending.retransmits < DNS_MAX_RETRANSMITS &&
      now_ns > g_pending.sent_ns &&
      now_ns - g_pending.sent_ns >= DNS_RETRANSMIT_NS) {
    if (virtio_net_tx(g_pending.frame, g_pending.frame_len) != XAIOS_OK) {
      ++g_reject_count;
      return;
    }
    g_pending.sent_ns = now_ns;
    ++g_pending.retransmits;
    klog("dns: retransmit id=%u host=%s\n", g_pending.id, g_pending.hostname);
  }
}

uint64_t dns_query_count(void) { return g_query_count; }
uint64_t dns_response_count(void) { return g_response_count; }
uint64_t dns_reject_count(void) { return g_reject_count; }
uint64_t dns_timeout_count(void) { return g_timeout_count; }
uint32_t dns_pending_count(void) { return g_pending.active != 0U ? 1U : 0U; }

void dns_self_test(void) {
  dns_init();
  /* Test dns_encode_name */
  uint8_t enc[64];
  uint32_t elen = dns_encode_name(enc, sizeof(enc), "www.google.com");
  kassert(elen == 16);
  uint8_t expected[16] = {3, 'w', 'w', 'w', 6, 'g', 'o', 'o',
                          'g', 'l', 'e', 3, 'c', 'o', 'm', 0};
  kassert(enc[15] == 0);
  for (uint32_t i = 0; i < 15; ++i) kassert(enc[i] == expected[i]);

  /* Test empty label (root) */
  elen = dns_encode_name(enc, sizeof(enc), "");
  kassert(elen == 1 && enc[0] == 0);

  /* Test dns_decode_name round-trip */
  const char *names[] = {"www.google.com", "example.org", "a.b.c.d.e", ""};
  for (uint32_t ti = 0; ti < 4; ++ti) {
    elen = dns_encode_name(enc, sizeof(enc), names[ti]);
    kassert(elen > 0);
    char dec[64];
    int dlen = dns_decode_name(enc, elen, 0, dec, sizeof(dec));
    kassert(dlen > 0);
    kassert(str_n_cmp(dec, names[ti], sizeof(dec)) == 0);
    klog("dns: round-trip '%s' ok\n", names[ti]);
  }

  /* Test dns_decode_name with pointer compression. */
  uint8_t comp[64] = {6, 'g', 'o', 'o', 'g', 'l', 'e',
                      3, 'c', 'o', 'm', 0,
                      3, 'w', 'w', 'w', 0xC0, 0x00};
  char dec[64];
  int dlen = dns_decode_name(comp, 18U, 12U, dec, sizeof(dec));
  kassert(dlen == 18);
  kassert(str_n_cmp(dec, "www.google.com", sizeof(dec)) == 0);
  klog("dns: compression decode ok -> '%s'\n", dec);

  uint8_t loop[2] = {0xC0, 0x00};
  kassert(dns_decode_name(loop, sizeof(loop), 0U, dec, sizeof(dec)) < 0);
  kassert(dns_decode_name(loop, sizeof(loop), 0U, dec, 0U) < 0);
  uint8_t reserved_label[2] = {0x40, 0};
  kassert(dns_decode_name(reserved_label, sizeof(reserved_label), 0U, dec,
                          sizeof(dec)) < 0);
  kassert(dns_encode_name(enc, sizeof(enc), ".bad") == 0U);
  kassert(dns_encode_name(enc, sizeof(enc), "bad..name") == 0U);

  /* Test cache */
  uint64_t now = 1000000ULL;
  uint32_t ip_out = 0;
  kassert(cache_lookup("nonexistent", &ip_out, now) == 0);
  cache_insert("test.example.com", 0x08080808, 60, now);
  kassert(cache_lookup("test.example.com", &ip_out, now) == 1);
  kassert(ip_out == 0x08080808);
  kassert(cache_lookup("test.example.com", &ip_out, now + 61000000000ULL) == 0);

  kassert(cache_lookup("other", &ip_out, now) == 0);
  cache_insert("other.example.com", 0x01020304, 60, now);
  kassert(cache_lookup("other.example.com", &ip_out, now) == 1);
  kassert(ip_out == 0x01020304);

  klog("dns: self-test passed\n");
}
