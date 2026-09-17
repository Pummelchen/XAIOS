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

/* C-01: the resolver cache is reached from the NET_RESOLVE syscall, which runs
   on the calling thread's CPU. It takes the network stack's guard rather than
   one of its own: this code calls tcp_open, send, recv and close, and
   network_poll_tick calls back into dns_tick, so a separate guard would invert
   the two orders the moment anyone added a call. */
static void dns_lock(void) { network_stack_lock(); }
static void dns_unlock(void) { network_stack_unlock(); }

static void complete_pending(xaios_status_t status) {
  g_dns_pending.state = DNS_PENDING_COMPLETE;
  g_dns_pending.result = status;
  if (g_dns_pending.tcp_flow_id != 0U)
    (void)network_stack_tcp_abort_flow(g_dns_pending.tcp_flow_id);
  g_dns_pending.tcp_flow_id = 0U;
}

static xaios_status_t send_udp_query(dns_pending_t *pending) {
  uint8_t *frame = pending->udp_frame;
  network_config_gateway_mac(frame);
  uint8_t local_mac[6];
  if (network_device_get_mac(local_mac) != XAIOS_OK) {
    static const uint8_t fallback[6] = {0x02U, 0U, 0U, 0U, 0U, 1U};
    dns_bytes_copy(local_mac, fallback, sizeof(fallback));
  }
  dns_bytes_copy(frame + 6U, local_mac, sizeof(local_mac));
  dns_put_be16(frame + 12U, UINT16_C(0x0800));
  uint32_t ip_offset = 14U;
  uint32_t udp_offset = ip_offset + XAIOS_IPV4_HEADER_SIZE;
  uint32_t dns_offset = udp_offset + 8U;
  if (dns_offset + pending->query_len > DNS_UDP_FRAME_SIZE)
    return XAIOS_ERR_INVALID;
  dns_bytes_copy(frame + dns_offset, pending->query, pending->query_len);
  uint16_t udp_length = (uint16_t)(8U + pending->query_len);
  dns_put_be16(frame + udp_offset, pending->udp_port);
  dns_put_be16(frame + udp_offset + 2U, XAIOS_DNS_PORT);
  dns_put_be16(frame + udp_offset + 4U, udp_length);
  dns_put_be16(frame + udp_offset + 6U, 0U);
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
    for (uint32_t i = dns_str_len(hostname); i > 0U; --i) {
      if (hostname[i - 1U] == '.' && ++seen == labels) {
        start = i;
        break;
      }
    }
    if (seen != labels) return -1;
  }
  if (dns_str_len(hostname + start) + 1U > capacity) return -1;
  dns_str_copy(out, hostname + start, capacity);
  return 0;
}

static xaios_status_t start_query(dns_pending_t *pending, const char *name,
                                  uint16_t type, uint64_t now_ns) {
  dns_str_copy(pending->query_name, name, sizeof(pending->query_name));
  pending->query_type = type;
  pending->id = dns_random_u16(g_dns_next_id++);
  if (pending->id == 0U) pending->id = g_dns_next_id;
  if (g_dns_next_id == 0U) g_dns_next_id = 1U;
  pending->retransmits = 0U;
  pending->udp_port = dns_random_ephemeral_port((uint16_t)(UINT16_C(0xc001) ^ pending->id));
  pending->tcp_port = dns_random_ephemeral_port((uint16_t)(UINT16_C(0xc002) ^ pending->id));
  if (pending->tcp_port == pending->udp_port) ++pending->tcp_port;
  pending->query_len = (uint16_t)dns_build_query(pending->query,
      sizeof(pending->query), name, pending->id, type);
  if (pending->query_len == 0U) return XAIOS_ERR_INVALID;
  pending->state = DNS_PENDING_UDP;
  if (send_udp_query(pending) != XAIOS_OK) return XAIOS_ERR_IO;
  pending->query_started_ns = now_ns;
  pending->sent_ns = now_ns;
  ++g_dns_query_count;
  return XAIOS_OK;
}

static xaios_status_t dns_resolve_address_unlocked(const char *hostname, uint8_t family,
                                   xaios_ip_addr_t *out_address) {
  if (hostname == 0 || out_address == 0 ||
      (family != XAIOS_IP_FAMILY_V4 && family != XAIOS_IP_FAMILY_V6)) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t now_ns = timer_now_ns();
  if (dns_cache_lookup(hostname, family, out_address, now_ns)) return XAIOS_OK;
#if XAIOS_BOOT_TEST_APPS
  if (dns_selftest_is_fixture_name(hostname)) {
    return dns_selftest_fixture_resolve(hostname, family, out_address, now_ns);
  }
#endif
  if (g_dns_pending.state == DNS_PENDING_COMPLETE) {
    if (g_dns_pending.family == family &&
        dns_str_case_equal(g_dns_pending.hostname, hostname, DNS_MAX_HOSTNAME)) {
      xaios_status_t result = g_dns_pending.result;
      dns_bytes_zero(&g_dns_pending, sizeof(g_dns_pending));
      return result;
    }
    dns_bytes_zero(&g_dns_pending, sizeof(g_dns_pending));
  }
  uint32_t hostname_length = dns_str_len(hostname);
  if (hostname_length == 0U || hostname_length >= DNS_MAX_HOSTNAME)
    return XAIOS_ERR_INVALID;
  if (g_dns_pending.state != DNS_PENDING_NONE) return XAIOS_ERR_BUSY;
  dns_bytes_zero(&g_dns_pending, sizeof(g_dns_pending));
  g_dns_pending.family = family;
  dns_str_copy(g_dns_pending.hostname, hostname, DNS_MAX_HOSTNAME);
  g_dns_pending.hostname_labels = hostname_label_count(hostname);
  if (g_dns_pending.hostname_labels == 0U) return XAIOS_ERR_INVALID;
  g_dns_pending.dnssec_stage = DNSSEC_STAGE_ROOT_DNSKEY;
  g_dns_pending.walk_started_ns = now_ns;
  if (start_query(&g_dns_pending, "", DNS_TYPE_DNSKEY, now_ns) != XAIOS_OK) {
    dns_bytes_zero(&g_dns_pending, sizeof(g_dns_pending));
    ++g_dns_reject_count;
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

xaios_status_t dns_process_message(const uint8_t *message, uint32_t length,
                                   uint64_t now_ns, uint32_t from_tcp) {
  if (message == 0 || length < 12U || g_dns_pending.state == DNS_PENDING_NONE ||
      dns_get_be16(message) != g_dns_pending.id) {
    ++g_dns_reject_count;
    return XAIOS_ERR_INVALID;
  }
  uint16_t flags = dns_get_be16(message + 2U);
  if ((flags & UINT16_C(0xf800)) != DNS_FLAG_QR) {
    ++g_dns_reject_count;
    return XAIOS_ERR_INVALID;
  }
  if ((flags & DNS_FLAG_TC) != 0U && from_tcp == 0U) {
    g_dns_pending.state = DNS_PENDING_TCP_CONNECT;
    g_dns_pending.tcp_flow_id = 0U;
    g_dns_pending.tcp_received = 0U;
    ++g_dns_tcp_fallback_count;
    return XAIOS_ERR_BUSY;
  }
  if ((flags & DNS_FLAG_TC) != 0U || (flags & 0x000fU) != 0U) {
    complete_pending(XAIOS_ERR_NOT_FOUND);
    ++g_dns_response_count;
    return XAIOS_ERR_NOT_FOUND;
  }
  uint16_t question_count = dns_get_be16(message + 4U);
  if (question_count != 1U) {
    ++g_dns_reject_count;
    return XAIOS_ERR_INVALID;
  }
  uint32_t position = 12U;
  char question[XAIOS_DNS_MAX_NAME];
  int decoded = dns_decode_name(message, length, position, question,
                                sizeof(question));
  if (decoded < 0 || !dns_str_case_equal(question, g_dns_pending.query_name,
                                     DNS_MAX_HOSTNAME)) {
    ++g_dns_reject_count;
    return XAIOS_ERR_INVALID;
  }
  position = (uint32_t)decoded;
  if (position > length || length - position < 4U ||
      dns_get_be16(message + position) != g_dns_pending.query_type ||
      dns_get_be16(message + position + 2U) != XAIOS_DNS_CLASS_IN) {
    ++g_dns_reject_count;
    return XAIOS_ERR_INVALID;
  }
  /* The stage verifiers re-parse the whole message themselves, so nothing
     consumes an offset past the question section here. */
  xaios_status_t status = XAIOS_ERR_INVALID;
  uint64_t wall_ns = wall_time_now_ns();
  if (g_dns_pending.dnssec_stage == DNSSEC_STAGE_ROOT_DNSKEY) {
    status = dnssec_verify_dnskey(message, length, "", 0, wall_ns,
                                  &g_dns_pending.validated_keys);
    if (status == XAIOS_OK) {
      g_dns_pending.zone_labels = 1U;
      if (child_zone_name(g_dns_pending.hostname, g_dns_pending.zone_labels,
                          g_dns_pending.child_zone, sizeof(g_dns_pending.child_zone)) == 0)
        status = start_query(&g_dns_pending, g_dns_pending.child_zone, DNS_TYPE_DS, now_ns);
      else status = XAIOS_ERR_INVALID;
      g_dns_pending.dnssec_stage = DNSSEC_STAGE_CHILD_DS;
    }
  } else if (g_dns_pending.dnssec_stage == DNSSEC_STAGE_CHILD_DS) {
    status = dnssec_verify_ds(message, length, g_dns_pending.child_zone,
                             &g_dns_pending.validated_keys, wall_ns,
                             &g_dns_pending.child_ds);
    if (status == XAIOS_OK) {
      status = start_query(&g_dns_pending, g_dns_pending.child_zone, DNS_TYPE_DNSKEY, now_ns);
      g_dns_pending.dnssec_stage = DNSSEC_STAGE_CHILD_DNSKEY;
    } else if (dnssec_verify_nodata(message, length, g_dns_pending.child_zone,
                                    DNS_TYPE_DS, &g_dns_pending.validated_keys,
                                    wall_ns) == XAIOS_OK ||
               dnssec_verify_no_ds(message, length, g_dns_pending.child_zone,
                                   &g_dns_pending.validated_keys,
                                   wall_ns) == XAIOS_OK) {
      /* No DS at this delegation: the child is insecure, not bogus. Ask for
         the address directly rather than walking further down a chain that
         has no keys to offer. */
      g_dns_pending.dnssec_insecure = 1U;
      status = start_query(&g_dns_pending, g_dns_pending.hostname,
                           g_dns_pending.family == XAIOS_IP_FAMILY_V4 ? XAIOS_DNS_TYPE_A : XAIOS_DNS_TYPE_AAAA, now_ns);
      g_dns_pending.dnssec_stage = DNSSEC_STAGE_ADDRESS;
    }
  } else if (g_dns_pending.dnssec_stage == DNSSEC_STAGE_CHILD_DNSKEY) {
    dnssec_keyset_t child_keys;
    status = dnssec_verify_dnskey(message, length, g_dns_pending.child_zone,
                                  &g_dns_pending.child_ds, wall_ns, &child_keys);
    if (status == XAIOS_OK) {
      g_dns_pending.validated_keys = child_keys;
      if (g_dns_pending.zone_labels == g_dns_pending.hostname_labels) {
        status = start_query(&g_dns_pending, g_dns_pending.hostname,
                             g_dns_pending.family == XAIOS_IP_FAMILY_V4 ? XAIOS_DNS_TYPE_A : XAIOS_DNS_TYPE_AAAA, now_ns);
        g_dns_pending.dnssec_stage = DNSSEC_STAGE_ADDRESS;
      } else {
        ++g_dns_pending.zone_labels;
        if (child_zone_name(g_dns_pending.hostname, g_dns_pending.zone_labels,
                            g_dns_pending.child_zone, sizeof(g_dns_pending.child_zone)) == 0)
          status = start_query(&g_dns_pending, g_dns_pending.child_zone, DNS_TYPE_DS, now_ns);
        else status = XAIOS_ERR_INVALID;
        g_dns_pending.dnssec_stage = DNSSEC_STAGE_CHILD_DS;
      }
    }
  } else if (g_dns_pending.dnssec_stage == DNSSEC_STAGE_ADDRESS) {
    uint8_t bytes[16]; uint32_t ttl = 0U;
    uint16_t type = g_dns_pending.family == XAIOS_IP_FAMILY_V4 ? XAIOS_DNS_TYPE_A : XAIOS_DNS_TYPE_AAAA;
    status = g_dns_pending.dnssec_insecure != 0U
                 ? dnssec_extract_address_insecure(message, length,
                                                   g_dns_pending.hostname, type,
                                                   bytes, &ttl)
                 : dnssec_verify_address(message, length, g_dns_pending.hostname,
                                         type, &g_dns_pending.validated_keys,
                                         wall_ns, bytes, &ttl);
    if (status == XAIOS_OK) {
      xaios_ip_addr_t answer; xaios_ip_addr_zero(&answer); answer.family = g_dns_pending.family;
      dns_bytes_copy(answer.addr, bytes, g_dns_pending.family == XAIOS_IP_FAMILY_V4 ? 4U : 16U);
      dns_cache_insert(g_dns_pending.hostname, &answer, ttl, now_ns);
      /* Only a validated chain counts as authenticated. An insecure answer
         is a separate, weaker result and is counted separately so the two
         can never be read as the same thing. */
      if (g_dns_pending.dnssec_insecure != 0U) ++g_dns_insecure_count;
      else ++g_dns_authenticated_count;
      ++g_dns_response_count;
      if (g_dns_pending.tcp_flow_id != 0U) (void)network_stack_tcp_close_flow(g_dns_pending.tcp_flow_id);
      dns_bytes_zero(&g_dns_pending, sizeof(g_dns_pending)); return XAIOS_OK;
    }
    if (dnssec_verify_nodata(message, length, g_dns_pending.hostname, type,
                             &g_dns_pending.validated_keys, wall_ns) == XAIOS_OK)
      status = XAIOS_ERR_NOT_FOUND;
  }
  if (status == XAIOS_OK && g_dns_pending.state == DNS_PENDING_UDP)
    return XAIOS_ERR_BUSY;
  if (status == XAIOS_OK || status == XAIOS_ERR_BUSY) return status;
  complete_pending(status); ++g_dns_reject_count; return status;
}

xaios_status_t dns_process_ipv4_frame(const uint8_t *frame,
                                      uint32_t frame_length,
                                      uint64_t now_ns) {
  if (frame == 0 || frame_length < 42U ||
      g_dns_pending.state != DNS_PENDING_UDP) return XAIOS_ERR_NOT_FOUND;
  if (dns_get_be16(frame + 12U) != UINT16_C(0x0800) ||
      !ipv4_validate_incoming(frame, frame_length) ||
      ipv4_is_fragment(frame, frame_length)) return XAIOS_ERR_INVALID;
  const uint8_t *ip = frame + 14U;
  uint32_t ip_header_length = (uint32_t)(ip[0] & 0x0fU) * 4U;
  uint16_t ip_total = dns_get_be16(ip + 2U);
  if (ip[9U] != XAIOS_IPV4_PROTO_UDP || ip_header_length < 20U ||
      dns_get_be32(ip + 12U) != g_dns_server_ip ||
      ip_total < ip_header_length + 8U || 14U + ip_total > frame_length)
    return XAIOS_ERR_NOT_FOUND;
  const uint8_t *udp = ip + ip_header_length;
  uint16_t udp_length = dns_get_be16(udp + 4U);
  if (dns_get_be16(udp) != XAIOS_DNS_PORT ||
      dns_get_be16(udp + 2U) != g_dns_pending.udp_port) return XAIOS_ERR_NOT_FOUND;
  if (udp_length < 8U || udp_length > ip_total - ip_header_length) {
    ++g_dns_reject_count;
    return XAIOS_ERR_INVALID;
  }
  uint16_t checksum = dns_get_be16(udp + 6U);
  if (checksum != 0U &&
      ipv4_pseudo_checksum(dns_get_be32(ip + 12U), dns_get_be32(ip + 16U),
                           XAIOS_IPV4_PROTO_UDP, udp_length, udp,
                           udp_length) != 0U) {
    ++g_dns_reject_count;
    return XAIOS_ERR_INVALID;
  }
  return dns_process_message(udp + 8U, udp_length - 8U, now_ns, 0U);
}

void dns_transport_tick(uint64_t now_ns) {
  if (g_dns_pending.state == DNS_PENDING_TCP_CONNECT) {
    if (g_dns_pending.tcp_flow_id == 0U) {
      xaios_ip_addr_t server = xaios_ip_addr_from_ipv4(g_dns_server_ip);
      xaios_status_t status = network_stack_tcp_open(
          &server, XAIOS_DNS_PORT, g_dns_pending.tcp_port,
          &g_dns_pending.tcp_flow_id);
      if (status != XAIOS_OK) return;
    }
    xaios_status_t status =
        network_stack_tcp_open_status(g_dns_pending.tcp_flow_id);
    if (status == XAIOS_ERR_BUSY) return;
    if (status != XAIOS_OK) {
      complete_pending(XAIOS_ERR_IO);
      ++g_dns_reject_count;
      return;
    }
    uint8_t framed[DNS_UDP_FRAME_SIZE + 2U];
    dns_put_be16(framed, g_dns_pending.query_len);
    dns_bytes_copy(framed + 2U, g_dns_pending.query, g_dns_pending.query_len);
    uint32_t written = 0U;
    if (network_stack_tcp_send(g_dns_pending.tcp_flow_id, framed,
                               g_dns_pending.query_len + 2U, &written) != XAIOS_OK ||
        written != g_dns_pending.query_len + 2U) return;
    g_dns_pending.state = DNS_PENDING_TCP_REPLY;
    g_dns_pending.sent_ns = now_ns;
  }
  if (g_dns_pending.state != DNS_PENDING_TCP_REPLY) return;
  uint32_t available = sizeof(g_dns_pending.tcp_reply) - g_dns_pending.tcp_received;
  uint32_t received = network_stack_tcp_recv(
      g_dns_pending.tcp_flow_id, g_dns_pending.tcp_reply + g_dns_pending.tcp_received,
      available);
  g_dns_pending.tcp_received += received;
  if (g_dns_pending.tcp_received < 2U) return;
  uint32_t message_length = dns_get_be16(g_dns_pending.tcp_reply);
  if (message_length < 12U || message_length > DNS_TCP_MESSAGE_SIZE) {
    complete_pending(XAIOS_ERR_INVALID);
    ++g_dns_reject_count;
    return;
  }
  if (g_dns_pending.tcp_received < message_length + 2U) return;
  (void)dns_process_message(g_dns_pending.tcp_reply + 2U, message_length, now_ns,
                            1U);
}

void dns_tick(uint64_t now_ns) {
  if (g_dns_pending.state == DNS_PENDING_NONE ||
      g_dns_pending.state == DNS_PENDING_COMPLETE) return;
  if (now_ns > g_dns_pending.walk_started_ns &&
      now_ns - g_dns_pending.walk_started_ns >= DNS_WALK_TIMEOUT_NS) {
    klog("dns: walk timeout id=%u host=%s stage=%u queries_unanswered=1\n",
         g_dns_pending.id, g_dns_pending.hostname, (unsigned)g_dns_pending.dnssec_stage);
    complete_pending(XAIOS_ERR_CANCELLED);
    ++g_dns_timeout_count;
    return;
  }
  if (now_ns > g_dns_pending.query_started_ns &&
      now_ns - g_dns_pending.query_started_ns >= DNS_QUERY_TIMEOUT_NS) {
    klog("dns: query timeout id=%u host=%s name=%s stage=%u\n", g_dns_pending.id,
         g_dns_pending.hostname, g_dns_pending.query_name,
         (unsigned)g_dns_pending.dnssec_stage);
    complete_pending(XAIOS_ERR_CANCELLED);
    ++g_dns_timeout_count;
    return;
  }
  if (g_dns_pending.state == DNS_PENDING_UDP &&
      g_dns_pending.retransmits < DNS_MAX_RETRANSMITS &&
      now_ns > g_dns_pending.sent_ns &&
      now_ns - g_dns_pending.sent_ns >= DNS_RETRANSMIT_NS) {
    if (network_device_tx(g_dns_pending.udp_frame, g_dns_pending.udp_frame_len) != XAIOS_OK) {
      ++g_dns_reject_count;
      return;
    }
    g_dns_pending.sent_ns = now_ns;
    ++g_dns_pending.retransmits;
  }
}
