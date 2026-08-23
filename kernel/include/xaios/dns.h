#ifndef XAIOS_DNS_H
#define XAIOS_DNS_H

#include <xaios/status.h>
#include <xaios/types.h>
#include <xaios/ip_addr.h>

#define XAIOS_DNS_PORT 53U
#define XAIOS_DNS_MAX_NAME 256U
#define XAIOS_DNS_CACHE_SIZE 16U

/* DNS record types */
#define XAIOS_DNS_TYPE_A 1U
#define XAIOS_DNS_TYPE_AAAA 28U

/* DNS class IN */
#define XAIOS_DNS_CLASS_IN 1U

/* Configure DNS server IP (default 8.8.8.8) */
void dns_configure(uint32_t server_ip);

/* Reset cache, pending-query state, identifiers, and counters. */
void dns_init(void);

/* Resolve hostname to IPv4 address. Returns XAIOS_OK only on a cache hit.
 * XAIOS_ERR_BUSY means that a bounded asynchronous query is pending.
 * out_ip is in host byte order. */
xaios_status_t dns_resolve(const char *hostname, uint32_t *out_ip);

/* Resolve one address family without adding a new syscall. The configured
 * recursive resolver transports DNS material only; cache admission requires
 * a locally validated DNSKEY/DS/RRSIG chain from a compiled root DS anchor. */
xaios_status_t dns_resolve_address(const char *hostname, uint8_t family,
                                   xaios_ip_addr_t *out_address);

/* DNS background tick: send pending queries, process responses.
 * Call from network_poll_tick(). */
void dns_tick(uint64_t now_ns);

/* Advance DNS-over-TCP outside the network poll lock. */
void dns_transport_tick(uint64_t now_ns);

/* Consume an IPv4/UDP DNS response already received by the network poller. */
xaios_status_t dns_process_ipv4_frame(const uint8_t *frame,
                                      uint32_t frame_len,
                                      uint64_t now_ns);

/* Parse one DNS wire message. Exposed for deterministic malformed-response
 * and TCP-fallback tests. */
xaios_status_t dns_process_message(const uint8_t *message, uint32_t length,
                                   uint64_t now_ns, uint32_t from_tcp);

uint64_t dns_query_count(void);
uint64_t dns_response_count(void);
uint64_t dns_reject_count(void);
uint64_t dns_timeout_count(void);
uint64_t dns_tcp_fallback_count(void);
uint64_t dns_authenticated_count(void);
/* Answers accepted from a proven-insecure zone. Deliberately not folded into
   the authenticated count: the two carry different guarantees. */
uint64_t dns_insecure_count(void);
uint32_t dns_pending_count(void);

/* Encode a DNS name (e.g., "www.google.com" -> 3www6google3com0) */
uint32_t dns_encode_name(uint8_t *buf, uint32_t buf_size, const char *name);

/* Decode a DNS name from a response (may use pointer compression) */
int dns_decode_name(const uint8_t *msg, uint32_t msg_len,
                    uint32_t offset, char *out, uint32_t out_size);

void dns_self_test(void);

#endif
