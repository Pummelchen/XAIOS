/* Private interfaces of the DNS resolver, shared by the three translation
   units it is split across:

     dns.c          the wire codec, the cache, the counters and the public
                    entry points that do not need the query state machine;
     dns_resolver.c the pending-query state machine, its transport, and its
                    retry and deadline policy;
     dns_selftest.c the deterministic self-test and, under
                    XAIOS_BOOT_TEST_APPS, the fixture zone it answers from.

   This is not a public interface; xaios/dns.h is, and all three include it.
   The pending record and the counters are declared here rather than reached
   through accessors because the self-test builds and inspects exactly the
   state the resolver advances, and a copied interface could drift from it.
   The resolver globals themselves are defined once, in dns.c. */
#ifndef XAIOS_DNS_INTERNAL_H
#define XAIOS_DNS_INTERNAL_H

#include <xaios/dns.h>
#include <xaios/dnssec.h>

#ifndef XAIOS_BOOT_TEST_APPS
#define XAIOS_BOOT_TEST_APPS 0
#endif

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

/* Resolver globals. Defined in dns.c. */
extern uint32_t g_dns_server_ip;
extern uint16_t g_dns_next_id;
extern dns_pending_t g_dns_pending;
extern uint64_t g_dns_query_count;
extern uint64_t g_dns_response_count;
extern uint64_t g_dns_reject_count;
extern uint64_t g_dns_timeout_count;
extern uint64_t g_dns_tcp_fallback_count;
extern uint64_t g_dns_authenticated_count;
extern uint64_t g_dns_insecure_count;

/* Wire codec, byte and string helpers, cache and query builder. Defined in
   dns.c so that the resolver and the self-test share one implementation. */
uint16_t dns_get_be16(const uint8_t *src);
void dns_put_be16(uint8_t *dst, uint16_t value);
uint32_t dns_get_be32(const uint8_t *src);
uint32_t dns_str_len(const char *value);
int dns_str_case_equal(const char *a, const char *b, uint32_t capacity);
void dns_str_copy(char *dst, const char *src, uint32_t capacity);
void dns_bytes_zero(void *buffer, uint32_t size);
void dns_bytes_copy(void *output, const void *input, uint32_t size);
uint16_t dns_random_u16(uint16_t fallback);
uint16_t dns_random_ephemeral_port(uint16_t fallback);
uint32_t dns_build_query(uint8_t *output, uint32_t capacity,
                         const char *hostname, uint16_t id,
                         uint16_t query_type);
int dns_cache_lookup(const char *hostname, uint8_t family,
                     xaios_ip_addr_t *address, uint64_t now_ns);
void dns_cache_insert(const char *hostname, const xaios_ip_addr_t *address,
                      uint32_t ttl_seconds, uint64_t now_ns);

/* Boot log of the trust anchors in force; defined in dns.c and also used by
   the self-test's restore check. */
void dns_log_trust_anchors(void);

#if XAIOS_BOOT_TEST_APPS
/* The boot-test fixture zone, in dns_selftest.c. */
int dns_selftest_is_fixture_name(const char *hostname);
xaios_status_t dns_selftest_fixture_resolve(const char *hostname,
                                            uint8_t family,
                                            xaios_ip_addr_t *out_address,
                                            uint64_t now_ns);
#endif

#endif /* XAIOS_DNS_INTERNAL_H */
