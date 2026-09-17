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
#include "dns_selftest_chain.h"

/* The instant the fixture chain's signatures are judged at. Shared by the
   self-test and, in the boot-test configuration, by the fixture zone the
   resolver answers locally: both validate the same committed material, and
   both must do so without reading a wall clock that may still be the raw
   monotonic counter this early in boot. */
#define DNS_SELFTEST_WALL_NS UINT64_C(1900000000000000000)

/* The self-test chain's own trust anchor, as a DS record. The chain in
   dns_selftest_chain.h is rooted here rather than at the real root, and both
   callers -- the self-test, which installs it as the configured anchor set,
   and the boot-test fixture zone, which passes it in directly -- need the same
   bytes. */
static void dns_selftest_anchor(dnssec_ds_t *out) {
  dns_bytes_zero(out, sizeof(*out));
  out->key_tag = DNS_SELFTEST_ROOT_TAG;
  out->algorithm = 8U;
  out->digest_type = 2U;
  out->digest_length = (uint8_t)sizeof(k_selftest_anchor_digest);
  dns_bytes_copy(out->digest, k_selftest_anchor_digest,
             sizeof(k_selftest_anchor_digest));
}

#if XAIOS_BOOT_TEST_APPS
/* B-33. In the boot-test configuration only, the resolver answers one zone
   from the signed chain the image already carries, so that a userspace caller
   can drive a genuine DNSSEC validation on a machine with no recursive
   resolver to ask. /bin/nettest resolves it and compares the answer; before
   this, the marker it printed for that was a bare log call with no code behind
   it.

   Two names, because one of them only proves half of what the marker claims:

     selftest          the fixture zone. DNSKEY -> DS -> DNSKEY -> RRSIG over
                       the A or AAAA RRset, exactly the code a real answer goes
                       through, and then admitted to the ordinary cache.
     forged.selftest   the same zone and key with one bit of the signature
                       flipped. It must NOT validate. A verifier that returned
                       success unconditionally would satisfy every check
                       against the first name and fail only this one, so the
                       refusal is carried to userspace as a result rather than
                       being swallowed here.

   Nothing is transmitted and no wall clock is read, so this works before the
   network is up and on a machine with no NIC.

   Why this is not a special case in shipping code: the whole thing is inside
   XAIOS_BOOT_TEST_APPS, the same switch that selects the test applications and
   the same one /bin/nettest's branch is under. `make image`, `make release`
   and the kit builds set it to 0, so a shipping resolver has no fixture zone,
   no fixture keyset and no branch testing for either. */
#define DNS_FIXTURE_FORGED_NAME "forged." DNS_SELFTEST_ZONE

/* Whether a name belongs to the boot-test fixture zone. The resolver calls
   this rather than carrying DNS_SELFTEST_ZONE and DNS_FIXTURE_FORGED_NAME
   into its own translation unit, so the generated fixture header is included
   only where the fixture itself lives. The two comparisons are the ones that
   used to sit inline in dns_resolve_address_unlocked. */
int dns_selftest_is_fixture_name(const char *hostname) {
  return dns_str_case_equal(hostname, DNS_SELFTEST_ZONE, DNS_MAX_HOSTNAME) ||
         dns_str_case_equal(hostname, DNS_FIXTURE_FORGED_NAME,
                            DNS_MAX_HOSTNAME);
}

/* A keyset is roughly nine kilobytes; too much for the kernel stack of the
   thread that happens to make the syscall. Static, and reached only under the
   network stack guard that dns_resolve_address already holds. */
static dnssec_keyset_t g_fixture_keys;
static dnssec_dsset_t g_fixture_ds;

static xaios_status_t dns_fixture_walk(uint16_t type, const uint8_t *answer,
                                       uint32_t answer_length,
                                       uint8_t *out_address,
                                       uint32_t *out_ttl) {
  dnssec_dsset_t anchors;
  dns_bytes_zero(&anchors, sizeof(anchors));
  anchors.owner[0] = '\0';
  anchors.count = 1U;
  dns_selftest_anchor(&anchors.records[0]);
  /* The anchor is passed as the parent DS set rather than installed with
     dnssec_set_trust_anchors: this runs while the rest of the system is up,
     and swapping the configured root anchors underneath a real resolution in
     flight would be a fine way to make one fail for reasons nobody could
     explain. */
  if (dnssec_verify_dnskey(k_selftest_root_dnskey,
                           (uint32_t)sizeof(k_selftest_root_dnskey), "",
                           &anchors, DNS_SELFTEST_WALL_NS,
                           &g_fixture_keys) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  if (dnssec_verify_ds(k_selftest_ds, (uint32_t)sizeof(k_selftest_ds),
                       DNS_SELFTEST_ZONE, &g_fixture_keys,
                       DNS_SELFTEST_WALL_NS, &g_fixture_ds) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  if (dnssec_verify_dnskey(k_selftest_dnskey,
                           (uint32_t)sizeof(k_selftest_dnskey),
                           DNS_SELFTEST_ZONE, &g_fixture_ds,
                           DNS_SELFTEST_WALL_NS,
                           &g_fixture_keys) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  return dnssec_verify_address(answer, answer_length, DNS_SELFTEST_ZONE, type,
                               &g_fixture_keys, DNS_SELFTEST_WALL_NS,
                               out_address, out_ttl);
}

xaios_status_t dns_selftest_fixture_resolve(const char *hostname, uint8_t family,
                                          xaios_ip_addr_t *out_address,
                                          uint64_t now_ns) {
  uint8_t forged[sizeof(k_selftest_a)];
  uint8_t address[16];
  uint32_t ttl = 0U;
  uint16_t type = family == XAIOS_IP_FAMILY_V4 ? XAIOS_DNS_TYPE_A
                                               : XAIOS_DNS_TYPE_AAAA;
  const uint8_t *answer = k_selftest_a;
  uint32_t answer_length = (uint32_t)sizeof(k_selftest_a);
  int tampered = dns_str_case_equal(hostname, DNS_FIXTURE_FORGED_NAME,
                                DNS_MAX_HOSTNAME);
  if (tampered) {
    dns_bytes_copy(forged, k_selftest_a, sizeof(forged));
    forged[sizeof(forged) - 1U] ^= 0x01U;
    answer = forged;
    answer_length = (uint32_t)sizeof(forged);
    type = XAIOS_DNS_TYPE_A;
  } else if (family == XAIOS_IP_FAMILY_V6) {
    answer = k_selftest_aaaa;
    answer_length = (uint32_t)sizeof(k_selftest_aaaa);
  }
  if (dns_fixture_walk(type, answer, answer_length, address, &ttl) !=
      XAIOS_OK) {
    ++g_dns_reject_count;
    klog("dns: fixture %s refused by local validation%s\n", hostname,
         tampered ? " (expected: the signature was tampered with)" : "");
    return XAIOS_ERR_INVALID;
  }
  ++g_dns_authenticated_count;
  if (type == XAIOS_DNS_TYPE_A) {
    *out_address = xaios_ip_addr_from_ipv4(
        ((uint32_t)address[0] << 24U) | ((uint32_t)address[1] << 16U) |
        ((uint32_t)address[2] << 8U) | (uint32_t)address[3]);
  } else {
    out_address->family = XAIOS_IP_FAMILY_V6;
    dns_bytes_copy(out_address->addr, address, 16U);
  }
  if (tampered) {
    /* Reported, not hidden: userspace is the one that decides this is a
       failure, and it cannot decide that if the kernel quietly turns an
       accepted forgery into a refusal. */
    klog("dns: fixture %s VALIDATED a tampered signature\n", hostname);
    return XAIOS_OK;
  }
  klog("dns: fixture %s validated locally type=%u ttl=%u chain=selftest\n",
       hostname, (unsigned)type, (unsigned)ttl);
  dns_cache_insert(hostname, out_address, ttl, now_ns);
  return XAIOS_OK;
}
#endif

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
   real root; dns_init() at the end puts the IANA anchors back, and the end of
   this function asserts that it did.

   B-42, the question of whether any of this belongs in a release image. It is
   unconditional on purpose, and the decision was taken on measurement rather
   than on the feeling that test material in a shipping binary is untidy.

   What it costs, aarch64, `make image` against the same tree built with the
   self-test compiled out: 7,409 bytes of dns.o -- 3,008 of code, 1,445 of
   fixture chain, 2,951 of string literals, most of them the expressions
   kassert stringifies for its panic message. Linked, .rodata is one 4 KiB page
   larger and .text is unchanged (the removed code fits in the padding the
   linker script already leaves), so kernel.elf goes from 1,043,560 to
   1,038,920 bytes: 0.44%. The boot image is a fixed 64 MiB and does not move,
   and the initfs does not contain any of this.

   What it buys: the only DNSSEC verification that happens anywhere in a
   shipping configuration. B-33's fixture zone is correctly behind
   XAIOS_BOOT_TEST_APPS, no gate greps the marker below, and kassert is never
   compiled out -- so on a release machine this walk is what stands between a
   broken verifier and a resolver that believes whatever it is told. Guarding
   it out would buy 0.44% of the kernel and leave that at nothing.

   One thing a future guard would have to carry with it: this is the only
   unconditional caller of dns_init() on a boot whose persistent network never
   comes up, and dns_init() is what installs the root anchors. */
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
  dnssec_keyset_t *keys = &g_dns_pending.validated_keys;
  dnssec_dsset_t *ds = &g_dns_pending.child_ds;

  dns_selftest_anchor(&anchor);
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
  dns_bytes_copy(forged, k_selftest_a, sizeof(forged));
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
  dns_bytes_zero(&g_dns_pending, sizeof(g_dns_pending));
  g_dns_pending.state = DNS_PENDING_UDP;
  g_dns_pending.family = XAIOS_IP_FAMILY_V4;
  g_dns_pending.query_type = XAIOS_DNS_TYPE_A;
  g_dns_pending.dnssec_stage = stage;
  g_dns_pending.hostname_labels = 1U;
  g_dns_pending.id = id;
  /* Already out of retransmits, so dns_tick reaches its deadlines without
     asking a network device that may not exist to send anything. */
  g_dns_pending.retransmits = DNS_MAX_RETRANSMITS;
  dns_str_copy(g_dns_pending.hostname, DNS_SELFTEST_ZONE, DNS_MAX_HOSTNAME);
  dns_str_copy(g_dns_pending.query_name, DNS_SELFTEST_ZONE, DNS_MAX_HOSTNAME);
}

static uint32_t dns_self_test_truncation(void) {
  /* A truncated UDP reply moves the query to TCP; a reply that is still
     truncated after the TCP attempt is a dead end, not another retry. Both
     decisions are taken on the twelve-byte header, before any validation, so
     neither needs a signature, a clock, or a NIC. */
  uint8_t reply[12];
  uint64_t before = g_dns_tcp_fallback_count;
  dns_self_test_pending(UINT16_C(0xbeef), DNSSEC_STAGE_ADDRESS);
  dns_bytes_zero(reply, sizeof(reply));
  dns_put_be16(reply, g_dns_pending.id);
  dns_put_be16(reply + 2U, (uint16_t)(DNS_FLAG_QR | DNS_FLAG_TC));
  kassert(dns_process_message(reply, sizeof(reply), 0U, 0U) == XAIOS_ERR_BUSY);
  kassert(g_dns_pending.state == DNS_PENDING_TCP_CONNECT);
  kassert(g_dns_tcp_fallback_count == before + 1U);
  kassert(dns_process_message(reply, sizeof(reply), 0U, 1U) ==
          XAIOS_ERR_NOT_FOUND);
  kassert(g_dns_pending.state == DNS_PENDING_COMPLETE);
  kassert(g_dns_pending.result == XAIOS_ERR_NOT_FOUND);
  return (uint32_t)(g_dns_tcp_fallback_count - before);
}

static void dns_self_test_deadlines(void) {
  /* B-35, in the kernel that has to honour it. The clock is supplied, so this
     is exact rather than timing-dependent.

     The first tick is the control that fails on the defect: the walk is 21 s
     old, past the 15 s that used to cover all of it, while the query in flight
     is 1 s old. A resolver that judges a query by when the walk began ends the
     resolution here. */
  uint64_t timeouts = g_dns_timeout_count;
  klog("dns: self-test exercising resolver deadlines; the two timeout lines "
       "below are the test, not a fault\n");
  dns_self_test_pending(UINT16_C(0x0d15), DNSSEC_STAGE_CHILD_DS);
  g_dns_pending.walk_started_ns = 0U;
  g_dns_pending.query_started_ns = UINT64_C(20000000000);
  g_dns_pending.sent_ns = g_dns_pending.query_started_ns;
  dns_tick(UINT64_C(21000000000));
  kassert(g_dns_pending.state == DNS_PENDING_UDP);
  kassert(g_dns_timeout_count == timeouts);
  /* Its own deadline still ends it, and ends it as "no verdict". */
  dns_tick(g_dns_pending.query_started_ns + DNS_QUERY_TIMEOUT_NS);
  kassert(g_dns_pending.state == DNS_PENDING_COMPLETE);
  kassert(g_dns_pending.result == XAIOS_ERR_CANCELLED);
  kassert(g_dns_timeout_count == timeouts + 1U);

  /* And the walk budget ends a walk whose query in flight is young, which is
     what stops per-query deadlines composing without bound. */
  dns_self_test_pending(UINT16_C(0x0d16), DNSSEC_STAGE_CHILD_DNSKEY);
  g_dns_pending.walk_started_ns = 0U;
  g_dns_pending.query_started_ns = DNS_WALK_TIMEOUT_NS - UINT64_C(5000000000);
  g_dns_pending.sent_ns = g_dns_pending.query_started_ns;
  dns_tick(DNS_WALK_TIMEOUT_NS);
  kassert(g_dns_pending.state == DNS_PENDING_COMPLETE);
  kassert(g_dns_pending.result == XAIOS_ERR_CANCELLED);
  kassert(g_dns_timeout_count == timeouts + 2U);
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
  kassert(dns_str_case_equal(decoded, "www.google.com", sizeof(decoded)));
  uint8_t loop[2] = {0xc0U, 0x00U};
  kassert(dns_decode_name(loop, sizeof(loop), 0U, decoded,
                          sizeof(decoded)) < 0);
  uint8_t reserved[2] = {0x40U, 0U};
  kassert(dns_decode_name(reserved, sizeof(reserved), 0U, decoded,
                          sizeof(decoded)) < 0);
  kassert(dns_encode_name(encoded, sizeof(encoded), ".bad") == 0U);
  kassert(dns_encode_name(encoded, sizeof(encoded), "bad..name") == 0U);
  xaios_ip_addr_t address = xaios_ip_addr_from_ipv4(UINT32_C(0x01020304));
  dns_cache_insert("cache.test", &address, 60U, UINT64_C(1000000));
  xaios_ip_addr_t result;
  kassert(dns_cache_lookup("CACHE.TEST", XAIOS_IP_FAMILY_V4, &result,
                       UINT64_C(1000000)) == 1);
  kassert(xaios_ip_addr_to_ipv4(&result) == UINT32_C(0x01020304));
  kassert(dns_cache_lookup("cache.test", XAIOS_IP_FAMILY_V6, &result,
                       UINT64_C(1000000)) == 0);
  uint32_t aaaa_validated = 0U;
  uint32_t links = dns_self_test_chain(&aaaa_validated);
  uint32_t truncations = dns_self_test_truncation();
  dns_self_test_deadlines();
  /* Put the real root anchors back and drop everything the test left behind:
     the test anchor, the fake pending record, and the test's counter values. */
  dns_init();
  /* B-42, and the reason this function is allowed to touch the configured
     anchor set at all: the restore is checked rather than assumed. The chain
     above is rooted at a test anchor that this function installs as *the*
     anchor set, and a machine that finished boot still holding it would
     happily validate a forgery signed with a key committed to this
     repository. The restore is one call above and it is still worth
     asserting: the property is about a global, dns_init() is the only thing
     that resets it, and an edit that moves either call is exactly the kind
     that reads fine. Checked against the table, not against the call.

     This restore is the one that always runs. The kernel calls dns_init()
     once more when the persistent network stack comes up, which would clear a
     surviving test anchor a second time -- but only on a machine that got that
     far, and a machine with no usable network device skips that branch
     entirely and keeps whatever this function left installed.

     Control run: with the dns_init() above removed, an otherwise unchanged
     release image halts at "assertion failed: anchor_count ==
     XAIOS_DNSSEC_MAX_ANCHORS", and with these assertions removed as well the
     marker below reads root_anchors=1 and the line after it tags=9581. */
  uint16_t anchors_after[XAIOS_DNSSEC_MAX_ANCHORS];
  uint32_t anchor_count =
      dnssec_trust_anchor_tags(anchors_after, XAIOS_DNSSEC_MAX_ANCHORS);
  kassert(anchor_count == XAIOS_DNSSEC_MAX_ANCHORS);
  for (uint32_t i = 0U; i < anchor_count; ++i)
    kassert(anchors_after[i] != DNS_SELFTEST_ROOT_TAG);
  klog("dns: self-test passed dnssec=local-chain tcp-fallback=enabled "
       "aaaa=enabled chain_links=%u forged_signature=rejected "
       "expired_signature=rejected truncated_reply=%u validated_aaaa=%u "
       "root_anchors=%u\n",
       (unsigned)links, (unsigned)truncations, (unsigned)aaaa_validated,
       (unsigned)anchor_count);
  dns_log_trust_anchors();
}
