#include <xaios_user.h>

#if XAIOS_BOOT_TEST_APPS
static int bytes_equal(const unsigned char *lhs, const unsigned char *rhs,
                       u64 size) {
  for (u64 i = 0; i < size; ++i) {
    if (lhs[i] != rhs[i]) return 0;
  }
  return 1;
}
#endif

int main(void) {
  const char payload[] = "xaios-nettest";
  u64 echoed = 0;
  u64 round_trips = 0;
  u64 out = 0;
  char session[96];
  xaios_log("/bin/nettest: validating ethernet tcp udp network telemetry\n");
  if (xaios_net_udp_echo(payload, xaios_strlen(payload), &echoed) < 0 ||
      echoed != xaios_strlen(payload)) {
    xaios_log("/bin/nettest: udp echo syscall failed\n");
    return 1;
  }
  if (xaios_net_tcp_connect(&round_trips) < 0 || round_trips != 2U) {
    xaios_log("/bin/nettest: tcp connect syscall failed\n");
    return 1;
  }
  xaios_memzero(session, sizeof(session));
  if (xaios_net_external_session(XAIOS_NET_PROTOCOL_UDP, 2222, payload,
                                xaios_strlen(payload), session,
                                sizeof(session), &out) < 0 ||
      out == 0) {
    xaios_log("/bin/nettest: external udp session failed\n");
    return 1;
  }
  xaios_memzero(session, sizeof(session));
  out = 0;
  if (xaios_net_external_session(XAIOS_NET_PROTOCOL_TCP, 2222, payload,
                                xaios_strlen(payload), session,
                                sizeof(session), &out) < 0 ||
      out == 0) {
    xaios_log("/bin/nettest: external tcp session failed\n");
    return 1;
  }
#if XAIOS_BOOT_TEST_APPS
  /* B-33. The boot fixture must not depend on an external recursive resolver,
   * and until now it depended on nothing at all: this branch was a single log
   * call with no resolver code behind it, and qemu-smoke required the string.
   *
   * The boot-test kernel answers the zone "selftest" from the signed chain
   * committed in kernel/net/dns_selftest_chain.h, so what follows is a real
   * DNSSEC validation -- root DNSKEY against the chain's anchor, DS, child
   * DNSKEY, then the RRSIG over the address RRset -- driven by a userspace
   * syscall, with no packet sent and no wall clock read.
   *
   * The addresses are the fixture's own, from that header. Repeating them
   * here fails closed: a chain regenerated with different ones makes this
   * application exit non-zero rather than pass quietly. */
  static const unsigned char expected_v4[4] = {10U, 53U, 0U, 7U};
  static const unsigned char expected_v6[16] = {
      0x20U, 0x01U, 0x0dU, 0xb8U, 0x00U, 0x00U, 0x00U, 0x00U,
      0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x35U};
  xaios_ip_addr_user_t fixture_v4;
  xaios_ip_addr_user_t fixture_v6;
  xaios_ip_addr_user_t fixture_cached;
  xaios_ip_addr_user_t fixture_forged;
  u32 fixture_ipv4 = 0U;
  xaios_memzero(&fixture_v4, sizeof(fixture_v4));
  xaios_memzero(&fixture_v6, sizeof(fixture_v6));
  if (xaios_net_resolve_address("selftest", 4U, &fixture_v4) != 0 ||
      fixture_v4.family != 4U ||
      !bytes_equal(fixture_v4.addr, expected_v4, 4U)) {
    xaios_log("/bin/nettest: fixture zone A record did not validate\n");
    return 1;
  }
  if (xaios_net_resolve_address("selftest", 6U, &fixture_v6) != 0 ||
      fixture_v6.family != 6U ||
      !bytes_equal(fixture_v6.addr, expected_v6, 16U)) {
    xaios_log("/bin/nettest: fixture zone AAAA record did not validate\n");
    return 1;
  }
  /* Fail-closed, proved from here rather than asserted in the kernel: the
   * same zone and key with one bit of the signature flipped must not resolve.
   * A verifier that returned success unconditionally would satisfy both
   * checks above and only fail this one. */
  xaios_memzero(&fixture_forged, sizeof(fixture_forged));
  if (xaios_net_resolve_address("forged.selftest", 4U, &fixture_forged) == 0) {
    xaios_log("/bin/nettest: resolver accepted a forged DNSSEC signature\n");
    return 1;
  }
  xaios_log("/bin/nettest: deterministic local DNSSEC resolver path passed\n");
#else
  u32 resolved = 0U;
  u64 dns_deadline = xaios_clock_nanos() + 16000000000ULL;
  int dns_status = XAIOS_ERR_BUSY;
  while (dns_status == XAIOS_ERR_BUSY && xaios_clock_nanos() < dns_deadline) {
    dns_status = xaios_net_resolve("example.com", &resolved);
  }
  if (dns_status != 0 || resolved == 0U) {
    xaios_log("/bin/nettest: userspace DNS resolution failed\n");
    return 1;
  }
  u32 cached = 0U;
  if (xaios_net_resolve("example.com", &cached) != 0 || cached != resolved) {
    xaios_log("/bin/nettest: userspace DNS cache failed\n");
    return 1;
  }
#endif
  (void)xaios_osctl("osctl net");
  xaios_log_u64("/bin/nettest: udp_echo_bytes=", echoed, "\n");
  xaios_log_u64("/bin/nettest: tcp_round_trips=", round_trips, "\n");
  xaios_log("/bin/nettest: app-callable udp/tcp path passed\n");
  xaios_log("/bin/nettest: external host-to-guest tcp/udp session path passed\n");
#if XAIOS_BOOT_TEST_APPS
  /* The validated answer was admitted to the resolver cache, so the repeat
   * resolve is served from it and has to be the same address. This is the
   * cache half of what the other configuration's branch checks against a
   * real recursive resolver. */
  xaios_memzero(&fixture_cached, sizeof(fixture_cached));
  if (xaios_net_resolve_address("selftest", 4U, &fixture_cached) != 0 ||
      !bytes_equal(fixture_cached.addr, fixture_v4.addr, 4U)) {
    xaios_log("/bin/nettest: fixture zone cache lookup disagreed\n");
    return 1;
  }
  if (xaios_net_resolve("selftest", &fixture_ipv4) != 0) {
    xaios_log("/bin/nettest: fixture zone ipv4 resolve failed\n");
    return 1;
  }
  /* The figure, not just the verdict: 171245575 is 10.53.0.7, and the gate
   * pins it. A marker that carries the value it validated cannot be satisfied
   * by a resolver that returns something else. */
  xaios_log_u64("/bin/nettest: dnssec_fixture_ipv4=", fixture_ipv4, "\n");
  xaios_log("/bin/nettest: userspace DNS fixture path passed\n");
#else
  xaios_log("/bin/nettest: userspace DNS resolve/cache path passed\n");
#endif
  xaios_log("/bin/nettest: complete\n");
  return 0;
}
