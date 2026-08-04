#include <xaios_user.h>

int main(void) {
  const char payload[] = "xaios-nettest";
  u64 echoed = 0;
  u64 round_trips = 0;
  u64 out = 0;
  char session[96];
  u32 resolved = 0U;
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
  u64 dns_deadline = xaios_clock_nanos() + 5000000000ULL;
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
  (void)xaios_osctl("osctl net");
  xaios_log_u64("/bin/nettest: udp_echo_bytes=", echoed, "\n");
  xaios_log_u64("/bin/nettest: tcp_round_trips=", round_trips, "\n");
  xaios_log("/bin/nettest: app-callable udp/tcp path passed\n");
  xaios_log("/bin/nettest: external host-to-guest tcp/udp session path passed\n");
  xaios_log("/bin/nettest: userspace DNS resolve/cache path passed\n");
  xaios_log("/bin/nettest: complete\n");
  return 0;
}
