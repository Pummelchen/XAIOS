/* The tools' local socket (Phase 9).
 *
 * The plan's first completion criterion for the tools is that they "run local IPv4 and IPv6 packet
 * sessions", and the socket is the half of that which the runtime already owns: this module is the
 * thin piece that turns a `host:port` from a command line into a bound or targeted UDP endpoint,
 * with the family taken from the ADDRESS rather than from a flag. An `IPv4` address on an `IPv6`
 * socket is not reachable (the runtime sets `IPV6_V6ONLY` explicitly, because the platform default
 * differs), so a tool that guessed the family would work on one machine and not the next.
 *
 * What this module deliberately does NOT do is drive a session: it opens, binds, reports what it
 * bound and closes. The session driver is the rest of Phase 9, and keeping the two apart means the
 * socket half can be tested for what it is -- the address parser, the family choice, the actual
 * bound port -- instead of only through a handshake.
 */

#ifndef WEBTRANSPORT_CLI_ENDPOINT_H
#define WEBTRANSPORT_CLI_ENDPOINT_H

#include <stdio.h>

#include "webtransport/runtime/udp.h"
#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct wt_cli_endpoint {
  wt_udp_socket_t socket;
  wt_udp_address_t address;
  /* The port actually bound, which is not the one asked for when the port was 0. */
  uint16_t bound_port;
  int open;
} wt_cli_endpoint_t;

/* Open the socket for `host_port` and, for a listener, bind it. A client parses and does not bind:
 * its local port is the system's business. `host_port` may be `host:port` or `[v6]:port` -- a wildcard is spelled
 * `0.0.0.0:port` or `[::]:port` rather than a bare `:port`, because the address parser refuses an empty host, and
 * an earlier version of this comment claimed otherwise. Port 0 asks the system to choose one, which is what a
 * test wants. Returns the runtime's own statuses unchanged -- a bind that is refused is refused because the
 * system refused it, and translating that would hide the reason.
 *
 * The struct must be ZERO-INITIALISED (or closed) before the first call: `wt_cli_endpoint_open` clears it and
 * does not close what was there, because it cannot tell a caller's uninitialised bytes from a live socket --
 * closing those is how a library closes a descriptor it never opened. Opening an endpoint that is already open
 * therefore leaks its socket; call `wt_cli_endpoint_close` first. */
wt_status_t wt_cli_endpoint_open(wt_cli_endpoint_t *endpoint, const char *host_port, int listen);

void wt_cli_endpoint_close(wt_cli_endpoint_t *endpoint);

/* One JSON object describing what the tool is talking to, after the bind: the family by name, the
 * address as given, and the port actually bound. A script reads the PORT rather than parsing the
 * text, which is why a listener on port 0 can be used by a test at all. */
void wt_cli_endpoint_write_json(const wt_cli_endpoint_t *endpoint, const char *address, FILE *stream);

const char *wt_cli_family_name(wt_udp_family_t family);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_CLI_ENDPOINT_H */
