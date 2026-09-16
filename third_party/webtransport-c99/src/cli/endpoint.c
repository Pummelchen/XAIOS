/* The tools' local socket (Phase 9). */

#include "webtransport/cli/endpoint.h"

#include <string.h>

const char *wt_cli_family_name(wt_udp_family_t family) {
  switch (family) {
    case WT_UDP_IPV4: return "ipv4";
    case WT_UDP_IPV6: return "ipv6";
  }
  return "unknown";
}

wt_status_t wt_cli_endpoint_open(wt_cli_endpoint_t *endpoint, const char *host_port, int listen) {
  wt_status_t status;

  if (endpoint == NULL || host_port == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* The struct is ZEROED here and NOT closed first. Closing first was the obvious fix for the leak a second open
   * causes, and it is wrong: a caller that declares `wt_cli_endpoint_t endpoint;` and calls open has an
   * uninitialised struct, and `close` would then read a garbage `open` and a garbage descriptor -- on Wine it
   * closed a socket this function had not opened, and the test that opens a second listener on the same port
   * stopped seeing the refusal. The precondition is stated in the header instead: zero the struct, or close it,
   * before the first open. */
  memset(endpoint, 0, sizeof(*endpoint));
  endpoint->socket.fd = WT_UDP_INVALID_FD;

  /* The address decides the family, and the parser is the runtime's: a second parser here would
   * be a second set of rules about what `[::1]:443` means. */
  status = wt_udp_address_parse_host_port(host_port, &endpoint->address);
  if (status != WT_OK) return status;

  status = wt_udp_socket_open(&endpoint->socket, endpoint->address.family);
  if (status != WT_OK) return status;
  endpoint->open = 1;

  if (listen != 0) {
    status = wt_udp_bind(&endpoint->socket, &endpoint->address);
    if (status != WT_OK) {
      wt_cli_endpoint_close(endpoint);
      return status;
    }
    endpoint->bound_port = endpoint->socket.port;
  } else {
    /* A client does not bind: its local port is the system's business, and binding one would stop
     * two clients on the same machine from talking to the same server. */
    endpoint->bound_port = 0U;
  }
  return WT_OK;
}

void wt_cli_endpoint_close(wt_cli_endpoint_t *endpoint) {
  if (endpoint == NULL) return;
  if (endpoint->open != 0) wt_udp_close(&endpoint->socket);
  endpoint->open = 0;
  endpoint->socket.fd = WT_UDP_INVALID_FD;
}

void wt_cli_endpoint_write_json(const wt_cli_endpoint_t *endpoint, const char *address, FILE *stream) {
  if (stream == NULL) return;
  fputs("{\"family\":", stream);
  if (endpoint == NULL) {
    /* The newline is not decoration: every other path ends the object with one, and a consumer that reads one
     * JSON object per LINE mis-frames a report whose last line has none. */
    fputs("null,\"address\":null,\"boundPort\":0}\n", stream);
    return;
  }
  fprintf(stream, "\"%s\"", wt_cli_family_name(endpoint->address.family));
  fputs(",\"address\":", stream);
  if (address == NULL) {
    fputs("null", stream);
  } else {
    fprintf(stream, "\"%s\"", address);
  }
  fprintf(stream, ",\"boundPort\":%u}\n", (unsigned)endpoint->bound_port);
}
