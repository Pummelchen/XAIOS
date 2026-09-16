/* The UDP socket surface. See webtransport/runtime/udp.h.
 *
 * The only POSIX file in the tree. Every conversion between this library's types and the platform's
 * happens inside this file, and so does every classification of a syscall failure, so that nothing
 * above it has to know which platform it is on.
 */

#include "webtransport/runtime/udp.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The platform differences live in one private header: closing, non-blocking mode, readability and the error
 * number. The socket types and the datagram calls are still POSIX here, which is the NEXT step of WT-134 and is
 * written down in docs/PORTABILITY.md rather than pretended away. */
#include "udp_platform.h"

#include "webtransport/endian.h"
#include "webtransport/time.h"

/* How many bytes of an IPv4 address are meaningful, and of an IPv6 one. Named because the literal 4
 * and 16 appear wherever the two families are told apart. */
#define WT_UDP_IPV4_BYTES 4U
#define WT_UDP_IPV6_BYTES 16U
#define WT_UDP_MAX_PORT 65535U

/* The platform's error number and its classification both live in `udp_platform.h` now: the numbers are a
 * different integer space on Windows, and so is the set of names available to switch on. */

/* The address conversions and the family names live in `udp_platform.h` now, one implementation per platform:
 * they are the last place this file named `AF_INET`, `sockaddr_in` or `inet_pton`, and a socket header is what a
 * Windows build does not have. What is left here is the policy -- which family a literal names, which scope ids
 * are legal -- rather than the platform's types. */

const char *wt_udp_family_name(wt_udp_family_t family) {
  switch (family) {
    case WT_UDP_IPV4:
      return "ipv4";
    case WT_UDP_IPV6:
      return "ipv6";
  }
  return "unknown";
}

void wt_udp_address_loopback(wt_udp_family_t family, wt_udp_address_t *out) {
  if (out == NULL) return;
  memset(out, 0, sizeof(*out));
  out->family = family;
  if (family == WT_UDP_IPV4) {
    /* 127.0.0.1, written out rather than taken from INADDR_LOOPBACK: that constant is BSD and not
     * POSIX, and WT-14 found that defining _POSIX_C_SOURCE on one host removed it. The final 1 is
     * part of the address -- 127.0.0.0 is a network, not the loopback host, and binding it fails with
     * EADDRNOTAVAIL. */
    out->bytes[0] = 127U;
    out->bytes[3] = 1U;
  } else {
    /* ::1 in network order: fifteen zero bytes and a one. */
    out->bytes[15] = 1U;
  }
}

int wt_udp_address_equal(const wt_udp_address_t *a, const wt_udp_address_t *b) {
  size_t length;
  if (a == NULL || b == NULL) return 0;
  if (a->family != b->family || a->port != b->port || a->scope_id != b->scope_id) return 0;
  length = a->family == WT_UDP_IPV4 ? WT_UDP_IPV4_BYTES : WT_UDP_IPV6_BYTES;
  return memcmp(a->bytes, b->bytes, length) == 0;
}

size_t wt_udp_address_encode(const wt_udp_address_t *address, uint8_t *out, size_t capacity) {
  if (address == NULL || out == NULL || capacity < WT_UDP_ADDRESS_ENCODED_LENGTH) return 0U;
  out[0] = (uint8_t)address->family;
  memcpy(out + 1U, address->bytes, 16U);
  wt_store_be16(out + 17U, address->port);
  wt_store_be32(out + 19U, address->scope_id);
  return WT_UDP_ADDRESS_ENCODED_LENGTH;
}

wt_status_t wt_udp_socket_open(wt_udp_socket_t *out, wt_udp_family_t family) {
  int domain = wt_udp_platform_family_domain(family);
  wt_udp_handle_t fd;

  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  out->fd = WT_UDP_INVALID_FD;
  out->family = family;
  out->port = 0U;
  if (domain < 0) return WT_ERR_INVALID_ARGUMENT;

  /* The socket LIFETIME is the platform's first: on Windows this is where Winsock starts, and the matching
   * release is in `wt_udp_close`, which is the only other end of a socket's life. Every failure below
   * releases it, so a failed open does not leave the process holding the library. */
  if (wt_udp_platform_acquire() != 0) return wt_udp_platform_status_of_error(wt_udp_platform_last_error());

  fd = socket(domain, SOCK_DGRAM, 0);
  if (fd == WT_UDP_INVALID_HANDLE) {
    int error = wt_udp_platform_last_error();
    wt_udp_platform_release();
    return wt_udp_platform_status_of_error(error);
  }

  /* Non-blocking from the start: a socket that blocked on receive would make the connection runtime's
   * timers unenforceable, and setting it here means no caller can forget. */
  if (wt_udp_platform_set_nonblocking(fd) != 0) {
    int error = wt_udp_platform_last_error();
    (void)wt_udp_platform_close(fd);
    wt_udp_platform_release();
    return wt_udp_platform_status_of_error(error);
  }

  if (family == WT_UDP_IPV6) {
    /* Set rather than left to the platform: Linux and the BSDs disagree about the default, and a
     * socket that is sometimes dual-stack would make "which family is this connection" depend on the
     * host. One because a dual-stack socket would also receive IPv4-mapped addresses, which this
     * library's address type reports as a family it does not carry. */
    if (wt_udp_platform_set_v6_only(fd, 1) < 0) {
      int error = wt_udp_platform_last_error();
      (void)wt_udp_platform_close(fd);
      wt_udp_platform_release();
      return wt_udp_platform_status_of_error(error);
    }
  }

  /* A handle is a handle: on Windows this is a pointer-sized unsigned value going into an `intptr_t`, which is
   * the same bits and a different sign. The cast says so rather than letting a warning-as-error decide. */
  out->fd = (intptr_t)fd;
  return WT_OK;
}

wt_status_t wt_udp_bind(wt_udp_socket_t *socket, const wt_udp_address_t *address) {
  struct sockaddr_storage storage;
  wt_udp_socklen_t storage_len = 0;
  wt_status_t status;

  if (socket == NULL || address == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (socket->fd == WT_UDP_INVALID_FD) return WT_ERR_STATE;
  if (address->family != socket->family) {
    /* An IPv4 address cannot be bound to an IPv6 socket here: IPV6_V6ONLY is on, and a silent
     * mismatch would bind the wrong thing. */
    return WT_ERR_INVALID_ARGUMENT;
  }
  status = wt_udp_platform_address_to_storage(address, &storage, &storage_len);
  if (status != WT_OK) return status;
  if (bind((wt_udp_handle_t)socket->fd, (const struct sockaddr *)(const void *)&storage, storage_len) < 0) {
    return wt_udp_platform_status_of_error(wt_udp_platform_last_error());
  }
  socket->port = address->port;
  {
    uint16_t bound = 0U;
    wt_status_t status_port = wt_udp_local_port(socket, &bound);
    if (status_port != WT_OK) return status_port;
    socket->port = bound;
  }
  return WT_OK;
}

wt_status_t wt_udp_bind_loopback(wt_udp_socket_t *socket, uint16_t port, uint16_t *out_port) {
  wt_udp_address_t address;
  wt_status_t status;

  if (socket == NULL) return WT_ERR_INVALID_ARGUMENT;
  wt_udp_address_loopback(socket->family, &address);
  address.port = port;
  status = wt_udp_bind(socket, &address);
  if (status != WT_OK) return status;
  return wt_udp_local_port(socket, out_port);
}

wt_status_t wt_udp_local_port(const wt_udp_socket_t *socket, uint16_t *out_port) {
  struct sockaddr_storage storage;
  wt_udp_socklen_t storage_len = (wt_udp_socklen_t)sizeof(storage);

  if (socket == NULL || out_port == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (socket->fd == WT_UDP_INVALID_FD) return WT_ERR_STATE;
  memset(&storage, 0, sizeof(storage));
  if (getsockname((wt_udp_handle_t)socket->fd, (struct sockaddr *)(void *)&storage, &storage_len) < 0) {
    return wt_udp_platform_status_of_error(wt_udp_platform_last_error());
  }
  /* The port is read through the same conversion a received datagram uses, so "which family is this" has one
   * answer in this file rather than two. A family this library does not carry is UNSUPPORTED here, exactly as
   * it was when the code read `ss_family` itself. */
  {
    wt_udp_address_t bound;
    wt_status_t status = wt_udp_platform_address_from_storage((const struct sockaddr *)(const void *)&storage,
                                                              storage_len, &bound);
    if (status != WT_OK) return status;
    *out_port = bound.port;
  }
  return WT_OK;
}

void wt_udp_close(wt_udp_socket_t *socket) {
  if (socket == NULL) return;
  if (socket->fd != WT_UDP_INVALID_FD) {
    /* The descriptor is cleared before the call: a close that restarts on a signal or a second call
     * must not close a descriptor number the process has since reused -- and a second close must not
     * release the platform's socket lifetime twice, which on Windows would be a WSACleanup with no
     * matching WSAStartup. */
    wt_udp_handle_t handle = (wt_udp_handle_t)socket->fd;
    socket->fd = WT_UDP_INVALID_FD;
    (void)wt_udp_platform_close(handle);
    wt_udp_platform_release();
  }
  socket->port = 0U;
}

wt_status_t wt_udp_send(const wt_udp_socket_t *socket, const wt_udp_address_t *to,
                        const uint8_t *data, size_t length) {
  struct sockaddr_storage storage;
  wt_udp_socklen_t storage_len = 0;
  size_t written = 0U;
  wt_status_t status;

  if (socket == NULL || to == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (socket->fd == WT_UDP_INVALID_FD) return WT_ERR_STATE;
  if (data == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;
  /* Larger than UDP can carry, refused here rather than at the syscall: the number is knowable, and a
   * caller that asks for the impossible should be told which bound it broke. */
  if (length > WT_UDP_MAX_DATAGRAM) return WT_ERR_LIMIT;
  if (to->family != socket->family) return WT_ERR_INVALID_ARGUMENT;

  status = wt_udp_platform_address_to_storage(to, &storage, &storage_len);
  if (status != WT_OK) return status;
  if (wt_udp_platform_send_message((wt_udp_handle_t)socket->fd,
                                   (const struct sockaddr *)(const void *)&storage, (int)storage_len, data,
                                   length, &written) != 0) {
    return wt_udp_platform_status_of_error(wt_udp_platform_last_error());
  }
  /* A datagram is sent whole or not at all, so a short count is not a partial send: it is a platform
   * that did something this layer does not describe. */
  if (written != length) return WT_ERR_IO;
  return WT_OK;
}

wt_status_t wt_udp_receive(const wt_udp_socket_t *socket, uint8_t *buffer, size_t capacity,
                           size_t *out_length, wt_udp_address_t *out_from) {
  struct sockaddr_storage storage;
  wt_udp_platform_message_t message;
  int address_length = (int)sizeof(storage);
  wt_status_t status;

  if (socket == NULL || out_length == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (socket->fd == WT_UDP_INVALID_FD) return WT_ERR_STATE;
  if (buffer == NULL && capacity != 0U) return WT_ERR_INVALID_ARGUMENT;
  *out_length = 0U;

  memset(&storage, 0, sizeof(storage));
  memset(&message, 0, sizeof(message));
  message.bytes = buffer;
  message.capacity = capacity;
  message.address = &storage;
  message.address_length = &address_length;
  message.flags_in = 0;

  /* The platform call receives one datagram WITH its sender and its truncation flag: a receive that only
   * returned a short count would leave a caller unable to tell a truncated datagram from a peer that sent a
   * small one (WT-36). */
  if (wt_udp_platform_receive_message((wt_udp_handle_t)socket->fd, &message) != 0) {
    return wt_udp_platform_status_of_error(wt_udp_platform_last_error());
  }

  /* The sender is reported even when the datagram is discarded, because it is known and it is what a
   * diagnostic needs. */
  if (out_from != NULL) {
    status = wt_udp_platform_address_from_storage((const struct sockaddr *)(const void *)&storage,
                                                  (wt_udp_socklen_t)address_length, out_from);
    if (status != WT_OK) return status;
  }

  if ((message.flags_out & WT_UDP_PLATFORM_TRUNCATED) != 0) {
    /* The datagram was larger than the buffer, so its bytes are not the datagram. Nothing is written
     * to the length, which is what keeps a caller from parsing the prefix of a packet. */
    return WT_ERR_TRUNCATED;
  }
  *out_length = message.bytes_out;
  return WT_OK;
}

wt_status_t wt_udp_peek(const wt_udp_socket_t *socket, uint8_t *buffer, size_t capacity,
                        size_t *out_length, size_t *out_available, wt_udp_address_t *out_from) {
  struct sockaddr_storage storage;
  wt_udp_platform_message_t message;
  int address_length = (int)sizeof(storage);
  wt_status_t status;

  if (socket == NULL || out_length == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (socket->fd == WT_UDP_INVALID_FD) return WT_ERR_STATE;
  if (buffer == NULL && capacity != 0U) return WT_ERR_INVALID_ARGUMENT;
  *out_length = 0U;
  if (out_available != NULL) *out_available = 0U;

  memset(&storage, 0, sizeof(storage));
  memset(&message, 0, sizeof(message));
  message.bytes = buffer;
  message.capacity = capacity;
  message.address = &storage;
  message.address_length = &address_length;
  /* PEEK is the whole point: the datagram is read and left in the queue, so the connection's own receive
   * finds it exactly where it was. FULL_LENGTH is what makes the reported length the datagram's OWN rather
   * than the copied one -- and it is the flag a platform that cannot see past the buffer will not honour,
   * which the platform header says in the structure's comment. */
  message.flags_in = WT_UDP_PLATFORM_PEEK | WT_UDP_PLATFORM_FULL_LENGTH;

  if (wt_udp_platform_receive_message((wt_udp_handle_t)socket->fd, &message) != 0) {
    return wt_udp_platform_status_of_error(wt_udp_platform_last_error());
  }

  if (out_from != NULL) {
    status = wt_udp_platform_address_from_storage((const struct sockaddr *)(const void *)&storage,
                                                  (wt_udp_socklen_t)address_length, out_from);
    if (status != WT_OK) return status;
  }
  *out_length = message.bytes_out;
  if (out_available != NULL) {
    size_t copied = message.bytes_out < capacity ? message.bytes_out : capacity;
    *out_available = copied;
  }
  return WT_OK;
}

wt_status_t wt_udp_wait(const wt_udp_socket_t *socket, uint64_t timeout_micros) {
  struct pollfd entry;
  int timeout_ms;
  int ready;

  if (socket == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (socket->fd == WT_UDP_INVALID_FD) return WT_ERR_STATE;

  /* poll takes milliseconds and an int, so the conversion is bounded here: a caller asking for longer
   * than an int can express in milliseconds gets the longest wait the platform can represent rather
   * than a negative value that would mean "do not block". */
  if (timeout_micros == WT_UDP_WAIT_FOREVER) {
    timeout_ms = -1;
  } else if (timeout_micros / 1000U > (uint64_t)INT32_MAX) {
    timeout_ms = INT32_MAX;
  } else {
    /* Rounded up: a wait of one microsecond must not become a wait of none, which would turn a
     * deadline into a spin. */
    timeout_ms = (int)((timeout_micros + 999U) / 1000U);
  }

  entry.fd = (wt_udp_handle_t)socket->fd;
  entry.events = POLLIN;
  /* A pending error or a hangup is reported through these and only surfaced by a receive attempt, so
   * they are waited on as well: otherwise a socket with an error would never look ready and the
   * caller would time out instead of learning what happened. */
  entry.revents = 0;

  ready = wt_udp_platform_wait_readable(entry.fd, timeout_ms);
  /* The PLATFORM's error number, not `errno`: `WSAPoll` reports through `WSAGetLastError`, so reading
   * `errno` here asked the C runtime about a failure Winsock never reported to it -- and the answer was a
   * stale value classified as `WT_ERR_IO`. This is what `wt_udp_platform_last_error` exists for. */
  if (ready < 0) return wt_udp_platform_status_of_error(wt_udp_platform_last_error());
  if (ready == 0) return WT_ERR_TIMEOUT;
  return WT_OK;
}

wt_status_t wt_udp_address_parse(const char *text, uint16_t port, wt_udp_address_t *out) {
  char host[64];
  const char *scope = NULL;
  size_t length;
  unsigned long scope_id = 0UL;
  int family;

  if (text == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  memset(out, 0, sizeof(*out));

  length = strlen(text);
  if (length == 0U || length >= sizeof(host)) return WT_ERR_INVALID_ARGUMENT;
  memcpy(host, text, length + 1U);

  /* A scope id is written as a percent sign and a number: fe80::1%4. It is part of the address for a
   * link-local one and is not understood by inet_pton, so it is taken off here and put back by the
   * formatter. */
  scope = strchr(host, '%');
  if (scope != NULL) {
    char *end = NULL;
    host[(size_t)(scope - host)] = '\0';
    errno = 0;
    scope_id = strtoul(scope + 1, &end, 10);
    if (end == scope + 1 || *end != '\0' || errno != 0 || scope_id > UINT32_MAX) {
      return WT_ERR_INVALID_ARGUMENT;
    }
  }

  if (strchr(host, ':') != NULL) {
    family = AF_INET6;
    out->family = WT_UDP_IPV6;
  } else {
    family = AF_INET;
    out->family = WT_UDP_IPV4;
  }
  if (scope_id != 0UL && out->family != WT_UDP_IPV6) return WT_ERR_INVALID_ARGUMENT;

  if (wt_udp_platform_parse_address(host, family, out->bytes) != 1) return WT_ERR_INVALID_ARGUMENT;
  /* A scope on an address that cannot have one is a mistake worth reporting rather than dropping. */
  if (scope_id != 0UL) {
    /* A scope id means "on this interface", which only an address that is per-interface can carry:
     * fe80::/10 is link-local and ff02::/16 is link-local multicast, and every other address is
     * global, so a scope on one is a mistake worth reporting rather than dropping. */
    const uint8_t first = out->bytes[0];
    const uint8_t second = out->bytes[1];
    const int link_local = (first == 0xfeU && (second & 0xc0U) == 0x80U);
    const int multicast = (first == 0xffU && second == 0x02U);
    if (!link_local && !multicast) return WT_ERR_INVALID_ARGUMENT;
  }
  out->scope_id = (uint32_t)scope_id;
  out->port = port;
  return WT_OK;
}

wt_status_t wt_udp_address_parse_host_port(const char *text, wt_udp_address_t *out) {
  char host[64];
  const char *colon;
  const char *port_text;
  unsigned long port = 0UL;
  char *end = NULL;
  size_t host_len;
  wt_udp_address_t parsed;
  wt_status_t status;

  if (text == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  memset(out, 0, sizeof(*out));

  if (text[0] == '[') {
    /* An IPv6 literal is bracketed because a colon means the port and is also part of the address. */
    const char *close = strchr(text, ']');
    if (close == NULL) return WT_ERR_INVALID_ARGUMENT;
    host_len = (size_t)(close - text - 1);
    if (host_len == 0U || host_len >= sizeof(host)) return WT_ERR_INVALID_ARGUMENT;
    memcpy(host, text + 1, host_len);
    host[host_len] = '\0';
    if (close[1] != ':') return WT_ERR_INVALID_ARGUMENT;
    port_text = close + 2;
  } else {
    colon = strrchr(text, ':');
    if (colon == NULL) return WT_ERR_INVALID_ARGUMENT;
    host_len = (size_t)(colon - text);
    if (host_len == 0U || host_len >= sizeof(host)) return WT_ERR_INVALID_ARGUMENT;
    memcpy(host, text, host_len);
    host[host_len] = '\0';
    if (strchr(host, ':') != NULL) {
      /* An unbracketed address with more than one colon is ambiguous, and guessing which colon is the
       * port is how "[::1]:443" becomes an address nobody meant. */
      return WT_ERR_INVALID_ARGUMENT;
    }
    port_text = colon + 1;
  }

  errno = 0;
  port = strtoul(port_text, &end, 10);
  if (end == port_text || *end != '\0' || errno != 0 || port > WT_UDP_MAX_PORT) {
    return WT_ERR_INVALID_ARGUMENT;
  }

  status = wt_udp_address_parse(host, (uint16_t)port, &parsed);
  if (status != WT_OK) return status;
  *out = parsed;
  return WT_OK;
}

size_t wt_udp_address_format(const wt_udp_address_t *address, char *out, size_t capacity) {
  char host[64];
  char text[80];
  int written;
  size_t length;

  if (address == NULL) return 0U;
  if (capacity != 0U && out != NULL) out[0] = '\0';

  if (address->family == WT_UDP_IPV4) {
    if (wt_udp_platform_format_address(AF_INET, address->bytes, host, sizeof(host)) == 0U) return 0U;
    written = snprintf(text, sizeof(text), "%s:%u", host, (unsigned int)address->port);
  } else if (address->family == WT_UDP_IPV6) {
    if (wt_udp_platform_format_address(AF_INET6, address->bytes, host, sizeof(host)) == 0U) return 0U;
    if (address->scope_id != 0U) {
      written = snprintf(text, sizeof(text), "[%s%%%u]:%u", host, (unsigned int)address->scope_id,
                         (unsigned int)address->port);
    } else {
      written = snprintf(text, sizeof(text), "[%s]:%u", host, (unsigned int)address->port);
    }
  } else {
    return 0U;
  }
  if (written < 0) return 0U;
  length = (size_t)written;
  if (out == NULL || capacity == 0U) return length;
  /* snprintf truncates safely, and the terminator is written even when the address does not fit, which
   * is what the header promises. */
  (void)snprintf(out, capacity, "%s", text);
  return length;
}
