/* The five things about a socket that differ between platforms (WT-134).
 *
 * This header is private, and it exists so that `udp.c` names ONE operation per platform difference instead of
 * spelling POSIX in a dozen places: closing, non-blocking mode, waiting for readability, the error number, the
 * invalid handle, and the datagram calls themselves. The inventory of everything a port needs is `docs/PORTABILITY.md`, and
 * `scripts/check-portability.sh` keeps that document complete.
 *
 * The POSIX side is what this project builds and tests today. The `_WIN32` side is compiled by the cross-compile
 * in CI and is now RUN: `scripts/check-windows-wine.sh` executes the linked test binaries under Wine, which is
 * how `WT-199` and `WT-200` were found. It is still not verified on Windows ITSELF -- Wine is a faithful Win32
 * implementation, not Windows -- so what Wine does not settle is recorded rather than claimed.
 */

#ifndef WEBTRANSPORT_RUNTIME_UDP_PLATFORM_H
#define WEBTRANSPORT_RUNTIME_UDP_PLATFORM_H

#include "webtransport/runtime/udp.h"

#if defined(_WIN32)

/* Compiled by `scripts/check-windows-platform.sh`, and RUN by `scripts/check-windows-wine.sh`. */
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
/* `WSARecvMsg`, its `LPFN_WSARECVMSG` prototype, and the GUID that reaches it: the Windows recvmsg, and the
 * only call that answers the sender, the datagram's own length and its truncation flag at once. The protection
 * that stopped a header being written by hand here is `WT-199` -- see the receive function below. */
#include <mswsock.h>

typedef SOCKET wt_udp_handle_t;
/* Windows' socket calls take an `int` length, not a `socklen_t`: naming it here is the whole difference. */
typedef int wt_udp_socklen_t;
/* `inet_ntop`'s last argument is a `socklen_t` on POSIX and a `size_t` on Windows: two names for "how much room
 * is there", and the cross-compile is what noticed the difference. */
typedef size_t wt_udp_ntop_length_t;
#define WT_UDP_INVALID_HANDLE INVALID_SOCKET

#else

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

typedef int wt_udp_handle_t;
typedef socklen_t wt_udp_socklen_t;
typedef socklen_t wt_udp_ntop_length_t;
#define WT_UDP_INVALID_HANDLE (-1)

#endif


/* The datagram calls, which differ in more than a name: a platform's way of receiving one datagram WITH its
 * sender and its truncation flag. The structure is hoisted above both branches because it is the shape the two
 * sides share, and only the CALLS differ -- which is why the handle it names is defined above it.
 *
 * `flags_in` asks for behaviour, `flags_out` reports what happened:
 *
 *   WT_UDP_PLATFORM_PEEK         leave the datagram in the queue (POSIX MSG_PEEK)
 *   WT_UDP_PLATFORM_FULL_LENGTH  report the datagram's own length, not the copied one (POSIX MSG_TRUNC as an
 *                                input flag). On Windows a peek cannot see past the buffer, so this cannot be
 *                                honoured and `bytes_out` is what was copied -- which is why the portability
 *                                document says a Windows listener must HOLD the datagram it looked at
 *   WT_UDP_PLATFORM_TRUNCATED    reported: the datagram was longer than the buffer
 */
typedef struct wt_udp_platform_message {
  void *bytes;
  size_t capacity;
  struct sockaddr_storage *address;
  int *address_length;
  int flags_in;
  int flags_out;
  size_t bytes_out;
} wt_udp_platform_message_t;

#define WT_UDP_PLATFORM_PEEK ((int)0x01)
#define WT_UDP_PLATFORM_FULL_LENGTH ((int)0x02)
#define WT_UDP_PLATFORM_TRUNCATED ((int)0x04)

/* The two calls are defined below, once per branch, as `static` like the four above them: a prototype here
 * would have to be `static` too, and one that is not is the "static declaration follows non-static
 * declaration" error this file first produced. */

#if defined(_WIN32)

/* WSAStartup belongs to the socket lifetime, and this layer is the only place in the library that touches the
 * operating system at all: a reference count here means a caller cannot forget it, and cannot call it twice.
 * The count is the number of OPEN sockets, so the last close is what releases Winsock.
 *
 * ONE counter, at FILE scope, and that is the whole point of it being here: the first version declared
 * `static int open_sockets` inside EACH function, which is two distinct objects -- `release` decremented its
 * own zero and returned early, so `WSACleanup` was unreachable and the count documented above was fiction.
 * Both functions compiled, both looked right line by line, and only running the pair shows it. */
static int wt_udp_platform_open_sockets = 0;

static int wt_udp_platform_acquire(void) {
  if (wt_udp_platform_open_sockets == 0) {
    WSADATA data;
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return -1;
  }
  wt_udp_platform_open_sockets++;
  return 0;
}

static void wt_udp_platform_release(void) {
  if (wt_udp_platform_open_sockets == 0) return;
  wt_udp_platform_open_sockets--;
  if (wt_udp_platform_open_sockets == 0) (void)WSACleanup();
}

static int wt_udp_platform_close(wt_udp_handle_t handle) { return closesocket(handle); }

static int wt_udp_platform_set_nonblocking(wt_udp_handle_t handle) {
  u_long one = 1UL;
  /* `FIONBIO` is a `long` on Windows whose value does not fit a SIGNED long (0x8004667E > LONG_MAX), and mingw
   * says so: the cast is what the platform's own headers expect, and the cross-compile is what found it. */
  return ioctlsocket(handle, (long)FIONBIO, &one) == 0 ? 0 : -1;
}

/* WSAPoll has the same shape as poll, which is the one piece of luck in this port. */
static int wt_udp_platform_wait_readable(wt_udp_handle_t handle, int timeout_ms) {
  WSAPOLLFD entry;
  entry.fd = handle;
  entry.events = POLLRDNORM;
  entry.revents = 0;
  return WSAPoll(&entry, 1UL, timeout_ms);
}

static int wt_udp_platform_last_error(void) { return (int)WSAGetLastError(); }

static int wt_udp_platform_send_message(wt_udp_handle_t handle, const struct sockaddr *to, int to_length,
                                        const void *bytes, size_t length, size_t *out_written) {
  int written = sendto(handle, (const char *)bytes, (int)length, 0, to, to_length);
  if (written == SOCKET_ERROR) return -1;
  if (out_written != NULL) *out_written = (size_t)written;
  return 0;
}

/* `WSARecvMsg` is the Windows `recvmsg`, and it is the only call that answers all three questions this layer
 * has to answer at once: who sent the datagram, how long it really was, and whether it was longer than the
 * buffer.
 *
 * IT TAKES FIVE PARAMETERS, and the flags travel in the `WSAMSG` structure:
 *
 *   INT WSAAPI WSARecvMsg(SOCKET s, LPWSAMSG lpMsg, LPDWORD lpdwNumberOfBytesRecvd,
 *                         LPWSAOVERLAPPED lpOverlapped,
 *                         LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
 *
 * `MSG_PEEK` goes IN through `lpMsg->dwFlags`, and `MSG_TRUNC` comes back OUT through the same member. The
 * first version of this function declared a SIX-parameter signature with an `lpdwFlags` argument -- the shape
 * `WSASendMsg` has, whose third parameter really is a `dwFlags` -- and called the provider with `&flags` in
 * the `lpOverlapped` position. Nothing compiled could see it, because the declaration was this file's own; a
 * RUN is what showed it, and `tests/windows/probe-recvmsg-arity.c` is the measurement -- kept in the tree so
 * the claim can be re-run rather than believed: against one provider,
 * the documented call receives 9 bytes with the sender filled, and the six-parameter call fails with
 * `WSAENOTSOCK` and consumes nothing.
 *
 * The lesson is the declaration rather than the arity: `mswsock.h` already declares this function as
 * `LPFN_WSARECVMSG`, so this file USES that typedef and does not write its own. A hand-copied prototype of
 * somebody else's ABI is a claim the compiler cannot check -- it only checks that the call matches the copy.
 *
 * The function is not exported by name: Windows reaches it through `WSAIoctl` with
 * `SIO_GET_EXTENSION_FUNCTION_POINTER` and `WSAID_WSARECVMSG`. The pointer is a property of the provider
 * rather than of the socket, so fetching it once is enough -- and a provider that does not have it is a real
 * case rather than a hypothetical one, because the extension is optional.
 * `wt_udp_platform_recvfrom_message` below answers the call there; it is a FALLBACK and not the
 * implementation, and what it cannot do is written down beside it. */
static int wt_udp_platform_recvfrom_message(wt_udp_handle_t handle, wt_udp_platform_message_t *message);

/* Whether a handle is a live socket. The two failures this layer reads as "this provider has no usable
 * `WSARecvMsg`" -- an `WSAIoctl` that cannot name the extension, and a `WSARecvMsg` that answers
 * `WSAENOTSOCK` -- are also exactly what a CLOSED handle answers, and the difference is worth one call: the
 * first is a property of the provider and is remembered for the process, while the second is the caller's own
 * error and is reported as it stands. */
static int wt_udp_platform_handle_is_socket(wt_udp_handle_t handle) {
  int type = 0;
  int length = (int)sizeof(type);
  return getsockopt(handle, SOL_SOCKET, SO_TYPE, (char *)&type, &length) == 0;
}

static int wt_udp_platform_receive_message(wt_udp_handle_t handle, wt_udp_platform_message_t *message) {
  static LPFN_WSARECVMSG receive_message = NULL;
  /* Latched rather than re-probed per call: the extension belongs to the provider, so one refusal is the answer
   * for every socket this process opens. The two states are "not looked up yet" (a NULL pointer with `unusable`
   * clear) and "unusable", and either failure leads to the fallback. */
  static int unusable = 0;
  WSABUF buffer;
  WSAMSG msg;
  DWORD received = 0;
  int peek;

  if (!unusable && receive_message == NULL) {
    GUID guid = WSAID_WSARECVMSG;
    DWORD bytes = 0;
    if (WSAIoctl(handle, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, (DWORD)sizeof(guid), &receive_message,
                 (DWORD)sizeof(receive_message), &bytes, NULL, NULL) == SOCKET_ERROR) {
      if (!wt_udp_platform_handle_is_socket(handle)) return -1;
      unusable = 1;
    }
  }
  if (unusable) return wt_udp_platform_recvfrom_message(handle, message);

  peek = (message->flags_in & WT_UDP_PLATFORM_PEEK) != 0;
  buffer.buf = (char *)message->bytes;
  buffer.len = (ULONG)message->capacity;
  memset(&msg, 0, sizeof(msg));
  msg.name = (struct sockaddr *)(void *)message->address;
  msg.namelen = (message->address != NULL && message->address_length != NULL)
                    ? (INT)(*message->address_length)
                    : (INT)0;
  msg.lpBuffers = &buffer;
  msg.dwBufferCount = 1;
  /* The INPUT flag, in the structure where the documented prototype puts it. There is no `MSG_TRUNC` to ASK
   * with on this platform: a Windows peek cannot see past the caller's buffer, which is the
   * `WT_UDP_PLATFORM_FULL_LENGTH` difference `docs/PORTABILITY.md` records. */
  if (peek) msg.dwFlags = MSG_PEEK;

  if (receive_message(handle, &msg, &received, NULL, NULL) == 0) {
    if (message->address_length != NULL && msg.namelen > 0) *message->address_length = (int)msg.namelen;
    message->bytes_out = (size_t)received;
    message->flags_out = 0;
    /* The OUTPUT flag is authoritative, and that is what the guess it replaces could not be: a datagram that
     * exactly FILLS the buffer is not truncated, and `received == capacity` cannot tell the two apart. */
    if ((msg.dwFlags & MSG_TRUNC) != 0) message->flags_out |= WT_UDP_PLATFORM_TRUNCATED;
    return 0;
  }

  /* A datagram that does not fit FAILS here -- `WSAEMSGSIZE` -- rather than reporting a short count, and the
   * sender is filled on that path. It is the same shape the fallback sees, and it is why the truncation is
   * REPORTED rather than inferred (`WT-199`). */
  if (WSAGetLastError() == WSAEMSGSIZE) {
    if (message->address_length != NULL && msg.namelen > 0) *message->address_length = (int)msg.namelen;
    message->flags_out = WT_UDP_PLATFORM_TRUNCATED;
    /* The datagram's own length is not reported, so the buffer's is the honest floor: it filled it. */
    message->bytes_out = message->capacity;
    return 0;
  }

  /* A provider that rejects the CALL is a provider whose extension this layer cannot use, and that is not a
   * failure of this receive: the fallback answers it instead, and the provider is remembered. Everything else
   * keeps the platform's own error, because that is the caller's answer -- `WSAEWOULDBLOCK` is the common one,
   * and reading a timeout as "no extension here" would be the worse mistake. */
  {
    int error = WSAGetLastError();
    if (error != WSAENOTSOCK && error != WSAEOPNOTSUPP) return -1;
  }
  if (wt_udp_platform_handle_is_socket(handle)) unusable = 1;
  return wt_udp_platform_recvfrom_message(handle, message);
}

/* The fallback for a provider whose `WSARecvMsg` cannot be called, exercised by `tests/windows/test_windows_udp.c`
 * against a real pair of sockets rather than left to the machines that happen to lack the extension.
 *
 * `recvfrom` answers two of the three questions correctly, and the measurement that says so is
 * `tests/windows/probe-recvfrom.c`, kept in the tree so the claim can be re-run rather than believed: a datagram
 * that EXACTLY fills the buffer returns its full count with NO error (so a full buffer is not a truncation,
 * which is the case a "the buffer came back full, so it must have been truncated" guess gets wrong), and a
 * datagram that does not fit FAILS with `WSAEMSGSIZE` while still naming the sender in `from` and consuming the
 * datagram. Both halves of the contract therefore survive: the truncation is reported rather than inferred, and
 * the sender is reported for a datagram that is about to be discarded.
 *
 * The third question is the one it cannot answer: a PEEK cannot see past the buffer, so `bytes_out` is what
 * was copied rather than the datagram's own length and `WT_UDP_PLATFORM_FULL_LENGTH` is not honoured. That is
 * the documented Windows peek limitation, which is unchanged by this fallback. */
static int wt_udp_platform_recvfrom_message(wt_udp_handle_t handle, wt_udp_platform_message_t *message) {
  struct sockaddr_storage ignored;
  struct sockaddr *from = (struct sockaddr *)(void *)message->address;
  int from_length = (int)sizeof(struct sockaddr_storage);
  int flags = (message->flags_in & WT_UDP_PLATFORM_PEEK) != 0 ? MSG_PEEK : 0;
  int received;

  /* A caller that wants only the bytes passes no address -- `wt_udp_platform_message_t` allows it and POSIX's
   * `recvfrom` accepts `from == NULL`. WINDOWS DOES NOT: a NULL `from` with a non-NULL `fromlen` is WSAEFAULT, so
   * the same call that works on POSIX failed here with an error list that names the buffer rather than the
   * address. The NULL is replaced with a scratch address instead of being passed through, which is a fact about
   * the platform rather than about the caller. The native-Windows run found it: `test_windows_udp`'s one failing
   * check was a consume with no address, and the probe beside it showed the identical call succeeding WITH one. */
  if (from == NULL) {
    memset(&ignored, 0, sizeof(ignored));
    from = (struct sockaddr *)(void *)&ignored;
    from_length = (int)sizeof(ignored);
  } else if (message->address_length != NULL) {
    from_length = (int)(*message->address_length);
  }
  received = recvfrom(handle, (char *)message->bytes, (int)message->capacity, flags, from, &from_length);
  if (received == SOCKET_ERROR) {
    if (WSAGetLastError() != WSAEMSGSIZE) return -1;
    /* The datagram was longer than the buffer. It has been consumed unless this was a peek, and the sender is
     * filled either way, so both facts are reported: the caller decides what to do about a short packet. */
    message->flags_out = WT_UDP_PLATFORM_TRUNCATED;
    message->bytes_out = message->capacity;
  } else {
    message->flags_out = 0;
    message->bytes_out = (size_t)received;
  }
  if (message->address != NULL && message->address_length != NULL && from_length > 0) {
    *message->address_length = from_length;
  }
  return 0;
}

/* "IPv6 only", set rather than left to the platform's default. It is a helper because the option VALUE is a
 * pointer, and the two platforms declare that pointer differently: POSIX takes `const void *`, Windows
 * `const char *`. The cross-compile reported the incompatibility rather than letting it reach a compiler that
 * would have called it a warning. */
static int wt_udp_platform_set_v6_only(wt_udp_handle_t handle, int on) {
  return setsockopt(handle, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&on, (wt_udp_socklen_t)sizeof(on));
}

/* The ADDRESS conversions, which are the last place the two platforms disagree about TYPES rather than about
 * calls: `struct sockaddr_in`, `sockaddr_in6`, `htons`, `ntohs` and `inet_pton` have the same names on both
 * sides but the libraries that declare them do not, and the length type differs (`socklen_t` against `int`).
 * Everything below uses this library's own address type, so `udp.c` no longer includes a socket header or
 * names a constant from one (WT-134). */
static wt_status_t wt_udp_platform_address_to_storage(const wt_udp_address_t *address,
                                                      struct sockaddr_storage *out,
                                                      wt_udp_socklen_t *out_len) {
  memset(out, 0, sizeof(*out));
  if (address->family == WT_UDP_IPV4) {
    struct sockaddr_in *v4 = (struct sockaddr_in *)(void *)out;
    v4->sin_family = AF_INET;
    v4->sin_port = htons(address->port);
    memcpy(&v4->sin_addr, address->bytes, 4U);
    *out_len = (wt_udp_socklen_t)sizeof(*v4);
    return WT_OK;
  }
  if (address->family == WT_UDP_IPV6) {
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)(void *)out;
    v6->sin6_family = AF_INET6;
    v6->sin6_port = htons(address->port);
    memcpy(&v6->sin6_addr, address->bytes, 16U);
    v6->sin6_scope_id = address->scope_id;
    *out_len = (wt_udp_socklen_t)sizeof(*v6);
    return WT_OK;
  }
  return WT_ERR_INVALID_ARGUMENT;
}

static wt_status_t wt_udp_platform_address_from_storage(const struct sockaddr *from,
                                                        wt_udp_socklen_t from_len,
                                                        wt_udp_address_t *out) {
  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  memset(out, 0, sizeof(*out));
  if (from->sa_family == AF_INET) {
    const struct sockaddr_in *v4 = (const struct sockaddr_in *)(const void *)from;
    if (from_len < (wt_udp_socklen_t)sizeof(*v4)) return WT_ERR_INVALID_ARGUMENT;
    out->family = WT_UDP_IPV4;
    out->port = ntohs(v4->sin_port);
    memcpy(out->bytes, &v4->sin_addr, 4U);
    return WT_OK;
  }
  if (from->sa_family == AF_INET6) {
    const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)(const void *)from;
    if (from_len < (wt_udp_socklen_t)sizeof(*v6)) return WT_ERR_INVALID_ARGUMENT;
    out->family = WT_UDP_IPV6;
    out->port = ntohs(v6->sin6_port);
    memcpy(out->bytes, &v6->sin6_addr, 16U);
    out->scope_id = v6->sin6_scope_id;
    return WT_OK;
  }
  return WT_ERR_UNSUPPORTED;
}

static int wt_udp_platform_family_domain(wt_udp_family_t family) {
  return family == WT_UDP_IPV4 ? AF_INET : (family == WT_UDP_IPV6 ? AF_INET6 : -1);
}

/* `inet_pton` returns 1 for a parsed address, 0 for a malformed one and -1 for a family it does not know, and
 * the caller needs that distinction: a malformed literal is a caller's typo, an unknown family is a bug. */
static int wt_udp_platform_parse_address(const char *text, int domain, uint8_t *out_bytes) {
  return inet_pton(domain, text, out_bytes);
}

/* The Winsock numbers are a different integer space with the same meaning, and a few POSIX names have no
 * counterpart at all (`EHOSTDOWN`), which is why this cannot be one mapping with #ifs inside it: the
 * cross-compile of `udp.c` reported exactly that. */
static wt_status_t wt_udp_platform_status_of_error(int error) {
  switch (error) {
    case WSAEWOULDBLOCK:
    case WSAEINTR:
      return WT_ERR_AGAIN;
    case WSAEMSGSIZE:
      return WT_ERR_LIMIT;
    case WSAENOBUFS:
    case WSA_NOT_ENOUGH_MEMORY:
      return WT_ERR_OUT_OF_MEMORY;
    case WSAETIMEDOUT:
      return WT_ERR_TIMEOUT;
    case WSAECONNREFUSED:
    case WSAECONNRESET:
    case WSAENETUNREACH:
    case WSAEHOSTUNREACH:
    case WSAENETDOWN:
    case WSAEHOSTDOWN:
      return WT_ERR_CLOSED;
    case WSAEADDRINUSE:
    case WSAEADDRNOTAVAIL:
    case WSAEACCES:
      return WT_ERR_LIMIT;
    case WSAEAFNOSUPPORT:
    case WSAEPROTONOSUPPORT:
    case WSAEOPNOTSUPP:
      return WT_ERR_UNSUPPORTED;
    case WSAEISCONN:
    case WSAEALREADY:
    case WSAENOTCONN:
      return WT_ERR_STATE;
    case WSAEBADF:
    case WSAEINVAL:
    case WSAEDESTADDRREQ:
      return WT_ERR_INVALID_ARGUMENT;
    default:
      return WT_ERR_IO;
  }
}

/* The reverse: a printable address, for a log line. `inet_ntop` is the one name both platforms share, so this
 * exists only because `udp.c` must not include the header that declares it. Returns the text length, or 0 when
 * the family is not one this library carries. */
static size_t wt_udp_platform_format_address(int domain, const uint8_t *bytes, char *out, size_t capacity) {
  const char *written;
  size_t length;
  if (out == NULL || capacity == 0U) return 0U;
  out[0] = '\0';
  written = inet_ntop(domain, bytes, out, (wt_udp_ntop_length_t)capacity);
  if (written == NULL) {
    out[0] = '\0';
    return 0U;
  }
  length = strlen(out);
  return length;
}


#else

/* The POSIX side has nothing to start or stop: the two calls exist so that `udp.c` names one lifetime on
 * both platforms, and a no-op that says why is better than an `#if` at the call site. */
static int wt_udp_platform_acquire(void) { return 0; }

static void wt_udp_platform_release(void) {}

static int wt_udp_platform_close(wt_udp_handle_t handle) { return close(handle); }

static int wt_udp_platform_set_nonblocking(wt_udp_handle_t handle) {
  int flags = fcntl(handle, F_GETFL, 0);
  if (flags < 0) return -1;
  return fcntl(handle, F_SETFL, flags | O_NONBLOCK) < 0 ? -1 : 0;
}

static int wt_udp_platform_wait_readable(wt_udp_handle_t handle, int timeout_ms) {
  struct pollfd entry;
  entry.fd = handle;
  entry.events = POLLIN;
  entry.revents = 0;
  return poll(&entry, 1UL, timeout_ms);
}

static int wt_udp_platform_last_error(void) { return errno; }

static int wt_udp_platform_send_message(wt_udp_handle_t handle, const struct sockaddr *to, int to_length,
                                        const void *bytes, size_t length, size_t *out_written) {
  ssize_t written = sendto(handle, bytes, length, 0, to, (socklen_t)to_length);
  if (written < 0) return -1;
  if (out_written != NULL) *out_written = (size_t)written;
  return 0;
}

static int wt_udp_platform_receive_message(wt_udp_handle_t handle, wt_udp_platform_message_t *message) {
  struct iovec iov;
  struct msghdr msg;
  int flags = 0;
  ssize_t received;

  memset(&iov, 0, sizeof(iov));
  memset(&msg, 0, sizeof(msg));
  iov.iov_base = message->bytes;
  iov.iov_len = message->capacity;
  msg.msg_name = message->address;
  msg.msg_namelen = (message->address != NULL && message->address_length != NULL)
                        ? (socklen_t)*message->address_length
                        : (socklen_t)0;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  if ((message->flags_in & WT_UDP_PLATFORM_PEEK) != 0) flags |= MSG_PEEK;
  /* MSG_TRUNC as an INPUT flag asks for the datagram's own length; without it the count is what was copied.
   * Either way msg_flags reports whether the datagram was longer than the buffer, which is what keeps a
   * caller from parsing the prefix of a packet as if it were the packet (WT-36). */
  if ((message->flags_in & WT_UDP_PLATFORM_FULL_LENGTH) != 0) flags |= MSG_TRUNC;

  received = recvmsg(handle, &msg, flags);
  if (received < 0) return -1;
  message->bytes_out = (size_t)received;
  message->flags_out = 0;
  if ((msg.msg_flags & MSG_TRUNC) != 0) message->flags_out |= WT_UDP_PLATFORM_TRUNCATED;
  if (message->address_length != NULL) *message->address_length = (int)msg.msg_namelen;
  return 0;
}

/* "IPv6 only", set rather than left to the platform's default. It is a helper because the option VALUE is a
 * pointer, and the two platforms declare that pointer differently: POSIX takes `const void *`, Windows
 * `const char *`. The cross-compile reported the incompatibility rather than letting it reach a compiler that
 * would have called it a warning. */
static int wt_udp_platform_set_v6_only(wt_udp_handle_t handle, int on) {
  return setsockopt(handle, IPPROTO_IPV6, IPV6_V6ONLY, &on, (wt_udp_socklen_t)sizeof(on));
}

/* The ADDRESS conversions, which are the last place the two platforms disagree about TYPES rather than about
 * calls: `struct sockaddr_in`, `sockaddr_in6`, `htons`, `ntohs` and `inet_pton` have the same names on both
 * sides but the libraries that declare them do not, and the length type differs (`socklen_t` against `int`).
 * Everything below uses this library's own address type, so `udp.c` no longer includes a socket header or
 * names a constant from one (WT-134). */
static wt_status_t wt_udp_platform_address_to_storage(const wt_udp_address_t *address,
                                                      struct sockaddr_storage *out,
                                                      wt_udp_socklen_t *out_len) {
  memset(out, 0, sizeof(*out));
  if (address->family == WT_UDP_IPV4) {
    struct sockaddr_in *v4 = (struct sockaddr_in *)(void *)out;
    v4->sin_family = AF_INET;
    v4->sin_port = htons(address->port);
    memcpy(&v4->sin_addr, address->bytes, 4U);
    *out_len = (wt_udp_socklen_t)sizeof(*v4);
    return WT_OK;
  }
  if (address->family == WT_UDP_IPV6) {
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)(void *)out;
    v6->sin6_family = AF_INET6;
    v6->sin6_port = htons(address->port);
    memcpy(&v6->sin6_addr, address->bytes, 16U);
    v6->sin6_scope_id = address->scope_id;
    *out_len = (wt_udp_socklen_t)sizeof(*v6);
    return WT_OK;
  }
  return WT_ERR_INVALID_ARGUMENT;
}

static wt_status_t wt_udp_platform_address_from_storage(const struct sockaddr *from,
                                                        wt_udp_socklen_t from_len,
                                                        wt_udp_address_t *out) {
  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  memset(out, 0, sizeof(*out));
  if (from->sa_family == AF_INET) {
    const struct sockaddr_in *v4 = (const struct sockaddr_in *)(const void *)from;
    if (from_len < (wt_udp_socklen_t)sizeof(*v4)) return WT_ERR_INVALID_ARGUMENT;
    out->family = WT_UDP_IPV4;
    out->port = ntohs(v4->sin_port);
    memcpy(out->bytes, &v4->sin_addr, 4U);
    return WT_OK;
  }
  if (from->sa_family == AF_INET6) {
    const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)(const void *)from;
    if (from_len < (wt_udp_socklen_t)sizeof(*v6)) return WT_ERR_INVALID_ARGUMENT;
    out->family = WT_UDP_IPV6;
    out->port = ntohs(v6->sin6_port);
    memcpy(out->bytes, &v6->sin6_addr, 16U);
    out->scope_id = v6->sin6_scope_id;
    return WT_OK;
  }
  return WT_ERR_UNSUPPORTED;
}

static int wt_udp_platform_family_domain(wt_udp_family_t family) {
  return family == WT_UDP_IPV4 ? AF_INET : (family == WT_UDP_IPV6 ? AF_INET6 : -1);
}

/* `inet_pton` returns 1 for a parsed address, 0 for a malformed one and -1 for a family it does not know, and
 * the caller needs that distinction: a malformed literal is a caller's typo, an unknown family is a bug. */
static int wt_udp_platform_parse_address(const char *text, int domain, uint8_t *out_bytes) {
  return inet_pton(domain, text, out_bytes);
}

/* The platform's error NUMBER is not enough: `EAGAIN` and `WSAEWOULDBLOCK` are not the same integer, and the
 * CLASSES a QUIC runtime branches on -- retry, dead path, limit, unsupported -- are what this file has to
 * produce. So the classification lives beside the number, one implementation per platform, and `udp.c` names
 * one call. The mapping stays narrow on purpose: a failure it cannot classify is WT_ERR_IO rather than a guess,
 * because a caller that reads "limit" or "closed" acts on it. */
static wt_status_t wt_udp_platform_status_of_error(int error) {
  switch (error) {
    case EAGAIN:
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
    case EWOULDBLOCK:
#endif
    case EINTR:
      return WT_ERR_AGAIN;
    case EMSGSIZE:
      return WT_ERR_LIMIT;
    case ENOBUFS:
    case ENOMEM:
      return WT_ERR_OUT_OF_MEMORY;
    case ETIMEDOUT:
      return WT_ERR_TIMEOUT;
    case ECONNREFUSED:
    /* `ECONNRESET` belongs here because the Windows branch maps `WSAECONNRESET` to the same status: a reset
     * reported to a connected UDP socket is the same network event on both platforms, and a caller that
     * classified it as a generic IO failure here would see the platform change the meaning of its own error. */
    case ECONNRESET:
    case ENETUNREACH:
    case EHOSTUNREACH:
    case ENETDOWN:
    case EHOSTDOWN:
      return WT_ERR_CLOSED;
    case EADDRINUSE:
    case EADDRNOTAVAIL:
    case EACCES:
    case EPERM:
      return WT_ERR_LIMIT;
    case EAFNOSUPPORT:
    case EPROTONOSUPPORT:
    case EOPNOTSUPP:
      return WT_ERR_UNSUPPORTED;
    case EISCONN:
    case EALREADY:
    case ENOTCONN:
      return WT_ERR_STATE;
    case EBADF:
    case EINVAL:
    case EDESTADDRREQ:
      return WT_ERR_INVALID_ARGUMENT;
    default:
      return WT_ERR_IO;
  }
}

/* The reverse: a printable address, for a log line. `inet_ntop` is the one name both platforms share, so this
 * exists only because `udp.c` must not include the header that declares it. Returns the text length, or 0 when
 * the family is not one this library carries. */
static size_t wt_udp_platform_format_address(int domain, const uint8_t *bytes, char *out, size_t capacity) {
  const char *written;
  size_t length;
  if (out == NULL || capacity == 0U) return 0U;
  out[0] = '\0';
  written = inet_ntop(domain, bytes, out, (wt_udp_ntop_length_t)capacity);
  if (written == NULL) {
    out[0] = '\0';
    return 0U;
  }
  length = strlen(out);
  return length;
}

#endif


#endif /* WEBTRANSPORT_RUNTIME_UDP_PLATFORM_H */
