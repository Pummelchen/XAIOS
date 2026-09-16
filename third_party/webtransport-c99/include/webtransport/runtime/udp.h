/*
 * The UDP socket surface: RFC 768's datagram, on IPv4 and IPv6, for the QUIC runtime.
 *
 * WHAT THIS FILE IS AND IS NOT. It moves whole datagrams between two addresses and nothing else: no
 * connection state, no retransmission, no timers beyond a wait, and no knowledge of QUIC. The
 * connection runtime drives it, which is why a failure is reported as a status rather than by closing
 * anything, and why nothing here blocks an event loop for longer than the caller asked.
 *
 * IT IS THE ONE POSIX PART OF THE TREE (WT-13): C99 has no sockets, so this is the file where the
 * platform enters, and the feature-test macro is set by the build for exactly that reason (see
 * cmake/WTCompilerWarnings.cmake). Nothing above this layer may include <sys/socket.h>, and no
 * `errno` reaches a caller: every failure is classified in one place, `map_errno`, so that a caller
 * can act on WT_ERR_AGAIN or WT_ERR_LIMIT without knowing which platform produced it.
 *
 * DATAGRAM TRUNCATION IS REPORTED, NOT HIDDEN (WT-36). A datagram larger than the caller's buffer is a
 * datagram this endpoint cannot act on -- QUIC parses packets out of it and a partial packet is a
 * different packet -- so it is WT_ERR_TRUNCATED with nothing written to the length, while the peer's
 * address is still filled in, because "who sent the thing I could not receive" is the useful half of
 * the report. A caller that passes WT_UDP_MAX_DATAGRAM cannot be truncated at all.
 */

#ifndef WEBTRANSPORT_RUNTIME_UDP_H
#define WEBTRANSPORT_RUNTIME_UDP_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The largest UDP payload a datagram can carry on either family: 65535 minus the eight-byte UDP header
 * minus the twenty-byte IPv4 header, which is the smaller of the two families' bounds (IPv6 allows
 * twenty bytes more) and is therefore the size that always works. A receive buffer of this size cannot
 * be truncated, which is the only way to be sure (WT-36). */
#define WT_UDP_MAX_DATAGRAM 65507U

/* A sentinel for "wait until something arrives", for the rare case where a caller has no deadline --
 * a blocking CLI, for instance. It is not a duration and must not be added to one. */
#define WT_UDP_WAIT_FOREVER UINT64_MAX

/* The two families this layer carries. Deliberately not a copy of the platform's constants: the value
 * is this library's, and the socket layer is the only thing that translates it. */
typedef enum wt_udp_family {
  WT_UDP_IPV4 = 0,
  WT_UDP_IPV6 = 1
} wt_udp_family_t;

/* An address as the wire carries it: a family, sixteen bytes (four used for IPv4, all sixteen for
 * IPv6, both in network order), a port in host order, and an IPv6 scope id for a link-local address.
 *
 * The scope id is here because an address type that cannot express it silently drops the interface
 * from a link-local address, and two interfaces can carry the same fe80:: address: the scope is not
 * decoration, it is the difference between reaching the peer and reaching nobody. It is zero for
 * every other kind of address. */
typedef struct wt_udp_address {
  wt_udp_family_t family;
  uint16_t port;
  uint32_t scope_id;
  uint8_t bytes[16];
} wt_udp_address_t;

/* The value `fd` holds when there is no open socket. It is spelled once because the two platforms disagree
 * about what a valid handle looks like -- POSIX uses a small non-negative int, Windows a pointer-sized
 * SOCKET whose invalid value is all ones -- and `(intptr_t)-1` is that value on both. */
#define WT_UDP_INVALID_FD ((intptr_t)-1)

/* An open socket. `fd` is exposed because an event loop that already has a poll set wants to add it,
 * and hiding it would mean either a second poll set or a callback API this library does not need.
 *
 * It is `intptr_t` rather than `int` because a Windows SOCKET is a pointer-sized handle (WT-134): an `int`
 * field would truncate it, and the truncation would be silent until a socket handle happened to be large.
 * On POSIX the value is the small descriptor it always was, so this is a widening of the field and not a
 * change of meaning. */
typedef struct wt_udp_socket {
  intptr_t fd;
  wt_udp_family_t family;
  uint16_t port;
} wt_udp_socket_t;

/* Make a socket for one family, non-blocking, and set it up so that an IPv6 socket carries IPv6 and
 * not a second way to reach IPv4 (IPV6_V6ONLY is set explicitly rather than left to the platform's
 * default, which differs between Linux and the BSDs). An IPv4 address therefore needs an IPv4 socket,
 * which is what a caller that knows the family wants anyway. */
wt_status_t wt_udp_socket_open(wt_udp_socket_t *out, wt_udp_family_t family);

/* Bind to `address`. A port of zero asks the system for one, which `wt_udp_local_port` reports. */
wt_status_t wt_udp_bind(wt_udp_socket_t *socket, const wt_udp_address_t *address);

/* Bind to the loopback address of the socket's family on `port` (zero for any), and report the port
 * that was bound. This is what a test and a local client need, and it is here rather than in the test
 * so that the address construction -- 127.0.0.1 or ::1 -- is written once. */
wt_status_t wt_udp_bind_loopback(wt_udp_socket_t *socket, uint16_t port, uint16_t *out_port);

/* The port the socket is bound to, which is only interesting when zero was asked for. */
wt_status_t wt_udp_local_port(const wt_udp_socket_t *socket, uint16_t *out_port);

/* Close it. Idempotent, and safe on a socket that was never opened: a connection that fails to
 * establish must not leak a descriptor, and "close what you have" is the caller's cleanup path. */
void wt_udp_close(wt_udp_socket_t *socket);

/* Send one datagram. WT_ERR_AGAIN when the send buffer is full, which is not a failure and is what a
 * non-blocking caller retries; WT_ERR_LIMIT when the datagram is larger than UDP can carry or the
 * kernel refuses it as too big. A zero-length datagram is legal in UDP and is sent. */
wt_status_t wt_udp_send(const wt_udp_socket_t *socket, const wt_udp_address_t *to,
                        const uint8_t *data, size_t length);

/* Receive one datagram. WT_ERR_AGAIN when none is waiting.
 *
 * On WT_ERR_TRUNCATED the datagram was larger than `capacity`: the bytes in the buffer are its prefix
 * and NOT the datagram, so `out_length` is left at zero and the caller must discard it rather than
 * parse it -- a QUIC packet cut in half is a different packet, and acting on one is how a truncation
 * becomes a parsing bug. `out_from` is filled anyway, because the sender is known and is what a
 * diagnostic needs. */
wt_status_t wt_udp_receive(const wt_udp_socket_t *socket, uint8_t *buffer, size_t capacity,
                           size_t *out_length, wt_udp_address_t *out_from);

/* Wait until the socket has something to read, or `timeout_micros` passes.
 *
 * WT_OK means readable and WT_ERR_TIMEOUT means the wait ended with nothing; a timeout is not an error
 * in an event loop, and it is reported as a status rather than as an out-parameter so that a caller
 * cannot forget to check it. The wait is on POLLERR and POLLHUP as well, because a socket in that
 * state has a pending error and the way to learn it is to attempt the receive. */
wt_status_t wt_udp_wait(const wt_udp_socket_t *socket, uint64_t timeout_micros);

/* Look at the next datagram WITHOUT taking it: the bytes and the sender are reported and the packet stays in
 * the socket's queue for a later `wt_udp_receive`. A listener needs exactly this, and nothing narrower will do:
 * a connection has to be armed with the peer's address before it can process the packet that names the peer, so
 * a caller that CONSUMED that packet would have to wait for a retransmission -- and a peer that had already
 * given up would never send one.
 *
 * `out_available` is always how many of the datagram's bytes are in `buffer`, never more than `capacity`.
 * `out_length` is the datagram's OWN length where the platform can report it and the copied count where it
 * cannot, and WHICH PLATFORM THAT IS belongs to this contract rather than to the implementation:
 *
 *   - Linux honours `MSG_TRUNC` as an INPUT flag to `recvmsg`, so a 2000-byte datagram peeked into a 100-byte
 *     buffer reports `out_length = 2000` and `out_available = 100`;
 *   - macOS, the BSDs and Windows treat it as an OUTPUT flag only, so a peek cannot see past the caller's
 *     buffer: the same datagram reports `out_length = 100` and `out_available = 100`, which is byte-identical
 *     to a whole 100-byte datagram.
 *
 * A caller that needs the whole datagram therefore SIZES ITS BUFFER for the largest datagram it accepts, or
 * receives rather than peeks: on the second group of platforms `out_length` is a floor rather than a
 * measurement. The limitation is the one `docs/PORTABILITY.md` records for Windows, and it is not Windows-only,
 * which is why `tests/unit/test_runtime_udp.c` asserts the invariants that hold everywhere -- a datagram that
 * does not fit reports `out_available == capacity` and `out_length >= out_available`, and it is still in the
 * queue afterwards -- rather than a value that differs by platform.
 *
 * Both out-parameters are zeroed before the call and on every failure, like `wt_udp_receive`'s. */
wt_status_t wt_udp_peek(const wt_udp_socket_t *socket, uint8_t *buffer, size_t capacity,
                        size_t *out_length, size_t *out_available, wt_udp_address_t *out_from);

/* Parse a numeric address: "127.0.0.1", "::1", "fe80::1%4". No name resolution -- that is a policy
 * decision with a resolver, a timeout and a platform API behind it, and QUIC's own address handling is
 * numeric. Returns WT_ERR_INVALID_ARGUMENT for anything else. */
wt_status_t wt_udp_address_parse(const char *text, uint16_t port, wt_udp_address_t *out);

/* Parse a "host:port" pair, with an IPv6 literal in brackets ("[::1]:443") and a port that must be
 * present. Here rather than in a CLI so that the bracket rule -- a colon is a port separator and also
 * half of an IPv6 address -- is written once. */
wt_status_t wt_udp_address_parse_host_port(const char *text, wt_udp_address_t *out);

/* Write the address as text and return the number of characters it needs, excluding the terminator,
 * whether or not it fitted -- exactly what snprintf returns, so a caller can size a buffer by calling
 * this with a short one. `out` is always terminated when `capacity` is not zero, and zero is returned
 * for a family this type does not carry. The port is included, and an IPv6 address with a scope id is
 * "[fe80::1%4]:443". */
size_t wt_udp_address_format(const wt_udp_address_t *address, char *out, size_t capacity);

/* Whether two addresses are the same address: family, bytes, scope and port. */
int wt_udp_address_equal(const wt_udp_address_t *a, const wt_udp_address_t *b);

/* The canonical BYTE form of an address: family, sixteen address bytes, port and scope id, all big endian where
 * they are numbers, always the same length (`WT_UDP_ADDRESS_ENCODED_LENGTH`). It exists for the places that have
 * to bind a value to "this peer" without keeping the struct: a Retry token hashes it (WT-168), and a comparison
 * of two encodings is the same answer as `wt_udp_address_equal` while being something a hash can be taken of.
 *
 * Both IPv4 and IPv6 encode to the full sixteen bytes, so the family byte is what tells them apart -- an IPv4
 * address that happened to look like a truncated IPv6 one cannot collide. */
#define WT_UDP_ADDRESS_ENCODED_LENGTH 23U
size_t wt_udp_address_encode(const wt_udp_address_t *address, uint8_t *out, size_t capacity);

/* The loopback address of a family, port zero. */
void wt_udp_address_loopback(wt_udp_family_t family, wt_udp_address_t *out);

/* "ipv4" or "ipv6". Never NULL. */
const char *wt_udp_family_name(wt_udp_family_t family);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_RUNTIME_UDP_H */
