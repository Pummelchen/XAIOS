/*
 * The XAIOS platform seam for the vendored WebTransport C99 library (B-131).
 *
 * The upstream library keeps every operating-system difference behind
 * `src/runtime/udp_platform.h`, but that header is a POSIX branch: it includes
 * `<sys/socket.h>` and friends and implements the seam over them. XAIOS has no
 * BSD socket layer -- it has `NET_OPEN_UDP`, `NET_SEND`, `NET_RECV` and
 * `WAIT_EVENTS` -- so the seam is supplied from here instead.
 *
 * It is supplied *from here* rather than by editing upstream because the
 * vendored tree is hash-pinned (`check-webtransport-vendor.py`), and that is
 * worth keeping: an upstream copy that quietly diverges is no longer evidence
 * of anything. The build therefore compiles the upstream sources with
 *
 *     -DWEBTRANSPORT_RUNTIME_UDP_PLATFORM_H
 *     -include userspace/wt/xaios/wt_xaios_platform.h
 *
 * which makes the vendored header's body inert (its include guard is already
 * defined) and puts this header, and the definitions in
 * `wt_xaios_platform.c`, in its place. Nothing in `udp.c` changes: it still
 * calls `socket`, `bind`, `getsockname` and the private `wt_udp_platform_*`
 * operations, and this file provides exactly those.
 *
 * Two XAIOS facts shape the implementation, and both are in the `.c`:
 *
 * **Opening a UDP socket and binding it are one syscall.** `NET_OPEN_UDP`
 * takes the port and reports the port it bound, so the POSIX `socket()` then
 * `bind()` sequence cannot be two syscalls. Handles handed out here are small
 * indices into a table, and the kernel descriptor is created when the port is
 * first known -- at `bind()` for a listener, at first use for a client.
 *
 * **There is no `MSG_PEEK`.** The library peeks a datagram and leaves it for
 * the connection's own receive, so the seam keeps a one-datagram stash per
 * socket and serves the next receive from it.
 */

#ifndef XAIOS_WT_XAIOS_PLATFORM_H
#define XAIOS_WT_XAIOS_PLATFORM_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include "webtransport/runtime/udp.h"

/* The BSD shapes `udp.c` still names. Only the family constants have to agree
   with the ones this header hands back from `wt_udp_platform_family_domain`,
   because the two never leave this pair of files. */
#define AF_INET 2
#define AF_INET6 10
#define SOCK_DGRAM 2

/* `udp.c` builds one of these and passes only its descriptor on, so the shape
   is all that is needed -- there is no `poll()` in this port. */
struct pollfd {
  int fd;
  short events;
  short revents;
};
#define POLLIN 0x001

struct sockaddr {
  unsigned short sa_family;
  char sa_data[14];
};

/* What the conversions below fill and read. `udp.c` only ever treats it as an
   opaque 128-byte buffer, so its layout is this port's business; the fields
   are named instead of raw because the port is the only reader. */
struct sockaddr_storage {
  unsigned short ss_family;
  unsigned short ss_port;
  unsigned int ss_scope;
  unsigned char ss_bytes[16];
  unsigned char ss_pad[104];
};

typedef int wt_udp_handle_t;
typedef unsigned int wt_udp_socklen_t;
typedef unsigned int wt_udp_ntop_length_t;
#define WT_UDP_INVALID_HANDLE (-1)

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

/* The socket calls `udp.c` makes directly. They are not BSD: they are the
   three operations this port can express, over the handle table above. */
int socket(int domain, int type, int protocol);
int bind(int handle, const struct sockaddr *address, wt_udp_socklen_t length);
int getsockname(int handle, struct sockaddr *address,
                wt_udp_socklen_t *length);

/* The library's own platform operations, one per difference. */
int wt_udp_platform_acquire(void);
void wt_udp_platform_release(void);
int wt_udp_platform_close(wt_udp_handle_t handle);
int wt_udp_platform_set_nonblocking(wt_udp_handle_t handle);
int wt_udp_platform_wait_readable(wt_udp_handle_t handle, int timeout_ms);
int wt_udp_platform_last_error(void);
int wt_udp_platform_set_v6_only(wt_udp_handle_t handle, int on);
int wt_udp_platform_send_message(wt_udp_handle_t handle,
                                 const struct sockaddr *to, int to_length,
                                 const uint8_t *data, size_t length,
                                 size_t *written);
int wt_udp_platform_receive_message(wt_udp_handle_t handle,
                                    wt_udp_platform_message_t *message);
wt_status_t wt_udp_platform_address_to_storage(
    const wt_udp_address_t *address, struct sockaddr_storage *storage,
    wt_udp_socklen_t *length);
wt_status_t wt_udp_platform_address_from_storage(
    const struct sockaddr *from, wt_udp_socklen_t length,
    wt_udp_address_t *out);
int wt_udp_platform_family_domain(wt_udp_family_t family);
int wt_udp_platform_parse_address(const char *text, int domain,
                                  uint8_t *out_bytes);
wt_status_t wt_udp_platform_status_of_error(int error);
size_t wt_udp_platform_format_address(int domain, const uint8_t *bytes,
                                      char *out, size_t capacity);

#endif
