/*
 * The XAIOS side of the vendored WebTransport platform seam. The header,
 * `wt_xaios_platform.h`, says why this exists and how the build reaches it;
 * this file is the implementation, over the XAIOS UDP syscalls.
 */

#include "wt_xaios_platform.h"

#include <stdio.h>
#include <string.h>

#include <xaios_user.h>

#define WT_XAIOS_MAX_SOCKETS 8
#define WT_XAIOS_MAX_DATAGRAM 65507U
#define WT_XAIOS_MS_TO_NS UINT64_C(1000000)

/* What `wt_udp_platform_last_error` reports. The library never sees these
   numbers; it sees the `WT_ERR_*` that `status_of_error` maps them to. */
#define WT_XAIOS_ERROR_NONE 0
#define WT_XAIOS_ERROR_AGAIN 1
#define WT_XAIOS_ERROR_IO 2
#define WT_XAIOS_ERROR_LIMIT 3
#define WT_XAIOS_ERROR_INVALID 4
#define WT_XAIOS_ERROR_UNSUPPORTED 5

typedef struct wt_xaios_socket {
  int used;
  uint64_t descriptor; /* 0 until the kernel socket exists */
  uint16_t port;
  uint8_t family; /* 4 or 6, the kernel's spelling */
} wt_xaios_socket_t;

static wt_xaios_socket_t g_sockets[WT_XAIOS_MAX_SOCKETS];
static int g_last_error = WT_XAIOS_ERROR_NONE;

/* One datagram, held for the socket that peeked it. The library peeks and
   expects the datagram to still be there for the connection's own receive;
   XAIOS has no `MSG_PEEK`, so the seam keeps the datagram instead. One buffer
   rather than one per socket because the library is single-threaded, pumps one
   session at a time, and a per-socket 64 KiB buffer would be half a megabyte
   of BSS for a peek that happens once per received packet. */
static uint8_t g_stash[WT_XAIOS_MAX_DATAGRAM];
static struct sockaddr_storage g_stash_address;
static int g_stash_address_length;
static size_t g_stash_length;
static int g_stash_truncated;
static int g_stash_handle = -1;

static int family_to_kernel(int domain) { return domain == AF_INET6 ? 6 : 4; }

static int family_from_kernel(uint8_t family) {
  return family == 6 ? AF_INET6 : AF_INET;
}

static int family_to_domain(wt_udp_family_t family) {
  return family == WT_UDP_IPV6 ? AF_INET6 : AF_INET;
}

static wt_xaios_socket_t *slot_for(int handle) {
  if (handle < 0 || handle >= WT_XAIOS_MAX_SOCKETS) return NULL;
  if (g_sockets[handle].used == 0) return NULL;
  return &g_sockets[handle];
}

static int open_kernel_socket(wt_xaios_socket_t *slot, uint64_t port) {
  u64 descriptor = 0U;
  u64 bound = 0U;
  if (xaios_net_open_udp(port, &descriptor, &bound) != 0) {
    g_last_error = WT_XAIOS_ERROR_IO;
    return -1;
  }
  slot->descriptor = (uint64_t)descriptor;
  slot->port = (uint16_t)bound;
  return 0;
}

/* Open on first use. A client has no port to ask for, so the kernel chooses
   one; a listener went through `bind()` and already has its descriptor. */
static int ensure_open(wt_xaios_socket_t *slot) {
  if (slot->descriptor != 0U) return 0;
  return open_kernel_socket(slot, 0U);
}

static void fill_storage(struct sockaddr_storage *storage, uint8_t family,
                         const uint8_t *bytes, uint16_t port,
                         uint32_t scope) {
  size_t width = family == 6U ? 16U : 4U;
  memset(storage, 0, sizeof(*storage));
  storage->ss_family = (unsigned short)family_from_kernel(family);
  storage->ss_port = port;
  storage->ss_scope = scope;
  memcpy(storage->ss_bytes, bytes, width);
}

int socket(int domain, int type, int protocol) {
  (void)type;
  (void)protocol;
  for (int index = 0; index < WT_XAIOS_MAX_SOCKETS; ++index) {
    if (g_sockets[index].used == 0) {
      memset(&g_sockets[index], 0, sizeof(g_sockets[index]));
      g_sockets[index].used = 1;
      g_sockets[index].family = (uint8_t)family_to_kernel(domain);
      /* Deliberately no syscall here: XAIOS opens and binds in one call, and
         the library calls `socket()` before it knows the port. The descriptor
         is created at `bind()` or at first send. */
      return index;
    }
  }
  g_last_error = WT_XAIOS_ERROR_LIMIT;
  return -1;
}

int bind(int handle, const struct sockaddr *address, wt_udp_socklen_t length) {
  const struct sockaddr_storage *storage =
      (const struct sockaddr_storage *)(const void *)address;
  wt_xaios_socket_t *slot = slot_for(handle);
  if (length < sizeof(*storage) && length < 8U) {
    g_last_error = WT_XAIOS_ERROR_INVALID;
    return -1;
  }
  if (slot == NULL) {
    g_last_error = WT_XAIOS_ERROR_INVALID;
    return -1;
  }
  if (slot->descriptor != 0U) {
    (void)xaios_net_close(slot->descriptor);
    slot->descriptor = 0U;
  }
  slot->family =
      (uint8_t)family_to_kernel((int)storage->ss_family);
  return open_kernel_socket(slot, (uint64_t)storage->ss_port);
}

int getsockname(int handle, struct sockaddr *address,
                wt_udp_socklen_t *length) {
  wt_xaios_socket_t *slot = slot_for(handle);
  if (slot == NULL || address == NULL || length == NULL) {
    g_last_error = WT_XAIOS_ERROR_INVALID;
    return -1;
  }
  fill_storage((struct sockaddr_storage *)(void *)address, slot->family,
               (const uint8_t *)"", slot->port, 0U);
  *length = (wt_udp_socklen_t)sizeof(struct sockaddr_storage);
  return 0;
}

int wt_udp_platform_acquire(void) { return 0; }

void wt_udp_platform_release(void) {}

int wt_udp_platform_close(wt_udp_handle_t handle) {
  wt_xaios_socket_t *slot = slot_for(handle);
  if (slot == NULL) {
    g_last_error = WT_XAIOS_ERROR_INVALID;
    return -1;
  }
  if (slot->descriptor != 0U) {
    (void)xaios_net_close(slot->descriptor);
  }
  memset(slot, 0, sizeof(*slot));
  if (g_stash_handle == handle) {
    g_stash_handle = -1;
    g_stash_length = 0U;
    g_stash_truncated = 0;
  }
  return 0;
}

/* XAIOS datagram receives never block: an empty queue is `NET_RECV` returning
   success with nothing copied, which `receive_message` turns into the
   library's `WT_ERR_AGAIN`. There is nothing to set. */
int wt_udp_platform_set_nonblocking(wt_udp_handle_t handle) {
  (void)handle;
  return 0;
}

int wt_udp_platform_wait_readable(wt_udp_handle_t handle, int timeout_ms) {
  (void)handle;
  /* The wait is for the machine, not for this socket: XAIOS's event wait is
     what a syscall can do, and a caller that wakes for another socket simply
     finds this one empty and gets `WT_ERR_AGAIN`. A zero timeout is not a
     wait, so it reports readable and lets the receive decide. */
  if (timeout_ms <= 0) return 1;
  int ready = xaios_wait_events((u64)timeout_ms * WT_XAIOS_MS_TO_NS);
  if (ready < 0) {
    g_last_error = WT_XAIOS_ERROR_IO;
    return -1;
  }
  return ready > 0 ? 1 : 0;
}

int wt_udp_platform_last_error(void) { return g_last_error; }

/* XAIOS binds one family per socket, which is what the library asks for when
   it sets `IPV6_V6ONLY` on an IPv6 socket. There is nothing to set, and
   nothing to fail. */
int wt_udp_platform_set_v6_only(wt_udp_handle_t handle, int on) {
  (void)handle;
  (void)on;
  return 0;
}

int wt_udp_platform_send_message(wt_udp_handle_t handle,
                                 const struct sockaddr *to, int to_length,
                                 const uint8_t *data, size_t length,
                                 size_t *written) {
  const struct sockaddr_storage *storage =
      (const struct sockaddr_storage *)(const void *)to;
  wt_xaios_socket_t *slot = slot_for(handle);
  xaios_ip_addr_user_t destination;
  u64 sent = 0U;
  if (slot == NULL || written == NULL || to_length <= 0) {
    g_last_error = WT_XAIOS_ERROR_INVALID;
    return -1;
  }
  if (ensure_open(slot) != 0) return -1;
  memset(&destination, 0, sizeof(destination));
  destination.family = (unsigned char)family_to_kernel((int)storage->ss_family);
  memcpy(destination.addr, storage->ss_bytes, sizeof(destination.addr));
  if (xaios_net_sendto(slot->descriptor, data, (u64)length, &sent, &destination,
                       (u64)storage->ss_port) != 0) {
    g_last_error = WT_XAIOS_ERROR_IO;
    return -1;
  }
  *written = (size_t)sent;
  return 0;
}

/* Read one datagram into the stash, with its sender, so a peek and the
   receive that follows it see the same bytes. */
static int stash_one(wt_xaios_socket_t *slot, int handle) {
  xaios_ip_addr_user_t source;
  u64 received = 0U;
  memset(&source, 0, sizeof(source));
  if (xaios_net_recvfrom(slot->descriptor, g_stash, sizeof(g_stash),
                         &received, &source) != 0) {
    g_last_error = WT_XAIOS_ERROR_IO;
    return -1;
  }
  if (received == 0U) {
    /* An empty queue is not an error here: it is the library's AGAIN. */
    g_last_error = WT_XAIOS_ERROR_AGAIN;
    return -1;
  }
  g_stash_length = (size_t)received;
  g_stash_truncated = 0;
  g_stash_handle = handle;
  fill_storage(&g_stash_address, source.family, source.addr, 0U, 0U);
  g_stash_address_length = (int)sizeof(g_stash_address);
  return 0;
}

int wt_udp_platform_receive_message(wt_udp_handle_t handle,
                                    wt_udp_platform_message_t *message) {
  wt_xaios_socket_t *slot = slot_for(handle);
  size_t copied;
  if (slot == NULL || message == NULL || message->address == NULL ||
      message->address_length == NULL) {
    g_last_error = WT_XAIOS_ERROR_INVALID;
    return -1;
  }
  if (ensure_open(slot) != 0) return -1;
  if (g_stash_handle != handle) {
    if (stash_one(slot, handle) != 0) return -1;
  }
  copied = message->capacity < g_stash_length ? message->capacity
                                              : g_stash_length;
  if (copied != 0U && message->bytes != NULL) {
    memcpy(message->bytes, g_stash, copied);
  }
  message->bytes_out =
      (message->flags_in & WT_UDP_PLATFORM_FULL_LENGTH) != 0 ? g_stash_length
                                                             : copied;
  if (g_stash_truncated != 0 || copied < g_stash_length) {
    message->flags_out |= WT_UDP_PLATFORM_TRUNCATED;
  }
  *message->address = g_stash_address;
  *message->address_length = g_stash_address_length;
  /* A peek leaves the datagram where the caller will look for it; anything
     else consumes it. */
  if ((message->flags_in & WT_UDP_PLATFORM_PEEK) == 0) {
    g_stash_handle = -1;
    g_stash_length = 0U;
    g_stash_truncated = 0;
  }
  return 0;
}

wt_status_t wt_udp_platform_address_to_storage(
    const wt_udp_address_t *address, struct sockaddr_storage *storage,
    wt_udp_socklen_t *length) {
  if (address == NULL || storage == NULL || length == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  memset(storage, 0, sizeof(*storage));
  storage->ss_family =
      (unsigned short)family_to_domain(address->family);
  storage->ss_port = address->port;
  storage->ss_scope = address->scope_id;
  memcpy(storage->ss_bytes, address->bytes,
         address->family == WT_UDP_IPV6 ? 16U : 4U);
  *length = (wt_udp_socklen_t)sizeof(*storage);
  return WT_OK;
}

wt_status_t wt_udp_platform_address_from_storage(
    const struct sockaddr *from, wt_udp_socklen_t length,
    wt_udp_address_t *out) {
  const struct sockaddr_storage *storage =
      (const struct sockaddr_storage *)(const void *)from;
  if (from == NULL || out == NULL || length < 8U) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  memset(out, 0, sizeof(*out));
  if (storage->ss_family == AF_INET) {
    out->family = WT_UDP_IPV4;
    memcpy(out->bytes, storage->ss_bytes, 4U);
  } else if (storage->ss_family == AF_INET6) {
    out->family = WT_UDP_IPV6;
    memcpy(out->bytes, storage->ss_bytes, 16U);
  } else {
    return WT_ERR_UNSUPPORTED;
  }
  out->port = storage->ss_port;
  out->scope_id = storage->ss_scope;
  return WT_OK;
}

int wt_udp_platform_family_domain(wt_udp_family_t family) {
  return family_to_domain(family);
}

/* Numeric only, like the POSIX branch: this library does no name resolution,
   and the addresses it is handed are already literals. */
int wt_udp_platform_parse_address(const char *text, int domain,
                                  uint8_t *out_bytes) {
  if (text == NULL || out_bytes == NULL) return 0;
  if (domain == AF_INET) {
    unsigned values[4] = {0U, 0U, 0U, 0U};
    int field = 0;
    int digits = 0;
    for (const char *cursor = text;; ++cursor) {
      if (*cursor >= '0' && *cursor <= '9') {
        values[field] = values[field] * 10U + (unsigned)(*cursor - '0');
        if (values[field] > 255U || ++digits > 3) return 0;
        continue;
      }
      if (*cursor == '.' && field < 3 && digits > 0) {
        ++field;
        digits = 0;
        continue;
      }
      if (*cursor == '\0' && field == 3 && digits > 0) break;
      return 0;
    }
    for (int index = 0; index < 4; ++index) {
      out_bytes[index] = (uint8_t)values[index];
    }
    return 1;
  }
  if (domain == AF_INET6) {
    /* Colon-separated hexadecimal groups with one `::` run, which is every
       shape a literal takes here. A trailing IPv4-mapped form is not accepted
       because the library's address type reports it as a family it does not
       carry. */
    uint16_t groups[8] = {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U};
    int count = 0;
    int gap = -1;
    const char *cursor = text;
    if (*cursor == ':') {
      if (cursor[1] != ':') return 0;
      gap = 0;
      cursor += 2;
    }
    while (*cursor != '\0') {
      unsigned value = 0U;
      int digits = 0;
      while ((*cursor >= '0' && *cursor <= '9') ||
             (*cursor >= 'a' && *cursor <= 'f') ||
             (*cursor >= 'A' && *cursor <= 'F')) {
        unsigned digit = (unsigned)(*cursor >= 'a' ? *cursor - 'a' + 10
                                  : *cursor >= 'A' ? *cursor - 'A' + 10
                                                   : *cursor - '0');
        value = (value << 4U) | digit;
        if (++digits > 4) return 0;
        ++cursor;
      }
      if (digits == 0 || count >= 8) return 0;
      groups[count++] = (uint16_t)value;
      if (*cursor == '\0') break;
      if (*cursor != ':') return 0;
      ++cursor;
      if (*cursor == ':') {
        if (gap >= 0) return 0;
        gap = count;
        ++cursor;
        if (*cursor == '\0') break;
      }
    }
    if (gap < 0 && count != 8) return 0;
    {
      int tail = count - gap;
      for (int index = 0; index < 8; ++index) {
        uint16_t group;
        if (gap >= 0 && index >= gap && index < 8 - tail) {
          group = 0U;
        } else if (gap >= 0 && index >= 8 - tail) {
          group = groups[gap + (index - (8 - tail))];
        } else {
          group = groups[index];
        }
        out_bytes[index * 2] = (uint8_t)(group >> 8U);
        out_bytes[index * 2 + 1] = (uint8_t)(group & 0xffU);
      }
    }
    return 1;
  }
  return 0;
}

size_t wt_udp_platform_format_address(int domain, const uint8_t *bytes,
                                      char *out, size_t capacity) {
  int written;
  if (bytes == NULL || out == NULL || capacity == 0U) return 0U;
  if (domain == AF_INET) {
    written = snprintf(out, capacity, "%u.%u.%u.%u", (unsigned)bytes[0],
                       (unsigned)bytes[1], (unsigned)bytes[2],
                       (unsigned)bytes[3]);
  } else if (domain == AF_INET6) {
    written = snprintf(out, capacity,
                       "%x:%x:%x:%x:%x:%x:%x:%x",
                       ((unsigned)bytes[0] << 8U) | bytes[1],
                       ((unsigned)bytes[2] << 8U) | bytes[3],
                       ((unsigned)bytes[4] << 8U) | bytes[5],
                       ((unsigned)bytes[6] << 8U) | bytes[7],
                       ((unsigned)bytes[8] << 8U) | bytes[9],
                       ((unsigned)bytes[10] << 8U) | bytes[11],
                       ((unsigned)bytes[12] << 8U) | bytes[13],
                       ((unsigned)bytes[14] << 8U) | bytes[15]);
  } else {
    return 0U;
  }
  if (written < 0 || (size_t)written >= capacity) return 0U;
  return (size_t)written;
}

wt_status_t wt_udp_platform_status_of_error(int error) {
  switch (error) {
    case WT_XAIOS_ERROR_AGAIN:
      return WT_ERR_AGAIN;
    case WT_XAIOS_ERROR_LIMIT:
      return WT_ERR_LIMIT;
    case WT_XAIOS_ERROR_INVALID:
      return WT_ERR_INVALID_ARGUMENT;
    case WT_XAIOS_ERROR_UNSUPPORTED:
      return WT_ERR_UNSUPPORTED;
    case WT_XAIOS_ERROR_NONE:
      return WT_OK;
    default:
      return WT_ERR_IO;
  }
}
