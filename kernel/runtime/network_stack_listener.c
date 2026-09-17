/*
 * The listener registry, the accept queue and the socket-to-flow map.
 *
 * Split out of network_stack.c, which was 5468 lines. This group could leave
 * first because the rest of the stack only ever needed a *row* out of these
 * tables, never the tables themselves; the accessors declared in
 * network_stack_listener.h are that row-shaped interface, and everything the
 * staying code still calls is named there too.
 *
 * Locking, stated once. The stack's guard is g_network_guard, a reentrant
 * lock, and network_stack_lock()/network_stack_unlock() are the exported
 * handles for it -- the same calls the old file made through its
 * listener_lock() and network_lock() aliases. The accessors in this file take
 * no lock: their callers hold that guard, and saying so at each accessor is
 * what keeps the critical sections where they were. A row is read out, edited
 * and committed while the caller's guard is still held; nothing here releases
 * it in the middle of a read-modify-write, which would turn an atomic
 * enqueue or dequeue into a lost update.
 */

#include "network_stack_listener.h"

#include <xaios/ip_addr.h>
#include <xaios/klog.h>

#include "network_stack_wire.h"

/* ---- state ---- */

static network_listener_ex_t g_listeners_ex[NETWORK_MAX_LISTENERS];
static socket_flow_mapping_t g_socket_flow_map[NETWORK_SOCK_FLOW_MAP_SIZE];
/* Every mapping this table had no room for. Counted rather than inferred: the
   condition is otherwise invisible from outside the kernel. */
static uint64_t g_socket_map_exhausted_count;

/* ---- accessors (lock-free; the caller holds the stack guard) ---- */

uint32_t network_listener_slot_count(void) { return NETWORK_MAX_LISTENERS; }

int network_listener_slot_read(uint32_t index, network_listener_ex_t *out) {
  if (out == 0 || index >= NETWORK_MAX_LISTENERS) return 0;
  if (g_listeners_ex[index].active == 0U) return 0;
  *out = g_listeners_ex[index];
  return 1;
}

void network_listener_slot_write(uint32_t index,
                                 const network_listener_ex_t *row) {
  if (row == 0 || index >= NETWORK_MAX_LISTENERS) return;
  g_listeners_ex[index] = *row;
}

uint32_t network_listener_active_count(void) {
  uint32_t active = 0U;
  for (uint32_t i = 0U; i < NETWORK_MAX_LISTENERS; ++i) {
    if (g_listeners_ex[i].active != 0U) ++active;
  }
  return active;
}

uint32_t socket_map_slot_count(void) { return NETWORK_SOCK_FLOW_MAP_SIZE; }

int socket_map_slot_read(uint32_t index, socket_flow_mapping_t *out) {
  if (out == 0 || index >= NETWORK_SOCK_FLOW_MAP_SIZE) return 0;
  if (g_socket_flow_map[index].active == 0U) return 0;
  *out = g_socket_flow_map[index];
  return 1;
}

void socket_map_slot_write(uint32_t index, const socket_flow_mapping_t *row) {
  if (row == 0 || index >= NETWORK_SOCK_FLOW_MAP_SIZE) return;
  g_socket_flow_map[index] = *row;
}

uint32_t socket_map_active_count(void) {
  uint32_t used = 0U;
  for (uint32_t i = 0; i < NETWORK_SOCK_FLOW_MAP_SIZE; ++i) {
    if (g_socket_flow_map[i].active != 0U) ++used;
  }
  return used;
}

void socket_map_note_exhausted(void) { ++g_socket_map_exhausted_count; }

uint64_t socket_map_exhausted_count_value(void) {
  return g_socket_map_exhausted_count;
}

void socket_map_reset_exhausted(void) { g_socket_map_exhausted_count = 0U; }

/* ---- Listener Registry Functions ---- */

static xaios_status_t network_stack_register_listener_unlocked(uint16_t port,
                                                              uint64_t sockfd) {
  for (uint32_t i = 0; i < network_listener_slot_count(); ++i) {
    network_listener_ex_t row;
    if (network_listener_slot_read(i, &row)) continue;
    net_wire_bytes_zero(&row, sizeof(row));
    row.port = port;
    row.protocol = NETWORK_IP_PROTO_TCP;
    row.sockfd = sockfd;
    row.active = 1;
    row.backlog_count = 0;
    network_listener_slot_write(i, &row);
    return XAIOS_OK;
  }
  klog("network: listener registry full (port=%u)\n", port);
  return XAIOS_ERR_NO_MEMORY;
}

xaios_status_t network_stack_register_listener(uint16_t port, uint64_t sockfd) {
  network_stack_lock();
  const xaios_status_t status =
      network_stack_register_listener_unlocked(port, sockfd);
  network_stack_unlock();
  /* A full registry is not a detail the caller can be spared: the row is what
     makes the port answer, so a listener that was not given one cannot receive
     and must not be reported as listening (B-78). */
  return status;
}

static xaios_status_t network_stack_register_udp_listener_unlocked(
    uint16_t port, uint64_t sockfd) {
  for (uint32_t i = 0; i < network_listener_slot_count(); ++i) {
    network_listener_ex_t row;
    if (network_listener_slot_read(i, &row)) continue;
    net_wire_bytes_zero(&row, sizeof(row));
    row.port = port;
    row.protocol = NETWORK_IP_PROTO_UDP;
    row.sockfd = sockfd;
    row.active = 1;
    row.backlog_count = 0;
    network_listener_slot_write(i, &row);
    return XAIOS_OK;
  }
  klog("network: UDP listener registry full (port=%u)\n", port);
  return XAIOS_ERR_NO_MEMORY;
}

xaios_status_t network_stack_register_udp_listener(uint16_t port,
                                                   uint64_t sockfd) {
  network_stack_lock();
  const xaios_status_t status =
      network_stack_register_udp_listener_unlocked(port, sockfd);
  network_stack_unlock();
  return status;
}

static void network_stack_unregister_listener_unlocked(uint16_t port) {
  for (uint32_t i = 0; i < network_listener_slot_count(); ++i) {
    network_listener_ex_t row;
    if (!network_listener_slot_read(i, &row)) continue;
    if (row.port == port && row.protocol == NETWORK_IP_PROTO_TCP) {
      row.active = 0;
      row.backlog_count = 0;
      network_listener_slot_write(i, &row);
      return;
    }
  }
}

void network_stack_unregister_listener(uint16_t port) {
  network_stack_lock();
  network_stack_unregister_listener_unlocked(port);
  network_stack_unlock();
}

static void network_stack_unregister_udp_listener_unlocked(uint16_t port) {
  for (uint32_t i = 0; i < network_listener_slot_count(); ++i) {
    network_listener_ex_t row;
    if (!network_listener_slot_read(i, &row)) continue;
    if (row.port == port && row.protocol == NETWORK_IP_PROTO_UDP) {
      row.active = 0;
      row.backlog_count = 0;
      network_listener_slot_write(i, &row);
      return;
    }
  }
}

void network_stack_unregister_udp_listener(uint16_t port) {
  network_stack_lock();
  network_stack_unregister_udp_listener_unlocked(port);
  network_stack_unlock();
}

int network_stack_has_listener(uint16_t port) {
  network_stack_lock();
  int found = 0;
  for (uint32_t i = 0; i < network_listener_slot_count(); ++i) {
    network_listener_ex_t row;
    if (!network_listener_slot_read(i, &row)) continue;
    if (row.port == port && row.protocol == NETWORK_IP_PROTO_TCP) {
      found = 1;
      break;
    }
  }
  network_stack_unlock();
  return found;
}

/* ---- Accept Queue Functions ---- */

/* The row is read out, edited and written back with the guard still held, so
   an enqueue racing a dequeue cannot lose the other's update. */
static int listener_enqueue_backlog(uint16_t port, uint32_t flow_id,
                                     uint32_t peer_ip, uint16_t peer_port,
                                     const xaios_ip_addr_t *peer_addr) {
  network_stack_lock();
  for (uint32_t i = 0; i < network_listener_slot_count(); ++i) {
    network_listener_ex_t row;
    if (!network_listener_slot_read(i, &row)) continue;
    if (row.port != port || row.protocol != NETWORK_IP_PROTO_TCP) continue;
    if (row.backlog_count >= NETWORK_LISTENER_BACKLOG) {
      network_stack_unlock();
      return 0;
    }
    listener_accept_entry_t *e = &row.backlog[row.backlog_count++];
    e->flow_id = flow_id;
    e->peer_ip = peer_ip;
    if (peer_addr) e->peer_addr = *peer_addr;
    else { xaios_ip_addr_zero(&e->peer_addr); e->peer_addr.family = XAIOS_IP_FAMILY_V4; }
    e->peer_port = peer_port;
    e->local_port = port;
    e->payload_len = 0;
    e->active = 1;
    network_listener_slot_write(i, &row);
    network_readiness_note();
    network_stack_unlock();
    return 1;
  }
  network_stack_unlock();
  return 0;
}

static int listener_dequeue_backlog(uint16_t port, uint32_t *out_flow_id,
                                     uint32_t *out_peer_ip,
                                     uint16_t *out_peer_port,
                                     xaios_ip_addr_t *out_peer_addr) {
  network_stack_lock();
  for (uint32_t i = 0; i < network_listener_slot_count(); ++i) {
    network_listener_ex_t row;
    if (!network_listener_slot_read(i, &row)) continue;
    if (row.port != port || row.protocol != NETWORK_IP_PROTO_TCP) continue;
    if (row.backlog_count == 0) { network_stack_unlock(); return 0; }
    listener_accept_entry_t e = row.backlog[0];
    if (out_flow_id) *out_flow_id = e.flow_id;
    if (out_peer_ip) *out_peer_ip = e.peer_ip;
    if (out_peer_port) *out_peer_port = e.peer_port;
    if (out_peer_addr) *out_peer_addr = e.peer_addr;
    for (uint32_t j = 1; j < row.backlog_count; ++j)
      row.backlog[j - 1] = row.backlog[j];
    row.backlog_count--;
    network_listener_slot_write(i, &row);
    network_stack_unlock();
    return 1;
  }
  network_stack_unlock();
  return 0;
}

int udp_listener_enqueue(uint16_t port, uint32_t flow_id,
                                uint16_t peer_port,
                                const xaios_ip_addr_t *peer_addr,
                                uint16_t payload_len) {
  network_stack_lock();
  for (uint32_t i = 0; i < network_listener_slot_count(); ++i) {
    network_listener_ex_t row;
    if (!network_listener_slot_read(i, &row)) continue;
    if (row.port != port || row.protocol != NETWORK_IP_PROTO_UDP) continue;
    if (row.backlog_count >= NETWORK_LISTENER_BACKLOG) {
      network_stack_unlock();
      return 0;
    }
    listener_accept_entry_t *entry = &row.backlog[row.backlog_count++];
    entry->flow_id = flow_id;
    entry->peer_ip = 0;
    entry->peer_addr = *peer_addr;
    entry->peer_port = peer_port;
    entry->local_port = port;
    entry->payload_len = payload_len;
    entry->active = 1;
    network_listener_slot_write(i, &row);
    network_stack_unlock();
    return 1;
  }
  network_stack_unlock();
  return 0;
}

int accept_queue_enqueue(uint32_t flow_id, uint32_t peer_ip,
                                uint16_t peer_port, uint16_t local_port,
                                const xaios_ip_addr_t *peer_addr) {
  return listener_enqueue_backlog(local_port, flow_id, peer_ip, peer_port,
                                  peer_addr);
}

static xaios_status_t network_stack_accept_connection_unlocked(
    uint16_t listen_port, uint32_t *out_flow_id, uint32_t *out_peer_ip,
    uint16_t *out_peer_port, xaios_ip_addr_t *out_peer_addr) {
  if (!out_flow_id || !out_peer_ip || !out_peer_port || !out_peer_addr)
    return XAIOS_ERR_INVALID;
  if (listener_dequeue_backlog(listen_port, out_flow_id, out_peer_ip,
                               out_peer_port, out_peer_addr))
    return XAIOS_OK;
  return XAIOS_ERR_NOT_FOUND;
}

xaios_status_t network_stack_accept_connection(uint16_t listen_port,
                                                uint32_t *out_flow_id,
                                                uint32_t *out_peer_ip,
                                                uint16_t *out_peer_port,
                                                xaios_ip_addr_t *out_peer_addr) {
  network_stack_lock();
  xaios_status_t result = network_stack_accept_connection_unlocked(
      listen_port, out_flow_id, out_peer_ip, out_peer_port, out_peer_addr);
  network_stack_unlock();
  return result;
}

/* ---- Socket-to-Flow Mapping Functions ---- */

/* B-47. This used to return void and fall off the end when both scans failed,
   so a full table was indistinguishable from a successful mapping. The accept
   that called it still allocated a descriptor, still wrote the peer address
   back to userspace and still logged "syscall: net_accept" -- and the socket
   it handed out had no flow behind it, so every later send and recv on that
   descriptor looked up nothing and did nothing. A connection accepted and then
   never progressed, with not one line anywhere saying why.

   The table is NETWORK_TCP_CONNECTIONS + NETWORK_UDP_FLOWS entries, which
   reads like "one slot per flow, so it cannot run out before flows do". That
   is not what bounds it. A row is keyed by descriptor, not by flow, and is
   cleared on net_close or when the owning process is torn down -- for UDP also
   when the flow itself is released, but for TCP not: release_tcp_flow leaves
   the row standing. So the occupancy is the number of open mapped
   descriptors, and the kernel socket table holds at least 256 of those
   (KERNEL_SOCK_MIN_CAPACITY) against 160 rows here. A process that opens
   connections and leaves the descriptors open while their flows die -- a
   leak, a peer that resets, a plain idle timeout -- fills this table with an
   empty flow table. Sizing does not protect it; the refusal below does. */
xaios_status_t network_stack_map_socket_unlocked(uint64_t sockfd,
                                uint32_t flow_id,
                                uint8_t protocol) {
  for (uint32_t i = 0; i < socket_map_slot_count(); ++i) {
    socket_flow_mapping_t row;
    if (!socket_map_slot_read(i, &row)) continue;
    if (row.sockfd == sockfd) {
      row.flow_id = flow_id;
      row.protocol = protocol;
      socket_map_slot_write(i, &row);
      return XAIOS_OK;
    }
  }
  for (uint32_t i = 0; i < socket_map_slot_count(); ++i) {
    socket_flow_mapping_t row;
    if (socket_map_slot_read(i, &row)) continue;
    net_wire_bytes_zero(&row, sizeof(row));
    row.sockfd = sockfd;
    row.flow_id = flow_id;
    row.protocol = protocol;
    row.active = 1;
    socket_map_slot_write(i, &row);
    return XAIOS_OK;
  }
  socket_map_note_exhausted();
  /* Loud, but not loud enough to drown the console: a caller that retries in a
     tight loop would otherwise turn one exhausted table into a serial flood,
     and an unread serial pipe stalls the guest. First occurrence, then every
     sixty-fourth. */
  if (socket_map_exhausted_count_value() == 1U ||
      (socket_map_exhausted_count_value() % 64U) == 0U) {
    klog("network: socket-to-flow map exhausted size=%u sockfd=%lu flow=%u "
         "protocol=%u refusals=%lu\n",
         (unsigned)NETWORK_SOCK_FLOW_MAP_SIZE, (unsigned long)sockfd, flow_id,
         (unsigned)protocol, socket_map_exhausted_count_value());
  }
  return XAIOS_ERR_NO_MEMORY;
}

xaios_status_t network_stack_map_socket(uint64_t sockfd, uint32_t flow_id,
                                uint8_t protocol) {
  network_stack_lock();
  xaios_status_t status =
      network_stack_map_socket_unlocked(sockfd, flow_id, protocol);
  network_stack_unlock();
  return status;
}

uint64_t network_stack_socket_map_exhausted_count(void) {
  return socket_map_exhausted_count_value();
}

uint32_t network_stack_socket_map_capacity(void) {
  return NETWORK_SOCK_FLOW_MAP_SIZE;
}

uint32_t network_stack_socket_map_count(void) {
  network_stack_lock();
  uint32_t used = socket_map_active_count();
  network_stack_unlock();
  return used;
}

int network_stack_get_socket_mapping_unlocked(uint64_t sockfd,
                                              socket_flow_mapping_t *out) {
  if (out == 0) return 0;
  for (uint32_t i = 0; i < socket_map_slot_count(); ++i) {
    socket_flow_mapping_t row;
    if (!socket_map_slot_read(i, &row)) continue;
    if (row.sockfd == sockfd) {
      *out = row;
      return 1;
    }
  }
  return 0;
}

/* Copy the row out under the guard rather than handing back a pointer into the
   table. The old signature released the guard and returned an interior pointer,
   so a caller read the row with nothing holding it still: a concurrent close
   could clear that row between the lookup and the dereference, and the caller
   would then act on a flow that had already been released. Harmless while one
   CPU ran the kernel; reachable the moment syscalls run on several. */
int network_stack_get_socket_mapping(uint64_t sockfd,
                                     socket_flow_mapping_t *out) {
  if (out == 0) return 0;
  network_stack_lock();
  int present = network_stack_get_socket_mapping_unlocked(sockfd, out);
  network_stack_unlock();
  return present;
}

static void network_stack_unmap_socket_unlocked(uint64_t sockfd) {
  for (uint32_t i = 0; i < socket_map_slot_count(); ++i) {
    socket_flow_mapping_t row;
    if (!socket_map_slot_read(i, &row)) continue;
    if (row.sockfd == sockfd) {
      row.active = 0;
      socket_map_slot_write(i, &row);
      return;
    }
  }
}

void network_stack_unmap_socket(uint64_t sockfd) {
  network_stack_lock();
  network_stack_unmap_socket_unlocked(sockfd);
  network_stack_unlock();
}
