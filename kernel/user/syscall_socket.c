/*
 * The kernel socket table. See syscall_internal.h.
 */

#include "syscall_internal.h"

#include <xaios/assert.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/local_ports.h>
#include <xaios/network_stack.h>
#include <xaios/smp.h>
#include <xaios/vfs.h>

kernel_socket_t *g_kernel_sockets;
uint32_t g_kernel_socket_capacity;
uint32_t g_kernel_socket_per_port_limit;
uint64_t g_socket_next_id = 1;
uint16_t g_next_ephemeral_port = UINT16_C(49152);
uint32_t g_total_connections = 0;
xaios_spinlock_t g_kernel_socket_lock = XAIOS_SPINLOCK_INIT;

void kernel_socket_table_init(void) {
  uint64_t capacity = (uint64_t)smp_online_count() * KERNEL_SOCKETS_PER_CPU;
  if (capacity < KERNEL_SOCK_MIN_CAPACITY) capacity = KERNEL_SOCK_MIN_CAPACITY;
  if (capacity > UINT32_MAX) capacity = UINT32_MAX;
  g_kernel_sockets = (kernel_socket_t *)kheap_calloc(
      capacity * sizeof(*g_kernel_sockets), 64U);
  kassert(g_kernel_sockets != 0);
  g_kernel_socket_capacity = (uint32_t)capacity;
  uint64_t per_port = (uint64_t)smp_online_count() * 8U;
  if (per_port < KERNEL_SOCK_MIN_PER_PORT) {
    per_port = KERNEL_SOCK_MIN_PER_PORT;
  }
  if (per_port > capacity) per_port = capacity;
  g_kernel_socket_per_port_limit = (uint32_t)per_port;
  xaios_spin_init(&g_kernel_socket_lock);
}

uint64_t kernel_socket_alloc_locked(uint32_t type, uint16_t port,
                                           uint32_t owner_token) {
  if (g_total_connections >= g_kernel_socket_capacity) {
    klog("syscall: socket allocation denied (capacity reached: %u)\n",
         g_total_connections);
    return 0;
  }

  /* Enforce the per-port limit for connected sockets. */
  if (type == KERNEL_SOCK_CONNECTED) {
    uint32_t port_count = 0;
    for (uint32_t i = 0; i < g_kernel_socket_capacity; ++i) {
      if (g_kernel_sockets[i].state == KERNEL_SOCK_CONNECTED &&
          g_kernel_sockets[i].port == port) {
        port_count++;
      }
    }
    if (port_count >= g_kernel_socket_per_port_limit) {
      klog("syscall: socket allocation denied (max per-port: %u for port %u)\n",
           port_count, port);
      return 0;
    }
  }

  for (uint32_t i = 0; i < g_kernel_socket_capacity; ++i) {
    if (g_kernel_sockets[i].state == 0) {
      g_kernel_sockets[i].state = type;
      g_kernel_sockets[i].port = port;
      g_kernel_sockets[i].owner_token = owner_token;
      g_kernel_sockets[i].id = g_socket_next_id;
      g_total_connections++;
      uint64_t id = g_socket_next_id++;
      if (g_socket_next_id == 0U) g_socket_next_id = 1U;
      return id;
    }
  }
  return 0; /* no free slots */
}

uint64_t kernel_socket_alloc(uint32_t type, uint16_t port,
                                    uint32_t owner_token) {
  uint64_t sockfd;
  if (g_kernel_sockets == 0 || owner_token == 0U) return 0U;
  xaios_spin_lock(&g_kernel_socket_lock);
  sockfd = kernel_socket_alloc_locked(type, port, owner_token);
  xaios_spin_unlock(&g_kernel_socket_lock);
  return sockfd;
}

uint16_t kernel_ephemeral_next_after(uint16_t port) {
  uint16_t next = (uint16_t)(port + 1U);
  /* `uint16_t` cannot hold 65536, so the value after 65535 is 0 and the test
     below catches it: 0 < 49152 is true. The counter therefore never holds a
     value outside the range and no draw can return port 0. */
  if (next < KERNEL_EPHEMERAL_PORT_MIN) next = KERNEL_EPHEMERAL_PORT_MIN;
  return next;
}

uint16_t kernel_ephemeral_reserve(void) {
  uint32_t guard = 0U;
  for (;;) {
    uint16_t current = g_next_ephemeral_port;
    uint16_t next = kernel_ephemeral_next_after(current);
    if (__sync_bool_compare_and_swap(&g_next_ephemeral_port, current, next)) {
      return current;
    }
    /* Bounded: a failed exchange means another CPU moved the counter, which
       is progress, not livelock. The bound is a backstop that cannot be
       reached on a machine with any sane number of CPUs. */
    if (++guard > 1024U) return kernel_ephemeral_next_after(
        g_next_ephemeral_port);
  }
}

uint64_t kernel_socket_alloc_ephemeral_datagram(uint32_t owner_token,
                                                       uint16_t *out_port) {
  uint64_t sockfd = 0U;
  uint16_t port = 0U;

  if (g_kernel_sockets == 0 || owner_token == 0U) return 0U;

  xaios_spin_lock(&g_kernel_socket_lock);
  /* The whole range, so a run of busy ports costs those ports and not the
     call. The bound is the range size, so every port is considered once. */
  for (uint32_t attempt = 0U; attempt < 16384U; ++attempt) {
    uint16_t candidate = kernel_ephemeral_reserve();
    if (candidate < KERNEL_EPHEMERAL_PORT_MIN) continue;
    {
      /* Search the table rather than calling a helper that would take the
         lock again: `xaios_spin_lock` is a ticket lock and is not reentrant,
         so a nested acquire deadlocks rather than succeeding. */
      int in_use = 0;
      for (uint32_t i = 0U; i < g_kernel_socket_capacity; ++i) {
        if (g_kernel_sockets[i].state != 0 &&
            g_kernel_sockets[i].port == candidate) {
          in_use = 1;
          break;
        }
      }
      if (in_use) continue;
    }
    sockfd = kernel_socket_alloc_locked(KERNEL_SOCK_DATAGRAM, candidate,
                                        owner_token);
    if (sockfd != 0U) port = candidate;
    break;
  }
  xaios_spin_unlock(&g_kernel_socket_lock);

  if (sockfd == 0U) return 0U;
  *out_port = port;
  return sockfd;
}

kernel_socket_t *kernel_socket_find_owned_locked(uint64_t sockfd,
                                                        uint32_t owner_token) {
  for (uint32_t i = 0; i < g_kernel_socket_capacity; ++i) {
    if (g_kernel_sockets[i].state != 0 && g_kernel_sockets[i].id == sockfd &&
        g_kernel_sockets[i].owner_token == owner_token) {
      return &g_kernel_sockets[i];
    }
  }
  return 0;
}

xaios_status_t kernel_socket_snapshot_owned(uint64_t sockfd,
                                                   uint32_t owner_token,
                                                   kernel_socket_t *snapshot) {
  if (snapshot == 0) return XAIOS_ERR_INVALID;
  xaios_spin_lock(&g_kernel_socket_lock);
  kernel_socket_t *socket = kernel_socket_find_owned_locked(sockfd, owner_token);
  if (socket == 0) {
    xaios_spin_unlock(&g_kernel_socket_lock);
    return XAIOS_ERR_INVALID;
  }
  *snapshot = *socket;
  xaios_spin_unlock(&g_kernel_socket_lock);
  return XAIOS_OK;
}

int kernel_sockets_ready_for(uint32_t owner_token) {
  kernel_socket_t owned[KERNEL_SOCKETS_READY_SCAN];
  uint32_t count = 0U;
  if (owner_token == 0U || g_kernel_sockets == 0) return 0;
  xaios_spin_lock(&g_kernel_socket_lock);
  for (uint32_t i = 0; i < g_kernel_socket_capacity &&
                       count < KERNEL_SOCKETS_READY_SCAN; ++i) {
    if (g_kernel_sockets[i].state != 0U &&
        g_kernel_sockets[i].owner_token == owner_token) {
      owned[count++] = g_kernel_sockets[i];
    }
  }
  xaios_spin_unlock(&g_kernel_socket_lock);
  for (uint32_t i = 0; i < count; ++i) {
    uint32_t listening = owned[i].state != KERNEL_SOCK_CONNECTED;
    if (network_stack_socket_ready(owned[i].id, owned[i].protocol,
                                   owned[i].port, listening) != 0) {
      return 1;
    }
  }
  return 0;
}

xaios_status_t kernel_socket_free(uint64_t sockfd, uint32_t owner_token) {
  xaios_spin_lock(&g_kernel_socket_lock);
  kernel_socket_t *socket = kernel_socket_find_owned_locked(sockfd, owner_token);
  if (socket != 0) {
    socket->state = 0;
    socket->port = 0;
    socket->family = 0;
    socket->protocol = 0;
    socket->peer_port = 0;
    socket->owner_token = 0;
    socket->id = 0;
    for (uint32_t j = 0; j < 16; ++j) {
      socket->bind_addr[j] = 0;
      socket->peer_addr[j] = 0;
    }
    if (g_total_connections > 0) g_total_connections--;
    xaios_spin_unlock(&g_kernel_socket_lock);
    return XAIOS_OK;
  }
  xaios_spin_unlock(&g_kernel_socket_lock);
  return XAIOS_ERR_INVALID;
}

void syscall_release_process_resources(uint32_t owner_token) {
  if (owner_token == 0U) return;
  (void)vfs_release_owner(owner_token);
  if (g_kernel_sockets == 0) return;
  for (;;) {
    kernel_socket_t snapshot;
    uint32_t found = 0U;
    xaios_spin_lock(&g_kernel_socket_lock);
    for (uint32_t i = 0; i < g_kernel_socket_capacity; ++i) {
      if (g_kernel_sockets[i].state != 0U &&
          g_kernel_sockets[i].owner_token == owner_token) {
        snapshot = g_kernel_sockets[i];
        found = 1U;
        break;
      }
    }
    xaios_spin_unlock(&g_kernel_socket_lock);
    if (found == 0U) return;

    socket_flow_mapping_t mapping_copy;
    socket_flow_mapping_t *mapping =
        network_stack_get_socket_mapping(snapshot.id, &mapping_copy)
            ? &mapping_copy
            : 0;
    if (mapping != 0) {
      if (mapping->protocol == XAIOS_NETWORK_PROTOCOL_TCP) {
        (void)network_stack_tcp_close_flow(mapping->flow_id);
      }
      network_stack_unmap_socket(snapshot.id);
    }
    if (snapshot.state == KERNEL_SOCK_LISTEN) {
      network_stack_unregister_listener(snapshot.port);
    } else if (snapshot.state == KERNEL_SOCK_DATAGRAM) {
      network_stack_unregister_udp_listener(snapshot.port);
    }
    (void)kernel_socket_free(snapshot.id, owner_token);
  }
}

/* The socket lock, for the syscall handlers that fill in a socket's fields
   after allocating it and before mapping it. */
void syscall_socket_lock(void) { xaios_spin_lock(&g_kernel_socket_lock); }
void syscall_socket_unlock(void) { xaios_spin_unlock(&g_kernel_socket_lock); }

uint32_t syscall_socket_total_connections(void) { return g_total_connections; }

uint32_t syscall_socket_capacity(void) { return g_kernel_socket_capacity; }

uint32_t syscall_socket_per_port_limit(void) {
  return g_kernel_socket_per_port_limit;
}

