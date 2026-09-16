/*
 * The kernel socket table, shared between the syscall dispatcher and the
 * table's own translation unit.
 *
 * Split out of syscall.c, which was 2610 lines. The table owns its own state --
 * the row array, its capacity, the id and ephemeral-port counters, the
 * connection count and the lock over them -- so it moves as a unit, and the
 * dispatcher keeps its syscall table and its own counters.
 */

#ifndef XAIOS_KERNEL_USER_SYSCALL_INTERNAL_H
#define XAIOS_KERNEL_USER_SYSCALL_INTERNAL_H

#include <xaios/spinlock.h>
#include <xaios/status.h>
#include <xaios/syscall.h>

#define KERNEL_SOCK_LISTEN UINT32_C(1)
#define KERNEL_SOCK_CONNECTED UINT32_C(2)
#define KERNEL_SOCK_DATAGRAM UINT32_C(3)
#define KERNEL_SOCK_MIN_CAPACITY UINT32_C(256)
#define KERNEL_SOCKETS_PER_CPU UINT32_C(32)
#define KERNEL_SOCK_MIN_PER_PORT UINT32_C(128)
#define KERNEL_EPHEMERAL_PORT_MIN XAIOS_EPHEMERAL_PORT_MIN
/* How many rows `kernel_sockets_ready_for` scans in one call. */
#define KERNEL_SOCKETS_READY_SCAN UINT32_C(64)

typedef struct kernel_socket {
  uint32_t state;   /* 0=free, KERNEL_SOCK_LISTEN, KERNEL_SOCK_CONNECTED */
  uint16_t port;
  uint8_t  family;          /* 0=any, 4=IPv4, 6=IPv6 */
  uint8_t  protocol;        /* 6=TCP, 17=UDP */
  uint8_t  bind_addr[16];   /* bind address (16 bytes for IPv6) */
  uint8_t  peer_addr[16];   /* peer address (connected sockets) */
  uint16_t peer_port;
  uint32_t owner_token;
  uint64_t id;              /* unique socket ID from alloc */
} kernel_socket_t;

void kernel_socket_table_init(void);
uint64_t kernel_socket_alloc_locked(uint32_t type, uint16_t port, uint32_t owner_token);
uint64_t kernel_socket_alloc(uint32_t type, uint16_t port, uint32_t owner_token);
uint16_t kernel_ephemeral_next_after(uint16_t port);
uint16_t kernel_ephemeral_reserve(void);
uint64_t kernel_socket_alloc_ephemeral_datagram(uint32_t owner_token, uint16_t *out_port);
kernel_socket_t *kernel_socket_find_owned_locked(uint64_t sockfd, uint32_t owner_token);
xaios_status_t kernel_socket_snapshot_owned(uint64_t sockfd, uint32_t owner_token, kernel_socket_t *snapshot);
int kernel_sockets_ready_for(uint32_t owner_token);
xaios_status_t kernel_socket_free(uint64_t sockfd, uint32_t owner_token);
void syscall_release_process_resources(uint32_t owner_token);
void syscall_socket_lock(void);
void syscall_socket_unlock(void);
uint32_t syscall_socket_total_connections(void);
uint32_t syscall_socket_capacity(void);
uint32_t syscall_socket_per_port_limit(void);

void syscall_socket_lock(void);
void syscall_socket_unlock(void);
uint32_t syscall_socket_total_connections(void);

#endif /* XAIOS_KERNEL_USER_SYSCALL_INTERNAL_H */
