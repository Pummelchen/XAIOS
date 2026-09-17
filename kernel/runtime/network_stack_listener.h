/*
 * The listener registry, accept queue and socket-to-flow map, now their own
 * translation unit.
 *
 * These three tables were the first part of network_stack.c that could leave
 * it honestly. The rest of the stack never wanted the tables -- it wanted a
 * row out of them -- so what crosses this boundary is a copy of a row, not a
 * pointer into a table. That is the interface the note at the top of
 * network_stack.c asked for before any of it could be split.
 *
 * Locking. The stack's guard is g_network_guard, a reentrant lock, held
 * through network_stack_lock()/network_stack_unlock() (the same functions the
 * old file reached through its listener_lock() and network_lock() aliases).
 * Every accessor declared below is lock-free on purpose: the caller must
 * already hold that guard, and a second lock, a different lock order or a
 * wider critical section would each be a bug rather than a detail. The
 * exported entry points in network_stack_listener.c take the guard
 * themselves, exactly where the functions they replace took it.
 *
 * The shape is a cursor plus a commit, never a find() that hands back a
 * mutable pointer into a table. network_stack.c already decided against that
 * when it replaced the pointer-returning socket-map lookup with a copy: a
 * concurrent close could clear a row between the lookup and the dereference.
 */

#ifndef XAIOS_KERNEL_RUNTIME_NETWORK_STACK_LISTENER_H
#define XAIOS_KERNEL_RUNTIME_NETWORK_STACK_LISTENER_H

#include <xaios/network_stack.h>

/* The sizes the tables in network_stack_listener.c have. They live here now
   because the tables do; the rest of the stack still sizes its own flow
   tables from the two counts, so the header lends them back rather than
   repeating the numbers. */
#define NETWORK_TCP_CONNECTIONS 128U
#define NETWORK_UDP_FLOWS 32U
/* Two listener pools, one per protocol, because they bound different things
   and neither should be the other's ceiling (WT-39).

   A row is a receive entry: a TCP row holds connections the stack has accepted
   but the application has not taken off the backlog, and a UDP row holds
   datagrams that have arrived but not been read. They were one sixteen-row
   table, and sixteen datagram sockets -- which WT-35 made every send-capable
   client register -- exhausted the listeners a TCP service could register, and
   sixteen TCP listeners exhausted the datagram sockets. The pools are separate
   ranges of one flat slot index: TCP rows are [0, NETWORK_MAX_TCP_LISTENERS)
   and UDP rows follow immediately, so slot_count/slot_read/slot_write keep
   their single index while an allocation in one pool can never take a row from
   the other.

   The bound protects static kernel memory, and only that: these tables are
   kernel private, never cross the syscall trap and are part of no kernel-user
   layout. A TCP row is backed by NETWORK_TCP_CONNECTIONS flows, and sixteen
   listeners is already more than the machine's services use (sshd takes one).
   A UDP row is serviced by NETWORK_UDP_FLOWS flows, so past that many
   concurrent datagram sockets a row can only wait for a flow to free; the pool
   is that count. */
#define NETWORK_MAX_TCP_LISTENERS 16U
#define NETWORK_MAX_UDP_LISTENERS NETWORK_UDP_FLOWS
#define NETWORK_MAX_LISTENERS \
  (NETWORK_MAX_TCP_LISTENERS + NETWORK_MAX_UDP_LISTENERS)
#define NETWORK_LISTENER_BACKLOG NETWORK_TCP_CONNECTIONS
#define NETWORK_SOCK_FLOW_MAP_SIZE \
  (NETWORK_TCP_CONNECTIONS + NETWORK_UDP_FLOWS)

/* Per-listener accept backlog. */
typedef struct listener_accept_entry {
  uint32_t flow_id;
  uint32_t peer_ip;          /* IPv4 (host order) */
  xaios_ip_addr_t peer_addr; /* full address (IPv4 or IPv6) */
  uint16_t peer_port;
  uint16_t local_port;
  uint16_t payload_len;
  uint32_t active;
} listener_accept_entry_t;

typedef struct network_listener_ex {
  uint16_t port;
  uint8_t protocol;
  uint64_t sockfd;
  uint32_t active;
  listener_accept_entry_t backlog[NETWORK_LISTENER_BACKLOG];
  uint32_t backlog_count;
} network_listener_ex_t;

/* ---- listener rows (caller holds the stack guard) ---- */

/* How many rows the registry has, live or not. */
uint32_t network_listener_slot_count(void);
/* Copy a live row out; returns 0 without touching *out when the slot is not
   live. The caller must not keep anything but its own copy afterwards. */
int network_listener_slot_read(uint32_t index, network_listener_ex_t *out);
/* Commit a whole row back into a slot. */
void network_listener_slot_write(uint32_t index,
                                 const network_listener_ex_t *row);
/* Live rows, counted without copying any backlog. */
uint32_t network_listener_active_count(void);

/* ---- socket-to-flow map rows (caller holds the stack guard) ---- */

uint32_t socket_map_slot_count(void);
int socket_map_slot_read(uint32_t index, socket_flow_mapping_t *out);
void socket_map_slot_write(uint32_t index, const socket_flow_mapping_t *row);
uint32_t socket_map_active_count(void);
void socket_map_note_exhausted(void);
uint64_t socket_map_exhausted_count_value(void);
/* The boot self-test fills this table on purpose, so the init paths zero the
   refusal count before a running machine can be judged by it. */
void socket_map_reset_exhausted(void);

/* ---- still called from the code that stayed in network_stack.c ---- */

int accept_queue_enqueue(uint32_t flow_id, uint32_t peer_ip, uint16_t peer_port,
                         uint16_t local_port,
                         const xaios_ip_addr_t *peer_addr);
int udp_listener_enqueue(uint16_t port, uint32_t flow_id, uint16_t peer_port,
                         const xaios_ip_addr_t *peer_addr,
                         uint16_t payload_len);
/* Same contract as network_stack_map_socket without taking the guard: the
   caller already holds it. */
xaios_status_t network_stack_map_socket_unlocked(uint64_t sockfd,
                                                 uint32_t flow_id,
                                                 uint8_t protocol);
/* Same lookup as network_stack_get_socket_mapping without taking the guard:
   the caller already holds it. Copies the row out; 0 when there is none. */
int network_stack_get_socket_mapping_unlocked(uint64_t sockfd,
                                              socket_flow_mapping_t *out);

#endif
