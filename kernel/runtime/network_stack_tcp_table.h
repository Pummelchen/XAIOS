/*
 * The interface shared by the split modules of the TCP flow plane: the table,
 * its allocation, the connection API, the timers, the pending-transmit drain
 * and the two frame handlers, all cut out of network_stack.c.
 *
 * The table itself stays in network_stack.c. Its own note recorded why: a
 * network_tcp_flow_t row is about 17 KB against a 16 KB secondary stack, so
 * neither a row copy per receive nor a module-static copy-out lease is
 * possible on the frame path. What crosses instead is a caller-owned
 * `network_tcp_flow_t *flows`: every function below takes the table from the
 * caller that owns it and returns a pointer into that caller's table, exactly
 * the way the TCP data plane in network_stack_tcp_flow.c already takes the row
 * from the caller that owns it. Nothing here is an accessor that hands out a
 * pointer into a module's own file-scope state.
 *
 * The scalar state the moved code used to touch directly stays in
 * network_stack.c behind the small helpers below -- the half-open counter (read
 * it for the SYN-flood ceiling, acquire a slot on allocation, release one on
 * reset/abort/expire) and the drain cursor. Each helper is the plain read or
 * update the moved code made in place, so no critical section changes shape.
 * The flow-id counter and the raw interface MAC keep the accessors that already
 * crossed for the UDP listener and transmit code: net_stack_alloc_flow_id()
 * and net_stack_local_mac(). The IPv6 receive increment keeps
 * net_stack_note_ipv6_rx() from network_stack_udp_rx.h for the same reason.
 *
 * Locking. Every function declared here runs with the stack guard
 * (g_network_guard, through network_stack_lock()/network_stack_unlock()) held
 * by the caller that already held it, except the `net_tcp_api_*` impls, which
 * take it themselves exactly where the `_unlocked` bodies they replace did.
 * No module here takes a lock of its own, so no critical section is widened,
 * narrowed or split.
 */

#ifndef XAIOS_KERNEL_RUNTIME_NETWORK_STACK_TCP_TABLE_H
#define XAIOS_KERNEL_RUNTIME_NETWORK_STACK_TCP_TABLE_H

#include <xaios/ip_addr.h>
#include <xaios/network_stack.h>

#include "network_stack_tcp.h"

/* Frame, retransmission, keepalive and half-open constants the moved code and
   the stack both use. Each was defined in network_stack.c and is defined here
   now, so the two sides share one definition rather than repeating it. */

#define NETWORK_TCP_MAX_RETRANSMITS 5U
#define NETWORK_TCP_IPV6_RX_MAX 1440U
#define NETWORK_TCP_WSCALE_OK 1U

/* Congestion control constants */
#define TCP_INIT_CWND     1U
#define TCP_INIT_SSTHRESH 16U

/* Keepalive defaults (in seconds, converted to ns elsewhere) */
#define TCP_KEEPALIVE_IDLE_NS     UINT64_C(7200000000000)  /* 2 hours */
#define TCP_KEEPALIVE_INTERVAL_NS UINT64_C(10000000000)    /* 10 seconds */
#define TCP_KEEPALIVE_PROBES     3U

/* Bound half-open state so SYN floods cannot exhaust the flow table. */
#define NETWORK_TCP_MAX_HALF_OPEN 16U

/* ---- scalar state owned by network_stack.c ----
   Caller holds the stack guard. Each is exactly the read or update the moved
   code made in place. */

/* The half-open connection count. net_tcp_half_open_release() is the guarded
   `if (g_half_open_count > 0U) --g_half_open_count;` the old code wrote at
   every reset, abort, expire and failed-allocation site. */
uint32_t net_tcp_half_open_count(void);
void net_tcp_half_open_acquire(void);
void net_tcp_half_open_release(void);

/* Advance g_tcp_drain_cursor and report the index it held before the advance,
   which is the order net_stack_tcp_drain_pending() used. */
uint32_t net_tcp_drain_cursor_take(void);

/* The one flow-id counter the UDP and TCP tables share, and the raw interface
   MAC. Both are also declared in network_stack_udp.h; the declarations are
   identical. Caller holds the guard. */
uint32_t net_stack_alloc_flow_id(void);
void net_stack_local_mac(uint8_t out[6]);

/* ---- the flow table, network_stack_tcp_table.c ----
   `flows` is the caller's table of NETWORK_TCP_CONNECTIONS rows. The find
   helpers return a pointer into it or 0; alloc takes a free row (or recycles a
   stale TIME_WAIT row when the table is full) and returns a pointer into it or
   0. All run with the stack guard held. */

network_tcp_flow_t *net_tcp_table_find_v4(network_tcp_flow_t *flows,
                                          uint16_t local_port,
                                          uint16_t remote_port,
                                          uint32_t remote_address);
network_tcp_flow_t *net_tcp_table_find_v6(network_tcp_flow_t *flows,
                                          uint16_t local_port,
                                          uint16_t remote_port,
                                          const xaios_ip_addr_t *remote_addr);
network_tcp_flow_t *net_tcp_table_alloc(network_tcp_flow_t *flows,
                                        uint16_t local_port,
                                        uint16_t remote_port,
                                        uint32_t remote_address,
                                        const xaios_ip_addr_t *remote_addr);
uint64_t net_tcp_table_connections(const network_tcp_flow_t *flows);

/* ---- the timers, network_stack_tcp_timers.c ---- */

uint64_t net_tcp_table_retransmit(network_tcp_flow_t *flows, uint64_t now_ns);
uint64_t net_tcp_table_expire(network_tcp_flow_t *flows, uint64_t now_ns);

/* ---- the pending-transmit drain, network_stack_tcp_drain.c ---- */

void net_tcp_drain_pending(network_tcp_flow_t *flows);

/* ---- the connection API, network_stack_tcp_api.c ----
   Each is the `_unlocked` body the stack's public wrapper already called, with
   the table supplied by that wrapper. */

xaios_status_t net_tcp_api_open(network_tcp_flow_t *flows,
                                const xaios_ip_addr_t *remote_addr,
                                uint16_t remote_port, uint16_t local_port,
                                uint32_t *out_flow_id);
xaios_status_t net_tcp_api_open_status(network_tcp_flow_t *flows,
                                       uint32_t flow_id);
xaios_status_t net_tcp_api_abort_flow(network_tcp_flow_t *flows,
                                      uint32_t flow_id);
xaios_status_t net_tcp_api_send(network_tcp_flow_t *flows, uint32_t flow_id,
                                const uint8_t *data, uint32_t len,
                                uint32_t *bytes_written);
xaios_status_t net_tcp_api_close_flow(network_tcp_flow_t *flows,
                                      uint32_t flow_id);
uint32_t net_tcp_api_recv(network_tcp_flow_t *flows, uint32_t flow_id,
                          uint8_t *buffer, uint32_t buffer_size);
int net_tcp_api_peer_closed(network_tcp_flow_t *flows, uint32_t flow_id);
int net_tcp_api_socket_ready(network_tcp_flow_t *flows, uint64_t sockfd,
                             uint8_t protocol, uint16_t port,
                             uint32_t listening);

/* ---- the receive handlers, network_stack_tcp_frame.c and _frame_v6.c ----
   The two public entry points a poll dispatch calls, with the table supplied
   by network_stack.c's public wrappers. */

xaios_status_t net_tcp_frame_process_v4(network_tcp_flow_t *flows,
                                        const uint8_t *frame,
                                        uint64_t frame_len);
xaios_status_t net_tcp_frame_process_v6(network_tcp_flow_t *flows,
                                        const uint8_t *frame,
                                        uint64_t frame_len);

#endif /* XAIOS_KERNEL_RUNTIME_NETWORK_STACK_TCP_TABLE_H */
