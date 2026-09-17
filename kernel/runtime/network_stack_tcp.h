/*
 * The shared row types of the TCP/UDP flow tables, and the declarations that
 * join the two halves of the TCP data plane to the stack that owns the tables.
 *
 * network_stack.c's own note called the TCP data plane the cheaper of its two
 * remaining cuts, next to the IPv4/IPv6 receive dispatch, and that is why this
 * is the cut that landed. The dispatch reaches both flow tables, the packet
 * descriptors, the queue rings, the ARP/ICMP/ICMPv6/NDP reply counters, the
 * IPv6 receive count and the ping state from inside the poll loop -- a dozen
 * accessors, and it would have to rewrite the loop's early-return shape. The
 * data plane below works on a flow row its caller already owns, so moving it
 * crosses with two counter increments and one copy-out, the local MAC.
 *
 * It is two files because it is two coherent halves: the per-flow state
 * machine (bounded out-of-order buffering, release, RTO, transmit window,
 * close handshake and ACK/SACK processing) in network_stack_tcp_flow.c, and
 * the segment builder and per-flow transmit path (options, the IPv4 and IPv6
 * builders, next-hop resolution) in network_stack_tcp_segment.c.
 *
 * State and locking. The flow tables themselves -- g_tcp_flows, g_udp_flows,
 * the drain cursor and every counter -- stay in network_stack.c. Nothing here
 * is an accessor that hands a pointer into file-scope state back out: every
 * function takes the row as a caller-owned `network_tcp_flow_t *` or
 * `network_udp_flow_t *`, or reads a value into a caller-owned local. Every
 * function here runs with the stack's guard, g_network_guard, already held
 * through network_stack_lock()/network_stack_unlock(); none of them takes a
 * lock of its own, so no critical section is widened, narrowed or split. The
 * two counter accessors at the bottom are the plain `++` the moved code made,
 * and carry the same "caller holds the guard" contract.
 */

#ifndef XAIOS_KERNEL_RUNTIME_NETWORK_STACK_TCP_H
#define XAIOS_KERNEL_RUNTIME_NETWORK_STACK_TCP_H

#include <xaios/ip_addr.h>
#include <xaios/network_stack.h>
#include <xaios/socket_buffer.h>

#include "network_stack_wire.h"

/* Frame and TCP constants the moved code and the stack both use. Each was
   defined in network_stack.c and is defined here now, so the two sides share
   one definition rather than repeating it. */

#define NETWORK_BUFFER_SIZE 1520U
#define NETWORK_TCP_RETRANSMIT_NS UINT64_C(1000000000)

#define NETWORK_TCP_FLAG_FIN 0x01U
#define NETWORK_TCP_FLAG_SYN 0x02U
#define NETWORK_TCP_FLAG_RST 0x04U
#define NETWORK_TCP_FLAG_PSH 0x08U
#define NETWORK_TCP_FLAG_ACK 0x10U

#define NETWORK_TCP_MSS 1400U
#define NETWORK_TCP_IPV6_MSS 1200U
#define NETWORK_TCP_IPV4_RX_MAX 1460U

#define TCP_TX_WINDOW_SEGMENTS 8U

/* Congestion control constant the ACK path uses. */
#define TCP_MAX_DUP_ACK   3U

typedef struct network_udp_flow {
  uint8_t active;
  uint32_t flow_id;
  uint32_t queue_id;
  uint32_t cell_id;
  uint16_t local_port;
  uint16_t remote_port;
  uint32_t local_address;
  uint32_t remote_address;
  xaios_ip_addr_t local_addr;
  xaios_ip_addr_t remote_addr;
  uint64_t packets_rx;
  uint64_t packets_tx;
  uint64_t last_seen_ns;
  uint8_t remote_mac[6];
  uint8_t remote_mac_valid;
  /* Data plane */
  socket_buffer_t *rx_buf;
} network_udp_flow_t;

typedef struct network_tcp_flow {
  xaios_network_flow_state_t state;
  uint32_t flow_id;
  uint32_t queue_id;
  uint32_t cell_id;
  uint16_t local_port;
  uint16_t remote_port;
  uint32_t remote_address;
  uint32_t local_address;
  xaios_ip_addr_t remote_addr;
  xaios_ip_addr_t local_addr;
  uint32_t remote_seq;
  uint32_t local_seq;
  uint64_t last_seen_ns;
  uint32_t retransmits;
  uint64_t packets_rx;
  uint64_t packets_tx;
  /* Data plane fields */
  socket_buffer_t *rx_buf;
  socket_buffer_t *tx_buf;
  uint32_t expected_seq;      /* next expected seq from peer */
  uint32_t next_send_seq;     /* next seq we send */
  uint16_t window_size;        /* advertised receive window */
  uint8_t  pending_synack;     /* SYN-ACK needs to be sent */
  uint8_t  pending_syn;        /* active-open SYN needs to be sent */
  uint8_t  pending_fin;        /* FIN needs to be sent */
  uint8_t  pending_ack;        /* ACK needs to be sent */
  uint8_t  close_requested;    /* local side called close */
  uint8_t  remote_mac[6];      /* cached peer MAC */
  uint8_t  remote_mac_valid;
  /* TCP retransmission state. */
  uint64_t rto_ns;             /* current retransmission timeout */
  uint8_t  in_retransmit;      /* currently in retransmission */
  /* Bounded out-of-order data buffering. */
  struct {
    uint32_t seq;
    uint16_t len;
    uint8_t  in_use;
    uint8_t  data[NETWORK_TCP_IPV4_RX_MAX];
  } ooo_buf[TCP_OOO_BUF_ENTRIES];
  /* TCP MSS negotiation. */
  uint16_t peer_mss;           /* received from peer */
  uint8_t  mss_parsed;         /* we parsed peer MSS */
  /* TCP window scaling. */
  uint8_t  ws_parsed;          /* peer sent window scale */
  uint8_t  peer_sack_permitted;
  uint8_t  peer_ws;            /* peer's window scale factor */
  uint8_t  our_ws;             /* our window scale factor */
  uint32_t peer_window;        /* latest scaled peer receive window */
  /* TCP congestion control. */
  uint32_t cwnd;               /* congestion window (bytes) */
  uint32_t ssthresh;           /* slow start threshold (bytes) */
  uint32_t dup_ack_count;      /* duplicate ACK counter */
  uint32_t highest_acked;      /* highest seq acked by peer */
  uint32_t in_flight;          /* bytes sent but not yet acked */
  uint8_t zero_window_probe;
  struct {
    uint32_t seq;
    uint16_t len;
    uint8_t in_use;
    uint8_t pending;
    uint8_t retransmitted;
    uint8_t retries;
    uint64_t first_tx_ns;
    uint64_t last_tx_ns;
    uint8_t data[NETWORK_TCP_MSS];
  } tx_segments[TCP_TX_WINDOW_SEGMENTS];
  uint64_t srtt_ns;
  uint64_t rttvar_ns;
  /* TCP keepalive. */
  uint64_t keepalive_last_rx_ns;
  uint64_t keepalive_last_tx_ns;
  uint32_t keepalive_probes_sent;
  uint8_t pending_keepalive;
  /* Reliable close handshake. */
  uint32_t fin_seq;
  uint32_t peer_fin_seq;
  uint64_t fin_last_tx_ns;
  uint32_t fin_retries;
  uint8_t fin_outstanding;
  uint8_t peer_fin_pending;
  uint8_t peer_fin_received;
} network_tcp_flow_t;

/* ---- the per-flow state machine, network_stack_tcp_flow.c ----
   Caller holds the stack guard; each function takes the flow row it operates
   on. No accessor returns a pointer into a table. */

uint32_t net_tcp_ooo_buffer_store(network_tcp_flow_t *flow, uint32_t seq,
                                  const uint8_t *data, uint32_t len,
                                  uint32_t expected_seq);
uint32_t net_tcp_ooo_buffer_drain(network_tcp_flow_t *flow);
void net_tcp_release_flow(network_tcp_flow_t *flow);
void net_tcp_release_udp_flow(network_udp_flow_t *flow);
void net_tcp_backoff_rto(network_tcp_flow_t *flow);
uint32_t net_tcp_tx_segment_count(const network_tcp_flow_t *flow);
int net_tcp_tx_has_pending(const network_tcp_flow_t *flow);
uint32_t net_tcp_tx_oldest_index(const network_tcp_flow_t *flow);
void net_tcp_queue_send_window(network_tcp_flow_t *flow);
void net_tcp_accept_peer_fin(network_tcp_flow_t *flow, uint64_t now_ns);
int net_tcp_acknowledge(network_tcp_flow_t *flow, uint32_t ack,
                        uint64_t now_ns);
uint32_t net_tcp_apply_sack_blocks(network_tcp_flow_t *flow,
                                   const tcp_parsed_options_t *options);

/* ---- the segment builder and transmit path, network_stack_tcp_segment.c ----
   Also under the caller's guard. network_stack_local_mac() is the existing
   public copy-out accessor the transmit path reads into a caller-owned local,
   in place of the file-scope g_local_mac it used to read directly. */

uint32_t net_tcp_build_options(const network_tcp_flow_t *flow, uint8_t flags,
                               uint8_t options[40]);
int net_tcp_resolve_mac(uint32_t dest_ip_net_order, uint8_t out_mac[6],
                        const uint8_t local_mac[6]);
xaios_status_t net_tcp_send_flow_segment(network_tcp_flow_t *flow, uint32_t seq,
                                         uint8_t flags, const uint8_t *payload,
                                         uint16_t payload_len);

/* ---- counters owned by network_stack.c ----
   The closed and retransmit counters stay beside the rest of the stack's
   counters, so the flow module writes them through these two increments
   rather than owning them. Caller holds the guard; each is the plain `++` it
   replaced, so no critical section changes shape. */

void net_tcp_note_closed(void);
void net_tcp_note_retransmit(void);

#endif /* XAIOS_KERNEL_RUNTIME_NETWORK_STACK_TCP_H */
