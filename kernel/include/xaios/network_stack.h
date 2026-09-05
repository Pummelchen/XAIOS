#ifndef XAIOS_NETWORK_STACK_H
#define XAIOS_NETWORK_STACK_H

#include <xaios/ip_addr.h>
#include <xaios/status.h>
#include <xaios/types.h>

#define XAIOS_NETWORK_MAX_QUEUE_BINDINGS 4U
#define XAIOS_NETWORK_QUEUE_ID_INVALID UINT32_C(0xffffffff)
#define XAIOS_NETWORK_PROTOCOL_UDP UINT64_C(17)
#define XAIOS_NETWORK_PROTOCOL_TCP UINT64_C(6)

typedef enum xaios_network_ping_state {
  XAIOS_NETWORK_PING_IDLE = 0,
  XAIOS_NETWORK_PING_PENDING = 1,
  XAIOS_NETWORK_PING_REPLIED = 2,
  XAIOS_NETWORK_PING_TIMEOUT = 3,
  XAIOS_NETWORK_PING_FAILED = 4,
} xaios_network_ping_state_t;

typedef struct xaios_network_ping_status {
  xaios_network_ping_state_t state;
  uint32_t target_ip;
  uint32_t attempts;
  uint64_t round_trip_ns;
  xaios_status_t last_error;
} xaios_network_ping_status_t;

typedef enum xaios_network_flow_state {
  XAIOS_NETWORK_FLOW_FREE = 0,
  XAIOS_NETWORK_FLOW_SYN_RECV = 1,
  XAIOS_NETWORK_FLOW_ESTABLISHED = 2,
  XAIOS_NETWORK_FLOW_CLOSED = 3,
  XAIOS_NETWORK_FLOW_FIN_WAIT = 4,
  XAIOS_NETWORK_FLOW_FIN_WAIT_2 = 8,
  XAIOS_NETWORK_FLOW_CLOSE_WAIT = 5,
  XAIOS_NETWORK_FLOW_LAST_ACK = 6,
  XAIOS_NETWORK_FLOW_TIME_WAIT = 7,
  XAIOS_NETWORK_FLOW_SYN_SENT = 9,
} xaios_network_flow_state_t;

void network_stack_init(void);
xaios_status_t network_stack_bind_queue(uint32_t cell_id, uint32_t queue_id,
                                       uint32_t core_mask);
xaios_status_t network_stack_release_queue(uint32_t queue_id, uint32_t cell_id);
xaios_status_t network_stack_process_udp_frame(const uint8_t *frame,
                                            uint64_t frame_len);
xaios_status_t network_stack_process_tcp_frame(const uint8_t *frame,
                                            uint64_t frame_len);
xaios_status_t network_stack_process_udp_frame_v6(const uint8_t *frame,
                                                  uint64_t frame_len);
xaios_status_t network_stack_process_tcp_frame_v6(const uint8_t *frame,
                                                  uint64_t frame_len);
xaios_status_t network_stack_app_udp_echo(const uint8_t *payload,
                                         uint64_t payload_len,
                                         uint64_t *echoed_bytes);
xaios_status_t network_stack_app_tcp_connect(uint64_t *round_trips);
xaios_status_t network_stack_tcp_open(const xaios_ip_addr_t *remote_addr,
                                      uint16_t remote_port,
                                      uint16_t local_port,
                                      uint32_t *out_flow_id);
xaios_status_t network_stack_tcp_open_status(uint32_t flow_id);
xaios_status_t network_stack_tcp_abort_flow(uint32_t flow_id);
xaios_status_t network_stack_external_session(uint64_t protocol, uint64_t port,
                                             const uint8_t *payload,
                                             uint64_t payload_len,
                                             char *output,
                                             uint64_t output_capacity,
                                             uint64_t *output_bytes);
uint64_t network_stack_expire_udp_flows(uint64_t now_ns);
uint64_t network_stack_retransmit_tcp_flows(uint64_t now_ns);
uint64_t network_stack_expire_tcp_flows(uint64_t now_ns);

uint64_t network_stack_udp_tx_count(void);
uint64_t network_stack_udp_rx_count(void);
uint64_t network_stack_udp_malformed_count(void);
uint64_t network_stack_udp_dropped_count(void);
uint64_t network_stack_udp_flow_count(void);
uint64_t network_stack_udp_flow_hit_count(void);
uint64_t network_stack_udp_expired_count(void);
uint64_t network_stack_tcp_connections(void);
uint64_t network_stack_tcp_handshake_count(void);
uint64_t network_stack_tcp_reset_count(void);
uint64_t network_stack_tcp_timeout_count(void);
uint64_t network_stack_tcp_retransmit_count(void);
uint64_t network_stack_tcp_established_count(void);
uint64_t network_stack_tcp_closed_count(void);
uint64_t network_stack_queue_bindings(void);
uint64_t network_stack_rx_packet_count(void);
uint64_t network_stack_tx_packet_count(void);
uint64_t network_stack_packet_drop_count(void);
uint64_t network_stack_packet_lifecycle_count(void);
uint64_t network_stack_queue_rx_enqueue_count(void);
uint64_t network_stack_queue_tx_enqueue_count(void);
uint64_t network_stack_queue_completion_count(void);
uint64_t network_stack_queue_backpressure_drop_count(void);
uint64_t network_stack_flow_core_mismatch_count(void);
uint64_t network_stack_udp_latency_p50_ns(void);
uint64_t network_stack_udp_latency_p95_ns(void);
uint64_t network_stack_udp_latency_p99_ns(void);
uint64_t network_stack_udp_latency_p999_ns(void);
uint64_t network_stack_tcp_latency_p50_ns(void);
uint64_t network_stack_tcp_latency_p95_ns(void);
uint64_t network_stack_tcp_latency_p99_ns(void);
uint64_t network_stack_tcp_latency_p999_ns(void);
void network_stack_self_test(void);

/* Persistent network mode: real TX/RX via VirtIO-net */
void network_init_persistent(void);
/* The resolver runs inside this stack: it calls tcp_open, send, recv and close
   to carry queries, and network_poll_tick drives its timers. Two guards across
   that boundary would be a lock-order inversion waiting for one added call, so
   the resolver takes this one. Reentrant, so nesting either way is safe. */
void network_stack_lock(void);
void network_stack_unlock(void);

void network_poll_tick(void);
uint64_t network_poll_tick_count(void);
uint64_t network_icmp_reply_count(void);
uint64_t network_arp_reply_sent_count(void);
uint64_t network_icmpv6_reply_count(void);
uint64_t network_ndp_reply_count(void);
uint64_t network_ipv6_rx_count(void);
uint32_t network_stack_local_ipv4(void);
/* Solicit a router and poll until a global IPv6 address is configured, or the
   timeout expires. Returns XAIOS_ERR_NOT_FOUND on a link with no router
   advertising a prefix, which leaves the link-local address in place. */
xaios_status_t network_wait_for_ipv6_slaac(uint64_t timeout_ns);
xaios_status_t network_stack_local_mac(uint8_t mac[6]);
/* Returns the current SLAAC global-unicast address, never link-local or ULA. */
xaios_status_t network_stack_local_public_ipv6(xaios_ip_addr_t *address);
/* The address this host sends IPv6 from: the one configured from a router
   advertisement when there is one, whether globally routable or unique-local,
   and otherwise the link-local address. */
xaios_status_t network_stack_local_ipv6(xaios_ip_addr_t *address);

/* Install an address obtained from a DHCPv6 server. Separate from the SLAAC
   path because a lease and a derived address are different things with
   different obligations, even though both end up on the same send path. */
xaios_status_t network_stack_adopt_dhcpv6(const xaios_ip_addr_t *address,
                                          uint32_t valid_lifetime_s);
xaios_status_t network_stack_ping_start(uint32_t target_ip);
xaios_network_ping_status_t network_stack_ping_status(void);

/* Data plane: TCP send/close */
xaios_status_t network_stack_tcp_send(uint32_t flow_id, const uint8_t *data,
                                       uint32_t len, uint32_t *bytes_written);
xaios_status_t network_stack_tcp_close_flow(uint32_t flow_id);
xaios_status_t network_stack_udp_send(uint32_t flow_id, const uint8_t *data,
                                       uint32_t len, uint32_t *bytes_written);
uint32_t network_stack_udp_recv(uint64_t sockfd, uint8_t *buffer,
                                uint32_t buffer_size,
                                xaios_ip_addr_t *source_addr,
                                uint16_t *source_port,
                                uint32_t *flow_id);
uint32_t network_stack_tcp_recv(uint32_t flow_id, uint8_t *buffer,
                                  uint32_t buffer_size);
int network_stack_tcp_peer_closed(uint32_t flow_id);
/* Bumped wherever a socket could have become readable: bytes into a receive
   buffer, a connection onto a listener's backlog, a peer closing. A waiter
   that has seen this value knows the answer it computed is still current,
   which is worth a great deal more than the counter costs -- deriving it
   walks the socket table and then the flow table, per socket, under two
   locks. Advisory: a path that forgets to bump delays a wake to the wait's
   housekeeping cadence, it does not lose it. */
void network_readiness_note(void);
uint64_t network_readiness_generation(void);
/* Whether a non-blocking call on this socket would return something: a
   queued connection or datagram on a listener, bytes on a connected
   stream, or a peer that has closed. */
int network_stack_socket_ready(uint64_t sockfd, uint8_t protocol,
                               uint16_t port, uint32_t listening);

/* Listener registry */
void network_stack_register_listener(uint16_t port, uint64_t sockfd);
void network_stack_unregister_listener(uint16_t port);
int  network_stack_has_listener(uint16_t port);
void network_stack_register_udp_listener(uint16_t port, uint64_t sockfd);
void network_stack_unregister_udp_listener(uint16_t port);

/* Accept queue */
xaios_status_t network_stack_accept_connection(uint16_t listen_port,
                                                uint32_t *out_flow_id,
                                                uint32_t *out_peer_ip,
                                                uint16_t *out_peer_port,
                                                xaios_ip_addr_t *out_peer_addr);

/* Socket-to-flow mapping */
typedef struct socket_flow_mapping {
  uint64_t sockfd;
  uint32_t flow_id;
  uint8_t  protocol;   /* 6=TCP, 17=UDP */
  uint32_t active;
} socket_flow_mapping_t;
void network_stack_map_socket(uint64_t sockfd, uint32_t flow_id,
                                uint8_t protocol);
/* Copies the mapping and returns non-zero when one exists. Never hands out a
   pointer into the table: see the definition. */
int network_stack_get_socket_mapping(uint64_t sockfd,
                                     socket_flow_mapping_t *out);
void network_stack_unmap_socket(uint64_t sockfd);

#endif
