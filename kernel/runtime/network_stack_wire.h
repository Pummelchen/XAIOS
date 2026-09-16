/*
 * Wire-format helpers for the network stack: the on-the-wire structures, the
 * byte-order readers and writers, and the frame and segment parsers.
 *
 * Split out of network_stack.c, which was 5900 lines. These are the functions
 * that touch no file-scope state of their own -- they read a frame and report
 * what is in it -- so they move without carrying any of the stack's tables or
 * counters with them. Everything else in that file does touch them, and the
 * note at the top of it explains why the rest has not been cut the same way.
 */

#ifndef XAIOS_KERNEL_RUNTIME_NETWORK_STACK_WIRE_H
#define XAIOS_KERNEL_RUNTIME_NETWORK_STACK_WIRE_H

#include <xaios/ip_addr.h>
#include <xaios/ipv4.h>

/* Wire constants the moved code and the stack both use. */
#define NETWORK_ETHERTYPE_IPV4 UINT16_C(0x0800)
#define NETWORK_ETHERTYPE_IPV6 UINT16_C(0x86DD)
#define NETWORK_IP_PROTO_UDP UINT8_C(17)
#define NETWORK_IP_PROTO_TCP UINT8_C(6)
#define NETWORK_MAX_SAMPLES 64U
#define TCP_OPT_END       0U
#define TCP_OPT_NOP       1U
#define TCP_OPT_MSS       2U
#define TCP_OPT_WSCALE    3U
#define TCP_OPT_SACK_PERMITTED 4U
#define TCP_OPT_SACK      5U
#define TCP_OOO_BUF_ENTRIES 4U

typedef struct tcp_parsed_options {
  uint16_t mss;
  uint8_t window_scale;
  uint8_t sack_permitted;
  uint8_t sack_count;
  uint32_t sack_left[TCP_OOO_BUF_ENTRIES];
  uint32_t sack_right[TCP_OOO_BUF_ENTRIES];
} tcp_parsed_options_t;

typedef struct network_ip4_header {
  uint8_t version_ihl;
  uint8_t tos;
  uint16_t total_length;
  uint16_t id;
  uint16_t flags_fragment_offset;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t checksum;
  uint32_t source;
  uint32_t destination;
} network_ip4_header_t;

typedef struct network_ip6_header {
  uint8_t  version_tc_flow[4];
  uint16_t payload_length;
  uint8_t  next_header;
  uint8_t  hop_limit;
  uint8_t  source[16];
  uint8_t  destination[16];
} network_ip6_header_t;

typedef struct network_udp_header {
  uint16_t source_port;
  uint16_t dest_port;
  uint16_t length;
  uint16_t checksum;
} network_udp_header_t;

typedef struct network_tcp_header {
  uint16_t source_port;
  uint16_t dest_port;
  uint32_t seq;
  uint32_t ack;
  uint8_t data_offset_reserved;
  uint8_t flags;
  uint16_t window_size;
  uint16_t checksum;
  uint16_t urgent_pointer;
} network_tcp_header_t;

int net_wire_tcp_seq_before(uint32_t left, uint32_t right);
int net_wire_tcp_seq_after(uint32_t left, uint32_t right);
uint16_t net_wire_read_u16_be(const uint8_t *bytes);
uint32_t net_wire_read_u32_be(const uint8_t *bytes);
void net_wire_write_be16(uint8_t *dst, uint16_t value);
void net_wire_write_be32(uint8_t *dst, uint32_t value);
uint32_t net_wire_tcp_generate_isn(uint32_t flow_id);
uint32_t net_wire_tcp_scaled_window(uint16_t window, uint8_t shift);
int net_wire_parse_tcp_options(const uint8_t *tcp_hdr, uint32_t hdr_bytes,
                             tcp_parsed_options_t *options);
uint64_t net_wire_percentile(uint64_t *samples, uint32_t count, uint32_t p);
void net_wire_bytes_zero(void *buffer, uint64_t size);
uint32_t net_wire_ip4_addr_host_order(uint32_t network_order_address);
int net_wire_eth_frame_has_ipv4(const uint8_t *frame, uint64_t frame_len);
int net_wire_parse_udp(const uint8_t *frame, uint64_t frame_len,
                     uint16_t *src_port, uint16_t *dst_port,
                     uint16_t *payload_len, uint32_t *src_address,
                     uint32_t *dst_address);
int net_wire_parse_tcp(const uint8_t *frame, uint64_t frame_len, uint16_t *src_port,
                    uint16_t *dst_port, uint32_t *seq, uint32_t *ack,
                    uint8_t *flags);
int net_wire_eth_frame_has_ipv6(const uint8_t *frame, uint64_t frame_len);
int net_wire_parse_udp_v6(const uint8_t *frame, uint64_t frame_len,
                        uint16_t *src_port, uint16_t *dst_port,
                        uint16_t *payload_len,
                        xaios_ip_addr_t *src_addr, xaios_ip_addr_t *dst_addr);
int net_wire_parse_tcp_v6(const uint8_t *frame, uint64_t frame_len,
                        uint16_t *src_port, uint16_t *dst_port,
                        uint32_t *seq, uint32_t *ack_val, uint8_t *flags,
                        xaios_ip_addr_t *src_addr, xaios_ip_addr_t *dst_addr);

#endif /* XAIOS_KERNEL_RUNTIME_NETWORK_STACK_WIRE_H */
