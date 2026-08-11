#ifndef XAIOS_IPV6_H
#define XAIOS_IPV6_H

#include <xaios/ip_addr.h>
#include <xaios/status.h>
#include <xaios/types.h>

#define XAIOS_IPV6_HEADER_SIZE       40U
#define XAIOS_IPV6_VERSION_TC_FLOW   0x60000000U /* version=6, TC=0, flow=0 */
#define XAIOS_IPV6_ETHERTYPE         0x86DDU
#define XAIOS_IPV6_NEXT_ICMPV6       58U
#define XAIOS_IPV6_NEXT_TCP          6U
#define XAIOS_IPV6_NEXT_UDP         17U
#define XAIOS_IPV6_DEFAULT_HOP_LIMIT 64U

/* Extension header next_header values */
#define XAIOS_IPV6_NEXT_HOP_BY_HOP 0U
#define XAIOS_IPV6_NEXT_ROUTING    43U
#define XAIOS_IPV6_NEXT_FRAGMENT    44U
#define XAIOS_IPV6_NEXT_AH         51U
#define XAIOS_IPV6_NEXT_ESP        50U
#define XAIOS_IPV6_NEXT_DEST       60U

/* Fragment header structure (8 bytes) */
#define XAIOS_IPV6_FRAG_HEADER_SIZE 8U

/* Link-local prefix fe80::/10 */
#define XAIOS_IPV6_LINK_LOCAL_BYTE0  0xFEU
#define XAIOS_IPV6_LINK_LOCAL_BYTE1  0x80U

/* All-routers multicast: ff02::2 */
#define XAIOS_IPV6_MCAST_ALL_ROUTERS 0U
/* All-nodes multicast: ff02::1 */
#define XAIOS_IPV6_MCAST_ALL_NODES   0U

/* ICMPv6 types for extension headers */
#define XAIOS_IPV6_NEXT_ICMPV6_DEST_UNREACHABLE 1U
#define XAIOS_IPV6_NEXT_ICMPV6_PACKET_TOO_BIG   2U
#define XAIOS_IPV6_NEXT_ICMPV6_TIME_EXCEEDED     3U
#define XAIOS_IPV6_NEXT_ICMPV6_PARAM_PROBLEM     4U

/* IPv6 address families and constants */
#define XAIOS_IPV6_ADDR_LEN 16U

/* Max frame size for IPv6 (MTU = 1280 min, 1500 typical) */
#define XAIOS_IPV6_MIN_MTU 1280U
/* Max extension headers to walk before giving up */
#define XAIOS_IPV6_MAX_EXTENSION_CHAIN_DEPTH 16U
#define XAIOS_IPV6_FRAG_TIMEOUT_NS UINT64_C(60000000000)
#define XAIOS_IPV6_MAX_REASSEMBLED_PAYLOAD 1466U

/* Threshold for ICMPv6 error generation rate limit (shared with IPv4) */
#define XAIOS_ICMPV6_RATE_LIMIT_MAX_PER_SECOND 100U

void ipv6_build_header(uint8_t *hdr, uint16_t payload_length,
                       uint8_t next_header,
                       const xaios_ip_addr_t *src,
                       const xaios_ip_addr_t *dst);

int ipv6_parse_header(const uint8_t *hdr, uint64_t hdr_len,
                      uint16_t *payload_length, uint8_t *next_header,
                      xaios_ip_addr_t *src, xaios_ip_addr_t *dst);

uint16_t ipv6_pseudo_checksum(const xaios_ip_addr_t *src,
                               const xaios_ip_addr_t *dst,
                               uint8_t next_header,
                               uint32_t upper_layer_length,
                               const uint8_t *payload,
                               uint32_t payload_len);

/* Derive link-local address from MAC (EUI-64) */
void ipv6_link_local_from_mac(xaios_ip_addr_t *addr, const uint8_t mac[6]);

/* ---- C1: IPv6 Extension Header Parsing ---- */
/* Walk extension header chain to find final next_header and upper layer payload.
 * Returns 0 on success, -1 on parse failure.
 * out_next_hdr: final next_header value (real upper layer protocol).
 * out_upper_layer: pointer to start of upper layer payload.
 * out_upper_len: length of upper layer payload (remaining bytes after extension chain).
 */
int ipv6_walk_extension_headers(const uint8_t *ip6_hdr, uint64_t hdr_len,
                                 uint8_t *out_next_hdr,
                                 const uint8_t **out_upper_layer,
                                 uint32_t *out_upper_len);

/* ---- C2: IPv6 Fragmentation ---- */
/* Check if frame has a Fragment header (next_header == 44) */
int ipv6_is_fragment_v6(const uint8_t *frame, uint64_t frame_len);

/* Fragment a complete IPv6 packet into fragments.
 * out_buf: buffer to write fragments into.
 * out_len: total length of all fragments written.
 * out_capacity: max bytes of output buffer.
 * Returns XAIOS_OK on success.
 */
xaios_status_t ipv6_fragment_v6(const uint8_t *frame, uint64_t frame_len,
                                 uint8_t *out_buf, uint64_t *out_len,
                                 uint64_t out_capacity);

/* Reassemble a fragmented IPv6 packet into a complete frame.
 * frame: buffer containing fragments (reassembled in place).
 * frame_len: in/out - length of the reassembled packet.
 * Returns XAIOS_OK on success, XAIOS_ERR_INVALID on parse error.
 */
xaios_status_t ipv6_reassemble_v6(uint8_t *frame, uint64_t *frame_len);
void ipv6_frag_init(void);

/* ---- Self-test ---- */
void ipv6_self_test(void);

#endif /* XAIOS_IPV6_H */
