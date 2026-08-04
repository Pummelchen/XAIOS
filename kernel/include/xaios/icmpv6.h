#ifndef XAIOS_ICMPV6_H
#define XAIOS_ICMPV6_H

#include <xaios/ip_addr.h>
#include <xaios/status.h>
#include <xaios/types.h>

/* ICMPv6 message types */
#define XAIOS_ICMPV6_ECHO_REQUEST     128U
#define XAIOS_ICMPV6_ECHO_REPLY       129U
#define XAIOS_ICMPV6_NEIGHBOR_SOLICIT 135U
#define XAIOS_ICMPV6_NEIGHBOR_ADVERT  136U
#define XAIOS_ICMPV6_ROUTER_SOLICIT   133U
#define XAIOS_ICMPV6_ROUTER_ADVERT    134U

/* ---- C8: ICMPv6 Error Message Types and Codes ---- */
#define XAIOS_ICMPV6_DEST_UNREACHABLE  1U
#define XAIOS_ICMPV6_PACKET_TOO_BIG    2U
#define XAIOS_ICMPV6_TIME_EXCEEDED     3U
#define XAIOS_ICMPV6_PARAM_PROBLEM     4U

/* Destination Unreachable codes */
#define XAIOS_ICMPV6_CODE_NO_ROUTE         0U
#define XAIOS_ICMPV6_CODE_ADMIN_PROHIB     1U
#define XAIOS_ICMPV6_CODE_BEYOND_SCOPE     2U
#define XAIOS_ICMPV6_CODE_ADDR_UNREACHABLE 3U
#define XAIOS_ICMPV6_CODE_PORT_UNREACHABLE 4U

/* Time Exceeded codes */
#define XAIOS_ICMPV6_CODE_HOP_LIMIT_EXCEEDED 0U
#define XAIOS_ICMPV6_CODE_FRAG_REASSEMBLY    1U

/* Minimum frame: Ethernet(14) + IPv6(40) + ICMPv6(8) = 62 */
#define XAIOS_ICMPV6_MIN_FRAME        62U
/* Ethernet(14) + IPv6(40) + ICMPv6 header */
#define XAIOS_ICMPV6_OFFSET           54U

/* Max bytes of original packet to include in ICMPv6 error (RFC 4443: at least as much as fits without min MTU violation) */
#define XAIOS_ICMPV6_ERROR_EMBED_LEN 128U

/* Rate limit: max ICMPv6 error messages per second (shared counter with IPv4 ICMP) */
#define XAIOS_ICMPV6_RATE_MAX 100U

/* ---- Existing function declarations ---- */
xaios_status_t icmpv6_process_echo_request(
    const uint8_t *frame, uint64_t frame_len,
    uint16_t *identifier, uint16_t *sequence,
    xaios_ip_addr_t *src, xaios_ip_addr_t *dst);

xaios_status_t icmpv6_build_echo_reply(
    uint8_t *frame, uint64_t *frame_len,
    const uint8_t src_mac[6], const uint8_t dst_mac[6],
    const xaios_ip_addr_t *src_ip, const xaios_ip_addr_t *dst_ip,
    const uint8_t *request_frame, uint64_t request_len);

xaios_status_t icmpv6_build_neighbor_advertisement(
    uint8_t *frame, uint64_t *frame_len,
    const uint8_t src_mac[6], const uint8_t dst_mac[6],
    const xaios_ip_addr_t *src_ip, const xaios_ip_addr_t *dst_ip,
    const xaios_ip_addr_t *target,
    const uint8_t *ns_frame, uint64_t ns_len);

/* ---- C8: ICMPv6 Error Generation ---- */
/* Build an ICMPv6 Destination Unreachable message.
 * frame: output buffer for the full Ethernet+IPv6+ICMPv6 frame.
 * frame_len: in/out - length of the frame.
 * src_mac/dst_mac: Ethernet addresses.
 * src_ip/dst_ip: IPv6 addresses (src = original dst, dst = original src).
 * code: one of XAIOS_ICMPV6_CODE_*.
 * orig_frame: the original problematic packet.
 * orig_len: length of original packet (up to XAIOS_ICMPV6_ERROR_EMBED_LEN bytes used).
 */
xaios_status_t icmpv6_build_dest_unreachable(uint8_t *frame, uint64_t *frame_len,
    const uint8_t src_mac[6], const uint8_t dst_mac[6],
    const xaios_ip_addr_t *src_ip, const xaios_ip_addr_t *dst_ip,
    uint8_t code, const uint8_t *orig_frame, uint64_t orig_len);

/* Check if we can send an ICMPv6 error (rate limited).
 * Returns 1 if allowed, 0 if rate limited.
 * Uses a shared counter with IPv4 ICMP error generation.
 */
int icmpv6_error_can_send(void);

/* Build an ICMPv6 Time Exceeded message (code = hop limit exceeded).
 * Same signature pattern as dest_unreachable but for Time Exceeded.
 */
xaios_status_t icmpv6_build_time_exceeded(uint8_t *frame, uint64_t *frame_len,
    const uint8_t src_mac[6], const uint8_t dst_mac[6],
    const xaios_ip_addr_t *src_ip, const xaios_ip_addr_t *dst_ip,
    uint8_t code, const uint8_t *orig_frame, uint64_t orig_len);

void icmpv6_self_test(void);

#endif /* XAIOS_ICMPV6_H */
