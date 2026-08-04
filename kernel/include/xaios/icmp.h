#ifndef XAIOS_ICMP_H
#define XAIOS_ICMP_H

#include <xaios/status.h>
#include <xaios/types.h>

#define XAIOS_ICMP_ECHO_REPLY 0U
#define XAIOS_ICMP_ECHO_REQUEST 8U

/* B2: ICMP error types */
#define XAIOS_ICMP_DEST_UNREACHABLE 3
#define XAIOS_ICMP_TIME_EXCEEDED 11
#define XAIOS_ICMP_CODE_PORT_UNREACHABLE 3
#define XAIOS_ICMP_CODE_HOST_UNREACHABLE 1
#define XAIOS_ICMP_CODE_NET_UNREACHABLE 0
#define XAIOS_ICMP_CODE_TTL_EXCEEDED 0
#define XAIOS_ICMP_MAX_ERROR_RATE 100

xaios_status_t icmp_build_echo_reply(uint8_t *frame, uint64_t *frame_len,
                                      const uint8_t src_mac[6],
                                      const uint8_t dst_mac[6],
                                      uint32_t src_ip, uint32_t dst_ip,
                                      const uint8_t *request_frame,
                                      uint64_t request_len);
xaios_status_t icmp_process_echo_request(const uint8_t *frame,
                                          uint64_t frame_len,
                                          uint16_t *identifier,
                                          uint16_t *sequence);

/* B2: error generation */
xaios_status_t icmp_build_dest_unreachable(uint8_t *frame, uint64_t *frame_len,
    const uint8_t src_mac[6], const uint8_t dst_mac[6],
    uint32_t src_ip, uint32_t dst_ip,
    uint8_t code, const uint8_t *orig_frame, uint64_t orig_len);
xaios_status_t icmp_build_time_exceeded(uint8_t *frame, uint64_t *frame_len,
    const uint8_t src_mac[6], const uint8_t dst_mac[6],
    uint32_t src_ip, uint32_t dst_ip,
    const uint8_t *orig_frame, uint64_t orig_len);
int icmp_error_can_send(void);
void icmp_error_tick(void);

void icmp_self_test(void);

#endif
