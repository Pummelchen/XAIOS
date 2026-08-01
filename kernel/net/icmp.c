#include <xaios/assert.h>
#include <xaios/icmp.h>
#include <xaios/ipv4.h>
#include <xaios/klog.h>

/* B2: Rate limiting */
static uint64_t g_icmp_error_count;
static uint64_t g_icmp_error_last_ns;

static void bytes_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0; i < size; ++i) { bytes[i] = 0; }
}

static void put_be16(uint8_t *dst, uint16_t value) {
  dst[0] = (uint8_t)(value >> 8U);
  dst[1] = (uint8_t)value;
}



static uint16_t get_be16(const uint8_t *src) {
  return (uint16_t)(((uint16_t)src[0] << 8U) | src[1]);
}

static void bytes_copy(void *dst, const void *src, uint64_t n) {
  uint8_t *d = (uint8_t *)dst;
  const uint8_t *s = (const uint8_t *)src;
  for (uint64_t i = 0; i < n; ++i) { d[i] = s[i]; }
}

/* B2: Check if we can send an ICMP error (rate limit: max 100/sec) */
int icmp_error_can_send(void) {
  extern uint64_t timer_now_ns(void);
  uint64_t now = timer_now_ns();
  uint64_t elapsed = now - g_icmp_error_last_ns;

  /* Reset counter if more than 1 second has passed */
  if (elapsed >= UINT64_C(1000000000)) {
    g_icmp_error_count = 0;
    g_icmp_error_last_ns = now;
    return 1;
  }

  if (g_icmp_error_count < XAIOS_ICMP_MAX_ERROR_RATE) {
    g_icmp_error_count++;
    return 1;
  }

  return 0;
}

/* B2: Tick — called periodically to decay the error counter */
void icmp_error_tick(void) {
  extern uint64_t timer_now_ns(void);
  uint64_t now = timer_now_ns();
  uint64_t elapsed = now - g_icmp_error_last_ns;

  if (elapsed >= UINT64_C(1000000000)) {
    g_icmp_error_count = 0;
    g_icmp_error_last_ns = now;
  }
}

/* Build an ICMP error containing the original IPv4 header and up to eight bytes
 * of its payload, as required by RFC 792. */
static xaios_status_t icmp_build_error(uint8_t *frame, uint64_t *frame_len,
    const uint8_t src_mac[6], const uint8_t dst_mac[6],
    uint32_t src_ip, uint32_t dst_ip,
    uint8_t type, uint8_t code, const uint8_t *orig_frame, uint64_t orig_len) {
  if (frame == 0 || frame_len == 0 || src_mac == 0 || dst_mac == 0 ||
      orig_frame == 0 || orig_len < 34U) {
    return XAIOS_ERR_INVALID;
  }

  uint8_t ip_header_len = (uint8_t)((orig_frame[14] & 0x0fU) * 4U);
  uint16_t ip_total_len = get_be16(orig_frame + 16);
  if ((orig_frame[14] >> 4U) != 4U || ip_header_len < XAIOS_IPV4_HEADER_SIZE ||
      ip_total_len < ip_header_len || 14U + ip_total_len > orig_len) {
    return XAIOS_ERR_INVALID;
  }

  uint64_t quote_len = (uint64_t)ip_header_len + 8U;
  if (quote_len > ip_total_len) {
    quote_len = ip_total_len;
  }
  uint64_t icmp_len = 8U + quote_len;
  uint64_t total = 14U + XAIOS_IPV4_HEADER_SIZE + icmp_len;

  bytes_zero(frame, total);

  for (uint32_t i = 0; i < 6; ++i) {
    frame[i] = dst_mac[i];
    frame[6 + i] = src_mac[i];
  }
  put_be16(frame + 12, 0x0800);

  ipv4_build_header(frame + 14,
                    (uint16_t)(XAIOS_IPV4_HEADER_SIZE + icmp_len),
                    XAIOS_IPV4_PROTO_ICMP, src_ip, dst_ip);

  uint8_t *icmp = frame + 34U;
  icmp[0] = type;
  icmp[1] = code;
  put_be16(icmp + 2, 0);
  put_be16(icmp + 4, 0);
  put_be16(icmp + 6, 0);

  bytes_copy(icmp + 8, orig_frame + 14U, quote_len);

  uint16_t cksum = ipv4_checksum(icmp, (uint32_t)icmp_len);
  put_be16(icmp + 2, cksum);

  *frame_len = total;
  return XAIOS_OK;
}

/* B2: Build ICMP Destination Unreachable message */
xaios_status_t icmp_build_dest_unreachable(uint8_t *frame, uint64_t *frame_len,
    const uint8_t src_mac[6], const uint8_t dst_mac[6],
    uint32_t src_ip, uint32_t dst_ip,
    uint8_t code, const uint8_t *orig_frame, uint64_t orig_len) {
  return icmp_build_error(frame, frame_len, src_mac, dst_mac, src_ip, dst_ip,
                          XAIOS_ICMP_DEST_UNREACHABLE, code,
                          orig_frame, orig_len);
}

/* B2: Build ICMP Time Exceeded message */
xaios_status_t icmp_build_time_exceeded(uint8_t *frame, uint64_t *frame_len,
    const uint8_t src_mac[6], const uint8_t dst_mac[6],
    uint32_t src_ip, uint32_t dst_ip,
    const uint8_t *orig_frame, uint64_t orig_len) {
  return icmp_build_error(frame, frame_len, src_mac, dst_mac, src_ip, dst_ip,
                          XAIOS_ICMP_TIME_EXCEEDED,
                          XAIOS_ICMP_CODE_TTL_EXCEEDED,
                          orig_frame, orig_len);
}

xaios_status_t icmp_process_echo_request(const uint8_t *frame,
                                          uint64_t frame_len,
                                          uint16_t *identifier,
                                          uint16_t *sequence) {
  if (frame == 0 || frame_len < 34U || identifier == 0 || sequence == 0) {
    return XAIOS_ERR_INVALID;
  }
  if (frame_len < 42U) { return XAIOS_ERR_INVALID; }
  if (get_be16(frame + 12) != 0x0800) { return XAIOS_ERR_INVALID; }

  const uint8_t *icmp = frame + 34U;
  uint8_t type = icmp[0];
  if (type != XAIOS_ICMP_ECHO_REQUEST) { return XAIOS_ERR_INVALID; }

  uint16_t ip_total_len = get_be16(frame + 16);
  uint64_t icmp_len = (uint64_t)ip_total_len - XAIOS_IPV4_HEADER_SIZE;
  if (34U + icmp_len > frame_len) { return XAIOS_ERR_INVALID; }

  uint16_t cksum = ipv4_checksum(icmp, (uint32_t)icmp_len);
  if (cksum != 0) { return XAIOS_ERR_INVALID; }

  *identifier = get_be16(icmp + 4);
  *sequence = get_be16(icmp + 6);
  return XAIOS_OK;
}

xaios_status_t icmp_build_echo_reply(uint8_t *frame, uint64_t *frame_len,
                                      const uint8_t src_mac[6],
                                      const uint8_t dst_mac[6],
                                      uint32_t src_ip, uint32_t dst_ip,
                                      const uint8_t *request_frame,
                                      uint64_t request_len) {
  if (frame == 0 || frame_len == 0 || src_mac == 0 || dst_mac == 0 ||
      request_frame == 0 || request_len < 42U) {
    return XAIOS_ERR_INVALID;
  }

  const uint8_t *req_icmp = request_frame + 34U;
  uint16_t ip_total_len = get_be16(request_frame + 16);
  uint64_t icmp_len = (uint64_t)ip_total_len - XAIOS_IPV4_HEADER_SIZE;
  if (34U + icmp_len > request_len || icmp_len < 8U) {
    return XAIOS_ERR_INVALID;
  }

  uint64_t total = 14U + XAIOS_IPV4_HEADER_SIZE + icmp_len;
  bytes_zero(frame, total);

  for (uint32_t i = 0; i < 6; ++i) {
    frame[i] = dst_mac[i];
    frame[6 + i] = src_mac[i];
  }
  put_be16(frame + 12, 0x0800);

  ipv4_build_header(frame + 14, (uint16_t)(XAIOS_IPV4_HEADER_SIZE + icmp_len),
                    XAIOS_IPV4_PROTO_ICMP, src_ip, dst_ip);

  uint8_t *icmp = frame + 34U;
  icmp[0] = XAIOS_ICMP_ECHO_REPLY;
  icmp[1] = 0;
  put_be16(icmp + 2, 0);
  icmp[4] = req_icmp[4];
  icmp[5] = req_icmp[5];
  icmp[6] = req_icmp[6];
  icmp[7] = req_icmp[7];
  for (uint64_t i = 8; i < icmp_len; ++i) { icmp[i] = req_icmp[i]; }

  uint16_t cksum = ipv4_checksum(icmp, (uint32_t)icmp_len);
  put_be16(icmp + 2, cksum);

  *frame_len = total;
  return XAIOS_OK;
}

void icmp_self_test(void) {
  uint8_t request[64];
  bytes_zero(request, sizeof(request));
  uint8_t src_mac[6] = {0x52, 0x54, 0x00, 0x12, 0x35, 0x02};
  uint8_t dst_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x15};
  for (uint32_t i = 0; i < 6; ++i) {
    request[i] = dst_mac[i];
    request[6 + i] = src_mac[i];
  }
  put_be16(request + 12, 0x0800);
  ipv4_build_header(request + 14, 28, XAIOS_IPV4_PROTO_ICMP, 0x0a000202,
                     0x0a00020f);
  request[34] = XAIOS_ICMP_ECHO_REQUEST;
  request[35] = 0;
  put_be16(request + 36, 0);
  put_be16(request + 38, 0x1234);
  put_be16(request + 40, 0x0001);
  uint16_t cksum = ipv4_checksum(request + 34, 8);
  put_be16(request + 36, cksum);

  uint16_t id = 0, seq = 0;
  kassert(icmp_process_echo_request(request, 42, &id, &seq) == XAIOS_OK);
  kassert(id == 0x1234);
  kassert(seq == 0x0001);

  uint8_t reply[64];
  uint64_t reply_len = 0;
  kassert(icmp_build_echo_reply(reply, &reply_len, dst_mac, src_mac,
                                 0x0a00020f, 0x0a000202, request, 42) == XAIOS_OK);
  kassert(reply_len == 42);
  kassert(reply[34] == XAIOS_ICMP_ECHO_REPLY);
  kassert(ipv4_checksum(reply + 34, 8) == 0);

  /* B2: Test error generation */
  uint8_t err_frame[1520];
  uint64_t err_len = 0;
  kassert(icmp_build_dest_unreachable(err_frame, &err_len, dst_mac, src_mac,
      0x0a00020f, 0x0a000202, XAIOS_ICMP_CODE_PORT_UNREACHABLE,
      request, 42) == XAIOS_OK);
  kassert(err_len == 70U);
  kassert(err_frame[34] == XAIOS_ICMP_DEST_UNREACHABLE);
  kassert(err_frame[35] == XAIOS_ICMP_CODE_PORT_UNREACHABLE);
  kassert(ipv4_checksum(err_frame + 34, 36U) == 0);

  /* B2: Test Time Exceeded */
  err_len = 0;
  kassert(icmp_build_time_exceeded(err_frame, &err_len, dst_mac, src_mac,
      0x0a00020f, 0x0a000202, request, 42) == XAIOS_OK);
  kassert(err_len == 70U);
  kassert(err_frame[34] == XAIOS_ICMP_TIME_EXCEEDED);
  kassert(err_frame[35] == XAIOS_ICMP_CODE_TTL_EXCEEDED);
  kassert(ipv4_checksum(err_frame + 34, 36U) == 0);

  klog("icmp: self-test passed id=0x%04x seq=%u reply_len=%lu\n", id, seq,
       reply_len);
}
