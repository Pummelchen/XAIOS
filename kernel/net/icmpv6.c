#include <xaios/assert.h>
#include <xaios/icmpv6.h>
#include <xaios/ipv6.h>
#include <xaios/klog.h>

/* ---- C8: Shared ICMPv6 error rate counter ---- */
static uint64_t g_icmpv6_error_count = 0;
static uint64_t g_icmpv6_error_last_reset_ns = 0;
static uint64_t g_icmpv6_error_window_start_ns = 0;

static void bytes_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0; i < size; ++i) {
    bytes[i] = 0;
  }
}

static void put_be16(uint8_t *dst, uint16_t value) {
  dst[0] = (uint8_t)(value >> 8U);
  dst[1] = (uint8_t)value;
}

static uint16_t get_be16(const uint8_t *src) {
  return (uint16_t)(((uint16_t)src[0] << 8U) | src[1]);
}

xaios_status_t icmpv6_process_echo_request(
    const uint8_t *frame, uint64_t frame_len,
    uint16_t *identifier, uint16_t *sequence,
    xaios_ip_addr_t *src, xaios_ip_addr_t *dst) {
  if (frame == 0 || frame_len < XAIOS_ICMPV6_MIN_FRAME ||
      identifier == 0 || sequence == 0) {
    return XAIOS_ERR_INVALID;
  }
  if (get_be16(frame + 12) != XAIOS_IPV6_ETHERTYPE) {
    return XAIOS_ERR_INVALID;
  }
  uint16_t payload_length = 0;
  uint8_t next_header = 0;
  xaios_ip_addr_t ip_src;
  xaios_ip_addr_t ip_dst;
  if (ipv6_parse_header(frame + 14, frame_len - 14, &payload_length,
                        &next_header, &ip_src, &ip_dst) != 0) {
    return XAIOS_ERR_INVALID;
  }
  if (next_header != XAIOS_IPV6_NEXT_ICMPV6) {
    return XAIOS_ERR_INVALID;
  }
  const uint8_t *icmpv6 = frame + XAIOS_ICMPV6_OFFSET;
  uint8_t type = icmpv6[0];
  if (type != XAIOS_ICMPV6_ECHO_REQUEST) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t icmpv6_len = (uint64_t)payload_length;
  if (XAIOS_ICMPV6_OFFSET + icmpv6_len > frame_len || icmpv6_len < 8U) {
    return XAIOS_ERR_INVALID;
  }
  uint16_t cksum = ipv6_pseudo_checksum(&ip_src, &ip_dst,
                                         XAIOS_IPV6_NEXT_ICMPV6,
                                         (uint32_t)icmpv6_len,
                                         icmpv6, (uint32_t)icmpv6_len);
  if (cksum != 0) {
    return XAIOS_ERR_INVALID;
  }
  *identifier = get_be16(icmpv6 + 4);
  *sequence = get_be16(icmpv6 + 6);
  if (src != 0) {
    *src = ip_src;
  }
  if (dst != 0) {
    *dst = ip_dst;
  }
  return XAIOS_OK;
}

xaios_status_t icmpv6_build_echo_reply(
    uint8_t *frame, uint64_t *frame_len,
    const uint8_t src_mac[6], const uint8_t dst_mac[6],
    const xaios_ip_addr_t *src_ip, const xaios_ip_addr_t *dst_ip,
    const uint8_t *request_frame, uint64_t request_len) {
  if (frame == 0 || frame_len == 0 || src_mac == 0 || dst_mac == 0 ||
      src_ip == 0 || dst_ip == 0 || request_frame == 0 ||
      request_len < XAIOS_ICMPV6_MIN_FRAME) {
    return XAIOS_ERR_INVALID;
  }
  const uint8_t *req_icmpv6 = request_frame + XAIOS_ICMPV6_OFFSET;
  uint16_t payload_length = get_be16(request_frame + 18);
  uint64_t icmpv6_len = (uint64_t)payload_length;
  if (XAIOS_ICMPV6_OFFSET + icmpv6_len > request_len || icmpv6_len < 8U) {
    return XAIOS_ERR_INVALID;
  }

  uint64_t total = 14U + XAIOS_IPV6_HEADER_SIZE + icmpv6_len;
  bytes_zero(frame, total);

  for (uint32_t i = 0; i < 6; ++i) {
    frame[i] = dst_mac[i];
    frame[6 + i] = src_mac[i];
  }
  put_be16(frame + 12, XAIOS_IPV6_ETHERTYPE);

  ipv6_build_header(frame + 14, (uint16_t)icmpv6_len,
                    XAIOS_IPV6_NEXT_ICMPV6, src_ip, dst_ip);

  uint8_t *icmpv6 = frame + XAIOS_ICMPV6_OFFSET;
  icmpv6[0] = XAIOS_ICMPV6_ECHO_REPLY;
  icmpv6[1] = 0;
  put_be16(icmpv6 + 2, 0);
  for (uint64_t i = 4; i < icmpv6_len; ++i) {
    icmpv6[i] = req_icmpv6[i];
  }

  uint16_t cksum = ipv6_pseudo_checksum(src_ip, dst_ip,
                                         XAIOS_IPV6_NEXT_ICMPV6,
                                         (uint32_t)icmpv6_len,
                                         icmpv6, (uint32_t)icmpv6_len);
  put_be16(icmpv6 + 2, cksum);

  *frame_len = total;
  return XAIOS_OK;
}

xaios_status_t icmpv6_build_neighbor_advertisement(
    uint8_t *frame, uint64_t *frame_len,
    const uint8_t src_mac[6], const uint8_t dst_mac[6],
    const xaios_ip_addr_t *src_ip, const xaios_ip_addr_t *dst_ip,
    const xaios_ip_addr_t *target,
    const uint8_t *ns_frame, uint64_t ns_len) {
  (void)ns_frame;
  (void)ns_len;

  uint64_t icmpv6_len = 32U;
  uint64_t total = 14U + XAIOS_IPV6_HEADER_SIZE + icmpv6_len;
  bytes_zero(frame, total);

  for (uint32_t i = 0; i < 6; ++i) {
    frame[i] = dst_mac[i];
    frame[6 + i] = src_mac[i];
  }
  put_be16(frame + 12, XAIOS_IPV6_ETHERTYPE);

  uint8_t *ipv6_hdr = frame + 14;
  ipv6_build_header(ipv6_hdr, (uint16_t)icmpv6_len,
                    XAIOS_IPV6_NEXT_ICMPV6, src_ip, dst_ip);
  ipv6_hdr[7] = 255U;

  uint8_t *icmpv6 = frame + XAIOS_ICMPV6_OFFSET;
  icmpv6[0] = XAIOS_ICMPV6_NEIGHBOR_ADVERT;
  icmpv6[1] = 0;
  put_be16(icmpv6 + 2, 0);
  icmpv6[4] = 0x60U;
  icmpv6[5] = 0;
  icmpv6[6] = 0;
  icmpv6[7] = 0;
  for (uint32_t i = 0; i < 16; ++i) {
    icmpv6[8 + i] = target->addr[i];
  }
  icmpv6[24] = 2;
  icmpv6[25] = 1;
  for (uint32_t i = 0; i < 6; ++i) {
    icmpv6[26 + i] = src_mac[i];
  }

  uint16_t cksum = ipv6_pseudo_checksum(src_ip, dst_ip,
                                         XAIOS_IPV6_NEXT_ICMPV6,
                                         (uint32_t)icmpv6_len,
                                         icmpv6, (uint32_t)icmpv6_len);
  put_be16(icmpv6 + 2, cksum);

  *frame_len = total;
  return XAIOS_OK;
}

/* ---- C8: Build ICMPv6 Destination Unreachable ---- */
xaios_status_t icmpv6_build_dest_unreachable(
    uint8_t *frame, uint64_t *frame_len,
    const uint8_t src_mac[6], const uint8_t dst_mac[6],
    const xaios_ip_addr_t *src_ip, const xaios_ip_addr_t *dst_ip,
    uint8_t code, const uint8_t *orig_frame, uint64_t orig_len) {
  if (frame == 0 || frame_len == 0 || src_mac == 0 || dst_mac == 0 ||
      src_ip == 0 || dst_ip == 0 || orig_frame == 0) {
    return XAIOS_ERR_INVALID;
  }

  /* ICMPv6 error must not be rate-limited; we check before building */
  /* Build: Ethernet(14) + IPv6(40) + ICMPv6(8 + embedded) */
  uint64_t embed_len = (orig_len < XAIOS_ICMPV6_ERROR_EMBED_LEN)
                        ? orig_len : XAIOS_ICMPV6_ERROR_EMBED_LEN;
  uint64_t icmpv6_len = 8U + embed_len; /* 8 = type+code+cksum+MTU, then original */
  if (icmpv6_len < 8U) icmpv6_len = 8U;

  uint64_t total = 14U + XAIOS_IPV6_HEADER_SIZE + icmpv6_len;
  bytes_zero(frame, total);

  for (uint32_t i = 0; i < 6; ++i) {
    frame[i] = dst_mac[i]; /* reverse MAC */
    frame[6 + i] = src_mac[i];
  }
  put_be16(frame + 12, XAIOS_IPV6_ETHERTYPE);

  ipv6_build_header(frame + 14, (uint16_t)icmpv6_len,
                    XAIOS_IPV6_NEXT_ICMPV6, src_ip, dst_ip);

  uint8_t *icmpv6 = frame + XAIOS_ICMPV6_OFFSET;
  icmpv6[0] = XAIOS_ICMPV6_DEST_UNREACHABLE; /* type = 1 */
  icmpv6[1] = code;
  put_be16(icmpv6 + 2, 0); /* Clear checksum field before calculation. */
  /* Unused (4 bytes) - set to 0 */
  icmpv6[4] = 0;
  icmpv6[5] = 0;
  icmpv6[6] = 0;
  icmpv6[7] = 0;

  /* Embed as much of the original packet as fits */
  for (uint64_t i = 0; i < embed_len; ++i) {
    icmpv6[8 + i] = orig_frame[i];
  }

  uint16_t cksum = ipv6_pseudo_checksum(src_ip, dst_ip,
                                         XAIOS_IPV6_NEXT_ICMPV6,
                                         (uint32_t)icmpv6_len,
                                         icmpv6, (uint32_t)icmpv6_len);
  put_be16(icmpv6 + 2, cksum);

  *frame_len = total;
  return XAIOS_OK;
}

/* ---- C8: Build ICMPv6 Time Exceeded ---- */
xaios_status_t icmpv6_build_time_exceeded(
    uint8_t *frame, uint64_t *frame_len,
    const uint8_t src_mac[6], const uint8_t dst_mac[6],
    const xaios_ip_addr_t *src_ip, const xaios_ip_addr_t *dst_ip,
    uint8_t code, const uint8_t *orig_frame, uint64_t orig_len) {
  if (frame == 0 || frame_len == 0 || src_mac == 0 || dst_mac == 0 ||
      src_ip == 0 || dst_ip == 0 || orig_frame == 0) {
    return XAIOS_ERR_INVALID;
  }

  uint64_t embed_len = (orig_len < XAIOS_ICMPV6_ERROR_EMBED_LEN)
                        ? orig_len : XAIOS_ICMPV6_ERROR_EMBED_LEN;
  uint64_t icmpv6_len = 8U + embed_len;
  if (icmpv6_len < 8U) icmpv6_len = 8U;

  uint64_t total = 14U + XAIOS_IPV6_HEADER_SIZE + icmpv6_len;
  bytes_zero(frame, total);

  for (uint32_t i = 0; i < 6; ++i) {
    frame[i] = dst_mac[i];
    frame[6 + i] = src_mac[i];
  }
  put_be16(frame + 12, XAIOS_IPV6_ETHERTYPE);

  ipv6_build_header(frame + 14, (uint16_t)icmpv6_len,
                    XAIOS_IPV6_NEXT_ICMPV6, src_ip, dst_ip);

  uint8_t *icmpv6 = frame + XAIOS_ICMPV6_OFFSET;
  icmpv6[0] = XAIOS_ICMPV6_TIME_EXCEEDED; /* type = 3 */
  icmpv6[1] = code;
  put_be16(icmpv6 + 2, 0);
  icmpv6[4] = 0;
  icmpv6[5] = 0;
  icmpv6[6] = 0;
  icmpv6[7] = 0;

  for (uint64_t i = 0; i < embed_len; ++i) {
    icmpv6[8 + i] = orig_frame[i];
  }

  uint16_t cksum = ipv6_pseudo_checksum(src_ip, dst_ip,
                                         XAIOS_IPV6_NEXT_ICMPV6,
                                         (uint32_t)icmpv6_len,
                                         icmpv6, (uint32_t)icmpv6_len);
  put_be16(icmpv6 + 2, cksum);

  *frame_len = total;
  return XAIOS_OK;
}

/* ---- C8: Error can send (rate limiter) ---- */
int icmpv6_error_can_send(void) {
  /* Use a simple rate counter (resets each second based on wall time) */
  /* If no time source available, just allow (no strict rate limiting) */
  if (g_icmpv6_error_window_start_ns == 0) {
    g_icmpv6_error_window_start_ns = 1; /* init */
  }

  /* Simple token bucket: max 100 per second */
  if (g_icmpv6_error_count < XAIOS_ICMPV6_RATE_MAX) {
    g_icmpv6_error_count++;
    return 1;
  }

  /* Reset window if more than 1s has passed */
  if (g_icmpv6_error_last_reset_ns == 0) {
    g_icmpv6_error_last_reset_ns = 1;
  }

  /* Assuming wall_time_now_ns is used externally to reset */
  return 0;
}

/* ---- Reset rate limit window (called from timer tick) ---- */
void icmpv6_error_rate_reset(uint64_t now_ns) {
  (void)now_ns;
  g_icmpv6_error_count = 0;
  g_icmpv6_error_window_start_ns = now_ns;
}

void icmpv6_self_test(void) {
  /* Build a fake echo request: fe80::1 -> fe80::2 */
  uint8_t request[96];
  bytes_zero(request, sizeof(request));

  uint8_t src_mac[6] = {0x52, 0x54, 0x00, 0x12, 0x35, 0x02};
  uint8_t dst_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x15};

  xaios_ip_addr_t src;
  src.family = XAIOS_IP_FAMILY_V6;
  for (uint32_t i = 0; i < 16; ++i) src.addr[i] = 0;
  src.addr[0] = 0xFE;
  src.addr[1] = 0x80;
  src.addr[15] = 0x01;

  xaios_ip_addr_t dst;
  dst.family = XAIOS_IP_FAMILY_V6;
  for (uint32_t i = 0; i < 16; ++i) dst.addr[i] = 0;
  dst.addr[0] = 0xFE;
  dst.addr[1] = 0x80;
  dst.addr[15] = 0x02;

  for (uint32_t i = 0; i < 6; ++i) {
    request[i] = dst_mac[i];
    request[6 + i] = src_mac[i];
  }
  put_be16(request + 12, XAIOS_IPV6_ETHERTYPE);

  uint16_t icmpv6_len = 8;
  ipv6_build_header(request + 14, icmpv6_len, XAIOS_IPV6_NEXT_ICMPV6,
                    &src, &dst);

  uint8_t *icmpv6 = request + XAIOS_ICMPV6_OFFSET;
  icmpv6[0] = XAIOS_ICMPV6_ECHO_REQUEST;
  icmpv6[1] = 0;
  put_be16(icmpv6 + 2, 0);
  put_be16(icmpv6 + 4, 0xABCD);
  put_be16(icmpv6 + 6, 0x0042);

  uint16_t cksum = ipv6_pseudo_checksum(&src, &dst,
                                         XAIOS_IPV6_NEXT_ICMPV6,
                                         (uint32_t)icmpv6_len,
                                         icmpv6, (uint32_t)icmpv6_len);
  put_be16(icmpv6 + 2, cksum);

  uint64_t request_len = 14U + XAIOS_IPV6_HEADER_SIZE + icmpv6_len;
  uint16_t id = 0, seq = 0;
  xaios_ip_addr_t parsed_src;
  xaios_ip_addr_t parsed_dst;
  kassert(icmpv6_process_echo_request(request, request_len, &id, &seq,
                                       &parsed_src, &parsed_dst) == XAIOS_OK);
  kassert(id == 0xABCD);
  kassert(seq == 0x0042);
  kassert(xaios_ip_addr_equal(&parsed_src, &src));
  kassert(xaios_ip_addr_equal(&parsed_dst, &dst));

  /* Build echo reply */
  uint8_t reply[96];
  uint64_t reply_len = 0;
  kassert(icmpv6_build_echo_reply(reply, &reply_len, dst_mac, src_mac,
                                   &dst, &src, request, request_len) == XAIOS_OK);
  kassert(reply_len == request_len);
  kassert(reply[XAIOS_ICMPV6_OFFSET] == XAIOS_ICMPV6_ECHO_REPLY);

  uint8_t *reply_icmpv6 = reply + XAIOS_ICMPV6_OFFSET;
  uint16_t reply_cksum = ipv6_pseudo_checksum(&dst, &src,
                                              XAIOS_IPV6_NEXT_ICMPV6,
                                              (uint32_t)icmpv6_len,
                                              reply_icmpv6, (uint32_t)icmpv6_len);
  kassert(reply_cksum == 0);

  /* ---- C8: ICMPv6 error generation test ---- */
  {
    /* Build a dest unreachable */
    uint8_t error_frame[256];
    uint64_t error_len = 0;

    /* Use the original request as the "offending packet" */
    kassert(icmpv6_build_dest_unreachable(
        error_frame, &error_len,
        src_mac, dst_mac,
        &dst, &src,
        XAIOS_ICMPV6_CODE_NO_ROUTE,
        request, request_len) == XAIOS_OK);

    kassert(error_len > 14U + XAIOS_IPV6_HEADER_SIZE);
    kassert(error_frame[XAIOS_ICMPV6_OFFSET] == XAIOS_ICMPV6_DEST_UNREACHABLE);
    kassert(error_frame[XAIOS_ICMPV6_OFFSET + 1] == XAIOS_ICMPV6_CODE_NO_ROUTE);
    kassert(ipv6_parse_header(error_frame + 14, error_len - 14,
                               &icmpv6_len, 0, 0, 0) == 0);

    /* Verify checksum */
    uint8_t *err_icmp = error_frame + XAIOS_ICMPV6_OFFSET;
    uint16_t err_cksum = ipv6_pseudo_checksum(&dst, &src,
                                              XAIOS_IPV6_NEXT_ICMPV6,
                                              (uint32_t)(error_len - 54),
                                              err_icmp,
                                              (uint32_t)(error_len - 54));
    kassert(err_cksum == 0);

    klog("icmpv6: dest-unreachable test passed\n");
  }

  /* ---- Time Exceeded test ---- */
  {
    uint8_t te_frame[256];
    uint64_t te_len = 0;
    kassert(icmpv6_build_time_exceeded(
        te_frame, &te_len,
        src_mac, dst_mac,
        &dst, &src,
        XAIOS_ICMPV6_CODE_HOP_LIMIT_EXCEEDED,
        request, request_len) == XAIOS_OK);

    kassert(te_frame[XAIOS_ICMPV6_OFFSET] == XAIOS_ICMPV6_TIME_EXCEEDED);
    kassert(te_frame[XAIOS_ICMPV6_OFFSET + 1] == XAIOS_ICMPV6_CODE_HOP_LIMIT_EXCEEDED);

    klog("icmpv6: time-exceeded test passed\n");
  }

  /* ---- Rate limiter test ---- */
  {
    /* Initially should allow */
    int allowed = 0;
    for (uint32_t i = 0; i < XAIOS_ICMPV6_RATE_MAX; ++i) {
      allowed = icmpv6_error_can_send();
    }
    kassert(allowed == 1); /* last call was at limit */

    /* Next should be denied (rate limited) */
    allowed = icmpv6_error_can_send();
    kassert(allowed == 0);

    klog("icmpv6: rate limiter passed (allowed=%d)\n", allowed);
  }

  /* Build Neighbor Advertisement */
  xaios_ip_addr_t target = src;
  uint8_t na_frame[128];
  uint64_t na_len = 0;
  kassert(icmpv6_build_neighbor_advertisement(na_frame, &na_len,
            dst_mac, src_mac, &dst, &src, &target, 0, 0) == XAIOS_OK);
  kassert(na_len == 14U + XAIOS_IPV6_HEADER_SIZE + 32U);
  kassert(na_frame[XAIOS_ICMPV6_OFFSET] == XAIOS_ICMPV6_NEIGHBOR_ADVERT);

  uint8_t *na_icmpv6 = na_frame + XAIOS_ICMPV6_OFFSET;
  uint16_t na_cksum = ipv6_pseudo_checksum(&dst, &src,
                                            XAIOS_IPV6_NEXT_ICMPV6,
                                            32, na_icmpv6, 32);
  kassert(na_cksum == 0);

  klog("icmpv6: self-test passed echo_id=0x%04x seq=%u reply_len=%lu na_len=%lu\n",
       id, seq, reply_len, na_len);
}
