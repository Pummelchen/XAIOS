#include <xaios/assert.h>
#include <xaios/ipv4.h>
#include <xaios/klog.h>
#include <xaios/ntp.h>
#include <xaios/timer.h>
#include <xaios/virtio_net.h>

#define NTP_PORT UINT16_C(123)
#define NTP_LOCAL_PORT UINT16_C(49155)
#define NTP_PACKET_BYTES 48U
#define NTP_FRAME_BYTES (14U + 20U + 8U + NTP_PACKET_BYTES)
#define NTP_UNIX_DELTA UINT64_C(2208988800)
#define NTP_RETRY_NS UINT64_C(3000000000)
#define NTP_TIMEOUT_NS UINT64_C(10000000000)
#define NTP_DEFAULT_SERVER UINT32_C(0xa29fc801) /* 162.159.200.1 */

static xaios_ntp_status_t g_status;
static uint8_t g_frame[NTP_FRAME_BYTES];
static uint64_t g_sent_ns;
static uint64_t g_request_timestamp;

static void put_be16(uint8_t *dst, uint16_t value) {
  dst[0] = (uint8_t)(value >> 8U);
  dst[1] = (uint8_t)value;
}

static void put_be32(uint8_t *dst, uint32_t value) {
  dst[0] = (uint8_t)(value >> 24U);
  dst[1] = (uint8_t)(value >> 16U);
  dst[2] = (uint8_t)(value >> 8U);
  dst[3] = (uint8_t)value;
}

static uint16_t get_be16(const uint8_t *src) {
  return (uint16_t)(((uint16_t)src[0] << 8U) | src[1]);
}

static uint32_t get_be32(const uint8_t *src) {
  return ((uint32_t)src[0] << 24U) | ((uint32_t)src[1] << 16U) |
         ((uint32_t)src[2] << 8U) | src[3];
}

static uint64_t get_be64(const uint8_t *src) {
  return ((uint64_t)get_be32(src) << 32U) | get_be32(src + 4U);
}

static void put_be64(uint8_t *dst, uint64_t value) {
  put_be32(dst, (uint32_t)(value >> 32U));
  put_be32(dst + 4U, (uint32_t)value);
}

static void bytes_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0U; i < size; ++i) bytes[i] = 0U;
}

static uint64_t unix_to_ntp(uint64_t epoch_ns) {
  uint64_t seconds = epoch_ns / UINT64_C(1000000000);
  uint64_t nanos = epoch_ns % UINT64_C(1000000000);
  uint64_t fraction = (nanos << 32U) / UINT64_C(1000000000);
  return ((seconds + NTP_UNIX_DELTA) << 32U) | fraction;
}

static xaios_status_t ntp_to_unix(uint64_t stamp, uint64_t *epoch_ns) {
  uint64_t seconds = stamp >> 32U;
  uint64_t fraction = stamp & UINT64_C(0xffffffff);
  if (epoch_ns == 0 || seconds < NTP_UNIX_DELTA) return XAIOS_ERR_INVALID;
  seconds -= NTP_UNIX_DELTA;
  if (seconds > UINT64_MAX / UINT64_C(1000000000)) return XAIOS_ERR_INVALID;
  *epoch_ns = seconds * UINT64_C(1000000000) +
      (fraction * UINT64_C(1000000000) >> 32U);
  return XAIOS_OK;
}

static xaios_status_t transmit(void) {
  xaios_status_t status = virtio_net_tx(g_frame, sizeof(g_frame));
  if (status == XAIOS_OK) {
    g_sent_ns = timer_now_ns();
    ++g_status.attempts;
  } else {
    g_status.state = XAIOS_NTP_FAILED;
    g_status.last_error = status;
  }
  return status;
}

void ntp_init(void) {
  bytes_zero(&g_status, sizeof(g_status));
  bytes_zero(g_frame, sizeof(g_frame));
  g_status.state = XAIOS_NTP_IDLE;
  g_status.server_ip = NTP_DEFAULT_SERVER;
  g_status.last_error = XAIOS_OK;
  g_sent_ns = 0U;
  g_request_timestamp = 0U;
}

xaios_status_t ntp_sync(uint32_t server_ip) {
  uint8_t local_mac[6];
  uint8_t gateway_mac[6] = {0x52U, 0x55U, 0x0aU, 0x00U, 0x02U, 0x02U};
  if (g_status.state == XAIOS_NTP_PENDING) return XAIOS_ERR_BUSY;
  if (server_ip == 0U) server_ip = NTP_DEFAULT_SERVER;
  bytes_zero(g_frame, sizeof(g_frame));
  if (virtio_net_get_mac(local_mac) != XAIOS_OK) return XAIOS_ERR_NOT_FOUND;
  for (uint32_t i = 0U; i < 6U; ++i) {
    g_frame[i] = gateway_mac[i];
    g_frame[6U + i] = local_mac[i];
  }
  put_be16(g_frame + 12U, UINT16_C(0x0800));
  ipv4_build_header(g_frame + 14U, 20U + 8U + NTP_PACKET_BYTES,
                    XAIOS_IPV4_PROTO_UDP, XAIOS_IPV4_GUEST_IP, server_ip);
  put_be16(g_frame + 34U, NTP_LOCAL_PORT);
  put_be16(g_frame + 36U, NTP_PORT);
  put_be16(g_frame + 38U, 8U + NTP_PACKET_BYTES);
  put_be16(g_frame + 40U, 0U);
  g_frame[42U] = UINT8_C(0x23); /* LI=0, version=4, client mode. */
  g_request_timestamp = unix_to_ntp(wall_time_now_ns());
  put_be64(g_frame + 42U + 40U, g_request_timestamp);
  g_status.state = XAIOS_NTP_PENDING;
  g_status.server_ip = server_ip;
  g_status.attempts = 0U;
  g_status.stratum = 0U;
  g_status.round_trip_ns = 0U;
  g_status.last_error = XAIOS_OK;
  return transmit() == XAIOS_OK ? XAIOS_ERR_BUSY : g_status.last_error;
}

static xaios_status_t parse_response(const uint8_t *packet, uint32_t bytes,
                                     uint64_t expected_origin,
                                     uint64_t *epoch_ns,
                                     uint32_t *stratum) {
  if (packet == 0 || bytes < NTP_PACKET_BYTES || epoch_ns == 0 ||
      stratum == 0) return XAIOS_ERR_INVALID;
  uint8_t mode = packet[0] & UINT8_C(0x07);
  uint8_t version = (packet[0] >> 3U) & UINT8_C(0x07);
  if ((mode != 4U && mode != 5U) || version < 3U || packet[1] == 0U ||
      packet[1] > 15U || get_be64(packet + 24U) != expected_origin) {
    return XAIOS_ERR_INVALID;
  }
  *stratum = packet[1];
  return ntp_to_unix(get_be64(packet + 40U), epoch_ns);
}

xaios_status_t ntp_process_ipv4_frame(const uint8_t *frame,
                                      uint32_t frame_len,
                                      uint64_t now_ns) {
  if (frame == 0 || frame_len < NTP_FRAME_BYTES ||
      g_status.state != XAIOS_NTP_PENDING) return XAIOS_ERR_NOT_FOUND;
  if (get_be16(frame + 12U) != UINT16_C(0x0800) ||
      !ipv4_validate_incoming(frame, frame_len) ||
      ipv4_is_fragment(frame, frame_len)) return XAIOS_ERR_INVALID;
  const uint8_t *ip = frame + 14U;
  uint32_t header_bytes = (uint32_t)(ip[0] & UINT8_C(0x0f)) * 4U;
  uint16_t ip_bytes = get_be16(ip + 2U);
  if (header_bytes < 20U || ip[9U] != XAIOS_IPV4_PROTO_UDP ||
      get_be32(ip + 12U) != g_status.server_ip ||
      ip_bytes < header_bytes + 8U + NTP_PACKET_BYTES ||
      14U + ip_bytes > frame_len)
    return XAIOS_ERR_NOT_FOUND;
  const uint8_t *udp = ip + header_bytes;
  if (get_be16(udp) != NTP_PORT || get_be16(udp + 2U) != NTP_LOCAL_PORT)
    return XAIOS_ERR_NOT_FOUND;
  uint16_t udp_bytes = get_be16(udp + 4U);
  if (udp_bytes < 8U + NTP_PACKET_BYTES ||
      udp_bytes > ip_bytes - header_bytes) return XAIOS_ERR_INVALID;
  uint16_t wire_checksum = get_be16(udp + 6U);
  if (wire_checksum != 0U &&
      ipv4_pseudo_checksum(get_be32(ip + 12U), get_be32(ip + 16U),
                           XAIOS_IPV4_PROTO_UDP, udp_bytes, udp,
                           udp_bytes) != 0U) return XAIOS_ERR_INVALID;
  uint64_t epoch_ns = 0U;
  uint32_t stratum = 0U;
  xaios_status_t status = parse_response(udp + 8U,
      (uint32_t)udp_bytes - 8U, g_request_timestamp,
      &epoch_ns, &stratum);
  if (status != XAIOS_OK) {
    g_status.state = XAIOS_NTP_FAILED;
    g_status.last_error = status;
    return status;
  }
  g_status.round_trip_ns = now_ns >= g_sent_ns ? now_ns - g_sent_ns : 0U;
  if (epoch_ns <= UINT64_MAX - g_status.round_trip_ns / 2U)
    epoch_ns += g_status.round_trip_ns / 2U;
  status = wall_time_set_ns(epoch_ns, 2U);
  g_status.state = status == XAIOS_OK ? XAIOS_NTP_SYNCED : XAIOS_NTP_FAILED;
  g_status.stratum = stratum;
  g_status.last_sync_epoch_ns = status == XAIOS_OK ? epoch_ns : 0U;
  g_status.last_error = status;
  klog("ntp: sync state=%u stratum=%u rtt_ns=%lu status=%d\n",
       (unsigned)g_status.state, stratum, g_status.round_trip_ns, (int)status);
  return status;
}

void ntp_tick(uint64_t now_ns) {
  if (g_status.state != XAIOS_NTP_PENDING || now_ns < g_sent_ns) return;
  if (now_ns - g_sent_ns >= NTP_TIMEOUT_NS) {
    g_status.state = XAIOS_NTP_TIMEOUT;
    g_status.last_error = XAIOS_ERR_IO;
    return;
  }
  if (now_ns - g_sent_ns >= NTP_RETRY_NS && g_status.attempts < 2U)
    (void)transmit();
}

xaios_ntp_status_t ntp_status(void) { return g_status; }

void ntp_self_test(void) {
  uint8_t packet[NTP_PACKET_BYTES];
  uint64_t epoch_ns = UINT64_C(1700000000123456789);
  uint64_t parsed_ns = 0U;
  uint32_t stratum = 0U;
  bytes_zero(packet, sizeof(packet));
  packet[0] = UINT8_C(0x24);
  packet[1] = 2U;
  uint64_t origin = unix_to_ntp(UINT64_C(1699999999000000000));
  put_be64(packet + 24U, origin);
  put_be64(packet + 40U, unix_to_ntp(epoch_ns));
  kassert(parse_response(packet, sizeof(packet), origin, &parsed_ns,
                         &stratum) == XAIOS_OK);
  kassert(stratum == 2U);
  kassert(parsed_ns >= epoch_ns - 1U && parsed_ns <= epoch_ns + 1U);
  packet[1] = 0U;
  kassert(parse_response(packet, sizeof(packet), origin, &parsed_ns,
                         &stratum) == XAIOS_ERR_INVALID);
  ntp_init();
  klog("ntp: self-test passed\n");
}
