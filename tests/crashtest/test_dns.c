#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <xaios/dns.h>
#include <xaios/ipv4.h>
#include <xaios/status.h>

#define DNS_PAYLOAD_OFFSET 42U
#define DNS_TEST_PORT 0xC001U

static uint64_t g_now_ns = UINT64_C(1000000000);
static uint8_t g_tx_frame[512];
static uint32_t g_tx_length;

void panic_at(const char *file, int line, const char *fmt, ...) {
  (void)fmt;
  fprintf(stderr, "panic at %s:%d\n", file, line);
  abort();
}

void klog(const char *fmt, ...) { (void)fmt; }

uint64_t timer_now_ns(void) { return g_now_ns; }

xaios_status_t virtio_net_get_mac(uint8_t mac[6]) {
  static const uint8_t value[6] = {0x52U, 0x54U, 0x00U,
                                   0x12U, 0x34U, 0x56U};
  memcpy(mac, value, sizeof(value));
  return XAIOS_OK;
}

xaios_status_t virtio_net_tx(const uint8_t *data, uint64_t length) {
  if (data == 0 || length > sizeof(g_tx_frame)) return XAIOS_ERR_INVALID;
  memcpy(g_tx_frame, data, (size_t)length);
  g_tx_length = (uint32_t)length;
  return XAIOS_OK;
}

uint32_t virtio_net_rx_poll(uint8_t *buffer, uint64_t capacity) {
  (void)buffer;
  (void)capacity;
  return 0U;
}

static void put_be16(uint8_t *output, uint16_t value) {
  output[0] = (uint8_t)(value >> 8U);
  output[1] = (uint8_t)value;
}

static void put_be32(uint8_t *output, uint32_t value) {
  output[0] = (uint8_t)(value >> 24U);
  output[1] = (uint8_t)(value >> 16U);
  output[2] = (uint8_t)(value >> 8U);
  output[3] = (uint8_t)value;
}

static uint16_t get_be16(const uint8_t *input) {
  return (uint16_t)(((uint16_t)input[0] << 8U) | input[1]);
}

static uint32_t question_length(const uint8_t *query, uint32_t length) {
  uint32_t position = DNS_PAYLOAD_OFFSET + 12U;
  while (position < length && query[position] != 0U) {
    uint32_t label = query[position];
    if (label > 63U || position + 1U + label > length) return 0U;
    position += 1U + label;
  }
  if (position >= length || length - position < 5U) return 0U;
  return position + 5U - (DNS_PAYLOAD_OFFSET + 12U);
}

static uint32_t build_response(uint8_t frame[512], uint32_t answer_ip) {
  static const uint8_t gateway_mac[6] = {0x52U, 0x55U, 0x0aU,
                                         0x00U, 0x02U, 0x02U};
  static const uint8_t guest_mac[6] = {0x52U, 0x54U, 0x00U,
                                       0x12U, 0x34U, 0x56U};
  uint32_t qlen = question_length(g_tx_frame, g_tx_length);
  assert(qlen != 0U);
  memcpy(frame, guest_mac, 6U);
  memcpy(frame + 6U, gateway_mac, 6U);
  put_be16(frame + 12U, 0x0800U);

  uint8_t *udp = frame + 34U;
  uint8_t *dns = frame + DNS_PAYLOAD_OFFSET;
  uint16_t query_id = get_be16(g_tx_frame + DNS_PAYLOAD_OFFSET);
  put_be16(dns, query_id);
  put_be16(dns + 2U, 0x8180U);
  put_be16(dns + 4U, 1U);
  put_be16(dns + 6U, 1U);
  put_be16(dns + 8U, 0U);
  put_be16(dns + 10U, 0U);
  memcpy(dns + 12U, g_tx_frame + DNS_PAYLOAD_OFFSET + 12U, qlen);
  uint32_t position = 12U + qlen;
  dns[position++] = 0xC0U;
  dns[position++] = 0x0CU;
  put_be16(dns + position, XAIOS_DNS_TYPE_A); position += 2U;
  put_be16(dns + position, XAIOS_DNS_CLASS_IN); position += 2U;
  put_be32(dns + position, 60U); position += 4U;
  put_be16(dns + position, 4U); position += 2U;
  put_be32(dns + position, answer_ip); position += 4U;

  uint16_t udp_length = (uint16_t)(8U + position);
  put_be16(udp, XAIOS_DNS_PORT);
  put_be16(udp + 2U, DNS_TEST_PORT);
  put_be16(udp + 4U, udp_length);
  put_be16(udp + 6U, 0U);
  ipv4_build_header(frame + 14U, (uint16_t)(20U + udp_length),
                    XAIOS_IPV4_PROTO_UDP, UINT32_C(0x0a000203),
                    XAIOS_IPV4_GUEST_IP);
  return 14U + 20U + udp_length;
}

static void run_decode_corpus(void) {
  char output[256];
  uint8_t self_loop[2] = {0xC0U, 0x00U};
  uint8_t two_loop[4] = {0xC0U, 0x02U, 0xC0U, 0x00U};
  uint8_t out_of_range[2] = {0xC0U, 0x7fU};
  assert(dns_decode_name(self_loop, sizeof(self_loop), 0U, output,
                         sizeof(output)) < 0);
  assert(dns_decode_name(two_loop, sizeof(two_loop), 0U, output,
                         sizeof(output)) < 0);
  assert(dns_decode_name(out_of_range, sizeof(out_of_range), 0U, output,
                         sizeof(output)) < 0);
  assert(dns_decode_name(self_loop, sizeof(self_loop), 0U, output, 0U) < 0);

  uint32_t seed = UINT32_C(0x5841494f);
  uint8_t input[96];
  for (uint32_t case_id = 0U; case_id < 20000U; ++case_id) {
    seed = seed * UINT32_C(1664525) + UINT32_C(1013904223);
    uint32_t length = seed % sizeof(input) + 1U;
    for (uint32_t i = 0U; i < length; ++i) {
      seed = seed * UINT32_C(1664525) + UINT32_C(1013904223);
      input[i] = (uint8_t)(seed >> 24U);
    }
    (void)dns_decode_name(input, length, seed % length, output,
                          sizeof(output));
  }
}

int main(void) {
  run_decode_corpus();
  dns_init();
  dns_configure(UINT32_C(0x0a000203));

  uint32_t address = 0U;
  assert(dns_resolve("example.test", &address) == XAIOS_ERR_BUSY);
  assert(g_tx_frame[30] == 10U && g_tx_frame[31] == 0U &&
         g_tx_frame[32] == 2U && g_tx_frame[33] == 3U);
  assert(g_tx_length > DNS_PAYLOAD_OFFSET + 16U);
  assert(dns_query_count() == 1U && dns_pending_count() == 1U);

  uint8_t response[512];
  uint32_t response_length = build_response(response, UINT32_C(0x01020304));
  assert(dns_process_ipv4_frame(response, response_length, g_now_ns) ==
         XAIOS_OK);
  assert(dns_response_count() == 1U && dns_pending_count() == 0U);
  assert(dns_resolve("example.test", &address) == XAIOS_OK);
  assert(address == UINT32_C(0x01020304));

  assert(dns_resolve("timeout.test", &address) == XAIOS_ERR_BUSY);
  g_now_ns += UINT64_C(40000000000);
  dns_tick(g_now_ns);
  g_now_ns += UINT64_C(40000000000);
  dns_tick(g_now_ns);
  assert(dns_pending_count() == 0U && dns_timeout_count() == 1U);

  puts("dns: deterministic malformed corpus, response, cache, and timeout passed");
  return 0;
}
