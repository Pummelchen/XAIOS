#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <xaios/dns.h>
#include <xaios/dnssec.h>
#include <xaios/ipv4.h>
#include <xaios/net_device.h>
#include <xaios/network_config.h>
#include <xaios/status.h>

#define DNS_PAYLOAD_OFFSET 42U
static uint64_t g_now_ns = UINT64_C(1000000000);
static uint8_t g_tx_frame[512];
static uint32_t g_tx_length;
static uint16_t g_rng_value = UINT16_C(0x1234);

void panic_at(const char *file, int line, const char *fmt, ...) {
  (void)fmt; fprintf(stderr, "panic at %s:%d\n", file, line); abort();
}
void klog(const char *fmt, ...) { (void)fmt; }
uint64_t timer_now_ns(void) { return g_now_ns; }
uint64_t wall_time_now_ns(void) { return UINT64_C(1900000000000000000); }
int xaios_random(void *buffer, uint64_t size) { memset(buffer, 0x5a, (size_t)size); return 0; }
xaios_status_t virtio_rng_read(void *buffer, uint64_t size) {
  uint8_t *bytes = buffer;
  for (uint64_t i = 0U; i < size; ++i) bytes[i] = (uint8_t)(g_rng_value >> ((i & 1U) * 8U));
  ++g_rng_value; return XAIOS_OK;
}
xaios_status_t virtio_net_get_mac(uint8_t mac[6]) {
  static const uint8_t value[6] = {0x52U,0x54U,0U,0x12U,0x34U,0x56U};
  memcpy(mac, value, sizeof(value)); return XAIOS_OK;
}
xaios_status_t virtio_net_tx(const uint8_t *data, uint64_t length) {
  if (data == 0 || length > sizeof(g_tx_frame)) return XAIOS_ERR_INVALID;
  memcpy(g_tx_frame, data, (size_t)length); g_tx_length = (uint32_t)length; return XAIOS_OK;
}
xaios_status_t network_stack_tcp_open(const xaios_ip_addr_t *a, uint16_t b, uint16_t c, uint32_t *d) { (void)a; (void)b; (void)c; *d = 1U; return XAIOS_OK; }
xaios_status_t network_stack_tcp_open_status(uint32_t id) { return id == 1U ? XAIOS_OK : XAIOS_ERR_NOT_FOUND; }
xaios_status_t network_stack_tcp_abort_flow(uint32_t id) { (void)id; return XAIOS_OK; }
xaios_status_t network_stack_tcp_close_flow(uint32_t id) { (void)id; return XAIOS_OK; }
xaios_status_t network_stack_tcp_send(uint32_t id, const uint8_t *d, uint32_t n, uint32_t *w) { (void)id; (void)d; *w = n; return XAIOS_OK; }
uint32_t network_stack_tcp_recv(uint32_t id, uint8_t *b, uint32_t n) { (void)id; (void)b; (void)n; return 0U; }
uint32_t virtio_net_rx_poll(uint8_t *b, uint64_t n) { (void)b; (void)n; return 0U; }

/* DNS uses the portable NIC/config boundary; keep the hosted fixture below
 * that boundary instead of linking a hardware driver into the parser test. */
xaios_status_t network_device_get_mac(uint8_t mac[6]) {
  return virtio_net_get_mac(mac);
}
xaios_status_t network_device_tx(const uint8_t *data, uint64_t length) {
  return virtio_net_tx(data, length);
}
uint32_t network_device_rx_poll(uint8_t *buffer, uint64_t capacity) {
  return virtio_net_rx_poll(buffer, capacity);
}
uint32_t network_config_local_ipv4(void) { return XAIOS_IPV4_GUEST_IP; }
void network_config_gateway_mac(uint8_t mac[6]) {
  static const uint8_t gateway[6] = {0x52U, 0x55U, 0x0aU,
                                     0x00U, 0x02U, 0x02U};
  memcpy(mac, gateway, sizeof(gateway));
}

static void put_be16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8U); p[1] = (uint8_t)v; }
static uint16_t get_be16(const uint8_t *p) { return (uint16_t)(((uint16_t)p[0] << 8U) | p[1]); }

#ifdef XAIOS_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char output[XAIOS_DNS_MAX_NAME];
  if (size == 0U || size > UINT32_MAX) return 0;
  for (uint32_t offset = 0U; offset < (uint32_t)size; ++offset)
    (void)dns_decode_name(data, (uint32_t)size, offset, output, sizeof(output));
  dnssec_keyset_t keys = {0};
  dnssec_dsset_t ds = {0};
  uint8_t address[16] = {0};
  uint32_t ttl = 0U;
  dnssec_init();
  (void)dnssec_verify_dnskey(data, (uint32_t)size, "", 0,
      UINT64_C(1900000000000000000), &keys);
  (void)dnssec_verify_ds(data, (uint32_t)size, "test", &keys,
      UINT64_C(1900000000000000000), &ds);
  (void)dnssec_verify_address(data, (uint32_t)size, "test",
      XAIOS_DNS_TYPE_A, &keys, UINT64_C(1900000000000000000), address, &ttl);
  (void)dnssec_verify_nodata(data, (uint32_t)size, "missing.test",
      XAIOS_DNS_TYPE_AAAA, &keys, UINT64_C(1900000000000000000));
  return 0;
}
#else
#include "dnssec_fixture.h"

static void configure_test_anchor(void) {
  dnssec_ds_t anchor;
  memset(&anchor, 0, sizeof(anchor));
  anchor.key_tag = DNSSEC_TEST_ROOT_TAG;
  anchor.algorithm = 8U;
  anchor.digest_type = 2U;
  anchor.digest_length = sizeof(k_test_anchor_digest);
  memcpy(anchor.digest, k_test_anchor_digest, sizeof(k_test_anchor_digest));
  assert(dnssec_set_trust_anchors(&anchor, 1U) == XAIOS_OK);
}

static uint16_t test_dnskey_tag(const uint8_t *rdata, uint32_t length) {
  uint32_t accumulator = 0U;
  for (uint32_t i = 0U; i < length; ++i)
    accumulator += (i & 1U) != 0U ? rdata[i] : (uint32_t)rdata[i] << 8U;
  accumulator += (accumulator >> 16U) & 0xffffU;
  return (uint16_t)accumulator;
}

static void verify_supported_address_algorithm(const uint8_t *key,
                                               uint32_t key_length,
                                               uint8_t algorithm,
                                               const uint8_t *message,
                                               uint32_t message_length) {
  dnssec_keyset_t keyset;
  uint8_t address[16];
  uint32_t ttl = 0U;
  memset(&keyset, 0, sizeof(keyset));
  memcpy(keyset.owner, "test", 5U);
  keyset.count = 1U;
  keyset.keys[0].key_tag = test_dnskey_tag(key, key_length);
  keyset.keys[0].algorithm = algorithm;
  keyset.keys[0].rdata_length = (uint16_t)key_length;
  memcpy(keyset.keys[0].rdata, key, key_length);
  xaios_status_t status = dnssec_verify_address(
      message, message_length, "test", XAIOS_DNS_TYPE_A, &keyset,
      wall_time_now_ns(), address, &ttl);
  if (status != XAIOS_OK)
    fprintf(stderr, "dnssec algorithm %u verification failed: %d\n", algorithm,
            status);
  assert(status == XAIOS_OK);
  assert(ttl == 60U && memcmp(address, "\x05\x06\x07\x08", 4U) == 0);
}

static void run_malformed_corpus(void) {
  char output[256]; uint8_t self_loop[2] = {0xc0U, 0U}; uint8_t out_of_range[2] = {0xc0U, 0x7fU};
  assert(dns_decode_name(self_loop, sizeof(self_loop), 0U, output, sizeof(output)) < 0);
  assert(dns_decode_name(out_of_range, sizeof(out_of_range), 0U, output, sizeof(output)) < 0);
  uint32_t seed = UINT32_C(0x5841494f); uint8_t input[96];
  for (uint32_t case_id = 0U; case_id < 20000U; ++case_id) {
    seed = seed * UINT32_C(1664525) + UINT32_C(1013904223); uint32_t length = seed % sizeof(input) + 1U;
    for (uint32_t i = 0U; i < length; ++i) { seed = seed * UINT32_C(1664525) + UINT32_C(1013904223); input[i] = (uint8_t)(seed >> 24U); }
    (void)dns_decode_name(input, length, seed % length, output, sizeof(output));
    (void)dnssec_verify_dnskey(input, length, "", 0, wall_time_now_ns(), &(dnssec_keyset_t){0});
  }
}

static void run_validator_tests(void) {
  dnssec_keyset_t root, child; dnssec_dsset_t ds; uint8_t address[16]; uint32_t ttl = 0U;
  dnssec_init(); configure_test_anchor();
  assert(dnssec_verify_dnskey(k_root_dnskey_message, sizeof(k_root_dnskey_message), "", 0, wall_time_now_ns(), &root) == XAIOS_OK);
  assert(dnssec_verify_ds(k_test_ds_message, sizeof(k_test_ds_message), "test", &root, wall_time_now_ns(), &ds) == XAIOS_OK);
  assert(dnssec_verify_dnskey(k_test_dnskey_message, sizeof(k_test_dnskey_message), "test", &ds, wall_time_now_ns(), &child) == XAIOS_OK);
  assert(dnssec_verify_address(k_test_a_message, sizeof(k_test_a_message), "test", XAIOS_DNS_TYPE_A, &child, wall_time_now_ns(), address, &ttl) == XAIOS_OK);
  assert(ttl == 60U && memcmp(address, "\x01\x02\x03\x04", 4U) == 0);
  assert(dnssec_verify_nodata(k_test_nsec_message, sizeof(k_test_nsec_message), "missing.test", XAIOS_DNS_TYPE_AAAA, &child, wall_time_now_ns()) == XAIOS_OK);
  assert(dnssec_verify_nodata(k_test_nsec_message, sizeof(k_test_nsec_message), "other.test", XAIOS_DNS_TYPE_AAAA, &child, wall_time_now_ns()) == XAIOS_ERR_INVALID);
  verify_supported_address_algorithm(k_p256_key, sizeof(k_p256_key), 13U,
                                     k_p256_message, sizeof(k_p256_message));
  verify_supported_address_algorithm(k_p384_key, sizeof(k_p384_key), 14U,
                                     k_p384_message, sizeof(k_p384_message));
  verify_supported_address_algorithm(k_ed25519_key, sizeof(k_ed25519_key),
                                     15U, k_ed25519_message,
                                     sizeof(k_ed25519_message));
  uint8_t corrupt[sizeof(k_test_a_message)]; memcpy(corrupt, k_test_a_message, sizeof(corrupt)); corrupt[sizeof(corrupt) - 1U] ^= 1U;
  assert(dnssec_verify_address(corrupt, sizeof(corrupt), "test", XAIOS_DNS_TYPE_A, &child, wall_time_now_ns(), address, &ttl) == XAIOS_ERR_INVALID);
  assert(dnssec_verify_dnskey(k_root_dnskey_message, sizeof(k_root_dnskey_message), "", 0, UINT64_C(2530000000000000000), &root) == XAIOS_ERR_INVALID);
}

static uint32_t frame_from_dns(uint8_t *frame, const uint8_t *payload, uint32_t payload_length) {
  static const uint8_t gateway[6] = {0x52U,0x55U,0x0aU,0U,0x02U,0x02U}; static const uint8_t guest[6] = {0x52U,0x54U,0U,0x12U,0x34U,0x56U};
  assert(payload_length + DNS_PAYLOAD_OFFSET <= 512U); memcpy(frame, guest, 6U); memcpy(frame + 6U, gateway, 6U); put_be16(frame + 12U, 0x0800U); memcpy(frame + DNS_PAYLOAD_OFFSET, payload, payload_length); put_be16(frame + DNS_PAYLOAD_OFFSET, get_be16(g_tx_frame + DNS_PAYLOAD_OFFSET));
  uint8_t *udp = frame + 34U; uint16_t udp_length = (uint16_t)(8U + payload_length); put_be16(udp, XAIOS_DNS_PORT); put_be16(udp + 2U, get_be16(g_tx_frame + 34U)); put_be16(udp + 4U, udp_length); put_be16(udp + 6U, 0U); ipv4_build_header(frame + 14U, (uint16_t)(20U + udp_length), XAIOS_IPV4_PROTO_UDP, UINT32_C(0x0a000203), XAIOS_IPV4_GUEST_IP); return 14U + 20U + udp_length;
}

static const uint8_t *response_for_query(uint32_t *length) {
  char name[XAIOS_DNS_MAX_NAME]; int next = dns_decode_name(g_tx_frame + DNS_PAYLOAD_OFFSET, g_tx_length - DNS_PAYLOAD_OFFSET, 12U, name, sizeof(name)); assert(next >= 0); uint16_t type = get_be16(g_tx_frame + DNS_PAYLOAD_OFFSET + (uint32_t)next);
  if (name[0] == '\0' && type == 48U) { *length = sizeof(k_root_dnskey_message); return k_root_dnskey_message; }
  if (strcmp(name, "test") == 0 && type == 43U) { *length = sizeof(k_test_ds_message); return k_test_ds_message; }
  if (strcmp(name, "test") == 0 && type == 48U) { *length = sizeof(k_test_dnskey_message); return k_test_dnskey_message; }
  assert(strcmp(name, "test") == 0 && type == XAIOS_DNS_TYPE_A); *length = sizeof(k_test_a_message); return k_test_a_message;
}

static void run_resolver_chain(void) {
  uint32_t address = 0U; uint8_t frame[512]; dns_init(); configure_test_anchor(); dns_configure(UINT32_C(0x0a000203)); assert(dns_resolve("test", &address) == XAIOS_ERR_BUSY);
  for (uint32_t i = 0U; i < 4U; ++i) {
    uint32_t length = 0U; const uint8_t *payload = response_for_query(&length);
    xaios_status_t status = dns_process_ipv4_frame(
        frame, frame_from_dns(frame, payload, length), g_now_ns);
    assert(i == 3U ? status == XAIOS_OK : status == XAIOS_ERR_BUSY);
  }
  assert(dns_resolve("TEST", &address) == XAIOS_OK && address == UINT32_C(0x01020304)); assert(dns_authenticated_count() == 1U && dns_query_count() == 4U);
}

int main(void) {
  run_malformed_corpus();
  run_validator_tests();
  run_resolver_chain();
  puts("dns: local DNSSEC chain, negative proof, malformed corpus, and cache passed");
  return 0;
}
#endif
