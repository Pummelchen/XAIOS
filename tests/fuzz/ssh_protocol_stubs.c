#include <stdint.h>

#include "ssh_connection.h"

ssh_connection_t *ssh_conn_find(uint64_t sockfd) {
  (void)sockfd;
  return (ssh_connection_t *)0;
}

ssh_connection_scratch_t *ssh_conn_scratch(void) {
  return (ssh_connection_scratch_t *)0;
}

int xaios_net_recv(uint64_t socket, void *buffer, uint64_t size,
                   uint64_t *received) {
  (void)socket; (void)buffer; (void)size; (void)received;
  return -1;
}

int xaios_net_send(uint64_t socket, const void *buffer, uint64_t size,
                   uint64_t *sent) {
  (void)socket; (void)buffer; (void)size; (void)sent;
  return -1;
}

uint64_t xaios_clock_nanos(void) { return 0U; }
void xaios_log(const char *message) { (void)message; }
int crypto_random_bytes(uint8_t *output, uint32_t len) {
  (void)output; (void)len; return -1;
}
void ssh_mem_copy(void *dst, const void *src, uint32_t len) {
  uint8_t *d = (uint8_t *)dst;
  const uint8_t *s = (const uint8_t *)src;
  for (uint32_t i = 0U; i < len; ++i) d[i] = s[i];
}
void ssh_mem_zero(void *dst, uint32_t len) {
  uint8_t *d = (uint8_t *)dst;
  for (uint32_t i = 0U; i < len; ++i) d[i] = 0U;
}
void hmac_sha256(const uint8_t *key, uint64_t key_len, const uint8_t *data,
                 uint64_t data_len, uint8_t out[32]) {
  (void)key; (void)key_len; (void)data; (void)data_len; (void)out;
}
void aes128_ctr(const aes128_ctx_t *ctx, const uint8_t iv[16],
                const uint8_t *input, uint8_t *output, uint64_t len) {
  (void)ctx; (void)iv; (void)input; (void)output; (void)len;
}
