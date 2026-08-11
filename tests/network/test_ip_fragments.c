#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <xaios/ipv4.h>
#include <xaios/ipv6.h>

static uint64_t g_now_ns = UINT64_C(1000000000);

void panic_at(const char *file, int line, const char *fmt, ...) {
  (void)fmt;
  fprintf(stderr, "panic at %s:%d\n", file, line);
  abort();
}

void klog(const char *fmt, ...) { (void)fmt; }

uint64_t timer_now_ns(void) {
  g_now_ns += UINT64_C(1000);
  return g_now_ns;
}

static uint32_t next_random(uint32_t *state) {
  *state = *state * UINT32_C(1664525) + UINT32_C(1013904223);
  return *state;
}

static void run_malformed_corpus(void) {
  uint8_t frame[1520];
  uint32_t seed = UINT32_C(0x5841494f);
  for (uint32_t case_id = 0U; case_id < 50000U; ++case_id) {
    uint32_t length = next_random(&seed) % sizeof(frame) + 1U;
    for (uint32_t i = 0U; i < length; ++i) {
      frame[i] = (uint8_t)(next_random(&seed) >> 24U);
    }
    if ((case_id & UINT32_C(0xff)) == 0U) {
      ipv4_frag_init();
      ipv6_frag_init();
      g_now_ns += XAIOS_IPV6_FRAG_TIMEOUT_NS;
    }

    uint64_t mutable_length = length;
    (void)ipv4_validate_incoming(frame, length);
    (void)ipv4_is_fragment(frame, length);
    (void)ipv4_reassemble(frame, &mutable_length);

    mutable_length = length;
    (void)ipv6_is_fragment_v6(frame, length);
    (void)ipv6_reassemble_v6(frame, &mutable_length);
  }
}

int main(void) {
  ipv4_self_test();
  ipv6_self_test();
  run_malformed_corpus();
  puts("ip-fragments: valid vectors and 50000 malformed IPv4/IPv6 cases passed");
  return 0;
}
