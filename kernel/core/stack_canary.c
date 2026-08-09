#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/panic.h>
#include <xaios/stack_canary.h>

/* Global canary, seeded by entry.S before kmain */
uint64_t g_stack_canary;

static uint64_t g_canary_initialized;
static uint64_t g_corruption_count;
static uint64_t g_test_mode;

void stack_canary_init(void) {
  /* If entry.S didn't seed the canary (e.g., test environment),
   * generate one from the timer counter here */
  if (g_stack_canary == 0) {
    g_stack_canary = xaios_cpu_counter() ^ XAIOS_CANARY_MAGIC;
  }
  g_canary_initialized = 1;
  g_corruption_count = 0;
  g_test_mode = 0;
  klog("stack_canary: initialized value=0x%lx\n", g_stack_canary);
}

uint64_t stack_canary_value(void) {
  return g_stack_canary;
}

void stack_canary_check(uint64_t saved, const char *func) {
  uint64_t sp_val = xaios_cpu_stack_pointer();
  uint64_t expected = g_stack_canary ^ sp_val;
  if (saved != expected) {
    ++g_corruption_count;
    if (g_test_mode == 0) {
      klog("STACK CORRUPTION detected in %s saved=0x%lx expected=0x%lx\n",
           func, saved, expected);
      panic("stack canary corruption detected");
    }
  }
}

uint64_t stack_canary_corruption_count(void) {
  return g_corruption_count;
}

static void canary_test_function(uint64_t *corruption_detected) {
  uint64_t saved;
  XAIOS_STACK_PROTECT_BEGIN(saved);
  /* Simulate some work */
  volatile uint64_t x = 42;
  (void)x;
  XAIOS_STACK_PROTECT_END(saved, "canary_test_function");
  *corruption_detected = 0;
}

void stack_canary_self_test(void) {
  kassert(g_canary_initialized == 1);
  kassert(g_stack_canary != 0);
  kassert(stack_canary_value() == g_stack_canary);
  /* Verify stability across reads */
  kassert(stack_canary_value() == stack_canary_value());

  /* Test protected function runs normally */
  uint64_t corruption_detected = 1;
  canary_test_function(&corruption_detected);
  kassert(corruption_detected == 0);
  kassert(g_corruption_count == 0);

  /* Test deliberate corruption detection */
  g_test_mode = 1;
  uint64_t bad_saved = 0xDEADBEEF; /* deliberately wrong */
  stack_canary_check(bad_saved, "test_corruption");
  kassert(g_corruption_count == 1);
  g_test_mode = 0;

  klog("stack_canary: self-test passed value=0x%lx corruptions_detected=%lu\n",
       g_stack_canary, g_corruption_count);
  /* Reset corruption count after self-test */
  g_corruption_count = 0;
}
