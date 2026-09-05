#include <xaios/timer.h>

/* Why this is a counter and not a flag: two interrupts between one sleeper's
   sample and its next look are indistinguishable from none if the sleeper
   clears a flag it did not set. Counting cannot lose the second one, and a
   64-bit counter incremented per interrupt does not wrap in any life this
   machine will have.

   Relaxed ordering is enough. The sleeper re-reads the world after it wakes;
   the counter says only "look again", never what to look at. */
static volatile uint64_t g_wake_generation;

void timer_wake_signal(void) {
  __atomic_add_fetch(&g_wake_generation, 1U, __ATOMIC_RELAXED);
}

uint64_t timer_wake_generation(void) {
  return __atomic_load_n(&g_wake_generation, __ATOMIC_RELAXED);
}
