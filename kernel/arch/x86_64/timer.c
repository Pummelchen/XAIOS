#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/rtc.h>
#include <xaios/scheduler.h>
#include <xaios/timer.h>

#include "platform.h"

#define NANOSECONDS_PER_SECOND UINT64_C(1000000000)

static uint64_t g_frequency;
static uint64_t g_lapic_frequency;
static uint64_t g_wall_epoch;
static uint64_t g_wall_monotonic_base;
static uint32_t g_wall_calibrated;
static uint32_t g_periodic_active;
static xaios_context_frame_t g_irq_frame;

static uint64_t ticks_to_ns(uint64_t ticks) {
  if (g_frequency == 0U) return 0U;
  uint64_t seconds = ticks / g_frequency;
  uint64_t remainder = ticks % g_frequency;
  if (seconds > UINT64_MAX / NANOSECONDS_PER_SECOND) return UINT64_MAX;
  return seconds * NANOSECONDS_PER_SECOND +
         (remainder * NANOSECONDS_PER_SECOND) / g_frequency;
}

void timer_init(void) {
  g_frequency = x86_64_platform_tsc_hz();
  g_lapic_frequency = x86_64_platform_lapic_hz();
  if (g_frequency == 0U) g_frequency = UINT64_C(1000000000);
  if (g_lapic_frequency == 0U) g_lapic_frequency = UINT64_C(1000000);
  g_periodic_active = 0U;
  g_wall_calibrated = 0U;
  klog("timer: x86 TSC frequency=%lu Hz lapic=%lu Hz\n", g_frequency,
       g_lapic_frequency);
}

uint64_t timer_counter(void) { return x86_64_platform_tsc(); }

uint64_t timer_frequency_hz(void) { return g_frequency; }

uint64_t timer_now_ns(void) { return ticks_to_ns(timer_counter()); }

void timer_enable_periodic(uint32_t hz) {
  if (hz == 0U) {
    timer_disable();
    return;
  }
  uint64_t count = g_lapic_frequency / hz;
  if (count == 0U) count = 1U;
  if (count > UINT32_MAX) count = UINT32_MAX;
  g_periodic_active = 1U;
  x86_64_platform_timer_start((uint32_t)count, 1U);
  klog("timer: periodic enabled hz=%u interval=%lu\n", hz, count);
}

void timer_mask_local(void) { x86_64_platform_timer_stop(); }

void timer_disable(void) {
  g_periodic_active = 0U;
  x86_64_platform_timer_stop();
  klog("timer: periodic disabled\n");
}

void timer_rearm(void) {
  if (g_periodic_active == 0U) x86_64_platform_timer_stop();
}

void timer_idle_until(uint64_t deadline_ns) {
  while (timer_now_ns() < deadline_ns) {
    __asm__ volatile("pause" ::: "memory");
  }
}

void wall_time_calibrate(void) {
  g_wall_epoch = rtc_read_epoch();
  g_wall_monotonic_base = timer_now_ns();
  g_wall_calibrated = 1U;
  klog("timer: wall time calibrated epoch=%lu mono_base=%lu\n", g_wall_epoch,
       g_wall_monotonic_base);
}

uint64_t wall_time_now_ns(void) {
  if (g_wall_calibrated == 0U) return timer_now_ns();
  uint64_t now = timer_now_ns();
  uint64_t elapsed = now - g_wall_monotonic_base;
  uint64_t seconds = elapsed / NANOSECONDS_PER_SECOND;
  uint64_t remainder = elapsed % NANOSECONDS_PER_SECOND;
  if (g_wall_epoch > UINT64_MAX - seconds) return UINT64_MAX;
  uint64_t epoch = g_wall_epoch + seconds;
  if (epoch > UINT64_MAX / NANOSECONDS_PER_SECOND) return UINT64_MAX;
  return epoch * NANOSECONDS_PER_SECOND + remainder;
}

void timer_self_test(void) {
  uint64_t start = timer_counter();
  uint64_t start_ns = timer_now_ns();
  for (uint32_t spin = 0U; spin < 10000U; ++spin) {
    __asm__ volatile("pause" ::: "memory");
  }
  uint64_t end = timer_counter();
  uint64_t end_ns = timer_now_ns();
  kassert(end > start && end_ns >= start_ns);
  klog("timer: monotonic self-test passed counter_delta=%lu ns_delta=%lu\n",
       end - start, end_ns - start_ns);
}

void x86_64_platform_timer_irq(void) {
  if (g_periodic_active != 0U) scheduler_tick(&g_irq_frame);
}
