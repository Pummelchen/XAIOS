#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/rtc.h>
#include <xaios/scheduler.h>
#include <xaios/timer.h>

#include "platform.h"

#define NANOSECONDS_PER_SECOND UINT64_C(1000000000)

static uint64_t g_frequency;
static uint64_t g_lapic_frequency;
static uint64_t g_wall_epoch_ns;
static uint64_t g_wall_monotonic_base;
static uint64_t g_wall_last_return_ns;
static uint64_t g_wall_slew_last_mono_ns;
static int64_t g_wall_slew_remaining_ns;
static uint32_t g_wall_slew_ppm;
static uint32_t g_wall_calibrated;
static uint32_t g_wall_source;
static uint64_t g_wall_last_sync_ns;
static uint32_t g_periodic_active;
static uint32_t g_periodic_hz;
/* Set while a CPU idles on a one-shot: the interrupt that ends the wait must
   not tick the scheduler, because it lands inside a syscall's wait, not
   between two instructions of a process. */
static uint32_t g_idle_wait;
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
  g_wall_epoch_ns = 0U;
  g_wall_monotonic_base = 0U;
  g_wall_last_return_ns = 0U;
  g_wall_slew_last_mono_ns = 0U;
  g_wall_slew_remaining_ns = 0;
  g_wall_slew_ppm = 0U;
  g_wall_calibrated = 0U;
  g_wall_source = 0U;
  g_wall_last_sync_ns = 0U;
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
  g_periodic_hz = hz;
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

/* Wait for a deadline with the CPU halted.
 *
 * This was a `pause` loop, which waits with the CPU fully busy: every idle
 * wait a process made -- sshd's between two polls, the process monitor's
 * between two frames -- burned the core it made it on, and the monitor,
 * once it was honest about who was running, showed sshd at a hundred
 * percent on an idle machine. AArch64 and RISC-V arm a one-shot at the
 * deadline and sleep; this is the same: the local APIC timer is set to fire
 * at the deadline, the CPU halts with interrupts enabled, and the periodic
 * tick, if this CPU had one, is put back afterwards. The interrupt that
 * ends the wait is counted but does not tick the scheduler. */
void timer_idle_until(uint64_t deadline_ns) {
  uint32_t had_periodic = g_periodic_active;
  for (;;) {
    uint64_t now_ns = timer_now_ns();
    if (now_ns >= deadline_ns) break;
    uint64_t wait_ns = deadline_ns - now_ns;
    uint64_t count = (wait_ns * g_lapic_frequency) / UINT64_C(1000000000);
    if (count == 0U) count = 1U;
    if (count > UINT32_MAX) count = UINT32_MAX;
    g_idle_wait = 1U;
    x86_64_platform_timer_start((uint32_t)count, 0U);
    __asm__ volatile("sti; hlt; cli" ::: "memory");
    g_idle_wait = 0U;
  }
  if (had_periodic != 0U && g_periodic_hz != 0U) {
    uint64_t period = g_lapic_frequency / g_periodic_hz;
    if (period == 0U) period = 1U;
    if (period > UINT32_MAX) period = UINT32_MAX;
    x86_64_platform_timer_start((uint32_t)period, 1U);
  } else {
    x86_64_platform_timer_stop();
  }
}

void wall_time_calibrate(void) {
  g_wall_epoch_ns = rtc_read_epoch() * NANOSECONDS_PER_SECOND;
  g_wall_monotonic_base = timer_now_ns();
  g_wall_last_return_ns = g_wall_epoch_ns;
  g_wall_slew_last_mono_ns = g_wall_monotonic_base;
  g_wall_calibrated = 1U;
  g_wall_source = 1U;
  g_wall_last_sync_ns = timer_now_ns();
  klog("timer: wall time calibrated epoch=%lu mono_base=%lu\n",
       g_wall_epoch_ns / NANOSECONDS_PER_SECOND,
       g_wall_monotonic_base);
}

xaios_status_t wall_time_set_ns(uint64_t epoch_ns, uint32_t source) {
  uint64_t now_ns;
  if (epoch_ns < UINT64_C(946684800000000000) || source == 0U) {
    return XAIOS_ERR_INVALID;
  }
  now_ns = timer_now_ns();
  if (g_wall_calibrated != 0U && epoch_ns < g_wall_last_return_ns) {
    return XAIOS_ERR_INVALID;
  }
  g_wall_epoch_ns = epoch_ns;
  g_wall_monotonic_base = now_ns;
  g_wall_last_return_ns = epoch_ns;
  g_wall_slew_last_mono_ns = now_ns;
  g_wall_slew_remaining_ns = 0;
  g_wall_slew_ppm = 0U;
  g_wall_calibrated = 1U;
  g_wall_source = source;
  g_wall_last_sync_ns = now_ns;
  return XAIOS_OK;
}

static int64_t slew_correction(uint64_t elapsed_ns, int64_t remaining,
                               uint32_t ppm) {
  uint64_t maximum = elapsed_ns > UINT64_MAX / ppm
                         ? UINT64_MAX
                         : (elapsed_ns * ppm) / UINT64_C(1000000);
  uint64_t magnitude = remaining < 0 ? (uint64_t)(-(remaining + 1)) + 1U
                                     : (uint64_t)remaining;
  if (maximum > magnitude) maximum = magnitude;
  return remaining < 0 ? -(int64_t)maximum : (int64_t)maximum;
}

xaios_status_t wall_time_discipline_ns(uint64_t epoch_ns, uint32_t source,
                                      uint32_t maximum_ppm) {
  if (epoch_ns < UINT64_C(946684800000000000) || source == 0U ||
      maximum_ppm == 0U || maximum_ppm > 1000U) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t current = wall_time_now_ns();
  uint64_t difference = current > epoch_ns ? current - epoch_ns
                                           : epoch_ns - current;
  if (g_wall_calibrated == 0U || current < UINT64_C(946684800000000000) ||
      (epoch_ns > current && difference > UINT64_C(300000000000))) {
    return wall_time_set_ns(epoch_ns, source);
  }
  if (difference > (uint64_t)INT64_MAX) return XAIOS_ERR_INVALID;
  g_wall_slew_remaining_ns = current > epoch_ns ? -(int64_t)difference
                                                 : (int64_t)difference;
  g_wall_slew_ppm = maximum_ppm;
  g_wall_slew_last_mono_ns = timer_now_ns();
  g_wall_source = source;
  g_wall_last_sync_ns = g_wall_slew_last_mono_ns;
  return XAIOS_OK;
}

int64_t wall_time_slew_remaining_ns(void) {
  return g_wall_slew_remaining_ns;
}

uint32_t wall_time_source(void) { return g_wall_source; }
uint64_t wall_time_last_sync_ns(void) { return g_wall_last_sync_ns; }

uint64_t wall_time_now_ns(void) {
  if (g_wall_calibrated == 0U) return timer_now_ns();
  uint64_t now = timer_now_ns();
  uint64_t elapsed = now >= g_wall_monotonic_base
                         ? now - g_wall_monotonic_base
                         : 0U;
  uint64_t candidate = g_wall_epoch_ns > UINT64_MAX - elapsed
                           ? UINT64_MAX
                           : g_wall_epoch_ns + elapsed;
  if (g_wall_slew_remaining_ns != 0 && now >= g_wall_slew_last_mono_ns) {
    int64_t correction = slew_correction(
        now - g_wall_slew_last_mono_ns, g_wall_slew_remaining_ns,
        g_wall_slew_ppm);
    if (correction < 0) {
      uint64_t magnitude = (uint64_t)(-(correction + 1)) + 1U;
      candidate = candidate > magnitude ? candidate - magnitude : 0U;
    } else if (candidate <= UINT64_MAX - (uint64_t)correction) {
      candidate += (uint64_t)correction;
    } else {
      candidate = UINT64_MAX;
    }
    g_wall_slew_remaining_ns -= correction;
    g_wall_slew_last_mono_ns = now;
  }
  if (candidate < g_wall_last_return_ns) candidate = g_wall_last_return_ns;
  g_wall_epoch_ns = candidate;
  g_wall_monotonic_base = now;
  g_wall_last_return_ns = candidate;
  return candidate;
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
  kassert(slew_correction(UINT64_C(1000000000), INT64_C(1000000), 500U) ==
          INT64_C(500000));
  kassert(slew_correction(UINT64_C(1000000000), -INT64_C(1000000), 500U) ==
          -INT64_C(500000));
  klog("timer: monotonic self-test passed counter_delta=%lu ns_delta=%lu\n",
       end - start, end_ns - start_ns);
}

void x86_64_platform_timer_irq(void) {
  if (g_periodic_active != 0U && g_idle_wait == 0U) {
    scheduler_tick(&g_irq_frame, 0);
  }
}
