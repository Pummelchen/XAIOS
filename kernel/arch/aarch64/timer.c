#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/rtc.h>
#include <xaios/timer.h>

static uint64_t g_wall_epoch_ns;
static uint64_t g_wall_monotonic_base;
static uint64_t g_wall_last_return_ns;
static uint64_t g_wall_slew_last_mono_ns;
static int64_t g_wall_slew_remaining_ns;
static uint32_t g_wall_slew_ppm;
static uint32_t g_wall_calibrated;
static uint32_t g_wall_source;
static uint64_t g_wall_last_sync_ns;

static uint64_t g_timer_frequency_hz;
static uint64_t g_timer_interval;
static uint32_t g_timer_periodic_active;

static uint64_t read_cntfrq_el0(void) {
  uint64_t value = 0;
  __asm__ volatile("mrs %[value], cntfrq_el0" : [value] "=r"(value));
  return value;
}

static void write_cntv_cval_el0(uint64_t value) {
  __asm__ volatile("msr cntv_cval_el0, %[value]" : : [value] "r"(value));
}

static void write_cntv_ctl_el0(uint64_t value) {
  __asm__ volatile("msr cntv_ctl_el0, %[value]\n\tisb"
                   :
                   : [value] "r"(value)
                   : "memory");
}

uint64_t timer_counter(void) {
  uint64_t value = 0;
  __asm__ volatile("isb\nmrs %[value], cntvct_el0" : [value] "=r"(value));
  return value;
}

uint64_t timer_frequency_hz(void) {
  return g_timer_frequency_hz;
}

uint64_t timer_now_ns(void) {
  uint64_t counter = timer_counter();
  if (g_timer_frequency_hz == 0) {
    return 0;
  }

  return (counter / g_timer_frequency_hz) * UINT64_C(1000000000) +
         ((counter % g_timer_frequency_hz) * UINT64_C(1000000000)) /
             g_timer_frequency_hz;
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
  g_timer_frequency_hz = read_cntfrq_el0();
  klog("timer: generic counter frequency=%lu Hz\n", g_timer_frequency_hz);
  kassert(g_timer_frequency_hz != 0);
}

void timer_enable_periodic(uint32_t hz) {
  if (g_timer_frequency_hz == 0 || hz == 0) {
    return;
  }
  g_timer_interval = g_timer_frequency_hz / (uint64_t)hz;
  if (g_timer_interval == 0) {
    g_timer_interval = 1;
  }
  /* Set first compare value = now + interval */
  uint64_t now = timer_counter();
  write_cntv_cval_el0(now + g_timer_interval);
  /* Enable timer: ENABLE=1, IMASK=0 */
  write_cntv_ctl_el0(1);
  g_timer_periodic_active = 1;
  klog("timer: periodic enabled hz=%u interval=%lu\n", hz, g_timer_interval);
}

void timer_mask_local(void) {
  /* CNTV_CTL_EL0 is banked per CPU; do not alter the boot CPU's policy. */
  write_cntv_ctl_el0(2);
}

void timer_disable(void) {
  /* Disable timer: ENABLE=0, IMASK=1 */
  timer_mask_local();
  g_timer_periodic_active = 0;
  klog("timer: periodic disabled\n");
}

void timer_rearm(void) {
  if (g_timer_periodic_active == 0) {
    /* The enable register is banked per CPU. Mask a secondary's expired
     * timer after the boot CPU stops the shared periodic scheduler. */
    write_cntv_ctl_el0(2);
    return;
  }
  if (g_timer_interval == 0) {
    return;
  }
  /* Set next compare value = now + interval */
  uint64_t now = timer_counter();
  write_cntv_cval_el0(now + g_timer_interval);
}

static uint64_t duration_ticks(uint64_t duration_ns) {
  uint64_t seconds = duration_ns / UINT64_C(1000000000);
  uint64_t remainder = duration_ns % UINT64_C(1000000000);
  if (seconds > UINT64_MAX / g_timer_frequency_hz) return UINT64_MAX;
  uint64_t ticks = seconds * g_timer_frequency_hz;
  uint64_t fractional =
      (remainder * g_timer_frequency_hz + UINT64_C(999999999)) /
      UINT64_C(1000000000);
  return ticks > UINT64_MAX - fractional ? UINT64_MAX : ticks + fractional;
}

void timer_idle_until(uint64_t deadline_ns) {
  uint64_t outer_elr;
  uint64_t outer_spsr;
  __asm__ volatile("mrs %0, elr_el1\n\tmrs %1, spsr_el1"
                   : "=r"(outer_elr), "=r"(outer_spsr));
  for (;;) {
    uint64_t now_ns = timer_now_ns();
    if (now_ns >= deadline_ns) break;
    uint64_t ticks = duration_ticks(deadline_ns - now_ns);
    uint64_t counter = timer_counter();
    uint64_t compare = ticks > UINT64_MAX - counter
                           ? UINT64_MAX
                           : counter + (ticks == 0U ? 1U : ticks);
    write_cntv_cval_el0(compare);
    write_cntv_ctl_el0(1U);
    /* Sleep with interrupts masked. wfi wakes on an interrupt that is
       pending whether or not PSTATE masks it, so a timer that fires
       between arming and here still ends the sleep; unmasking first let
       it be taken before wfi, which then waited for the next interrupt
       -- on a worker CPU, which has no periodic tick, for as long as it
       took something unrelated to happen. The unmask afterwards takes
       whatever woke us. */
    __asm__ volatile("wfi\n\tmsr daifclr, #2\n\tisb\n\tmsr daifset, #2"
                     ::: "memory");
  }
  timer_mask_local();
  __asm__ volatile("msr elr_el1, %0\n\tmsr spsr_el1, %1\n\tisb"
                   :
                   : "r"(outer_elr), "r"(outer_spsr)
                   : "memory");
}

void wall_time_calibrate(void) {
  g_wall_epoch_ns = (uint64_t)rtc_read_epoch() * UINT64_C(1000000000);
  g_wall_monotonic_base = timer_now_ns();
  g_wall_last_return_ns = g_wall_epoch_ns;
  g_wall_slew_last_mono_ns = g_wall_monotonic_base;
  g_wall_calibrated = 1;
  g_wall_source = 1U;
  g_wall_last_sync_ns = timer_now_ns();
  klog("timer: wall time calibrated epoch=%lu mono_base=%lu\n",
       g_wall_epoch_ns / UINT64_C(1000000000), g_wall_monotonic_base);
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
  if (g_wall_calibrated == 0) {
    return timer_now_ns();
  }
  uint64_t mono = timer_now_ns();
  uint64_t elapsed_ns = mono >= g_wall_monotonic_base
                            ? mono - g_wall_monotonic_base
                            : 0U;
  uint64_t candidate = g_wall_epoch_ns > UINT64_MAX - elapsed_ns
                           ? UINT64_MAX
                           : g_wall_epoch_ns + elapsed_ns;
  if (g_wall_slew_remaining_ns != 0 && mono >= g_wall_slew_last_mono_ns) {
    int64_t correction = slew_correction(
        mono - g_wall_slew_last_mono_ns, g_wall_slew_remaining_ns,
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
    g_wall_slew_last_mono_ns = mono;
  }
  if (candidate < g_wall_last_return_ns) candidate = g_wall_last_return_ns;
  g_wall_epoch_ns = candidate;
  g_wall_monotonic_base = mono;
  g_wall_last_return_ns = candidate;
  return candidate;
}

void timer_self_test(void) {
  uint64_t c0 = timer_counter();
  uint64_t n0 = timer_now_ns();

  for (volatile uint64_t spin = 0; spin < UINT64_C(100000); ++spin) {
  }

  uint64_t c1 = timer_counter();
  uint64_t n1 = timer_now_ns();

  kassert(c1 >= c0);
  kassert(n1 >= n0);
  kassert(slew_correction(UINT64_C(1000000000), INT64_C(1000000), 500U) ==
          INT64_C(500000));
  kassert(slew_correction(UINT64_C(1000000000), -INT64_C(1000000), 500U) ==
          -INT64_C(500000));
  klog("timer: monotonic self-test passed counter_delta=%lu ns_delta=%lu\n",
       c1 - c0, n1 - n0);
}
