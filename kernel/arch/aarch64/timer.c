#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/rtc.h>
#include <xaios/timer.h>

static uint64_t g_wall_epoch;
static uint64_t g_wall_monotonic_base;
static uint32_t g_wall_calibrated;

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
    __asm__ volatile("msr daifclr, #2\n\twfi\n\tmsr daifset, #2"
                     ::: "memory");
  }
  timer_mask_local();
  __asm__ volatile("msr elr_el1, %0\n\tmsr spsr_el1, %1\n\tisb"
                   :
                   : "r"(outer_elr), "r"(outer_spsr)
                   : "memory");
}

void wall_time_calibrate(void) {
  g_wall_epoch = (uint64_t)rtc_read_epoch();
  g_wall_monotonic_base = timer_now_ns();
  g_wall_calibrated = 1;
  klog("timer: wall time calibrated epoch=%lu mono_base=%lu\n",
       g_wall_epoch, g_wall_monotonic_base);
}

uint64_t wall_time_now_ns(void) {
  if (g_wall_calibrated == 0) {
    return timer_now_ns();
  }
  uint64_t mono = timer_now_ns();
  uint64_t elapsed_ns = mono - g_wall_monotonic_base;
  /* Compute wall = epoch_seconds * 1e9 + elapsed_ns, split to avoid
   * uint64_t overflow when epoch_seconds exceeds ~18.4 billion.
   * For real Unix epochs (~1.7B), the multiplication alone is ~1.7e18,
   * which fits in uint64_t (~1.8e19 max).  Add elapsed_ns separately
   * after validating no overflow. */
  if (elapsed_ns > UINT64_C(1000000000)) {
    /* More than 1 second elapsed: update epoch and keep sub-second remainder */
    uint64_t extra_sec = elapsed_ns / UINT64_C(1000000000);
    uint64_t sub_ns = elapsed_ns % UINT64_C(1000000000);
    g_wall_epoch += extra_sec;
    g_wall_monotonic_base = mono - sub_ns;
    return g_wall_epoch * UINT64_C(1000000000) + sub_ns;
  }
  return g_wall_epoch * UINT64_C(1000000000) + elapsed_ns;
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
  klog("timer: monotonic self-test passed counter_delta=%lu ns_delta=%lu\n",
       c1 - c0, n1 - n0);
}
