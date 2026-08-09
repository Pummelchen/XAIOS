#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/rtc.h>
#include <xaios/timer.h>

/* PL031 register offsets */
#define PL031_RTCDR  0x00U  /* Data Register (read-only, epoch seconds) */
#define PL031_RTCMR  0x04U  /* Match Register */
#define PL031_RTCLR  0x08U  /* Load Register */
#define PL031_RTCCR  0x0CU  /* Control Register (bit 0 = enable) */
#define PL031_RTCIMSC 0x10U /* Interrupt Mask Set/Clear */

static volatile uint32_t *g_rtc_base;
static uint32_t g_rtc_initialized;

void rtc_init(void) {
  g_rtc_base = (volatile uint32_t *)(uintptr_t)XAIOS_PL031_RTC_BASE;

  /* Ensure RTC is enabled (bit 0 of RTCCR) */
  uint32_t cr = g_rtc_base[PL031_RTCCR / 4];
  uint32_t epoch = rtc_read_epoch();
  if (cr == UINT32_MAX || epoch == UINT32_MAX) {
    g_rtc_base = 0;
    g_rtc_initialized = 0U;
    klog("rtc: QEMU fixed-address PL031 unavailable\n");
    return;
  }
  if ((cr & 1U) == 0) {
    g_rtc_base[PL031_RTCCR / 4] = 1U;
  }

  /* Disable interrupts */
  g_rtc_base[PL031_RTCIMSC / 4] = 0U;

  g_rtc_initialized = 1;
  klog("rtc: PL031 initialized epoch=%u\n", epoch);
}

uint32_t rtc_read_epoch(void) {
  if (g_rtc_base == 0) {
    return 0;
  }
  return g_rtc_base[PL031_RTCDR / 4];
}

void rtc_self_test(void) {
  if (g_rtc_initialized == 0U) {
    klog("rtc: self-test skipped no compatible clock\n");
    return;
  }

  uint32_t epoch0 = rtc_read_epoch();
  if (epoch0 == 0) {
    klog("rtc: WARNING epoch=0 (PL031 may not be at 0x%lx)\n",
         (uint64_t)XAIOS_PL031_RTC_BASE);
    klog("rtc: self-test skipped epoch=%u\n", epoch0);
    return;
  }

  /* wall_time_now_ns() should be monotonically increasing */
  uint64_t w0 = wall_time_now_ns();
  for (volatile uint64_t spin = 0; spin < UINT64_C(100000); ++spin) {
  }
  uint64_t w1 = wall_time_now_ns();
  kassert(w1 >= w0);
  kassert(w0 >= (uint64_t)epoch0 * UINT64_C(1000000000));

  klog("rtc: self-test passed epoch=%u wall_ns=%lu\n", epoch0, w1);
}
