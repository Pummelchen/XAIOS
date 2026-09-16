/* Monotonic time. See webtransport/time.h.
 *
 * One source per platform, chosen at compile time, and every one of them is
 * monotonic. Where a platform offers only a wall clock, the right answer is a
 * build error rather than a fallback: a QUIC timer driven by a clock that can
 * step backwards is a connection that hangs or spins, and a silent fallback
 * would make that a platform-specific bug report instead of a compile failure.
 */

#include "webtransport/time.h"

#include "time_internal.h"

/* See the header. The conversion divides before multiplying so that the tick count is turned into whole seconds
 * first; multiplying first, which is what this used to do, wraps uint64 once the tick count passes
 * 2^64 / 10^6 ~ 1.84e13 -- about 21 days at the usual 10 MHz QueryPerformanceFrequency -- and the clock then
 * returns a SMALLER value than before, breaking the monotonicity this file promises and mis-arming every QUIC
 * deadline, idle timeout and probe timeout on the connection. */
uint64_t wt_time_counter_to_micros(uint64_t counter, uint64_t frequency) {
  if (frequency == 0U) return 0U;
  return (counter / frequency) * UINT64_C(1000000) +
         ((counter % frequency) * UINT64_C(1000000)) / frequency;
}

#if defined(_WIN32)
/* QueryPerformanceCounter is the monotonic source on Windows, and it is
 * specified as non-decreasing. The frequency is fixed per boot, so it is
 * queried once and cached; a frequency of zero would mean the API failed, which
 * is answered with a zero clock rather than a division by zero -- a caller that
 * sees time stand still will time out, which is the safe failure. */
#include <windows.h>
static uint64_t wt_windows_frequency(void) {
  static uint64_t cached = 0U;
  if (cached == 0U) {
    LARGE_INTEGER frequency;
    if (QueryPerformanceFrequency(&frequency) == 0 || frequency.QuadPart <= 0) {
      return 0U;
    }
    cached = (uint64_t)frequency.QuadPart;
  }
  return cached;
}
uint64_t wt_now_micros(void) {
  LARGE_INTEGER counter;
  uint64_t frequency = wt_windows_frequency();
  if (frequency == 0U) return 0U;
  if (QueryPerformanceCounter(&counter) == 0 || counter.QuadPart < 0) return 0U;
  return wt_time_counter_to_micros((uint64_t)counter.QuadPart, frequency);
}
#else
/* clock_gettime(CLOCK_MONOTONIC) on macOS, Linux and FreeBSD. Its epoch is
 * unspecified by POSIX, which is exactly the property wanted here: nothing can
 * accidentally treat this value as a calendar time. */
#include <time.h>
uint64_t wt_now_micros(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0U;
  return ((uint64_t)ts.tv_sec * 1000000U) + ((uint64_t)ts.tv_nsec / 1000U);
}
#endif

uint64_t wt_now_millis(void) { return wt_now_micros() / 1000U; }

int wt_deadline_passed(uint64_t start_micros, uint64_t interval_micros,
                       uint64_t now_micros) {
  return (now_micros - start_micros) >= interval_micros;
}

uint64_t wt_deadline_remaining(uint64_t start_micros, uint64_t interval_micros,
                               uint64_t now_micros) {
  uint64_t elapsed = now_micros - start_micros;
  if (elapsed >= interval_micros) return 0U;
  return interval_micros - elapsed;
}
