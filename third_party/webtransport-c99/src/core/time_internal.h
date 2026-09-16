/* Monotonic-clock arithmetic shared between the clock implementation and its test.
 *
 * Windows' QueryPerformanceCounter counts ticks at a per-boot frequency, and the conversion to microseconds is
 * the one platform-specific piece of arithmetic in `time.c`. It is a function rather than an expression so the
 * test can drive it with a tick count past the point where the naive form wraps, on every platform -- including
 * the POSIX ones whose own clock needs no conversion at all. This header is private to the library. */

#ifndef WEBTRANSPORT_TIME_INTERNAL_H
#define WEBTRANSPORT_TIME_INTERNAL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* `counter` ticks at `frequency` ticks per second, converted to microseconds. The result is
 * floor(counter * 10^6 / frequency) whenever that value is representable in uint64, which is every tick count a
 * real counter (frequency >= 10^6) can reach. A zero frequency is answered with zero rather than dividing by
 * zero, which is the same safe failure `wt_now_micros` uses. */
uint64_t wt_time_counter_to_micros(uint64_t counter, uint64_t frequency);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_TIME_INTERNAL_H */
