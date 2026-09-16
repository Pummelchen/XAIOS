/*
 * `clock_gettime` for the vendored WebTransport library (B-131).
 *
 * The library's `src/core/time.c` asks POSIX for `clock_gettime(CLOCK_MONOTONIC)`
 * and refuses to fall back to a clock that can step backwards, which is the
 * right demand and one XAIOS can meet: `CLOCK_NANOS` with the monotonic kind
 * is exactly that clock. XAIOS's hosted libc declares the call (its `time.h`
 * has the POSIX section) but does not implement it -- `build/libc` reports it
 * as an undefined symbol -- so the port supplies it, and the library compiles
 * unchanged.
 *
 * Every clock id is answered with the monotonic clock rather than refused.
 * The library only ever asks for monotonic, and a caller that asked for wall
 * time would get a value this library would reject anyway; failing here would
 * turn a clock it does not use into a link error it cannot explain.
 */

#include <time.h>

#include <xaios_user.h>

int clock_gettime(clockid_t clock_id, struct timespec *value) {
  u64 nanos;
  (void)clock_id;
  if (value == NULL) return -1;
  nanos = xaios_clock_nanos_kind(XAIOS_CLOCK_MONOTONIC);
  value->tv_sec = (time_t)(nanos / 1000000000ULL);
  value->tv_nsec = (long)(nanos % 1000000000ULL);
  return 0;
}
