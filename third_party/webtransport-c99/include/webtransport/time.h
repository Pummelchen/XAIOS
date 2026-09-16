/* WebTransport C99: monotonic time.
 *
 * QUIC's timers -- idle timeout, loss detection, PTO, the handshake deadline --
 * are all intervals, and every one of them is wrong if the clock can go
 * backwards. So there is exactly one time source here and it is monotonic: it
 * never decreases, it is unaffected by the system clock being set, and it is not
 * comparable between processes or machines.
 *
 * That last property is why there is no wall-clock function in this header. A
 * wall clock would tempt a caller into computing a deadline as an absolute
 * timestamp, which is the bug that makes a connection hang for an hour when the
 * host's clock steps forward. Deadlines in this library are `wt_now_micros() +
 * interval`, and the comparison is a subtraction.
 */

#ifndef WEBTRANSPORT_TIME_H
#define WEBTRANSPORT_TIME_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Microseconds from an unspecified, monotonic origin. The origin is not
 * guaranteed to be process start or system boot, and the value may be large, so
 * a caller stores a base and subtracts rather than assuming where zero is. */
uint64_t wt_now_micros(void);

/* The same instant in milliseconds, truncated. Convenience for a caller whose
 * intervals are milliseconds; the subtraction rule is the same. */
uint64_t wt_now_millis(void);

/* Whether `now` is at or after the deadline `start + interval`. Written as a
 * subtraction so that a deadline beyond the counter's range -- or a start in the
 * far past -- cannot wrap into "already expired". A uint64 microsecond counter
 * covers 584,000 years, so the wrap this avoids is theoretical; the reason to
 * write it this way anyway is that it is the same length and it cannot be got
 * wrong. */
int wt_deadline_passed(uint64_t start_micros, uint64_t interval_micros,
                       uint64_t now_micros);

/* Microseconds left before `start + interval`, or 0 when it has passed. */
uint64_t wt_deadline_remaining(uint64_t start_micros, uint64_t interval_micros,
                               uint64_t now_micros);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_TIME_H */
