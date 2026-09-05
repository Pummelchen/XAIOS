#ifndef XAIOS_TIMER_H
#define XAIOS_TIMER_H

#include <xaios/status.h>
#include <xaios/types.h>

void timer_init(void);
uint64_t timer_counter(void);
uint64_t timer_frequency_hz(void);
uint64_t timer_now_ns(void);
void timer_enable_periodic(uint32_t hz);
void timer_mask_local(void);
void timer_disable(void);
void timer_rearm(void);
/* Sleep until the deadline, whatever happens in between. A caller that
   asked for a duration gets the duration: a program that sleeps for a second
   and is woken by an unrelated packet has not slept for a second. */
void timer_idle_until(uint64_t deadline_ns);
/* Sleep until the deadline or until something the caller is waiting for
   arrives, whichever comes first. Only for callers that are waiting on an
   event and treat the deadline as a bound rather than a request. */
void timer_idle_until_event(uint64_t deadline_ns);
/* An interrupt that whoever is sleeping was waiting for. The idle wait
   samples the generation on entry and returns as soon as it changes, so a
   frame that arrives early does not wait out a sleep sized for a timeout.
   Signalled from interrupt context, so it does no more than count. */
void timer_wake_signal(void);
uint64_t timer_wake_generation(void);
void wall_time_calibrate(void);
uint64_t wall_time_now_ns(void);
xaios_status_t wall_time_set_ns(uint64_t epoch_ns, uint32_t source);
xaios_status_t wall_time_discipline_ns(uint64_t epoch_ns, uint32_t source,
                                      uint32_t maximum_ppm);
int64_t wall_time_slew_remaining_ns(void);
uint32_t wall_time_source(void);
uint64_t wall_time_last_sync_ns(void);
void timer_self_test(void);

#endif
