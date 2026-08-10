#ifndef XAIOS_TIMER_H
#define XAIOS_TIMER_H

#include <xaios/types.h>

void timer_init(void);
uint64_t timer_counter(void);
uint64_t timer_frequency_hz(void);
uint64_t timer_now_ns(void);
void timer_enable_periodic(uint32_t hz);
void timer_mask_local(void);
void timer_disable(void);
void timer_rearm(void);
void timer_idle_until(uint64_t deadline_ns);
void wall_time_calibrate(void);
uint64_t wall_time_now_ns(void);
void timer_self_test(void);

#endif
