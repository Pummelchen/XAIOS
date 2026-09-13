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
/* Carry the network tick on this CPU, once per machine.
 *
 * The network stack is polled from the syscalls a process makes and from
 * `xaios_wait_events`, which on a booted machine means `/bin/sshd` -- and the
 * boot CPU runs kernel code with interrupts masked, so every blocking call in
 * sshd's loop is a window in which no frame is serviced at all. That is
 * `OD-011`, and it is why a served connection can die while the guest is
 * healthy: the peer gives up at its own patience, about eighteen seconds for a
 * macOS client, before anything looks at the wire again. Narrowing the window
 * is what this is for.
 *
 * `kmain` stops the shared periodic tick before it starts sshd, so the tick has
 * to be *armed*, not merely hooked: a poll placed in a timer handler that no
 * CPU reaches is unreachable code. This arms this CPU's timer after that point,
 * and the interrupt is then the network's rather than the scheduler's -- the
 * holder polls the stack and does not tick the scheduler, which stays masked on
 * that CPU exactly as the port left it. No CPU gains or loses a preemption.
 *
 * Called from the idle loop, so it is idempotent for the holder and doubles as
 * the repair for a tick that was masked while this CPU ran a task. **It must
 * not re-point a timer that is already armed.** The idle loop can iterate
 * faster than the period -- a pending interrupt sets the wait-for-event latch,
 * so `wfe` returns immediately instead of sleeping -- and re-arming every turn
 * postpones the deadline indefinitely and starves the very interrupt that would
 * advance it. That is measured, not feared: it froze the count at 18 polls and
 * again at 50 before the check was added.
 *
 * Returns 1 when this CPU holds the tick, 0 when another holds it or this port
 * cannot carry one. A port that cannot is a stated refusal, not a silent one.
 */
uint32_t timer_arm_network_tick(void);
/* The CPU carrying the network tick, or UINT32_MAX when none is. */
uint32_t timer_network_tick_cpu(void);
/* Whether this CPU's tick is the network's rather than the scheduler's.
 *
 * The carrier claims while the scheduler's own tick may still be running, and
 * until that stops it must keep taking the scheduler's branch. So the answer is
 * "am I the carrier *and* is the shared periodic tick stopped".
 */
uint32_t timer_local_tick_is_network_only(void);
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
