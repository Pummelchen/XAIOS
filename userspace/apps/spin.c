/*
 * A process that never yields.
 *
 * The EL0 preemption proof needs an EL0 context the timer has to take the CPU
 * away from: every other userspace program this tree dispatches either blocks
 * in a syscall or exits in milliseconds, so a switch count measured across one
 * of them says what the dispatcher did and nothing about preemption (B-132).
 *
 * So this one loops for a fixed wall-clock span and never blocks -- there is
 * no sleep, no wait, no yield and no socket in it. It touches the clock once
 * per burst rather than continuously, so nearly all of the span is spent
 * executing in EL0 with the timer interrupt as the only thing that can take
 * the CPU away. The burst is real arithmetic rather than a delay loop the
 * optimiser would delete, and it is folded into a volatile sink so that the
 * work cannot be removed either.
 *
 * The span is wall-clock and not an iteration count on purpose: a count that
 * preempts in two seconds under TCG and in fifty milliseconds under a
 * hypervisor is a test whose strength depends on the machine it runs on.
 */

#include <xaios_user.h>

#define SPIN_DURATION_NS 1200000000ULL
/* Small enough that a burst is a fraction of a tick, so the clock is read
   often enough to end the loop promptly, and large enough that the clock
   syscalls are a negligible part of the span. */
#define SPIN_BURST_ROUNDS 20000ULL

static volatile u64 g_spin_sink;

static void spin_burst(u64 rounds) {
  u64 accumulator = g_spin_sink;
  for (u64 round = 0; round < rounds; ++round) {
    accumulator += round * 2654435761ULL;
    accumulator ^= accumulator >> 13;
  }
  g_spin_sink = accumulator;
}

int main(void) {
  u64 started = xaios_clock_nanos();
  u64 bursts = 0;
  xaios_log("/bin/spin: looping in EL0 without yielding\n");
  do {
    spin_burst(SPIN_BURST_ROUNDS);
    ++bursts;
  } while (xaios_clock_nanos() - started < SPIN_DURATION_NS);
  xaios_log_u64("/bin/spin: EL0 bursts=", bursts, "\n");
  return 0;
}
