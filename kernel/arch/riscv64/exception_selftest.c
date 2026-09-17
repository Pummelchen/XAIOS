/* The RISC-V kernel-context preemption self-test.
 *
 * This was the tail of exception.c, moved here whole. It hands this CPU to a
 * second kernel context whose frame xaios_context_frame_kernel_entry built,
 * and requires the timer to bring the first context back with its own
 * floating-point register value intact -- the measurement behind B-132. The
 * order of the registration, adoption and runnable calls is unchanged and
 * matters; nothing but the file it sits in has moved.
 *
 * It reaches the rest of the kernel only through public declarations --
 * xaios/scheduler.h, xaios/context.h, xaios/smp.h, xaios/timer.h -- and shares
 * no state with exception.c or exception_frame.c.
 */
#include "exception_internal.h"

#include <xaios/assert.h>
#include <xaios/context.h>
#include <xaios/scheduler.h>
#include <xaios/smp.h>
#include <xaios/status.h>
#include <xaios/timer.h>

/* One 8 KiB stack for the test's own task, and the count its trampoline bumps.
 *
 * Static rather than allocated: the point of the test is the switch itself, and
 * a kernel stack obtained from an allocator would add a way for the test to
 * fail for a reason that is not the switch. */
static uint64_t g_preempt_stack[1024] __attribute__((aligned(16)));
static volatile uint64_t g_preempt_runs;

/* One floating-point register, written and read as bits so the test cannot be
 * rewritten by a compiler into something that never touches the unit. */
static const uint64_t RISCV64_FP_HOST_BITS = UINT64_C(0x0123456789abcdef);
static const uint64_t RISCV64_FP_TASK_BITS = UINT64_C(0xfedcba9876543210);

static void riscv64_fp_write(uint64_t bits) {
  __asm__ volatile("fmv.d.x f0, %0" : : "r"(bits));
}

static uint64_t riscv64_fp_read(void) {
  uint64_t bits = 0U;
  __asm__ volatile("fmv.x.d %0, f0" : "=r"(bits));
  return bits;
}
#define RISCV64_PREEMPT_TASK_PID UINT32_C(30000)
#define RISCV64_PREEMPT_HOST_PID UINT32_C(30001)

/* Runs in kernel mode on the test task's own stack, and never returns: a task
 * that returns has nowhere to return to, which is the whole reason leaving is a
 * switch rather than a `ret`.
 *
 * The order of the two calls matters. The context that handed the CPU over has
 * to be runnable *before* this one stops being, or the tick that follows finds
 * nothing to pick and leaves the machine in a task that is doing nothing. */
static void riscv64_preempt_task_entry(void) {
  ++g_preempt_runs;
  /* A value of this task's own, in the same register the context that handed
     the CPU over wrote before it stopped: on the way back that context must
     find its own value, not this one. */
  riscv64_fp_write(RISCV64_FP_TASK_BITS);
  (void)scheduler_set_runnable(RISCV64_PREEMPT_HOST_PID);
  (void)scheduler_set_blocked(RISCV64_PREEMPT_TASK_PID);
  for (;;) {
    __asm__ volatile("wfi" ::: "memory");
  }
}

void platform_kernel_preemption_self_test(void) {
  uint32_t cpu = smp_cpu_id();
  const xaios_cpu_state_t *cpu_state = smp_cpu_state(cpu);
  uint32_t was_enabled = cpu_state != 0 ? cpu_state->scheduling_enabled : 0U;
  uint64_t stack_top = ((uint64_t)(uintptr_t)g_preempt_stack +
                        sizeof(g_preempt_stack)) & ~UINT64_C(0xf);

  xaios_context_frame_t probe;
  if (xaios_context_frame_kernel_entry(&probe, riscv64_preempt_task_entry,
                                       stack_top) == 0) {
    klog("sched-preempt: riscv64 not applicable -- this port cannot build a "
         "kernel-entry frame\n");
    return;
  }
  if (smp_set_scheduling_enabled(cpu, 1U) != XAIOS_OK) {
    klog("sched-preempt: riscv64 could not enable scheduling on cpu=%u\n",
         (unsigned)cpu);
    return;
  }

  g_preempt_runs = 0U;
  /* Order matters: the task is registered but not yet runnable, this context is
     adopted (so the tick can save it), and only then is the task made runnable.
     Registering it runnable first leaves a window in which a tick takes the CPU
     from a context whose frame does not exist yet. */
  int registered =
      scheduler_register_kernel_task(RISCV64_PREEMPT_TASK_PID,
                                     riscv64_preempt_task_entry, stack_top,
                                     XAIOS_PRIORITY_HIGH) == XAIOS_OK &&
      scheduler_adopt_this_context(RISCV64_PREEMPT_HOST_PID,
                                   XAIOS_PRIORITY_NORMAL) == XAIOS_OK &&
      scheduler_set_runnable(RISCV64_PREEMPT_TASK_PID) == XAIOS_OK;
  uint64_t deadline = timer_now_ns() + UINT64_C(500000000);
  if (registered != 0) {
    /* A live floating-point value, written before the CPU is given away. */
    riscv64_fp_write(RISCV64_FP_HOST_BITS);
    /* This context stops being runnable, so the very next tick must run the
       other task rather than keep this one for the rest of its slice. */
    (void)scheduler_set_blocked(RISCV64_PREEMPT_HOST_PID);
    while (g_preempt_runs == 0U && timer_now_ns() < deadline) {
      __asm__ volatile("wfi" ::: "memory");
    }
  }

  int ran = g_preempt_runs != 0U;
  /* Per-task floating-point state, asserted across a real switch: this
     register held `RISCV64_FP_HOST_BITS` when the CPU was given away and the
     other task wrote its own value into it while it ran. Anything but the
     host's value here means the two tasks shared one set of registers. */
  int fp_kept = riscv64_fp_read() == RISCV64_FP_HOST_BITS;
  /* Counted, not assumed: the switch numbers the scheduler kept while the test
     held the CPU are the difference between "the other task ran" and "the other
     task ran because two tasks were switched between". */
  uint64_t switches = scheduler_context_switch_count();
  scheduler_unregister(RISCV64_PREEMPT_TASK_PID);
  scheduler_unregister(RISCV64_PREEMPT_HOST_PID);
  (void)smp_set_scheduling_enabled(cpu, was_enabled);

  klog("sched-preempt: riscv64 kernel-context switch registered=%d ran=%d "
       "runs=%lu switches=%lu fp_kept=%d\n",
       registered, ran, (unsigned long)g_preempt_runs,
       (unsigned long)switches, fp_kept);
  kassert(registered != 0);
  kassert(ran != 0);
  kassert(fp_kept != 0);
  klog("sched-preempt: riscv64 kernel-context preemption self-test passed\n");
}
