/* The scheduler's load-average accounting, its statistics surface and the
 * self-tests that exercise it.
 *
 * Split out of scheduler.c, which was 1202 lines. The load-average step and
 * decay, the counters the tick and the yield publish, the per-CPU statistics
 * copy and dump, and the two self-tests (`scheduler_self_test` and the NUMA
 * steal probe) live together because the tests read exactly the numbers these
 * functions keep.
 *
 * The state itself stays in scheduler.c and is named here through
 * scheduler_internal.h, so the order `scheduler_init` establishes -- counters
 * zeroed, load-average epoch stamped, guard cleared -- is unchanged.
 */

#include "scheduler_internal.h"

#include <xaios/arch_cpu.h>
#include <xaios/assert.h>
#include <xaios/context.h>
#include <xaios/klog.h>
#include <xaios/numa.h>
#include <xaios/scheduler.h>
#include <xaios/smp.h>
#include <xaios/timer.h>
#include <xaios/topology.h>
#include <xaios/types.h>
#include <xaios/user.h>

#define XAIOS_LOAD_FIXED_ONE UINT64_C(65536)

static void scheduler_load_average_step(uint32_t active_tasks) {
  static const uint32_t decay_q16[3] = {64453U, 65318U, 65463U};
  uint64_t active_q16 = (uint64_t)active_tasks * XAIOS_LOAD_FIXED_ONE;
  for (uint32_t i = 0U; i < 3U; ++i) {
    uint64_t retained = g_load_average_q16[i] * decay_q16[i];
    uint64_t added = active_q16 * (XAIOS_LOAD_FIXED_ONE - decay_q16[i]);
    g_load_average_q16[i] =
        (retained + added + XAIOS_LOAD_FIXED_ONE / 2U) / XAIOS_LOAD_FIXED_ONE;
  }
}

static uint64_t scheduler_load_decay_power(uint32_t decay_q16,
                                           uint64_t seconds) {
  uint64_t result = XAIOS_LOAD_FIXED_ONE;
  uint64_t factor = decay_q16;
  while (seconds != 0U) {
    if ((seconds & 1U) != 0U) {
      result = (result * factor + XAIOS_LOAD_FIXED_ONE / 2U) /
               XAIOS_LOAD_FIXED_ONE;
    }
    seconds >>= 1U;
    if (seconds != 0U) {
      factor = (factor * factor + XAIOS_LOAD_FIXED_ONE / 2U) /
               XAIOS_LOAD_FIXED_ONE;
    }
  }
  return result;
}

void sched_load_average_update(uint64_t now_ns) {
  static const uint32_t decay_q16[3] = {64453U, 65318U, 65463U};
  if (__sync_lock_test_and_set(&g_load_average_guard, 1U) != 0U) return;
  if (g_load_average_last_ns == 0U) g_load_average_last_ns = now_ns;
  uint64_t elapsed_ns = now_ns >= g_load_average_last_ns
                            ? now_ns - g_load_average_last_ns
                            : 0U;
  uint64_t seconds = elapsed_ns / UINT64_C(1000000000);
  if (seconds != 0U) {
    uint64_t active = user_process_active_count();
    if (active > UINT32_MAX) active = UINT32_MAX;
    uint64_t target = active * XAIOS_LOAD_FIXED_ONE;
    for (uint32_t i = 0U; i < 3U; ++i) {
      uint64_t decay = scheduler_load_decay_power(decay_q16[i], seconds);
      g_load_average_q16[i] =
          (g_load_average_q16[i] * decay +
           target * (XAIOS_LOAD_FIXED_ONE - decay) +
           XAIOS_LOAD_FIXED_ONE / 2U) /
          XAIOS_LOAD_FIXED_ONE;
    }
    g_load_average_last_ns += seconds * UINT64_C(1000000000);
  }
  __sync_lock_release(&g_load_average_guard);
}

uint64_t scheduler_tick_count(void) { return g_tick_count; }
uint64_t scheduler_context_switch_count(void) { return g_context_switch_count; }
uint64_t scheduler_yield_count(void) { return g_yield_count; }

void scheduler_load_average_hundredths(uint32_t averages[3]) {
  if (averages == 0) {
    return;
  }
  sched_load_average_update(timer_now_ns());
  for (uint32_t i = 0U; i < 3U; ++i) {
    uint64_t value = __atomic_load_n(&g_load_average_q16[i], __ATOMIC_RELAXED);
    averages[i] = (uint32_t)((value * 100U + XAIOS_LOAD_FIXED_ONE / 2U) /
                             XAIOS_LOAD_FIXED_ONE);
  }
}

void scheduler_get_stats(uint32_t cpu_id, xaios_sched_stats_t *stats) {
  if (cpu_id >= g_cpu_capacity || stats == 0) {
    return;
  }
  *stats = g_sched_stats[cpu_id];
}

void scheduler_dump_stats(void) {
  uint32_t online = smp_online_count();

  klog("scheduler: statistics dump (%u online CPUs)\n", online);
  for (uint32_t cpu = 0; cpu < online; ++cpu) {
    const xaios_sched_stats_t *s = &g_sched_stats[cpu];
    if (s->tick_count > 0) {
      klog("scheduler: cpu%u ticks=%lu switches=%lu yields=%lu "
           "steals=%lu/%lu idle=%lu busy=%lu\n",
           cpu, s->tick_count, s->context_switch_count, s->yield_count,
           s->steal_success_count, s->steal_fail_count,
           s->idle_ticks, s->busy_ticks);
    }
  }
}

/* Load `victim` with three runnable tasks and try to steal one onto
   `this_cpu` through the hierarchy. Returns the pid stolen, or 0. Three is
   the smallest number the steal path accepts, since it refuses a victim whose
   runqueue holds two or fewer. */
static uint32_t steal_probe(uint32_t this_cpu, uint32_t victim,
                            const uint32_t *pids) {
  const xaios_cpu_state_t *state = smp_cpu_state(victim);
  if (state == 0 || state->online == 0U) return UINT32_MAX;
  uint32_t restore = state->scheduling_enabled;
  kassert(smp_set_scheduling_enabled(victim, 1U) == XAIOS_OK);
  for (uint32_t index = 0U; index < 3U; ++index) {
    kassert(sched_register_on_cpu(pids[index], XAIOS_PRIORITY_NORMAL,
                                      victim) == XAIOS_OK);
    kassert(scheduler_set_runnable(pids[index]) == XAIOS_OK);
  }
  kassert(g_runqueues[victim].count == 3U);
  uint32_t stolen = sched_try_steal_hierarchical(this_cpu);
  for (uint32_t index = 0U; index < 3U; ++index) {
    scheduler_unregister(pids[index]);
  }
  kassert(smp_set_scheduling_enabled(victim, restore) == XAIOS_OK);
  return stolen;
}

/* What the scheduler's NUMA awareness is worth, measured rather than
   asserted in a comment. Work is taken from a CPU on this CPU's own node and
   left alone on a CPU that is not, which is the whole of the policy: the
   hierarchy stops at the NUMA level and deliberately does not go system-wide,
   so a task keeps the memory it was placed near.
   
   Both halves are needed. The "does steal" half alone passes on a topology
   that puts every CPU in one domain; the "does not steal" half alone passes
   on a topology so broken that nothing is stealable at all. */
static void scheduler_numa_steal_self_test(uint32_t this_cpu) {
  if (numa_node_count() < 2U || smp_online_count() < 2U) {
    klog("scheduler: numa steal self-test skipped nodes=%u online=%u\n",
         numa_node_count(), smp_online_count());
    return;
  }
  uint32_t local_node = topology_get_numa_node_for_cpu(this_cpu);
  uint32_t local_victim = UINT32_MAX;
  uint32_t remote_victim = UINT32_MAX;
  for (uint32_t cpu = 0U; cpu < g_cpu_capacity; ++cpu) {
    const xaios_cpu_state_t *state = smp_cpu_state(cpu);
    if (cpu == this_cpu || state == 0 || state->online == 0U) continue;
    uint32_t node = topology_get_numa_node_for_cpu(cpu);
    if (node == local_node && local_victim == UINT32_MAX) local_victim = cpu;
    if (node != local_node && remote_victim == UINT32_MAX) remote_victim = cpu;
  }
  if (local_victim == UINT32_MAX || remote_victim == UINT32_MAX) {
    klog("scheduler: numa steal self-test skipped local_victim=%u remote_victim=%u\n",
         local_victim, remote_victim);
    return;
  }

  const uint32_t remote_pids[3] = {9001U, 9002U, 9003U};
  const uint32_t local_pids[3] = {9004U, 9005U, 9006U};
  uint32_t stolen_remote = steal_probe(this_cpu, remote_victim, remote_pids);
  kassert(stolen_remote == 0U);
  uint32_t stolen_local = steal_probe(this_cpu, local_victim, local_pids);
  kassert(stolen_local != 0U && stolen_local != UINT32_MAX);
  klog("scheduler: numa steal self-test passed cpu=%u node=%u local_victim=%u stole=%u remote_victim=%u stole=0\n",
       this_cpu, local_node, local_victim, stolen_local, remote_victim);
}

void scheduler_self_test(void) {
  kassert(g_initialized != 0);
  uint32_t cpu = smp_cpu_id();
  const xaios_cpu_state_t *cpu_state = smp_cpu_state(cpu);
  kassert(cpu_state != 0);
  uint32_t scheduling_was_enabled = cpu_state->scheduling_enabled;
  kassert(smp_set_scheduling_enabled(cpu, 1U) == XAIOS_OK);

  uint32_t load_average[3];
  scheduler_load_average_step(4U);
  scheduler_load_average_hundredths(load_average);
  kassert(g_load_average_q16[0] == 4332U);
  kassert(g_load_average_q16[1] == 872U);
  kassert(g_load_average_q16[2] == 292U);
  kassert(load_average[0] == 7U && load_average[1] == 1U &&
          load_average[2] == 0U);
  for (uint32_t i = 0U; i < 3U; ++i) {
    g_load_average_q16[i] = 0U;
  }

  /* Interrupts off while fake tasks are registered.
   *
   * Everything below registers three tasks whose frames are the scheduler's
   * zeroed dummy -- every register zero and `elr_el1` 0x1000 -- because what is
   * under test is the pick and the write-back into the caller's frame, not the
   * tasks. A real timer interrupt taken in this window therefore ticks the
   * scheduler for real and picks one of them, and an architecture that applies
   * the frame it is handed resumes at that task's program counter. RISC-V's now
   * does, and this was measured there: `scheduler[cpu0]: switch 0 -> 1 ... switch
   * 1 -> 2` and then `user exception: cause=12 sepc=0x0` inside this function,
   * on a boot that differed from a passing one only in timing. The mask makes
   * the window atomic with respect to the mechanism under test; it is restored
   * before the steal self-test below, which needs a live timer. */
  xaios_interrupt_state_t interrupts = xaios_interrupts_disable();
  kassert(sched_register_on_cpu(1, XAIOS_PRIORITY_HIGH, cpu) == XAIOS_OK);
  kassert(sched_register_on_cpu(2, XAIOS_PRIORITY_NORMAL, cpu) == XAIOS_OK);
  kassert(sched_register_on_cpu(3, XAIOS_PRIORITY_LOW, cpu) == XAIOS_OK);
  kassert(scheduler_set_runnable(1) == XAIOS_OK);
  kassert(scheduler_set_runnable(2) == XAIOS_OK);
  kassert(scheduler_set_runnable(3) == XAIOS_OK);
  kassert(scheduler_runnable_count() == 3);

  xaios_sched_task_t *t1 = sched_find_task_local(cpu, 1);
  xaios_sched_task_t *t2 = sched_find_task_local(cpu, 2);
  xaios_sched_task_t *t3 = sched_find_task_local(cpu, 3);
  kassert(t1 != 0 && t1->priority == XAIOS_PRIORITY_HIGH);
  kassert(t2 != 0 && t2->priority == XAIOS_PRIORITY_NORMAL);
  kassert(t3 != 0 && t3->priority == XAIOS_PRIORITY_LOW);

  g_runqueues[cpu].current_pid = 0;
  xaios_context_frame_t dummy_frame;
  sched_bytes_zero(&dummy_frame, sizeof(dummy_frame));
  dummy_frame.elr_el1 = 0x1000;

  scheduler_tick(&dummy_frame, 0);
  uint32_t picked = g_runqueues[cpu].current_pid;
  kassert(picked == 1 || picked == 2 || picked == 3);
  /* And the decision reaches the frame the caller passed, which is what an
     architecture's trap return resumes: the frame it supplied (elr 0x1000, all
     registers zero) is now the chosen task's. An architecture whose tick fills
     and applies its own frame -- and RISC-V's now does -- is checked by this
     line, and one that cannot yet apply a decision says so in its own port
     (B-129). */
  kassert(dummy_frame.elr_el1 != UINT64_C(0x1000));

  scheduler_lock();
  uint32_t before = g_runqueues[cpu].current_pid;
  scheduler_tick(&dummy_frame, 0);
  kassert(g_runqueues[cpu].current_pid == before);
  scheduler_unlock();

  kassert(scheduler_set_blocked(2) == XAIOS_OK);
  kassert(scheduler_set_runnable(2) == XAIOS_OK);

  scheduler_unregister(1);
  scheduler_unregister(2);
  scheduler_unregister(3);
  kassert(sched_find_task_local(cpu, 1) == 0);
  kassert(sched_find_task_local(cpu, 2) == 0);
  kassert(sched_find_task_local(cpu, 3) == 0);

  /* A task that is switched away from before its slice expires must stay
     pickable.
   *
   * The pick removes the running task from the queue, so a tick that chooses
   * another task has to put the outgoing one back first. Without that, the
   * second tick below finds an empty queue and leaves this CPU with no current
   * task while the task it abandoned keeps running on a frame the scheduler
   * has stopped saving -- the shape a dispatching context and the process it
   * dispatched had the first time both were runnable (B-132).
   *
   * The two tasks are equal on purpose: queue order is then the only thing
   * deciding, which is what that design rests on. A task of any other
   * priority from the block above would be picked first and hide the
   * mechanism. Interrupts are off across this window (see above), so these
   * are the only ticks. */
  kassert(sched_register_on_cpu(10, XAIOS_PRIORITY_NORMAL, cpu) == XAIOS_OK);
  kassert(sched_register_on_cpu(11, XAIOS_PRIORITY_NORMAL, cpu) == XAIOS_OK);
  kassert(scheduler_set_runnable(10) == XAIOS_OK);
  kassert(scheduler_set_runnable(11) == XAIOS_OK);
  xaios_spin_lock(&g_runqueues[cpu].lock);
  /* Emulate the state a pick leaves behind: running, and in no queue. */
  sched_rq_remove(&g_runqueues[cpu], 10);
  g_runqueues[cpu].current_pid = 10;
  xaios_spin_unlock(&g_runqueues[cpu].lock);
  xaios_sched_task_t *ten = sched_find_task_local(cpu, 10);
  kassert(ten != 0);
  ten->state = XAIOS_TASK_STATE_RUNNING;
  ten->remaining_ticks = XAIOS_PRIORITY_NORMAL_SLICE;

  xaios_context_frame_t alternate_frame;
  sched_bytes_zero(&alternate_frame, sizeof(alternate_frame));
  alternate_frame.elr_el1 = UINT64_C(0x2000);
  scheduler_tick(&alternate_frame, 0);
  scheduler_tick(&alternate_frame, 0);

  uint32_t alternate_current = g_runqueues[cpu].current_pid;
  kassert(alternate_current == 10 || alternate_current == 11);
  uint32_t alternate_waiting = alternate_current == 10U ? 11U : 10U;
  kassert(sched_rq_index(&g_runqueues[cpu], alternate_waiting) !=
          UINT32_C(0xffffffff));
  scheduler_unregister(10);
  scheduler_unregister(11);
  kassert(sched_find_task_local(cpu, 10) == 0);
  kassert(sched_find_task_local(cpu, 11) == 0);

  xaios_interrupts_restore(interrupts);
  kassert(smp_set_scheduling_enabled(cpu, scheduling_was_enabled) == XAIOS_OK);

  scheduler_numa_steal_self_test(cpu);

  klog("scheduler: hierarchical SMP self-test passed ticks=%lu switches=%lu "
       "yields=%lu steals=%lu\n",
       g_tick_count, g_context_switch_count, g_yield_count, g_steal_count);
}

