/* The AArch64 SMP registry's public surface: the per-CPU query, the AI-cell
 * core lease, the reporting counters, the architecture's interrupt-depth
 * answer and the self-tests.
 *
 * The registry itself -- the bootstrap region, the xaios_cpu_state_t array and
 * the lock these entry points take -- belongs to smp.c, which fills it and
 * starts the secondaries; smp_platform.c answers what firmware reports. Every
 * function below moved out of smp.c whole: the same lock windows, the same
 * roles, the same klog wording. The lease paths still take the lock around the
 * whole check-and-update, and still unlock before a refusal is reported.
 */
#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/smp.h>
#include <xaios/spinlock.h>
#include <xaios/thread.h>
#include <xaios/types.h>

#include "smp_internal.h"

const xaios_cpu_state_t *smp_cpu_state(uint32_t cpu_id) {
  if (cpu_id >= a64smp_cpu_capacity) {
    return 0;
  }
  return &a64smp_cpu_states[cpu_id];
}

xaios_status_t smp_set_scheduling_enabled(uint32_t cpu_id, uint32_t enabled) {
  if (cpu_id >= a64smp_cpu_capacity || enabled > 1U) {
    return XAIOS_ERR_INVALID;
  }

  xaios_spin_lock(&a64smp_lock);
  if (a64smp_cpu_states[cpu_id].online == 0 ||
      (a64smp_cpu_states[cpu_id].role != XAIOS_CPU_ROLE_HOUSEKEEPING &&
       a64smp_cpu_states[cpu_id].role != XAIOS_CPU_ROLE_SCHEDULING)) {
    xaios_spin_unlock(&a64smp_lock);
    return XAIOS_ERR_INVALID;
  }
  a64smp_cpu_states[cpu_id].scheduling_enabled = enabled;
  xaios_spin_unlock(&a64smp_lock);
  return XAIOS_OK;
}

xaios_status_t smp_mark_core_leased(uint32_t cpu_id, uint32_t owner_id) {
  xaios_spin_lock(&a64smp_lock);

  if (cpu_id == 0 || cpu_id >= a64smp_cpu_capacity || owner_id == UINT32_MAX ||
      a64smp_cpu_states[cpu_id].online == 0 ||
      a64smp_cpu_states[cpu_id].role != XAIOS_CPU_ROLE_SCHEDULING) {
    xaios_spin_unlock(&a64smp_lock);
    return XAIOS_ERR_INVALID;
  }

  if (a64smp_cpu_states[cpu_id].lease_owner_id != 0 &&
      a64smp_cpu_states[cpu_id].lease_owner_id != owner_id + 1U) {
    ++a64smp_cpu_states[cpu_id].migration_count;
    xaios_spin_unlock(&a64smp_lock);
    return XAIOS_ERR_BUSY;
  }

  a64smp_cpu_states[cpu_id].role = XAIOS_CPU_ROLE_AI_HOT;
  a64smp_cpu_states[cpu_id].lease_owner_id = owner_id + 1U;
  a64smp_cpu_states[cpu_id].irq_routed_away = 1;
  a64smp_cpu_states[cpu_id].tick_suppressed = 1;
  a64smp_cpu_states[cpu_id].scheduling_enabled = 0;

  xaios_spin_unlock(&a64smp_lock);
  klog("smp: cpu%u leased owner=%u role=ai-hot\n", cpu_id, owner_id);
  return XAIOS_OK;
}

xaios_status_t smp_release_core_lease(uint32_t cpu_id, uint32_t owner_id) {
  xaios_spin_lock(&a64smp_lock);

  if (cpu_id == 0 || cpu_id >= a64smp_cpu_capacity ||
      a64smp_cpu_states[cpu_id].online == 0 ||
      a64smp_cpu_states[cpu_id].role != XAIOS_CPU_ROLE_AI_HOT ||
      a64smp_cpu_states[cpu_id].lease_owner_id != owner_id + 1U) {
    xaios_spin_unlock(&a64smp_lock);
    return XAIOS_ERR_INVALID;
  }

  a64smp_cpu_states[cpu_id].role = XAIOS_CPU_ROLE_SCHEDULING;
  a64smp_cpu_states[cpu_id].lease_owner_id = 0;
  a64smp_cpu_states[cpu_id].irq_routed_away = 0;
  a64smp_cpu_states[cpu_id].tick_suppressed = 0;
  a64smp_cpu_states[cpu_id].scheduling_enabled = a64smp_secondary_release;

  xaios_spin_unlock(&a64smp_lock);
  klog("smp: cpu%u released owner=%u role=scheduling\n", cpu_id, owner_id);
  return XAIOS_OK;
}

uint32_t smp_hot_core_mask(void) {
  uint32_t mask = 0;
  /* uint32_t mask only covers CPUs 0-31 */
  uint32_t limit = a64smp_cpu_capacity < 32U ? a64smp_cpu_capacity : 32U;
  for (uint32_t cpu = 0; cpu < limit; ++cpu) {
    if (a64smp_cpu_states[cpu].role == XAIOS_CPU_ROLE_AI_HOT) {
      mask |= UINT32_C(1) << cpu;
    }
  }
  return mask;
}

uint32_t smp_irq_isolated_mask(void) {
  uint32_t mask = 0;
  /* uint32_t mask only covers CPUs 0-31 */
  uint32_t limit = a64smp_cpu_capacity < 32U ? a64smp_cpu_capacity : 32U;
  for (uint32_t cpu = 0; cpu < limit; ++cpu) {
    if (a64smp_cpu_states[cpu].irq_routed_away != 0) {
      mask |= UINT32_C(1) << cpu;
    }
  }
  return mask;
}

uint64_t smp_total_migration_count(void) {
  uint64_t total = 0;
  uint32_t limit = a64smp_count_online();
  for (uint32_t cpu = 0; cpu < limit; ++cpu) {
    total += a64smp_cpu_states[cpu].migration_count;
  }
  return total;
}

uint64_t smp_total_involuntary_context_switch_count(void) {
  uint64_t total = 0;
  uint32_t limit = a64smp_count_online();
  for (uint32_t cpu = 0; cpu < limit; ++cpu) {
    total += a64smp_cpu_states[cpu].involuntary_context_switch_count;
  }
  return total;
}

uint32_t smp_online_count(void) {
  return a64smp_count_online();
}

uint32_t smp_capacity(void) { return a64smp_cpu_capacity; }

xaios_status_t smp_bootstrap_reserved_range(uint64_t *start, uint64_t *end) {
  if (start == 0 || end == 0 || a64smp_bootstrap_start == 0U ||
      a64smp_bootstrap_start >= a64smp_bootstrap_end) {
    return XAIOS_ERR_INVALID;
  }
  *start = a64smp_bootstrap_start;
  *end = a64smp_bootstrap_end;
  return XAIOS_OK;
}

xaios_status_t smp_cpu_id_at(uint32_t ordinal, uint32_t *cpu_id) {
  if (cpu_id == 0 || ordinal >= a64smp_count_online()) {
    return XAIOS_ERR_INVALID;
  }
  uint32_t found = 0;
  for (uint32_t cpu = 0; cpu < a64smp_cpu_capacity; ++cpu) {
    if (a64smp_cpu_states[cpu].online == 0) {
      continue;
    }
    if (found == ordinal) {
      *cpu_id = cpu;
      return XAIOS_OK;
    }
    ++found;
  }
  return XAIOS_ERR_INVALID;
}


xaios_status_t smp_run_user_thread_group(uint64_t requested_threads,
                                        uint64_t iterations,
                                        uint64_t *ran_threads,
                                        uint64_t *checksum) {
  return xaios_thread_run_group(requested_threads, iterations, ran_threads,
                                checksum);
}

/* The shootdown acknowledgement check is x86-64's, and saying so is the point:
 * an absent check that looks like a passed one is the failure mode this
 * project keeps having to fix (B-123).
 *
 * AArch64 does not have the problem at all: `tlbi vaae1is` is broadcast by the
 * hardware across the inner shareable domain, so no CPU waits for another
 * CPU's acknowledgement and there is no answer an interrupt could carry. */
void smp_shootdown_ack_self_test(void) {
  klog("smp: shootdown acknowledgement self-test not applicable on aarch64 "
       "-- tlbi is broadcast, nothing waits for an acknowledgement\n");
}

/* The idle-wakeup check is x86-64's, and saying so is the point: an absent
 * check that looks like a passed one is the failure mode this project keeps
 * having to fix (B-120).
 *
 * AArch64 has no such window. `sev` -- which `xaios_cpu_notify()` issues after
 * publishing a thread -- sets the wait-for-event latch that a `wfe` reaching it
 * later returns on, so a wakeup consumed before the `wfe` still leaves the
 * event that wakes it. */
void smp_idle_wakeup_self_test(void) {
  klog("smp: idle wakeup self-test not applicable on aarch64 -- sev sets the "
       "wait-for-event latch the wfe waits on\n");
}

/* Whether this CPU is inside a trap handler.
 *
 * This port answers with the interrupt mask rather than a trap depth, which is
 * what every caller asked before the question was separated: it is
 * conservative, shortening the console lock's wait in a thread context that
 * happens to hold a spinlock. x86-64 answers exactly because the observed drop
 * was there (B-119). */
uint32_t xaios_cpu_in_interrupt(void) {
  return xaios_interrupts_enabled() != 0 ? 0U : 1U;
}

void smp_self_test(void) {
  kassert(a64smp_cpu_states[0].online != 0);
  kassert(a64smp_cpu_states[0].role == XAIOS_CPU_ROLE_HOUSEKEEPING);
  kassert(a64smp_cpu_states[0].tick_suppressed == 0);
  kassert(smp_online_count() >= 1);
  klog("smp: per-core registry self-test passed online=%u\n",
       smp_online_count());
}
