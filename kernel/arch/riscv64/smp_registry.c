/* The RISC-V SMP registry's public surface: the per-CPU query, the AI-cell
 * core lease, the reporting counters and the self-tests.
 *
 * The registry itself -- the per-CPU state array, its capacity and the
 * rendezvous flag -- belongs to smp.c, which fills it and runs the secondary
 * wait loop; smp_bringup.c discovers and starts the harts. Every function
 * below moved out of smp.c whole: the same lock windows, the same roles, the
 * same klog wording. The lease paths still take the lock around the whole
 * check-and-update, and still unlock before a refusal is reported.
 */
#include <xaios/smp.h>
#include <xaios/spinlock.h>
#include <xaios/status.h>
#include <xaios/types.h>

#include "smp_internal.h"

const xaios_cpu_state_t *smp_cpu_state(uint32_t cpu_id) {
  if (cpu_id >= RISCV64_MAX_HARTS || riscv64_smp_cpu_states[cpu_id].online == 0U) {
    return 0;
  }
  return &riscv64_smp_cpu_states[cpu_id];
}

xaios_status_t smp_set_scheduling_enabled(uint32_t cpu_id, uint32_t enabled) {
  /* The value is recorded, which it was not: this discarded `enabled`, said
     XAIOS_OK, and left the flag the scheduler reads at zero. The kernel duly
     enabled scheduling, was told it had worked, and every tick then returned
     without picking anything -- a scheduler that ran, held no lock, had three
     runnable tasks, and chose none of them. A setter that reports success and
     stores nothing is worse than one that fails. */
  if (cpu_id >= RISCV64_MAX_HARTS || riscv64_smp_cpu_states[cpu_id].online == 0U) {
    return XAIOS_ERR_NOT_FOUND;
  }
  __atomic_store_n(&riscv64_smp_cpu_states[cpu_id].scheduling_enabled,
                   enabled == 0U ? 0U : 1U, __ATOMIC_RELEASE);
  return XAIOS_OK;
}

xaios_status_t smp_cpu_id_at(uint32_t ordinal, uint32_t *cpu_id) {
  if (cpu_id == 0) return XAIOS_ERR_INVALID;
  uint32_t seen = 0U;
  for (uint32_t hart = 0U; hart < RISCV64_MAX_HARTS; ++hart) {
    if (riscv64_smp_cpu_states[hart].online == 0U) continue;
    if (seen == ordinal) {
      *cpu_id = hart;
      return XAIOS_OK;
    }
    ++seen;
  }
  return XAIOS_ERR_NOT_FOUND;
}

/* The shootdown acknowledgement check is x86-64's, and saying so is the point:
 * an absent check that looks like a passed one is the failure mode this
 * project keeps having to fix (B-123).
 *
 * RISC-V's remote fence is firmware's (`sbi_remote_sfence_vma`), and that call
 * does not return until firmware says every named hart has fenced: the wait is
 * the call, so there is no acknowledgement for an interrupt to carry. */
void smp_shootdown_ack_self_test(void) {
  klog("smp: shootdown acknowledgement self-test not applicable on riscv64 "
       "-- firmware fences every hart before the call returns\n");
}

/* The idle-wakeup check is x86-64's, and saying so is the point: an absent
 * check that looks like a passed one is the failure mode this project keeps
 * having to fix (B-120).
 *
 * RISC-V has no such window after the change above: the queue is asked once
 * more with sstatus.SIE clear and `wfi` runs with it clear, so a wakeup that
 * arrives in the gap stays pending and is what `wfi` resumes for. */
void smp_idle_wakeup_self_test(void) {
  klog("smp: idle wakeup self-test not applicable on riscv64 -- wfi resumes "
       "for a pending interrupt that stays masked\n");
}

void smp_self_test(void) {
  klog("smp: riscv64 self-test passed id=%u online=%u capacity=%u\n",
       smp_cpu_id(), smp_online_count(), smp_capacity());
}

/* Memory the bootstrap path needs kept out of the allocator's hands.
 *
 * x86-64 reserves the real-mode trampoline application processors start in;
 * AArch64 reserves the spin-table page firmware parks them on. RISC-V starts
 * a hart with SBI, passing the entry address in a register, so there is no
 * fixed page to protect -- and reserving one anyway would take memory out of
 * service to guard something that does not exist. */
xaios_status_t smp_bootstrap_reserved_range(uint64_t *start, uint64_t *end) {
  if (start != 0) *start = 0U;
  if (end != 0) *end = 0U;
  return XAIOS_ERR_UNSUPPORTED;
}

/* Which cores are held for latency-sensitive work, and which have interrupts
   steered away from them. Both are empty on one hart: there is nothing to
   isolate work onto and nothing to isolate it from. */
uint32_t smp_hot_core_mask(void) { return 0U; }

uint32_t smp_irq_isolated_mask(void) { return 0U; }

/* Leasing a core to the AI runtime needs a second core to lease. Refused
   rather than granted: a lease that reports success and leaves the caller
   sharing the only hart is worse than no leasing at all. */
/* Leasing a hart out of the scheduler, which this platform used to answer
   "unsupported" to. That answer was made before secondaries existed early
   enough to lease, and once they did it was the only thing standing between
   this architecture and the cell lifecycle the other two exercise on every
   boot -- the self-test skipped itself here rather than failing, so the gap
   read as an absence of tests rather than an absence of a feature.

   The state a lease changes is the same on every architecture, because it is
   the shared scheduler that reads it. What differs is only that RISC-V has
   no interrupt affinity to route away from a leased hart: the PLIC has
   per-hart contexts and could, but nothing here programs them yet, so the
   flag is set and the routing is not claimed. */
static xaios_spinlock_t g_lease_lock = XAIOS_SPINLOCK_INIT;

xaios_status_t smp_mark_core_leased(uint32_t cpu_id, uint32_t owner_id) {
  xaios_spin_lock(&g_lease_lock);
  if (cpu_id == 0U || cpu_id >= riscv64_smp_capacity || owner_id == UINT32_MAX ||
      riscv64_smp_cpu_states[cpu_id].online == 0U ||
      riscv64_smp_cpu_states[cpu_id].role != XAIOS_CPU_ROLE_SCHEDULING) {
    xaios_spin_unlock(&g_lease_lock);
    return XAIOS_ERR_INVALID;
  }
  if (riscv64_smp_cpu_states[cpu_id].lease_owner_id != 0U &&
      riscv64_smp_cpu_states[cpu_id].lease_owner_id != owner_id + 1U) {
    ++riscv64_smp_cpu_states[cpu_id].migration_count;
    xaios_spin_unlock(&g_lease_lock);
    return XAIOS_ERR_BUSY;
  }
  riscv64_smp_cpu_states[cpu_id].role = XAIOS_CPU_ROLE_AI_HOT;
  riscv64_smp_cpu_states[cpu_id].lease_owner_id = owner_id + 1U;
  /* Not routed away, and saying so: see above. */
  riscv64_smp_cpu_states[cpu_id].irq_routed_away = 0U;
  riscv64_smp_cpu_states[cpu_id].tick_suppressed = 1U;
  riscv64_smp_cpu_states[cpu_id].scheduling_enabled = 0U;
  xaios_spin_unlock(&g_lease_lock);
  klog("smp: hart%u leased owner=%u role=ai-hot irq_routed=0\n", cpu_id,
       owner_id);
  return XAIOS_OK;
}

xaios_status_t smp_release_core_lease(uint32_t cpu_id, uint32_t owner_id) {
  xaios_spin_lock(&g_lease_lock);
  if (cpu_id == 0U || cpu_id >= riscv64_smp_capacity ||
      riscv64_smp_cpu_states[cpu_id].online == 0U ||
      riscv64_smp_cpu_states[cpu_id].role != XAIOS_CPU_ROLE_AI_HOT ||
      riscv64_smp_cpu_states[cpu_id].lease_owner_id != owner_id + 1U) {
    xaios_spin_unlock(&g_lease_lock);
    return XAIOS_ERR_INVALID;
  }
  riscv64_smp_cpu_states[cpu_id].role = XAIOS_CPU_ROLE_SCHEDULING;
  riscv64_smp_cpu_states[cpu_id].lease_owner_id = 0U;
  riscv64_smp_cpu_states[cpu_id].tick_suppressed = 0U;
  /* Back into the scheduler only if the scheduler has been opened at all: a
     hart leased before the rendezvous must not start scheduling because a
     lease ended. */
  riscv64_smp_cpu_states[cpu_id].scheduling_enabled =
      __atomic_load_n(&riscv64_smp_secondary_release, __ATOMIC_ACQUIRE);
  xaios_spin_unlock(&g_lease_lock);
  klog("smp: hart%u released owner=%u role=scheduling\n", cpu_id, owner_id);
  return XAIOS_OK;
}

uint64_t smp_total_migration_count(void) { return 0U; }

uint64_t smp_total_involuntary_context_switch_count(void) { return 0U; }
