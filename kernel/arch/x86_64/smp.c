#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/smp.h>
#include <xaios/thread.h>
#include <xaios/timer.h>

#include "platform.h"

#define SECONDARY_WORKER_READY_TIMEOUT_NS UINT64_C(30000000000)

static uint32_t g_capacity;
static uint32_t g_online;
static uint32_t g_housekeeping_cpu;
static uint32_t g_workers_released;
static xaios_spinlock_t g_lock = XAIOS_SPINLOCK_INIT;

uint32_t smp_cpu_id(void) { return x86_64_platform_current_ordinal(); }

xaios_status_t smp_wake_cpu(uint32_t cpu_id) {
  xaios_cpu_state_t *state = x86_64_platform_cpu_state(cpu_id);
  if (state == 0 || state->online == 0U ||
      state->scheduling_enabled == 0U) {
    return XAIOS_ERR_INVALID;
  }
  x86_64_platform_wake(cpu_id);
  return XAIOS_OK;
}

void smp_init_platform(const xaios_boot_info_t *boot) {
  (void)boot;
  g_capacity = x86_64_platform_cpu_count();
  g_online = 0U;
  g_housekeeping_cpu = x86_64_platform_current_ordinal();
  g_workers_released = 0U;
  kassert(g_housekeeping_cpu < g_capacity);
  xaios_spin_init(&g_lock);
  for (uint32_t cpu = 0U; cpu < g_capacity; ++cpu) {
    xaios_cpu_state_t *state = x86_64_platform_cpu_state(cpu);
    kassert(state != 0);
    state->cpu_id = cpu;
    state->online = x86_64_platform_cpu_online(cpu);
    state->mpidr = x86_64_platform_cpu_apic_id(cpu);
    state->role = cpu == g_housekeeping_cpu ? XAIOS_CPU_ROLE_HOUSEKEEPING
                                            : XAIOS_CPU_ROLE_SCHEDULING;
    state->lease_owner_id = 0U;
    state->irq_routed_away = 0U;
    state->tick_suppressed = 0U;
    state->migration_count = 0U;
    state->involuntary_context_switch_count = 0U;
    state->scheduling_enabled = 0U;
    state->steal_count = 0U;
    if (state->online != 0U) ++g_online;
  }
  klog("smp: x86 MADT/APIC online cpus=%u dynamic_capacity=%u\n", g_online,
       g_capacity);
}

xaios_status_t smp_bring_secondaries_online(void) {
  /* Already online: this platform starts its secondaries in
     smp_init_platform, where firmware hands them over with an address space
     they can run in. Nothing to do, and saying so is the point -- the caller
     should not have to know which platforms need it. */
  return XAIOS_OK;
}

xaios_status_t smp_release_secondary_schedulers(void) {
  for (uint32_t cpu = 0U; cpu < g_capacity; ++cpu) {
    if (cpu == g_housekeeping_cpu) continue;
    xaios_cpu_state_t *state = x86_64_platform_cpu_state(cpu);
    if (state != 0 && state->online != 0U) state->scheduling_enabled = 1U;
  }
  g_workers_released = 1U;
  x86_64_platform_release_workers();
  uint64_t started = timer_now_ns();
  for (;;) {
    uint32_t ready = x86_64_platform_workers_ready();
    if (ready == g_online) {
      klog("smp: x86 secondary worker barrier passed ready=%u\n", ready);
      return XAIOS_OK;
    }
    for (uint32_t cpu = 0U; cpu < g_capacity; ++cpu) {
      if (cpu != g_housekeeping_cpu) x86_64_platform_wake(cpu);
    }
    if (timer_now_ns() - started >= SECONDARY_WORKER_READY_TIMEOUT_NS) {
      klog("smp: x86 secondary worker barrier timed out ready=%u online=%u\n",
           ready, g_online);
      return XAIOS_ERR_BUSY;
    }
    xaios_cpu_relax();
  }
}

const xaios_cpu_state_t *smp_cpu_state(uint32_t cpu_id) {
  return x86_64_platform_cpu_state(cpu_id);
}

xaios_status_t smp_set_scheduling_enabled(uint32_t cpu_id, uint32_t enabled) {
  xaios_cpu_state_t *state = x86_64_platform_cpu_state(cpu_id);
  if (state == 0 || state->online == 0U || enabled > 1U ||
      (state->role != XAIOS_CPU_ROLE_HOUSEKEEPING &&
       state->role != XAIOS_CPU_ROLE_SCHEDULING)) {
    return XAIOS_ERR_INVALID;
  }
  state->scheduling_enabled = enabled;
  return XAIOS_OK;
}

uint32_t smp_online_count(void) { return g_online == 0U ? 1U : g_online; }
uint32_t smp_capacity(void) { return g_capacity == 0U ? 1U : g_capacity; }
/* x86_64 has no equivalent of the window this guards on AArch64: long mode
 * requires paging, so a secondary is never running with translation off, and
 * every CPU that is online already agrees on the memory attributes. Online is
 * therefore the right question here, and this just answers it in the shape the
 * lock asks for. */
uint32_t smp_locking_active(void) { return smp_online_count() > 1U ? 1U : 0U; }


xaios_status_t smp_bootstrap_reserved_range(uint64_t *start, uint64_t *end) {
  if (start == 0 || end == 0 || x86_64_platform_bootstrap_start() == 0U ||
      x86_64_platform_bootstrap_start() >= x86_64_platform_bootstrap_end()) {
    return XAIOS_ERR_INVALID;
  }
  *start = x86_64_platform_bootstrap_start();
  *end = x86_64_platform_bootstrap_end();
  return XAIOS_OK;
}

xaios_status_t smp_cpu_id_at(uint32_t ordinal, uint32_t *cpu_id) {
  if (cpu_id == 0 || ordinal >= g_online) return XAIOS_ERR_INVALID;
  uint32_t found = 0U;
  for (uint32_t cpu = 0U; cpu < g_capacity; ++cpu) {
    const xaios_cpu_state_t *state = smp_cpu_state(cpu);
    if (state == 0 || state->online == 0U) continue;
    if (found++ == ordinal) {
      *cpu_id = cpu;
      return XAIOS_OK;
    }
  }
  return XAIOS_ERR_INVALID;
}

xaios_status_t smp_mark_core_leased(uint32_t cpu_id, uint32_t owner_id) {
  xaios_cpu_state_t *state = x86_64_platform_cpu_state(cpu_id);
  if (cpu_id == g_housekeeping_cpu || state == 0 || state->online == 0U ||
      owner_id == UINT32_MAX || state->role != XAIOS_CPU_ROLE_SCHEDULING) {
    return XAIOS_ERR_INVALID;
  }
  xaios_spin_lock(&g_lock);
  if (state->lease_owner_id != 0U &&
      state->lease_owner_id != owner_id + 1U) {
    ++state->migration_count;
    xaios_spin_unlock(&g_lock);
    return XAIOS_ERR_BUSY;
  }
  state->role = XAIOS_CPU_ROLE_AI_HOT;
  state->lease_owner_id = owner_id + 1U;
  state->irq_routed_away = 1U;
  state->tick_suppressed = 1U;
  state->scheduling_enabled = 0U;
  xaios_spin_unlock(&g_lock);
  return XAIOS_OK;
}

xaios_status_t smp_release_core_lease(uint32_t cpu_id, uint32_t owner_id) {
  xaios_cpu_state_t *state = x86_64_platform_cpu_state(cpu_id);
  if (cpu_id == g_housekeeping_cpu || state == 0 || state->online == 0U ||
      state->role != XAIOS_CPU_ROLE_AI_HOT ||
      state->lease_owner_id != owner_id + 1U) {
    return XAIOS_ERR_INVALID;
  }
  xaios_spin_lock(&g_lock);
  state->role = XAIOS_CPU_ROLE_SCHEDULING;
  state->lease_owner_id = 0U;
  state->irq_routed_away = 0U;
  state->tick_suppressed = 0U;
  state->scheduling_enabled = g_workers_released;
  xaios_spin_unlock(&g_lock);
  return XAIOS_OK;
}

uint32_t smp_hot_core_mask(void) {
  uint32_t mask = 0U;
  uint32_t limit = g_capacity < 32U ? g_capacity : 32U;
  for (uint32_t cpu = 0U; cpu < limit; ++cpu) {
    const xaios_cpu_state_t *state = smp_cpu_state(cpu);
    if (state != 0 && state->role == XAIOS_CPU_ROLE_AI_HOT) {
      mask |= UINT32_C(1) << cpu;
    }
  }
  return mask;
}

uint32_t smp_irq_isolated_mask(void) {
  uint32_t mask = 0U;
  uint32_t limit = g_capacity < 32U ? g_capacity : 32U;
  for (uint32_t cpu = 0U; cpu < limit; ++cpu) {
    const xaios_cpu_state_t *state = smp_cpu_state(cpu);
    if (state != 0 && state->irq_routed_away != 0U) {
      mask |= UINT32_C(1) << cpu;
    }
  }
  return mask;
}

uint64_t smp_total_migration_count(void) {
  uint64_t total = 0U;
  for (uint32_t cpu = 0U; cpu < g_capacity; ++cpu) {
    const xaios_cpu_state_t *state = smp_cpu_state(cpu);
    if (state != 0) total += state->migration_count;
  }
  return total;
}

uint64_t smp_total_involuntary_context_switch_count(void) {
  uint64_t total = 0U;
  for (uint32_t cpu = 0U; cpu < g_capacity; ++cpu) {
    const xaios_cpu_state_t *state = smp_cpu_state(cpu);
    if (state != 0) total += state->involuntary_context_switch_count;
  }
  return total;
}


xaios_status_t smp_run_user_thread_group(uint64_t requested_threads,
                                        uint64_t iterations,
                                        uint64_t *ran_threads,
                                        uint64_t *checksum) {
  return xaios_thread_run_group(requested_threads, iterations, ran_threads,
                                checksum);
}

void smp_secondary_main(uint64_t cpu_id) { (void)cpu_id; }

void smp_self_test(void) {
  kassert(g_capacity >= g_online && g_online >= 1U);
  const xaios_cpu_state_t *boot = smp_cpu_state(smp_cpu_id());
  kassert(boot != 0 && boot->role == XAIOS_CPU_ROLE_HOUSEKEEPING);
  klog("smp: x86 per-core registry self-test passed online=%u capacity=%u\n",
       g_online, g_capacity);
}

/* ---------------------------------------------------------------------------
 * A CPU that cannot take an interrupt still answers a TLB shootdown (B-123).
 *
 * The cycle this builds on purpose. The boot CPU takes a guard, which masks
 * interrupts for the whole critical section. A thread on another CPU asks for
 * that same guard and spins with interrupts masked. The boot CPU, still inside
 * the guard, issues a shootdown. The other CPU's acknowledgement is supposed
 * to arrive as an interrupt it can no longer take, so before the fix neither
 * side could move and the shootdown timed out -- which is exactly what the
 * operations closure's x86-64 leg did, with the network guard.
 *
 * The check is run twice: once as the kernel is, where the spinning CPU
 * answers by hand and the shootdown must complete, and once with that answer
 * suppressed, which is the kernel as it was, where it must time out. Without
 * the second run "it passed" would only mean the cycle was never built; the
 * counters say which path answered, so a pass that came from the interrupt is
 * a failure of the test rather than a success of the kernel.
 * ------------------------------------------------------------------------- */

/* A guard of its own, because what the test needs is the property every
 * reentrant guard has -- it masks interrupts before it spins -- and not the
 * tables any particular guard protects. */
static xaios_reentrant_lock_t g_shootdown_test_guard =
    XAIOS_REENTRANT_LOCK_INIT("shootdown self-test guard");

typedef struct x86_shootdown_test_context {
  volatile uint32_t go;
  volatile uint32_t attempting;
  volatile uint32_t acquired;
  volatile uint32_t done;
} x86_shootdown_test_context_t;

static x86_shootdown_test_context_t g_shootdown_test;

/* Runs on the other CPU: waits for the boot CPU to take the guard, then asks
 * for it -- the masked spin the shootdown has to be answerable from. */
static uint64_t shootdown_test_worker(void *opaque) {
  x86_shootdown_test_context_t *context =
      (x86_shootdown_test_context_t *)opaque;
  while (__atomic_load_n(&context->go, __ATOMIC_ACQUIRE) == 0U) {
    xaios_cpu_relax();
  }
  __atomic_store_n(&context->attempting, 1U, __ATOMIC_RELEASE);
  xaios_reentrant_lock(&g_shootdown_test_guard, smp_cpu_id());
  __atomic_store_n(&context->acquired, 1U, __ATOMIC_RELEASE);
  xaios_reentrant_unlock(&g_shootdown_test_guard);
  __atomic_store_n(&context->done, 1U, __ATOMIC_RELEASE);
  return UINT64_C(0x5a00d);
}

/* Time the worker is given, once it says it is entering the guard, to be
 * inside the masked spin: it masks a few instructions later, and this is real
 * time rather than a guess about speed. */
#define X86_SHOOTDOWN_TEST_SETTLE_NS UINT64_C(20000000)
/* What the negative control waits for an answer it must not get. Short,
 * because the control is expected to spend it all. */
#define X86_SHOOTDOWN_TEST_CONTROL_NS UINT64_C(50000000)
#define X86_SHOOTDOWN_TEST_JOIN_NS UINT64_C(30000000000)
#define X86_SHOOTDOWN_TEST_RESULT UINT64_C(0x5a00d)

/* Run one phase and report the walk out of it. Returns the shootdown's verdict
 * (1 every CPU acknowledged, 0 the budget ran out, -1 the cycle could not be
 * built), and the two counters' deltas for the CPU under test. */
static int shootdown_test_phase(uint32_t target_cpu, uint64_t address,
                                uint64_t budget_ns, uint32_t suppress_poll,
                                uint64_t *polled_delta,
                                uint64_t *handled_delta) {
  g_shootdown_test.go = 0U;
  g_shootdown_test.attempting = 0U;
  g_shootdown_test.acquired = 0U;
  g_shootdown_test.done = 0U;
  uint64_t polled_before = x86_64_platform_shootdowns_polled(target_cpu);
  uint64_t handled_before = x86_64_platform_shootdowns_handled(target_cpu);
  uint64_t id = 0U;
  if (xaios_thread_create(shootdown_test_worker, &g_shootdown_test, target_cpu,
                          &id) != XAIOS_OK) {
    return -1;
  }
  xaios_reentrant_lock(&g_shootdown_test_guard, smp_cpu_id());
  __atomic_store_n(&g_shootdown_test.go, 1U, __ATOMIC_RELEASE);
  /* Wait for the worker's own note that it is acquiring the guard, then give
     the instructions between that note and the masked spin a fixed budget. */
  const xaios_cpu_state_t *target = smp_cpu_state(target_cpu);
  uint64_t settle_deadline = timer_now_ns() + X86_SHOOTDOWN_TEST_SETTLE_NS;
  while (target != 0 && target->waiting_for != g_shootdown_test_guard.name &&
         timer_now_ns() < settle_deadline) {
    xaios_cpu_relax();
  }
  while (timer_now_ns() < settle_deadline) {
    xaios_cpu_relax();
  }
  int complete = x86_64_platform_shootdown_probe(address, budget_ns,
                                                 suppress_poll);
  xaios_reentrant_unlock(&g_shootdown_test_guard);
  uint64_t result = 0U;
  int joined = xaios_thread_join(id, X86_SHOOTDOWN_TEST_JOIN_NS, &result) ==
               XAIOS_OK;
  *polled_delta =
      x86_64_platform_shootdowns_polled(target_cpu) - polled_before;
  *handled_delta =
      x86_64_platform_shootdowns_handled(target_cpu) - handled_before;
  if (joined == 0 || result != X86_SHOOTDOWN_TEST_RESULT) return -1;
  return complete;
}

void smp_shootdown_ack_self_test(void) {
  uint32_t self = smp_cpu_id();
  uint32_t target_cpu = UINT32_MAX;
  for (uint32_t ordinal = 0U; ordinal < x86_64_platform_cpu_count();
       ++ordinal) {
    if (ordinal != self && x86_64_platform_cpu_online(ordinal) != 0U) {
      target_cpu = ordinal;
      break;
    }
  }
  if (target_cpu == UINT32_MAX) {
    klog("smp: x86 shootdown acknowledgement self-test skipped -- one cpu "
         "online\n");
    return;
  }
  /* A permanently mapped kernel address, so the invalidation is real and the
     control that times out leaves no mapping that is about to change. */
  uint64_t address = (uint64_t)(uintptr_t)&g_shootdown_test;
  uint64_t polled_fixed = 0U;
  uint64_t handled_fixed = 0U;
  uint64_t polled_control = 0U;
  uint64_t handled_control = 0U;
  int fixed = shootdown_test_phase(target_cpu, address,
                                   x86_64_platform_shootdown_budget_ns(), 0U,
                                   &polled_fixed, &handled_fixed);
  int control = shootdown_test_phase(target_cpu, address,
                                     X86_SHOOTDOWN_TEST_CONTROL_NS, 1U,
                                     &polled_control, &handled_control);
  klog("smp: x86 shootdown acknowledgement self-test fixed=%d control=%d "
       "polled=%lu/%lu interrupted=%lu/%lu cpu=%u\n",
       fixed, control, polled_fixed, polled_control, handled_fixed,
       handled_control, target_cpu);
  kassert(fixed == 1);
  /* The answer has to have come from the spin: an interrupt could have landed
     before the worker masked them, and then this test would have proved
     nothing. */
  kassert(polled_fixed >= 1U);
  kassert(control == 0);
  kassert(polled_control == 0U);
  klog("smp: x86 shootdown acknowledgement self-test passed cpu=%u\n",
       target_cpu);
}
