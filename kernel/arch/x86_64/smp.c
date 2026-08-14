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

xaios_status_t smp_run_user_task_set(uint64_t requested_workers,
                                    uint64_t iterations,
                                    uint64_t *ran_workers,
                                    uint64_t *checksum) {
  if (requested_workers == 0U || iterations == 0U || ran_workers == 0 ||
      checksum == 0) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t workers = requested_workers < g_online ? requested_workers : g_online;
  if (iterations > UINT64_C(100000)) iterations = UINT64_C(100000);
  uint64_t total = 0U;
  for (uint64_t worker = 0U; worker < workers; ++worker) {
    uint64_t value = (worker + 1U) * UINT64_C(0x9e3779b185ebca87);
    for (uint64_t index = 0U; index < iterations; ++index) {
      value ^= (index + 1U) * (worker + 3U);
      value = (value << 7U) | (value >> 57U);
    }
    total ^= value + (iterations << (worker & 7U));
  }
  *ran_workers = workers;
  *checksum = total;
  return XAIOS_OK;
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
