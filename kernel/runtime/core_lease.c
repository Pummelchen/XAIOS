#include <xaios/core_lease.h>
#include <xaios/assert.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/smp.h>

typedef struct core_lease {
  uint32_t owner_id;
  uint32_t cpu_count;
  uint32_t active;
} core_lease_t;

static core_lease_t *g_leases;
static uint32_t *g_cpu_owners;
static uint32_t g_capacity;
static uint32_t g_lease_capacity;

void core_lease_init(void) {
  kheap_free(g_leases);
  kheap_free(g_cpu_owners);
  g_capacity = smp_capacity();
  g_lease_capacity = g_capacity == 0U ? 1U : g_capacity;
  g_leases = (core_lease_t *)kheap_calloc(
      (uint64_t)g_lease_capacity * sizeof(core_lease_t), 16U);
  g_cpu_owners = (uint32_t *)kheap_calloc(
      (uint64_t)(g_capacity == 0U ? 1U : g_capacity) * sizeof(uint32_t), 16U);
  kassert(g_leases != 0 && g_cpu_owners != 0);
  klog("core-lease: initialized cpu_capacity=%u lease_capacity=%u\n",
       g_capacity, g_lease_capacity);
}

int core_lease_cpu_is_used(uint32_t cpu_id) {
  return cpu_id < g_capacity && g_cpu_owners[cpu_id] != 0U;
}

int core_lease_cpu_is_irq_isolated(uint32_t cpu_id) {
  const xaios_cpu_state_t *state = smp_cpu_state(cpu_id);
  return core_lease_cpu_is_used(cpu_id) != 0 && state != 0 &&
         state->irq_routed_away != 0U;
}

uint32_t core_lease_cpu_count(void) {
  uint32_t count = 0U;
  for (uint32_t cpu = 0U; cpu < g_capacity; ++cpu) {
    count += g_cpu_owners[cpu] != 0U ? 1U : 0U;
  }
  return count;
}

static core_lease_t *find_free_lease(void) {
  for (uint32_t i = 0U; i < g_lease_capacity; ++i) {
    if (g_leases[i].active == 0U) {
      return &g_leases[i];
    }
  }
  return 0;
}

static int cpu_id_appears_before(const uint32_t *cpu_ids, uint32_t index) {
  for (uint32_t i = 0U; i < index; ++i) {
    if (cpu_ids[i] == cpu_ids[index]) {
      return 1;
    }
  }
  return 0;
}

static void rollback_marked_cores(uint32_t owner_id, const uint32_t *cpu_ids,
                                  uint32_t marked_count) {
  for (uint32_t i = 0U; i < marked_count; ++i) {
    uint32_t cpu = cpu_ids[i];
    if (g_cpu_owners[cpu] == owner_id + 1U) {
      g_cpu_owners[cpu] = 0U;
      kassert(smp_release_core_lease(cpu, owner_id) == XAIOS_OK);
    }
  }
}

xaios_status_t core_lease_acquire_cpus(uint32_t owner_id,
                                       const uint32_t *cpu_ids,
                                       uint32_t cpu_count) {
  if (cpu_ids == 0 || cpu_count == 0U || owner_id == UINT32_MAX) {
    return XAIOS_ERR_INVALID;
  }
  core_lease_t *lease = find_free_lease();
  if (lease == 0) {
    return XAIOS_ERR_NO_MEMORY;
  }
  for (uint32_t i = 0U; i < cpu_count; ++i) {
    uint32_t cpu = cpu_ids[i];
    const xaios_cpu_state_t *state = smp_cpu_state(cpu);
    if (cpu == 0U || cpu >= g_capacity || state == 0 || state->online == 0U ||
        state->role != XAIOS_CPU_ROLE_SCHEDULING ||
        g_cpu_owners[cpu] != 0U || cpu_id_appears_before(cpu_ids, i) != 0) {
      return XAIOS_ERR_INVALID;
    }
  }

  uint32_t marked = 0U;
  for (; marked < cpu_count; ++marked) {
    uint32_t cpu = cpu_ids[marked];
    if (smp_mark_core_leased(cpu, owner_id) != XAIOS_OK) {
      rollback_marked_cores(owner_id, cpu_ids, marked);
      return XAIOS_ERR_INVALID;
    }
    g_cpu_owners[cpu] = owner_id + 1U;
  }
  lease->owner_id = owner_id;
  lease->cpu_count = cpu_count;
  lease->active = 1U;
  klog("core-lease: owner=%u cpus=%u acquired migration_total=%lu context_switch_total=%lu\n",
       owner_id, cpu_count, core_lease_migration_count(),
       core_lease_involuntary_context_switch_count());
  return XAIOS_OK;
}

xaios_status_t core_lease_acquire(uint32_t owner_id, uint32_t core_mask) {
  uint32_t cpu_ids[31];
  uint32_t count = 0U;
  if (core_mask == 0U || (core_mask & 1U) != 0U) {
    return XAIOS_ERR_INVALID;
  }
  for (uint32_t cpu = 1U; cpu < 32U; ++cpu) {
    if ((core_mask & (UINT32_C(1) << cpu)) != 0U) {
      cpu_ids[count++] = cpu;
    }
  }
  return core_lease_acquire_cpus(owner_id, cpu_ids, count);
}

xaios_status_t core_lease_release(uint32_t owner_id) {
  core_lease_t *lease = 0;
  for (uint32_t i = 0U; i < g_lease_capacity; ++i) {
    if (g_leases[i].active != 0U && g_leases[i].owner_id == owner_id) {
      lease = &g_leases[i];
      break;
    }
  }
  if (lease == 0) {
    return XAIOS_ERR_INVALID;
  }
  uint32_t released = 0U;
  for (uint32_t cpu = 1U; cpu < g_capacity; ++cpu) {
    if (g_cpu_owners[cpu] == owner_id + 1U) {
      kassert(smp_release_core_lease(cpu, owner_id) == XAIOS_OK);
      g_cpu_owners[cpu] = 0U;
      ++released;
    }
  }
  kassert(released == lease->cpu_count);
  klog("core-lease: owner=%u cpus=%u released\n", owner_id, released);
  lease->owner_id = 0U;
  lease->cpu_count = 0U;
  lease->active = 0U;
  return XAIOS_OK;
}

/* Low-32 compatibility views retained for the v1 AI-cell ABI and telemetry. */
uint32_t core_lease_used_mask(void) {
  uint32_t mask = 0U;
  uint32_t limit = g_capacity < 32U ? g_capacity : 32U;
  for (uint32_t cpu = 0U; cpu < limit; ++cpu) {
    if (core_lease_cpu_is_used(cpu) != 0) {
      mask |= UINT32_C(1) << cpu;
    }
  }
  return mask;
}

uint32_t core_lease_irq_isolated_mask(void) {
  uint32_t mask = 0U;
  uint32_t limit = g_capacity < 32U ? g_capacity : 32U;
  for (uint32_t cpu = 0U; cpu < limit; ++cpu) {
    if (core_lease_cpu_is_irq_isolated(cpu) != 0) {
      mask |= UINT32_C(1) << cpu;
    }
  }
  return mask;
}

uint64_t core_lease_migration_count(void) {
  return smp_total_migration_count();
}

uint64_t core_lease_involuntary_context_switch_count(void) {
  return smp_total_involuntary_context_switch_count();
}

void core_lease_self_test(void) {
  core_lease_init();
  if (smp_online_count() < 2U) {
    klog("core-lease: self-test skipped (single-core)\n");
    return;
  }

  uint32_t cpu = 1U;
  kassert(core_lease_acquire_cpus(99U, &cpu, 1U) == XAIOS_OK);
  kassert(core_lease_cpu_count() == 1U);
  kassert(core_lease_cpu_is_used(cpu) != 0);
  kassert(core_lease_cpu_is_irq_isolated(cpu) != 0);
  kassert(core_lease_acquire_cpus(100U, &cpu, 1U) == XAIOS_ERR_INVALID);
  kassert(core_lease_acquire(100U, 0x1U) == XAIOS_ERR_INVALID);
  kassert(core_lease_release(99U) == XAIOS_OK);
  kassert(core_lease_cpu_count() == 0U);

  if (smp_online_count() > 32U) {
    cpu = 32U;
    kassert(core_lease_acquire_cpus(101U, &cpu, 1U) == XAIOS_OK);
    kassert(core_lease_cpu_is_used(32U) != 0);
    kassert(core_lease_release(101U) == XAIOS_OK);
  }
  klog("core-lease: dynamic isolation self-test passed cpu_capacity=%u migration_total=%lu context_switch_total=%lu\n",
       g_capacity, core_lease_migration_count(),
       core_lease_involuntary_context_switch_count());
}
