#include <xaios/core_lease.h>
#include <xaios/assert.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/numa.h>
#include <xaios/smp.h>

/* How far a node-aware lease will look for CPUs when the requested node
   cannot fill the request. A machine with more nodes than this leases from
   the nearest 64 and then refuses, which is a lease that could have been
   granted and never a lease of the wrong cores. */
#define XAIOS_CORE_LEASE_MAX_NODES 64U

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

/* Whether this CPU could be leased right now, by exactly the rules
   core_lease_acquire_cpus enforces. Selection has to agree with acceptance or
   it hands back a set that is then rejected. */
static int cpu_is_leasable(uint32_t cpu_id) {
  const xaios_cpu_state_t *state = smp_cpu_state(cpu_id);
  return cpu_id != 0U && cpu_id < g_capacity && state != 0 &&
         state->online != 0U && state->role == XAIOS_CPU_ROLE_SCHEDULING &&
         g_cpu_owners[cpu_id] == 0U;
}

xaios_status_t core_lease_acquire_on_node(uint32_t owner_id, uint32_t node_id,
                                          uint32_t cpu_count,
                                          uint32_t *selected_cpu_ids) {
  if (selected_cpu_ids == 0 || cpu_count == 0U ||
      node_id >= numa_node_count()) {
    return XAIOS_ERR_INVALID;
  }
  uint32_t order[XAIOS_CORE_LEASE_MAX_NODES];
  uint32_t node_count =
      numa_nodes_by_distance(node_id, order, XAIOS_CORE_LEASE_MAX_NODES);
  if (node_count == 0U) return XAIOS_ERR_INVALID;
  uint32_t chosen = 0U;
  for (uint32_t index = 0U; index < node_count && chosen < cpu_count;
       ++index) {
    /* Ascending CPU id inside a node, so the same request on the same machine
       leases the same cores twice running. A selection that varied with, say,
       an allocation hint would make a placement-dependent failure impossible
       to reproduce. */
    for (uint32_t cpu = 1U; cpu < g_capacity && chosen < cpu_count; ++cpu) {
      if (numa_node_has_cpu(order[index], cpu) == 0) continue;
      if (!cpu_is_leasable(cpu)) continue;
      selected_cpu_ids[chosen++] = cpu;
    }
  }
  if (chosen < cpu_count) {
    /* Nothing is leased and nothing is written. The alternative -- lease what
       there is and report a short count -- gives an owner fewer CPUs than the
       work was sized for while looking like success. */
    klog("core-lease: owner=%u node=%u requested=%u available=%u refused\n",
         owner_id, node_id, cpu_count, chosen);
    return XAIOS_ERR_NO_MEMORY;
  }
  xaios_status_t status =
      core_lease_acquire_cpus(owner_id, selected_cpu_ids, cpu_count);
  if (status != XAIOS_OK) return status;
  uint32_t on_requested_node = 0U;
  for (uint32_t index = 0U; index < cpu_count; ++index) {
    if (numa_node_has_cpu(node_id, selected_cpu_ids[index])) {
      ++on_requested_node;
    }
  }
  klog("core-lease: owner=%u node=%u cpus=%u on_node=%u first_cpu=%u node_aware=1\n",
       owner_id, node_id, cpu_count, on_requested_node, selected_cpu_ids[0]);
  return XAIOS_OK;
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

static uint32_t leasable_on_node(uint32_t node_id) {
  uint32_t count = 0U;
  for (uint32_t cpu = 1U; cpu < g_capacity; ++cpu) {
    if (numa_node_has_cpu(node_id, cpu) != 0 && cpu_is_leasable(cpu) != 0) {
      ++count;
    }
  }
  return count;
}

/* The topology half of core leasing, which until node-aware selection existed
   could not be tested at all: a lease of a CPU the caller names makes no
   placement decision, so there was nothing to be right or wrong about. Every
   assertion below is written so that a selector ignoring its node argument
   fails it -- the target node is deliberately not the node owning the lowest
   leasable CPU, which is the CPU such a selector returns. */
static void core_lease_node_selection_self_test(void) {
  uint32_t nodes = numa_node_count();
  if (nodes < 2U) {
    klog("core-lease: node-aware selection self-test skipped nodes=%u (one node decides nothing)\n",
         nodes);
    return;
  }
  uint32_t lowest = 0U;
  for (uint32_t cpu = 1U; cpu < g_capacity && lowest == 0U; ++cpu) {
    if (cpu_is_leasable(cpu) != 0) lowest = cpu;
  }
  if (lowest == 0U) {
    klog("core-lease: node-aware selection self-test skipped: no leasable cpu\n");
    return;
  }
  uint32_t lowest_node = numa_node_of_cpu(lowest);
  uint32_t target = UINT32_MAX;
  for (uint32_t node = 0U; node < nodes && target == UINT32_MAX; ++node) {
    if (node != lowest_node && leasable_on_node(node) != 0U) target = node;
  }
  if (target == UINT32_MAX) {
    /* Reported rather than passed over in silence: a machine whose leasable
       CPUs all sit on one node has no placement choice to make, and a reader
       of a green gate needs to know that is why this said nothing. */
    klog("core-lease: node-aware selection self-test skipped: every leasable cpu is on node %u\n",
         lowest_node);
    return;
  }

  uint32_t available[XAIOS_CORE_LEASE_MAX_NODES];
  uint32_t available_nodes =
      nodes < XAIOS_CORE_LEASE_MAX_NODES ? nodes : XAIOS_CORE_LEASE_MAX_NODES;
  uint32_t total = 0U;
  for (uint32_t node = 0U; node < available_nodes; ++node) {
    available[node] = leasable_on_node(node);
    total += available[node];
  }

  uint32_t selected[XAIOS_CORE_LEASE_MAX_NODES];
  kassert(core_lease_acquire_on_node(200U, target, 1U, selected) == XAIOS_OK);
  kassert(numa_node_has_cpu(target, selected[0]) != 0);
  kassert(selected[0] != lowest);
  kassert(core_lease_cpu_is_used(selected[0]) != 0);
  kassert(core_lease_cpu_count() == 1U);
  kassert(core_lease_release(200U) == XAIOS_OK);
  kassert(core_lease_cpu_count() == 0U);

  uint32_t on_target = available[target];
  if (total > on_target && on_target + 1U <= XAIOS_CORE_LEASE_MAX_NODES) {
    /* One more CPU than the node can supply. The requested node must be
       emptied before another node is touched, and the spill must land on the
       nearest node that had a CPU to give -- the whole point of reading a
       SLIT. */
    uint32_t want = on_target + 1U;
    kassert(core_lease_acquire_on_node(201U, target, want, selected) ==
            XAIOS_OK);
    uint32_t from_target = 0U;
    for (uint32_t index = 0U; index < want; ++index) {
      if (numa_node_has_cpu(target, selected[index]) != 0) ++from_target;
    }
    kassert(from_target == on_target);
    uint32_t spill_node = numa_node_of_cpu(selected[want - 1U]);
    kassert(spill_node != UINT32_MAX && spill_node != target);
    for (uint32_t node = 0U; node < available_nodes; ++node) {
      if (node == target || available[node] == 0U) continue;
      kassert(numa_distance(target, spill_node) <=
              numa_distance(target, node));
    }
    klog("core-lease: node-aware spill node=%u filled=%u spill_node=%u spill_distance=%u\n",
         target, from_target, spill_node,
         (uint32_t)numa_distance(target, spill_node));
    kassert(core_lease_release(201U) == XAIOS_OK);
    kassert(core_lease_cpu_count() == 0U);
  }

  if (total + 1U <= XAIOS_CORE_LEASE_MAX_NODES) {
    /* More CPUs than the machine has: nothing is leased, so a caller that
       ignores the status does not silently run on a partial set. */
    kassert(core_lease_acquire_on_node(202U, target, total + 1U, selected) ==
            XAIOS_ERR_NO_MEMORY);
    kassert(core_lease_cpu_count() == 0U);
  }
  kassert(core_lease_acquire_on_node(203U, nodes, 1U, selected) ==
          XAIOS_ERR_INVALID);
  klog("core-lease: node-aware selection self-test passed nodes=%u target_node=%u leasable_on_target=%u leasable_total=%u\n",
       nodes, target, on_target, total);
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

  core_lease_node_selection_self_test();
  klog("core-lease: dynamic isolation self-test passed cpu_capacity=%u migration_total=%lu context_switch_total=%lu\n",
       g_capacity, core_lease_migration_count(),
       core_lease_involuntary_context_switch_count());
}
