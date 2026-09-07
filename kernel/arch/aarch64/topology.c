#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/kheap.h>
#include <xaios/numa.h>
#include <xaios/smp.h>
#include <xaios/topology.h>

/*
 * CPU Topology Discovery and Scheduling Domain Construction
 *
 * Hierarchy, built from what NUMA discovery found rather than from an
 * assumption:
 *   - Level 0: Core domains (groups of up to 16 CPUs within one node)
 *   - Level 1: Socket domain (one per node; sockets are not discovered)
 *   - Level 2: NUMA domain (one per node that owns CPUs)
 *   - Level 3: System domain (every NUMA domain)
 *
 * This file used to write numa_node = 0 for every CPU with a comment saying
 * QEMU has one node. That was true of the profiles it was written against and
 * false of the two-node one, and the cost was not a wrong number in a struct:
 * the scheduler asks topology_get_numa_node_for_cpu which CPUs are local
 * before placing a task, so on a machine with two nodes every CPU answered
 * "node 0", every candidate satisfied "prefer the local node", and NUMA-aware
 * placement was a branch that could not fail. Nothing detected it because
 * nothing compared the answer against the SRAT the kernel had already parsed.
 *
 * Level 0 domain members are CPU ids; every other level's members are domain
 * ids. That distinction is not decorative -- see try_steal_domain, which read
 * the members of a socket domain as if they were CPUs.
 */

static xaios_cpu_topology_t *g_cpu_topology;
static xaios_sched_domain_t *g_sched_domains;
static uint32_t g_domain_count;
static uint32_t g_domain_capacity;
static uint32_t g_cpu_capacity;
static uint32_t g_topology_initialized;

static uint32_t next_domain_id(void) {
  if (g_domain_count >= g_domain_capacity) {
    return UINT32_MAX; /* overflow */
  }
  return g_domain_count++;
}

/* The NUMA node a CPU belongs to, or node 0 when nothing claims it.
   A CPU no proximity domain names still has to be scheduled somewhere, and
   node 0 is the honest default -- but the count of CPUs that landed there
   that way is logged, because folding every CPU into node 0 in silence is
   exactly what the previous hardcoded topology did and it read as working. */
static uint32_t node_of_cpu(uint32_t cpu_id, uint32_t node_count,
                            uint32_t *unclaimed) {
  if (numa_node_count() == 0U) return 0U;
  uint32_t node = numa_node_of_cpu(cpu_id);
  if (node == UINT32_MAX || node >= node_count) {
    if (unclaimed != 0) ++(*unclaimed);
    return 0U;
  }
  return node;
}

void topology_init(void) {
  uint32_t online = smp_online_count();
  if (online == 0) {
    klog("topology: no online CPUs, skipping\n");
    return;
  }

  g_cpu_capacity = smp_capacity();
  /* One NUMA domain and one socket domain per node that owns CPUs, the core
     domains under them, and the system domain. Node grouping means a node
     with a partly filled group of 16 still costs a whole core domain, so the
     bound adds one per node rather than assuming the CPUs pack. This used to
     be core_domains + 3, which is only enough while the whole machine is one
     node -- a four-node machine would have run next_domain_id() out and lost
     domains without saying so. */
  uint32_t node_count = numa_node_count();
  if (node_count == 0U) node_count = 1U;
  uint32_t core_domains = (online + 15U) / 16U;
  g_domain_capacity = core_domains + 3U * node_count + 1U;
  g_cpu_topology = (xaios_cpu_topology_t *)kheap_calloc(
      (uint64_t)g_cpu_capacity * sizeof(*g_cpu_topology), 16U);
  g_sched_domains = (xaios_sched_domain_t *)kheap_calloc(
      (uint64_t)g_domain_capacity * sizeof(*g_sched_domains), 16U);
  kassert(g_cpu_topology != 0 && g_sched_domains != 0);
  g_domain_count = 0;

  /* Level 3: System domain (covers every NUMA domain) */
  uint32_t sys_domain = next_domain_id();
  g_sched_domains[sys_domain].domain_id = sys_domain;
  g_sched_domains[sys_domain].level = 3;
  g_sched_domains[sys_domain].parent_domain = UINT32_MAX;
  g_sched_domains[sys_domain].member_count = 0;
  g_sched_domains[sys_domain].load_estimate = 0;

  uint32_t unclaimed_cpus = 0U;
  uint32_t placed_cpus = 0U;
  uint32_t nodes_with_cpus = 0U;
  for (uint32_t node = 0U; node < node_count; ++node) {
    /* Sockets are not discovered here, so each node gets one. That is a
       simplification and not a claim: a two-socket node would be described as
       one socket, which costs a level of stealing locality and never puts a
       CPU in the wrong node. */
    uint32_t numa_domain = UINT32_MAX;
    uint32_t socket_domain = UINT32_MAX;
    uint32_t core_domain = UINT32_MAX;
    uint32_t node_cpus = 0U;
    for (uint32_t cpu = 0U; cpu < g_cpu_capacity; ++cpu) {
      const xaios_cpu_state_t *state = smp_cpu_state(cpu);
      if (state == 0 || state->online == 0) {
        continue;
      }
      /* Walking CPU ids rather than an ordinal range: firmware may leave gaps
         in the id space, and this loop used to treat the first `online` ids
         as the online ones. */
      if (node_of_cpu(cpu, node_count, 0) != node) {
        continue;
      }
      if (numa_domain == UINT32_MAX) {
        numa_domain = next_domain_id();
        kassert(numa_domain != UINT32_MAX);
        g_sched_domains[numa_domain].domain_id = numa_domain;
        g_sched_domains[numa_domain].level = 2;
        g_sched_domains[numa_domain].parent_domain = sys_domain;
        g_sched_domains[numa_domain].member_count = 0;
        g_sched_domains[numa_domain].load_estimate = 0;
        if (g_sched_domains[sys_domain].member_count <
            XAIOS_SCHED_DOMAIN_MAX_MEMBERS) {
          g_sched_domains[sys_domain]
              .members[g_sched_domains[sys_domain].member_count++] =
              numa_domain;
        }

        socket_domain = next_domain_id();
        kassert(socket_domain != UINT32_MAX);
        g_sched_domains[socket_domain].domain_id = socket_domain;
        g_sched_domains[socket_domain].level = 1;
        g_sched_domains[socket_domain].parent_domain = numa_domain;
        g_sched_domains[socket_domain].member_count = 0;
        g_sched_domains[socket_domain].load_estimate = 0;
        if (g_sched_domains[numa_domain].member_count <
            XAIOS_SCHED_DOMAIN_MAX_MEMBERS) {
          g_sched_domains[numa_domain]
              .members[g_sched_domains[numa_domain].member_count++] =
              socket_domain;
        }
        ++nodes_with_cpus;
      }

      if (node_cpus % XAIOS_SCHED_DOMAIN_MAX_MEMBERS == 0U) {
        core_domain = next_domain_id();
        kassert(core_domain != UINT32_MAX);
        g_sched_domains[core_domain].domain_id = core_domain;
        g_sched_domains[core_domain].level = 0;
        g_sched_domains[core_domain].parent_domain = socket_domain;
        g_sched_domains[core_domain].member_count = 0;
        g_sched_domains[core_domain].load_estimate = 0;
        if (g_sched_domains[socket_domain].member_count <
            XAIOS_SCHED_DOMAIN_MAX_MEMBERS) {
          g_sched_domains[socket_domain]
              .members[g_sched_domains[socket_domain].member_count++] =
              core_domain;
        }
      }

      g_cpu_topology[cpu].cpu_id = cpu;
      g_cpu_topology[cpu].numa_node = node;
      g_cpu_topology[cpu].socket_id = node;
      g_cpu_topology[cpu].core_id = cpu;
      g_cpu_topology[cpu].thread_id = 0;
      g_cpu_topology[cpu].sched_domain_id = core_domain;

      if (g_sched_domains[core_domain].member_count <
          XAIOS_SCHED_DOMAIN_MAX_MEMBERS) {
        g_sched_domains[core_domain]
            .members[g_sched_domains[core_domain].member_count++] = cpu;
      }
      ++node_cpus;
      ++placed_cpus;
    }
  }
  for (uint32_t cpu = 0U; cpu < g_cpu_capacity; ++cpu) {
    const xaios_cpu_state_t *state = smp_cpu_state(cpu);
    if (state != 0 && state->online != 0U) {
      (void)node_of_cpu(cpu, node_count, &unclaimed_cpus);
    }
  }

  g_topology_initialized = 1;

  klog("topology: initialized cpus=%u placed=%u domains=%u numa_nodes=%u nodes_with_cpus=%u unclaimed_cpus=%u\n",
       online, placed_cpus, g_domain_count, node_count, nodes_with_cpus,
       unclaimed_cpus);
}

uint32_t topology_get_core_domain(uint32_t cpu_id) {
  if (cpu_id >= g_cpu_capacity || !g_topology_initialized) {
    return UINT32_MAX;
  }
  return g_cpu_topology[cpu_id].sched_domain_id;
}

uint32_t topology_get_socket_domain(uint32_t cpu_id) {
  if (cpu_id >= g_cpu_capacity || !g_topology_initialized) {
    return UINT32_MAX;
  }

  uint32_t core_domain = g_cpu_topology[cpu_id].sched_domain_id;
  if (core_domain >= g_domain_count) {
    return UINT32_MAX;
  }

  uint32_t socket_domain = g_sched_domains[core_domain].parent_domain;
  if (socket_domain >= g_domain_count) {
    return UINT32_MAX;
  }

  return socket_domain;
}

uint32_t topology_get_numa_domain(uint32_t cpu_id) {
  if (cpu_id >= g_cpu_capacity || !g_topology_initialized) {
    return UINT32_MAX;
  }

  uint32_t dom_id = g_cpu_topology[cpu_id].sched_domain_id;
  /* Walk up the domain hierarchy until we find a level-2 (NUMA) domain */
  for (uint32_t depth = 0; depth < 4 && dom_id < g_domain_count; ++depth) {
    if (g_sched_domains[dom_id].level == 2) {
      return dom_id;
    }
    dom_id = g_sched_domains[dom_id].parent_domain;
    if (dom_id == UINT32_MAX) {
      break;
    }
  }
  return UINT32_MAX;
}

const xaios_sched_domain_t *topology_get_domain(uint32_t domain_id) {
  if (domain_id >= g_domain_count || !g_topology_initialized) {
    return 0;
  }
  return &g_sched_domains[domain_id];
}

const xaios_cpu_topology_t *topology_get_cpu(uint32_t cpu_id) {
  if (cpu_id >= g_cpu_capacity || !g_topology_initialized) {
    return 0;
  }
  return &g_cpu_topology[cpu_id];
}

uint32_t topology_get_numa_node_for_cpu(uint32_t cpu_id) {
  if (cpu_id >= g_cpu_capacity || !g_topology_initialized) {
    return UINT32_MAX;
  }
  return g_cpu_topology[cpu_id].numa_node;
}

void topology_self_test(void) {
  kassert(g_topology_initialized != 0);

  uint32_t online = smp_online_count();
  kassert(online >= 1);

  /* Verify CPU 0 has valid topology */
  const xaios_cpu_topology_t *topo = topology_get_cpu(0);
  kassert(topo != 0);
  kassert(topo->cpu_id == 0);
  kassert(topo->sched_domain_id != UINT32_MAX);

  /* Verify domain hierarchy */
  uint32_t core_domain = topology_get_core_domain(0);
  kassert(core_domain != UINT32_MAX);

  const xaios_sched_domain_t *dom = topology_get_domain(core_domain);
  kassert(dom != 0);
  kassert(dom->level == 0);
  kassert(dom->member_count >= 1);

  /* Verify NUMA domain exists */
  uint32_t numa_domain = topology_get_numa_domain(0);
  kassert(numa_domain != UINT32_MAX);

  dom = topology_get_domain(numa_domain);
  kassert(dom != 0);
  kassert(dom->level == 2);

  /* Every domain has the shape the schedulers assume: a level-0 domain lists
     online CPU ids, and every other level lists domain ids that name it as
     their parent. Nothing asserted this, which is how try_steal_domain came
     to read a socket domain's members -- domain ids -- as CPU ids and go
     looking at whatever runqueue that number happened to hit. */
  for (uint32_t id = 0U; id < g_domain_count; ++id) {
    const xaios_sched_domain_t *domain = &g_sched_domains[id];
    for (uint32_t index = 0U; index < domain->member_count; ++index) {
      uint32_t member = domain->members[index];
      if (domain->level == 0U) {
        const xaios_cpu_state_t *state = smp_cpu_state(member);
        kassert(state != 0 && state->online != 0U);
        kassert(g_cpu_topology[member].sched_domain_id == id);
      } else {
        kassert(member < g_domain_count);
        kassert(g_sched_domains[member].parent_domain == id);
        kassert(g_sched_domains[member].level == domain->level - 1U);
      }
    }
  }

  /* Every CPU is in the node NUMA discovery puts it in, and a machine with
     CPUs on two nodes is described as having CPUs on two nodes. The second
     assertion is the one that fails against the topology this file used to
     build: it answered node 0 for every CPU, which satisfies the first
     assertion on a machine where node 0 happens to own CPU 0. */
  uint32_t distinct_nodes = 0U;
  uint32_t numa_nodes = numa_node_count();
  for (uint32_t node = 0U; node < (numa_nodes == 0U ? 1U : numa_nodes);
       ++node) {
    uint32_t owned = 0U;
    for (uint32_t cpu = 0U; cpu < g_cpu_capacity; ++cpu) {
      const xaios_cpu_state_t *state = smp_cpu_state(cpu);
      if (state == 0 || state->online == 0U) continue;
      if (numa_nodes != 0U && numa_node_has_cpu(node, cpu) == 0) continue;
      kassert(topology_get_numa_node_for_cpu(cpu) == node);
      ++owned;
    }
    if (owned != 0U) ++distinct_nodes;
  }
  if (numa_nodes > 1U) {
    uint32_t first_cpu = UINT32_MAX;
    uint32_t other_cpu = UINT32_MAX;
    for (uint32_t cpu = 0U; cpu < g_cpu_capacity; ++cpu) {
      const xaios_cpu_state_t *state = smp_cpu_state(cpu);
      if (state == 0 || state->online == 0U) continue;
      if (first_cpu == UINT32_MAX) {
        first_cpu = cpu;
      } else if (topology_get_numa_node_for_cpu(cpu) !=
                 topology_get_numa_node_for_cpu(first_cpu)) {
        other_cpu = cpu;
        break;
      }
    }
    kassert(distinct_nodes >= 2U);
    kassert(other_cpu != UINT32_MAX);
    /* Two CPUs on different nodes must land in different level-2 domains, or
       "steal from the same NUMA node" is stealing from the whole machine. */
    kassert(topology_get_numa_domain(first_cpu) !=
            topology_get_numa_domain(other_cpu));
    klog("topology: numa split verified cpu%u node=%u domain=%u vs cpu%u node=%u domain=%u\n",
         first_cpu, topology_get_numa_node_for_cpu(first_cpu),
         topology_get_numa_domain(first_cpu), other_cpu,
         topology_get_numa_node_for_cpu(other_cpu),
         topology_get_numa_domain(other_cpu));
  }

  klog("topology: self-test passed domains=%u online=%u numa_nodes_with_cpus=%u\n",
       g_domain_count, online, distinct_nodes);
}
