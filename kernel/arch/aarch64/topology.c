#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/kheap.h>
#include <xaios/smp.h>
#include <xaios/topology.h>

/*
 * CPU Topology Discovery and Scheduling Domain Construction
 *
 * For QEMU virt: assumes single NUMA node, single socket, linear core IDs, no SMT.
 * Builds a simplified hierarchy:
 *   - Level 0: Core domains (groups of up to 16 consecutive CPUs)
 *   - Level 1: Socket domain (single socket containing all core domains)
 *   - Level 2: NUMA domain (single NUMA node containing the socket)
 *   - Level 3: System domain (all CPUs)
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

void topology_init(void) {
  uint32_t online = smp_online_count();
  if (online == 0) {
    klog("topology: no online CPUs, skipping\n");
    return;
  }

  g_cpu_capacity = smp_capacity();
  uint32_t core_domains = (online + 15U) / 16U;
  g_domain_capacity = core_domains + 3U;
  g_cpu_topology = (xaios_cpu_topology_t *)kheap_calloc(
      (uint64_t)g_cpu_capacity * sizeof(*g_cpu_topology), 16U);
  g_sched_domains = (xaios_sched_domain_t *)kheap_calloc(
      (uint64_t)g_domain_capacity * sizeof(*g_sched_domains), 16U);
  kassert(g_cpu_topology != 0 && g_sched_domains != 0);
  g_domain_count = 0;

  /* QEMU virt assumptions:
   * - Single NUMA node (node 0)
   * - Single socket (socket 0)
   * - No SMT (thread_id = 0 for all CPUs)
   * - Linear core IDs (core_id = cpu_id)
   */

  /* Level 3: System domain (covers all CPUs) */
  uint32_t sys_domain = next_domain_id();
  g_sched_domains[sys_domain].domain_id = sys_domain;
  g_sched_domains[sys_domain].level = 3;
  g_sched_domains[sys_domain].parent_domain = UINT32_MAX;
  g_sched_domains[sys_domain].member_count = 0;
  g_sched_domains[sys_domain].load_estimate = 0;

  /* Level 2: NUMA domain (single node for QEMU) */
  uint32_t numa_domain = next_domain_id();
  g_sched_domains[numa_domain].domain_id = numa_domain;
  g_sched_domains[numa_domain].level = 2;
  g_sched_domains[numa_domain].parent_domain = sys_domain;
  g_sched_domains[numa_domain].member_count = 0;
  g_sched_domains[numa_domain].load_estimate = 0;

  /* Add NUMA domain to system domain */
  if (g_sched_domains[sys_domain].member_count < XAIOS_SCHED_DOMAIN_MAX_MEMBERS) {
    g_sched_domains[sys_domain].members[g_sched_domains[sys_domain].member_count++] = numa_domain;
  }

  /* Level 1: Socket domain (single socket for QEMU) */
  uint32_t socket_domain = next_domain_id();
  g_sched_domains[socket_domain].domain_id = socket_domain;
  g_sched_domains[socket_domain].level = 1;
  g_sched_domains[socket_domain].parent_domain = numa_domain;
  g_sched_domains[socket_domain].member_count = 0;
  g_sched_domains[socket_domain].load_estimate = 0;

  /* Add socket domain to NUMA domain */
  if (g_sched_domains[numa_domain].member_count < XAIOS_SCHED_DOMAIN_MAX_MEMBERS) {
    g_sched_domains[numa_domain].members[g_sched_domains[numa_domain].member_count++] = socket_domain;
  }

  /* Level 0: Core domains (groups of up to 16 CPUs) */
  uint32_t core_domain = UINT32_MAX;
  for (uint32_t cpu = 0; cpu < online; ++cpu) {
    const xaios_cpu_state_t *state = smp_cpu_state(cpu);
    if (state == 0 || state->online == 0) {
      continue;
    }

    /* Create new core domain every 16 CPUs */
    if (cpu % 16 == 0) {
      core_domain = next_domain_id();
      g_sched_domains[core_domain].domain_id = core_domain;
      g_sched_domains[core_domain].level = 0;
      g_sched_domains[core_domain].parent_domain = socket_domain;
      g_sched_domains[core_domain].member_count = 0;
      g_sched_domains[core_domain].load_estimate = 0;

      /* Add core domain to socket domain */
      if (g_sched_domains[socket_domain].member_count < XAIOS_SCHED_DOMAIN_MAX_MEMBERS) {
        g_sched_domains[socket_domain].members[g_sched_domains[socket_domain].member_count++] = core_domain;
      }
    }

    /* Populate CPU topology */
    g_cpu_topology[cpu].cpu_id = cpu;
    g_cpu_topology[cpu].numa_node = 0;
    g_cpu_topology[cpu].socket_id = 0;
    g_cpu_topology[cpu].core_id = cpu;
    g_cpu_topology[cpu].thread_id = 0;
    g_cpu_topology[cpu].sched_domain_id = core_domain;

    /* Add CPU to core domain */
    if (g_sched_domains[core_domain].member_count < XAIOS_SCHED_DOMAIN_MAX_MEMBERS) {
      g_sched_domains[core_domain].members[g_sched_domains[core_domain].member_count++] = cpu;
    }
  }

  g_topology_initialized = 1;

  klog("topology: initialized %u CPUs, %u domains, %u core domains\n",
       online, g_domain_count, (online + 15U) / 16U);
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

  klog("topology: self-test passed domains=%u online=%u\n",
       g_domain_count, online);
}
