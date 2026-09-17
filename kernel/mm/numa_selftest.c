/* NUMA reporting and self-test: renders each node's distance-ordered
   fallback list and verifies ownership, placement and accounting. Split
   out of kernel/mm/numa.c to keep that file under the repository source
   limit; the code is moved verbatim. */
#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/numa.h>
#include <xaios/smp.h>

#include "numa_internal.h"

/* klog has no way to print a list, and a fallback order is only evidence if a
   reader can see the whole of it: "nearest first" is a claim about every
   position, not about the first one. */
static void format_node_list(const uint32_t *nodes, uint32_t count,
                             char *buffer, uint64_t capacity) {
  uint64_t used = 0U;
  for (uint32_t index = 0U; index < count && used + 12U < capacity; ++index) {
    if (index != 0U) buffer[used++] = ',';
    uint32_t value = nodes[index];
    char digits[12];
    uint32_t digit_count = 0U;
    do {
      digits[digit_count++] = (char)('0' + (value % 10U));
      value /= 10U;
    } while (value != 0U);
    while (digit_count != 0U) buffer[used++] = digits[--digit_count];
  }
  buffer[used] = '\0';
}

void numa_self_test(void) {
  kassert(g_numa_node_count >= 1U);
  const xaios_numa_node_t *node0 = numa_node(0U);
  kassert(node0 != 0 && node0->online == 1U);
  kassert(node0->managed_pages == node0->total_pages);
  kassert(node0->managed_pages >= node0->free_count);
  kassert(node0->free_count > 0U);
  kassert(numa_node_has_cpu(0U, 0U));
  kassert(numa_distance(0U, 0U) == 10U);
  kassert(numa_preferred_node_for_cpu(0U) < g_numa_node_count);
  kassert(node0->phys_start < node0->phys_end);

  void *page = numa_alloc_page_on_node(0U);
  kassert(page != 0);
  kassert(numa_node_of_phys((uint64_t)(uintptr_t)page) == 0U);
  uint64_t previous_free = g_numa_nodes[0].free_count;
  kassert(numa_free_page(page) == 1);
  kassert(g_numa_nodes[0].free_count == previous_free + 1U);
  kassert(numa_free_page(page) == 0);
  numa_record_access(0U, (uint64_t)(uintptr_t)node0->phys_start, 64U);
  kassert(numa_local_bytes() == 64U);
  if (g_numa_node_count > 1U) {
    const xaios_numa_node_t *node1 = numa_node(1U);
    kassert(node1 != 0 && numa_distance(0U, 1U) >= 10U);
    void *remote_page = numa_alloc_page_on_node(1U);
    kassert(remote_page != 0);
    /* The page must be in the node it was asked for. Node 0 was checked this
       way and node 1 was not, which left the case that matters untested: an
       allocator that ignored the node argument and always served node 0 would
       have passed everything above, and the whole point of asking for a node
       is that memory comes from it. */
    kassert(numa_node_of_phys((uint64_t)(uintptr_t)remote_page) == 1U);
    kassert((uint64_t)(uintptr_t)remote_page >= node1->phys_start &&
            (uint64_t)(uintptr_t)remote_page < node1->phys_end);
    /* Every CPU belongs to exactly the node that claims it, on both nodes.
       numa_node_has_cpu and numa_preferred_node_for_cpu are separate lookups
       and nothing checked they agree beyond CPU 0. */
    for (uint32_t cpu = 0U; cpu < smp_capacity(); ++cpu) {
      uint32_t preferred = numa_preferred_node_for_cpu(cpu);
      kassert(preferred < g_numa_node_count);
      kassert(numa_node_has_cpu(preferred, cpu));
      for (uint32_t node = 0U; node < g_numa_node_count; ++node) {
        if (node != preferred) kassert(!numa_node_has_cpu(node, cpu));
      }
    }
    numa_record_access(0U, (uint64_t)(uintptr_t)remote_page, 128U);
    kassert(numa_remote_bytes() == 128U);
    kassert(numa_free_page(remote_page) == 1);

    /* At least two nodes must own a CPU. Nothing checked this, and the way
       the x86 SRAT walk fails is silent: a processor affinity whose APIC id
       matches no online CPU leaves that CPU on node 0, so a parse that found
       no processor affinities at all puts every CPU on node 0 and every
       assertion above still holds -- each CPU maps to exactly one node, and
       that node is node 0. A machine whose firmware says it has two memory
       nodes and one CPU node is either a parse failure here or a table worth
       refusing to guess about. */
    uint32_t nodes_with_cpus = 0U;
    for (uint32_t node = 0U; node < g_numa_node_count; ++node) {
      uint32_t owned = 0U;
      for (uint32_t cpu = 0U; cpu < smp_capacity(); ++cpu) {
        if (numa_node_has_cpu(node, cpu)) ++owned;
      }
      if (owned != 0U) ++nodes_with_cpus;
      uint32_t order[16];
      uint32_t order_count = numa_nodes_by_distance(node, order, 16U);
      char order_text[128];
      format_node_list(order, order_count, order_text, sizeof(order_text));
      klog("NUMA: node=%u domain=%u cpus=%u pages=%lu fallback_order=%s\n",
           node, g_numa_nodes[node].proximity_domain, owned,
           g_numa_nodes[node].total_pages, order_text);
    }
    kassert(nodes_with_cpus >= 2U);

    /* The fallback order is the placement policy, so it is asserted rather
       than only printed: the local node first, then every other node exactly
       once, by non-decreasing SLIT distance. The old allocator walked node
       ids instead, which agrees with this on node 0 of a two-node machine and
       disagrees everywhere else -- that is why the assertion runs from every
       node and not just from the one the boot CPU happens to be on. */
    for (uint32_t node = 0U; node < g_numa_node_count; ++node) {
      uint32_t order[16];
      uint32_t order_count = numa_nodes_by_distance(node, order, 16U);
      kassert(order_count ==
              (g_numa_node_count < 16U ? g_numa_node_count : 16U));
      kassert(order[0] == node);
      for (uint32_t index = 1U; index < order_count; ++index) {
        kassert(numa_distance(node, order[index - 1U]) <=
                numa_distance(node, order[index]));
        for (uint32_t earlier = 0U; earlier < index; ++earlier) {
          kassert(order[earlier] != order[index]);
        }
      }
    }

    /* Placement accounting has to move for a real allocation, and it has to
       move on the correct side. The deltas are asserted as lower bounds, not
       as equalities: the secondaries are online by this point and an exact
       figure would be a flake rather than a stronger check. What makes the
       check bite is the side -- an allocator charging every page as local
       leaves the remote delta at zero. */
    uint32_t local_node = numa_node_of_cpu(smp_cpu_id());
    kassert(local_node != UINT32_MAX);
    uint32_t far_node = local_node == 0U ? 1U : 0U;
    uint64_t local_before = numa_local_placement_bytes();
    uint64_t remote_before = numa_remote_placement_bytes();
    void *near_page = numa_alloc_page_on_node(local_node);
    kassert(near_page != 0);
    uint64_t local_delta = numa_local_placement_bytes() - local_before;
    kassert(local_delta >= PAGE_SIZE);
    remote_before = numa_remote_placement_bytes();
    void *far_page = numa_alloc_page_on_node(far_node);
    kassert(far_page != 0);
    uint64_t remote_delta = numa_remote_placement_bytes() - remote_before;
    kassert(remote_delta >= PAGE_SIZE);
    kassert(numa_free_page(near_page) == 1);
    kassert(numa_free_page(far_page) == 1);
    klog("NUMA: placement accounting cpu=%u local_node=%u far_node=%u local_delta=%lu remote_delta=%lu verified=1\n",
         smp_cpu_id(), local_node, far_node, local_delta, remote_delta);
  }

  void *pages[64];
  for (uint32_t index = 0U; index < 64U; ++index) {
    pages[index] = numa_alloc_page_on_node(0U);
    kassert(pages[index] != 0);
  }
  for (uint32_t index = 0U; index < 64U; ++index) {
    kassert(numa_free_page(pages[index]) == 1);
  }
  klog("NUMA: self-test passed nodes=%u regions=%u managed=%lu free=%lu dynamic_metadata=1 ownership=verified local_bytes=%lu remote_bytes=%lu placement_local_bytes=%lu placement_remote_bytes=%lu\n",
       g_numa_node_count, node0->region_count, node0->managed_pages,
       node0->free_count, numa_local_bytes(), numa_remote_bytes(),
       numa_local_placement_bytes(), numa_remote_placement_bytes());
}
