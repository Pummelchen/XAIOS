#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/numa.h>
#include <xaios/pmm.h>

static uint64_t g_total_pages;
static uint64_t g_managed_pages;
static uint64_t g_reserved_pages;

void pmm_init(const xaios_boot_info_t *boot) {
  /* numa_init(boot) must be called before pmm_init().
   * PMM now delegates to NUMA node free-stacks. */
  (void)boot;
  g_total_pages = 0;
  g_managed_pages = 0;
  g_reserved_pages = 0;

  uint32_t ncount = numa_node_count();
  for (uint32_t i = 0; i < ncount; ++i) {
    const xaios_numa_node_t *node = numa_node(i);
    if (node != 0) {
      g_total_pages += node->total_pages;
      g_managed_pages += node->managed_pages;
    }
  }

  uint64_t total_free = pmm_free_pages();
  if (g_managed_pages > total_free) {
    g_reserved_pages = g_managed_pages - total_free;
  }

  klog("PMM total pages=%lu managed=%lu free=%lu reserved=%lu "
       "(NUMA nodes=%u)\n",
       g_total_pages, g_managed_pages, total_free, g_reserved_pages, ncount);
  kassert(total_free != 0);
}

void *pmm_alloc_page(void) {
  /* Try node 0 first, then fallback to other nodes */
  void *page = numa_alloc_page_on_node(0);
  if (page != 0) {
    return page;
  }
  uint32_t ncount = numa_node_count();
  for (uint32_t i = 1; i < ncount; ++i) {
    page = numa_alloc_page_on_node(i);
    if (page != 0) {
      return page;
    }
  }
  return 0;
}

void *pmm_alloc_page_on_node(uint32_t node_id) {
  return numa_alloc_page_on_node(node_id);
}

void *pmm_alloc_page_near(uint32_t preferred_node) {
  void *page = numa_alloc_page_on_node(preferred_node);
  if (page != 0) {
    return page;
  }
  /* Fallback: try all other nodes */
  uint32_t ncount = numa_node_count();
  for (uint32_t i = 0; i < ncount; ++i) {
    if (i == preferred_node) {
      continue;
    }
    page = numa_alloc_page_on_node(i);
    if (page != 0) {
      return page;
    }
  }
  return 0;
}

void pmm_free_page(void *page) {
  if (page == 0) {
    klog("pmm: WARNING: attempt to free NULL page\n");
    return;
  }

  if (!numa_free_page(page)) {
    klog("pmm: CRITICAL: rejected invalid or double free at page 0x%lx\n",
         (uint64_t)(uintptr_t)page);
  }
}

uint32_t pmm_node_of_page(void *page) {
  if (page == 0) {
    return UINT32_C(0xffffffff);
  }
  return numa_node_of_phys((uint64_t)(uintptr_t)page);
}

uint64_t pmm_total_pages(void) {
  return g_total_pages;
}

uint64_t pmm_managed_pages(void) {
  return g_managed_pages;
}

uint64_t pmm_free_pages(void) {
  uint64_t total = 0;
  uint32_t ncount = numa_node_count();
  for (uint32_t i = 0; i < ncount; ++i) {
    const xaios_numa_node_t *node = numa_node(i);
    if (node != 0) {
      total += node->free_count;
    }
  }
  return total;
}
