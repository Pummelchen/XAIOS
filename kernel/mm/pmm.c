#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/numa.h>
#include <xaios/pmm.h>
#include <xaios/spinlock.h>

static uint64_t g_total_pages;
static uint64_t g_managed_pages;
static uint64_t g_reserved_pages;

/* FIX-005: Double-free detection */
#define PMM_FREE_MAGIC UINT64_C(0xDEADBEEFCAFEBABE)
#define PMM_MAX_FREED_TRACK 64

typedef struct pmm_freed_entry {
  uint64_t page_addr;
  uint64_t freed_count;
} pmm_freed_entry_t;

static pmm_freed_entry_t g_freed_pages[PMM_MAX_FREED_TRACK];
static uint32_t g_freed_count = 0;
static xaios_spinlock_t g_pmm_free_lock;

void pmm_init(const xaios_boot_info_t *boot) {
  /* numa_init(boot) must be called before pmm_init().
   * PMM now delegates to NUMA node free-stacks. */
  (void)boot;
  g_total_pages = 0;
  g_managed_pages = 0;
  g_reserved_pages = 0;
  xaios_spin_init(&g_pmm_free_lock);

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

  xaios_spin_lock(&g_pmm_free_lock);

  /* FIX-005: Check for double-free */
  uint64_t page_addr = (uint64_t)(uintptr_t)page;
  for (uint32_t i = 0; i < g_freed_count && i < PMM_MAX_FREED_TRACK; ++i) {
    if (g_freed_pages[i].page_addr == page_addr) {
      klog("pmm: CRITICAL: double-free detected at page 0x%lx (freed %lu times)\n",
           page_addr, g_freed_pages[i].freed_count);
      g_freed_pages[i].freed_count++;
      xaios_spin_unlock(&g_pmm_free_lock);
      return;  /* Reject double-free */
    }
  }

  /* Track this freed page */
  if (g_freed_count < PMM_MAX_FREED_TRACK) {
    g_freed_pages[g_freed_count].page_addr = page_addr;
    g_freed_pages[g_freed_count].freed_count = 1;
    g_freed_count++;
  }

  /* Return page to NUMA allocator BEFORE writing magic,
   * preventing a race where another CPU allocates the same
   * page and reads stale magic data. */
  numa_free_page(page);

  /* Mark page with magic number for after-free detection */
  uint64_t *page_ptr = (uint64_t *)page;
  page_ptr[0] = PMM_FREE_MAGIC;
  page_ptr[1] = PMM_FREE_MAGIC;

  xaios_spin_unlock(&g_pmm_free_lock);
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
