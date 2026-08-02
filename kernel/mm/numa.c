#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/numa.h>
#include <xaios/smp.h>

#define PAGE_SIZE UINT64_C(4096)

static xaios_numa_node_t g_numa_nodes[XAIOS_NUMA_MAX_NODES];
static uint32_t g_numa_node_count;

static uint64_t align_up(uint64_t value, uint64_t align) {
  return (value + align - 1) & ~(align - 1);
}

static uint64_t align_down(uint64_t value, uint64_t align) {
  return value & ~(align - 1);
}

static int overlaps(uint64_t start, uint64_t end, uint64_t used_start,
                    uint64_t used_end) {
  return start < used_end && used_start < end;
}

static int page_is_reserved(const xaios_boot_info_t *boot, uint64_t page) {
  uint64_t page_end = page + PAGE_SIZE;
  uint64_t map_start = boot->memory_map;
  uint64_t map_end = boot->memory_map + boot->memory_map_size;
  if (overlaps(page, page_end, boot->kernel_phys_base, boot->kernel_phys_end)) {
    return 1;
  }
  if (overlaps(page, page_end, map_start, map_end)) {
    return 1;
  }
  return 0;
}

static void bitmap_set_free(xaios_numa_node_t *node, uint64_t page_index) {
  if (page_index >= XAIOS_NUMA_BITMAP_BITS) {
    return;
  }
  uint64_t word = page_index / 64U;
  uint64_t bit = page_index % 64U;
  node->bitmap[word] |= UINT64_C(1) << bit;
}

static int bitmap_is_free(const xaios_numa_node_t *node, uint64_t page_index) {
  if (page_index >= XAIOS_NUMA_BITMAP_BITS) {
    return 0;
  }
  uint64_t word = page_index / 64U;
  uint64_t bit = page_index % 64U;
  return (node->bitmap[word] & (UINT64_C(1) << bit)) != 0;
}

static void bitmap_set_allocated(xaios_numa_node_t *node,
                                 uint64_t page_index) {
  uint64_t word = page_index / 64U;
  uint64_t bit = page_index % 64U;
  node->allocated_bitmap[word] |= UINT64_C(1) << bit;
}

static void bitmap_clear_allocated(xaios_numa_node_t *node,
                                   uint64_t page_index) {
  uint64_t word = page_index / 64U;
  uint64_t bit = page_index % 64U;
  node->allocated_bitmap[word] &= ~(UINT64_C(1) << bit);
}

static int bitmap_is_allocated(const xaios_numa_node_t *node,
                               uint64_t page_index) {
  if (page_index >= XAIOS_NUMA_BITMAP_BITS) {
    return 0;
  }
  uint64_t word = page_index / 64U;
  uint64_t bit = page_index % 64U;
  return (node->allocated_bitmap[word] & (UINT64_C(1) << bit)) != 0;
}

void numa_init(const xaios_boot_info_t *boot) {
  for (uint32_t i = 0; i < XAIOS_NUMA_MAX_NODES; ++i) {
    g_numa_nodes[i].node_id = i;
    g_numa_nodes[i].online = 0;
    g_numa_nodes[i].phys_start = 0;
    g_numa_nodes[i].phys_end = 0;
    g_numa_nodes[i].total_pages = 0;
    g_numa_nodes[i].managed_pages = 0;
    g_numa_nodes[i].free_count = 0;
    g_numa_nodes[i].cpu_mask = 0;
    g_numa_nodes[i].alloc_hint = 0;
    xaios_spin_init(&g_numa_nodes[i].lock);
    for (uint64_t w = 0; w < XAIOS_NUMA_BITMAP_WORDS; ++w) {
      g_numa_nodes[i].bitmap[w] = 0;
      g_numa_nodes[i].allocated_bitmap[w] = 0;
    }
  }
  g_numa_node_count = 0;

  uint64_t lowest = UINT64_C(0xffffffffffffffff);
  uint64_t highest = 0;
  uint64_t offset = 0;
  while (offset + sizeof(xaios_memory_descriptor_t) <= boot->memory_map_size) {
    const xaios_memory_descriptor_t *desc =
        (const xaios_memory_descriptor_t *)(uintptr_t)(boot->memory_map + offset);
    if (desc->type == XAIOS_MEMORY_TYPE_CONVENTIONAL) {
      uint64_t region_start = desc->physical_start;
      uint64_t region_end =
          region_start + (desc->number_of_pages * PAGE_SIZE);
      if (region_start < lowest) {
        lowest = region_start;
      }
      if (region_end > highest) {
        highest = region_end;
      }
    }
    offset += boot->memory_descriptor_size;
  }

  if (lowest >= highest) {
    klog("NUMA: no conventional memory found\n");
    return;
  }

  xaios_numa_node_t *node = &g_numa_nodes[0];
  node->node_id = 0;
  node->online = 1;
  node->phys_start = lowest;
  node->phys_end = highest;
  node->cpu_mask = 0;
  /* cpu_mask is uint64_t — tracks up to 64 CPUs for affinity */
  uint32_t online = smp_online_count();
  uint32_t mask_limit = online < 64U ? online : 64U;
  for (uint32_t c = 0; c < mask_limit; ++c) {
    node->cpu_mask |= (UINT64_C(1) << c);
  }
  if (online > 64U) {
    klog("NUMA: cpu_mask covers first 64 of %u online CPUs\n", online);
  }

  node->total_pages = 0;
  node->managed_pages = 0;
  node->free_count = 0;
  uint64_t skipped_overflow = 0;
  offset = 0;
  while (offset + sizeof(xaios_memory_descriptor_t) <= boot->memory_map_size) {
    const xaios_memory_descriptor_t *desc =
        (const xaios_memory_descriptor_t *)(uintptr_t)(boot->memory_map + offset);
    if (desc->type == XAIOS_MEMORY_TYPE_CONVENTIONAL) {
      uint64_t region_start = desc->physical_start;
      uint64_t region_end =
          region_start + (desc->number_of_pages * PAGE_SIZE);
      uint64_t page = align_up(region_start, PAGE_SIZE);
      uint64_t end = align_down(region_end, PAGE_SIZE);
      while (page + PAGE_SIZE <= end) {
        ++node->total_pages;
        if (page < node->phys_start || page >= node->phys_end) {
          /* outside node range */
        } else {
          uint64_t page_index = (page - node->phys_start) / PAGE_SIZE;
          if (page_index >= XAIOS_NUMA_BITMAP_BITS) {
            ++skipped_overflow;
          } else {
            ++node->managed_pages;
            if (!page_is_reserved(boot, page)) {
              bitmap_set_free(node, page_index);
              ++node->free_count;
            }
          }
        }
        page += PAGE_SIZE;
      }
    }
    offset += boot->memory_descriptor_size;
  }

  g_numa_node_count = 1;
  uint64_t total_bytes = node->total_pages * PAGE_SIZE;
  uint64_t free_bytes = node->free_count * PAGE_SIZE;
  klog("NUMA: node 0 phys=[0x%lx, 0x%lx) total=%lu (%lu MB) managed=%lu "
       "free=%lu (%lu MB) overflow=%lu\n",
       node->phys_start, node->phys_end, node->total_pages,
       total_bytes / UINT64_C(1048576), node->managed_pages, node->free_count,
       free_bytes / UINT64_C(1048576), skipped_overflow);
  if (skipped_overflow > 0) {
    uint64_t lost_mb = (skipped_overflow * PAGE_SIZE) / UINT64_C(1048576);
    klog("NUMA: WARNING %lu pages (%lu MB) beyond bitmap capacity "
         "(%lu pages/node = %lu GB/node)\n",
         skipped_overflow, lost_mb, (uint64_t)XAIOS_NUMA_BITMAP_BITS,
         (uint64_t)XAIOS_NUMA_BITMAP_BITS / UINT64_C(262144));
    klog("NUMA: increase XAIOS_NUMA_BITMAP_BITS in numa.h to recover\n");
  }
  klog("NUMA: system capacity %u nodes x %lu GB = %lu GB max\n",
       XAIOS_NUMA_MAX_NODES,
       (uint64_t)XAIOS_NUMA_BITMAP_BITS / UINT64_C(262144),
       (uint64_t)XAIOS_NUMA_MAX_NODES *
           ((uint64_t)XAIOS_NUMA_BITMAP_BITS / UINT64_C(262144)));
}

uint32_t numa_node_count(void) { return g_numa_node_count; }

const xaios_numa_node_t *numa_node(uint32_t node_id) {
  if (node_id >= g_numa_node_count) {
    return 0;
  }
  return &g_numa_nodes[node_id];
}

uint32_t numa_node_of_phys(uint64_t phys_addr) {
  for (uint32_t i = 0; i < g_numa_node_count; ++i) {
    if (phys_addr >= g_numa_nodes[i].phys_start &&
        phys_addr < g_numa_nodes[i].phys_end) {
      return i;
    }
  }
  return UINT32_C(0xffffffff);
}

void *numa_alloc_page_on_node(uint32_t node_id) {
  if (node_id >= g_numa_node_count) {
    return 0;
  }
  xaios_numa_node_t *node = &g_numa_nodes[node_id];
  xaios_spin_lock(&node->lock);

  if (node->free_count == 0) {
    xaios_spin_unlock(&node->lock);
    return 0;
  }

  uint64_t start_word = node->alloc_hint / 64U;
  uint64_t max_page = (node->phys_end - node->phys_start) / PAGE_SIZE;
  if (max_page > XAIOS_NUMA_BITMAP_BITS) {
    max_page = XAIOS_NUMA_BITMAP_BITS;
  }
  uint64_t used_words = (max_page + 63U) / 64U;
  if (used_words == 0) {
    used_words = 1;
  }
  if (start_word >= used_words) {
    start_word = 0;
  }

  for (uint64_t i = 0; i < used_words; ++i) {
    uint64_t word_idx = (start_word + i) % used_words;
    uint64_t word = node->bitmap[word_idx];
    if (word == 0) {
      continue;
    }

    uint32_t bit = 0;
    uint64_t mask = 1;
    while ((word & mask) == 0) {
      ++bit;
      mask <<= 1U;
    }

    uint64_t page_index = word_idx * 64U + bit;
    if (page_index >= max_page) {
      continue;
    }

    node->bitmap[word_idx] &= ~mask;
    bitmap_set_allocated(node, page_index);
    --node->free_count;
    node->alloc_hint = page_index + 1;

    uint64_t phys = node->phys_start + page_index * PAGE_SIZE;
    xaios_spin_unlock(&node->lock);
    return (void *)(uintptr_t)phys;
  }

  xaios_spin_unlock(&node->lock);
  return 0;
}

int numa_free_page(void *page) {
  if (page == 0) {
    return 0;
  }
  uint64_t phys = (uint64_t)(uintptr_t)page;
  if ((phys & (PAGE_SIZE - 1U)) != 0) {
    return 0;
  }
  uint32_t node_id = numa_node_of_phys(phys);
  if (node_id == UINT32_C(0xffffffff)) {
    return 0;
  }
  xaios_numa_node_t *node = &g_numa_nodes[node_id];
  uint64_t page_index = (phys - node->phys_start) / PAGE_SIZE;
  uint64_t max_page = (node->phys_end - node->phys_start) / PAGE_SIZE;

  xaios_spin_lock(&node->lock);
  if (page_index >= max_page || page_index >= XAIOS_NUMA_BITMAP_BITS ||
      !bitmap_is_allocated(node, page_index) ||
      bitmap_is_free(node, page_index)) {
    xaios_spin_unlock(&node->lock);
    return 0;
  }
  bitmap_clear_allocated(node, page_index);
  bitmap_set_free(node, page_index);
  ++node->free_count;
  xaios_spin_unlock(&node->lock);
  return 1;
}

void numa_self_test(void) {
  kassert(g_numa_node_count >= 1);
  const xaios_numa_node_t *node0 = numa_node(0);
  kassert(node0 != 0);
  kassert(node0->online == 1);
  kassert(node0->managed_pages >= node0->free_count);
  kassert(node0->free_count > 0);
  kassert(node0->cpu_mask != 0);
  kassert(node0->phys_start < node0->phys_end);

  void *p = numa_alloc_page_on_node(0);
  kassert(p != 0);
  uint64_t phys = (uint64_t)(uintptr_t)p;
  kassert(numa_node_of_phys(phys) == 0);
  kassert(phys >= node0->phys_start && phys < node0->phys_end);

  uint64_t prev_free = g_numa_nodes[0].free_count;
  kassert(numa_free_page(p) == 1);
  kassert(g_numa_nodes[0].free_count == prev_free + 1);
  kassert(numa_free_page(p) == 0);
  kassert(g_numa_nodes[0].free_count == prev_free + 1);

  void *pages[64];
  for (uint32_t i = 0; i < 64; ++i) {
    pages[i] = numa_alloc_page_on_node(0);
    kassert(pages[i] != 0);
    kassert(numa_node_of_phys((uint64_t)(uintptr_t)pages[i]) == 0);
  }
  uint64_t reuse_index =
      ((uint64_t)(uintptr_t)pages[0] - node0->phys_start) / PAGE_SIZE;
  kassert(numa_free_page(pages[0]) == 1);
  g_numa_nodes[0].alloc_hint = reuse_index;
  void *reused = numa_alloc_page_on_node(0);
  kassert(reused == pages[0]);
  kassert(numa_free_page(reused) == 1);
  for (uint32_t i = 1; i < 64; ++i) {
    kassert(numa_free_page(pages[i]) == 1);
  }

  uint64_t sum_total = 0;
  for (uint32_t i = 0; i < g_numa_node_count; ++i) {
    sum_total += g_numa_nodes[i].total_pages;
  }
  kassert(sum_total > 0);

  klog("NUMA: self-test passed nodes=%u node0_free=%lu bitmap_capacity=%lu "
       "ownership=verified\n",
       g_numa_node_count, g_numa_nodes[0].free_count,
       (uint64_t)XAIOS_NUMA_BITMAP_BITS);
}
