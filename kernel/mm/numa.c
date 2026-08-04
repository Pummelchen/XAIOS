#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/numa.h>
#include <xaios/smp.h>

#define PAGE_SIZE UINT64_C(4096)
#define EARLY_IDENTITY_LIMIT UINT64_C(0x100000000)

static xaios_numa_node_t *g_numa_nodes;
static uint32_t g_numa_node_count;
static uint64_t g_metadata_start;
static uint64_t g_metadata_end;

static uint64_t align_up(uint64_t value, uint64_t align) {
  if (value > UINT64_MAX - (align - 1U)) return UINT64_MAX;
  return (value + align - 1U) & ~(align - 1U);
}

static uint64_t align_down(uint64_t value, uint64_t align) {
  return value & ~(align - 1U);
}

static int overlaps(uint64_t start, uint64_t end, uint64_t used_start,
                    uint64_t used_end) {
  return start < used_end && used_start < end;
}

static void bytes_zero(void *buffer, uint64_t length) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t index = 0U; index < length; ++index) bytes[index] = 0U;
}

static int descriptor_bounds(const xaios_memory_descriptor_t *descriptor,
                             uint64_t *start, uint64_t *end) {
  if (descriptor->number_of_pages > UINT64_MAX / PAGE_SIZE) return 0;
  uint64_t bytes = descriptor->number_of_pages * PAGE_SIZE;
  if (descriptor->physical_start > UINT64_MAX - bytes) return 0;
  *start = align_up(descriptor->physical_start, PAGE_SIZE);
  *end = align_down(descriptor->physical_start + bytes, PAGE_SIZE);
  return *start < *end;
}

static int page_is_reserved(const xaios_boot_info_t *boot, uint64_t page) {
  uint64_t page_end = page + PAGE_SIZE;
  uint64_t map_start = boot->memory_map;
  uint64_t map_end = boot->memory_map + boot->memory_map_size;
  uint64_t smp_start = 0U;
  uint64_t smp_end = 0U;
  (void)smp_bootstrap_reserved_range(&smp_start, &smp_end);
  return overlaps(page, page_end, boot->kernel_phys_base,
                  boot->kernel_phys_end) ||
         overlaps(page, page_end, map_start, map_end) ||
         overlaps(page, page_end, smp_start, smp_end) ||
         overlaps(page, page_end, g_metadata_start, g_metadata_end);
}

static uint64_t find_metadata_space(const xaios_boot_info_t *boot,
                                    uint64_t required_bytes) {
  uint64_t offset = 0U;
  while (offset + sizeof(xaios_memory_descriptor_t) <=
         boot->memory_map_size) {
    const xaios_memory_descriptor_t *descriptor =
        (const xaios_memory_descriptor_t *)(uintptr_t)(boot->memory_map +
                                                       offset);
    uint64_t start = 0U;
    uint64_t end = 0U;
    if (descriptor->type == XAIOS_MEMORY_TYPE_CONVENTIONAL &&
        descriptor_bounds(descriptor, &start, &end)) {
      if (end > EARLY_IDENTITY_LIMIT) end = EARLY_IDENTITY_LIMIT;
      uint64_t candidate = start;
      for (uint32_t retry = 0U; retry < 4U && candidate < end; ++retry) {
        uint64_t candidate_end = candidate + required_bytes;
        if (candidate_end < candidate || candidate_end > end) break;
        if (overlaps(candidate, candidate_end, boot->kernel_phys_base,
                     boot->kernel_phys_end)) {
          candidate = align_up(boot->kernel_phys_end, PAGE_SIZE);
          continue;
        }
        uint64_t map_end = boot->memory_map + boot->memory_map_size;
        if (overlaps(candidate, candidate_end, boot->memory_map, map_end)) {
          candidate = align_up(map_end, PAGE_SIZE);
          continue;
        }
        uint64_t smp_start = 0U;
        uint64_t smp_end = 0U;
        if (smp_bootstrap_reserved_range(&smp_start, &smp_end) == XAIOS_OK &&
            overlaps(candidate, candidate_end, smp_start, smp_end)) {
          candidate = align_up(smp_end, PAGE_SIZE);
          continue;
        }
        return candidate;
      }
    }
    offset += boot->memory_descriptor_size;
  }
  return 0U;
}

static void bitmap_set(uint64_t *bitmap, uint64_t page_index) {
  bitmap[page_index / 64U] |= UINT64_C(1) << (page_index % 64U);
}

static void bitmap_clear(uint64_t *bitmap, uint64_t page_index) {
  bitmap[page_index / 64U] &= ~(UINT64_C(1) << (page_index % 64U));
}

static int bitmap_test(const uint64_t *bitmap, uint64_t page_index) {
  return (bitmap[page_index / 64U] &
          (UINT64_C(1) << (page_index % 64U))) != 0U;
}

void numa_init(const xaios_boot_info_t *boot) {
  g_numa_nodes = 0;
  g_numa_node_count = 0U;
  g_metadata_start = 0U;
  g_metadata_end = 0U;
  if (boot == 0 || boot->memory_descriptor_size <
                       sizeof(xaios_memory_descriptor_t)) {
    klog("NUMA: invalid boot memory map\n");
    return;
  }

  uint32_t region_count = 0U;
  uint64_t total_pages = 0U;
  uint64_t offset = 0U;
  while (offset + sizeof(xaios_memory_descriptor_t) <=
         boot->memory_map_size) {
    const xaios_memory_descriptor_t *descriptor =
        (const xaios_memory_descriptor_t *)(uintptr_t)(boot->memory_map +
                                                       offset);
    uint64_t start = 0U;
    uint64_t end = 0U;
    if (descriptor->type == XAIOS_MEMORY_TYPE_CONVENTIONAL &&
        descriptor_bounds(descriptor, &start, &end)) {
      uint64_t pages = (end - start) / PAGE_SIZE;
      if (total_pages > UINT64_MAX - pages || region_count == UINT32_MAX) {
        klog("NUMA: memory map capacity overflow\n");
        return;
      }
      total_pages += pages;
      ++region_count;
    }
    offset += boot->memory_descriptor_size;
  }
  if (region_count == 0U || total_pages == 0U) {
    klog("NUMA: no conventional memory found\n");
    return;
  }

  uint64_t bitmap_words = (total_pages + 63U) / 64U;
  uint32_t cpu_words = (smp_online_count() + 63U) / 64U;
  if (cpu_words == 0U) cpu_words = 1U;
  uint64_t metadata_bytes = sizeof(xaios_numa_node_t) +
      (uint64_t)region_count * sizeof(xaios_numa_region_t) +
      bitmap_words * sizeof(uint64_t) * 2U +
      (uint64_t)cpu_words * sizeof(uint64_t) + 64U;
  metadata_bytes = align_up(metadata_bytes, PAGE_SIZE);
  g_metadata_start = find_metadata_space(boot, metadata_bytes);
  if (g_metadata_start == 0U) {
    klog("NUMA: no bootstrap space for %lu metadata bytes\n",
         metadata_bytes);
    return;
  }
  g_metadata_end = g_metadata_start + metadata_bytes;
  bytes_zero((void *)(uintptr_t)g_metadata_start, metadata_bytes);

  uint64_t cursor = g_metadata_start;
  g_numa_nodes = (xaios_numa_node_t *)(uintptr_t)cursor;
  cursor = align_up(cursor + sizeof(xaios_numa_node_t), 8U);
  xaios_numa_node_t *node = &g_numa_nodes[0];
  node->regions = (xaios_numa_region_t *)(uintptr_t)cursor;
  cursor = align_up(cursor +
                        (uint64_t)region_count *
                            sizeof(xaios_numa_region_t),
                    8U);

  node->node_id = 0U;
  node->online = 1U;
  node->phys_start = UINT64_MAX;
  node->phys_end = 0U;
  node->total_pages = total_pages;
  node->managed_pages = total_pages;
  node->free_count = 0U;
  node->metadata_pages = metadata_bytes / PAGE_SIZE;
  node->region_count = region_count;
  node->cpu_word_count = cpu_words;
  node->alloc_region_hint = 0U;
  node->alloc_page_hint = 0U;
  xaios_spin_init(&node->lock);

  uint32_t region_index = 0U;
  offset = 0U;
  while (offset + sizeof(xaios_memory_descriptor_t) <=
         boot->memory_map_size) {
    const xaios_memory_descriptor_t *descriptor =
        (const xaios_memory_descriptor_t *)(uintptr_t)(boot->memory_map +
                                                       offset);
    uint64_t start = 0U;
    uint64_t end = 0U;
    if (descriptor->type == XAIOS_MEMORY_TYPE_CONVENTIONAL &&
        descriptor_bounds(descriptor, &start, &end)) {
      xaios_numa_region_t *region = &node->regions[region_index++];
      region->phys_start = start;
      region->page_count = (end - start) / PAGE_SIZE;
      region->bitmap_words = (region->page_count + 63U) / 64U;
      region->free_bitmap = (uint64_t *)(uintptr_t)cursor;
      cursor += region->bitmap_words * sizeof(uint64_t);
      region->allocated_bitmap = (uint64_t *)(uintptr_t)cursor;
      cursor += region->bitmap_words * sizeof(uint64_t);
      if (start < node->phys_start) node->phys_start = start;
      if (end > node->phys_end) node->phys_end = end;
      for (uint64_t page_index = 0U; page_index < region->page_count;
           ++page_index) {
        uint64_t page = start + page_index * PAGE_SIZE;
        if (!page_is_reserved(boot, page)) {
          bitmap_set(region->free_bitmap, page_index);
          ++node->free_count;
        }
      }
    }
    offset += boot->memory_descriptor_size;
  }
  cursor = align_up(cursor, 8U);
  node->cpu_bitmap = (uint64_t *)(uintptr_t)cursor;
  for (uint32_t ordinal = 0U; ordinal < smp_online_count(); ++ordinal) {
    uint32_t cpu_id = 0U;
    if (smp_cpu_id_at(ordinal, &cpu_id) == XAIOS_OK &&
        cpu_id / 64U < node->cpu_word_count) {
      node->cpu_bitmap[cpu_id / 64U] |=
          UINT64_C(1) << (cpu_id % 64U);
    }
  }
  g_numa_node_count = 1U;

  klog("NUMA: node 0 regions=%u phys=[0x%lx, 0x%lx) total=%lu managed=%lu free=%lu metadata_pages=%lu cpu_words=%u\n",
       node->region_count, node->phys_start, node->phys_end,
       node->total_pages, node->managed_pages, node->free_count,
       node->metadata_pages, node->cpu_word_count);
  klog("NUMA: dynamic metadata bytes=%lu no fixed RAM or CPU bitmap ceiling\n",
       metadata_bytes);
}

uint32_t numa_node_count(void) { return g_numa_node_count; }

const xaios_numa_node_t *numa_node(uint32_t node_id) {
  if (node_id >= g_numa_node_count) return 0;
  return &g_numa_nodes[node_id];
}

uint32_t numa_node_of_phys(uint64_t phys_addr) {
  for (uint32_t node_index = 0U; node_index < g_numa_node_count;
       ++node_index) {
    const xaios_numa_node_t *node = &g_numa_nodes[node_index];
    for (uint32_t region_index = 0U; region_index < node->region_count;
         ++region_index) {
      const xaios_numa_region_t *region = &node->regions[region_index];
      uint64_t end = region->phys_start + region->page_count * PAGE_SIZE;
      if (phys_addr >= region->phys_start && phys_addr < end) {
        return node_index;
      }
    }
  }
  return UINT32_MAX;
}

int numa_node_has_cpu(uint32_t node_id, uint32_t cpu_id) {
  if (node_id >= g_numa_node_count) return 0;
  const xaios_numa_node_t *node = &g_numa_nodes[node_id];
  if (cpu_id / 64U >= node->cpu_word_count) return 0;
  return (node->cpu_bitmap[cpu_id / 64U] &
          (UINT64_C(1) << (cpu_id % 64U))) != 0U;
}

void *numa_alloc_page_on_node(uint32_t node_id) {
  if (node_id >= g_numa_node_count) return 0;
  xaios_numa_node_t *node = &g_numa_nodes[node_id];
  xaios_spin_lock(&node->lock);
  if (node->free_count == 0U) {
    xaios_spin_unlock(&node->lock);
    return 0;
  }
  for (uint32_t region_step = 0U; region_step < node->region_count;
       ++region_step) {
    uint32_t region_index =
        (node->alloc_region_hint + region_step) % node->region_count;
    xaios_numa_region_t *region = &node->regions[region_index];
    uint64_t start_word = region_index == node->alloc_region_hint
                              ? node->alloc_page_hint / 64U
                              : 0U;
    if (start_word >= region->bitmap_words) start_word = 0U;
    for (uint64_t word_step = 0U; word_step < region->bitmap_words;
         ++word_step) {
      uint64_t word_index =
          (start_word + word_step) % region->bitmap_words;
      uint64_t word = region->free_bitmap[word_index];
      if (word == 0U) continue;
      uint32_t bit = 0U;
      while ((word & (UINT64_C(1) << bit)) == 0U) ++bit;
      uint64_t page_index = word_index * 64U + bit;
      if (page_index >= region->page_count) continue;
      bitmap_clear(region->free_bitmap, page_index);
      bitmap_set(region->allocated_bitmap, page_index);
      --node->free_count;
      node->alloc_region_hint = region_index;
      node->alloc_page_hint = page_index + 1U;
      uint64_t physical = region->phys_start + page_index * PAGE_SIZE;
      xaios_spin_unlock(&node->lock);
      return (void *)(uintptr_t)physical;
    }
  }
  xaios_spin_unlock(&node->lock);
  return 0;
}

int numa_free_page(void *page) {
  if (page == 0) return 0;
  uint64_t physical = (uint64_t)(uintptr_t)page;
  if ((physical & (PAGE_SIZE - 1U)) != 0U) return 0;
  uint32_t node_id = numa_node_of_phys(physical);
  if (node_id == UINT32_MAX) return 0;
  xaios_numa_node_t *node = &g_numa_nodes[node_id];
  xaios_spin_lock(&node->lock);
  for (uint32_t region_index = 0U; region_index < node->region_count;
       ++region_index) {
    xaios_numa_region_t *region = &node->regions[region_index];
    uint64_t end = region->phys_start + region->page_count * PAGE_SIZE;
    if (physical < region->phys_start || physical >= end) continue;
    uint64_t page_index = (physical - region->phys_start) / PAGE_SIZE;
    if (!bitmap_test(region->allocated_bitmap, page_index) ||
        bitmap_test(region->free_bitmap, page_index)) {
      xaios_spin_unlock(&node->lock);
      return 0;
    }
    bitmap_clear(region->allocated_bitmap, page_index);
    bitmap_set(region->free_bitmap, page_index);
    ++node->free_count;
    xaios_spin_unlock(&node->lock);
    return 1;
  }
  xaios_spin_unlock(&node->lock);
  return 0;
}

void numa_self_test(void) {
  kassert(g_numa_node_count == 1U);
  const xaios_numa_node_t *node0 = numa_node(0U);
  kassert(node0 != 0 && node0->online == 1U);
  kassert(node0->managed_pages == node0->total_pages);
  kassert(node0->managed_pages >= node0->free_count);
  kassert(node0->free_count > 0U);
  kassert(numa_node_has_cpu(0U, 0U));
  kassert(node0->phys_start < node0->phys_end);

  void *page = numa_alloc_page_on_node(0U);
  kassert(page != 0);
  kassert(numa_node_of_phys((uint64_t)(uintptr_t)page) == 0U);
  uint64_t previous_free = g_numa_nodes[0].free_count;
  kassert(numa_free_page(page) == 1);
  kassert(g_numa_nodes[0].free_count == previous_free + 1U);
  kassert(numa_free_page(page) == 0);

  void *pages[64];
  for (uint32_t index = 0U; index < 64U; ++index) {
    pages[index] = numa_alloc_page_on_node(0U);
    kassert(pages[index] != 0);
  }
  for (uint32_t index = 0U; index < 64U; ++index) {
    kassert(numa_free_page(pages[index]) == 1);
  }
  klog("NUMA: self-test passed nodes=1 regions=%u managed=%lu free=%lu dynamic_metadata=1 ownership=verified\n",
       node0->region_count, node0->managed_pages, node0->free_count);
}
