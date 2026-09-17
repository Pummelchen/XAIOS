#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/numa.h>
#include <xaios/smp.h>

#include "numa_internal.h"

xaios_numa_node_t *g_numa_nodes;
uint32_t g_numa_node_count;
uint64_t g_metadata_start;
uint64_t g_metadata_end;
static volatile uint64_t g_local_bytes;
static volatile uint64_t g_remote_bytes;
static volatile uint64_t g_local_placement_bytes;
static volatile uint64_t g_remote_placement_bytes;

uint64_t numa_align_up(uint64_t value, uint64_t align) {
  if (value > UINT64_MAX - (align - 1U)) return UINT64_MAX;
  return (value + align - 1U) & ~(align - 1U);
}

uint64_t numa_align_down(uint64_t value, uint64_t align) {
  return value & ~(align - 1U);
}

int numa_overlaps(uint64_t start, uint64_t end, uint64_t used_start,
                  uint64_t used_end) {
  return start < used_end && used_start < end;
}

static void boot_image_range(const xaios_boot_info_t *boot, uint64_t *start,
                             uint64_t *end) {
  *start = 0U;
  *end = 0U;
  if (boot->boot_image_base == 0U || boot->boot_image_size == 0U ||
      boot->boot_image_base > UINT64_MAX - boot->boot_image_size) {
    return;
  }
  *start = numa_align_down(boot->boot_image_base, PAGE_SIZE);
  *end = numa_align_up(boot->boot_image_base + boot->boot_image_size,
                       PAGE_SIZE);
}

void numa_bytes_zero(void *buffer, uint64_t length) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t index = 0U; index < length; ++index) bytes[index] = 0U;
}

int numa_descriptor_bounds(const xaios_memory_descriptor_t *descriptor,
                           uint64_t *start, uint64_t *end) {
  if (descriptor->number_of_pages > UINT64_MAX / PAGE_SIZE) return 0;
  uint64_t bytes = descriptor->number_of_pages * PAGE_SIZE;
  if (descriptor->physical_start > UINT64_MAX - bytes) return 0;
  *start = numa_align_up(descriptor->physical_start, PAGE_SIZE);
  *end = numa_align_down(descriptor->physical_start + bytes, PAGE_SIZE);
  return *start < *end;
}

uint32_t numa_cpu_bitmap_words(void) {
  uint32_t maximum = 0U;
  for (uint32_t ordinal = 0U; ordinal < smp_online_count(); ++ordinal) {
    uint32_t cpu_id = 0U;
    if (smp_cpu_id_at(ordinal, &cpu_id) == XAIOS_OK && cpu_id > maximum) {
      maximum = cpu_id;
    }
  }
  return (maximum / 64U) + 1U;
}

int numa_page_is_reserved(const xaios_boot_info_t *boot, uint64_t page) {
  /* A physical allocation is returned as a pointer, so page zero cannot be
   * represented without colliding with the allocation-failure sentinel. */
  if (page == 0U) return 1;
  uint64_t page_end = page + PAGE_SIZE;
  uint64_t map_start = boot->memory_map;
  uint64_t map_end = boot->memory_map + boot->memory_map_size;
  uint64_t boot_image_start = 0U;
  uint64_t boot_image_end = 0U;
  uint64_t smp_start = 0U;
  uint64_t smp_end = 0U;
  boot_image_range(boot, &boot_image_start, &boot_image_end);
  (void)smp_bootstrap_reserved_range(&smp_start, &smp_end);
  return numa_overlaps(page, page_end, boot->kernel_phys_base,
                       boot->kernel_phys_end) ||
         numa_overlaps(page, page_end, map_start, map_end) ||
         numa_overlaps(page, page_end, boot_image_start, boot_image_end) ||
         numa_overlaps(page, page_end, smp_start, smp_end) ||
         numa_overlaps(page, page_end, g_metadata_start, g_metadata_end);
}

uint64_t numa_find_metadata_space(const xaios_boot_info_t *boot,
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
        numa_descriptor_bounds(descriptor, &start, &end)) {
      if (end > EARLY_IDENTITY_LIMIT) end = EARLY_IDENTITY_LIMIT;
      uint64_t candidate = start;
      if (candidate == 0U) candidate = PAGE_SIZE;
      while (candidate < end) {
        uint64_t candidate_end = candidate + required_bytes;
        if (candidate_end < candidate || candidate_end > end) break;
        uint64_t next = candidate;
        if (numa_overlaps(candidate, candidate_end, boot->kernel_phys_base,
                          boot->kernel_phys_end)) {
          next = numa_align_up(boot->kernel_phys_end, PAGE_SIZE);
        }
        uint64_t map_end = boot->memory_map + boot->memory_map_size;
        if (numa_overlaps(candidate, candidate_end, boot->memory_map,
                          map_end)) {
          uint64_t after_map = numa_align_up(map_end, PAGE_SIZE);
          if (after_map > next) next = after_map;
        }
        uint64_t boot_image_start = 0U;
        uint64_t boot_image_end = 0U;
        boot_image_range(boot, &boot_image_start, &boot_image_end);
        if (numa_overlaps(candidate, candidate_end, boot_image_start,
                          boot_image_end)) {
          uint64_t after_image = numa_align_up(boot_image_end, PAGE_SIZE);
          if (after_image > next) next = after_image;
        }
        uint64_t smp_start = 0U;
        uint64_t smp_end = 0U;
        if (smp_bootstrap_reserved_range(&smp_start, &smp_end) == XAIOS_OK &&
            numa_overlaps(candidate, candidate_end, smp_start, smp_end)) {
          uint64_t after_smp = numa_align_up(smp_end, PAGE_SIZE);
          if (after_smp > next) next = after_smp;
        }
        if (next == candidate) return candidate;
        if (next < candidate) break;
        candidate = next;
      }
    }
    offset += boot->memory_descriptor_size;
  }
  return 0U;
}

void numa_bitmap_set(uint64_t *bitmap, uint64_t page_index) {
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
  g_local_bytes = 0U;
  g_remote_bytes = 0U;
  g_local_placement_bytes = 0U;
  g_remote_placement_bytes = 0U;
  if (boot == 0 || boot->memory_descriptor_size <
                       sizeof(xaios_memory_descriptor_t)) {
    klog("NUMA: invalid boot memory map\n");
    return;
  }

#ifdef XAIOS_X86_COMMON_RUNTIME
  if (numa_init_from_acpi(boot)) return;
#endif

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
        numa_descriptor_bounds(descriptor, &start, &end)) {
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
  uint32_t cpu_words = numa_cpu_bitmap_words();
  uint64_t metadata_bytes = sizeof(xaios_numa_node_t) +
      (uint64_t)region_count * sizeof(xaios_numa_region_t) +
      bitmap_words * sizeof(uint64_t) * 2U +
      (uint64_t)cpu_words * sizeof(uint64_t) + 64U;
  metadata_bytes = numa_align_up(metadata_bytes, PAGE_SIZE);
  g_metadata_start = numa_find_metadata_space(boot, metadata_bytes);
  if (g_metadata_start == 0U) {
    klog("NUMA: no bootstrap space for %lu metadata bytes\n",
         metadata_bytes);
    return;
  }
  g_metadata_end = g_metadata_start + metadata_bytes;
  numa_bytes_zero((void *)(uintptr_t)g_metadata_start, metadata_bytes);

  uint64_t cursor = g_metadata_start;
  g_numa_nodes = (xaios_numa_node_t *)(uintptr_t)cursor;
  cursor = numa_align_up(cursor + sizeof(xaios_numa_node_t), 8U);
  xaios_numa_node_t *node = &g_numa_nodes[0];
  node->regions = (xaios_numa_region_t *)(uintptr_t)cursor;
  cursor = numa_align_up(cursor +
                        (uint64_t)region_count *
                            sizeof(xaios_numa_region_t),
                    8U);

  node->node_id = 0U;
  node->online = 1U;
  node->proximity_domain = 0U;
  node->distance_count = 1U;
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
        numa_descriptor_bounds(descriptor, &start, &end)) {
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
        if (!numa_page_is_reserved(boot, page)) {
          numa_bitmap_set(region->free_bitmap, page_index);
          ++node->free_count;
        }
      }
    }
    offset += boot->memory_descriptor_size;
  }
  cursor = numa_align_up(cursor, 8U);
  node->cpu_bitmap = (uint64_t *)(uintptr_t)cursor;
  cursor += (uint64_t)node->cpu_word_count * sizeof(uint64_t);
  node->distances = (uint8_t *)(uintptr_t)cursor;
  node->distances[0] = 10U;
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

uint32_t numa_node_of_cpu(uint32_t cpu_id) {
  for (uint32_t node_id = 0U; node_id < g_numa_node_count; ++node_id) {
    if (numa_node_has_cpu(node_id, cpu_id)) return node_id;
  }
  return UINT32_MAX;
}

void numa_record_access(uint32_t cpu_id, uint64_t physical_address,
                        uint64_t bytes) {
  uint32_t cpu_node = numa_node_of_cpu(cpu_id);
  uint32_t memory_node = numa_node_of_phys(physical_address);
  if (cpu_node == UINT32_MAX || memory_node == UINT32_MAX || bytes == 0U) {
    return;
  }
  if (cpu_node == memory_node) {
    __atomic_fetch_add(&g_local_bytes, bytes, __ATOMIC_RELAXED);
  } else {
    __atomic_fetch_add(&g_remote_bytes, bytes, __ATOMIC_RELAXED);
  }
}

uint64_t numa_local_bytes(void) {
  return __atomic_load_n(&g_local_bytes, __ATOMIC_RELAXED);
}

uint64_t numa_remote_bytes(void) {
  return __atomic_load_n(&g_remote_bytes, __ATOMIC_RELAXED);
}

uint64_t numa_local_placement_bytes(void) {
  return __atomic_load_n(&g_local_placement_bytes, __ATOMIC_RELAXED);
}

uint64_t numa_remote_placement_bytes(void) {
  return __atomic_load_n(&g_remote_placement_bytes, __ATOMIC_RELAXED);
}

/* Called on every successful physical page allocation. Until this existed the
   local/remote counters moved only when the NUMA self-test poked them by
   hand, so the telemetry described a test rather than the machine: a kernel
   that placed every page on node 0 would have reported exactly the same two
   numbers. A CPU with no node -- which is what the fallback topology gives --
   is charged to neither side rather than to "local", because calling an
   unknown placement local is the flattering answer and it would hide the
   case where SRAT parsing produced nothing. */
static void record_placement(uint32_t node_id, uint64_t bytes) {
  if (g_numa_node_count < 2U) return;
  uint32_t cpu_node = numa_node_of_cpu(smp_cpu_id());
  if (cpu_node == UINT32_MAX) return;
  if (cpu_node == node_id) {
    __atomic_fetch_add(&g_local_placement_bytes, bytes, __ATOMIC_RELAXED);
  } else {
    __atomic_fetch_add(&g_remote_placement_bytes, bytes, __ATOMIC_RELAXED);
  }
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
      numa_bitmap_set(region->allocated_bitmap, page_index);
      --node->free_count;
      node->alloc_region_hint = region_index;
      node->alloc_page_hint = page_index + 1U;
      uint64_t physical = region->phys_start + page_index * PAGE_SIZE;
      xaios_spin_unlock(&node->lock);
      record_placement(node_id, PAGE_SIZE);
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
    numa_bitmap_set(region->free_bitmap, page_index);
    ++node->free_count;
    xaios_spin_unlock(&node->lock);
    return 1;
  }
  xaios_spin_unlock(&node->lock);
  return 0;
}
