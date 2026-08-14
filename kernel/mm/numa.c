#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/numa.h>
#include <xaios/smp.h>

#ifdef XAIOS_X86_COMMON_RUNTIME
#include "../arch/x86_64/acpi.h"
#endif

#define PAGE_SIZE UINT64_C(4096)
#define EARLY_IDENTITY_LIMIT UINT64_C(0x100000000)

static xaios_numa_node_t *g_numa_nodes;
static uint32_t g_numa_node_count;
static uint64_t g_metadata_start;
static uint64_t g_metadata_end;
static volatile uint64_t g_local_bytes;
static volatile uint64_t g_remote_bytes;

static int page_is_reserved(const xaios_boot_info_t *boot, uint64_t page);
static uint64_t find_metadata_space(const xaios_boot_info_t *boot,
                                    uint64_t required_bytes);
static void bitmap_set(uint64_t *bitmap, uint64_t page_index);

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

static void boot_image_range(const xaios_boot_info_t *boot, uint64_t *start,
                             uint64_t *end) {
  *start = 0U;
  *end = 0U;
  if (boot->boot_image_base == 0U || boot->boot_image_size == 0U ||
      boot->boot_image_base > UINT64_MAX - boot->boot_image_size) {
    return;
  }
  *start = align_down(boot->boot_image_base, PAGE_SIZE);
  *end = align_up(boot->boot_image_base + boot->boot_image_size, PAGE_SIZE);
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

static uint32_t cpu_bitmap_words(void) {
  uint32_t maximum = 0U;
  for (uint32_t ordinal = 0U; ordinal < smp_online_count(); ++ordinal) {
    uint32_t cpu_id = 0U;
    if (smp_cpu_id_at(ordinal, &cpu_id) == XAIOS_OK && cpu_id > maximum) {
      maximum = cpu_id;
    }
  }
  return (maximum / 64U) + 1U;
}

#ifdef XAIOS_X86_COMMON_RUNTIME
static int domain_seen_before(const x86_64_acpi_info_t *info,
                              uint32_t ordinal, uint32_t domain) {
  for (uint32_t i = 0U; i < ordinal; ++i) {
    x86_64_acpi_memory_affinity_t affinity;
    if (x86_64_acpi_memory_affinity_at(info, i, &affinity) &&
        affinity.proximity_domain == domain) {
      return 1;
    }
  }
  return 0;
}

static uint32_t domain_count(const x86_64_acpi_info_t *info) {
  uint32_t count = 0U;
  for (uint32_t i = 0U; i < info->memory_affinities; ++i) {
    x86_64_acpi_memory_affinity_t affinity;
    if (!x86_64_acpi_memory_affinity_at(info, i, &affinity)) return 0U;
    if (!domain_seen_before(info, i, affinity.proximity_domain)) ++count;
  }
  return count;
}

static int domain_at(const x86_64_acpi_info_t *info, uint32_t node_index,
                     uint32_t *domain) {
  uint32_t current = 0U;
  for (uint32_t i = 0U; i < info->memory_affinities; ++i) {
    x86_64_acpi_memory_affinity_t affinity;
    if (!x86_64_acpi_memory_affinity_at(info, i, &affinity)) return 0;
    if (domain_seen_before(info, i, affinity.proximity_domain)) continue;
    if (current++ == node_index) {
      *domain = affinity.proximity_domain;
      return 1;
    }
  }
  return 0;
}

static uint32_t node_for_domain(const x86_64_acpi_info_t *info,
                                uint32_t domain) {
  uint32_t count = domain_count(info);
  for (uint32_t node = 0U; node < count; ++node) {
    uint32_t candidate = 0U;
    if (domain_at(info, node, &candidate) && candidate == domain) return node;
  }
  return UINT32_MAX;
}

static int affinity_ranges_valid(const x86_64_acpi_info_t *info) {
  for (uint32_t i = 0U; i < info->memory_affinities; ++i) {
    x86_64_acpi_memory_affinity_t left;
    if (!x86_64_acpi_memory_affinity_at(info, i, &left)) return 0;
    uint64_t left_end = left.base + left.length;
    for (uint32_t j = 0U; j < i; ++j) {
      x86_64_acpi_memory_affinity_t right;
      if (!x86_64_acpi_memory_affinity_at(info, j, &right)) return 0;
      if (overlaps(left.base, left_end, right.base,
                   right.base + right.length)) {
        return 0;
      }
    }
  }
  return 1;
}

static int affinity_intersection(
    const xaios_memory_descriptor_t *descriptor,
    const x86_64_acpi_memory_affinity_t *affinity, uint64_t *start,
    uint64_t *end) {
  uint64_t descriptor_start = 0U;
  uint64_t descriptor_end = 0U;
  if (!descriptor_bounds(descriptor, &descriptor_start, &descriptor_end)) {
    return 0;
  }
  uint64_t affinity_end = affinity->base + affinity->length;
  uint64_t intersection_start = descriptor_start > affinity->base
                                    ? descriptor_start
                                    : affinity->base;
  uint64_t intersection_end = descriptor_end < affinity_end
                                  ? descriptor_end
                                  : affinity_end;
  *start = align_up(intersection_start, PAGE_SIZE);
  *end = align_down(intersection_end, PAGE_SIZE);
  return *start < *end;
}

static int numa_init_from_acpi(const xaios_boot_info_t *boot) {
  x86_64_acpi_info_t info;
  if (boot->acpi_rsdp == 0U ||
      !x86_64_acpi_parse(boot->acpi_rsdp, &info)) {
    klog("NUMA: ACPI topology unavailable; using firmware-map fallback\n");
    return 0;
  }
  if (info.memory_affinities == 0U || !affinity_ranges_valid(&info)) {
    klog("NUMA: ACPI memory affinities invalid count=%u; using firmware-map fallback\n",
         info.memory_affinities);
    return 0;
  }
  uint32_t node_count = domain_count(&info);
  if (node_count == 0U) {
    klog("NUMA: ACPI proximity domains unavailable; using firmware-map fallback\n");
    return 0;
  }
  uint64_t total_pages = 0U;
  uint64_t total_bitmap_words = 0U;
  uint32_t total_regions = 0U;
  for (uint32_t affinity_index = 0U;
       affinity_index < info.memory_affinities; ++affinity_index) {
    x86_64_acpi_memory_affinity_t affinity;
    if (!x86_64_acpi_memory_affinity_at(&info, affinity_index, &affinity)) {
      return 0;
    }
    for (uint64_t offset = 0U;
         offset + sizeof(xaios_memory_descriptor_t) <= boot->memory_map_size;
         offset += boot->memory_descriptor_size) {
      const xaios_memory_descriptor_t *descriptor =
          (const xaios_memory_descriptor_t *)(uintptr_t)(boot->memory_map +
                                                         offset);
      uint64_t start = 0U;
      uint64_t end = 0U;
      if (descriptor->type != XAIOS_MEMORY_TYPE_CONVENTIONAL ||
          !affinity_intersection(descriptor, &affinity, &start, &end)) {
        continue;
      }
      uint64_t pages = (end - start) / PAGE_SIZE;
      uint64_t words = (pages + 63U) / 64U;
      if (total_pages > UINT64_MAX - pages ||
          total_bitmap_words > UINT64_MAX - words ||
          total_regions == UINT32_MAX) {
        return 0;
      }
      total_pages += pages;
      total_bitmap_words += words;
      ++total_regions;
    }
  }
  if (total_regions == 0U || total_pages == 0U ||
      total_bitmap_words > UINT64_MAX / (2U * sizeof(uint64_t))) {
    klog("NUMA: ACPI ranges do not intersect usable memory regions=%u pages=%lu\n",
         total_regions, total_pages);
    return 0;
  }
  uint32_t cpu_words = cpu_bitmap_words();
  uint64_t metadata_bytes = (uint64_t)node_count * sizeof(xaios_numa_node_t);
  uint64_t addition = (uint64_t)total_regions * sizeof(xaios_numa_region_t);
  if (metadata_bytes > UINT64_MAX - addition) return 0;
  metadata_bytes += addition;
  addition = total_bitmap_words * 2U * sizeof(uint64_t);
  if (metadata_bytes > UINT64_MAX - addition) return 0;
  metadata_bytes += addition;
  addition = (uint64_t)node_count * cpu_words * sizeof(uint64_t);
  if (metadata_bytes > UINT64_MAX - addition) return 0;
  metadata_bytes += addition;
  addition = (uint64_t)node_count * node_count *
                 (sizeof(uint8_t) + 2U * sizeof(uint64_t)) +
             128U;
  if (metadata_bytes > UINT64_MAX - addition) return 0;
  metadata_bytes = align_up(metadata_bytes + addition, PAGE_SIZE);
  if (metadata_bytes == UINT64_MAX) return 0;

  g_metadata_start = find_metadata_space(boot, metadata_bytes);
  if (g_metadata_start == 0U ||
      g_metadata_start > UINT64_MAX - metadata_bytes) {
    klog("NUMA: ACPI topology metadata allocation failed bytes=%lu\n",
         metadata_bytes);
    return 0;
  }
  g_metadata_end = g_metadata_start + metadata_bytes;
  bytes_zero((void *)(uintptr_t)g_metadata_start, metadata_bytes);
  uint64_t cursor = g_metadata_start;
  g_numa_nodes = (xaios_numa_node_t *)(uintptr_t)cursor;
  cursor = align_up(cursor +
                        (uint64_t)node_count * sizeof(xaios_numa_node_t),
                    8U);
  xaios_numa_region_t *regions =
      (xaios_numa_region_t *)(uintptr_t)cursor;
  cursor = align_up(cursor +
                        (uint64_t)total_regions * sizeof(xaios_numa_region_t),
                    8U);

  uint32_t region_cursor = 0U;
  for (uint32_t node_index = 0U; node_index < node_count; ++node_index) {
    xaios_numa_node_t *node = &g_numa_nodes[node_index];
    uint32_t domain = 0U;
    if (!domain_at(&info, node_index, &domain)) return 0;
    node->node_id = node_index;
    node->online = 1U;
    node->proximity_domain = domain;
    node->distance_count = node_count;
    node->phys_start = UINT64_MAX;
    node->cpu_word_count = cpu_words;
    node->regions = &regions[region_cursor];
    xaios_spin_init(&node->lock);
    for (uint32_t affinity_index = 0U;
         affinity_index < info.memory_affinities; ++affinity_index) {
      x86_64_acpi_memory_affinity_t affinity;
      if (!x86_64_acpi_memory_affinity_at(&info, affinity_index, &affinity) ||
          affinity.proximity_domain != domain) {
        continue;
      }
      for (uint64_t offset = 0U;
           offset + sizeof(xaios_memory_descriptor_t) <= boot->memory_map_size;
           offset += boot->memory_descriptor_size) {
        const xaios_memory_descriptor_t *descriptor =
            (const xaios_memory_descriptor_t *)(uintptr_t)(boot->memory_map +
                                                           offset);
        uint64_t start = 0U;
        uint64_t end = 0U;
        if (descriptor->type != XAIOS_MEMORY_TYPE_CONVENTIONAL ||
            !affinity_intersection(descriptor, &affinity, &start, &end)) {
          continue;
        }
        xaios_numa_region_t *region = &regions[region_cursor++];
        region->phys_start = start;
        region->page_count = (end - start) / PAGE_SIZE;
        region->bitmap_words = (region->page_count + 63U) / 64U;
        region->free_bitmap = (uint64_t *)(uintptr_t)cursor;
        cursor += region->bitmap_words * sizeof(uint64_t);
        region->allocated_bitmap = (uint64_t *)(uintptr_t)cursor;
        cursor += region->bitmap_words * sizeof(uint64_t);
        ++node->region_count;
        node->total_pages += region->page_count;
        node->managed_pages += region->page_count;
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
    }
  }
  cursor = align_up(cursor, 8U);
  for (uint32_t node_index = 0U; node_index < node_count; ++node_index) {
    g_numa_nodes[node_index].cpu_bitmap = (uint64_t *)(uintptr_t)cursor;
    cursor += (uint64_t)cpu_words * sizeof(uint64_t);
  }
  for (uint32_t node_index = 0U; node_index < node_count; ++node_index) {
    xaios_numa_node_t *node = &g_numa_nodes[node_index];
    node->distances = (uint8_t *)(uintptr_t)cursor;
    cursor += node_count;
    for (uint32_t target = 0U; target < node_count; ++target) {
      uint32_t target_domain = g_numa_nodes[target].proximity_domain;
      uint8_t distance = node_index == target ? 10U : 20U;
      (void)x86_64_acpi_slit_distance(&info, node->proximity_domain,
                                      target_domain, &distance);
      node->distances[target] = distance;
    }
  }
  cursor = align_up(cursor, 8U);
  for (uint32_t node_index = 0U; node_index < node_count; ++node_index) {
    xaios_numa_node_t *node = &g_numa_nodes[node_index];
    node->hmat_latency_ps = (uint64_t *)(uintptr_t)cursor;
    cursor += (uint64_t)node_count * sizeof(uint64_t);
    node->hmat_bandwidth_bytes_per_second = (uint64_t *)(uintptr_t)cursor;
    cursor += (uint64_t)node_count * sizeof(uint64_t);
    node->preferred_memory_node = node_index;
    uint64_t best_latency = UINT64_MAX;
    uint64_t best_bandwidth = 0U;
    for (uint32_t target = 0U; target < node_count; ++target) {
      uint32_t target_domain = g_numa_nodes[target].proximity_domain;
      uint64_t latency = 0U;
      uint64_t bandwidth = 0U;
      int have_latency = x86_64_acpi_hmat_metric(
          &info, node->proximity_domain, target_domain, 0U, &latency);
      int have_bandwidth = x86_64_acpi_hmat_metric(
          &info, node->proximity_domain, target_domain, 3U, &bandwidth);
      node->hmat_latency_ps[target] = have_latency ? latency : 0U;
      node->hmat_bandwidth_bytes_per_second[target] =
          have_bandwidth ? bandwidth : 0U;
      if (have_latency && have_bandwidth &&
          (latency < best_latency ||
           (latency == best_latency && bandwidth > best_bandwidth))) {
        best_latency = latency;
        best_bandwidth = bandwidth;
        node->preferred_memory_node = target;
      }
    }
    node->hmat_metrics_valid = best_latency != UINT64_MAX ? 1U : 0U;
  }
  if (cursor > g_metadata_end) return 0;
  for (uint32_t ordinal = 0U; ordinal < smp_online_count(); ++ordinal) {
    uint32_t cpu_id = 0U;
    if (smp_cpu_id_at(ordinal, &cpu_id) != XAIOS_OK) continue;
    uint32_t node_index = 0U;
    for (uint32_t affinity_index = 0U;
         affinity_index < info.processor_affinities; ++affinity_index) {
      x86_64_acpi_processor_affinity_t affinity;
      if (x86_64_acpi_processor_affinity_at(&info, affinity_index,
                                            &affinity) &&
          affinity.apic_id == cpu_id) {
        uint32_t candidate = node_for_domain(&info, affinity.proximity_domain);
        if (candidate != UINT32_MAX) node_index = candidate;
        break;
      }
    }
    g_numa_nodes[node_index].cpu_bitmap[cpu_id / 64U] |=
        UINT64_C(1) << (cpu_id % 64U);
  }
  g_numa_node_count = node_count;
  klog("NUMA: ACPI topology nodes=%u regions=%u managed=%lu cpu_words=%u metadata_bytes=%lu hmat_structures=%u\n",
       node_count, total_regions, total_pages, cpu_words, metadata_bytes,
       info.hmat_locality_structures);
  for (uint32_t node_index = 0U; node_index < node_count; ++node_index) {
    const xaios_numa_node_t *node = &g_numa_nodes[node_index];
    klog("NUMA: HMAT initiator=%u preferred=%u valid=%u latency_ps=%lu bandwidth_Bps=%lu\n",
         node->proximity_domain, node->preferred_memory_node,
         node->hmat_metrics_valid,
         node->hmat_latency_ps[node->preferred_memory_node],
         node->hmat_bandwidth_bytes_per_second[node->preferred_memory_node]);
  }
  return 1;
}
#endif

static int page_is_reserved(const xaios_boot_info_t *boot, uint64_t page) {
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
  return overlaps(page, page_end, boot->kernel_phys_base,
                  boot->kernel_phys_end) ||
         overlaps(page, page_end, map_start, map_end) ||
         overlaps(page, page_end, boot_image_start, boot_image_end) ||
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
      if (candidate == 0U) candidate = PAGE_SIZE;
      while (candidate < end) {
        uint64_t candidate_end = candidate + required_bytes;
        if (candidate_end < candidate || candidate_end > end) break;
        uint64_t next = candidate;
        if (overlaps(candidate, candidate_end, boot->kernel_phys_base,
                     boot->kernel_phys_end)) {
          next = align_up(boot->kernel_phys_end, PAGE_SIZE);
        }
        uint64_t map_end = boot->memory_map + boot->memory_map_size;
        if (overlaps(candidate, candidate_end, boot->memory_map, map_end)) {
          uint64_t after_map = align_up(map_end, PAGE_SIZE);
          if (after_map > next) next = after_map;
        }
        uint64_t boot_image_start = 0U;
        uint64_t boot_image_end = 0U;
        boot_image_range(boot, &boot_image_start, &boot_image_end);
        if (overlaps(candidate, candidate_end, boot_image_start,
                     boot_image_end)) {
          uint64_t after_image = align_up(boot_image_end, PAGE_SIZE);
          if (after_image > next) next = after_image;
        }
        uint64_t smp_start = 0U;
        uint64_t smp_end = 0U;
        if (smp_bootstrap_reserved_range(&smp_start, &smp_end) == XAIOS_OK &&
            overlaps(candidate, candidate_end, smp_start, smp_end)) {
          uint64_t after_smp = align_up(smp_end, PAGE_SIZE);
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
  g_local_bytes = 0U;
  g_remote_bytes = 0U;
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
  uint32_t cpu_words = cpu_bitmap_words();
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

uint8_t numa_distance(uint32_t from_node, uint32_t to_node) {
  if (from_node >= g_numa_node_count || to_node >= g_numa_node_count ||
      g_numa_nodes[from_node].distances == 0 ||
      to_node >= g_numa_nodes[from_node].distance_count) {
    return UINT8_MAX;
  }
  return g_numa_nodes[from_node].distances[to_node];
}

uint32_t numa_preferred_node_for_cpu(uint32_t cpu_id) {
  uint32_t local = numa_node_of_cpu(cpu_id);
  if (local == UINT32_MAX || local >= g_numa_node_count) return 0U;
  uint32_t preferred = g_numa_nodes[local].preferred_memory_node;
  return preferred < g_numa_node_count ? preferred : local;
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
    numa_record_access(0U, (uint64_t)(uintptr_t)remote_page, 128U);
    kassert(numa_remote_bytes() == 128U);
    kassert(numa_free_page(remote_page) == 1);
  }

  void *pages[64];
  for (uint32_t index = 0U; index < 64U; ++index) {
    pages[index] = numa_alloc_page_on_node(0U);
    kassert(pages[index] != 0);
  }
  for (uint32_t index = 0U; index < 64U; ++index) {
    kassert(numa_free_page(pages[index]) == 1);
  }
  klog("NUMA: self-test passed nodes=%u regions=%u managed=%lu free=%lu dynamic_metadata=1 ownership=verified local_bytes=%lu remote_bytes=%lu\n",
       g_numa_node_count, node0->region_count, node0->managed_pages,
       node0->free_count, numa_local_bytes(), numa_remote_bytes());
}
