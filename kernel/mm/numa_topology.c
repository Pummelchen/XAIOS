/* NUMA topology discovery and the distance table it produces: x86_64 ACPI
   SRAT proximity domains, SLIT distances and HMAT latency/bandwidth metrics,
   plus the distance-table accessors and the distance-ordered fallback policy
   the placement paths read. Split out of kernel/mm/numa.c to keep that file
   under the repository source limit; the code is moved verbatim. */
#include <xaios/klog.h>
#include <xaios/numa.h>
#include <xaios/smp.h>

#include "numa_internal.h"

#ifdef XAIOS_X86_COMMON_RUNTIME
#include "../arch/x86_64/acpi.h"
#endif

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
      if (numa_overlaps(left.base, left_end, right.base,
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
  if (!numa_descriptor_bounds(descriptor, &descriptor_start, &descriptor_end)) {
    return 0;
  }
  uint64_t affinity_end = affinity->base + affinity->length;
  uint64_t intersection_start = descriptor_start > affinity->base
                                    ? descriptor_start
                                    : affinity->base;
  uint64_t intersection_end = descriptor_end < affinity_end
                                  ? descriptor_end
                                  : affinity_end;
  *start = numa_align_up(intersection_start, PAGE_SIZE);
  *end = numa_align_down(intersection_end, PAGE_SIZE);
  return *start < *end;
}

int numa_init_from_acpi(const xaios_boot_info_t *boot) {
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
  uint32_t cpu_words = numa_cpu_bitmap_words();
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
  metadata_bytes = numa_align_up(metadata_bytes + addition, PAGE_SIZE);
  if (metadata_bytes == UINT64_MAX) return 0;

  g_metadata_start = numa_find_metadata_space(boot, metadata_bytes);
  if (g_metadata_start == 0U ||
      g_metadata_start > UINT64_MAX - metadata_bytes) {
    klog("NUMA: ACPI topology metadata allocation failed bytes=%lu\n",
         metadata_bytes);
    return 0;
  }
  g_metadata_end = g_metadata_start + metadata_bytes;
  numa_bytes_zero((void *)(uintptr_t)g_metadata_start, metadata_bytes);
  uint64_t cursor = g_metadata_start;
  g_numa_nodes = (xaios_numa_node_t *)(uintptr_t)cursor;
  cursor = numa_align_up(cursor +
                        (uint64_t)node_count * sizeof(xaios_numa_node_t),
                    8U);
  xaios_numa_region_t *regions =
      (xaios_numa_region_t *)(uintptr_t)cursor;
  cursor = numa_align_up(cursor +
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
          if (!numa_page_is_reserved(boot, page)) {
            numa_bitmap_set(region->free_bitmap, page_index);
            ++node->free_count;
          }
        }
      }
    }
  }
  cursor = numa_align_up(cursor, 8U);
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
  cursor = numa_align_up(cursor, 8U);
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

uint32_t numa_nodes_by_distance(uint32_t from_node, uint32_t *out_nodes,
                                uint32_t capacity) {
  if (out_nodes == 0 || capacity == 0U || g_numa_node_count == 0U) return 0U;
  uint32_t written = 0U;
  /* The starting node goes first without consulting the table. A SLIT is
     firmware-supplied and a placement policy that trusted it blindly would
     send every allocation off-node the moment a machine shipped a table
     claiming a remote node is nearer than the local one. Distance decides the
     order of the alternatives, not whether local memory is tried first. */
  if (from_node < g_numa_node_count) out_nodes[written++] = from_node;
  while (written < capacity) {
    uint32_t best = UINT32_MAX;
    uint8_t best_distance = UINT8_MAX;
    for (uint32_t candidate = 0U; candidate < g_numa_node_count; ++candidate) {
      uint32_t already = 0U;
      for (uint32_t index = 0U; index < written; ++index) {
        if (out_nodes[index] == candidate) already = 1U;
      }
      if (already != 0U) continue;
      uint8_t distance = numa_distance(from_node, candidate);
      /* Strictly-less keeps the tie on the lower node id, because candidates
         are walked in ascending order. Two boots of one machine must lease
         and allocate from the same node, or a failure that depends on
         placement stops being reproducible. */
      if (best == UINT32_MAX || distance < best_distance) {
        best = candidate;
        best_distance = distance;
      }
    }
    if (best == UINT32_MAX) break;
    out_nodes[written++] = best;
  }
  return written;
}
