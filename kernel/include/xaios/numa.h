#ifndef XAIOS_NUMA_H
#define XAIOS_NUMA_H

#include <xaios/boot_info.h>
#include <xaios/spinlock.h>
#include <xaios/types.h>

typedef struct xaios_numa_region {
  uint64_t phys_start;
  uint64_t page_count;
  uint64_t bitmap_words;
  uint64_t *free_bitmap;
  uint64_t *allocated_bitmap;
} xaios_numa_region_t;

typedef struct xaios_numa_node {
  uint32_t node_id;
  uint32_t online;
  uint32_t proximity_domain;
  uint32_t distance_count;
  uint64_t phys_start;
  uint64_t phys_end;
  uint64_t total_pages;
  uint64_t managed_pages;
  uint64_t free_count;
  uint64_t metadata_pages;
  uint32_t region_count;
  uint32_t cpu_word_count;
  xaios_numa_region_t *regions;
  uint64_t *cpu_bitmap;
  uint8_t *distances;
  uint64_t *hmat_latency_ps;
  uint64_t *hmat_bandwidth_bytes_per_second;
  uint32_t preferred_memory_node;
  uint32_t hmat_metrics_valid;
  uint32_t alloc_region_hint;
  uint32_t reserved;
  uint64_t alloc_page_hint;
  xaios_spinlock_t lock;
} xaios_numa_node_t;

void numa_init(const xaios_boot_info_t *boot);
uint32_t numa_node_count(void);
const xaios_numa_node_t *numa_node(uint32_t node_id);
uint32_t numa_node_of_phys(uint64_t phys_addr);
int numa_node_has_cpu(uint32_t node_id, uint32_t cpu_id);
uint32_t numa_node_of_cpu(uint32_t cpu_id);
uint8_t numa_distance(uint32_t from_node, uint32_t to_node);
uint32_t numa_preferred_node_for_cpu(uint32_t cpu_id);
void numa_record_access(uint32_t cpu_id, uint64_t physical_address,
                        uint64_t bytes);
uint64_t numa_local_bytes(void);
uint64_t numa_remote_bytes(void);
void *numa_alloc_page_on_node(uint32_t node_id);
int numa_free_page(void *page);
void numa_self_test(void);

#endif
