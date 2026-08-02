#ifndef XAIOS_NUMA_H
#define XAIOS_NUMA_H

#include <xaios/boot_info.h>
#include <xaios/spinlock.h>
#include <xaios/types.h>

/*
 * NUMA node capacity: up to 8 nodes (covers QEMU and typical servers).
 * Actual node count detected from UEFI memory map at boot.
 * 8 nodes x 1GB per node = 8 GB total system capacity.
 * BSS: ~512 KB at max scale (8 x two 32 KB bitmaps).
 * For large-scale deployments, increase XAIOS_NUMA_MAX_NODES and
 * XAIOS_NUMA_BITMAP_BITS proportionally.
 */
#define XAIOS_NUMA_MAX_NODES 8U

/*
 * Bitmap page allocator: 1 bit per 4KB page.
 * XAIOS_NUMA_BITMAP_BITS = 262,144 entries -> supports up to 1GB per node.
 * 8 nodes x 1GB = 8 GB total system capacity.
 * Bitmap memory cost: 64 KB per node for free and allocation ownership maps
 * (8 nodes = 512 KB total in BSS).
 * Detected RAM via UEFI memory map; pages beyond bitmap capacity are logged.
 * For systems with >1GB per NUMA node, increase XAIOS_NUMA_BITMAP_BITS.
 */
#define XAIOS_NUMA_BITMAP_BITS UINT64_C(262144)
#define XAIOS_NUMA_BITMAP_WORDS (XAIOS_NUMA_BITMAP_BITS / 64U)

typedef struct xaios_numa_node {
  uint32_t node_id;
  uint32_t online;
  uint64_t phys_start;
  uint64_t phys_end;
  uint64_t total_pages;
  uint64_t managed_pages;
  uint64_t free_count;
  uint64_t cpu_mask;
  uint64_t alloc_hint; /* next-fit hint for faster allocation */
  xaios_spinlock_t lock;
  uint64_t bitmap[XAIOS_NUMA_BITMAP_WORDS]; /* 1 = free page */
  uint64_t allocated_bitmap[XAIOS_NUMA_BITMAP_WORDS]; /* 1 = PMM-owned */
} xaios_numa_node_t;

void numa_init(const xaios_boot_info_t *boot);
uint32_t numa_node_count(void);
const xaios_numa_node_t *numa_node(uint32_t node_id);
uint32_t numa_node_of_phys(uint64_t phys_addr);
void *numa_alloc_page_on_node(uint32_t node_id);
int numa_free_page(void *page);
void numa_self_test(void);

#endif
