#ifndef XAIOS_MM_NUMA_INTERNAL_H
#define XAIOS_MM_NUMA_INTERNAL_H

/* Private declarations shared by kernel/mm/numa.c and the translation units
   split out of it (numa_topology.c, numa_selftest.c). The public NUMA API is
   <xaios/numa.h>; nothing here is for other subsystems. */

#include <xaios/boot_info.h>
#include <xaios/numa.h>
#include <xaios/types.h>

#define PAGE_SIZE UINT64_C(4096)
#define EARLY_IDENTITY_LIMIT UINT64_C(0x100000000)

/* Early-boot NUMA state owned by kernel/mm/numa.c. */
extern xaios_numa_node_t *g_numa_nodes;
extern uint32_t g_numa_node_count;
extern uint64_t g_metadata_start;
extern uint64_t g_metadata_end;

/* Boot-time memory helpers shared by the topology paths in numa.c and
   numa_topology.c. */
uint64_t numa_align_up(uint64_t value, uint64_t align);
uint64_t numa_align_down(uint64_t value, uint64_t align);
int numa_overlaps(uint64_t start, uint64_t end, uint64_t used_start,
                  uint64_t used_end);
void numa_bytes_zero(void *buffer, uint64_t length);
int numa_descriptor_bounds(const xaios_memory_descriptor_t *descriptor,
                           uint64_t *start, uint64_t *end);
uint32_t numa_cpu_bitmap_words(void);
int numa_page_is_reserved(const xaios_boot_info_t *boot, uint64_t page);
uint64_t numa_find_metadata_space(const xaios_boot_info_t *boot,
                                  uint64_t required_bytes);
void numa_bitmap_set(uint64_t *bitmap, uint64_t page_index);

#ifdef XAIOS_X86_COMMON_RUNTIME
int numa_init_from_acpi(const xaios_boot_info_t *boot);
#endif

#endif /* XAIOS_MM_NUMA_INTERNAL_H */
