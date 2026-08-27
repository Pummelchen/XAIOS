#ifndef XAIOS_VMM_H
#define XAIOS_VMM_H

#include <xaios/boot_info.h>
#include <xaios/status.h>
#include <xaios/types.h>

#define XAIOS_VMM_PRESENT UINT32_C(1)
#define XAIOS_VMM_WRITABLE (UINT32_C(1) << 1)
#define XAIOS_VMM_EXECUTABLE (UINT32_C(1) << 2)
#define XAIOS_VMM_DEVICE (UINT32_C(1) << 3)
#define XAIOS_VMM_USER (UINT32_C(1) << 4)
#define XAIOS_VMM_NG (UINT32_C(1) << 5)

#define XAIOS_VMM_LARGE_PAGE_SIZE UINT64_C(0x200000)
#define XAIOS_VMM_GIGANTIC_PAGE_SIZE UINT64_C(0x40000000)

/*
 * Userspace occupies the last gibibyte this kernel can address, and the
 * identity map is stopped one gibibyte short of it. That is the whole
 * arrangement, and it exists because the two used to overlap.
 *
 * Userspace began at 4 GiB. The kernel identity-maps physical memory in 1 GiB
 * blocks, and the per-CPU roots copy that map and then replace the entry
 * covering this window with the user directory -- so a machine with 4 GiB of
 * RAM handed the kernel's own 4-5 GiB of physical memory to userspace and lost
 * it. VMware Fusion faulted at level 1 on the first access to it; QEMU booted
 * and failed self-tests further in. Nothing was wrong with either platform:
 * the two address spaces were literally the same addresses, and which machines
 * noticed depended only on how much RAM they had.
 *
 * The kernel walks a single level-0 entry, so everything has to live below
 * 512 GiB and moving userspace above the identity map is not available. The
 * top slot is, and vmm_init caps the identity map at XAIOS_USER_BASE, so the
 * identity map cannot grow into userspace however much memory the machine has
 * -- the collision is now impossible rather than merely unlikely.
 */
#define XAIOS_USER_BASE UINT64_C(0x7fc0000000)
#define XAIOS_USER_LIMIT UINT64_C(0x8000000000)
#define XAIOS_USER_STACK_TOP UINT64_C(0x7fff000000)

void vmm_init(const xaios_boot_info_t *boot);
void vmm_activate_kernel(void);
/* Cache maintenance for memory shared with a CPU that has translation off,
 * where accesses bypass these caches entirely. Sizes come from CTR_EL0. */
void vmm_clean_to_memory(const void *buffer, uint64_t bytes);
void vmm_invalidate_from_memory(const void *buffer, uint64_t bytes);
xaios_status_t vmm_translate(uint64_t virtual_address, uint64_t *physical_address,
                            uint32_t *flags);
xaios_status_t vmm_validate_range_flags(uint64_t virtual_address, uint64_t size,
                                        uint32_t required_flags,
                                        uint32_t forbidden_flags);
xaios_status_t vmm_map_page(uint64_t virtual_address, uint64_t physical_address,
                           uint32_t flags);
xaios_status_t vmm_unmap_page(uint64_t virtual_address);
xaios_status_t vmm_map_large_page(uint64_t virtual_address,
                                 uint64_t physical_address, uint32_t flags);
xaios_status_t vmm_unmap_large_page(uint64_t virtual_address);
xaios_status_t vmm_map_gigantic_page(uint64_t virtual_address,
                                    uint64_t physical_address,
                                    uint32_t flags);
xaios_status_t vmm_unmap_gigantic_page(uint64_t virtual_address);
xaios_status_t vmm_validate_user_buffer(uint64_t virtual_address, uint64_t size,
                                       uint32_t required_flags);
void vmm_self_test(void);

/* Per-process address space APIs */
void vmm_create_user_aspace(uint64_t l3_tables[], uint32_t max_tables,
                            uint32_t *out_count);
xaios_status_t vmm_map_user_page(uint64_t virtual_address,
                                uint64_t physical_address, uint32_t flags,
                                uint64_t l3_tables[], uint32_t l3_count);
xaios_status_t vmm_unmap_user_page(uint64_t virtual_address,
                                  uint64_t l3_tables[], uint32_t l3_count);
void vmm_switch_user_aspace(uint64_t l3_tables[], uint32_t l3_count);
void vmm_destroy_user_aspace(uint64_t l3_tables[], uint32_t l3_count);

#endif
