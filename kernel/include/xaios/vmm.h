#ifndef XAIOS_VMM_H
#define XAIOS_VMM_H

#include <xaios/boot_info.h>
#include <xaios/status.h>
#include <xaios/types.h>

#define XAIOS_VMM_PRESENT UINT32_C(1)
#define XAIOS_VMM_WRITABLE UINT32_C(1 << 1)
#define XAIOS_VMM_EXECUTABLE UINT32_C(1 << 2)
#define XAIOS_VMM_DEVICE UINT32_C(1 << 3)
#define XAIOS_VMM_USER UINT32_C(1 << 4)
#define XAIOS_VMM_NG UINT32_C(1 << 5)

#define XAIOS_USER_BASE UINT64_C(0x100000000)
#define XAIOS_USER_LIMIT UINT64_C(0x140000000)
#define XAIOS_USER_STACK_TOP UINT64_C(0x13f000000)

void vmm_init(const xaios_boot_info_t *boot);
void vmm_activate_kernel(void);
xaios_status_t vmm_translate(uint64_t virtual_address, uint64_t *physical_address,
                            uint32_t *flags);
xaios_status_t vmm_map_page(uint64_t virtual_address, uint64_t physical_address,
                           uint32_t flags);
xaios_status_t vmm_unmap_page(uint64_t virtual_address);
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
