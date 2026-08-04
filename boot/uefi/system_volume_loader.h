#ifndef XAIOS_SYSTEM_VOLUME_LOADER_H
#define XAIOS_SYSTEM_VOLUME_LOADER_H

#include "include/uefi_min.h"

efi_status_t system_volume_read_kernel(
    efi_handle_t image_handle, efi_system_table_t *system_table,
    void **kernel_buffer, uint64_t *kernel_size, uint32_t *selected_slot,
    uint64_t *selected_generation, uint32_t *rollback_performed);

#endif
