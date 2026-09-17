#ifndef XAIOS_LOADER_IMAGE_H
#define XAIOS_LOADER_IMAGE_H

#include "loader_common.h"

/* Finding the kernel: the verified A/B system volume first, then the EFI
   System Partition, then a payload embedded in this loader's own image. */
efi_status_t xaios_loader_open_root(efi_handle_t image_handle,
                                    efi_system_table_t *system_table,
                                    efi_file_protocol_t **root);
efi_status_t xaios_loader_read_kernel_file(efi_system_table_t *system_table,
                                           efi_file_protocol_t *root,
                                           void **kernel_buffer,
                                           uint64_t *kernel_size);
efi_status_t xaios_loader_read_optional_boot_image(
    efi_system_table_t *system_table, efi_file_protocol_t *root,
    uint64_t *image_base, uint64_t *image_size);
/* Where the firmware mapped this loader, or nothing if it will not say. */
const void *xaios_loader_image_base(efi_handle_t image_handle,
                                    efi_system_table_t *system_table);

/* Validating and placing it. */
int xaios_loader_validate_elf(const void *kernel_buffer, uint64_t kernel_size,
                              const elf64_ehdr_t **ehdr_out);
efi_status_t xaios_loader_load_kernel_segments(
    efi_system_table_t *system_table, const void *kernel_buffer,
    uint64_t kernel_size, const elf64_ehdr_t *ehdr, uint64_t *kernel_base,
    uint64_t *kernel_end, uint64_t *kernel_vaddr_base);

#endif
