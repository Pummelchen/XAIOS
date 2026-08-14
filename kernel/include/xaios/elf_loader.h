#ifndef XAIOS_ELF_LOADER_H
#define XAIOS_ELF_LOADER_H

#include <xaios/initramfs.h>
#include <xaios/status.h>
#include <xaios/types.h>
#include <xaios/vmm.h>

#define XAIOS_ELF_CODE_WINDOWS 8U
#define XAIOS_ELF_LOADER_L3_TABLES (XAIOS_ELF_CODE_WINDOWS + 1U)

typedef struct xaios_process_page_mapping {
  uint64_t va;
  uint64_t pa;
} xaios_process_page_mapping_t;

typedef struct xaios_process_aspace {
  uint64_t l3_phys[XAIOS_ELF_LOADER_L3_TABLES];
  uint32_t l3_count;
  xaios_process_page_mapping_t *pages;
  uint32_t page_count;
  uint32_t page_capacity;
} xaios_process_aspace_t;

xaios_status_t elf_loader_load(const xaios_initramfs_file_t *file,
                              xaios_process_aspace_t *aspace,
                              uint64_t *out_entry);
xaios_status_t elf_loader_map_stack(xaios_process_aspace_t *aspace,
                                   uint64_t stack_va, uint64_t guard_low,
                                   uint64_t guard_high);
xaios_status_t elf_loader_write_user(xaios_process_aspace_t *aspace,
                                     uint64_t virtual_address,
                                     const void *source, uint64_t size);
void elf_loader_reclaim(xaios_process_aspace_t *aspace, uint64_t mapped_low,
                        uint64_t mapped_high);
void elf_loader_self_test(void);

#endif
