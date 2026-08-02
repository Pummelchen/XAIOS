#ifndef XAIOS_ELF_LOADER_H
#define XAIOS_ELF_LOADER_H

#include <xaios/initramfs.h>
#include <xaios/status.h>
#include <xaios/types.h>
#include <xaios/vmm.h>

#define XAIOS_ELF_LOADER_MAX_PAGES 256U
#define XAIOS_ELF_LOADER_L3_TABLES 4U

typedef struct xaios_process_aspace {
  uint64_t l3_phys[XAIOS_ELF_LOADER_L3_TABLES];
  uint32_t l3_count;
  uint64_t page_va[XAIOS_ELF_LOADER_MAX_PAGES];
  uint64_t page_pa[XAIOS_ELF_LOADER_MAX_PAGES];
  uint32_t page_count;
} xaios_process_aspace_t;

xaios_status_t elf_loader_load(const xaios_initramfs_file_t *file,
                              xaios_process_aspace_t *aspace,
                              uint64_t *out_entry);
xaios_status_t elf_loader_map_stack(xaios_process_aspace_t *aspace,
                                   uint64_t stack_va, uint64_t guard_low,
                                   uint64_t guard_high);
void elf_loader_reclaim(xaios_process_aspace_t *aspace, uint64_t mapped_low,
                        uint64_t mapped_high);
void elf_loader_self_test(void);

#endif
