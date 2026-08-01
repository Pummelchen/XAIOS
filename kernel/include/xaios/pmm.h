#ifndef XAIOS_PMM_H
#define XAIOS_PMM_H

#include <xaios/boot_info.h>
#include <xaios/types.h>

void pmm_init(const xaios_boot_info_t *boot);
void *pmm_alloc_page(void);
void *pmm_alloc_page_on_node(uint32_t node_id);
void *pmm_alloc_page_near(uint32_t preferred_node);
void pmm_free_page(void *page);
uint32_t pmm_node_of_page(void *page);
uint64_t pmm_total_pages(void);
uint64_t pmm_managed_pages(void);
uint64_t pmm_free_pages(void);

#endif
