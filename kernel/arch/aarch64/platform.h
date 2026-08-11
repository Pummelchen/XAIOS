#ifndef XAIOS_AARCH64_PLATFORM_H
#define XAIOS_AARCH64_PLATFORM_H

#include <xaios/types.h>

void aarch64_platform_set_page_tables(uint32_t ordinal, uint64_t *root,
                                      uint64_t *user_directory);
uint64_t *aarch64_platform_page_table_root(uint32_t ordinal);
uint64_t *aarch64_platform_user_page_directory(uint32_t ordinal);
uint32_t aarch64_platform_current_ordinal(void);

#endif
