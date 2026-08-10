#ifndef XAIOS_BOOT_UI_H
#define XAIOS_BOOT_UI_H

#include <xaios/types.h>

void boot_ui_begin(void);
void boot_ui_update(uint32_t percent, const char *loaded,
                    const char *loading, uint32_t remaining);
void boot_ui_error(const char *component, int32_t status);

#endif
