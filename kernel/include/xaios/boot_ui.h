#ifndef XAIOS_BOOT_UI_H
#define XAIOS_BOOT_UI_H

#include <xaios/boot_info.h>
#include <xaios/types.h>

#define XAIOS_BOOT_UI_CONTROL_MAGIC UINT32_C(0x58425549)
#define XAIOS_BOOT_UI_CONTROL_VERSION UINT32_C(3)
#define XAIOS_BOOT_UI_STAGE_SSH_LOADING UINT32_C(1)
#define XAIOS_BOOT_UI_STAGE_SSH_READY UINT32_C(2)
#define XAIOS_BOOT_UI_STAGE_SSH_FAILED UINT32_C(3)
#define XAIOS_BOOT_UI_CONSOLE_LOCKED UINT32_C(0)
#define XAIOS_BOOT_UI_CONSOLE_LOGIN UINT32_C(1)
#define XAIOS_BOOT_UI_CONSOLE_PASSWORD UINT32_C(2)
#define XAIOS_BOOT_UI_CONSOLE_SHELL UINT32_C(3)

typedef struct xaios_boot_ui_control {
  uint32_t magic;
  uint32_t version;
  uint32_t stage;
  int32_t status;
  uint32_t ipv4;
  uint32_t console_state;
  uint32_t cursor_visible;
} xaios_boot_ui_control_t;

void boot_ui_begin(const xaios_boot_info_t *boot);
void boot_ui_update(uint32_t percent, const char *loaded,
                    const char *loading, uint32_t remaining);
void boot_ui_error(const char *component, int32_t status);
uint32_t boot_ui_handle_control(const xaios_boot_ui_control_t *control);

#endif
