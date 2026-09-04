#ifndef XAIOS_BOOT_UI_H
#define XAIOS_BOOT_UI_H

#include <xaios/boot_info.h>
#include <xaios/status.h>
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
/* Mirror console bytes onto the framebuffer terminal, once boot hands the
   display over. No-ops when there is no framebuffer or before handover. */
void boot_ui_console_write(const char *text, uint64_t length);
/* Present drawing a throttled console write left pending, once the present
   interval has passed. Called from the console-read syscall. */
void boot_ui_present_pending(void);
uint32_t boot_ui_has_framebuffer(void);
/* The framebuffer terminal's size in character cells, or zero in both when
   there is no framebuffer terminal to measure. */
void boot_ui_terminal_size(uint32_t *columns, uint32_t *rows);
void boot_ui_adopt_framebuffer(uint32_t *pixels, uint32_t width,
                               uint32_t height,
                               xaios_status_t (*present)(uint32_t x,
                                                         uint32_t y,
                                                         uint32_t width,
                                                         uint32_t height));
void boot_ui_console_text(const char *text);
void boot_ui_self_test(void);

#endif
