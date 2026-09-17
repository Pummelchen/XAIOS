/* Private interface shared by boot_ui.c, boot_ui_render.c and boot_ui_term.c.
 *
 * boot_ui.c keeps the boot order, the font tables and the public entry points.
 * boot_ui_render.c draws the boot UI -- the framebuffer primitives, the status
 * panel, the readback self-test, the present path and the console progress
 * text. boot_ui_term.c is the framebuffer text terminal the display becomes
 * after boot: its cell cache, its xterm colours, its UTF-8 decoder and its
 * escape parser.
 *
 * boot_ui.c keeps the font tables and the constants FB_GLYPH_WIDTH,
 * FB_GLYPH_HEIGHT, TERM_MARGIN_X and TERM_MARGIN_Y because
 * tests/scripts/qemu-console-xtop-gate.py reads the console geometry
 * out of that file. The guarded copies here are the same values, for
 * the two modules that need them across the translation-unit
 * boundary; the gate would catch the two drifting apart.
 *
 * The terminal's state is defined in boot_ui_term.c and declared here because
 * boot_ui.c still decides when the terminal exists and when it is presented.
 * Nothing here returns a pointer into that state; a caller that needs a value
 * reads it into its own local.
 */
#ifndef XAIOS_KERNEL_CORE_BOOT_UI_INTERNAL_H
#define XAIOS_KERNEL_CORE_BOOT_UI_INTERNAL_H

#include <xaios/boot_info.h>
#include <xaios/boot_ui.h>
#include <xaios/network_stack.h>
#include <xaios/status.h>
#include <xaios/types.h>

#define BOOT_BAR_WIDTH UINT32_C(40)
#define FB_MARGIN UINT32_C(48)
#define FB_BAR_MAX_WIDTH UINT32_C(720)

#ifndef FB_GLYPH_WIDTH
#define FB_GLYPH_WIDTH UINT32_C(8)
#endif
#ifndef FB_GLYPH_HEIGHT
#define FB_GLYPH_HEIGHT UINT32_C(8)
#endif

/* Glyph geometry follows the mode the firmware gave us; fb_init() sets these
   from the display width. */
extern uint32_t g_glyph_x_scale;
extern uint32_t g_glyph_y_scale;
extern uint32_t g_glyph_advance;
#define FB_GLYPH_X_SCALE g_glyph_x_scale
#define FB_GLYPH_Y_SCALE g_glyph_y_scale
#define FB_GLYPH_ADVANCE g_glyph_advance

typedef struct boot_framebuffer {
  volatile uint32_t *pixels;
  uint32_t width;
  uint32_t height;
  uint32_t stride;
  uint32_t format;
} boot_framebuffer_t;

extern boot_framebuffer_t g_framebuffer;

/* The ASCII face, defined once in boot_ui.c beside the extra glyph table. */
extern const uint8_t g_font[UINT32_C(96)][FB_GLYPH_HEIGHT];
const uint8_t *fb_extra_rows(uint32_t code_point);

uint32_t fb_color(uint8_t red, uint8_t green, uint8_t blue);
void fb_mark_dirty(uint32_t x, uint32_t y, uint32_t width, uint32_t height);
void fb_rect(uint32_t x, uint32_t y, uint32_t width, uint32_t height,
             uint32_t color);
void fb_glyph_rows(uint32_t x, uint32_t y, const uint8_t *glyph,
                   uint32_t color);

/* Whether a region drawn since the last present is still waiting for one. */
uint32_t fb_dirty_pending(void);
void fb_present(void);
void fb_init(const xaios_boot_info_t *boot);
void fb_draw_status(uint32_t percent, const char *loaded, const char *loading,
                    uint32_t remaining);
void fb_draw_ready(const xaios_boot_ui_control_t *control);

/* The serial console's half of the same picture. */
void write_text(const char *text);
void write_uint(uint32_t value);
void write_int(int32_t value);
void write_brand_inline(void);
void write_brand(void);
void write_bar(uint32_t percent);

/* ---- Framebuffer text terminal ----
   The terminal's state is private to boot_ui_term.c except where boot_ui.c
   activates it; the declarations below are that narrow surface. */
#ifndef TERM_MARGIN_X
#define TERM_MARGIN_X UINT32_C(8)
#endif
#ifndef TERM_MARGIN_Y
#define TERM_MARGIN_Y UINT32_C(8)
#endif
#define TERM_LINE_HEIGHT (FB_GLYPH_HEIGHT * FB_GLYPH_Y_SCALE + UINT32_C(2))
#define TERM_TAB_WIDTH UINT32_C(8)
#define TERM_ESC_IDLE UINT32_C(0)
#define TERM_ESC_SAW_ESC UINT32_C(1)
#define TERM_ESC_CSI UINT32_C(2)
#define TERM_CSI_PARAM_MAX UINT32_C(8)

/* What each cell shows, so a write that changes nothing draws nothing.
 *
 * A full-screen program redraws its whole frame several times a second, and
 * most of a frame is the frame before it. Drawing every cell anyway -- six
 * thousand glyphs and their backgrounds, then a present -- was most of what
 * the process monitor cost this machine, charged to sshd, which is where the
 * console's bytes come from. With the cells remembered, a frame costs the
 * cells that changed. A cell the cursor has been drawn or erased in is
 * forgotten, because the cursor paints over the glyph's last rows. */
typedef struct term_cell {
  uint32_t code_point;
  uint32_t fg;
  uint32_t bg;
} term_cell_t;
#define TERM_CELL_UNKNOWN UINT32_C(0xffffffff)

extern uint32_t g_term_active;
extern uint32_t g_term_columns;
extern uint32_t g_term_rows;
extern uint32_t g_term_column;
extern uint32_t g_term_row;
extern uint32_t g_term_color;
extern uint32_t g_term_esc_state;
extern uint32_t g_term_param_count;
extern uint32_t g_term_cursor_drawn;
extern term_cell_t *g_term_cells;
extern uint32_t g_term_cell_count;

uint32_t term_default_background(void);
uint32_t term_foreground(void);
uint32_t term_background(void);
void term_cells_reset(uint32_t background);
void term_putc(uint8_t value);
void term_erase_cursor(void);
void term_draw_cursor(void);

#endif /* XAIOS_KERNEL_CORE_BOOT_UI_INTERNAL_H */
