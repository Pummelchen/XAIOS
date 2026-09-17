#include <xaios/boot_ui.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/timer.h>
#include <xaios/network_stack.h>

#ifndef XAIOS_BOOT_TEST_APPS
#define XAIOS_BOOT_TEST_APPS 0
#endif
#ifndef XAIOS_BOOT_VERBOSE
#define XAIOS_BOOT_VERBOSE 0
#endif

#define FB_GLYPH_WIDTH UINT32_C(8)
#define FB_GLYPH_HEIGHT UINT32_C(8)

/* Public-domain 8x8 IBM VGA bitmap glyphs, adapted from Daniel Hepper's
 * font8x8 collection. Keep the post-UEFI display allocation-free. */
/* 0x20 through 0x7f: printable ASCII, upper and lower case.
 *
 * This stopped at 0x5f and folded lowercase onto uppercase, which was fine
 * while the only thing it drew was a boot progress screen in capitals. It is
 * not fine now: a terminal application is read here, and one that renders
 * "Tasks" as "TASKS" locally and "Tasks" over SSH is two different programs
 * wearing the same name. */
const uint8_t g_font[UINT32_C(96)][FB_GLYPH_HEIGHT] = {
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, /* space */
    {0x18, 0x3c, 0x3c, 0x18, 0x18, 0x00, 0x18, 0x00}, /* ! */
    {0x36, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, /* \" */
    {0x36, 0x36, 0x7f, 0x36, 0x7f, 0x36, 0x36, 0x00}, /* # */
    {0x0c, 0x3e, 0x03, 0x1e, 0x30, 0x1f, 0x0c, 0x00}, /* $ */
    {0x00, 0x63, 0x33, 0x18, 0x0c, 0x66, 0x63, 0x00}, /* % */
    {0x1c, 0x36, 0x1c, 0x6e, 0x3b, 0x33, 0x6e, 0x00}, /* & */
    {0x06, 0x06, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00}, /* ' */
    {0x18, 0x0c, 0x06, 0x06, 0x06, 0x0c, 0x18, 0x00}, /* ( */
    {0x06, 0x0c, 0x18, 0x18, 0x18, 0x0c, 0x06, 0x00}, /* ) */
    {0x00, 0x66, 0x3c, 0xff, 0x3c, 0x66, 0x00, 0x00}, /* * */
    {0x00, 0x0c, 0x0c, 0x3f, 0x0c, 0x0c, 0x00, 0x00}, /* + */
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x0c, 0x06}, /* , */
    {0x00, 0x00, 0x00, 0x3f, 0x00, 0x00, 0x00, 0x00}, /* - */
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x0c, 0x00}, /* . */
    {0x60, 0x30, 0x18, 0x0c, 0x06, 0x03, 0x01, 0x00}, /* / */
    {0x3e, 0x63, 0x73, 0x7b, 0x6f, 0x67, 0x3e, 0x00}, /* 0 */
    {0x0c, 0x0e, 0x0c, 0x0c, 0x0c, 0x0c, 0x3f, 0x00}, /* 1 */
    {0x1e, 0x33, 0x30, 0x1c, 0x06, 0x33, 0x3f, 0x00}, /* 2 */
    {0x1e, 0x33, 0x30, 0x1c, 0x30, 0x33, 0x1e, 0x00}, /* 3 */
    {0x38, 0x3c, 0x36, 0x33, 0x7f, 0x30, 0x78, 0x00}, /* 4 */
    {0x3f, 0x03, 0x1f, 0x30, 0x30, 0x33, 0x1e, 0x00}, /* 5 */
    {0x1c, 0x06, 0x03, 0x1f, 0x33, 0x33, 0x1e, 0x00}, /* 6 */
    {0x3f, 0x33, 0x30, 0x18, 0x0c, 0x0c, 0x0c, 0x00}, /* 7 */
    {0x1e, 0x33, 0x33, 0x1e, 0x33, 0x33, 0x1e, 0x00}, /* 8 */
    {0x1e, 0x33, 0x33, 0x3e, 0x30, 0x18, 0x0e, 0x00}, /* 9 */
    {0x00, 0x0c, 0x0c, 0x00, 0x00, 0x0c, 0x0c, 0x00}, /* : */
    {0x00, 0x0c, 0x0c, 0x00, 0x00, 0x0c, 0x0c, 0x06}, /* ; */
    {0x18, 0x0c, 0x06, 0x03, 0x06, 0x0c, 0x18, 0x00}, /* < */
    {0x00, 0x00, 0x3f, 0x00, 0x00, 0x3f, 0x00, 0x00}, /* = */
    {0x06, 0x0c, 0x18, 0x30, 0x18, 0x0c, 0x06, 0x00}, /* > */
    {0x1e, 0x33, 0x30, 0x18, 0x0c, 0x00, 0x0c, 0x00}, /* ? */
    {0x3e, 0x63, 0x7b, 0x7b, 0x7b, 0x03, 0x1e, 0x00}, /* @ */
    {0x0c, 0x1e, 0x33, 0x33, 0x3f, 0x33, 0x33, 0x00}, /* A */
    {0x3f, 0x66, 0x66, 0x3e, 0x66, 0x66, 0x3f, 0x00}, /* B */
    {0x3c, 0x66, 0x03, 0x03, 0x03, 0x66, 0x3c, 0x00}, /* C */
    {0x1f, 0x36, 0x66, 0x66, 0x66, 0x36, 0x1f, 0x00}, /* D */
    {0x7f, 0x46, 0x16, 0x1e, 0x16, 0x46, 0x7f, 0x00}, /* E */
    {0x7f, 0x46, 0x16, 0x1e, 0x16, 0x06, 0x0f, 0x00}, /* F */
    {0x3c, 0x66, 0x03, 0x03, 0x73, 0x66, 0x7c, 0x00}, /* G */
    {0x33, 0x33, 0x33, 0x3f, 0x33, 0x33, 0x33, 0x00}, /* H */
    {0x1e, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x1e, 0x00}, /* I */
    {0x78, 0x30, 0x30, 0x30, 0x33, 0x33, 0x1e, 0x00}, /* J */
    {0x67, 0x66, 0x36, 0x1e, 0x36, 0x66, 0x67, 0x00}, /* K */
    {0x0f, 0x06, 0x06, 0x06, 0x46, 0x66, 0x7f, 0x00}, /* L */
    {0x63, 0x77, 0x7f, 0x7f, 0x6b, 0x63, 0x63, 0x00}, /* M */
    {0x63, 0x67, 0x6f, 0x7b, 0x73, 0x63, 0x63, 0x00}, /* N */
    {0x1c, 0x36, 0x63, 0x63, 0x63, 0x36, 0x1c, 0x00}, /* O */
    {0x3f, 0x66, 0x66, 0x3e, 0x06, 0x06, 0x0f, 0x00}, /* P */
    {0x1e, 0x33, 0x33, 0x33, 0x3b, 0x1e, 0x38, 0x00}, /* Q */
    {0x3f, 0x66, 0x66, 0x3e, 0x36, 0x66, 0x67, 0x00}, /* R */
    {0x1e, 0x33, 0x07, 0x0e, 0x38, 0x33, 0x1e, 0x00}, /* S */
    {0x3f, 0x2d, 0x0c, 0x0c, 0x0c, 0x0c, 0x1e, 0x00}, /* T */
    {0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x3f, 0x00}, /* U */
    {0x33, 0x33, 0x33, 0x33, 0x33, 0x1e, 0x0c, 0x00}, /* V */
    {0x63, 0x63, 0x63, 0x6b, 0x7f, 0x77, 0x63, 0x00}, /* W */
    {0x63, 0x63, 0x36, 0x1c, 0x1c, 0x36, 0x63, 0x00}, /* X */
    {0x33, 0x33, 0x33, 0x1e, 0x0c, 0x0c, 0x1e, 0x00}, /* Y */
    {0x7f, 0x63, 0x31, 0x18, 0x4c, 0x66, 0x7f, 0x00}, /* Z */
    {0x1e, 0x06, 0x06, 0x06, 0x06, 0x06, 0x1e, 0x00}, /* [ */
    {0x03, 0x06, 0x0c, 0x18, 0x30, 0x60, 0x40, 0x00}, /* \\ */
    {0x1e, 0x18, 0x18, 0x18, 0x18, 0x18, 0x1e, 0x00}, /* ] */
    {0x08, 0x1c, 0x36, 0x63, 0x00, 0x00, 0x00, 0x00}, /* ^ */
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff}, /* _ */
     {0x0c, 0x0c, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00}, /* ` */
     {0x00, 0x00, 0x1e, 0x30, 0x3e, 0x33, 0x6e, 0x00}, /* a */
     {0x07, 0x06, 0x06, 0x3e, 0x66, 0x66, 0x3b, 0x00}, /* b */
     {0x00, 0x00, 0x1e, 0x33, 0x03, 0x33, 0x1e, 0x00}, /* c */
     {0x38, 0x30, 0x30, 0x3e, 0x33, 0x33, 0x6e, 0x00}, /* d */
     {0x00, 0x00, 0x1e, 0x33, 0x3f, 0x03, 0x1e, 0x00}, /* e */
     {0x1c, 0x36, 0x06, 0x0f, 0x06, 0x06, 0x0f, 0x00}, /* f */
     {0x00, 0x00, 0x6e, 0x33, 0x33, 0x3e, 0x30, 0x1f}, /* g */
     {0x07, 0x06, 0x36, 0x6e, 0x66, 0x66, 0x67, 0x00}, /* h */
     {0x0c, 0x00, 0x0e, 0x0c, 0x0c, 0x0c, 0x1e, 0x00}, /* i */
     {0x30, 0x00, 0x30, 0x30, 0x30, 0x33, 0x33, 0x1e}, /* j */
     {0x07, 0x06, 0x66, 0x36, 0x1e, 0x36, 0x67, 0x00}, /* k */
     {0x0e, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x1e, 0x00}, /* l */
     {0x00, 0x00, 0x33, 0x7f, 0x7f, 0x6b, 0x63, 0x00}, /* m */
     {0x00, 0x00, 0x1f, 0x33, 0x33, 0x33, 0x33, 0x00}, /* n */
     {0x00, 0x00, 0x1e, 0x33, 0x33, 0x33, 0x1e, 0x00}, /* o */
     {0x00, 0x00, 0x3b, 0x66, 0x66, 0x3e, 0x06, 0x0f}, /* p */
     {0x00, 0x00, 0x6e, 0x33, 0x33, 0x3e, 0x30, 0x78}, /* q */
     {0x00, 0x00, 0x3b, 0x6e, 0x66, 0x06, 0x0f, 0x00}, /* r */
     {0x00, 0x00, 0x3e, 0x03, 0x1e, 0x30, 0x1f, 0x00}, /* s */
     {0x08, 0x0c, 0x3e, 0x0c, 0x0c, 0x2c, 0x18, 0x00}, /* t */
     {0x00, 0x00, 0x33, 0x33, 0x33, 0x33, 0x6e, 0x00}, /* u */
     {0x00, 0x00, 0x33, 0x33, 0x33, 0x1e, 0x0c, 0x00}, /* v */
     {0x00, 0x00, 0x63, 0x6b, 0x7f, 0x7f, 0x36, 0x00}, /* w */
     {0x00, 0x00, 0x63, 0x36, 0x1c, 0x36, 0x63, 0x00}, /* x */
     {0x00, 0x00, 0x33, 0x33, 0x33, 0x3e, 0x30, 0x1f}, /* y */
     {0x00, 0x00, 0x3f, 0x19, 0x0c, 0x26, 0x3f, 0x00}, /* z */
     {0x38, 0x0c, 0x0c, 0x07, 0x0c, 0x0c, 0x38, 0x00}, /* { */
     {0x18, 0x18, 0x18, 0x00, 0x18, 0x18, 0x18, 0x00}, /* | */
     {0x07, 0x0c, 0x0c, 0x38, 0x0c, 0x0c, 0x07, 0x00}, /* } */
     {0x6e, 0x3b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, /* ~ */
     {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, /* 0x7f */
};

/* The glyphs a panelled terminal application draws its borders and gauges
 * with.
 *
 * Beside the ASCII table rather than in it, because they are not ASCII: each
 * arrives as a multi-byte UTF-8 sequence and is found by code point. The line
 * pieces all meet at column three and row three, so a corner joins a rule
 * without leaving a gap. */
typedef struct fb_extra_glyph {
  uint32_t code_point;
  uint8_t rows[FB_GLYPH_HEIGHT];
} fb_extra_glyph_t;

static const fb_extra_glyph_t g_font_extra[] = {
    {0x2500U, {0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00}},
    {0x2502U, {0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08}},
    {0x250cU, {0x00, 0x00, 0x00, 0xf8, 0x08, 0x08, 0x08, 0x08}},
    {0x2510U, {0x00, 0x00, 0x00, 0x0f, 0x08, 0x08, 0x08, 0x08}},
    {0x2514U, {0x08, 0x08, 0x08, 0xf8, 0x00, 0x00, 0x00, 0x00}},
    {0x2518U, {0x08, 0x08, 0x08, 0x0f, 0x00, 0x00, 0x00, 0x00}},
    {0x2588U, {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
    {0x2591U, {0x88, 0x22, 0x88, 0x22, 0x88, 0x22, 0x88, 0x22}},
    {0x2592U, {0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa}},
    {0x2014U, {0x00, 0x00, 0x00, 0x7e, 0x00, 0x00, 0x00, 0x00}},
    /* Arrows, for the process monitor's scroll hint. Bit 0 is the left
       column, so 0x10 is the fourth from the left. */
    {0x2191U, {0x10, 0x38, 0x54, 0x10, 0x10, 0x10, 0x10, 0x00}},
    {0x2193U, {0x10, 0x10, 0x10, 0x10, 0x54, 0x38, 0x10, 0x00}},
    /* Lower blocks in eighths, for bar charts: row 7 is the bottom, so a
       one-eighth block lights that row alone. */
    {0x2581U, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff}},
    {0x2582U, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff}},
    {0x2583U, {0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff}},
    {0x2584U, {0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff}},
    {0x2585U, {0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff}},
    {0x2586U, {0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
    {0x2587U, {0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
};

#define FB_EXTRA_GLYPHS (sizeof(g_font_extra) / sizeof(g_font_extra[0]))

/* The row pattern for a code point, or null when this font has none. */
const uint8_t *fb_extra_rows(uint32_t code_point) {
  for (uint32_t i = 0U; i < FB_EXTRA_GLYPHS; ++i) {
    if (g_font_extra[i].code_point == code_point) {
      return g_font_extra[i].rows;
    }
  }
  return 0;
}

/* The terminal's margins, read out of this file by
   tests/scripts/qemu-console-xtop-gate.py along with the font geometry. The
   terminal engine carries the same guarded values; these are the ones the code
   in this translation unit uses, and the gate catches the two drifting. */
#define TERM_MARGIN_X UINT32_C(8)
#define TERM_MARGIN_Y UINT32_C(8)

/* The framebuffer primitives and the terminal engine live in boot_ui_render.c
   and boot_ui_term.c beside this file. Their interface is included here, after
   the font tables and the geometry constants this file owns, so that what the
   console gate reads out of this file is what the code here compiles. */
#include "boot_ui_internal.h"

static void term_activate(const xaios_boot_ui_control_t *control) {
  if (g_framebuffer.pixels == 0 || g_term_active != 0U) return;
  g_term_columns =
      (g_framebuffer.width - 2U * TERM_MARGIN_X) / FB_GLYPH_ADVANCE;
  g_term_rows = (g_framebuffer.height - 2U * TERM_MARGIN_Y) / TERM_LINE_HEIGHT;
  if (g_term_columns == 0U || g_term_rows == 0U) return;
  if (g_term_columns > UINT32_C(512)) g_term_columns = UINT32_C(512);
  g_term_cell_count = g_term_columns * g_term_rows;
  g_term_cells = (term_cell_t *)kheap_calloc(
      (uint64_t)g_term_cell_count * sizeof(term_cell_t), 16U);
  if (g_term_cells == 0) {
    /* Without the memory, every write draws, as it always did. */
    g_term_cell_count = 0U;
  } else {
    term_cells_reset(term_default_background());
  }
  fb_rect(0U, 0U, g_framebuffer.width, g_framebuffer.height, term_background());
  g_term_column = 0U;
  g_term_row = 0U;
  g_term_color = term_foreground();
  g_term_esc_state = TERM_ESC_IDLE;
  g_term_param_count = 0U;
  g_term_cursor_drawn = 0U;
  g_term_active = 1U;
  klog("boot-ui: framebuffer terminal active %ux%u cells\n", g_term_columns,
       g_term_rows);

  /* The login banner was written to the console before this display existed,
     so reproduce the reachability summary and the prompt for the state the
     console is actually in. */
  boot_ui_console_text("\x1b[1;35mXAI\x1b[0m \x1b[1;36mOS\x1b[0m\n\n");
  if (control != 0 && control->ipv4 != 0U) {
    boot_ui_console_text("IPv4: ");
    uint32_t address = control->ipv4;
    for (uint32_t i = 0U; i < 4U; ++i) {
      uint32_t octet = (address >> (24U - 8U * i)) & UINT32_C(0xff);
      char digits[4];
      uint32_t count = 0U;
      do {
        digits[count++] = (char)('0' + octet % 10U);
        octet /= 10U;
      } while (octet != 0U);
      while (count != 0U) term_putc((uint8_t)digits[--count]);
      if (i != 3U) term_putc((uint8_t)'.');
    }
    boot_ui_console_text("\n");
  }
  {
    /* The graphical panel reports the IPv6 address too, and a machine with no
       framebuffer should not be the only one left guessing. */
    xaios_ip_addr_t console_ipv6;
    if (network_stack_local_ipv6(&console_ipv6) == XAIOS_OK) {
      static const char hex_digits[] = "0123456789abcdef";
      boot_ui_console_text("IPv6: ");
      for (uint32_t group = 0U; group < 8U; ++group) {
        uint32_t value = ((uint32_t)console_ipv6.addr[group * 2U] << 8U) |
                         (uint32_t)console_ipv6.addr[group * 2U + 1U];
        term_putc((uint8_t)hex_digits[(value >> 12U) & 0xFU]);
        term_putc((uint8_t)hex_digits[(value >> 8U) & 0xFU]);
        term_putc((uint8_t)hex_digits[(value >> 4U) & 0xFU]);
        term_putc((uint8_t)hex_digits[value & 0xFU]);
        if (group != 7U) term_putc((uint8_t)':');
      }
      boot_ui_console_text("\n");
    }
  }
  boot_ui_console_text("SSH server: up and running (tcp/22)\n\n");
  if (control != 0 && control->console_state == XAIOS_BOOT_UI_CONSOLE_PASSWORD) {
    boot_ui_console_text("Password: ");
  } else if (control != 0 &&
             control->console_state == XAIOS_BOOT_UI_CONSOLE_SHELL) {
    boot_ui_console_text("admin@xaios:/$ ");
  } else if (control == 0 ||
             control->console_state != XAIOS_BOOT_UI_CONSOLE_LOCKED) {
    boot_ui_console_text("xaios login: ");
  } else {
    boot_ui_console_text("Local console locked: use SSH public-key access.\n");
  }
}

/* How often the terminal hands its drawing to the display.
 *
 * Every console write used to end with a present of the dirty rectangle,
 * and a screen-sized frame arrives in four-kilobyte writes: six transfers of
 * most of the screen per frame, each a synchronous round trip to the device,
 * all inside the single thread that also serves SSH. On the slower emulated
 * machines that was most of a second per frame, and an SSH session starved.
 * Writes still draw at once; the present is made at most once per sixteen
 * milliseconds -- a frame at sixty a second -- except for a short write,
 * which is someone typing and wants its echo now. Whatever is left dirty is
 * presented by boot_ui_present_pending, called from the console-read syscall
 * the console's owner polls continuously. */
#define TERM_PRESENT_INTERVAL_NS UINT64_C(16000000)
#define TERM_PRESENT_NOW_BYTES UINT64_C(256)
static uint64_t g_term_last_present_ns;

static void term_present(uint64_t now_ns) {
  fb_present();
  g_term_last_present_ns = now_ns;
}

void boot_ui_present_pending(void) {
  if (g_term_active == 0U || fb_dirty_pending() == 0U) return;
  uint64_t now_ns = timer_now_ns();
  if (now_ns - g_term_last_present_ns >= TERM_PRESENT_INTERVAL_NS) {
    term_present(now_ns);
  }
}

void boot_ui_console_write(const char *text, uint64_t length) {
  if (g_term_active == 0U || text == 0) return;
  term_erase_cursor();
  for (uint64_t i = 0U; i < length; ++i) term_putc((uint8_t)text[i]);
  term_draw_cursor();
  uint64_t now_ns = timer_now_ns();
  if (length < TERM_PRESENT_NOW_BYTES ||
      now_ns - g_term_last_present_ns >= TERM_PRESENT_INTERVAL_NS) {
    term_present(now_ns);
  }
}

void boot_ui_console_text(const char *text) {
  if (text == 0) return;
  uint64_t length = 0U;
  while (text[length] != '\0') ++length;
  if (g_term_active == 0U) return;
  for (uint64_t i = 0U; i < length; ++i) term_putc((uint8_t)text[i]);
}

void boot_ui_begin(const xaios_boot_info_t *boot) {
  fb_init(boot);
#if XAIOS_BOOT_TEST_APPS || XAIOS_BOOT_VERBOSE
  write_brand();
  write_text("boot-ui: XAI OS\n");
#else
  klog_console_set_log_output(0U);
  write_text("\x1b[2J\x1b[H");
  write_brand();
#endif
}

void boot_ui_update(uint32_t percent, const char *loaded,
                    const char *loading, uint32_t remaining) {
  if (percent > 100U) percent = 100U;
  fb_draw_status(percent, loaded, loading, remaining);
  fb_present();
#if XAIOS_BOOT_TEST_APPS || XAIOS_BOOT_VERBOSE
  write_text("boot-ui: progress=");
  write_uint(percent);
  write_text(" loaded=");
  write_text(loaded);
  write_text(" loading=");
  write_text(loading);
  write_text(" remaining=");
  write_uint(remaining);
  write_text("\n");
  /* After the machine-readable line, never instead of it: gates match that
     line exactly, and a bar drawn into the middle of it would break every
     one of them while looking like a cosmetic change. */
  write_brand_inline();
  write_text(" ");
  write_bar(percent);
  write_text("\n");
#else
  write_text("\x1b[H\x1b[J");
  write_brand();
  write_bar(percent);
  write_text("\n\nLoaded: ");
  write_text(loaded);
  write_text("\nLoading: ");
  write_text(loading);
  write_text("\nRemaining: ");
  write_uint(remaining);
  write_text(" components\n");
#endif
}

void boot_ui_error(const char *component, int32_t status) {
  klog_console_set_log_output(1U);
  write_text("\n\x1b[1;31mBOOT ERROR\x1b[0m component=");
  write_text(component);
  write_text(" code=");
  write_int(status);
  write_text("\n");
}

/* What the console can tell a program about its own shape.
 *
 * A terminal application has to lay itself out against a width, and the local
 * console used to have none to offer: the shell handed every program a fixed
 * eighty by twenty-four. On a serial line that is the right guess, because
 * there is nothing to measure. On a framebuffer it is simply wrong -- the
 * screen is a hundred and forty cells wide -- and a process monitor drew
 * itself into the left half of the display with its rightmost columns cut
 * off, which is not the picture the same program gives over SSH. */
void boot_ui_terminal_size(uint32_t *columns, uint32_t *rows) {
  uint32_t width = g_term_active != 0U ? g_term_columns : 0U;
  uint32_t height = g_term_active != 0U ? g_term_rows : 0U;
  if (columns != 0) *columns = width;
  if (rows != 0) *rows = height;
}

uint32_t boot_ui_handle_control(const xaios_boot_ui_control_t *control) {
  if (control == 0 || control->magic != XAIOS_BOOT_UI_CONTROL_MAGIC ||
      control->version != XAIOS_BOOT_UI_CONTROL_VERSION) {
    return 0U;
  }
  /* Every branch below draws, so every branch below has to present. Drawing
     changes the buffer and nothing else: until the dirty region is handed to
     the device, a viewer sees the frame before it. `boot_ui_update` has
     always done both, and this function did only the first half -- so the
     kernel's last `boot_ui_update(90, ...)` was the last thing to reach the
     screen. Everything after it, which is the whole end of boot, was drawn
     into a buffer nobody sent: 95%, 100%, the ready summary with the machine's
     addresses, and the handover to the terminal. A machine sitting at a login
     prompt showed a progress bar stopped at 90% for as long as it was left
     there. It was invisible from the console side, because the serial log
     reported every one of those stages. */
  if (control->stage == XAIOS_BOOT_UI_STAGE_SSH_LOADING) {
    fb_draw_status(95U, "IPv4 network configuration", "SSH server", 1U);
    fb_present();
    return 1U;
  }
  if (control->stage == XAIOS_BOOT_UI_STAGE_SSH_READY) {
    if (g_term_active == 0U) {
      fb_draw_status(100U, "system services", "complete", 0U);
      fb_draw_ready(control);
      /* Boot is finished, so hand the display over to a real terminal. From
         here the framebuffer mirrors the console instead of summarising it. */
      term_activate(control);
      fb_present();
      return 1U;
    }
    /* In terminal mode the control record only drives the cursor; the text
       itself arrives through the console stream. */
    if (control->cursor_visible != 0U) {
      term_draw_cursor();
    } else {
      term_erase_cursor();
    }
    fb_present();
    return 1U;
  }
  if (control->stage == XAIOS_BOOT_UI_STAGE_SSH_FAILED) {
    boot_ui_error("sshd", control->status);
    return 1U;
  }
  return 0U;
}
