#include <xaios/boot_ui.h>
#include <xaios/klog.h>
#include <xaios/network_stack.h>

#ifndef XAIOS_BOOT_TEST_APPS
#define XAIOS_BOOT_TEST_APPS 0
#endif
#ifndef XAIOS_BOOT_VERBOSE
#define XAIOS_BOOT_VERBOSE 0
#endif

#define BOOT_BAR_WIDTH UINT32_C(40)
#define FB_MARGIN UINT32_C(48)
#define FB_BAR_MAX_WIDTH UINT32_C(720)
#define FB_GLYPH_WIDTH UINT32_C(8)
#define FB_GLYPH_HEIGHT UINT32_C(8)
/* Glyph geometry follows the mode the firmware gave us. The bitmap font is
   8x8, so a fixed 1x2 scale that reads well at 1024x768 turns into unreadable
   specks once the loader selects a 1920x1200 mode. Scale with the display so
   text keeps roughly the same physical size instead. */
static uint32_t g_glyph_x_scale = UINT32_C(1);
static uint32_t g_glyph_y_scale = UINT32_C(2);
static uint32_t g_glyph_advance = UINT32_C(9);
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

static boot_framebuffer_t g_framebuffer;

/* Public-domain 8x8 IBM VGA bitmap glyphs, adapted from Daniel Hepper's
 * font8x8 collection. Keep the post-UEFI display allocation-free. */
static const uint8_t g_font[UINT32_C(64)][FB_GLYPH_HEIGHT] = {
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
};

static uint64_t text_length(const char *text) {
  uint64_t length = 0U;
  if (text == 0) return 0U;
  while (text[length] != '\0') ++length;
  return length;
}

static void write_text(const char *text) {
  klog_console_write(text, text_length(text));
}

static void write_uint(uint32_t value) {
  char digits[10];
  uint32_t count = 0U;
  if (value == 0U) {
    write_text("0");
    return;
  }
  while (value != 0U && count < sizeof(digits)) {
    digits[count++] = (char)('0' + (value % 10U));
    value /= 10U;
  }
  while (count != 0U) {
    --count;
    klog_console_write(&digits[count], 1U);
  }
}

static void write_int(int32_t value) {
  uint32_t magnitude;
  if (value < 0) {
    write_text("-");
    magnitude = (uint32_t)(-(value + 1)) + 1U;
  } else {
    magnitude = (uint32_t)value;
  }
  write_uint(magnitude);
}

static uint32_t fb_color(uint8_t red, uint8_t green, uint8_t blue) {
  if (g_framebuffer.format == XAIOS_FRAMEBUFFER_BGRX8) {
    return ((uint32_t)red << 16U) | ((uint32_t)green << 8U) | blue;
  }
  return ((uint32_t)blue << 16U) | ((uint32_t)green << 8U) | red;
}

/* Which part of the buffer has been drawn on since it was last made visible.
   A device that copies on demand has to be told what to copy, and telling it
   "all of it" costs a transfer of the whole screen for a one-glyph change: at
   1280x800 that is 4 MiB pushed to redraw a cursor. Held as a bounding box
   rather than a list of rectangles, because console output is one or two
   regions at a time and a box costs four words to track.

   Empty is width == 0, which is why the box is not initialised to the whole
   screen: a present with nothing drawn should do nothing at all. */
static struct {
  uint32_t x;
  uint32_t y;
  uint32_t width;
  uint32_t height;
} g_dirty;

static void fb_mark_dirty(uint32_t x, uint32_t y, uint32_t width,
                          uint32_t height) {
  if (width == 0U || height == 0U) return;
  if (g_dirty.width == 0U) {
    g_dirty.x = x;
    g_dirty.y = y;
    g_dirty.width = width;
    g_dirty.height = height;
    return;
  }
  uint32_t right = g_dirty.x + g_dirty.width;
  uint32_t bottom = g_dirty.y + g_dirty.height;
  if (x + width > right) right = x + width;
  if (y + height > bottom) bottom = y + height;
  if (x < g_dirty.x) g_dirty.x = x;
  if (y < g_dirty.y) g_dirty.y = y;
  g_dirty.width = right - g_dirty.x;
  g_dirty.height = bottom - g_dirty.y;
}

static void fb_rect(uint32_t x, uint32_t y, uint32_t width, uint32_t height,
                    uint32_t color) {
  if (g_framebuffer.pixels == 0 || x >= g_framebuffer.width ||
      y >= g_framebuffer.height) return;
  if (width > g_framebuffer.width - x) width = g_framebuffer.width - x;
  if (height > g_framebuffer.height - y) height = g_framebuffer.height - y;
  for (uint32_t row = 0U; row < height; ++row) {
    volatile uint32_t *pixel =
        &g_framebuffer.pixels[(uint64_t)(y + row) * g_framebuffer.stride + x];
    for (uint32_t column = 0U; column < width; ++column) pixel[column] = color;
  }
  /* Marked here rather than at each caller: every drawing primitive in this
     file reaches the buffer through this function, so one mark covers them
     all and none can be forgotten. The exception is term_scroll, which moves
     pixels rather than painting them and marks its own region. */
  fb_mark_dirty(x, y, width, height);
}

static uint32_t glyph_index(char value) {
  if (value >= 'a' && value <= 'z') value = (char)(value - ('a' - 'A'));
  if (value < ' ' || value > '_') return 0U;
  return (uint32_t)(value - ' ');
}

static void fb_glyph(uint32_t x, uint32_t y, char value, uint32_t color) {
  const uint8_t *glyph = g_font[glyph_index(value)];
  for (uint32_t row = 0U; row < FB_GLYPH_HEIGHT; ++row) {
    for (uint32_t column = 0U; column < FB_GLYPH_WIDTH; ++column) {
      if ((glyph[row] & (UINT8_C(1) << column)) != 0U) {
        fb_rect(x + column * FB_GLYPH_X_SCALE, y + row * FB_GLYPH_Y_SCALE,
                FB_GLYPH_X_SCALE, FB_GLYPH_Y_SCALE, color);
      }
    }
  }
}

static void fb_text(uint32_t x, uint32_t y, const char *text, uint32_t color) {
  if (text == 0) return;
  while (*text != '\0' && x + FB_GLYPH_WIDTH < g_framebuffer.width) {
    fb_glyph(x, y, *text++, color);
    x += FB_GLYPH_ADVANCE;
  }
}

static void fb_uint(uint32_t x, uint32_t y, uint32_t value, uint32_t color) {
  char digits[10];
  uint32_t count = 0U;
  if (value == 0U) {
    fb_glyph(x, y, '0', color);
    return;
  }
  while (value != 0U && count < sizeof(digits)) {
    digits[count++] = (char)('0' + value % 10U);
    value /= 10U;
  }
  while (count != 0U) {
    --count;
    fb_glyph(x, y, digits[count], color);
    x += FB_GLYPH_ADVANCE;
  }
}

static uint32_t fb_uint_width(uint32_t value) {
  if (value < 10U) return 1U;
  if (value < 100U) return 2U;
  return 3U;
}

static void fb_ipv4(uint32_t x, uint32_t y, uint32_t address, uint32_t color) {
  for (uint32_t octet = 0U; octet < 4U; ++octet) {
    uint32_t value = (address >> (24U - octet * 8U)) & UINT32_C(0xff);
    fb_uint(x, y, value, color);
    x += fb_uint_width(value) * FB_GLYPH_ADVANCE;
    if (octet != 3U) {
      fb_glyph(x, y, '.', color);
      x += FB_GLYPH_ADVANCE;
    }
  }
}

static void fb_hex4(uint32_t x, uint32_t y, uint16_t value, uint32_t color) {
  for (uint32_t shift = 12U;; shift -= 4U) {
    uint32_t digit = (value >> shift) & UINT16_C(0xf);
    fb_glyph(x, y, digit < 10U ? (char)('0' + digit)
                                : (char)('A' + digit - 10U), color);
    x += FB_GLYPH_ADVANCE;
    if (shift == 0U) return;
  }
}

static void fb_ipv6(uint32_t x, uint32_t y, const xaios_ip_addr_t *address,
                    uint32_t color) {
  if (address == 0 || address->family != XAIOS_IP_FAMILY_V6) return;
  for (uint32_t group = 0U; group < 8U; ++group) {
    uint16_t value = (uint16_t)((uint16_t)address->addr[group * 2U] << 8U) |
                     address->addr[group * 2U + 1U];
    fb_hex4(x, y, value, color);
    x += 4U * FB_GLYPH_ADVANCE;
    if (group != 7U) {
      fb_glyph(x, y, ':', color);
      x += FB_GLYPH_ADVANCE;
    }
  }
}

/* Whether anything has been drawn over the display's initial contents yet. */
static uint32_t g_status_painted;

static void fb_draw_status(uint32_t percent, const char *loaded,
                           const char *loading, uint32_t remaining) {
  if (g_framebuffer.pixels == 0) return;
  const uint32_t white = fb_color(220U, 220U, 220U);
  const uint32_t cyan = fb_color(0U, 220U, 230U);
  const uint32_t purple = fb_color(210U, 0U, 220U);
  const uint32_t green = fb_color(50U, 210U, 100U);
  const uint32_t dim = fb_color(110U, 110U, 110U);
  const uint32_t margin = g_framebuffer.width > FB_MARGIN * 2U ? FB_MARGIN : 8U;
  uint32_t bar_width = g_framebuffer.width - margin * 2U;
  if (bar_width > FB_BAR_MAX_WIDTH) bar_width = FB_BAR_MAX_WIDTH;
  const uint32_t bar_y = margin + 28U;
  /* The first draw clears the whole screen, because whatever the display held
     before the kernel claimed it is not ours. After that only the band the
     status occupies is repainted: clearing the rest each time would dirty the
     entire framebuffer and force a full-screen transfer to the device for a
     progress bar that moves a few pixels. Nothing else draws here during
     boot, so the band is the whole of what changes. */
  uint32_t band = bar_y + 88U + FB_GLYPH_HEIGHT * FB_GLYPH_Y_SCALE + 4U;
  if (band > g_framebuffer.height || g_status_painted == 0U) {
    band = g_framebuffer.height;
  }
  g_status_painted = 1U;
  fb_rect(0U, 0U, g_framebuffer.width, band, fb_color(0U, 0U, 0U));
  fb_text(margin, margin, "XAI", purple);
  fb_text(margin + 36U, margin, "OS", cyan);
  fb_rect(margin, bar_y, bar_width, 10U, dim);
  fb_rect(margin, bar_y, (bar_width * percent) / 100U, 10U, green);
  fb_uint(margin, bar_y + 20U, percent, white);
  fb_text(margin + 36U, bar_y + 20U, "PERCENT", white);
  fb_text(margin, bar_y + 44U, "LOADED:", cyan);
  fb_text(margin + 72U, bar_y + 44U, loaded, white);
  fb_text(margin, bar_y + 66U, "LOADING:", cyan);
  fb_text(margin + 81U, bar_y + 66U, loading, white);
  fb_text(margin, bar_y + 88U, "REMAINING:", cyan);
  fb_uint(margin + 99U, bar_y + 88U, remaining, white);
  fb_text(margin + 144U, bar_y + 88U, "COMPONENTS", white);
}

static void fb_draw_ready(const xaios_boot_ui_control_t *control) {
  const uint32_t cyan = fb_color(0U, 220U, 230U);
  const uint32_t green = fb_color(50U, 210U, 100U);
  const uint32_t white = fb_color(220U, 220U, 220U);
  const uint32_t margin = g_framebuffer.width > FB_MARGIN * 2U ? FB_MARGIN : 8U;
  const uint32_t base_y = margin + 142U;
  xaios_ip_addr_t public_ipv6;
  uint32_t prompt_y = base_y + 72U;
  fb_text(margin, base_y, "IPV4:", cyan);
  fb_ipv4(margin + 54U, base_y, control->ipv4, white);
  if (network_stack_local_public_ipv6(&public_ipv6) == XAIOS_OK) {
    fb_text(margin, base_y + 24U, "PUBLIC IPV6:", cyan);
    fb_ipv6(margin + 117U, base_y + 24U, &public_ipv6, white);
    fb_text(margin, base_y + 48U, "SSH SERVER: UP TCP/22", green);
    prompt_y = base_y + 96U;
  } else {
    fb_text(margin, base_y + 24U, "SSH SERVER: UP TCP/22", green);
  }
  /* Reserve one full terminal row after SSH readiness before the prompt. */
  if (control->console_state == XAIOS_BOOT_UI_CONSOLE_LOGIN) {
    fb_text(margin, prompt_y, "XAIOS LOGIN:", cyan);
  } else if (control->console_state == XAIOS_BOOT_UI_CONSOLE_PASSWORD) {
    fb_text(margin, prompt_y, "PASSWORD:", cyan);
  } else if (control->console_state == XAIOS_BOOT_UI_CONSOLE_SHELL) {
    fb_text(margin, prompt_y, "ADMIN@XAIOS:/$", green);
  } else {
    fb_text(margin, prompt_y, "LOCAL LOGIN: KEY ONLY", white);
  }
  if (control->console_state != XAIOS_BOOT_UI_CONSOLE_LOCKED &&
      control->cursor_visible != 0U) {
    uint32_t cursor_x = margin;
    if (control->console_state == XAIOS_BOOT_UI_CONSOLE_LOGIN) {
      cursor_x += UINT32_C(13) * FB_GLYPH_ADVANCE;
    } else if (control->console_state == XAIOS_BOOT_UI_CONSOLE_PASSWORD) {
      cursor_x += UINT32_C(9) * FB_GLYPH_ADVANCE;
    } else {
      cursor_x += UINT32_C(15) * FB_GLYPH_ADVANCE;
    }
    fb_glyph(cursor_x, prompt_y, '_', white);
  }
}

/* ---- Framebuffer text terminal ----
   After boot the display stops being a status panel and becomes a terminal
   that mirrors the console byte stream, so a machine with no serial cable --
   VMware Fusion in particular -- offers the same session as a QEMU serial
   console: prompt, echoed input, and command output. */
#define TERM_MARGIN_X UINT32_C(8)
#define TERM_MARGIN_Y UINT32_C(8)
#define TERM_LINE_HEIGHT (FB_GLYPH_HEIGHT * FB_GLYPH_Y_SCALE + UINT32_C(2))
#define TERM_TAB_WIDTH UINT32_C(8)
#define TERM_ESC_IDLE UINT32_C(0)
#define TERM_ESC_SAW_ESC UINT32_C(1)
#define TERM_ESC_CSI UINT32_C(2)
#define TERM_CSI_PARAM_MAX UINT32_C(8)

static uint32_t g_term_active;
static void term_putc(uint8_t value);
static uint32_t g_term_columns;
static uint32_t g_term_rows;
static uint32_t g_term_column;
static uint32_t g_term_row;
static uint32_t g_term_color;
static uint32_t g_term_esc_state;
static uint32_t g_term_params[TERM_CSI_PARAM_MAX];
static uint32_t g_term_param_count;
static uint32_t g_term_cursor_drawn;

static uint32_t term_background(void) { return fb_color(4U, 6U, 10U); }
static uint32_t term_foreground(void) { return fb_color(222U, 230U, 236U); }

static uint32_t term_sgr_color(uint32_t code) {
  switch (code) {
    case 30U: case 90U: return fb_color(90U, 100U, 110U);
    case 31U: case 91U: return fb_color(235U, 110U, 100U);
    case 32U: case 92U: return fb_color(120U, 210U, 140U);
    case 33U: case 93U: return fb_color(226U, 190U, 110U);
    case 34U: case 94U: return fb_color(120U, 165U, 235U);
    case 35U: case 95U: return fb_color(200U, 140U, 225U);
    case 36U: case 96U: return fb_color(110U, 200U, 210U);
    default: return term_foreground();
  }
}

static uint32_t term_x(uint32_t column) {
  return TERM_MARGIN_X + column * FB_GLYPH_ADVANCE;
}

static uint32_t term_y(uint32_t row) {
  return TERM_MARGIN_Y + row * TERM_LINE_HEIGHT;
}

static void term_erase_cursor(void) {
  if (g_term_cursor_drawn == 0U) return;
  fb_rect(term_x(g_term_column), term_y(g_term_row) + FB_GLYPH_HEIGHT *
              FB_GLYPH_Y_SCALE - UINT32_C(2),
          FB_GLYPH_WIDTH, UINT32_C(2), term_background());
  g_term_cursor_drawn = 0U;
}

static void term_draw_cursor(void) {
  if (g_term_active == 0U || g_term_cursor_drawn != 0U) return;
  fb_rect(term_x(g_term_column), term_y(g_term_row) + FB_GLYPH_HEIGHT *
              FB_GLYPH_Y_SCALE - UINT32_C(2),
          FB_GLYPH_WIDTH, UINT32_C(2), term_foreground());
  g_term_cursor_drawn = 1U;
}

static void term_scroll(void) {
  uint32_t shift = TERM_LINE_HEIGHT;
  if (g_framebuffer.pixels == 0 || shift >= g_framebuffer.height) return;
  uint64_t stride = g_framebuffer.stride;
  for (uint32_t y = TERM_MARGIN_Y; y + shift < g_framebuffer.height; ++y) {
    volatile uint32_t *destination = &g_framebuffer.pixels[(uint64_t)y * stride];
    volatile uint32_t *source =
        &g_framebuffer.pixels[(uint64_t)(y + shift) * stride];
    for (uint32_t x = 0U; x < g_framebuffer.width; ++x) destination[x] = source[x];
  }
  /* Everything from the top margin down moved, and the strip below is repainted
     by the fb_rect that follows, which marks itself. */
  fb_mark_dirty(0U, TERM_MARGIN_Y, g_framebuffer.width,
                g_framebuffer.height - TERM_MARGIN_Y);
  fb_rect(0U, g_framebuffer.height - shift, g_framebuffer.width, shift,
          term_background());
}

static void term_newline(void) {
  g_term_column = 0U;
  if (g_term_row + 1U < g_term_rows) {
    ++g_term_row;
    return;
  }
  term_scroll();
}

static void term_apply_csi(char final) {
  if (final == 'm') {
    if (g_term_param_count == 0U) {
      g_term_color = term_foreground();
      return;
    }
    for (uint32_t i = 0U; i < g_term_param_count; ++i) {
      uint32_t code = g_term_params[i];
      if (code == 0U) {
        g_term_color = term_foreground();
      } else if ((code >= 30U && code <= 37U) || (code >= 90U && code <= 97U)) {
        g_term_color = term_sgr_color(code);
      }
    }
    return;
  }
  if (final == 'J' || final == 'H') {
    /* Clear and home are the only cursor controls the shell emits that must
       affect this display; the remainder are ignored deliberately. */
    if (final == 'J') {
      fb_rect(0U, 0U, g_framebuffer.width, g_framebuffer.height,
              term_background());
    }
    g_term_column = 0U;
    g_term_row = 0U;
  }
}

static void term_putc(uint8_t value) {
  if (g_term_esc_state == TERM_ESC_SAW_ESC) {
    if (value == '[') {
      g_term_esc_state = TERM_ESC_CSI;
      g_term_param_count = 0U;
      g_term_params[0] = 0U;
    } else {
      g_term_esc_state = TERM_ESC_IDLE;
    }
    return;
  }
  if (g_term_esc_state == TERM_ESC_CSI) {
    if (value >= '0' && value <= '9') {
      if (g_term_param_count == 0U) g_term_param_count = 1U;
      uint32_t *slot = &g_term_params[g_term_param_count - 1U];
      if (*slot < UINT32_C(100000)) *slot = *slot * 10U + (uint32_t)(value - '0');
      return;
    }
    if (value == ';') {
      if (g_term_param_count < TERM_CSI_PARAM_MAX) {
        g_term_params[g_term_param_count++] = 0U;
      }
      return;
    }
    if (value == '?' || value == ':') return;
    term_apply_csi((char)value);
    g_term_esc_state = TERM_ESC_IDLE;
    return;
  }
  if (value == UINT8_C(0x1b)) {
    g_term_esc_state = TERM_ESC_SAW_ESC;
    return;
  }
  if (value == '\n') {
    term_newline();
    return;
  }
  if (value == '\r') {
    g_term_column = 0U;
    return;
  }
  if (value == '\b') {
    if (g_term_column != 0U) --g_term_column;
    fb_rect(term_x(g_term_column), term_y(g_term_row), FB_GLYPH_ADVANCE,
            TERM_LINE_HEIGHT, term_background());
    return;
  }
  if (value == '\t') {
    uint32_t next = (g_term_column / TERM_TAB_WIDTH + 1U) * TERM_TAB_WIDTH;
    while (g_term_column < next) {
      if (g_term_column >= g_term_columns) {
        term_newline();
        break;
      }
      fb_rect(term_x(g_term_column), term_y(g_term_row), FB_GLYPH_ADVANCE,
              TERM_LINE_HEIGHT, term_background());
      ++g_term_column;
    }
    return;
  }
  if (value < ' ' || value > '~') return;
  if (g_term_column >= g_term_columns) term_newline();
  fb_rect(term_x(g_term_column), term_y(g_term_row), FB_GLYPH_ADVANCE,
          TERM_LINE_HEIGHT, term_background());
  fb_glyph(term_x(g_term_column), term_y(g_term_row), (char)value, g_term_color);
  ++g_term_column;
}

static void term_activate(const xaios_boot_ui_control_t *control) {
  if (g_framebuffer.pixels == 0 || g_term_active != 0U) return;
  g_term_columns =
      (g_framebuffer.width - 2U * TERM_MARGIN_X) / FB_GLYPH_ADVANCE;
  g_term_rows = (g_framebuffer.height - 2U * TERM_MARGIN_Y) / TERM_LINE_HEIGHT;
  if (g_term_columns == 0U || g_term_rows == 0U) return;
  if (g_term_columns > UINT32_C(512)) g_term_columns = UINT32_C(512);
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
  boot_ui_console_text("XAI OS\n\n");
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

/* Render a known glyph into a scratch cell and read the pixels back, so the
   display path is proven on the machine that actually has a framebuffer
   rather than assumed from the code. */
void boot_ui_self_test(void) {
  if (g_framebuffer.pixels == 0) {
    klog("boot-ui: no framebuffer; terminal renders to serial only\n");
    return;
  }
  uint32_t foreground = fb_color(255U, 255U, 255U);
  uint32_t background = fb_color(0U, 0U, 0U);
  uint32_t width = FB_GLYPH_WIDTH * FB_GLYPH_X_SCALE;
  uint32_t height = FB_GLYPH_HEIGHT * FB_GLYPH_Y_SCALE;
  uint32_t origin_x = g_framebuffer.width - width;
  uint32_t origin_y = g_framebuffer.height - height;

  fb_rect(origin_x, origin_y, width, height, background);
  fb_glyph(origin_x, origin_y, 'A', foreground);
  uint32_t lit = 0U;
  for (uint32_t row = 0U; row < height; ++row) {
    volatile uint32_t *pixel =
        &g_framebuffer.pixels[(uint64_t)(origin_y + row) * g_framebuffer.stride +
                              origin_x];
    for (uint32_t column = 0U; column < width; ++column) {
      if ((pixel[column] & UINT32_C(0x00ffffff)) ==
          (foreground & UINT32_C(0x00ffffff))) {
        ++lit;
      }
    }
  }
  fb_rect(origin_x, origin_y, width, height, background);
  klog("boot-ui: framebuffer %ux%u glyph readback lit=%u %s\n",
       g_framebuffer.width, g_framebuffer.height, lit,
       lit != 0U ? "passed" : "FAILED");
}

uint32_t boot_ui_has_framebuffer(void) {
  return g_framebuffer.pixels != 0 ? 1U : 0U;
}

/* Adopt a framebuffer discovered after the loader handed off. fb_init() only
   ever saw what firmware published, which on a platform reporting PixelBltOnly
   is nothing; a virtio-GPU scanout is the same thing arriving later. */
/* How to make what was drawn visible, for a device that copies on demand
   rather than scanning memory continuously. Held as a callback so this file
   stays independent of which device supplied the buffer. */
static xaios_status_t (*g_present)(uint32_t x, uint32_t y, uint32_t width,
                                   uint32_t height);

void boot_ui_adopt_framebuffer(uint32_t *pixels, uint32_t width,
                               uint32_t height,
                               xaios_status_t (*present)(uint32_t x, uint32_t y,
                                                         uint32_t width,
                                                         uint32_t height)) {
  if (pixels == 0 || width == 0U || height == 0U) return;
  g_present = present;
  g_framebuffer.pixels = (volatile uint32_t *)pixels;
  g_framebuffer.width = width;
  g_framebuffer.height = height;
  g_framebuffer.stride = width;
  g_framebuffer.format = XAIOS_FRAMEBUFFER_BGRX8;
  klog("boot-ui: adopted a %ux%u framebuffer from the display device\n", width,
       height);
}

/* Drawing into the buffer changes nothing a viewer can see until this runs.
   Only the region drawn since the last call is sent, and a call with nothing
   drawn does not reach the device at all. */
static void fb_present(void) {
  if (g_present == 0 || g_dirty.width == 0U) return;
  (void)g_present(g_dirty.x, g_dirty.y, g_dirty.width, g_dirty.height);
  g_dirty.width = 0U;
  g_dirty.height = 0U;
}

void boot_ui_console_write(const char *text, uint64_t length) {
  if (g_term_active == 0U || text == 0) return;
  term_erase_cursor();
  for (uint64_t i = 0U; i < length; ++i) term_putc((uint8_t)text[i]);
  term_draw_cursor();
  fb_present();
}

void boot_ui_console_text(const char *text) {
  if (text == 0) return;
  uint64_t length = 0U;
  while (text[length] != '\0') ++length;
  if (g_term_active == 0U) return;
  for (uint64_t i = 0U; i < length; ++i) term_putc((uint8_t)text[i]);
}

static void fb_init(const xaios_boot_info_t *boot) {
  if (boot == 0 || boot->framebuffer_base == 0U ||
      boot->framebuffer_format == XAIOS_FRAMEBUFFER_NONE ||
      boot->framebuffer_width == 0U || boot->framebuffer_height == 0U ||
      boot->framebuffer_pixels_per_scan_line < boot->framebuffer_width ||
      (boot->framebuffer_format != XAIOS_FRAMEBUFFER_RGBX8 &&
       boot->framebuffer_format != XAIOS_FRAMEBUFFER_BGRX8)) return;
  uint64_t pixels = (uint64_t)boot->framebuffer_pixels_per_scan_line *
                    boot->framebuffer_height;
  if (pixels > UINT64_MAX / 4U || pixels * 4U > boot->framebuffer_size) return;
  g_framebuffer.pixels = (volatile uint32_t *)(uintptr_t)boot->framebuffer_base;
  g_framebuffer.width = boot->framebuffer_width;
  g_framebuffer.height = boot->framebuffer_height;
  g_framebuffer.stride = boot->framebuffer_pixels_per_scan_line;
  g_framebuffer.format = boot->framebuffer_format;

  /* Roughly 100-160 columns at any supported width. */
  uint32_t scale = g_framebuffer.width / UINT32_C(1024);
  if (scale == 0U) scale = 1U;
  if (scale > 3U) scale = 3U;
  g_glyph_x_scale = scale;
  g_glyph_y_scale = scale * 2U;
  g_glyph_advance = (FB_GLYPH_WIDTH + 1U) * scale;
}

#if !XAIOS_BOOT_TEST_APPS && !XAIOS_BOOT_VERBOSE
static void write_brand(void) {
  write_text("\x1b[1;35mXAI\x1b[0m \x1b[1;36mOS\x1b[0m\n\n");
}
#endif

void boot_ui_begin(const xaios_boot_info_t *boot) {
  fb_init(boot);
#if XAIOS_BOOT_TEST_APPS || XAIOS_BOOT_VERBOSE
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
#else
  write_text("\x1b[H\x1b[J");
  write_brand();
  write_text("[");
  uint32_t filled = (percent * BOOT_BAR_WIDTH) / 100U;
  for (uint32_t i = 0U; i < BOOT_BAR_WIDTH; ++i) write_text(i < filled ? "#" : ".");
  write_text("] ");
  write_uint(percent);
  write_text("%\n\nLoaded: ");
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
