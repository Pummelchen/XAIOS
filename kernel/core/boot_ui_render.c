/* The boot UI's drawing: the framebuffer primitives and the status panel, the
 * readback self-test and present path, and the progress text the serial console
 * receives.
 *
 * The font tables stay in boot_ui.c because the console gate reads the geometry
 * out of that file; g_font and fb_extra_rows are declared in the private header
 * and defined once in boot_ui.c. The glyph scale is set by fb_init() from the
 * display the firmware gave us, so it is shared state here rather than a
 * constant.
 *
 * Nothing in this module prints a message of its own: every string below is
 * byte-identical to the one boot_ui.c used to print, which is what the boot
 * gates match.
 */
#include "boot_ui_internal.h"
#include <xaios/klog.h>

/* Glyph geometry follows the mode the firmware gave us. The bitmap font is
   8x8, so a fixed 1x2 scale that reads well at 1024x768 turns into unreadable
   specks once the loader selects a 1920x1200 mode. Scale with the display so
   text keeps roughly the same physical size instead. */
uint32_t g_glyph_x_scale = UINT32_C(1);
uint32_t g_glyph_y_scale = UINT32_C(2);
uint32_t g_glyph_advance = UINT32_C(9);

boot_framebuffer_t g_framebuffer;

static uint64_t text_length(const char *text) {
  uint64_t length = 0U;
  if (text == 0) return 0U;
  while (text[length] != '\0') ++length;
  return length;
}

void write_text(const char *text) {
  klog_console_write(text, text_length(text));
}

void write_uint(uint32_t value) {
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

void write_int(int32_t value) {
  uint32_t magnitude;
  if (value < 0) {
    write_text("-");
    magnitude = (uint32_t)(-(value + 1)) + 1U;
  } else {
    magnitude = (uint32_t)value;
  }
  write_uint(magnitude);
}

uint32_t fb_color(uint8_t red, uint8_t green, uint8_t blue) {
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

void fb_mark_dirty(uint32_t x, uint32_t y, uint32_t width,
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

void fb_rect(uint32_t x, uint32_t y, uint32_t width, uint32_t height,
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
  unsigned char byte = (unsigned char)value;
  if (byte < 0x20U || byte > 0x7fU) return 0U;
  return (uint32_t)byte - 0x20U;
}

/* Draw one cell from an explicit row pattern, whichever table it came from. */
void fb_glyph_rows(uint32_t x, uint32_t y, const uint8_t *glyph,
                   uint32_t color) {
  for (uint32_t row = 0U; row < FB_GLYPH_HEIGHT; ++row) {
    for (uint32_t column = 0U; column < FB_GLYPH_WIDTH; ++column) {
      if ((glyph[row] & (UINT8_C(1) << column)) != 0U) {
        fb_rect(x + column * FB_GLYPH_X_SCALE, y + row * FB_GLYPH_Y_SCALE,
                FB_GLYPH_X_SCALE, FB_GLYPH_Y_SCALE, color);
      }
    }
  }
}

static void fb_glyph(uint32_t x, uint32_t y, char value, uint32_t color) {
  fb_glyph_rows(x, y, g_font[glyph_index(value)], color);
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

void fb_draw_status(uint32_t percent, const char *loaded,
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

void fb_draw_ready(const xaios_boot_ui_control_t *control) {
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
void fb_present(void) {
  if (g_present == 0 || g_dirty.width == 0U) return;
  (void)g_present(g_dirty.x, g_dirty.y, g_dirty.width, g_dirty.height);
  g_dirty.width = 0U;
  g_dirty.height = 0U;
}

/* Whether a drawn region is still waiting to be sent. */
uint32_t fb_dirty_pending(void) {
  return g_dirty.width != 0U ? 1U : 0U;
}

void fb_init(const xaios_boot_info_t *boot) {
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

/* The name, in its colours. Not conditional on the build: a verbose kernel is
   still this operating system booting, and a machine that says "XAI OS" in
   plain grey on one configuration and in purple and cyan on another is two
   products as far as anyone looking at the screen is concerned. */
void write_brand_inline(void) {
  write_text("\x1b[1;35mXAI\x1b[0m \x1b[1;36mOS\x1b[0m");
}

void write_brand(void) {
  write_brand_inline();
  write_text("\n\n");
}

/* The bar, drawn where it is rather than by repainting the screen.
   The release console owns the whole display and redraws it; a verbose boot
   is interleaving kernel log lines that a person and several gates are
   reading, so the bar is one line among them and scrolls with them. */
void write_bar(uint32_t percent) {
  uint32_t filled = (percent * BOOT_BAR_WIDTH) / 100U;
  write_text("[\x1b[1;32m");
  for (uint32_t i = 0U; i < BOOT_BAR_WIDTH; ++i) {
    if (i == filled) write_text("\x1b[0m");
    write_text(i < filled ? "#" : ".");
  }
  if (filled >= BOOT_BAR_WIDTH) write_text("\x1b[0m");
  write_text("] ");
  write_uint(percent);
  write_text("%");
}
