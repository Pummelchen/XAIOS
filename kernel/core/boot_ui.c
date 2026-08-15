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
#define FB_GLYPH_X_SCALE UINT32_C(1)
#define FB_GLYPH_Y_SCALE UINT32_C(2)
#define FB_GLYPH_ADVANCE UINT32_C(9)

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
  fb_rect(0U, 0U, g_framebuffer.width, g_framebuffer.height, fb_color(0U, 0U, 0U));
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
  if (control->stage == XAIOS_BOOT_UI_STAGE_SSH_LOADING) {
    fb_draw_status(95U, "IPv4 network configuration", "SSH server", 1U);
    return 1U;
  }
  if (control->stage == XAIOS_BOOT_UI_STAGE_SSH_READY) {
    fb_draw_status(100U, "system services", "complete", 0U);
    fb_draw_ready(control);
    return 1U;
  }
  if (control->stage == XAIOS_BOOT_UI_STAGE_SSH_FAILED) {
    boot_ui_error("sshd", control->status);
    return 1U;
  }
  return 0U;
}
