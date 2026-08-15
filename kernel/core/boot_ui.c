#include <xaios/boot_ui.h>
#include <xaios/klog.h>

#ifndef XAIOS_BOOT_TEST_APPS
#define XAIOS_BOOT_TEST_APPS 0
#endif
#ifndef XAIOS_BOOT_VERBOSE
#define XAIOS_BOOT_VERBOSE 0
#endif

#define BOOT_BAR_WIDTH UINT32_C(40)
#define FB_MARGIN UINT32_C(64)
#define FB_SCALE UINT32_C(3)
#define FB_GLYPH_WIDTH UINT32_C(5)
#define FB_GLYPH_HEIGHT UINT32_C(7)

typedef struct boot_framebuffer {
  volatile uint32_t *pixels;
  uint32_t width;
  uint32_t height;
  uint32_t stride;
  uint32_t format;
} boot_framebuffer_t;

static boot_framebuffer_t g_framebuffer;

/* 5x7 uppercase display font. Keep the post-UEFI boot UI allocation-free. */
static const uint8_t g_font[][FB_GLYPH_HEIGHT] = {
    {0, 0, 0, 0, 0, 0, 0},             /* space */
    {14, 17, 17, 31, 17, 17, 17},       /* A */
    {30, 17, 17, 30, 17, 17, 30},       /* B */
    {15, 16, 16, 16, 16, 16, 15},       /* C */
    {30, 17, 17, 17, 17, 17, 30},       /* D */
    {31, 16, 16, 30, 16, 16, 31},       /* E */
    {31, 16, 16, 30, 16, 16, 16},       /* F */
    {15, 16, 16, 23, 17, 17, 15},       /* G */
    {17, 17, 17, 31, 17, 17, 17},       /* H */
    {31, 4, 4, 4, 4, 4, 31},            /* I */
    {1, 1, 1, 1, 17, 17, 14},           /* J */
    {17, 18, 20, 24, 20, 18, 17},       /* K */
    {16, 16, 16, 16, 16, 16, 31},       /* L */
    {17, 27, 21, 21, 17, 17, 17},       /* M */
    {17, 25, 21, 19, 17, 17, 17},       /* N */
    {14, 17, 17, 17, 17, 17, 14},       /* O */
    {30, 17, 17, 30, 16, 16, 16},       /* P */
    {14, 17, 17, 17, 21, 18, 13},       /* Q */
    {30, 17, 17, 30, 20, 18, 17},       /* R */
    {15, 16, 16, 14, 1, 1, 30},         /* S */
    {31, 4, 4, 4, 4, 4, 4},             /* T */
    {17, 17, 17, 17, 17, 17, 14},       /* U */
    {17, 17, 17, 17, 17, 10, 4},        /* V */
    {17, 17, 17, 21, 21, 21, 10},       /* W */
    {17, 17, 10, 4, 10, 17, 17},        /* X */
    {17, 17, 10, 4, 4, 4, 4},           /* Y */
    {31, 1, 2, 4, 8, 16, 31},           /* Z */
    {14, 17, 19, 21, 25, 17, 14},       /* 0 */
    {4, 12, 4, 4, 4, 4, 14},            /* 1 */
    {14, 17, 1, 2, 4, 8, 31},           /* 2 */
    {30, 1, 1, 14, 1, 1, 30},           /* 3 */
    {2, 6, 10, 18, 31, 2, 2},           /* 4 */
    {31, 16, 16, 30, 1, 1, 30},         /* 5 */
    {14, 16, 16, 30, 17, 17, 14},       /* 6 */
    {31, 1, 2, 4, 8, 8, 8},             /* 7 */
    {14, 17, 17, 14, 17, 17, 14},       /* 8 */
    {14, 17, 17, 15, 1, 1, 14},         /* 9 */
    {0, 4, 0, 0, 4, 0, 0},              /* : */
    {0, 0, 0, 31, 0, 0, 0},             /* - */
    {17, 2, 4, 8, 16, 0, 0},            /* / */
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
  if (value >= 'A' && value <= 'Z') return 1U + (uint32_t)(value - 'A');
  if (value >= '0' && value <= '9') return 27U + (uint32_t)(value - '0');
  if (value == ':') return 37U;
  if (value == '-') return 38U;
  if (value == '/') return 39U;
  return 0U;
}

static void fb_glyph(uint32_t x, uint32_t y, char value, uint32_t scale,
                     uint32_t color) {
  const uint8_t *glyph = g_font[glyph_index(value)];
  for (uint32_t row = 0U; row < FB_GLYPH_HEIGHT; ++row) {
    for (uint32_t column = 0U; column < FB_GLYPH_WIDTH; ++column) {
      if ((glyph[row] & (UINT8_C(1) << (FB_GLYPH_WIDTH - 1U - column))) != 0U) {
        fb_rect(x + column * scale, y + row * scale, scale, scale, color);
      }
    }
  }
}

static void fb_text(uint32_t x, uint32_t y, const char *text, uint32_t scale,
                    uint32_t color) {
  if (text == 0) return;
  const uint32_t advance = (FB_GLYPH_WIDTH + 1U) * scale;
  while (*text != '\0' && x + FB_GLYPH_WIDTH * scale < g_framebuffer.width) {
    fb_glyph(x, y, *text++, scale, color);
    x += advance;
  }
}

static void fb_uint(uint32_t x, uint32_t y, uint32_t value, uint32_t scale,
                    uint32_t color) {
  char digits[10];
  uint32_t count = 0U;
  if (value == 0U) {
    fb_glyph(x, y, '0', scale, color);
    return;
  }
  while (value != 0U && count < sizeof(digits)) {
    digits[count++] = (char)('0' + value % 10U);
    value /= 10U;
  }
  while (count != 0U) {
    --count;
    fb_glyph(x, y, digits[count], scale, color);
    x += (FB_GLYPH_WIDTH + 1U) * scale;
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
  const uint32_t bar_width = g_framebuffer.width - margin * 2U;
  const uint32_t bar_y = margin + 80U;
  fb_rect(0U, 0U, g_framebuffer.width, g_framebuffer.height, fb_color(0U, 0U, 0U));
  fb_text(margin, margin, "XAI", FB_SCALE, purple);
  fb_text(margin + 18U * FB_SCALE, margin, "OS", FB_SCALE, cyan);
  fb_rect(margin, bar_y, bar_width, 24U, dim);
  fb_rect(margin, bar_y, (bar_width * percent) / 100U, 24U, green);
  fb_uint(margin, bar_y + 44U, percent, FB_SCALE, white);
  fb_text(margin + 24U * FB_SCALE, bar_y + 44U, "PERCENT", FB_SCALE, white);
  fb_text(margin, bar_y + 96U, "LOADED:", FB_SCALE, cyan);
  fb_text(margin + 48U * FB_SCALE, bar_y + 96U, loaded, FB_SCALE, white);
  fb_text(margin, bar_y + 132U, "LOADING:", FB_SCALE, cyan);
  fb_text(margin + 54U * FB_SCALE, bar_y + 132U, loading, FB_SCALE, white);
  fb_text(margin, bar_y + 168U, "REMAINING:", FB_SCALE, cyan);
  fb_uint(margin + 66U * FB_SCALE, bar_y + 168U, remaining, FB_SCALE, white);
  fb_text(margin + 84U * FB_SCALE, bar_y + 168U, "COMPONENTS", FB_SCALE, white);
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
    boot_ui_update(95U, "IPv4 network configuration", "SSH server", 1U);
    return 1U;
  }
  if (control->stage == XAIOS_BOOT_UI_STAGE_SSH_READY) {
    boot_ui_update(100U, "system services", "complete", 0U);
    return 1U;
  }
  if (control->stage == XAIOS_BOOT_UI_STAGE_SSH_FAILED) {
    boot_ui_error("sshd", control->status);
    return 1U;
  }
  return 0U;
}
