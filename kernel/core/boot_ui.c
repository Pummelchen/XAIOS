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
/* 0x20 through 0x7f: printable ASCII, upper and lower case.
 *
 * This stopped at 0x5f and folded lowercase onto uppercase, which was fine
 * while the only thing it drew was a boot progress screen in capitals. It is
 * not fine now: a terminal application is read here, and one that renders
 * "Tasks" as "TASKS" locally and "Tasks" over SSH is two different programs
 * wearing the same name. */
static const uint8_t g_font[UINT32_C(96)][FB_GLYPH_HEIGHT] = {
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
static const uint8_t *fb_extra_rows(uint32_t code_point) {
  for (uint32_t i = 0U; i < FB_EXTRA_GLYPHS; ++i) {
    if (g_font_extra[i].code_point == code_point) {
      return g_font_extra[i].rows;
    }
  }
  return 0;
}


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
  unsigned char byte = (unsigned char)value;
  if (byte < 0x20U || byte > 0x7fU) return 0U;
  return (uint32_t)byte - 0x20U;
}

/* Draw one cell from an explicit row pattern, whichever table it came from. */
static void fb_glyph_rows(uint32_t x, uint32_t y, const uint8_t *glyph,
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

static uint32_t term_default_background(void) { return fb_color(4U, 6U, 10U); }
static uint32_t term_foreground(void) { return fb_color(222U, 230U, 236U); }

/* The background the terminal is currently painting with.
 *
 * This used to be a function returning one fixed colour, and the escape
 * parser below understood foreground codes only. The consequence was that the
 * panic screen -- which asks for white on cyan and is called the cyan screen
 * of death in its own banner -- came out as white on the ordinary background
 * on any machine with a framebuffer, which is every local console on x86-64
 * and on Fusion. It was cyan over a serial line and nowhere else, and the two
 * consoles disagreeing about what a crash looks like is worth more than the
 * few lines it takes to fix. */
/* A UTF-8 sequence in progress.
 *
 * The terminal used to drop every byte outside printable ASCII, which meant a
 * program drawing a box left gaps where its borders should be and the local
 * console showed a different picture from the one an SSH client showed of the
 * same program. Sequences are gathered here and looked up by code point; one
 * this font has no glyph for is drawn as a light shade rather than as
 * nothing, so a hole in the font reads as a hole and not as a space. */
static uint32_t g_term_utf8_code;
static uint32_t g_term_utf8_remaining;

static uint32_t g_term_bg_set;
static uint32_t g_term_bg;

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
static term_cell_t *g_term_cells;
static uint32_t g_term_cell_count;

static term_cell_t *term_cell(uint32_t column, uint32_t row) {
  if (g_term_cells == 0 || column >= g_term_columns || row >= g_term_rows) {
    return 0;
  }
  return &g_term_cells[row * g_term_columns + column];
}

static void term_cell_forget(uint32_t column, uint32_t row) {
  term_cell_t *cell = term_cell(column, row);
  if (cell != 0) cell->code_point = TERM_CELL_UNKNOWN;
}

static void term_cells_reset(uint32_t background) {
  for (uint32_t i = 0U; i < g_term_cell_count; ++i) {
    g_term_cells[i].code_point = (uint32_t)' ';
    g_term_cells[i].fg = 0U;
    g_term_cells[i].bg = background;
  }
}

static uint32_t term_background(void) {
  return g_term_bg_set != 0U ? g_term_bg : term_default_background();
}

/* Background codes, in the same order as the foreground ones above. */
static uint32_t term_sgr_background(uint32_t code) {
  switch (code) {
    case 40U: case 100U: return fb_color(12U, 14U, 18U);
    case 41U: case 101U: return fb_color(150U, 40U, 35U);
    case 42U: case 102U: return fb_color(30U, 120U, 60U);
    case 43U: case 103U: return fb_color(150U, 120U, 40U);
    case 44U: case 104U: return fb_color(35U, 60U, 160U);
    case 45U: case 105U: return fb_color(120U, 40U, 140U);
    case 46U: case 106U: return fb_color(0U, 150U, 165U);
    case 47U: case 107U: return fb_color(190U, 196U, 202U);
    default: return term_default_background();
  }
}

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

/* The xterm 256-colour palette: eight standard shades, eight bright ones, a
   six by six by six cube, and a grey ramp. A program that names a shade by
   index gets the same shade on this console that it gets in an SSH client,
   which is the whole point of having the table. */
static uint32_t term_sgr_indexed(uint32_t index) {
  static const uint8_t cube[6] = {0U, 95U, 135U, 175U, 215U, 255U};
  if (index < 8U) return term_sgr_color(30U + index);
  if (index < 16U) return term_sgr_color(90U + (index - 8U));
  if (index < 232U) {
    uint32_t value = index - 16U;
    return fb_color(cube[(value / 36U) % 6U], cube[(value / 6U) % 6U],
                    cube[value % 6U]);
  }
  if (index < 256U) {
    uint32_t grey = 8U + (index - 232U) * 10U;
    return fb_color(grey, grey, grey);
  }
  return term_foreground();
}

/* Read one extended colour -- 38;5;<index>, 48;5;<index>, or the 2;<r>;<g>;<b>
 * spelling -- starting at the parameter after the 38 or 48. Returns the number
 * of parameters consumed, or zero if the sequence is malformed.
 *
 * Reading these one parameter at a time is not a harmless simplification. The
 * process monitor asks for foreground 45 as 38;5;45, and a parser that walks
 * the list looking at each number on its own sees the 45 and sets a magenta
 * *background*: the whole display came out on a purple field, which is not
 * what any SSH client shows for the same bytes. */
static uint32_t term_sgr_extended(uint32_t first, uint32_t count,
                                  uint32_t *color) {
  if (count >= 2U && g_term_params[first] == 5U) {
    *color = term_sgr_indexed(g_term_params[first + 1U]);
    return 2U;
  }
  if (count >= 4U && g_term_params[first] == 2U) {
    uint32_t red = g_term_params[first + 1U];
    uint32_t green = g_term_params[first + 2U];
    uint32_t blue = g_term_params[first + 3U];
    if (red > 255U) red = 255U;
    if (green > 255U) green = 255U;
    if (blue > 255U) blue = 255U;
    *color = fb_color(red, green, blue);
    return 4U;
  }
  return 0U;
}

static uint32_t term_x(uint32_t column) {
  return TERM_MARGIN_X + column * FB_GLYPH_ADVANCE;
}

static uint32_t term_y(uint32_t row) {
  return TERM_MARGIN_Y + row * TERM_LINE_HEIGHT;
}

static void term_erase_cursor(void) {
  if (g_term_cursor_drawn == 0U) return;
  term_cell_forget(g_term_column, g_term_row);
  fb_rect(term_x(g_term_column), term_y(g_term_row) + FB_GLYPH_HEIGHT *
              FB_GLYPH_Y_SCALE - UINT32_C(2),
          FB_GLYPH_WIDTH, UINT32_C(2), term_background());
  g_term_cursor_drawn = 0U;
}

static void term_draw_cursor(void) {
  if (g_term_active == 0U || g_term_cursor_drawn != 0U) return;
  term_cell_forget(g_term_column, g_term_row);
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
  if (g_term_cells != 0 && g_term_rows > 1U) {
    for (uint32_t row = 1U; row < g_term_rows; ++row) {
      for (uint32_t column = 0U; column < g_term_columns; ++column) {
        g_term_cells[(row - 1U) * g_term_columns + column] =
            g_term_cells[row * g_term_columns + column];
      }
    }
    for (uint32_t column = 0U; column < g_term_columns; ++column) {
      term_cell_t *cell = &g_term_cells[(g_term_rows - 1U) * g_term_columns + column];
      cell->code_point = (uint32_t)' ';
      cell->fg = 0U;
      cell->bg = term_background();
    }
  }
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
        g_term_bg_set = 0U;
      } else if ((code >= 30U && code <= 37U) || (code >= 90U && code <= 97U)) {
        g_term_color = term_sgr_color(code);
      } else if ((code >= 40U && code <= 47U) ||
                 (code >= 100U && code <= 107U)) {
        g_term_bg = term_sgr_background(code);
        g_term_bg_set = 1U;
      } else if (code == 38U || code == 48U) {
        uint32_t color = term_foreground();
        uint32_t consumed = term_sgr_extended(
            i + 1U, g_term_param_count - i - 1U, &color);
        /* A sequence that does not parse is not a licence to keep reading:
           the numbers after it belong to the colour, not to the terminal. */
        if (consumed == 0U) break;
        if (code == 38U) {
          g_term_color = color;
        } else {
          g_term_bg = color;
          g_term_bg_set = 1U;
        }
        i += consumed;
      } else if (code == 39U) {
        g_term_color = term_foreground();
      } else if (code == 49U) {
        g_term_bg_set = 0U;
      }
    }
    return;
  }
  if (final == 'J') {
    fb_rect(0U, 0U, g_framebuffer.width, g_framebuffer.height,
            term_background());
    if (g_term_cells != 0) term_cells_reset(term_background());
    g_term_column = 0U;
    g_term_row = 0U;
    return;
  }
  if (final == 'H' || final == 'f') {
    /* Cursor position, row;column, one-based, with a missing or zero
       parameter meaning the first. This was "home" whatever the parameters
       said, because nothing on this machine positioned the cursor when it
       was written. The process monitor now sends only the cells that
       changed, each run positioned -- and a terminal that puts every run at
       the top-left showed one run, the last, and nothing else. */
    uint32_t row = g_term_param_count >= 1U && g_term_params[0] != 0U
                       ? g_term_params[0] - 1U : 0U;
    uint32_t column = g_term_param_count >= 2U && g_term_params[1] != 0U
                          ? g_term_params[1] - 1U : 0U;
    if (row >= g_term_rows) row = g_term_rows != 0U ? g_term_rows - 1U : 0U;
    if (column >= g_term_columns) {
      column = g_term_columns != 0U ? g_term_columns - 1U : 0U;
    }
    g_term_row = row;
    g_term_column = column;
  }
}

/* One character cell: clear it to the current background, then draw. */
static void term_put_code_point(uint32_t code_point) {
  const uint8_t *rows;
  if (code_point >= 0x20U && code_point <= 0x7fU) {
    rows = g_font[code_point - 0x20U];
  } else {
    rows = fb_extra_rows(code_point);
    /* Not a space: a glyph this font lacks should look like a gap in the
       font, which is a thing to fix, rather than like whitespace the program
       asked for, which is not. */
    if (rows == 0) rows = fb_extra_rows(0x2591U);
    if (rows == 0) return;
  }
  if (g_term_column >= g_term_columns) term_newline();
  term_cell_t *cell = term_cell(g_term_column, g_term_row);
  if (cell != 0 && cell->code_point == code_point &&
      cell->fg == g_term_color && cell->bg == term_background()) {
    /* Already showing exactly this. */
    ++g_term_column;
    return;
  }
  if (cell != 0) {
    cell->code_point = code_point;
    cell->fg = g_term_color;
    cell->bg = term_background();
  }
  fb_rect(term_x(g_term_column), term_y(g_term_row), FB_GLYPH_ADVANCE,
          TERM_LINE_HEIGHT, term_background());
  fb_glyph_rows(term_x(g_term_column), term_y(g_term_row), rows,
                g_term_color);
  /* A vertical rule has to reach the next row. Each row is the glyph plus a
     two-pixel gap beneath it, and a stroke that stops at the glyph's edge
     leaves a gap in every rule -- a box drawn on this console came out
     dashed where an SSH client drew it solid. The glyphs whose stroke
     reaches their bottom edge carry it on through the gap; the ones whose
     stroke starts at the top meet it there. */
  if (code_point == 0x2502U || code_point == 0x250cU ||
      code_point == 0x2510U) {
    fb_rect(term_x(g_term_column) + UINT32_C(3) * FB_GLYPH_X_SCALE,
            term_y(g_term_row) + FB_GLYPH_HEIGHT * FB_GLYPH_Y_SCALE,
            FB_GLYPH_X_SCALE, UINT32_C(2), g_term_color);
  }
  ++g_term_column;
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
    term_cell_forget(g_term_column, g_term_row);
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
      term_cell_forget(g_term_column, g_term_row);
      ++g_term_column;
    }
    return;
  }
  /* A continuation byte, or the start of a sequence. */
  if ((value & 0xc0U) == 0x80U) {
    if (g_term_utf8_remaining == 0U) return; /* stray continuation */
    g_term_utf8_code = (g_term_utf8_code << 6) | (uint32_t)(value & 0x3fU);
    if (--g_term_utf8_remaining == 0U) {
      term_put_code_point(g_term_utf8_code);
    }
    return;
  }
  g_term_utf8_remaining = 0U;
  if ((value & 0xe0U) == 0xc0U) {
    g_term_utf8_code = (uint32_t)(value & 0x1fU);
    g_term_utf8_remaining = 1U;
    return;
  }
  if ((value & 0xf0U) == 0xe0U) {
    g_term_utf8_code = (uint32_t)(value & 0x0fU);
    g_term_utf8_remaining = 2U;
    return;
  }
  if ((value & 0xf8U) == 0xf0U) {
    g_term_utf8_code = (uint32_t)(value & 0x07U);
    g_term_utf8_remaining = 3U;
    return;
  }
  if (value < ' ' || value > '~') return;
  term_put_code_point((uint32_t)value);
}

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
  if (g_term_active == 0U || g_dirty.width == 0U) return;
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
