/* Drawing primitives shared by xtop.c and xtop_draw.c: the screen grid, the
   cell-or-text canvas, the rules and panels, and their number formatters.
   Split out of xtop.c; see xtop_glyph.h for what crosses. */

#include <xaios_user.h>
#include <xaios_screen.h>
#include <xaios/types.h>
#include "xtop_serve.h"
#include "xtop_glyph.h"

uint64_t xtop_u64_digits(uint64_t value) {
  uint64_t digits = 1U;
  while (value >= 10U) {
    value /= 10U;
    ++digits;
  }
  return digits;
}

/* Terminal columns in a UTF-8 string: every byte that does not continue a
   sequence starts one glyph, and every glyph this program prints is one
   column wide. Measuring in bytes instead padded the title two columns short,
   because the em dash in it is three bytes. */
uint32_t xtop_columns(const char *text) {
  uint32_t columns = 0U;
  for (uint64_t i = 0U; text[i] != '\0'; ++i) {
    if (((uint8_t)text[i] & 0xc0U) != 0x80U) ++columns;
  }
  return columns;
}

/* The look is mactop's: a blue field, green rules with panel names set into
 * them, tall solid gauges with the figure centred, a green header bar over
 * the process list, and the keys in the bottom rule. Every line is padded to
 * the full width in the field colour, so nothing depends on what a terminal
 * does with an erase.
 *
 * UTF-8 for the rules and blocks, drawn identically by an SSH client and by
 * the local framebuffer console, which carries these glyphs and parses the
 * 256-colour escapes -- `make qemu-console-xtop-gate` reads the screen back
 * as pixels to hold it to that. Nothing here emits a bare reset: the reset
 * used everywhere re-asserts the field and text colours, or the blue would
 * have holes wherever an attribute ended. */
#define XTOP_BG "\033[48;5;68m"
#define XTOP_FG "\033[38;5;120m"
#define XTOP_RESET "\033[0;48;5;68;38;5;120m"
#define XTOP_TITLE "\033[1;97m"
#define XTOP_FILL_BG "\033[48;5;70m"
#define XTOP_HEADER "\033[48;5;70;30m"
#define XTOP_SELECTED "\033[48;5;70;30m"

#define XTOP_COLOR_FIELD UINT16_C(68)
#define XTOP_COLOR_TEXT UINT16_C(120)
#define XTOP_COLOR_FILL UINT16_C(70)
#define XTOP_COLOR_WHITE UINT16_C(15)
#define XTOP_COLOR_BLACK UINT16_C(0)
#define XTOP_COLOR_ALERT UINT16_C(9)
#define XTOP_COLOR_HOT UINT16_C(203)
#define XTOP_COLOR_WARM UINT16_C(215)
#define XTOP_COLOR_COOL UINT16_C(79)
#define XTOP_COLOR_EMPTY UINT16_C(75)
#define XTOP_COLOR_CHART UINT16_C(70)

/* The screen framework holds the grid and writes the difference between
   presents; see userspace/include/xaios_screen.h. */
static xaios_screen_cell_t g_screen_next[XAIOS_SCREEN_MAX_CELLS];
static xaios_screen_cell_t g_screen_shown[XAIOS_SCREEN_MAX_CELLS];
static xaios_screen_t g_screen;

/* The screen grid is the renderer's file-scope state; the serving
   session reaches it only through these, never as a pointer. */
void xtop_screen_open(uint32_t rows, uint32_t columns) {
  xaios_screen_init(&g_screen, g_screen_next, g_screen_shown,
                    XAIOS_SCREEN_MAX_CELLS, rows, columns);
  g_screen.cursor_hidden = 1U;
}

uint64_t xtop_screen_take_diff(char *out, uint64_t capacity) {
  return xaios_screen_present(&g_screen, out, capacity);
}

int xtop_screen_incomplete(void) { return g_screen.incomplete != 0U; }

void xtop_screen_invalidate(void) { xaios_screen_invalidate(&g_screen); }

void xtop_canvas_text_init(xtop_canvas_t *cv, char *text, uint64_t capacity,
                           uint64_t *used) {
  cv->screen = 0;
  cv->text = text;
  cv->capacity = capacity;
  cv->used = used;
  cv->fg = XTOP_COLOR_TEXT;
  cv->bg = XTOP_COLOR_FIELD;
  cv->bold = 0U;
  cv->row = 0U;
  cv->column = 0U;
}

void xtop_canvas_cells_init(xtop_canvas_t *cv) {
  cv->screen = &g_screen;
  cv->text = 0;
  cv->capacity = 0U;
  cv->used = 0;
  cv->fg = XTOP_COLOR_TEXT;
  cv->bg = XTOP_COLOR_FIELD;
  cv->bold = 0U;
  cv->row = 0U;
  cv->column = 0U;
}

void xtop_canvas_style(xtop_canvas_t *cv, xtop_style_t style) {
  const char *escape = "";
  switch (style) {
  case XTOP_STYLE_RESET:
    cv->fg = XTOP_COLOR_TEXT; cv->bg = XTOP_COLOR_FIELD; cv->bold = 0U;
    escape = XTOP_RESET; break;
  case XTOP_STYLE_FG:
    cv->fg = XTOP_COLOR_TEXT; escape = XTOP_FG; break;
  case XTOP_STYLE_TITLE:
    cv->fg = XTOP_COLOR_WHITE; cv->bold = 1U; escape = XTOP_TITLE; break;
  case XTOP_STYLE_FILL_BG:
    cv->bg = XTOP_COLOR_FILL; escape = XTOP_FILL_BG; break;
  case XTOP_STYLE_HEADER:
    cv->bg = XTOP_COLOR_FILL; cv->fg = XTOP_COLOR_BLACK; escape = XTOP_HEADER; break;
  case XTOP_STYLE_ALERT:
    cv->fg = XTOP_COLOR_ALERT; cv->bold = 1U; escape = "\033[1;91m"; break;
  case XTOP_STYLE_HOT:
    cv->fg = XTOP_COLOR_HOT; escape = "\033[38;5;203m"; break;
  case XTOP_STYLE_WARM:
    cv->fg = XTOP_COLOR_WARM; escape = "\033[38;5;215m"; break;
  case XTOP_STYLE_COOL:
    cv->fg = XTOP_COLOR_COOL; escape = "\033[38;5;79m"; break;
  case XTOP_STYLE_EMPTY:
    cv->fg = XTOP_COLOR_EMPTY; escape = "\033[38;5;75m"; break;
  case XTOP_STYLE_CHART:
    cv->fg = XTOP_COLOR_CHART; escape = "\033[38;5;70m"; break;
  default:
    break;
  }
  if (cv->text != 0) xtop_output_append(cv->text, cv->capacity, cv->used, escape);
}

void xtop_canvas_text(xtop_canvas_t *cv, const char *text) {
  if (cv->screen != 0) {
    if (cv->row < cv->screen->rows) {
      cv->column += xaios_screen_put(cv->screen, cv->row, cv->column, text,
                                     cv->fg, cv->bg, cv->bold);
    }
    return;
  }
  xtop_output_append(cv->text, cv->capacity, cv->used, text);
}

void xtop_canvas_char(xtop_canvas_t *cv, char value) {
  char one[2];
  one[0] = value;
  one[1] = '\0';
  xtop_canvas_text(cv, one);
}

static void canvas_u64(xtop_canvas_t *cv, uint64_t value) {
  char digits[24];
  uint64_t used = 0U;
  digits[0] = '\0';
  xtop_output_append_u64(digits, sizeof(digits), &used, value);
  xtop_canvas_text(cv, digits);
}

void xtop_canvas_repeat(xtop_canvas_t *cv, char value, uint32_t count) {
  for (uint32_t i = 0U; i < count; ++i) xtop_canvas_char(cv, value);
}

/* Repeat a string rather than a byte: a glyph here is three bytes wide and
   one column wide, and the layout arithmetic counts columns. */
void xtop_canvas_repeat_str(xtop_canvas_t *cv, const char *glyph,
                              uint32_t count) {
  for (uint32_t i = 0U; i < count; ++i) xtop_canvas_text(cv, glyph);
}

void xtop_canvas_newline(xtop_canvas_t *cv) {
  if (cv->screen != 0) {
    ++cv->row;
    cv->column = 0U;
    return;
  }
  xtop_output_append(cv->text, cv->capacity, cv->used, "\r\n");
}

/* Start a frame: the field colour everywhere, the cursor home and shown or
   hidden as asked. */
void xtop_canvas_begin(xtop_canvas_t *cv, int cursor_hidden) {
  xtop_canvas_style(cv, XTOP_STYLE_RESET);
  if (cv->screen != 0) {
    xaios_screen_clear(cv->screen, XTOP_COLOR_FIELD);
    cv->screen->cursor_hidden = cursor_hidden != 0 ? 1U : 0U;
    cv->row = 0U;
    cv->column = 0U;
    return;
  }
  xtop_output_append(cv->text, cv->capacity, cv->used, "\033[2J\033[H");
  xtop_output_append(cv->text, cv->capacity, cv->used,
                cursor_hidden != 0 ? "\033[?25l" : "\033[?25h");
}

void xtop_canvas_cursor(xtop_canvas_t *cv, int cursor_hidden) {
  if (cv->screen != 0) {
    cv->screen->cursor_hidden = cursor_hidden != 0 ? 1U : 0U;
    return;
  }
  xtop_output_append(cv->text, cv->capacity, cv->used,
                cursor_hidden != 0 ? "\033[?25l" : "\033[?25h");
}

/* Whether this many more bytes fit: always, into cells. */
int xtop_canvas_room(const xtop_canvas_t *cv, uint64_t bytes) {
  if (cv->screen != 0) return 1;
  return *cv->used < cv->capacity && bytes < cv->capacity - *cv->used;
}

void xtop_canvas_u64_width(xtop_canvas_t *cv, uint64_t value,
                             uint32_t width) {
  uint64_t digits = xtop_u64_digits(value);
  if (digits < width) xtop_canvas_repeat(cv, ' ', width - (uint32_t)digits);
  canvas_u64(cv, value);
}

void xtop_canvas_percent_width(xtop_canvas_t *cv, uint64_t tenths) {
  uint64_t whole = tenths / 10U;
  uint64_t digits = xtop_u64_digits(whole);
  if (digits < 3U) xtop_canvas_repeat(cv, ' ', 3U - (uint32_t)digits);
  canvas_u64(cv, whole);
  xtop_canvas_text(cv, ".");
  canvas_u64(cv, tenths % 10U);
  xtop_canvas_text(cv, "%");
}

/* At most `width` columns of a string. */
void xtop_canvas_bounded(xtop_canvas_t *cv, const char *text,
                           uint32_t width) {
  char glyph[8];
  uint32_t columns = 0U;
  uint64_t i = 0U;
  while (text[i] != '\0' && columns < width) {
    uint32_t n = 0U;
    glyph[n++] = text[i++];
    while (text[i] != '\0' && ((uint8_t)text[i] & 0xc0U) == 0x80U && n < 7U) {
      glyph[n++] = text[i++];
    }
    glyph[n] = '\0';
    xtop_canvas_text(cv, glyph);
    ++columns;
  }
}

void xtop_canvas_runtime(xtop_canvas_t *cv, uint64_t runtime_ns) {
  uint64_t seconds = runtime_ns / UINT64_C(1000000000);
  uint64_t hours = seconds / 3600U;
  uint64_t minutes = (seconds / 60U) % 60U;
  seconds %= 60U;
  xtop_canvas_u64_width(cv, hours, 2U);
  xtop_canvas_text(cv, ":");
  if (minutes < 10U) xtop_canvas_text(cv, "0");
  canvas_u64(cv, minutes);
  xtop_canvas_text(cv, ":");
  if (seconds < 10U) xtop_canvas_text(cv, "0");
  canvas_u64(cv, seconds);
}

static uint32_t canvas_uptime(xtop_canvas_t *cv, uint64_t now_ns) {
  uint64_t seconds = now_ns / UINT64_C(1000000000);
  uint64_t days = seconds / 86400U;
  uint64_t hours = (seconds / 3600U) % 24U;
  uint64_t minutes = (seconds / 60U) % 60U;
  seconds %= 60U;
  canvas_u64(cv, days);
  xtop_canvas_text(cv, " days, ");
  if (hours < 10U) xtop_canvas_text(cv, "0");
  canvas_u64(cv, hours);
  xtop_canvas_text(cv, ":");
  if (minutes < 10U) xtop_canvas_text(cv, "0");
  canvas_u64(cv, minutes);
  xtop_canvas_text(cv, ":");
  if (seconds < 10U) xtop_canvas_text(cv, "0");
  canvas_u64(cv, seconds);
  return (uint32_t)xtop_u64_digits(days) + 15U;
}

static void canvas_hundredths(xtop_canvas_t *cv, uint32_t value) {
  canvas_u64(cv, value / 100U);
  xtop_canvas_text(cv, ".");
  if (value % 100U < 10U) xtop_canvas_text(cv, "0");
  canvas_u64(cv, value % 100U);
}

/* A rule with an optional name set into it by the left corner and an
   optional note by the right: exactly `width` columns and no line ending, so
   two can share a screen row. */
void xtop_draw_rule(xtop_canvas_t *cv, const char *left_corner,
                    const char *right_corner, const char *title,
                    const char *note, uint32_t width) {
  if (width < 2U) return;
  uint32_t inner = width - 2U;
  uint32_t title_columns = title != 0 ? xtop_columns(title) + 3U : 0U;
  uint32_t note_columns = note != 0 ? xtop_columns(note) + 3U : 0U;
  if (title_columns + note_columns > inner) note_columns = 0U;
  if (title_columns > inner) title_columns = 0U;
  xtop_canvas_style(cv, XTOP_STYLE_RESET);
  xtop_canvas_text(cv, left_corner);
  if (title_columns != 0U) {
    xtop_canvas_text(cv, XTOP_BOX_H " ");
    xtop_canvas_style(cv, XTOP_STYLE_TITLE);
    xtop_canvas_text(cv, title);
    xtop_canvas_style(cv, XTOP_STYLE_RESET);
    xtop_canvas_text(cv, " ");
  }
  if (inner > title_columns + note_columns) {
    xtop_canvas_repeat_str(cv, XTOP_BOX_H, inner - title_columns - note_columns);
  }
  if (note_columns != 0U) {
    xtop_canvas_text(cv, " ");
    xtop_canvas_style(cv, XTOP_STYLE_TITLE);
    xtop_canvas_text(cv, note);
    xtop_canvas_style(cv, XTOP_STYLE_RESET);
    xtop_canvas_text(cv, " " XTOP_BOX_H);
  }
  xtop_canvas_text(cv, right_corner);
}

void xtop_draw_panel_top(xtop_canvas_t *cv, const char *title,
                                uint32_t width) {
  xtop_draw_rule(cv, XTOP_BOX_TL, XTOP_BOX_TR, title, 0, width);
}

void xtop_draw_panel_bottom(xtop_canvas_t *cv, uint32_t width) {
  xtop_draw_rule(cv, XTOP_BOX_BL, XTOP_BOX_BR, 0, 0, width);
}

/* Text in a style, padded with the field to exactly `width` columns. */
void xtop_draw_padded(xtop_canvas_t *cv, xtop_style_t style,
                      const char *text, uint32_t width) {
  uint32_t visible = xtop_columns(text);
  if (visible > width) visible = width;
  xtop_canvas_style(cv, style);
  xtop_canvas_bounded(cv, text, width);
  if (visible < width) xtop_canvas_repeat(cv, ' ', width - visible);
  xtop_canvas_style(cv, XTOP_STYLE_RESET);
}

static void xtop_draw_key(xtop_canvas_t *cv, uint32_t *visible,
                          const char *key, const char *label) {
  xtop_canvas_style(cv, XTOP_STYLE_TITLE);
  xtop_canvas_text(cv, key);
  xtop_canvas_style(cv, XTOP_STYLE_RESET);
  xtop_canvas_text(cv, label);
  xtop_canvas_char(cv, ' ');
  *visible += (uint32_t)xtop_cstr_len(key) + (uint32_t)xtop_cstr_len(label) + 1U;
}

/* The screen's bottom rule, with the keys set into it the way mactop sets
   its own: a corner, a rule, the keys, and the rule out to the far corner. */
void xtop_draw_key_bar(xtop_canvas_t *cv, uint32_t columns,
                              int interactive, uint32_t refresh_ms,
                              uint32_t layout) {
  uint32_t visible = 3U;
  /* The redraw cadence by the right corner, the way mactop shows its own
     -/+ interval; nothing when the caller did not say. */
  char cadence[32];
  uint64_t cadence_used = 0U;
  cadence[0] = '\0';
  if (interactive != 0 && refresh_ms != 0U) {
    xtop_output_append(cadence, sizeof(cadence), &cadence_used, "-/+ ");
    xtop_output_append_u64(cadence, sizeof(cadence), &cadence_used, refresh_ms);
    xtop_output_append(cadence, sizeof(cadence), &cadence_used, "ms");
  }
  uint32_t cadence_columns = cadence[0] != '\0' ? xtop_columns(cadence) + 3U : 0U;
  xtop_canvas_style(cv, XTOP_STYLE_RESET);
  xtop_canvas_text(cv, XTOP_BOX_BL XTOP_BOX_H " ");
  if (interactive != 0) {
    /* "1/3 layout" by the left corner, as mactop counts its own. */
    xtop_canvas_style(cv, XTOP_STYLE_TITLE);
    canvas_u64(cv, layout);
    xtop_canvas_text(cv, "/");
    canvas_u64(cv, XTOP_LAYOUT_COUNT);
    xtop_canvas_style(cv, XTOP_STYLE_RESET);
    xtop_canvas_text(cv, " layout  ");
    visible += 2U + (uint32_t)xtop_u64_digits(layout) + (uint32_t)xtop_u64_digits(XTOP_LAYOUT_COUNT) + 8U;
    xtop_draw_key(cv, &visible, "L", "Layout");
    xtop_draw_key(cv, &visible, "F1", "Help");
    xtop_draw_key(cv, &visible, "F3", "Search");
    xtop_draw_key(cv, &visible, "F4", "Filter");
    xtop_draw_key(cv, &visible, "F5", "Tree");
    if (columns >= 80U) {
      xtop_draw_key(cv, &visible, "F6", "Sort");
      xtop_draw_key(cv, &visible, "I", "Reverse");
      xtop_draw_key(cv, &visible, "[/]", "CPUs");
    }
    xtop_draw_key(cv, &visible, "F10", "Quit");
  } else {
    const char *text = columns < 60U
                           ? "--active --all --sort KEY --plain "
                           : "--active  --all  --sort KEY  --filter TEXT  --cpu-start N  --plain ";
    xtop_canvas_text(cv, text);
    visible += (uint32_t)xtop_cstr_len(text);
  }
  if (columns < visible + cadence_columns + 1U) cadence_columns = 0U;
  if (columns > visible + cadence_columns + 1U) {
    xtop_canvas_repeat_str(cv, XTOP_BOX_H, columns - visible - cadence_columns - 1U);
  }
  if (cadence_columns != 0U) {
    xtop_canvas_text(cv, " ");
    xtop_canvas_style(cv, XTOP_STYLE_TITLE);
    xtop_canvas_text(cv, cadence);
    xtop_canvas_style(cv, XTOP_STYLE_RESET);
    xtop_canvas_text(cv, " " XTOP_BOX_H);
  }
  xtop_canvas_text(cv, XTOP_BOX_BR);
  xtop_canvas_style(cv, XTOP_STYLE_RESET);
}

void xtop_draw_info_cell(xtop_canvas_t *cv, uint32_t row,
                                uint32_t width, uint32_t active_tasks,
                                uint32_t failed_tasks, uint32_t cpu_total,
                                const uint32_t load_average[3],
                                uint64_t now_ns) {
  uint32_t visible = 0U;
  if (row == 0U) {
    xtop_canvas_style(cv, XTOP_STYLE_FG);
    xtop_canvas_text(cv, "Tasks: ");
    xtop_canvas_style(cv, XTOP_STYLE_TITLE);
    canvas_u64(cv, active_tasks);
    visible = 7U + (uint32_t)xtop_u64_digits(active_tasks);
    if (width >= 40U) {
      xtop_canvas_style(cv, XTOP_STYLE_FG);
      xtop_canvas_text(cv, " active, ");
      /* Failures are the one figure that should shout, and only when there
         are any. */
      xtop_canvas_style(cv, failed_tasks != 0U ? XTOP_STYLE_ALERT : XTOP_STYLE_TITLE);
      canvas_u64(cv, failed_tasks);
      xtop_canvas_style(cv, XTOP_STYLE_FG);
      xtop_canvas_text(cv, " failed; CPUs: ");
      xtop_canvas_style(cv, XTOP_STYLE_TITLE);
      canvas_u64(cv, cpu_total);
      visible += 24U + (uint32_t)xtop_u64_digits(failed_tasks) +
                 (uint32_t)xtop_u64_digits(cpu_total);
    } else {
      xtop_canvas_style(cv, XTOP_STYLE_FG);
      xtop_canvas_text(cv, "  Fail: ");
      xtop_canvas_style(cv, failed_tasks != 0U ? XTOP_STYLE_ALERT : XTOP_STYLE_TITLE);
      canvas_u64(cv, failed_tasks);
      visible += 8U + (uint32_t)xtop_u64_digits(failed_tasks);
    }
  } else if (row == 1U) {
    const char *caption = width >= 32U ? "Load average: " : "Load: ";
    xtop_canvas_style(cv, XTOP_STYLE_FG);
    xtop_canvas_text(cv, caption);
    xtop_canvas_style(cv, XTOP_STYLE_TITLE);
    visible = (uint32_t)xtop_cstr_len(caption);
    uint32_t values = width >= 24U ? 3U : 2U;
    for (uint32_t i = 0U; i < values; ++i) {
      if (i != 0U) {
        xtop_canvas_text(cv, " ");
        ++visible;
      }
      canvas_hundredths(cv, load_average[i]);
      visible += (uint32_t)xtop_u64_digits(load_average[i] / 100U) + 3U;
    }
  } else {
    uint64_t seconds = now_ns / UINT64_C(1000000000);
    if (width >= 24U) {
      xtop_canvas_style(cv, XTOP_STYLE_FG);
      xtop_canvas_text(cv, "Uptime: ");
      xtop_canvas_style(cv, XTOP_STYLE_TITLE);
      visible = 8U + canvas_uptime(cv, now_ns);
    } else {
      uint64_t days = seconds / 86400U;
      uint64_t hours = (seconds / 3600U) % 24U;
      uint64_t minutes = (seconds / 60U) % 60U;
      seconds %= 60U;
      xtop_canvas_style(cv, XTOP_STYLE_FG);
      xtop_canvas_text(cv, "Uptime: ");
      xtop_canvas_style(cv, XTOP_STYLE_TITLE);
      canvas_u64(cv, days);
      xtop_canvas_text(cv, "d ");
      if (hours < 10U) xtop_canvas_text(cv, "0");
      canvas_u64(cv, hours);
      xtop_canvas_text(cv, ":");
      if (minutes < 10U) xtop_canvas_text(cv, "0");
      canvas_u64(cv, minutes);
      xtop_canvas_text(cv, ":");
      if (seconds < 10U) xtop_canvas_text(cv, "0");
      canvas_u64(cv, seconds);
      visible = 18U + (uint32_t)xtop_u64_digits(days);
    }
  }
  xtop_canvas_style(cv, XTOP_STYLE_RESET);
  if (visible < width) xtop_canvas_repeat(cv, ' ', width - visible);
}
