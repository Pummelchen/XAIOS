#ifndef XAIOS_APPS_XTOP_GLYPH_H
#define XAIOS_APPS_XTOP_GLYPH_H

/*
 * Private interface between xtop.c, xtop_draw.c and xtop_glyph.c.
 *
 * xtop_glyph.c owns the drawing primitives a frame is built from: the screen
 * grid, the canvas that writes cells for a serving session or escape-coded
 * text for a one-shot run, the rules, panels and key bar, and the small
 * number and column formatters they share.  xtop.c keeps the control queries
 * and the plain-text report; xtop_draw.c keeps the dashboard.
 *
 * The screen grid is xtop_glyph.c's file-scope state and is reached only
 * through the functions below, never handed out as a pointer.
 */

#include "xtop_serve.h"

/* Number and column formatting. */
uint64_t xtop_u64_digits(uint64_t value);
uint32_t xtop_columns(const char *text);

/* The canvas.  A text canvas is built over the caller's buffer; the cell
   canvas is built over the screen grid xtop_glyph.c owns, so it is asked for
   by name rather than handed a grid. */
void xtop_canvas_text_init(xtop_canvas_t *cv, char *text, uint64_t capacity,
                           uint64_t *used);
void xtop_canvas_cells_init(xtop_canvas_t *cv);
void xtop_canvas_style(xtop_canvas_t *cv, xtop_style_t style);
void xtop_canvas_text(xtop_canvas_t *cv, const char *text);
void xtop_canvas_char(xtop_canvas_t *cv, char value);
void xtop_canvas_repeat(xtop_canvas_t *cv, char value, uint32_t count);
void xtop_canvas_repeat_str(xtop_canvas_t *cv, const char *glyph,
                            uint32_t count);
void xtop_canvas_newline(xtop_canvas_t *cv);
void xtop_canvas_begin(xtop_canvas_t *cv, int cursor_hidden);
void xtop_canvas_cursor(xtop_canvas_t *cv, int cursor_hidden);
int xtop_canvas_room(const xtop_canvas_t *cv, uint64_t bytes);
void xtop_canvas_u64_width(xtop_canvas_t *cv, uint64_t value, uint32_t width);
void xtop_canvas_percent_width(xtop_canvas_t *cv, uint64_t tenths);
void xtop_canvas_bounded(xtop_canvas_t *cv, const char *text, uint32_t width);
void xtop_canvas_runtime(xtop_canvas_t *cv, uint64_t runtime_ns);

/* Rules, panels and the bottom key bar. */
void xtop_draw_rule(xtop_canvas_t *cv, const char *left_corner,
                    const char *right_corner, const char *title,
                    const char *note, uint32_t width);
void xtop_draw_panel_top(xtop_canvas_t *cv, const char *title, uint32_t width);
void xtop_draw_panel_bottom(xtop_canvas_t *cv, uint32_t width);
void xtop_draw_padded(xtop_canvas_t *cv, xtop_style_t style,
                      const char *text, uint32_t width);
void xtop_draw_key_bar(xtop_canvas_t *cv, uint32_t columns, int interactive,
                       uint32_t refresh_ms, uint32_t layout);
void xtop_draw_info_cell(xtop_canvas_t *cv, uint32_t row, uint32_t width,
                         uint32_t active_tasks, uint32_t failed_tasks,
                         uint32_t cpu_total, const uint32_t load_average[3],
                         uint64_t now_ns);

/* The screen grid, reached only through these. */
void xtop_screen_open(uint32_t rows, uint32_t columns);
uint64_t xtop_screen_take_diff(char *out, uint64_t capacity);
int xtop_screen_incomplete(void);
void xtop_screen_invalidate(void);

#endif /* XAIOS_APPS_XTOP_GLYPH_H */
