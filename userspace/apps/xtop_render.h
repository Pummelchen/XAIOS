#ifndef XAIOS_APPS_XTOP_RENDER_H
#define XAIOS_APPS_XTOP_RENDER_H

/*
 * Private interface between xtop.c and xtop_render.c.
 *
 * xtop.c keeps the process table, the control queries, the retained samples
 * and the dashboard that arranges them all; xtop_render.c owns the panel text
 * builders and the gauge, bar and meter renderers that the panels and the
 * dashboard draw with.  Declarations live here so neither side repeats a
 * definition: the extras the panels read stay single-instanced in xtop.c and
 * are handed to the renderer as a read-only pointer, and the glyph primitives
 * the renderer draws through stay single-instanced in xtop.c.
 */

#include "xtop_serve.h"

/* What the frame shows beyond the process table: the machine, the AI
   runtime, the network and disk rates, and a short history. Filled by the
   serving loop before each frame; a one-shot run fills what it can and has
   no rates, because a rate needs two samples. */
#define XTOP_HISTORY 96U
typedef struct xtop_extras {
  int have_hardware;
  xaios_control_hardware_payload_user_t hardware;
  int have_metrics;
  xaios_control_metrics_payload_user_t metrics;
  int have_rates;
  uint64_t rx_bytes_per_s;
  uint64_t tx_bytes_per_s;
  uint64_t reads_per_s;
  uint64_t writes_per_s;
  uint64_t inferences_per_s;
  uint32_t layout;
  uint16_t cpu_history[XTOP_HISTORY];
  uint16_t mem_history[XTOP_HISTORY];
  uint32_t net_history[XTOP_HISTORY]; /* KB/s, rx + tx */
  uint32_t history_count;
} xtop_extras_t;

/* Glyph primitives that stay in xtop.c and are called from the renderer. */
uint32_t xtop_columns(const char *text);
void xtop_canvas_style(xtop_canvas_t *cv, xtop_style_t style);
void xtop_canvas_char(xtop_canvas_t *cv, char value);
void xtop_canvas_repeat(xtop_canvas_t *cv, char value, uint32_t count);
void xtop_canvas_repeat_str(xtop_canvas_t *cv, const char *glyph,
                            uint32_t count);
void xtop_canvas_percent_width(xtop_canvas_t *cv, uint64_t tenths);

/* The block glyphs a gauge, bar or meter is made of. */
#define XTOP_BAR_FULL "\xe2\x96\x88"  /* U+2588 FULL BLOCK */
#define XTOP_BAR_EMPTY "\xe2\x96\x91" /* U+2591 LIGHT SHADE */
/* Columns a meter uses around its bar: a space after the label, two before
   the percentage, the six-column percentage, and a gutter after it. */
#define XTOP_METER_OVERHEAD 10U

/* Implemented in xtop_render.c. */
void xtop_render_platform_line(const xtop_extras_t *extras, char *line,
                               uint64_t capacity, uint32_t row,
                               uint32_t cpu_total);
void xtop_render_ai_line(const xtop_extras_t *extras, char *line,
                         uint64_t capacity, uint32_t row);
void xtop_render_netdisk_line(const xtop_extras_t *extras, char *line,
                              uint64_t capacity, uint32_t row);
void xtop_render_meter(xtop_canvas_t *cv, const char *label,
                       uint32_t label_columns, uint64_t tenths,
                       uint32_t bar_width, uint32_t cell_width);
void xtop_render_gauge_row(xtop_canvas_t *cv, uint32_t width, uint64_t tenths,
                           const char *figure);
void xtop_render_chart_row(xtop_canvas_t *cv, uint32_t width,
                           const uint16_t *history, uint32_t count,
                           uint32_t row, uint32_t rows, uint16_t scale);

#endif /* XAIOS_APPS_XTOP_RENDER_H */
