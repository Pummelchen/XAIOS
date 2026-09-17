#ifndef XAIOS_XTOP_SERVE_H
#define XAIOS_XTOP_SERVE_H

#include <xaios_user.h>
#include <xaios_screen.h>
#include <xaios/types.h>
#include "ssh_child_ipc.h"

/* ---- A serving session: one process, frames for as long as it lasts.
 *
 * sshd used to launch this program once per frame and keep the session's
 * state -- sort key, filter, selection -- on its own side. That put a
 * process launch under every frame, which caps a monitor at a few frames a
 * second whatever the terminal could show. Here the process is started once
 * as a child of the session, keeps its own state, reads keys from the child
 * channel, and writes frames into it at up to sixty a second; the kernel
 * snapshots it draws from are cheap, and the load figures come from the
 * retained-sample ring above rather than from the previous frame.
 *
 * The session itself is xtop_serve.c. The one-shot renderer, the canvas it
 * draws through, the screen grid and the retained samples stay in xtop.c,
 * and everything declared below is the whole of what crosses between the
 * two translation units. */

#define XAIOS_OK 0
#define XTOP_ERR_BUSY (-5) /* XAIOS_ERR_BUSY, as the kernel returns it */
#define XAIOS_XTOP_OUTPUT_BYTES 32768U
#define XTOP_LAYOUT_COUNT 3U

typedef int xaios_status_t;

#define XTOP_BOX_H "\xe2\x94\x80"     /* U+2500 */
#define XTOP_BOX_V "\xe2\x94\x82"     /* U+2502 */
#define XTOP_BOX_TL "\xe2\x94\x8c"    /* U+250C */
#define XTOP_BOX_TR "\xe2\x94\x90"    /* U+2510 */
#define XTOP_BOX_BL "\xe2\x94\x94"    /* U+2514 */
#define XTOP_BOX_BR "\xe2\x94\x98"    /* U+2518 */

typedef enum xtop_sort_key {
  XTOP_SORT_CPU = 0,
  XTOP_SORT_MEMORY,
  XTOP_SORT_TIME,
  XTOP_SORT_PID,
  XTOP_SORT_STATE,
  XTOP_SORT_SYSCALLS,
  XTOP_SORT_COMMAND,
  XTOP_SORT_PARENT
} xtop_sort_key_t;

/* ---- the canvas: where a frame is drawn ----
 *
 * A frame is drawn either into the screen framework's grid of cells -- the
 * serving session, where only the cells that changed are then sent -- or
 * into a byte buffer as escape-coded text, for a one-shot run whose output
 * is a stream. The same drawing code serves both; what differs is where a
 * glyph and a colour go. Drawing into cells skips composing thirty
 * kilobytes of escapes and parsing them back, which was most of what a
 * frame cost. The text form emits exactly the escapes it always did. */
typedef struct xtop_canvas {
  xaios_screen_t *screen; /* cells, or null */
  char *text;             /* bytes, or null */
  uint64_t capacity;
  uint64_t *used;
  uint16_t fg;
  uint16_t bg;
  uint8_t bold;
  uint32_t row;
  uint32_t column;
} xtop_canvas_t;

typedef enum xtop_style {
  XTOP_STYLE_RESET,   /* text on the field, not bold */
  XTOP_STYLE_FG,      /* the text colour, keeping the background */
  XTOP_STYLE_TITLE,   /* bold white */
  XTOP_STYLE_FILL_BG, /* the fill background */
  XTOP_STYLE_HEADER,  /* black on the fill: the list header and selection */
  XTOP_STYLE_ALERT,   /* bold red */
  XTOP_STYLE_HOT,
  XTOP_STYLE_WARM,
  XTOP_STYLE_COOL,
  XTOP_STYLE_EMPTY,
  XTOP_STYLE_CHART
} xtop_style_t;

/* The renderer and the parts of it the session calls back into, defined in
   xtop.c. */
xaios_status_t xtop_output_append(char *output, uint64_t capacity,
                                  uint64_t *offset, const char *text);
xaios_status_t xtop_output_append_u64(char *output, uint64_t capacity,
                                      uint64_t *offset, uint64_t value);
uint64_t xtop_cstr_len(const char *text);
int xtop_string_equal(const char *lhs, const char *rhs);
xaios_status_t xtop_token_next(const char *text, uint64_t *index, char *token,
                               uint64_t capacity);
void xtop_bytes_zero(void *buffer, uint64_t size);
xaios_status_t xtop_parse_u32_option(const char *args, uint64_t *index,
                                     uint32_t *value);
xaios_status_t xtop_parse_sort_option(const char *args, uint64_t *index,
                                      xtop_sort_key_t *key);
const char *xtop_sort_name(xtop_sort_key_t key);
xaios_status_t xtop_handle(const char *args, char *output,
                           uint64_t output_capacity, uint64_t *output_bytes);
void xtop_canvas_text_init(xtop_canvas_t *cv, char *text, uint64_t capacity,
                           uint64_t *used);
void xtop_canvas_text(xtop_canvas_t *cv, const char *text);
void xtop_canvas_newline(xtop_canvas_t *cv);
void xtop_canvas_begin(xtop_canvas_t *cv, int cursor_hidden);
void xtop_draw_rule(xtop_canvas_t *cv, const char *left_corner,
                    const char *right_corner, const char *title,
                    const char *note, uint32_t width);
void xtop_draw_padded(xtop_canvas_t *cv, xtop_style_t style,
                      const char *text, uint32_t width);
void xtop_draw_edge(xtop_canvas_t *cv);

/* The screen grid and the render arena are the renderer's file-scope state;
   the session reaches them only through these, and never as a pointer. */
void xtop_screen_open(uint32_t rows, uint32_t columns);
uint64_t xtop_screen_take_diff(char *out, uint64_t capacity);
int xtop_screen_incomplete(void);
void xtop_screen_invalidate(void);
void xtop_arena_reset(void);

/* The retained samples are the renderer's too. */
void xtop_serve_update_extras(uint64_t now_ns, uint64_t *last_ns,
                              xaios_control_metrics_payload_user_t *last,
                              int *have_last, uint32_t window_ms);
void xtop_serve_push_load_history(uint16_t cpu_tenths, uint16_t mem_tenths);
uint16_t xtop_last_cpu_tenths(void);
uint16_t xtop_last_mem_tenths(void);

int xtop_serve(u64 channel_id, const char *command);

#endif
