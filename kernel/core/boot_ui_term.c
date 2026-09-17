/* The framebuffer text terminal: the display stops summarising boot and starts
 * mirroring the console byte stream.
 *
 * This module owns the cell cache, the xterm colour tables, the UTF-8 decoder
 * and the escape parser. boot_ui.c still activates the terminal and drives it
 * through the narrow surface declared in the private header, and nothing here
 * prints anything of its own: the byte stream it is handed is what both the
 * console and the boot gates already expect.
 */
#include "boot_ui_internal.h"

/* ---- Framebuffer text terminal ----
   After boot the display stops being a status panel and becomes a terminal
   that mirrors the console byte stream, so a machine with no serial cable --
   VMware Fusion in particular -- offers the same session as a QEMU serial
   console: prompt, echoed input, and command output. */
uint32_t g_term_active;
uint32_t g_term_columns;
uint32_t g_term_rows;
uint32_t g_term_column;
uint32_t g_term_row;
uint32_t g_term_color;
uint32_t g_term_esc_state;
static uint32_t g_term_params[TERM_CSI_PARAM_MAX];
uint32_t g_term_param_count;
uint32_t g_term_cursor_drawn;
/* ESC[?25l hides the cursor until ESC[?25h: a program drawing a screen
   does not want a cursor wandering over it between updates. */
static uint32_t g_term_cursor_hidden;
static uint32_t g_term_csi_private;

uint32_t term_default_background(void) { return fb_color(4U, 6U, 10U); }
uint32_t term_foreground(void) { return fb_color(222U, 230U, 236U); }

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

term_cell_t *g_term_cells;
uint32_t g_term_cell_count;

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

void term_cells_reset(uint32_t background) {
  for (uint32_t i = 0U; i < g_term_cell_count; ++i) {
    g_term_cells[i].code_point = (uint32_t)' ';
    g_term_cells[i].fg = 0U;
    g_term_cells[i].bg = background;
  }
}

uint32_t term_background(void) {
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

static void term_repaint_cell(uint32_t column, uint32_t row);

/* The cursor is an underline over a cell; erasing it paints the cell back
   as the cache has it. Painting only the current background left a dark
   underline on a coloured field wherever the cursor had been. */
void term_erase_cursor(void) {
  if (g_term_cursor_drawn == 0U) return;
  g_term_cursor_drawn = 0U;
  if (g_term_column < g_term_columns && g_term_row < g_term_rows) {
    term_repaint_cell(g_term_column, g_term_row);
  }
}

void term_draw_cursor(void) {
  if (g_term_active == 0U || g_term_cursor_drawn != 0U ||
      g_term_cursor_hidden != 0U || g_term_column >= g_term_columns) {
    return;
  }
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
  if (g_term_csi_private != 0U) {
    if ((final == 'l' || final == 'h') && g_term_param_count != 0U &&
        g_term_params[0] == 25U) {
      g_term_cursor_hidden = final == 'l' ? 1U : 0U;
      if (g_term_cursor_hidden != 0U) term_erase_cursor();
    }
    return;
  }
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
static const uint8_t *term_glyph_rows(uint32_t code_point) {
  if (code_point >= 0x20U && code_point <= 0x7fU) {
    return g_font[code_point - 0x20U];
  }
  const uint8_t *rows = fb_extra_rows(code_point);
  /* Not a space: a glyph this font lacks should look like a gap in the
     font, which is a thing to fix, rather than like whitespace the program
     asked for, which is not. */
  if (rows == 0) rows = fb_extra_rows(0x2591U);
  return rows;
}

static void term_draw_cell(uint32_t column, uint32_t row, uint32_t code_point,
                           uint32_t fg, uint32_t bg) {
  const uint8_t *rows = term_glyph_rows(code_point);
  fb_rect(term_x(column), term_y(row), FB_GLYPH_ADVANCE, TERM_LINE_HEIGHT, bg);
  if (rows == 0) return;
  fb_glyph_rows(term_x(column), term_y(row), rows, fg);
  /* A vertical rule has to reach the next row. Each row is the glyph plus a
     two-pixel gap beneath it, and a stroke that stops at the glyph's edge
     leaves a gap in every rule -- a box drawn on this console came out
     dashed where an SSH client drew it solid. The glyphs whose stroke
     reaches their bottom edge carry it on through the gap; the ones whose
     stroke starts at the top meet it there. */
  if (code_point == 0x2502U || code_point == 0x250cU ||
      code_point == 0x2510U) {
    fb_rect(term_x(column) + UINT32_C(3) * FB_GLYPH_X_SCALE,
            term_y(row) + FB_GLYPH_HEIGHT * FB_GLYPH_Y_SCALE,
            FB_GLYPH_X_SCALE, UINT32_C(2), fg);
  }
}

/* Paint a cell as the cache says it is: what erasing the cursor over it
   needs. A cell the cache does not know is painted as a blank in the
   current background. */
static void term_repaint_cell(uint32_t column, uint32_t row) {
  term_cell_t *cell = term_cell(column, row);
  if (cell == 0 || cell->code_point == TERM_CELL_UNKNOWN) {
    fb_rect(term_x(column), term_y(row), FB_GLYPH_ADVANCE, TERM_LINE_HEIGHT,
            term_background());
    return;
  }
  term_draw_cell(column, row, cell->code_point, cell->fg, cell->bg);
}

static void term_put_code_point(uint32_t code_point) {
  if (term_glyph_rows(code_point) == 0) return;
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
  term_draw_cell(g_term_column, g_term_row, code_point, g_term_color,
                 term_background());
  ++g_term_column;
}

void term_putc(uint8_t value) {
  if (g_term_esc_state == TERM_ESC_SAW_ESC) {
    if (value == '[') {
      g_term_esc_state = TERM_ESC_CSI;
      g_term_param_count = 0U;
      g_term_params[0] = 0U;
      g_term_csi_private = 0U;
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
    if (value == '?') {
      g_term_csi_private = 1U;
      return;
    }
    if (value == ':') return;
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
