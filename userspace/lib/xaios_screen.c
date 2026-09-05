#include <xaios_screen.h>

/* Freestanding helpers: this file is linked into programs with no libc. */
static void cells_blank(xaios_screen_cell_t *cells, uint32_t count,
                        uint16_t bg) {
  for (uint32_t i = 0U; i < count; ++i) {
    cells[i].glyph[0] = ' ';
    cells[i].glyph[1] = 0U;
    cells[i].glyph[2] = 0U;
    cells[i].glyph[3] = 0U;
    cells[i].fg = XAIOS_SCREEN_DEFAULT;
    cells[i].bg = bg;
    cells[i].bold = 0U;
    cells[i].pad[0] = 0U;
    cells[i].pad[1] = 0U;
    cells[i].pad[2] = 0U;
  }
}

static int cell_equal(const xaios_screen_cell_t *a,
                      const xaios_screen_cell_t *b) {
  return a->glyph[0] == b->glyph[0] && a->glyph[1] == b->glyph[1] &&
         a->glyph[2] == b->glyph[2] && a->glyph[3] == b->glyph[3] &&
         a->fg == b->fg && a->bg == b->bg && a->bold == b->bold;
}

static uint32_t cell_count(const xaios_screen_t *screen) {
  return screen->rows * screen->columns;
}

void xaios_screen_init(xaios_screen_t *screen, xaios_screen_cell_t *next,
                       xaios_screen_cell_t *shown, uint32_t cells_capacity,
                       uint32_t rows, uint32_t columns) {
  if (screen == 0) return;
  screen->next = next;
  screen->shown = shown;
  screen->cells_capacity = cells_capacity;
  screen->alternate = 0U;
  xaios_screen_resize(screen, rows, columns);
}

void xaios_screen_resize(xaios_screen_t *screen, uint32_t rows,
                         uint32_t columns) {
  if (screen == 0) return;
  if (rows == 0U) rows = 1U;
  if (columns == 0U) columns = 1U;
  if (rows > XAIOS_SCREEN_MAX_ROWS) rows = XAIOS_SCREEN_MAX_ROWS;
  if (columns > XAIOS_SCREEN_MAX_COLUMNS) columns = XAIOS_SCREEN_MAX_COLUMNS;
  /* A grid smaller than the terminal models the top-left of it; that is
     still correct, and never writes past the storage. */
  while (rows * columns > screen->cells_capacity && rows > 1U) --rows;
  while (rows * columns > screen->cells_capacity && columns > 1U) --columns;
  screen->rows = rows;
  screen->columns = columns;
  screen->cursor_row = 0U;
  screen->cursor_column = 0U;
  screen->cursor_hidden = 0U;
  screen->fg = XAIOS_SCREEN_DEFAULT;
  screen->bg = XAIOS_SCREEN_DEFAULT;
  screen->bold = 0U;
  if (screen->next != 0) cells_blank(screen->next, cell_count(screen),
                                     XAIOS_SCREEN_DEFAULT);
  xaios_screen_invalidate(screen);
}

void xaios_screen_invalidate(xaios_screen_t *screen) {
  if (screen == 0) return;
  screen->shown_valid = 0U;
  screen->incomplete = 0U;
}

void xaios_screen_clear(xaios_screen_t *screen, uint16_t bg) {
  if (screen == 0 || screen->next == 0) return;
  cells_blank(screen->next, cell_count(screen), bg);
}

static uint32_t utf8_length(uint8_t lead) {
  if (lead < 0x80U) return 1U;
  if ((lead & 0xe0U) == 0xc0U) return 2U;
  if ((lead & 0xf0U) == 0xe0U) return 3U;
  return 4U;
}

static void cell_set(xaios_screen_cell_t *cell, const uint8_t *glyph,
                     uint32_t glyph_bytes, uint16_t fg, uint16_t bg,
                     uint8_t bold) {
  for (uint32_t k = 0U; k < 4U; ++k) {
    cell->glyph[k] = k < glyph_bytes ? glyph[k] : 0U;
  }
  cell->fg = fg;
  cell->bg = bg;
  cell->bold = bold;
}

uint32_t xaios_screen_put(xaios_screen_t *screen, uint32_t row,
                          uint32_t column, const char *utf8, uint16_t fg,
                          uint16_t bg, uint8_t bold) {
  uint32_t written = 0U;
  if (screen == 0 || screen->next == 0 || utf8 == 0 ||
      row >= screen->rows) {
    return 0U;
  }
  const uint8_t *bytes = (const uint8_t *)utf8;
  while (*bytes != 0U && column < screen->columns) {
    uint32_t glyph_bytes = utf8_length(*bytes);
    uint32_t have = 0U;
    while (have < glyph_bytes && bytes[have] != 0U) ++have;
    cell_set(&screen->next[row * screen->columns + column], bytes, have, fg,
             bg, bold);
    bytes += have;
    ++column;
    ++written;
  }
  return written;
}

/* ---- painting: a terminal model for what programs write ---- */

static void paint_erase(xaios_screen_t *screen, uint32_t from, uint32_t to) {
  uint32_t count = cell_count(screen);
  if (to > count) to = count;
  if (from < to) cells_blank(screen->next + from, to - from, screen->bg);
}

static void paint_sgr(xaios_screen_t *screen, const uint32_t *params,
                      uint32_t count) {
  if (count == 0U) {
    screen->fg = XAIOS_SCREEN_DEFAULT;
    screen->bg = XAIOS_SCREEN_DEFAULT;
    screen->bold = 0U;
    return;
  }
  for (uint32_t k = 0U; k < count; ++k) {
    uint32_t v = params[k];
    if (v == 0U) {
      screen->fg = XAIOS_SCREEN_DEFAULT;
      screen->bg = XAIOS_SCREEN_DEFAULT;
      screen->bold = 0U;
    } else if (v == 1U) {
      screen->bold = 1U;
    } else if (v == 22U) {
      screen->bold = 0U;
    } else if (v >= 30U && v <= 37U) {
      screen->fg = (uint16_t)(v - 30U);
    } else if (v >= 90U && v <= 97U) {
      screen->fg = (uint16_t)(v - 90U + 8U);
    } else if (v >= 40U && v <= 47U) {
      screen->bg = (uint16_t)(v - 40U);
    } else if (v >= 100U && v <= 107U) {
      screen->bg = (uint16_t)(v - 100U + 8U);
    } else if ((v == 38U || v == 48U) && k + 2U < count &&
               params[k + 1U] == 5U) {
      uint16_t index = (uint16_t)(params[k + 2U] & 0xffU);
      if (v == 38U) screen->fg = index; else screen->bg = index;
      k += 2U;
    } else if (v == 39U) {
      screen->fg = XAIOS_SCREEN_DEFAULT;
    } else if (v == 49U) {
      screen->bg = XAIOS_SCREEN_DEFAULT;
    }
  }
}

static void paint_csi(xaios_screen_t *screen, const uint32_t *params,
                      uint32_t count, int private_mode, char final) {
  uint32_t p0 = count >= 1U ? params[0] : 0U;
  uint32_t p1 = count >= 2U ? params[1] : 0U;
  uint32_t n = p0 == 0U ? 1U : p0;
  uint32_t cursor = screen->cursor_row * screen->columns + screen->cursor_column;
  if (private_mode) {
    if (p0 == 25U) screen->cursor_hidden = final == 'l' ? 1U : 0U;
    if (p0 == 1049U || p0 == 1047U || p0 == 47U) {
      screen->alternate = final == 'h' ? 1U : 0U;
    }
    return;
  }
  switch (final) {
  case 'm':
    paint_sgr(screen, params, count);
    break;
  case 'H':
  case 'f':
    screen->cursor_row = p0 != 0U ? p0 - 1U : 0U;
    screen->cursor_column = p1 != 0U ? p1 - 1U : 0U;
    break;
  case 'A':
    screen->cursor_row = screen->cursor_row >= n ? screen->cursor_row - n : 0U;
    break;
  case 'B':
    screen->cursor_row += n;
    break;
  case 'C':
    screen->cursor_column += n;
    break;
  case 'D':
    screen->cursor_column =
        screen->cursor_column >= n ? screen->cursor_column - n : 0U;
    break;
  case 'G':
    screen->cursor_column = p0 != 0U ? p0 - 1U : 0U;
    break;
  case 'd':
    screen->cursor_row = p0 != 0U ? p0 - 1U : 0U;
    break;
  case 'J':
    if (p0 == 0U) paint_erase(screen, cursor, cell_count(screen));
    else if (p0 == 1U) paint_erase(screen, 0U, cursor + 1U);
    else paint_erase(screen, 0U, cell_count(screen));
    break;
  case 'K': {
    uint32_t line = screen->cursor_row * screen->columns;
    if (p0 == 0U) paint_erase(screen, cursor, line + screen->columns);
    else if (p0 == 1U) paint_erase(screen, line, cursor + 1U);
    else paint_erase(screen, line, line + screen->columns);
    break;
  }
  default:
    break;
  }
  if (screen->cursor_row >= screen->rows) screen->cursor_row = screen->rows - 1U;
  if (screen->cursor_column > screen->columns) {
    screen->cursor_column = screen->columns;
  }
}

void xaios_screen_paint(xaios_screen_t *screen, const char *bytes,
                        uint64_t length) {
  if (screen == 0 || screen->next == 0 || bytes == 0) return;
  const uint8_t *data = (const uint8_t *)bytes;
  for (uint64_t i = 0U; i < length;) {
    uint8_t byte = data[i];
    if (byte == 0x1bU) {
      if (i + 1U >= length) return;
      uint8_t kind = data[i + 1U];
      if (kind == '[') {
        uint64_t j = i + 2U;
        uint32_t params[8];
        uint32_t count = 0U;
        uint32_t value = 0U;
        int have = 0;
        int private_mode = 0;
        while (j < length && data[j] >= 0x30U && data[j] <= 0x3fU) {
          uint8_t c = data[j];
          if (c == ';') {
            if (count < 8U) params[count++] = value;
            value = 0U;
            have = 0;
          } else if (c >= '0' && c <= '9') {
            value = value * 10U + (uint32_t)(c - '0');
            have = 1;
          } else if (c == '?') {
            private_mode = 1;
          }
          ++j;
        }
        if (have && count < 8U) params[count++] = value;
        while (j < length && data[j] >= 0x20U && data[j] <= 0x2fU) ++j;
        if (j >= length) return;
        paint_csi(screen, params, count, private_mode, (char)data[j]);
        i = j + 1U;
        continue;
      }
      if (kind == ']') {
        /* An operating-system command runs to BEL or ESC \. */
        uint64_t j = i + 2U;
        while (j < length && data[j] != 0x07U &&
               !(data[j] == 0x1bU && j + 1U < length && data[j + 1U] == '\\')) {
          ++j;
        }
        i = j < length ? (data[j] == 0x07U ? j + 1U : j + 2U) : length;
        continue;
      }
      /* ESC ( B and the like take one more byte; ESC 7, ESC = take none. */
      i += (kind == '(' || kind == ')' || kind == '#') ? 3U : 2U;
      continue;
    }
    ++i;
    if (byte == '\r') { screen->cursor_column = 0U; continue; }
    if (byte == '\n') {
      if (screen->cursor_row + 1U < screen->rows) ++screen->cursor_row;
      screen->cursor_column = 0U;
      continue;
    }
    if (byte == 0x08U) {
      if (screen->cursor_column != 0U) --screen->cursor_column;
      continue;
    }
    if (byte == 0x09U) {
      screen->cursor_column = (screen->cursor_column / 8U + 1U) * 8U;
      if (screen->cursor_column > screen->columns) {
        screen->cursor_column = screen->columns;
      }
      continue;
    }
    if (byte < 0x20U || byte == 0x7fU) continue;
    uint32_t glyph_bytes = utf8_length(byte);
    if (i - 1U + glyph_bytes > length) glyph_bytes = (uint32_t)(length - (i - 1U));
    if (screen->cursor_column >= screen->columns) {
      if (screen->cursor_row + 1U < screen->rows) ++screen->cursor_row;
      screen->cursor_column = 0U;
    }
    cell_set(&screen->next[screen->cursor_row * screen->columns +
                           screen->cursor_column],
             data + i - 1U, glyph_bytes, screen->fg, screen->bg, screen->bold);
    ++screen->cursor_column;
    i += glyph_bytes - 1U;
  }
}

/* ---- presenting: the bytes from what is shown to what is wanted ---- */

static void out_char(char *output, uint64_t capacity, uint64_t *used, char c) {
  if (*used + 1U < capacity) output[(*used)++] = c;
  else *used = capacity; /* overflowed: the caller checks */
}

static void out_text(char *output, uint64_t capacity, uint64_t *used,
                     const char *text) {
  while (*text != '\0') out_char(output, capacity, used, *text++);
}

static void out_u32(char *output, uint64_t capacity, uint64_t *used,
                    uint32_t value) {
  char digits[12];
  uint32_t n = 0U;
  do {
    digits[n++] = (char)('0' + value % 10U);
    value /= 10U;
  } while (value != 0U);
  while (n != 0U) out_char(output, capacity, used, digits[--n]);
}

static void out_attrs(char *output, uint64_t capacity, uint64_t *used,
                      const xaios_screen_cell_t *cell) {
  out_text(output, capacity, used, "\033[0");
  if (cell->bold) out_text(output, capacity, used, ";1");
  if (cell->fg != XAIOS_SCREEN_DEFAULT) {
    out_text(output, capacity, used, ";38;5;");
    out_u32(output, capacity, used, cell->fg);
  }
  if (cell->bg != XAIOS_SCREEN_DEFAULT) {
    out_text(output, capacity, used, ";48;5;");
    out_u32(output, capacity, used, cell->bg);
  }
  out_char(output, capacity, used, 'm');
}

/* A run is built here first, so a run that does not fit is left for the
   next present rather than written in part. The longest run is a full
   row: 240 cells of four glyph bytes and an attribute change each. */
#define XAIOS_SCREEN_RUN_BYTES 8192U
static char g_run[XAIOS_SCREEN_RUN_BYTES];

int xaios_screen_dirty(const xaios_screen_t *screen) {
  if (screen == 0 || screen->next == 0 || screen->shown == 0) return 0;
  if (screen->shown_valid == 0U) return 1;
  uint32_t count = cell_count(screen);
  for (uint32_t i = 0U; i < count; ++i) {
    if (!cell_equal(&screen->next[i], &screen->shown[i])) return 1;
  }
  return screen->shown_cursor_hidden != screen->cursor_hidden ||
         (screen->cursor_hidden == 0U &&
          (screen->shown_cursor_row != screen->cursor_row ||
           screen->shown_cursor_column != screen->cursor_column));
}

uint64_t xaios_screen_present(xaios_screen_t *screen, char *output,
                              uint64_t capacity) {
  uint64_t used = 0U;
  int attrs_known = 0;
  int wrote_cells = 0;
  int cut_short = 0;
  xaios_screen_cell_t current;
  /* Room kept for the trailer: reset, cursor position, show or hide. */
  const uint64_t trailer = 32U;
  if (screen == 0 || output == 0 || screen->next == 0 || screen->shown == 0 ||
      capacity <= trailer + 1U) {
    return 0U;
  }
  output[0] = '\0';
  cells_blank(&current, 1U, XAIOS_SCREEN_DEFAULT);
  if (screen->shown_valid == 0U) {
    out_text(output, capacity, &used, "\033[0m\033[2J\033[H");
    cells_blank(screen->shown, cell_count(screen), XAIOS_SCREEN_DEFAULT);
    screen->shown_valid = 1U;
    screen->shown_cursor_hidden = UINT32_MAX; /* unknown: the trailer says */
    wrote_cells = 1;
  }
  for (uint32_t r = 0U; r < screen->rows && !cut_short; ++r) {
    xaios_screen_cell_t *next_row = screen->next + r * screen->columns;
    xaios_screen_cell_t *shown_row = screen->shown + r * screen->columns;
    uint32_t c = 0U;
    while (c < screen->columns) {
      if (cell_equal(&next_row[c], &shown_row[c])) { ++c; continue; }
      /* A run of changed cells, allowing up to two unchanged cells inside
         it: a cursor move costs more than two glyphs. */
      uint32_t end = c;
      uint32_t last_changed = c;
      while (end < screen->columns) {
        if (!cell_equal(&next_row[end], &shown_row[end])) last_changed = end;
        else if (end - last_changed > 2U) break;
        ++end;
      }
      end = last_changed + 1U;
      uint64_t run_used = 0U;
      xaios_screen_cell_t run_current = current;
      int run_attrs_known = attrs_known;
      out_text(g_run, sizeof(g_run), &run_used, "\033[");
      out_u32(g_run, sizeof(g_run), &run_used, r + 1U);
      out_char(g_run, sizeof(g_run), &run_used, ';');
      out_u32(g_run, sizeof(g_run), &run_used, c + 1U);
      out_char(g_run, sizeof(g_run), &run_used, 'H');
      for (uint32_t k = c; k < end; ++k) {
        const xaios_screen_cell_t *cell = &next_row[k];
        if (!run_attrs_known || cell->fg != run_current.fg ||
            cell->bg != run_current.bg || cell->bold != run_current.bold) {
          out_attrs(g_run, sizeof(g_run), &run_used, cell);
          run_current = *cell;
          run_attrs_known = 1;
        }
        for (uint32_t b = 0U; b < 4U && cell->glyph[b] != 0U; ++b) {
          out_char(g_run, sizeof(g_run), &run_used, (char)cell->glyph[b]);
        }
      }
      if (run_used >= sizeof(g_run) || used + run_used + trailer > capacity) {
        cut_short = 1;
        break;
      }
      for (uint64_t b = 0U; b < run_used; ++b) output[used++] = g_run[b];
      for (uint32_t k = c; k < end; ++k) shown_row[k] = next_row[k];
      current = run_current;
      attrs_known = run_attrs_known;
      wrote_cells = 1;
      c = end;
    }
  }
  screen->incomplete = cut_short != 0 ? 1U : 0U;
  int cursor_moved =
      screen->shown_cursor_hidden != screen->cursor_hidden ||
      (screen->cursor_hidden == 0U &&
       (screen->shown_cursor_row != screen->cursor_row ||
        screen->shown_cursor_column != screen->cursor_column));
  if (!wrote_cells && !cursor_moved) return 0U;
  out_text(output, capacity, &used, "\033[0m");
  if (screen->cursor_hidden != 0U) {
    out_text(output, capacity, &used, "\033[?25l");
  } else {
    out_text(output, capacity, &used, "\033[");
    out_u32(output, capacity, &used, screen->cursor_row + 1U);
    out_char(output, capacity, &used, ';');
    out_u32(output, capacity, &used, screen->cursor_column + 1U);
    out_text(output, capacity, &used, "H\033[?25h");
  }
  screen->shown_cursor_hidden = screen->cursor_hidden;
  screen->shown_cursor_row = screen->cursor_row;
  screen->shown_cursor_column = screen->cursor_column;
  if (used < capacity) output[used] = '\0';
  return used;
}

/* ---- keys ---- */

uint32_t xaios_screen_read_key(const uint8_t *bytes, uint32_t length,
                               xaios_key_t *key, uint32_t *code) {
  xaios_key_t k = XAIOS_KEY_NONE;
  uint32_t c = 0U;
  uint32_t consumed = 0U;
  if (key == 0 || code == 0) return 0U;
  *key = XAIOS_KEY_NONE;
  *code = 0U;
  if (bytes == 0 || length == 0U) return 0U;
  uint8_t b = bytes[0];
  if (b != 0x1bU) {
    consumed = 1U;
    if (b == '\r' || b == '\n') k = XAIOS_KEY_ENTER;
    else if (b == '\t') k = XAIOS_KEY_TAB;
    else if (b == 0x7fU || b == 0x08U) k = XAIOS_KEY_BACKSPACE;
    else if (b >= 0x80U) {
      uint32_t n = utf8_length(b);
      if (n > length) return 0U;
      c = n == 2U ? (uint32_t)(b & 0x1fU) : n == 3U ? (uint32_t)(b & 0x0fU)
                                                      : (uint32_t)(b & 0x07U);
      for (uint32_t i = 1U; i < n; ++i) c = (c << 6U) | (bytes[i] & 0x3fU);
      consumed = n;
      k = XAIOS_KEY_CHAR;
    } else {
      k = XAIOS_KEY_CHAR;
      c = b;
    }
    *key = k;
    *code = c;
    return consumed;
  }
  if (length == 1U) {
    *key = XAIOS_KEY_ESCAPE;
    return 1U;
  }
  if (bytes[1] == 'O') {
    if (length < 3U) return 0U;
    uint8_t f = bytes[2];
    if (f >= 'P' && f <= 'S') { k = XAIOS_KEY_FUNCTION; c = (uint32_t)(f - 'P') + 1U; }
    else if (f == 'H') k = XAIOS_KEY_HOME;
    else if (f == 'F') k = XAIOS_KEY_END;
    else if (f == 'A') k = XAIOS_KEY_UP;
    else if (f == 'B') k = XAIOS_KEY_DOWN;
    else if (f == 'C') k = XAIOS_KEY_RIGHT;
    else if (f == 'D') k = XAIOS_KEY_LEFT;
    *key = k;
    *code = c;
    return 3U;
  }
  if (bytes[1] != '[') {
    /* Alt plus a key, or a sequence this decoder does not know. */
    *key = XAIOS_KEY_ESCAPE;
    return 1U;
  }
  uint32_t j = 2U;
  uint32_t value = 0U;
  uint32_t first = 0U;
  int have = 0;
  while (j < length && ((bytes[j] >= '0' && bytes[j] <= '9') || bytes[j] == ';')) {
    if (bytes[j] == ';') { if (!first) first = value; value = 0U; have = 0; }
    else { value = value * 10U + (uint32_t)(bytes[j] - '0'); have = 1; }
    ++j;
  }
  if (j >= length) return 0U;
  if (!first && have) first = value;
  uint8_t final = bytes[j];
  consumed = j + 1U;
  switch (final) {
  case 'A': k = XAIOS_KEY_UP; break;
  case 'B': k = XAIOS_KEY_DOWN; break;
  case 'C': k = XAIOS_KEY_RIGHT; break;
  case 'D': k = XAIOS_KEY_LEFT; break;
  case 'H': k = XAIOS_KEY_HOME; break;
  case 'F': k = XAIOS_KEY_END; break;
  case 'P': k = XAIOS_KEY_FUNCTION; c = 1U; break;
  case 'Q': k = XAIOS_KEY_FUNCTION; c = 2U; break;
  case 'R': k = XAIOS_KEY_FUNCTION; c = 3U; break;
  case 'S': k = XAIOS_KEY_FUNCTION; c = 4U; break;
  case '~':
    switch (first) {
    case 1U: case 7U: k = XAIOS_KEY_HOME; break;
    case 2U: k = XAIOS_KEY_INSERT; break;
    case 3U: k = XAIOS_KEY_DELETE; break;
    case 4U: case 8U: k = XAIOS_KEY_END; break;
    case 5U: k = XAIOS_KEY_PAGE_UP; break;
    case 6U: k = XAIOS_KEY_PAGE_DOWN; break;
    case 11U: case 12U: case 13U: case 14U: case 15U:
      k = XAIOS_KEY_FUNCTION; c = first - 10U; break;
    case 17U: case 18U: case 19U: case 20U: case 21U:
      k = XAIOS_KEY_FUNCTION; c = first - 11U; break;
    case 23U: case 24U:
      k = XAIOS_KEY_FUNCTION; c = first - 12U; break;
    default: break;
    }
    break;
  default:
    break;
  }
  *key = k;
  *code = c;
  return consumed;
}
