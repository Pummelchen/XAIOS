/*
 * sshd's local console screen renderer.
 *
 * The kernel's terminal keeps a cell cache of its own, so a program that
 * draws whole frames on the alternate screen would otherwise pay a write per
 * byte it paints. This module is the session filter in front of that terminal:
 * it holds the grid, interprets the program's escape-coded frames into it, and
 * writes only the cells that changed. The geometry helpers move with it
 * because the grid is sized from them, and sshd.c keeps the console_write()
 * cstring wrapper over the byte writer so its many call sites are unchanged.
 *
 * See sshd_console_screen.h for what crosses back into sshd.c.
 */

#include "sshd_console_screen.h"

#include <xaios_screen.h>

/* The local console has no window-size protocol the way SSH does, so it is
   asked instead: a framebuffer console knows its own geometry and reports it,
   and anything else -- a serial line -- reports nothing and gets the
   conservative terminal below, which renders correctly at any real width. */
#define SSHD_CONSOLE_FALLBACK_COLUMNS 80U
#define SSHD_CONSOLE_FALLBACK_ROWS 24U

uint32_t sshd_console_columns(void) {
  u32 columns = 0U;
  u32 rows = 0U;
  if (xaios_console_size(&columns, &rows) != 0 || columns < 40U) {
    return SSHD_CONSOLE_FALLBACK_COLUMNS;
  }
  return columns > 240U ? 240U : columns;
}

uint32_t sshd_console_rows(void) {
  u32 columns = 0U;
  u32 rows = 0U;
  if (xaios_console_size(&columns, &rows) != 0 || rows < 12U) {
    return SSHD_CONSOLE_FALLBACK_ROWS;
  }
  return rows > 100U ? 100U : rows;
}

static int console_write_raw(const char *data, u64 size) {
  u64 offset = 0U;
  if (data == 0) return -1;
  while (offset < size) {
    u64 chunk = size - offset;
    if (chunk > SSHD_CONSOLE_WRITE_MAX) chunk = SSHD_CONSOLE_WRITE_MAX;
    if (xaios_console_write(data + offset, chunk) != (int)chunk) return -1;
    offset += chunk;
  }
  return 0;
}

/* The session filter of the screen framework, for the local console: a
   program on the alternate screen is run through a screen this process
   holds, and only the cells that changed are written to the kernel's
   terminal -- which keeps a cell cache of its own, so the two together
   make a change cost its own width and nothing more. */
static xaios_screen_cell_t g_console_screen_cells[2][XAIOS_SCREEN_MAX_CELLS];
static xaios_screen_t g_console_screen;
static uint32_t g_console_screen_held;
static char g_console_screen_out[65536];
static uint8_t g_console_screen_in[SSHD_CONSOLE_OUTPUT_MAX + 8U];
static uint8_t g_console_carry[8];
static uint32_t g_console_carry_used;
static const uint8_t k_console_alternate_enter[8] = {0x1b, '[', '?', '1', '0', '4', '9', 'h'};
static const uint8_t k_console_alternate_leave[8] = {0x1b, '[', '?', '1', '0', '4', '9', 'l'};

static int64_t console_find_bytes(const uint8_t *data, u64 len,
                                  const uint8_t *needle, u64 n) {
  for (u64 i = 0U; i + n <= len; ++i) {
    u64 k = 0U;
    while (k < n && data[i + k] == needle[k]) ++k;
    if (k == n) return (int64_t)i;
  }
  return -1;
}

static u64 console_trailing_partial_escape(const uint8_t *data, u64 len) {
  u64 back = len < 8U ? len : 8U;
  for (u64 i = 0U; i < back; ++i) {
    u64 at = len - 1U - i;
    if (data[at] == 0x1bU) {
      if (at + 1U < len && data[at + 1U] == '[') {
        for (u64 j = at + 2U; j < len; ++j) {
          if (data[j] >= 0x40U && data[j] <= 0x7eU) return 0U;
        }
        return len - at;
      }
      return at + 1U == len ? 1U : 0U;
    }
  }
  return 0U;
}

static int console_screen_flush(void) {
  for (;;) {
    uint64_t n = xaios_screen_present(&g_console_screen, g_console_screen_out,
                                      sizeof(g_console_screen_out));
    if (n == 0U) return 0;
    if (console_write_raw(g_console_screen_out, n) != 0) return -1;
    if (g_console_screen.incomplete == 0U) return 0;
  }
}

int sshd_console_write_bytes(const char *text, u64 size) {
  const uint8_t *data = (const uint8_t *)text;
  if (text == 0) return -1;
  while (size != 0U) {
    if (g_console_screen_held == 0U) {
      int64_t at = console_find_bytes(data, size, k_console_alternate_enter, 8U);
      if (at < 0) return console_write_raw((const char *)data, size);
      u64 head = (u64)at + 8U;
      if (console_write_raw((const char *)data, head) != 0) return -1;
      data += head;
      size -= head;
      xaios_screen_init(&g_console_screen, g_console_screen_cells[0],
                        g_console_screen_cells[1], XAIOS_SCREEN_MAX_CELLS,
                        sshd_console_rows(), sshd_console_columns());
      g_console_screen_held = 1U;
      g_console_carry_used = 0U;
      continue;
    }
    u64 total = g_console_carry_used + size;
    if (total > sizeof(g_console_screen_in)) return -1;
    for (u64 i = 0U; i < g_console_carry_used; ++i) g_console_screen_in[i] = g_console_carry[i];
    for (u64 i = 0U; i < size; ++i) g_console_screen_in[g_console_carry_used + i] = data[i];
    g_console_carry_used = 0U;
    data = g_console_screen_in;
    size = total;
    int64_t at = console_find_bytes(data, size, k_console_alternate_leave, 8U);
    if (at < 0) {
      u64 keep = console_trailing_partial_escape(data, size);
      xaios_screen_paint(&g_console_screen, (const char *)data, size - keep);
      for (u64 i = 0U; i < keep; ++i) g_console_carry[i] = data[size - keep + i];
      g_console_carry_used = (uint32_t)keep;
      return console_screen_flush();
    }
    xaios_screen_paint(&g_console_screen, (const char *)data, (u64)at);
    if (console_screen_flush() != 0) return -1;
    g_console_screen_held = 0U;
    if (console_write_raw((const char *)data + at, 8U) != 0) return -1;
    data += (u64)at + 8U;
    size -= (u64)at + 8U;
  }
  return 0;
}
