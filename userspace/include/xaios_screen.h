#ifndef XAIOS_SCREEN_H
#define XAIOS_SCREEN_H

/* The screen framework: a terminal held as a grid of cells, and the bytes
   that turn what a terminal shows into the next grid.

   A program that draws a whole screen -- a monitor, an editor, a game --
   keeps one of these. It draws into the grid, either cell by cell or by
   painting the escape-coded frame it already produces, and presents; what
   goes to the terminal is only the cells that changed since the last
   present, positioned with cursor moves. An unchanged screen costs nothing,
   a changed figure costs its own width, and sixty presents a second are
   sixty small writes. The same bytes drive an SSH client and the local
   framebuffer console, whose kernel terminal keeps a cell cache of its own.

   The session server applies the same model to every program that enters
   the alternate screen, so a program that writes whole frames gets the
   saving without holding a screen itself. A program that holds one saves
   the parse as well, and can wait on xaios_wait_events between presents.

   Freestanding: no allocation, no libc. The caller supplies the two grids. */

#include <xaios/types.h>

#define XAIOS_SCREEN_MAX_ROWS 100U
#define XAIOS_SCREEN_MAX_COLUMNS 240U
#define XAIOS_SCREEN_MAX_CELLS (XAIOS_SCREEN_MAX_ROWS * XAIOS_SCREEN_MAX_COLUMNS)
/* A colour index meaning the terminal's default. */
#define XAIOS_SCREEN_DEFAULT UINT16_C(256)

typedef struct xaios_screen_cell {
  uint8_t glyph[4]; /* UTF-8, unused bytes zero; a blank is a space */
  uint16_t fg;      /* xterm-256 index, or XAIOS_SCREEN_DEFAULT */
  uint16_t bg;
  uint8_t bold;
  uint8_t pad[3];
} xaios_screen_cell_t;

typedef struct xaios_screen {
  uint32_t rows;
  uint32_t columns;
  /* The terminal model's cursor, where the next painted byte lands. */
  uint32_t cursor_row;
  uint32_t cursor_column;
  uint32_t cursor_hidden;
  uint32_t alternate; /* inside ESC[?1049h .. ESC[?1049l */
  /* The model's current attributes, for painting. */
  uint16_t fg;
  uint16_t bg;
  uint8_t bold;
  uint8_t pad[3];
  uint32_t shown_valid; /* the terminal shows `shown`; else present in full */
  uint32_t shown_cursor_hidden;
  uint32_t shown_cursor_row;
  uint32_t shown_cursor_column;
  uint32_t incomplete; /* the last present was cut short by its capacity */
  uint32_t cells_capacity;
  xaios_screen_cell_t *next;  /* what the program wants shown */
  xaios_screen_cell_t *shown; /* what the terminal shows */
} xaios_screen_t;

/* Both grids must hold at least rows * columns cells; XAIOS_SCREEN_MAX_CELLS
   holds any size. Clears the grid and marks the terminal unknown, so the
   first present is a full one. */
void xaios_screen_init(xaios_screen_t *screen, xaios_screen_cell_t *next,
                       xaios_screen_cell_t *shown, uint32_t cells_capacity,
                       uint32_t rows, uint32_t columns);
void xaios_screen_resize(xaios_screen_t *screen, uint32_t rows,
                         uint32_t columns);
/* The terminal no longer shows what the model thinks: the next present is
   a full one. For a program that left and re-entered the alternate screen,
   or shared the terminal with something else. */
void xaios_screen_invalidate(xaios_screen_t *screen);
/* Blank the grid to one background. */
void xaios_screen_clear(xaios_screen_t *screen, uint16_t bg);
/* Draw text at a cell; returns the cells written. Stops at the right edge. */
uint32_t xaios_screen_put(xaios_screen_t *screen, uint32_t row,
                          uint32_t column, const char *utf8, uint16_t fg,
                          uint16_t bg, uint8_t bold);
/* Interpret terminal output into the grid: printable UTF-8, CR, LF, SGR
   (0, 1, 30-37, 90-97, 40-47, 100-107, 38;5;n, 48;5;n, 39, 49), cursor
   position (H, f), clear screen (J), cursor show/hide (?25h/l), and the
   alternate screen (?1049h/l). Other sequences are consumed and ignored.
   Output that scrolls is not modelled: this is for programs that draw a
   screen, not for a stream. */
void xaios_screen_paint(xaios_screen_t *screen, const char *bytes,
                        uint64_t length);
/* Write the bytes that bring the terminal to `next`. Returns the length;
   zero when nothing changed. Only cells that were written are recorded as
   shown, so a present cut short by `capacity` is finished by the next one.
   Ends with attributes reset and the cursor placed and shown or hidden as
   the model has it. */
uint64_t xaios_screen_present(xaios_screen_t *screen, char *output,
                              uint64_t capacity);
/* Whether a present would write anything. */
int xaios_screen_dirty(const xaios_screen_t *screen);

/* Keys, decoded from the bytes a terminal sends. */
typedef enum xaios_key {
  XAIOS_KEY_NONE = 0,
  XAIOS_KEY_CHAR,  /* code is the byte or code point */
  XAIOS_KEY_ENTER,
  XAIOS_KEY_TAB,
  XAIOS_KEY_BACKSPACE,
  XAIOS_KEY_ESCAPE,
  XAIOS_KEY_UP,
  XAIOS_KEY_DOWN,
  XAIOS_KEY_LEFT,
  XAIOS_KEY_RIGHT,
  XAIOS_KEY_HOME,
  XAIOS_KEY_END,
  XAIOS_KEY_PAGE_UP,
  XAIOS_KEY_PAGE_DOWN,
  XAIOS_KEY_INSERT,
  XAIOS_KEY_DELETE,
  XAIOS_KEY_FUNCTION /* code is 1..12 */
} xaios_key_t;

/* Decode one key from the front of `bytes`. Returns the bytes consumed, or
   zero when the buffer holds the start of a sequence and needs more. A
   bare escape at the end of the buffer is the Escape key. Sequences the
   decoder does not know are consumed as XAIOS_KEY_NONE. */
uint32_t xaios_screen_read_key(const uint8_t *bytes, uint32_t length,
                               xaios_key_t *key, uint32_t *code);

#endif
