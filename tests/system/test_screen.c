/* Host-side test of the screen framework: a painted frame presents in full
   once, an unchanged frame presents nothing, a changed cell presents one
   positioned run, a present cut short by capacity is finished by the next,
   and the key decoder reads what terminals send. */
#include <xaios_screen.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static xaios_screen_cell_t g_next[XAIOS_SCREEN_MAX_CELLS];
static xaios_screen_cell_t g_shown[XAIOS_SCREEN_MAX_CELLS];
static char g_out[1 << 20];

static int g_failures;

#define CHECK(cond)                                                          \
  do {                                                                       \
    if (!(cond)) {                                                           \
      ++g_failures;                                                          \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);        \
    }                                                                        \
  } while (0)

static int contains(const char *haystack, size_t length, const char *needle) {
  size_t n = strlen(needle);
  if (n > length) return 0;
  for (size_t i = 0; i + n <= length; ++i) {
    if (memcmp(haystack + i, needle, n) == 0) return 1;
  }
  return 0;
}

static size_t count_of(const char *haystack, size_t length, const char *needle) {
  size_t n = strlen(needle);
  size_t found = 0;
  for (size_t i = 0; i + n <= length; ++i) {
    if (memcmp(haystack + i, needle, n) == 0) { ++found; i += n - 1; }
  }
  return found;
}

static void test_present_only_changes(void) {
  xaios_screen_t screen;
  xaios_screen_init(&screen, g_next, g_shown, XAIOS_SCREEN_MAX_CELLS, 24U, 80U);
  const char frame[] = "\033[2J\033[H\033[1;38;5;120mCPU 12%\033[0m\r\n"
                       "\033[48;5;68m          \033[0m\r\nline three";
  xaios_screen_paint(&screen, frame, sizeof(frame) - 1U);
  size_t full = (size_t)xaios_screen_present(&screen, g_out, sizeof(g_out));
  CHECK(full != 0U);
  CHECK(contains(g_out, full, "\033[2J"));
  CHECK(contains(g_out, full, "CPU 12%"));
  CHECK(contains(g_out, full, "line three"));
  CHECK(contains(g_out, full, "\033[0;1;38;5;120m"));
  CHECK(contains(g_out, full, "\033[0;48;5;68m"));
  /* The same frame again: nothing to send. */
  xaios_screen_clear(&screen, XAIOS_SCREEN_DEFAULT);
  xaios_screen_paint(&screen, frame, sizeof(frame) - 1U);
  CHECK(xaios_screen_present(&screen, g_out, sizeof(g_out)) == 0U);
  CHECK(!xaios_screen_dirty(&screen));
  /* One figure changes: one positioned run, nothing else. */
  const char frame2[] = "\033[2J\033[H\033[1;38;5;120mCPU 13%\033[0m\r\n"
                        "\033[48;5;68m          \033[0m\r\nline three";
  xaios_screen_clear(&screen, XAIOS_SCREEN_DEFAULT);
  xaios_screen_paint(&screen, frame2, sizeof(frame2) - 1U);
  CHECK(xaios_screen_dirty(&screen));
  size_t diff = (size_t)xaios_screen_present(&screen, g_out, sizeof(g_out));
  CHECK(diff != 0U && diff < 40U);
  CHECK(contains(g_out, diff, "\033[1;6H"));
  CHECK(contains(g_out, diff, "3"));
  CHECK(!contains(g_out, diff, "line three"));
  CHECK(!contains(g_out, diff, "\033[2J"));
  CHECK(count_of(g_out, diff, "H") >= 1U);
}

static void test_cursor_alone(void) {
  xaios_screen_t screen;
  xaios_screen_init(&screen, g_next, g_shown, XAIOS_SCREEN_MAX_CELLS, 24U, 80U);
  xaios_screen_paint(&screen, "\033[2J\033[Hhello\033[3;4H", 18U);
  size_t n = (size_t)xaios_screen_present(&screen, g_out, sizeof(g_out));
  CHECK(contains(g_out, n, "\033[3;4H\033[?25h"));
  /* Only the cursor moves: the present carries just the move. */
  xaios_screen_paint(&screen, "\033[5;6H", 6U);
  n = (size_t)xaios_screen_present(&screen, g_out, sizeof(g_out));
  CHECK(n != 0U && n < 24U);
  CHECK(contains(g_out, n, "\033[5;6H\033[?25h"));
  /* Hidden: no position is sent. */
  xaios_screen_paint(&screen, "\033[?25l", 6U);
  n = (size_t)xaios_screen_present(&screen, g_out, sizeof(g_out));
  CHECK(contains(g_out, n, "\033[?25l"));
  CHECK(!contains(g_out, n, "H\033[?25h"));
}

static void test_capacity_continues(void) {
  xaios_screen_t screen;
  xaios_screen_init(&screen, g_next, g_shown, XAIOS_SCREEN_MAX_CELLS, 10U, 40U);
  (void)xaios_screen_present(&screen, g_out, sizeof(g_out));
  for (uint32_t r = 0U; r < 10U; ++r) {
    xaios_screen_put(&screen, r, 0U, "0123456789012345678901234567890123456789",
                     r + 1U, XAIOS_SCREEN_DEFAULT, 0U);
  }
  size_t total = 0U;
  uint32_t presents = 0U;
  for (;;) {
    size_t n = (size_t)xaios_screen_present(&screen, g_out, 200U);
    if (n == 0U) break;
    CHECK(n <= 200U);
    total += n;
    ++presents;
    CHECK(presents < 100U);
    if (presents >= 100U) break;
  }
  CHECK(presents > 1U);
  CHECK(!xaios_screen_dirty(&screen));
  CHECK(total > 400U);
}

static void test_resize_is_full(void) {
  xaios_screen_t screen;
  xaios_screen_init(&screen, g_next, g_shown, XAIOS_SCREEN_MAX_CELLS, 24U, 80U);
  xaios_screen_paint(&screen, "\033[2J\033[Hx", 8U);
  (void)xaios_screen_present(&screen, g_out, sizeof(g_out));
  xaios_screen_resize(&screen, 30U, 100U);
  CHECK(screen.rows == 30U && screen.columns == 100U);
  xaios_screen_paint(&screen, "\033[2J\033[Hx", 8U);
  size_t n = (size_t)xaios_screen_present(&screen, g_out, sizeof(g_out));
  CHECK(contains(g_out, n, "\033[2J"));
}

static void test_utf8_and_wrap(void) {
  xaios_screen_t screen;
  xaios_screen_init(&screen, g_next, g_shown, XAIOS_SCREEN_MAX_CELLS, 3U, 4U);
  /* Five glyphs on a four-column row wrap to the next row. */
  xaios_screen_paint(&screen, "\033[2J\033[H\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80", 22U);
  CHECK(screen.cursor_row == 1U && screen.cursor_column == 1U);
  CHECK(g_next[3].glyph[0] == 0xe2U && g_next[3].glyph[2] == 0x80U);
  CHECK(g_next[4].glyph[0] == 0xe2U);
  CHECK(g_next[5].glyph[0] == ' ');
  size_t n = (size_t)xaios_screen_present(&screen, g_out, sizeof(g_out));
  CHECK(count_of(g_out, n, "\xe2\x94\x80") == 5U);
}

static void test_keys(void) {
  xaios_key_t key;
  uint32_t code;
  CHECK(xaios_screen_read_key((const uint8_t *)"q", 1U, &key, &code) == 1U &&
        key == XAIOS_KEY_CHAR && code == 'q');
  CHECK(xaios_screen_read_key((const uint8_t *)"\033[A", 3U, &key, &code) == 3U &&
        key == XAIOS_KEY_UP);
  CHECK(xaios_screen_read_key((const uint8_t *)"\033[6~", 4U, &key, &code) == 4U &&
        key == XAIOS_KEY_PAGE_DOWN);
  CHECK(xaios_screen_read_key((const uint8_t *)"\033[21~", 5U, &key, &code) == 5U &&
        key == XAIOS_KEY_FUNCTION && code == 10U);
  CHECK(xaios_screen_read_key((const uint8_t *)"\033OP", 3U, &key, &code) == 3U &&
        key == XAIOS_KEY_FUNCTION && code == 1U);
  CHECK(xaios_screen_read_key((const uint8_t *)"\033[1;5C", 6U, &key, &code) == 6U &&
        key == XAIOS_KEY_RIGHT);
  CHECK(xaios_screen_read_key((const uint8_t *)"\033", 1U, &key, &code) == 1U &&
        key == XAIOS_KEY_ESCAPE);
  CHECK(xaios_screen_read_key((const uint8_t *)"\033[", 2U, &key, &code) == 0U);
  CHECK(xaios_screen_read_key((const uint8_t *)"\r", 1U, &key, &code) == 1U &&
        key == XAIOS_KEY_ENTER);
  CHECK(xaios_screen_read_key((const uint8_t *)"\x7f", 1U, &key, &code) == 1U &&
        key == XAIOS_KEY_BACKSPACE);
  CHECK(xaios_screen_read_key((const uint8_t *)"\xc3\xa9", 2U, &key, &code) == 2U &&
        key == XAIOS_KEY_CHAR && code == 0xe9U);
  CHECK(xaios_screen_read_key((const uint8_t *)"\xc3", 1U, &key, &code) == 0U);
}

int main(void) {
  test_present_only_changes();
  test_cursor_alone();
  test_capacity_continues();
  test_resize_is_full();
  test_utf8_and_wrap();
  test_keys();
  if (g_failures != 0) {
    fprintf(stderr, "test-screen: %d failure(s)\n", g_failures);
    return 1;
  }
  printf("test-screen: ok\n");
  return 0;
}
