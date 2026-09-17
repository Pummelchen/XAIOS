#include <xaios_screen.h>

#include "xaios_screen_internal.h"

/* The key decoder: freestanding, linked into programs with no libc. */

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
      uint32_t n = xaios_screen_utf8_length(b);
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
