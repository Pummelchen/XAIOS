/* The read cursor. See webtransport/cursor.h.
 *
 * The whole safety argument is in one place: `take` is the only function that
 * advances the offset, it checks `n > len - offset` rather than `offset + n >
 * len`, and it marks the cursor failed before returning NULL. Because the
 * subtraction is written that way, an offset that somehow exceeded the length
 * would make the difference wrap to a huge value and the check would pass -- so
 * the invariant `offset <= len` is what makes the check sound, and it is
 * maintained by the fact that offset only ever moves by an amount the check
 * approved. Written as an addition, a caller could overflow `offset + n` and
 * pass. That is the reason for the shape, not style.
 */

#include "webtransport/cursor.h"
#include "webtransport/endian.h"

wt_cursor_t wt_cursor_init(const uint8_t *data, size_t len) {
  wt_cursor_t c;
  c.data = data;
  c.len = (data == NULL) ? 0U : len;
  c.offset = 0U;
  c.failed = 0;
  return c;
}

size_t wt_cursor_remaining(const wt_cursor_t *c) {
  if (c == NULL || c->failed) return 0U;
  return c->len - c->offset;
}

int wt_cursor_at_end(const wt_cursor_t *c) {
  if (c == NULL) return 0;
  if (c->failed) return 0;
  return c->offset == c->len;
}

int wt_cursor_failed(const wt_cursor_t *c) { return (c == NULL) ? 1 : c->failed; }

static const uint8_t *wt_cursor_take(wt_cursor_t *c, size_t n) {
  const uint8_t *result;
  if (c == NULL || c->failed) return NULL;
  if (n > c->len - c->offset) {
    c->failed = 1;
    return NULL;
  }
  result = c->data + c->offset;
  c->offset += n;
  return result;
}

uint8_t wt_cursor_u8(wt_cursor_t *c) {
  const uint8_t *p = wt_cursor_take(c, 1U);
  return (p == NULL) ? 0U : p[0];
}

uint16_t wt_cursor_u16(wt_cursor_t *c) {
  const uint8_t *p = wt_cursor_take(c, WT_BE16_SIZE);
  return (p == NULL) ? 0U : wt_load_be16(p);
}

uint32_t wt_cursor_u24(wt_cursor_t *c) {
  const uint8_t *p = wt_cursor_take(c, WT_BE24_SIZE);
  return (p == NULL) ? 0U : wt_load_be24(p);
}

uint32_t wt_cursor_u32(wt_cursor_t *c) {
  const uint8_t *p = wt_cursor_take(c, WT_BE32_SIZE);
  return (p == NULL) ? 0U : wt_load_be32(p);
}

uint64_t wt_cursor_u64(wt_cursor_t *c) {
  const uint8_t *p = wt_cursor_take(c, WT_BE64_SIZE);
  return (p == NULL) ? 0U : wt_load_be64(p);
}

const uint8_t *wt_cursor_bytes(wt_cursor_t *c, size_t n) {
  return wt_cursor_take(c, n);
}

wt_status_t wt_cursor_skip(wt_cursor_t *c, size_t n) {
  if (c == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (wt_cursor_take(c, n) == NULL) return WT_ERR_TRUNCATED;
  return WT_OK;
}

const uint8_t *wt_cursor_rest(const wt_cursor_t *c, size_t *out_len) {
  if (out_len != NULL) *out_len = 0U;
  if (c == NULL || c->failed) return NULL;
  if (out_len != NULL) *out_len = c->len - c->offset;
  return c->data + c->offset;
}
