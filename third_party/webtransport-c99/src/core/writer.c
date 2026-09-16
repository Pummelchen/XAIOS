/* The two-pass writer. See webtransport/writer.h.
 *
 * `wt_writer_put` mirrors the cursor's take: it tests `len > cap - offset`, so
 * `offset <= cap` is the invariant that makes the test sound, and it is
 * maintained because offset only moves by an amount the test approved. A
 * measuring writer claims a capacity large enough for any structure this library
 * builds and refuses past it, which is what keeps "measure" from turning into
 * "measure forever".
 */

#include "webtransport/writer.h"
#include "webtransport/endian.h"

#include <string.h>

/* A measured structure larger than this is a length computation that has gone
 * wrong rather than a message, because the largest thing this library builds is
 * a ClientHello or an HTTP/3 SETTINGS frame, both far below it. */
#define WT_WRITER_MEASURE_CAPACITY ((size_t)1U << 20)

wt_writer_t wt_writer_init(uint8_t *data, size_t cap) {
  wt_writer_t w;
  w.data = data;
  w.cap = (data == NULL) ? 0U : cap;
  w.offset = 0U;
  w.copy = (data != NULL) ? 1 : 0;
  /* A writer with no destination and copy set would be a caller error; treat it
   * as immediately overflowing so it cannot silently count nothing. */
  w.overflow = (data == NULL && cap != 0U) ? 1 : 0;
  return w;
}

wt_writer_t wt_writer_measure(void) {
  wt_writer_t w;
  w.data = NULL;
  w.cap = WT_WRITER_MEASURE_CAPACITY;
  w.offset = 0U;
  w.copy = 0;
  w.overflow = 0;
  return w;
}

size_t wt_writer_offset(const wt_writer_t *w) {
  return (w == NULL) ? 0U : w->offset;
}

int wt_writer_ok(const wt_writer_t *w) {
  return (w == NULL) ? 0 : (w->overflow == 0);
}

int wt_writer_is_measuring(const wt_writer_t *w) {
  return (w == NULL) ? 0 : (w->copy == 0);
}

static void wt_writer_put(wt_writer_t *w, const void *data, size_t len) {
  if (w == NULL || w->overflow) return;
  if (len > w->cap - w->offset) {
    w->overflow = 1;
    return;
  }
  if (w->copy && len != 0U) {
    /* `data` may be NULL only for a zero-length write, which the length test
     * above already admitted; a non-NULL data with a non-zero length is the
     * caller's contract. */
    memcpy(w->data + w->offset, data, len);
  }
  w->offset += len;
}

void wt_writer_u8(wt_writer_t *w, uint8_t value) {
  wt_writer_put(w, &value, 1U);
}

void wt_writer_u16(wt_writer_t *w, uint16_t value) {
  uint8_t bytes[WT_BE16_SIZE];
  wt_store_be16(bytes, value);
  wt_writer_put(w, bytes, sizeof(bytes));
}

void wt_writer_u24(wt_writer_t *w, uint32_t value) {
  uint8_t bytes[WT_BE24_SIZE];
  wt_store_be24(bytes, value);
  wt_writer_put(w, bytes, sizeof(bytes));
}

void wt_writer_u32(wt_writer_t *w, uint32_t value) {
  uint8_t bytes[WT_BE32_SIZE];
  wt_store_be32(bytes, value);
  wt_writer_put(w, bytes, sizeof(bytes));
}

void wt_writer_u64(wt_writer_t *w, uint64_t value) {
  uint8_t bytes[WT_BE64_SIZE];
  wt_store_be64(bytes, value);
  wt_writer_put(w, bytes, sizeof(bytes));
}

void wt_writer_bytes(wt_writer_t *w, const void *data, size_t len) {
  wt_writer_put(w, data, len);
}

uint8_t *wt_writer_reserve(wt_writer_t *w, size_t n) {
  uint8_t *at;
  if (w == NULL || w->overflow) return NULL;
  if (n > w->cap - w->offset) {
    w->overflow = 1;
    return NULL;
  }
  if (!w->copy) {
    /* A measuring writer has no storage to hand back. The offset still moves,
     * so the measurement is right, and a caller that needs the pointer must not
     * be using a measurement -- which is what the NULL says. */
    w->offset += n;
    return NULL;
  }
  at = w->data + w->offset;
  w->offset += n;
  return at;
}

wt_status_t wt_writer_patch(wt_writer_t *w, size_t offset, const void *data,
                            size_t n) {
  if (w == NULL || data == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (w->overflow) return WT_ERR_LIMIT;
  if (!w->copy) return WT_ERR_LIMIT;
  /* Patching is for a length that was reserved before its value was known, so
   * the region must already be inside what has been written. */
  if (offset > w->offset || n > w->offset - offset) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  memcpy(w->data + offset, data, n);
  return WT_OK;
}
