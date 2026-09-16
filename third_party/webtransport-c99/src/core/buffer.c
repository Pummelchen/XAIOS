/* The growable buffer. See webtransport/buffer.h.
 *
 * The growth policy is the only interesting part. `wt_buf_reserve(additional)`
 * asks for `len + additional` and grows the capacity to the larger of that and
 * twice the current capacity, so appending byte by byte is amortized linear
 * rather than quadratic -- and the doubling is bounded by WT_BUF_MAX_CAPACITY so
 * that a peer which can make the buffer grow cannot make it grow without limit.
 * A refusal past the bound is WT_ERR_LIMIT and not WT_ERR_OUT_OF_MEMORY, because
 * the two mean different things to a caller deciding whether to close the
 * connection.
 */

#include "webtransport/buffer.h"
#include "webtransport/checked.h"

#include <string.h>

wt_buf_t wt_buf_init(const wt_allocator_t *alloc) {
  wt_buf_t b;
  b.data = NULL;
  b.len = 0U;
  b.cap = 0U;
  /* The allocator is resolved now rather than at each use, so that the buffer
   * carries one answer to "who owns my storage" and freeing it cannot be done
   * with a different one. */
  b.alloc = wt_allocator_default();
  if (alloc != NULL) b.alloc = *alloc;
  if (b.alloc.alloc == NULL || b.alloc.realloc == NULL || b.alloc.free == NULL) {
    b.alloc = wt_allocator_default();
  }
  return b;
}

void wt_buf_free(wt_buf_t *b) {
  if (b == NULL) return;
  wt_dealloc(&b->alloc, b->data, b->cap);
  b->data = NULL;
  b->len = 0U;
  b->cap = 0U;
}

wt_status_t wt_buf_reserve(wt_buf_t *b, size_t additional) {
  size_t needed = 0U;
  size_t grown = 0U;
  uint8_t *block = NULL;

  if (b == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (additional > WT_BUF_MAX_CAPACITY) return WT_ERR_LIMIT;
  if (wt_checked_add_size(b->len, additional, &needed) != WT_OK) {
    return WT_ERR_OVERFLOW;
  }
  if (needed > WT_BUF_MAX_CAPACITY) return WT_ERR_LIMIT;
  if (needed <= b->cap) return WT_OK;

  /* Double, but never past the bound, and never less than what was asked for. */
  grown = (b->cap > WT_BUF_MAX_CAPACITY / 2U) ? WT_BUF_MAX_CAPACITY : b->cap * 2U;
  if (grown < needed) grown = needed;

  block = (uint8_t *)wt_realloc(&b->alloc, b->data, b->cap, grown);
  if (block == NULL) return WT_ERR_OUT_OF_MEMORY;
  b->data = block;
  b->cap = grown;
  return WT_OK;
}

wt_status_t wt_buf_append(wt_buf_t *b, const void *data, size_t len) {
  wt_status_t status;
  if (b == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (len == 0U) return WT_OK;
  if (data == NULL) return WT_ERR_INVALID_ARGUMENT;
  status = wt_buf_reserve(b, len);
  if (status != WT_OK) return status;
  memcpy(b->data + b->len, data, len);
  b->len += len;
  return WT_OK;
}

wt_status_t wt_buf_append_u8(wt_buf_t *b, uint8_t value) {
  return wt_buf_append(b, &value, 1U);
}

uint8_t *wt_buf_reserve_tail(wt_buf_t *b, size_t len) {
  uint8_t *at;
  if (b == NULL) return NULL;
  if (wt_buf_reserve(b, len) != WT_OK) return NULL;
  at = b->data + b->len;
  b->len += len;
  return at;
}

void wt_buf_consume(wt_buf_t *b, size_t n) {
  if (b == NULL) return;
  if (n == 0U) return;
  if (n >= b->len) {
    b->len = 0U;
    return;
  }
  memmove(b->data, b->data + n, b->len - n);
  b->len -= n;
}

void wt_buf_clear(wt_buf_t *b) {
  if (b == NULL) return;
  b->len = 0U;
}

void wt_buf_shrink_to_fit(wt_buf_t *b) {
  uint8_t *block;
  if (b == NULL) return;
  if (b->len == b->cap) return;
  /* Shrinking to zero releases everything and leaves the buffer empty but
   * usable: the next append allocates again through the same allocator. */
  if (b->len == 0U) {
    wt_dealloc(&b->alloc, b->data, b->cap);
    b->data = NULL;
    b->cap = 0U;
    return;
  }
  block = (uint8_t *)wt_realloc(&b->alloc, b->data, b->cap, b->len);
  /* Best effort by contract: on failure the buffer keeps its larger block and
   * remains valid, which is why no status is returned. */
  if (block != NULL) {
    b->data = block;
    b->cap = b->len;
  }
}

wt_cursor_t wt_buf_cursor(const wt_buf_t *b) {
  if (b == NULL) return wt_cursor_init(NULL, 0U);
  return wt_cursor_init(b->data, b->len);
}

uint8_t *wt_buf_copy_out(const wt_buf_t *b, size_t offset, size_t len,
                         const wt_allocator_t *alloc,
                         wt_status_t *out_status) {
  uint8_t *copy;
  if (out_status != NULL) *out_status = WT_OK;
  if (b == NULL || (len != 0U && b->data == NULL)) {
    if (out_status != NULL) *out_status = WT_ERR_INVALID_ARGUMENT;
    return NULL;
  }
  if (offset > b->len || len > b->len - offset) {
    if (out_status != NULL) *out_status = WT_ERR_INVALID_ARGUMENT;
    return NULL;
  }
  copy = (uint8_t *)wt_alloc(alloc, len);
  if (copy == NULL) {
    if (out_status != NULL) *out_status = WT_ERR_OUT_OF_MEMORY;
    return NULL;
  }
  if (len != 0U) memcpy(copy, b->data + offset, len);
  return copy;
}
