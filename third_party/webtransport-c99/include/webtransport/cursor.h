/* WebTransport C99: a read cursor over a byte range.
 *
 * Parsers in this library take a cursor rather than a pointer and a length,
 * because a parser that threads `(const uint8_t **p, size_t *remaining)` through
 * every field has to get a bounds check right at every call site, and one that
 * forgets reads past the end of a peer's buffer. Here every read is bounds
 * checked, a failed read leaves the cursor empty and marked, and a parser that
 * does not check each step still cannot read out of bounds. It can accept a
 * truncated message if it never asks whether the cursor ended up exactly at the
 * end, which is why `wt_cursor_at_end` exists and every message parser in this
 * library checks it.
 *
 * The cursor does not own the bytes. It is a view, valid exactly as long as the
 * buffer it was made from, and nothing here copies.
 */

#ifndef WEBTRANSPORT_CURSOR_H
#define WEBTRANSPORT_CURSOR_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct wt_cursor {
  const uint8_t *data;
  size_t len;
  size_t offset;
  /* Set by the first read that could not be satisfied, and never cleared. A
   * parser may therefore read a whole structure and check once at the end: the
   * first failure sticks and every later read is a no-op returning zero. */
  int failed;
} wt_cursor_t;

/* A cursor over `len` bytes at `data`. `data` may be NULL only when `len` is
 * zero, which is a valid empty cursor -- a zero-length QUIC frame payload, for
 * instance -- rather than an error. */
wt_cursor_t wt_cursor_init(const uint8_t *data, size_t len);

/* Bytes not yet read. Zero once the cursor has failed, because a failed read
 * consumes everything. */
size_t wt_cursor_remaining(const wt_cursor_t *c);

/* Whether every byte has been read and nothing failed. The check that makes a
 * parser reject trailing bytes rather than silently ignoring them. */
int wt_cursor_at_end(const wt_cursor_t *c);

int wt_cursor_failed(const wt_cursor_t *c);

/* Reads. Each returns zero when it cannot be satisfied and marks the cursor
 * failed; a parser reading a structure where every field is required may check
 * once, with wt_cursor_failed, after the last read. */
uint8_t wt_cursor_u8(wt_cursor_t *c);
uint16_t wt_cursor_u16(wt_cursor_t *c);
uint32_t wt_cursor_u24(wt_cursor_t *c);
uint32_t wt_cursor_u32(wt_cursor_t *c);
uint64_t wt_cursor_u64(wt_cursor_t *c);

/* A view of the next `n` bytes, advancing past them, or NULL and a failed
 * cursor. Zero bytes is a valid request and returns a pointer into the range
 * (never NULL for a non-NULL cursor), which the reader functions rely on. */
const uint8_t *wt_cursor_bytes(wt_cursor_t *c, size_t n);

/* Advance without reading. */
wt_status_t wt_cursor_skip(wt_cursor_t *c, size_t n);

/* The bytes remaining, as a view, without advancing. Used to hand a
 * length-delimited region to a sub-parser, which is how this library keeps a
 * nested structure from reading past its own end. */
const uint8_t *wt_cursor_rest(const wt_cursor_t *c, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_CURSOR_H */
