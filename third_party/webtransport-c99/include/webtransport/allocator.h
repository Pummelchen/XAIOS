/* WebTransport C99: the allocator interface.
 *
 * Every allocation the protocol core makes goes through a wt_allocator_t that
 * the caller supplies, and the default is malloc. That is not decoration: a
 * QUIC endpoint is a long-lived, peer-driven state machine, and the two
 * questions an operator asks when one misbehaves are "how much memory does this
 * cost" and "did every byte come back". Both are answerable only if the caller
 * owns the allocator, and a counting allocator that fails the test suite when
 * the outstanding byte count is not zero is how the "shutdown must free every
 * owned resource deterministically" rule in the plan is actually enforced.
 *
 * WHY free AND realloc TAKE A SIZE. free(ptr) can be implemented by a caller
 * that stores the size in a header, but a realloc(old, new) cannot: the
 * allocator would have to know the old size to copy the right number of bytes.
 * Passing it keeps the accounting exact and lets an allocator that tracks
 * memory hand back a truthful figure without trusting this library. The size
 * passed is always the size that was requested, never a rounded or guessed one.
 */

#ifndef WEBTRANSPORT_ALLOCATOR_H
#define WEBTRANSPORT_ALLOCATOR_H

#include <stddef.h>

#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct wt_allocator {
  /* Passed back to every function below untouched. The library never reads it,
   * which is what lets a caller put a counter, a pool, or an arena there. */
  void *context;

  /* Returns a block of at least `size` bytes aligned for any type, or NULL.
   * Called with a non-zero size only: a zero-size request reaches this function as
   * a request for ONE byte, and `free` below is told the same one byte, so an
   * allocator that accounts by the size it is given stays balanced. */
  void *(*alloc)(void *context, size_t size);

  /* Returns a block of at least `new_size` bytes whose first
   * min(old_size, new_size) bytes equal `ptr`'s, and releases `ptr`. Returns
   * NULL and leaves `ptr` valid on failure, like the C standard's realloc. May
   * assume `ptr` came from this allocator's alloc and that `old_size` is the
   * size it was asked for. */
  void *(*realloc)(void *context, void *ptr, size_t old_size, size_t new_size);

  /* Releases `ptr`, which came from this allocator's alloc or realloc, and
   * whose requested size was `size`. */
  void (*free)(void *context, void *ptr, size_t size);
} wt_allocator_t;

/* An allocator backed by malloc, realloc and free, with a NULL context.
 * Returns a value, not a pointer, so it may be used as
 * `wt_buf_init(&buf, wt_allocator_default())` without a lifetime question. */
wt_allocator_t wt_allocator_default(void);

/* The three operations, bound to an allocator.
 *
 * `a` may be NULL, which means the default allocator; that keeps a caller from
 * having to spell it out for a short-lived object and still routes the
 * allocation through one place.
 *
 * A request of size zero succeeds and returns a unique, freeable pointer rather
 * than NULL, so that NULL always means "the allocation failed" and never "you
 * asked for nothing". The pointer must still be released with the same size,
 * zero.
 */
void *wt_alloc(const wt_allocator_t *a, size_t size);

/* Zeroed allocation of count elements of elem_size bytes. The multiplication is
 * checked, so a count and an element size that a peer influenced cannot wrap
 * into a small allocation. Returns WT_ERR_OVERFLOW through `out_status` --
 * and NULL -- rather than allocating the wrong size. */
void *wt_calloc_array(const wt_allocator_t *a, size_t count, size_t elem_size,
                      wt_status_t *out_status);

/* Allocation of count elements, with the same checked multiplication. `out_status`
 * is WT_ERR_OVERFLOW when the product wraps and WT_ERR_OUT_OF_MEMORY when the
 * allocator returns NULL; NULL is returned in both failing cases, so a caller can
 * tell a refused size from an exhausted allocator. */
void *wt_alloc_array(const wt_allocator_t *a, size_t count, size_t elem_size,
                     wt_status_t *out_status);

/* Resize. On failure the original block is untouched and still valid, and NULL
 * is returned; the caller keeps ownership of it. */
void *wt_realloc(const wt_allocator_t *a, void *ptr, size_t old_size,
                 size_t new_size);

/* Release. Safe on a NULL pointer, in which case nothing happens -- a
 * documented convenience so that a cleanup path does not need a guard at every
 * step. */
void wt_dealloc(const wt_allocator_t *a, void *ptr, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_ALLOCATOR_H */
