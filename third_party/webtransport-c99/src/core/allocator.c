/* The allocator interface and its default. See webtransport/allocator.h. */

#include "webtransport/allocator.h"
#include "webtransport/checked.h"

#include <stdlib.h>
#include <string.h>

/* A zero-size request must still produce a unique, freeable pointer, so the
 * default allocator is asked for one byte. The size passed back to free is the
 * one the caller asked for -- zero -- which is why the default's free ignores
 * it: realloc and free are the only two places where the requested size and the
 * allocated size may differ, and they are the two the interface hands the size
 * to anyway. */
#define WT_ALLOC_MINIMUM ((size_t)1)

static void *wt_default_alloc(void *context, size_t size) {
  (void)context;
  if (size == 0U) size = WT_ALLOC_MINIMUM;
  return malloc(size);
}

static void *wt_default_realloc(void *context, void *ptr, size_t old_size,
                                size_t new_size) {
  (void)context;
  (void)old_size;
  if (new_size == 0U) new_size = WT_ALLOC_MINIMUM;
  return realloc(ptr, new_size);
}

static void wt_default_free(void *context, void *ptr, size_t size) {
  (void)context;
  (void)size;
  free(ptr);
}

wt_allocator_t wt_allocator_default(void) {
  wt_allocator_t a;
  a.context = NULL;
  a.alloc = wt_default_alloc;
  a.realloc = wt_default_realloc;
  a.free = wt_default_free;
  return a;
}

/* Whether an allocator can be used. A caller that zeroed a wt_allocator_t and
 * passed it means "the default", so a missing trio of functions selects it
 * rather than failing -- and a partially filled one is a bug in the caller, so
 * it selects the default too rather than calling through a NULL pointer. */
static int wt_allocator_is_usable(const wt_allocator_t *a) {
  if (a == NULL) return 0;
  return a->alloc != NULL && a->realloc != NULL && a->free != NULL;
}

static wt_allocator_t wt_allocator_resolve(const wt_allocator_t *a) {
  if (!wt_allocator_is_usable(a)) return wt_allocator_default();
  return *a;
}

/* The size an allocator is TOLD for a request of `size` bytes.
 *
 * The header states two rules that only agree if the answer is "at least one": `alloc` is "called with a non-zero
 * size only", and "a request of size zero succeeds and returns a unique, freeable pointer". One byte is what both
 * require, and it has to be substituted in the FREE path too -- an allocator is entitled to subtract the size it
 * is told, so a block allocated as one byte and freed as zero is a block it reports as still live. That asymmetry
 * is what an audit's strict allocator and this tree's own counting allocator both showed. */
static size_t wt_requested_size(size_t size) { return size == 0U ? 1U : size; }

void *wt_alloc(const wt_allocator_t *a, size_t size) {
  wt_allocator_t resolved = wt_allocator_resolve(a);
  return resolved.alloc(resolved.context, wt_requested_size(size));
}

void *wt_alloc_array(const wt_allocator_t *a, size_t count, size_t elem_size,
                     wt_status_t *out_status) {
  size_t total = 0U;
  void *block;
  wt_status_t status = wt_checked_mul_size(count, elem_size, &total);
  if (status != WT_OK) {
    if (out_status != NULL) *out_status = WT_ERR_OVERFLOW;
    return NULL;
  }
  block = wt_alloc(a, total);
  if (block == NULL) {
    if (out_status != NULL) *out_status = WT_ERR_OUT_OF_MEMORY;
    return NULL;
  }
  if (out_status != NULL) *out_status = WT_OK;
  return block;
}

void *wt_calloc_array(const wt_allocator_t *a, size_t count, size_t elem_size,
                      wt_status_t *out_status) {
  size_t total = 0U;
  void *block;
  wt_status_t status = wt_checked_mul_size(count, elem_size, &total);
  if (status != WT_OK) {
    if (out_status != NULL) *out_status = WT_ERR_OVERFLOW;
    return NULL;
  }
  block = wt_alloc(a, total);
  if (block == NULL) {
    if (out_status != NULL) *out_status = WT_ERR_OUT_OF_MEMORY;
    return NULL;
  }
  /* The count and element size that were checked are the ones zeroed, not the
   * product recomputed: a caller that passes a count whose product wrapped is
   * refused above, so this memsets exactly the bytes that were asked for. */
  memset(block, 0, total);
  if (out_status != NULL) *out_status = WT_OK;
  return block;
}

void *wt_realloc(const wt_allocator_t *a, void *ptr, size_t old_size,
                 size_t new_size) {
  wt_allocator_t resolved = wt_allocator_resolve(a);
  if (ptr == NULL) return resolved.alloc(resolved.context, wt_requested_size(new_size));
  return resolved.realloc(resolved.context, ptr, old_size, new_size);
}

void wt_dealloc(const wt_allocator_t *a, void *ptr, size_t size) {
  wt_allocator_t resolved;
  if (ptr == NULL) return;
  resolved = wt_allocator_resolve(a);
  resolved.free(resolved.context, ptr, wt_requested_size(size));
}
