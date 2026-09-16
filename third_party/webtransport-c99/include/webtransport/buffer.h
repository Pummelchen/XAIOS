/* WebTransport C99: a growable byte buffer.
 *
 * Used for the things that accumulate: a stream's reassembly buffer, a
 * handshake's CRYPTO data, a QPACK dynamic table's bytes. It owns its storage
 * and carries the allocator it was made with, so freeing it needs no second
 * argument and no memory of what it was created from -- the two mistakes that
 * leak in C are freeing with the wrong allocator and forgetting the size.
 *
 * The buffer is NOT a queue with a read cursor. `wt_buf_consume` drops bytes
 * from the front, which memmoves, and that is deliberate: the ring-buffer
 * alternative trades a memmove for an index that every reader must respect, and
 * QUIC's stream reassembly reads from the front once per delivered range. When a
 * profile shows the memmove mattering, the change belongs in the caller that
 * knows its access pattern, not here.
 */

#ifndef WEBTRANSPORT_BUFFER_H
#define WEBTRANSPORT_BUFFER_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/allocator.h"
#include "webtransport/cursor.h"
#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct wt_buf {
  uint8_t *data;
  size_t len;
  size_t cap;
  wt_allocator_t alloc;
} wt_buf_t;

/* An empty buffer that allocates through `alloc`. Passing a NULL allocator --
 * or a zeroed one -- selects the default. No allocation happens until the first
 * append, so a buffer that is never written costs nothing and `wt_buf_free` on
 * it is valid. */
wt_buf_t wt_buf_init(const wt_allocator_t *alloc);

/* Release the storage and reset the buffer to empty. Safe to call twice, and on
 * a buffer that was only initialized. */
void wt_buf_free(wt_buf_t *b);

/* Make room for `additional` more bytes beyond `len`. Growth doubles from the
 * current capacity, which makes appending n bytes amortized linear rather than
 * quadratic, and is capped by WT_BUF_MAX_CAPACITY: a peer that can make a buffer
 * grow is a peer that can make a process die, so the bound is explicit and the
 * refusal is WT_ERR_LIMIT rather than an allocation failure. */
wt_status_t wt_buf_reserve(wt_buf_t *b, size_t additional);

/* Append. On failure nothing is modified. */
wt_status_t wt_buf_append(wt_buf_t *b, const void *data, size_t len);
wt_status_t wt_buf_append_u8(wt_buf_t *b, uint8_t value);

/* Append `len` bytes and hand them back unwritten, for a case that fills a
 * region after reserving it. Returns NULL on failure -- and ALSO for a zero-length request on an EMPTY buffer,
 * where there is nothing to fail and no byte to point at (`b->data + b->len` is NULL + 0). A caller that asks for
 * zero bytes and checks only for NULL has to own that case: the status is WT_OK either way, which is what
 * `wt_buf_reserve` answers for a zero request. */
uint8_t *wt_buf_reserve_tail(wt_buf_t *b, size_t len);

/* Drop `n` bytes from the front, moving the rest down. `n` greater than `len`
 * empties the buffer; it is clamped rather than refused, because every caller of
 * this is dropping what it has already processed and "drop more than there is"
 * means "there was nothing left". */
void wt_buf_consume(wt_buf_t *b, size_t n);

/* Set len to zero without releasing storage, for a buffer that is reused. */
void wt_buf_clear(wt_buf_t *b);

/* Compact the storage to exactly `len`, releasing the slack. Best-effort: a
 * failure leaves the buffer valid and simply not shrunk. */
void wt_buf_shrink_to_fit(wt_buf_t *b);

/* A read cursor over the whole buffer, or over the first `len` bytes of it. */
wt_cursor_t wt_buf_cursor(const wt_buf_t *b);

/* A copy of `len` bytes owned by the caller, allocated through `alloc`. Used
 * where a value must outlive the buffer it came from -- see the plan's rule that
 * no ownership transfers unless the name says so; the name here does. */
uint8_t *wt_buf_copy_out(const wt_buf_t *b, size_t offset, size_t len,
                         const wt_allocator_t *alloc, wt_status_t *out_status);

/* The bound `wt_buf_reserve` refuses to grow past. 64 MiB is far above anything
 * a single stream, datagram or table in this protocol needs -- the largest is a
 * QPACK dynamic table, whose capacity is negotiated and defaults to 0 -- and far
 * below what would let one connection exhaust a small machine. It is a single
 * constant rather than a per-buffer argument so that there is one number to
 * audit; a caller that needs a tighter bound passes explicit maximum lengths to
 * the parsers, which is the mechanism the plan requires anyway. */
#define WT_BUF_MAX_CAPACITY ((size_t)64U * 1024U * 1024U)

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_BUFFER_H */
