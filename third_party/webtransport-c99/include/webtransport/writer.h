/* WebTransport C99: a two-pass write cursor.
 *
 * Every message in this library is length-prefixed, and the length is not known
 * until the body has been built. The usual answers are to build into a temporary
 * buffer and copy, or to remember to go back and patch a length. The first costs
 * an allocation per packet; the second is the kind of thing that is correct until
 * someone adds a field.
 *
 * So a writer works in one of two modes over the same call sequence. In
 * MEASURING mode it copies nothing and only counts, so a caller can ask "how many
 * bytes would this take" and then write the length prefix. In WRITING mode it
 * copies and refuses to run past the end, so an encoder cannot overflow the
 * buffer it was given. The encoder for a structure is written once as a function
 * that takes a writer, and it is correct in both modes or it is wrong in both --
 * which is what makes the two agree by construction rather than by review.
 *
 * The overflow flag is why the writer is usable without a status check after
 * every field: the first write that does not fit sticks, and every later write is
 * a no-op.
 */

#ifndef WEBTRANSPORT_WRITER_H
#define WEBTRANSPORT_WRITER_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct wt_writer {
  uint8_t *data;
  size_t cap;
  size_t offset;
  /* Whether to copy. A measuring writer has no destination, so this is what
   * distinguishes "count the bytes" from "write them", and it is separate from
   * `data == NULL` so that a measurement cannot accidentally be made to write. */
  int copy;
  int overflow;
} wt_writer_t;

/* A writer that copies into `data`, which must have room for `cap` bytes. */
wt_writer_t wt_writer_init(uint8_t *data, size_t cap);

/* A writer that copies nothing and answers only "how many bytes". The
 * capacity is bounded deliberately: an unbounded measurement would hide a
 * length computation that had already overflowed. */
wt_writer_t wt_writer_measure(void);

/* Bytes written so far. Meaningful in both modes. */
size_t wt_writer_offset(const wt_writer_t *w);

/* Whether every write fitted. An encoder that returns a length must have this
 * set, and a caller that is handed a length without it is being told a number
 * that was never bounded. */
int wt_writer_ok(const wt_writer_t *w);

/* Whether the writer copies. A function that needs a destination to exist --
 * to hash the same bytes, for instance -- can ask. */
int wt_writer_is_measuring(const wt_writer_t *w);

/* Writes. Each is a no-op once the writer has overflowed. */
void wt_writer_u8(wt_writer_t *w, uint8_t value);
void wt_writer_u16(wt_writer_t *w, uint16_t value);
void wt_writer_u24(wt_writer_t *w, uint32_t value);
void wt_writer_u32(wt_writer_t *w, uint32_t value);
void wt_writer_u64(wt_writer_t *w, uint64_t value);

/* `len` bytes from `data`. `data` may be NULL only when `len` is zero, which is
 * a legitimate empty field. */
void wt_writer_bytes(wt_writer_t *w, const void *data, size_t len);

/* Reserve `n` bytes and hand back a pointer to them, or NULL if the writer has
 * no room or is measuring. The bytes are not zeroed: a caller that wants them
 * zeroed writes zeros. This is how a field whose value is computed after its
 * position is fixed -- a length prefix -- is written in place.
 *
 * ON A MEASURING WRITER THIS RETURNS NULL AND STILL COUNTS THE BYTES, which is
 * what makes the two passes agree. An encoder that reserves a prefix and later
 * patches it therefore writes the patch only when
 * `!wt_writer_is_measuring(w)`: in the measuring pass the reserved bytes are
 * already in the count, so the patch has nothing to do and
 * `wt_writer_patch` refuses. Getting this backwards is the one mistake this
 * interface invites, which is why it is spelled out here rather than left to
 * the example. */
uint8_t *wt_writer_reserve(wt_writer_t *w, size_t n);

/* Overwrite `n` bytes at `offset`, which must be behind the write position.
 * Returns WT_ERR_INVALID_ARGUMENT for an offset or range that was not written
 * yet, and WT_ERR_LIMIT on a measuring writer, which has nowhere to write. */
wt_status_t wt_writer_patch(wt_writer_t *w, size_t offset, const void *data,
                            size_t n);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_WRITER_H */
