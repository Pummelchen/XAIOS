/* QUIC variable-length integers (RFC 9000 section 16).
 *
 * A varint is a two-bit length prefix in the first byte followed by one, two,
 * four or eight bytes of big-endian value, so a number's encoding says how many
 * bytes it occupies. Values above 2^62 - 1 cannot be encoded at all, which is
 * why the decoders here return a status rather than a value: the wire can
 * express 2^62 - 1 and a uint64_t holds much more, so a caller that assumed they
 * were the same range would accept a value the protocol cannot carry.
 *
 * RFC 9000 section 16 does NOT require the shortest encoding: "Values do not
 * need to be encoded on the minimum number of bytes necessary, with the sole
 * exception of the Frame Type field." So decoding accepts `00 00 00 01` as 1,
 * and the one place that has to enforce minimality -- the frame type -- does so
 * itself. An encoder here always writes the shortest form, because there is no
 * reason to spend bytes and a canonical encoding makes a test vector easy to
 * read.
 */

#ifndef WEBTRANSPORT_QUIC_VARINT_H
#define WEBTRANSPORT_QUIC_VARINT_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/cursor.h"
#include "webtransport/status.h"
#include "webtransport/writer.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The largest value a QUIC varint can carry, 2^62 - 1. RFC 9000 section 16
 * calls this 2^62 - 1 and every length field in the protocol is bounded by it. */
#define WT_QUIC_VARINT_MAX UINT64_C(0x3fffffffffffffff)

/* The number of bytes `value` occupies when encoded shortest, or 0 when it
 * cannot be encoded because it exceeds WT_QUIC_VARINT_MAX. Zero is not a valid
 * size, so it is unambiguous. */
size_t wt_quic_varint_size(uint64_t value);

/* Encode into `out`, which must have room for wt_quic_varint_size(value) bytes.
 * Returns the number of bytes written, or 0 on a bad argument, a value out of
 * range, or a buffer too small -- the buffer's capacity is an argument, so a
 * refusal is a return value and not a buffer overrun. */
size_t wt_quic_varint_encode(uint64_t value, uint8_t *out, size_t capacity);

/* Encode through a writer, which is how every structure in this library is
 * built, so that a measuring pass and a writing pass both work. Returns the
 * number of bytes the value occupies, which is what a caller that reserved a
 * length prefix needs to know; a writer that overflowed still reports the size
 * it would have taken, so the caller checks wt_writer_ok. */
size_t wt_quic_writer_varint(wt_writer_t *w, uint64_t value);

/* Decode one varint from a cursor, advancing past it. Returns WT_OK and the
 * value, or WT_ERR_TRUNCATED when the cursor ran out -- including when the
 * prefix says eight bytes and only three remain, which is the case a parser that
 * read the prefix and then a fixed number of bytes without checking would get
 * wrong. On failure the value is not written. */
wt_status_t wt_quic_varint_decode(wt_cursor_t *c, uint64_t *out);

/* The same, also reporting how many bytes the encoding occupied. The frame
 * parser needs this: RFC 9000 section 12.4 requires a frame type that is not
 * encoded on the minimum number of bytes to be a PROTOCOL_VIOLATION, and the
 * only way to tell is to compare the size the encoding took against the size the
 * value needs. */
wt_status_t wt_quic_varint_decode_sized(wt_cursor_t *c, uint64_t *out,
                                        size_t *out_size);

/* Whether a value decoded from `size` bytes was written on the minimum number of
 * bytes. False for a value that could have been shorter, which is the check
 * above expressed once so that it cannot be got subtly wrong at each call. */
int wt_quic_varint_is_minimal(uint64_t value, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_QUIC_VARINT_H */
