/* WebTransport C99: checked integer arithmetic.
 *
 * QUIC's wire format is a set of length-prefixed structures whose lengths are
 * 8, 16, 24, 32 and 62 bits wide, and a frame may nest several of them. An
 * implementation that computes `header_len + payload_len` and then allocates it
 * has a bug that only a hostile peer can reach: the sum wraps to a small number
 * and the allocation succeeds.
 *
 * Every addition, multiplication and subtraction that touches a length, an
 * offset or a capacity in this library goes through these helpers. They return
 * a status and write the result through an out-parameter, so the failure is a
 * value the caller must handle rather than a flag it may forget -- and
 * -Wconversion is on for every source file, so an unchecked narrowing does not
 * compile either.
 */

#ifndef WEBTRANSPORT_CHECKED_H
#define WEBTRANSPORT_CHECKED_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

/* a + b, or WT_ERR_OVERFLOW and no write. */
wt_status_t wt_checked_add_size(size_t a, size_t b, size_t *out);
wt_status_t wt_checked_add_u64(uint64_t a, uint64_t b, uint64_t *out);

/* a - b, or WT_ERR_OVERFLOW when b > a -- an unsigned subtraction that would
 * have gone below zero is an overflow here, because in every use in this
 * library it means a length was larger than the buffer it describes. */
wt_status_t wt_checked_sub_size(size_t a, size_t b, size_t *out);
wt_status_t wt_checked_sub_u64(uint64_t a, uint64_t b, uint64_t *out);

/* a * b, or WT_ERR_OVERFLOW. This is the one that matters: `count * elem_size`
 * with both from the wire is the classic pre-allocation overflow. */
wt_status_t wt_checked_mul_size(size_t a, size_t b, size_t *out);
wt_status_t wt_checked_mul_u64(uint64_t a, uint64_t b, uint64_t *out);

/* Narrowing, refused rather than truncated. A value that does not fit is
 * WT_ERR_OVERFLOW and no write, so `(uint32_t)some_u64` never appears in a
 * length field. */
wt_status_t wt_checked_narrow_u64_to_u32(uint64_t value, uint32_t *out);
wt_status_t wt_checked_narrow_u64_to_size(uint64_t value, size_t *out);
wt_status_t wt_checked_narrow_size_to_u32(size_t value, uint32_t *out);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_CHECKED_H */
