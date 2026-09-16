/* Checked integer arithmetic. See webtransport/checked.h.
 *
 * Each function is written as the overflow test followed by the operation, and
 * the test is expressed so that it does not itself overflow. For addition that
 * means comparing against the maximum minus the addend; for multiplication it
 * means dividing the maximum by one factor first, which is the only form that
 * cannot wrap.
 */

#include "webtransport/checked.h"

#include <limits.h>

wt_status_t wt_checked_add_size(size_t a, size_t b, size_t *out) {
  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (b > SIZE_MAX - a) return WT_ERR_OVERFLOW;
  *out = a + b;
  return WT_OK;
}

wt_status_t wt_checked_add_u64(uint64_t a, uint64_t b, uint64_t *out) {
  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (b > UINT64_MAX - a) return WT_ERR_OVERFLOW;
  *out = a + b;
  return WT_OK;
}

wt_status_t wt_checked_sub_size(size_t a, size_t b, size_t *out) {
  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (b > a) return WT_ERR_OVERFLOW;
  *out = a - b;
  return WT_OK;
}

wt_status_t wt_checked_sub_u64(uint64_t a, uint64_t b, uint64_t *out) {
  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (b > a) return WT_ERR_OVERFLOW;
  *out = a - b;
  return WT_OK;
}

wt_status_t wt_checked_mul_size(size_t a, size_t b, size_t *out) {
  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* The test is on the divisor, not on the product: computing the product to
   * see whether it overflowed is the bug this exists to prevent. */
  if (a != 0U && b > SIZE_MAX / a) return WT_ERR_OVERFLOW;
  *out = a * b;
  return WT_OK;
}

wt_status_t wt_checked_mul_u64(uint64_t a, uint64_t b, uint64_t *out) {
  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (a != 0U && b > UINT64_MAX / a) return WT_ERR_OVERFLOW;
  *out = a * b;
  return WT_OK;
}

wt_status_t wt_checked_narrow_u64_to_u32(uint64_t value, uint32_t *out) {
  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (value > (uint64_t)UINT32_MAX) return WT_ERR_OVERFLOW;
  *out = (uint32_t)value;
  return WT_OK;
}

wt_status_t wt_checked_narrow_u64_to_size(uint64_t value, size_t *out) {
  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (value > (uint64_t)SIZE_MAX) return WT_ERR_OVERFLOW;
  *out = (size_t)value;
  return WT_OK;
}

wt_status_t wt_checked_narrow_size_to_u32(size_t value, uint32_t *out) {
  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (value > (size_t)UINT32_MAX) return WT_ERR_OVERFLOW;
  *out = (uint32_t)value;
  return WT_OK;
}
