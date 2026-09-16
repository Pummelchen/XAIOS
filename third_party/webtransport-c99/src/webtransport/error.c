/* The WebTransport error-code mapping (draft-ietf-webtrans-http3-16 section 4.4). See the header for what the
 * two spaces are and why the protocol codes do not travel through this mapping. */

#include "webtransport/webtransport/error.h"

/* The two constants of section 4.4's pseudocode, and the divisors: `0x1e` going out (the number of application
 * codes per reserved codepoint) and `0x1f` coming back (the period of the reserved codepoints). They are written
 * as the section writes them rather than folded into one another, because the whole arithmetic is the section's
 * and a reader has to be able to check it line by line. */
#define WT_WEBTRANSPORT_ERROR_STRIDE_OUT 0x1eU
#define WT_WEBTRANSPORT_ERROR_STRIDE_IN 0x1fU
/* The first reserved codepoint's residue: every reserved codepoint is `0x1f * N + 0x21`. */
#define WT_WEBTRANSPORT_ERROR_RESERVED_RESIDUE 0x21U

int wt_webtransport_error_is_application_range(uint64_t http3_error) {
  if (http3_error < WT_WEBTRANSPORT_APPLICATION_ERROR_FIRST ||
      http3_error > WT_WEBTRANSPORT_APPLICATION_ERROR_LAST) {
    return 0;
  }
  /* RFC 9114 section 8.1 reserves the codepoints of the form `0x1f * N + 0x21`, and section 4.4 says they "have
   * to be skipped when mapping" -- so a codepoint with that residue is inside the range but is not one an
   * application error maps to. */
  if ((http3_error - WT_WEBTRANSPORT_ERROR_RESERVED_RESIDUE) % WT_WEBTRANSPORT_ERROR_STRIDE_IN == 0U) return 0;
  return 1;
}

uint64_t wt_webtransport_error_to_http3(uint32_t application_error) {
  uint64_t value = (uint64_t)application_error;
  /* `first + n + floor(n / 0x1e)`: every 0x1e application codes are followed by one reserved codepoint, and the
   * quotient is where the gaps accumulate. The arithmetic cannot overflow: 0xffffffff + 0xffffffff/0x1e is far
   * below 2^40, let alone 2^64. */
  return WT_WEBTRANSPORT_APPLICATION_ERROR_FIRST + value + (value / WT_WEBTRANSPORT_ERROR_STRIDE_OUT);
}

wt_status_t wt_webtransport_error_from_http3(uint64_t http3_error, uint32_t *out_application_error) {
  uint64_t shifted;

  if (out_application_error == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* A codepoint outside the range, or one of the reserved codepoints inside it, is not an application error --
   * section 4.4's pseudocode asserts both, and a caller that guessed instead would turn a protocol code into an
   * application one. */
  if (!wt_webtransport_error_is_application_range(http3_error)) return WT_ERR_INVALID_ARGUMENT;

  shifted = http3_error - WT_WEBTRANSPORT_APPLICATION_ERROR_FIRST;
  /* `shifted - floor(shifted / 0x1f)`, which is the inverse of the quotient added above. The result cannot
   * exceed 0xffffffff for a codepoint in the range: the range holds exactly 0xffffffff + 1 such values. */
  *out_application_error = (uint32_t)(shifted - (shifted / WT_WEBTRANSPORT_ERROR_STRIDE_IN));
  return WT_OK;
}
