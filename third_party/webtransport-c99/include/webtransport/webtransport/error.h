/* WebTransport's error codes, and the mapping between its application codes and HTTP/3's (draft-ietf-webtrans-http3-16
 * sections 4.4 and 9.5).
 *
 * TWO SPACES, AND THE DIFFERENCE MATTERS.
 *
 * A WebTransport APPLICATION error is an unsigned 32-bit integer the application chose -- the code it passes when
 * it resets one of its streams. Section 4.4: "Since WebTransport shares the error code space with HTTP/3,
 * WebTransport application errors for streams are limited to an unsigned 32-bit integer ... WebTransport
 * implementations MUST remap those error codes into the error range reserved for WT_APPLICATION_ERROR, where
 * 0x00000000 corresponds to 0x52e4a40fa8db, and 0xffffffff corresponds to 0x52e5ac983162." The remapping is not a
 * shift: HTTP/3 reserves the codepoints of the form `0x1f * N + 0x21` (RFC 9114 section 8.1), so every one of
 * them is SKIPPED, and section 4.4 gives the pseudocode both directions.
 *
 * A WebTransport PROTOCOL error is an HTTP/3 error code that the draft registered in HTTP/3's own registry
 * (section 9.5) -- WT_SESSION_GONE, WT_BUFFERED_STREAM_REJECTED, WT_FLOW_CONTROL_ERROR, WT_ALPN_ERROR and
 * WT_REQUIREMENTS_NOT_MET. Those travel UNMAPPED: `WT_SESSION_GONE` "is a protocol-level error code rather than an
 * application error code", which is why section 6 can say a terminating endpoint resets the session's streams
 * "using the WT_SESSION_GONE error code" and mean the number itself. A tree that mapped them through the
 * application range would name a code no peer recognises, which is the mistake this header exists to prevent.
 *
 * A code that is neither in the application range nor one of the five is a caller error and is refused:
 * `wt_webtransport_error_from_http3` reports a codepoint outside the range, and one of the reserved codepoints
 * INSIDE it, as WT_ERR_INVALID_ARGUMENT rather than inventing a value.
 */

#ifndef WEBTRANSPORT_WEBTRANSPORT_ERROR_H
#define WEBTRANSPORT_WEBTRANSPORT_ERROR_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The range section 9.5 registers for application error codes, with the codepoints of the form `0x1f * N + 0x21`
 * excluded -- which is what the mapping below does. */
#define WT_WEBTRANSPORT_APPLICATION_ERROR_FIRST ((uint64_t)0x52e4a40fa8dbULL)
#define WT_WEBTRANSPORT_APPLICATION_ERROR_LAST ((uint64_t)0x52e5ac983162ULL)

/* The draft's own registered codes, section 9.5. These are HTTP/3 error codes: they go on the wire as they are,
 * and they are NOT application codes (see the header comment). */
#define WT_WEBTRANSPORT_ERROR_BUFFERED_STREAM_REJECTED ((uint64_t)0x3994bd84ULL)
#define WT_WEBTRANSPORT_ERROR_SESSION_GONE ((uint64_t)0x170d7b68ULL)
#define WT_WEBTRANSPORT_ERROR_FLOW_CONTROL ((uint64_t)0x045d4487ULL)
#define WT_WEBTRANSPORT_ERROR_ALPN ((uint64_t)0x0817b3ddULL)
#define WT_WEBTRANSPORT_ERROR_REQUIREMENTS_NOT_MET ((uint64_t)0x212c0d48ULL)

/* The application code the application chose -> the HTTP/3 error code that goes on the wire (section 4.4's
 * `first + n + floor(n / 0x1e)`). Every 32-bit value maps to a codepoint in the registered range, and none of
 * them is a reserved codepoint, so the result is always a code a conforming peer can read. */
uint64_t wt_webtransport_error_to_http3(uint32_t application_error);

/* The other direction: a codepoint FROM the registered range -> the application code it carries (section 4.4's
 * `shifted - floor(shifted / 0x1f)`).
 *
 * WT_ERR_INVALID_ARGUMENT for a codepoint outside the range and for one of the reserved codepoints inside it --
 * a reserved value is not a WebTransport application error, and section 4.4's own pseudocode asserts both rules
 * rather than guessing. WT_ERR_INVALID_ARGUMENT for a null output. */
wt_status_t wt_webtransport_error_from_http3(uint64_t http3_error, uint32_t *out_application_error);

/* Whether a codepoint is one an application error can be mapped to: inside the registered range and not one of
 * the reserved codepoints. Exported because a receiver that is handed a code by a caller -- rather than by this
 * mapping -- needs the same test, and a second copy of the arithmetic is a second thing to get wrong. */
int wt_webtransport_error_is_application_range(uint64_t http3_error);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_WEBTRANSPORT_ERROR_H */
