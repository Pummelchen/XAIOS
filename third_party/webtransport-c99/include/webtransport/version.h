/* WebTransport C99: library identity.
 *
 * The version is part of the ABI contract: wt_version_string() returns a static
 * string that never needs freeing, and wt_abi_version() returns the integer that
 * a caller compares against the WT_ABI_VERSION it was compiled with. The two
 * exist separately because a bug-fix release changes the string and not the
 * integer, and a caller checking the integer is checking the thing that can
 * actually break it.
 *
 * C has no way to read the repository-root VERSION file at compile time, so the
 * three WT_VERSION_* macros below are a MIRROR of it, not a second source. The
 * authoritative value is VERSION; CMake fails at configure time and
 * Swift/check-version-sync.sh fails in CI if these macros -- or the Swift
 * constant in Swift/Sources/WebTransport/WebTransportVersion.swift -- disagree
 * with it. Never bump one of the three on its own.
 *
 * WT_ABI_VERSION is deliberately NOT part of that lockstep: it moves only for a
 * breaking layout or signature change, which a version bump does not imply.
 */

#ifndef WEBTRANSPORT_VERSION_H
#define WEBTRANSPORT_VERSION_H

#ifdef __cplusplus
extern "C" {
#endif

/* Mirrors VERSION. See the note above. */
#define WT_VERSION_MAJOR 1
#define WT_VERSION_MINOR 4
#define WT_VERSION_PATCH 0

/* Incremented only when a public structure's layout, a function's signature, or
 * a documented constant's value changes in a way that a caller compiled against
 * an earlier header would get wrong. */
#define WT_ABI_VERSION 1

/* "MAJOR.MINOR.PATCH" from the macros above. Static storage; never freed. No
 * literal here to go stale -- the string is stringified from them. */
const char *wt_version_string(void);

/* WT_ABI_VERSION at build time. */
int wt_abi_version(void);

/* The protocol draft this implementation targets, as a string for a User-Agent
 * or a diagnostic -- "draft-ietf-webtrans-http3-16". Static storage. */
const char *wt_protocol_draft(void);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_VERSION_H */
