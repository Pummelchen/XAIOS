#ifndef XAIOS_VERSION_H
#define XAIOS_VERSION_H

/*
 * What this build of XAIOS is.
 *
 * XAIOS is identified by build number. It carried a MAJOR.MINOR.PATCH version
 * for a while -- 0.1.0 -- which was invented rather than earned: nothing had
 * shipped, so the three numbers recorded no history and implied compatibility
 * rules nobody had agreed to. A build number states the one thing that is
 * true, which build this is, and implies nothing further.
 *
 * Both come from BUILD_NUMBER at the repository root, passed in by
 * scripts/build-image.sh. Paths that only compile -- the compile-only checks,
 * hosted unit tests, static analysis -- never run that script and have no
 * build to name. The fallbacks below exist for them and say "unbuilt" and 0
 * rather than inventing a number.
 *
 * An image cannot ship those fallbacks unnoticed: the first boot line carries
 * the label, and the boot gates match "XAIOS Build <n>" there, so an image
 * built without one fails the gate rather than claiming to be a release.
 */
/* The label is assembled here rather than passed in, because "Build 1"
   contains a space and the build's CFLAGS are expanded with word splitting:
   passing it as one -D argument makes the compiler look for a file named 1".
   Only the bare number crosses the command line. */
#define XAIOS_STRINGIFY_INNER(value) #value
#define XAIOS_STRINGIFY(value) XAIOS_STRINGIFY_INNER(value)

#ifndef XAIOS_BUILD_NUMBER
#define XAIOS_BUILD_NUMBER 0
#define XAIOS_BUILD_LABEL "unbuilt"
#else
#define XAIOS_BUILD_LABEL "Build " XAIOS_STRINGIFY(XAIOS_BUILD_NUMBER)
#endif

#endif
