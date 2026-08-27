#ifndef XAIOS_VERSION_H
#define XAIOS_VERSION_H

/*
 * The product version, single-sourced from VERSION at the repository root and
 * passed in by scripts/build-image.sh.
 *
 * Build paths that only compile -- the compile-only checks, hosted unit tests,
 * static analysis -- do not run the image build and have no version to pass.
 * They still have to compile, so the fallback below exists for them, and it
 * says "unknown" rather than inventing a number.
 *
 * An image cannot ship that fallback unnoticed: the first boot line carries
 * this string, and the boot gates match MAJOR.MINOR.PATCH there, so an image
 * built without a version fails the gate rather than claiming to be a release.
 */
#ifndef XAIOS_PRODUCT_VERSION
#define XAIOS_PRODUCT_VERSION "unknown"
#endif

/*
 * The build number, single-sourced from BUILD_NUMBER at the repository root.
 * Releases are named and referred to by this -- build 1 ships as xaios_b1.iso
 * -- while the version string above remains what the boot banner and the tools
 * report. A build not produced by scripts/build-image.sh has no number and
 * says 0 rather than claiming one.
 */
#ifndef XAIOS_BUILD_NUMBER
#define XAIOS_BUILD_NUMBER 0
#endif

#endif
