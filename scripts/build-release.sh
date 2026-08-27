#!/bin/sh
# Assemble the release package for the current build.
#
# Produces release/xaios_b<n>.iso and release/xaios_b<n>.iso.zip from the image
# the unified builder just made. The zip exists because the ISO is around 220
# MB and GitHub refuses any file over 100 MB: compressed it is roughly a tenth
# of that, which fits, so the release can travel with the repository rather
# than only as an attachment somewhere else.
#
# It is built here rather than by hand for one reason. A zip made separately
# from the image it contains drifts from it silently -- one was, within an hour
# of the image being rebuilt, and the only way anyone noticed was checksumming
# what was inside it. Both files are written together and both checksums are
# printed, so the pair cannot disagree without it being visible.
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
BUILD_DIR="$ROOT_DIR/build"
RELEASE_DIR="$ROOT_DIR/release"
BUILD_NUMBER="$(tr -d ' \n' < "$ROOT_DIR/BUILD_NUMBER" 2>/dev/null || printf '%s' 0)"
IMAGE="$BUILD_DIR/xaios_b${BUILD_NUMBER}.iso"
RELEASE_IMAGE="$RELEASE_DIR/xaios_b${BUILD_NUMBER}.iso"
RELEASE_ZIP="$RELEASE_IMAGE.zip"

command -v zip >/dev/null 2>&1 || {
  printf '%s\n' "error: zip is required" >&2
  exit 1
}
[ -f "$IMAGE" ] || {
  printf '%s\n' "missing: $IMAGE" "run: make unified-image" >&2
  exit 1
}

mkdir -p "$RELEASE_DIR"
cp "$IMAGE" "$RELEASE_IMAGE"

# -j drops directory paths, -X drops the extra file attributes that put a
# __MACOSX/._ entry beside every file when this is compressed from the Finder.
# What is wanted in the archive is one ISO and nothing else.
rm -f "$RELEASE_ZIP"
( cd "$RELEASE_DIR" && zip -q -j -X "$(basename "$RELEASE_ZIP")" "$(basename "$RELEASE_IMAGE")" )

printf '%s\n' "XAIOS build $BUILD_NUMBER release package"
printf '  %-14s %s bytes\n' "iso:" "$(wc -c < "$RELEASE_IMAGE" | tr -d ' ')"
printf '  %-14s %s\n' "" "$(shasum -a 256 "$RELEASE_IMAGE" | awk '{print $1}')"
printf '  %-14s %s bytes\n' "zip:" "$(wc -c < "$RELEASE_ZIP" | tr -d ' ')"
printf '  %-14s %s\n' "" "$(shasum -a 256 "$RELEASE_ZIP" | awk '{print $1}')"
printf '  %-14s %s\n' "contains:" "$(unzip -l "$RELEASE_ZIP" | awk 'NR==4 {print $4}')"
