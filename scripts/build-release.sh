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

# A release must boot every environment it claims. The unified builder warns
# and continues when the VMware Fusion chainloader is absent, which is right
# for a developer on a machine without Docker and wrong for a release: the
# image it produces boots three of the four and says so only in a line that
# scrolls past. This was nearly published once, after a clean of build/ took
# the chainloader with it.
if ! mdir -i "$BUILD_DIR/unified-esp.img" ::/EFI/BOOT 2>/dev/null |
     grep -q "BOOTAA64"; then
  printf '%s\n' "error: the image has no EFI boot loader" >&2
  exit 1
fi
chainloader_bytes=0
if [ -f "$BUILD_DIR/vmware-fusion/BOOTAA64.EFI" ]; then
  chainloader_bytes=$(wc -c < "$BUILD_DIR/vmware-fusion/BOOTAA64.EFI")
fi
if [ "$chainloader_bytes" -lt 1000000 ]; then
  printf '%s\n' \
    "error: no VMware Fusion chainloader; this image would boot three of the" \
    "       four environments the release note claims." \
    "       Run: make vmware-fusion-image, then make unified-image" >&2
  exit 1
fi

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
