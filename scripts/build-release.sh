#!/bin/sh
# Assemble the release packages for the current build: one image per
# architecture, and a zip beside each.
#
# The zips exist because GitHub refuses any file over 100 MB and the AArch64
# image is around 220 of them. Compressed it is roughly a tenth of that, which
# fits, so the release can travel with the repository rather than only as an
# attachment somewhere else. The other two images are under the limit already
# and are zipped anyway, because a release whose three files are fetched three
# different ways is a release people get wrong.
#
# Both files of a pair are written together and both checksums are printed. A
# zip made separately from the image it contains drifts from it silently -- one
# was, within an hour of the image being rebuilt, and the only way anyone
# noticed was checksumming what was inside it.
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
BUILD_DIR="$ROOT_DIR/build"
RELEASE_DIR="$ROOT_DIR/release"
BUILD_NUMBER="$(tr -d ' \n' < "$ROOT_DIR/BUILD_NUMBER" 2>/dev/null || printf '%s' 0)"

# Which architectures this release contains. Every one named here must be
# present and must carry its own loader; there is no "included when it happens
# to have been built". That rule is why this file exists at all -- the image
# builder it replaced skipped an architecture whose files were absent and said
# so in a line that scrolled past, and an image that boots on fewer machines
# than the release note claims looks exactly like one that does not.
ARCHS="${XAIOS_RELEASE_ARCHS:-aarch64 x86_64 riscv64}"

command -v zip >/dev/null 2>&1 || {
  printf '%s\n' "error: zip is required" >&2
  exit 1
}
command -v mdir >/dev/null 2>&1 || {
  printf '%s\n' "error: mdir (mtools) is required to inspect the images" >&2
  exit 1
}

loader_for() {
  case "$1" in
    aarch64) printf 'BOOTAA64.EFI' ;;
    x86_64)  printf 'BOOTX64.EFI' ;;
    riscv64) printf 'BOOTRISCV64.EFI' ;;
    *) printf 'error: unknown architecture %s\n' "$1" >&2; exit 2 ;;
  esac
}

# Everything is checked before anything is copied. A release that fails
# half-way leaves release/ holding some of this build and some of the last one,
# which is a worse state to be in than not having started.
for arch in $ARCHS; do
  image="$BUILD_DIR/xaios_b${BUILD_NUMBER}-${arch}.iso"
  esp="$BUILD_DIR/esp-${arch}.img"
  [ -f "$image" ] || {
    printf '%s\n' "missing: $image" "run: make release-image-$arch" >&2
    exit 1
  }
  [ -f "$esp" ] || {
    printf '%s\n' "missing: $esp" \
      "  The image is here and the partition it was built from is not, so" \
      "  what is inside it cannot be checked. Rebuild rather than ship" \
      "  something unexamined: make release-image-$arch" >&2
    exit 1
  }
  # The image is newer than its ESP only if something rebuilt one and not the
  # other, which is the case where checking the ESP proves nothing about the
  # image.
  if [ "$esp" -nt "$image" ]; then
    printf '%s\n' \
      "error: $esp is newer than $image, so the partition being checked is" \
      "       not the one inside the image. run: make release-image-$arch" >&2
    exit 1
  fi
  loader=$(loader_for "$arch")
  if ! mdir -i "$esp" ::/EFI/BOOT 2>/dev/null | grep -q "${loader%.EFI}"; then
    printf '%s\n' \
      "error: the $arch image has no $loader on the removable-media path." \
      "       Firmware looks for exactly that name and boots nothing when it" \
      "       is absent, with no output to say why." >&2
    exit 1
  fi
done

# VMware Fusion, and AArch64 only because Fusion here is AArch64 only.
#
# Fusion's firmware will not launch the XAIOS loader directly; it launches
# GRUB, which chainloads it. The image builder warns and continues when the
# chainloader is absent, which is right for a developer on a machine without
# Docker and wrong for a release: the image it produces boots three of the four
# environments and says so only in a line that scrolls past. This was nearly
# published once, after a clean of build/ took the chainloader with it.
#
# The test is the size. A placeholder file at that path passes any check that
# only asks whether it exists, and one did.
case " $ARCHS " in
  *" aarch64 "*)
    chainloader_bytes=0
    if [ -f "$BUILD_DIR/vmware-fusion/BOOTAA64.EFI" ]; then
      chainloader_bytes=$(wc -c < "$BUILD_DIR/vmware-fusion/BOOTAA64.EFI")
    fi
    if [ "$chainloader_bytes" -lt 1000000 ]; then
      printf '%s\n' \
        "error: no VMware Fusion chainloader; the aarch64 image would boot" \
        "       three of the four environments the release note claims." \
        "       Run: make vmware-fusion-image, then make release-image-aarch64" >&2
      exit 1
    fi ;;
esac

mkdir -p "$RELEASE_DIR"

printf '%s\n' "XAIOS build $BUILD_NUMBER release packages"
for arch in $ARCHS; do
  image="$BUILD_DIR/xaios_b${BUILD_NUMBER}-${arch}.iso"
  release_image="$RELEASE_DIR/xaios_b${BUILD_NUMBER}-${arch}.iso"
  release_zip="$release_image.zip"

  cp "$image" "$release_image"
  # -j drops directory paths, -X drops the extra file attributes that put a
  # __MACOSX/._ entry beside every file when this is compressed from the
  # Finder. What is wanted in the archive is one ISO and nothing else.
  rm -f "$release_zip"
  ( cd "$RELEASE_DIR" && zip -q -j -X "$(basename "$release_zip")" \
      "$(basename "$release_image")" )

  printf '  %s\n' "$arch"
  printf '    %-6s %s bytes\n' "iso:" "$(wc -c < "$release_image" | tr -d ' ')"
  printf '    %-6s %s\n' "" "$(shasum -a 256 "$release_image" | awk '{print $1}')"
  printf '    %-6s %s bytes\n' "zip:" "$(wc -c < "$release_zip" | tr -d ' ')"
  printf '    %-6s %s\n' "" "$(shasum -a 256 "$release_zip" | awk '{print $1}')"
  printf '    %-6s %s\n' "has:" "$(unzip -l "$release_zip" | awk 'NR==4 {print $4}')"
done
