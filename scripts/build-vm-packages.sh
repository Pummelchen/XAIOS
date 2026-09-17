#!/bin/sh
# Package XAIOS as something a person downloads, extracts and starts.
#
# The release already carries the images. What it does not carry is a way to
# run one: a person who downloads xaios_b<n>-aarch64.iso still has to know that
# QEMU wants gic-version=3, that Fusion boots it from a SATA CD-ROM and needs a
# .vmx, and that Virtualization.framework needs a harness they have to sign
# themselves. All of that is written down in this repository and none of it
# travels with the file.
#
# One kit per environment per architecture. There used to be one image that
# booted every environment, and three kits carrying a copy of it; the images
# are per-architecture now, so the QEMU kit is too, and each one carries the
# image for its own architecture and the launcher that starts it. A kit with
# one image and one runner cannot be started against the wrong file.
#
# Fusion and Virtualization.framework are AArch64 only, and that is not a gap
# waiting to be filled -- see their READMEs. Both run guests on this host's own
# cores, and this host's cores are AArch64, so an x86-64 or RISC-V guest here
# is emulation, which is what the QEMU kit already is.
#
# Virtualization.framework is also the one kit that ships source: the harness
# has to be code-signed with entitlements on the machine that runs it, so it
# carries the source and the build script rather than a binary nobody else's
# Mac would accept.
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
BUILD_DIR="$ROOT_DIR/build"
RELEASE_DIR="$ROOT_DIR/release"
STAGE_ROOT="$BUILD_DIR/vm-packages"
BUILD_NUMBER="$(tr -d ' \n' < "$ROOT_DIR/BUILD_NUMBER" 2>/dev/null || printf '%s' 0)"

# Which architectures get kits. Same variable and same spelling as
# build-release.sh and build-boot-media.sh, because all three are asked the
# same question about the same release.
ARCHS="${XAIOS_RELEASE_ARCHS:-aarch64 x86_64 riscv64}"

command -v zip >/dev/null 2>&1 || {
  printf '%s\n' "error: zip is required" >&2
  exit 1
}

# The fallback belongs on the checksum command rather than after the pipeline:
# a pipeline reports the status of its last command, so `shasum ... | cut ||
# sha256sum ...` never falls back -- cut succeeds on empty input and the
# printed checksum is a blank line.
sha_of() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  else
    sha256sum "$1" | cut -d' ' -f1
  fi
}

label_for() {
  case "$1" in
    aarch64) printf 'AArch64' ;;
    x86_64)  printf 'x86-64' ;;
    riscv64) printf 'RISC-V 64-bit' ;;
    *) printf 'error: unknown architecture %s\n' "$1" >&2; exit 2 ;;
  esac
}

# Checked before anything is copied, so a run that fails leaves the previous
# release's kits alone rather than replacing half of them.
for arch in $ARCHS; do
  image="$RELEASE_DIR/xaios_b${BUILD_NUMBER}-${arch}.iso"
  [ -f "$image" ] || {
    printf '%s\n' "missing: $image" "run: make release-package" >&2
    exit 1
  }
done

rm -rf "$STAGE_ROOT"
mkdir -p "$STAGE_ROOT" "$RELEASE_DIR"

# Shared by every README: the image in the kit is one artifact with one
# checksum, and a rebuild deliberately does not reproduce it. Takes the name
# and the checksum as arguments now that they differ between kits -- a footer
# that named one image while the kit carried another would be worse than none.
common_footer() {
  cat <<EOF

## Verifying what you downloaded

\`$1\` — SHA-256 \`$2\`

    shasum -a 256 $1

The image embeds a fresh boot entropy seed on every build, so rebuilding this
commit produces a working image with a different checksum. That checksum
identifies this artifact, not the commit: verify a download against it, and do
not expect a rebuild to match.

## What was tested, and where

See \`xaios_b${BUILD_NUMBER}.md\` in the release for the exact host, hypervisor
versions and firmware each environment was booted on. Nothing there is inferred
from a similar configuration.
EOF
}

KITS=""

. "$ROOT_DIR/scripts/lib/vm-packages-qemu.sh"

. "$ROOT_DIR/scripts/lib/vm-packages-fusion-vz.sh"

# ------------------------------------------------------------- archives
printf '%s\n' "XAIOS build $BUILD_NUMBER virtual machine kits"
for kit in $KITS; do
  name=$(basename "$kit")
  archive="$RELEASE_DIR/$name.zip"
  rm -f "$archive"
  (cd "$STAGE_ROOT" && zip -qr "$archive" "$name")
  printf '  %s\n' "$name.zip"
  printf '    %s bytes\n' "$(wc -c < "$archive" | tr -d ' ')"
  printf '    SHA-256 %s\n' "$(sha_of "$archive")"
done
for arch in $ARCHS; do
  printf '  image %-8s %s\n' "$arch" \
    "$(sha_of "$RELEASE_DIR/xaios_b${BUILD_NUMBER}-${arch}.iso")"
done
