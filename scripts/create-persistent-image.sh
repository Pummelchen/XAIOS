#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build"
PERSISTENT_IMAGE="${XAIOS_PERSISTENT_IMAGE:-$BUILD_DIR/xaios-persistent.img}"

mkdir -p "$BUILD_DIR"

if [ -f "$PERSISTENT_IMAGE" ]; then
  printf '%s\n' "Persistent image already exists: $PERSISTENT_IMAGE ($(wc -c < "$PERSISTENT_IMAGE") bytes)"
  exit 0
fi

printf '%s\n' "Creating persistent disk image: $PERSISTENT_IMAGE"
dd if=/dev/zero of="$PERSISTENT_IMAGE" bs=512 count=32768 status=none
printf '%s\n' "Created $PERSISTENT_IMAGE (16 MB, 32768 sectors)"
