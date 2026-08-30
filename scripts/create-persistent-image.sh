#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build"
PERSISTENT_IMAGE="${XAIOS_PERSISTENT_IMAGE:-$BUILD_DIR/xaios-persistent.img}"
# How large the volume is decides which format it gets: xaibootFS formats v6 on
# a device with room for a gibibyte of data and v5 on anything smaller. The
# default is the v5 size every profile has always used; a gate that wants to
# exercise v6 asks for a bigger one rather than editing this.
PERSISTENT_SECTORS="${XAIOS_PERSISTENT_SECTORS:-32768}"

mkdir -p "$BUILD_DIR"

if [ -f "$PERSISTENT_IMAGE" ]; then
  printf '%s\n' "Persistent image already exists: $PERSISTENT_IMAGE ($(wc -c < "$PERSISTENT_IMAGE") bytes)"
  exit 0
fi

printf '%s\n' "Creating persistent disk image: $PERSISTENT_IMAGE"
dd if=/dev/zero of="$PERSISTENT_IMAGE" bs=512 count="$PERSISTENT_SECTORS" status=none
printf '%s\n' "Created $PERSISTENT_IMAGE ($((PERSISTENT_SECTORS / 2048)) MB, $PERSISTENT_SECTORS sectors)"
