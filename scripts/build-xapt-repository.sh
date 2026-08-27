#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
REPOSITORY=${XAIOS_XAPT_REPOSITORY:-"$ROOT/build/xapt/repository"}
BUILD=${XAIOS_BUILD_NUMBER:-1}
GENERATION=${XAIOS_UPDATE_GENERATION:-100}

cd "$ROOT"
make image image-x86_64
rm -rf "$REPOSITORY"

for arch in aarch64 x86_64; do
  if [ "$arch" = aarch64 ]; then
    kernel="$ROOT/build/kernel/kernel.elf"
  else
    kernel="$ROOT/build/kernel-x86_64/kernel.elf"
  fi

  python3 tools/xaios_xapt_repo.py system \
    --repository "$REPOSITORY" \
    --image "$kernel" \
    --version "$BUILD" \
    --generation "$GENERATION" \
    --arch "$arch"
  python3 tools/xaios_xapt_repo.py catalog \
    --repository "$REPOSITORY" \
    --arch "$arch" \
    --generation 1 \
    --generated "xaios-$BUILD" \
    --os-record "$REPOSITORY/os/$arch/$BUILD/record.json"
done

python3 tools/xaios_xapt_repo.py verify --repository "$REPOSITORY"
printf 'Built verified xapt repository: %s\n' "$REPOSITORY"
