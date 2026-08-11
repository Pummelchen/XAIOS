#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
REPOSITORY=${XAIOS_XAPT_REPOSITORY:-"$ROOT/build/xapt/repository"}
VERSION=${XAIOS_VERSION:-0.1.0}
GENERATION=${XAIOS_UPDATE_GENERATION:-100}
CALCULATOR_VERSION=${XAIOS_CALCULATOR_VERSION:-1.0.0}
CAPABILITIES=1073741826

cd "$ROOT"
make image image-x86_64
rm -rf "$REPOSITORY"

for arch in aarch64 x86_64; do
  app="$ROOT/build/xapt/$arch/calculator.elf"
  if [ "$arch" = aarch64 ]; then
    kernel="$ROOT/build/kernel/kernel.elf"
  else
    kernel="$ROOT/build/kernel-x86_64/kernel.elf"
  fi

  ./scripts/build-user-app.sh --arch "$arch" \
    userspace/apps/calculator.c "$app"
  python3 tools/xaios_xapt_repo.py package \
    --repository "$REPOSITORY" \
    --elf "$app" \
    --name calculator \
    --version "$CALCULATOR_VERSION" \
    --arch "$arch" \
    --minimum-os "$VERSION" \
    --minimum-abi 1 \
    --capabilities "$CAPABILITIES" \
    --description "Signed 64-bit integer calculator"
  python3 tools/xaios_xapt_repo.py system \
    --repository "$REPOSITORY" \
    --image "$kernel" \
    --version "$VERSION" \
    --generation "$GENERATION" \
    --arch "$arch"
  python3 tools/xaios_xapt_repo.py catalog \
    --repository "$REPOSITORY" \
    --arch "$arch" \
    --generation 1 \
    --generated "xaios-$VERSION" \
    --os-record "$REPOSITORY/os/$arch/$VERSION/record.json"
done

python3 tools/xaios_xapt_repo.py verify --repository "$REPOSITORY"
printf 'Built verified xapt repository: %s\n' "$REPOSITORY"
