#!/bin/sh
# Run one script from this directory inside the CI-parity image.
#
#   tests/linux-parity/run-parity.sh riscv-smoke.sh
#
# The source goes in over stdin rather than through a bind mount: Docker Desktop
# does not share every host path, and a -v of one it cannot see silently creates
# an empty directory instead of failing, which costs a run to notice.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
HERE=tests/linux-parity
IMAGE=${XAIOS_PARITY_IMAGE:-xaios-ci-parity}
SCRIPT=${1:?usage: run-parity.sh <script-in-this-directory>}

command -v docker >/dev/null 2>&1 || {
  printf '%s\n' "error: docker is required" >&2; exit 1; }

docker image inspect "$IMAGE" >/dev/null 2>&1 || {
  printf '%s\n' "building $IMAGE ..."
  docker build -q -t "$IMAGE" -f "$ROOT/$HERE/Dockerfile.ci-parity" "$ROOT/$HERE" >/dev/null
}

# The pin the libc build asserts. picolibc's files travel in the tar but its
# submodule metadata does not, and the pin check has an override for that.
PIN=$(sed -n 's/^PIN=\([0-9a-f]\{40\}\)$/\1/p' "$ROOT/scripts/build-libc.sh" | head -1)
[ -n "$PIN" ] || { printf '%s\n' "error: could not read the picolibc pin" >&2; exit 1; }

# COPYFILE_DISABLE stops macOS tar embedding AppleDouble ._* files, which clang
# then tries to compile.
cd "$ROOT"
COPYFILE_DISABLE=1 tar czf - \
  --exclude=./build --exclude=./.git --exclude=./.claude --exclude=./release \
  --exclude='*.iso' --exclude='*.img' --exclude='*.zip' . \
| docker run -i --rm -e "XAIOS_PICOLIBC_REVISION_OVERRIDE=$PIN" "$IMAGE" \
    sh -c "tar xzf - && exec sh $HERE/$SCRIPT"
